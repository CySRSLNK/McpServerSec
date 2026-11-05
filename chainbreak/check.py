"""有界模型检测：宽度优先搜索 + 6 类安全模板 + 见证生成。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .compose import (
    Action,
    Policy,
    State,
    VIA_CTX,
    VIA_NONE,
    VIA_PARAM,
    VIA_STORE,
    apply,
    describe,
    enabled_actions,
    initial_state,
)
from .lattice import auth_rank
from .model import Deployment, Tool


@dataclass(frozen=True)
class Template:
    id: str
    name: str
    severity: str
    mechanism: str


TEMPLATES: tuple[Template, ...] = (
    Template("F1", "敏感数据外泄", "高", "私密数据经任一类边到达网络出口"),
    Template("F2", "不可信内容驱动特权动作", "高", "外部内容进入上下文后触发写入/外发"),
    Template("F3", "权限域放大", "中", "低权限域数据写入更高权限域的共享存储"),
    Template("F4", "来源丢失洗白", "高", "压缩抹掉来源后，不可信内容被当作可信"),
    Template("F5", "注解谎报 / 影子工具", "中", "声明效果与实测效果不一致且仍被调用"),
    Template("F6", "失效句柄仍被接受", "中", "已关闭的句柄服务器端仍默认放行"),
    Template("F7", "注入驱动外联", "高", "上下文含不可信内容时执行外发动作"),
)
TEMPLATE_MAP = {t.id: t for t in TEMPLATES}


@dataclass
class Finding:
    template: Template
    path: list[Action]
    channels: list[str]
    detail: str

    @property
    def depth(self) -> int:
        return len(self.path)

    @property
    def mode(self) -> str:
        used = set(self.channels)
        words = []
        if VIA_PARAM in used:
            words.append("模式A")
        if VIA_CTX in used:
            words.append("模式B")
        if VIA_STORE in used:
            words.append("模式C")
        return "+".join(words) if words else "-"


@dataclass
class Report:
    deployment: str
    policy: str
    states_explored: int
    depth_reached: int
    truncated: bool
    checked: tuple[str, ...] = ()
    findings: dict[str, Finding] = field(default_factory=dict)

    def has(self, tid: str) -> bool:
        return tid in self.findings

    @property
    def verdict(self) -> str:
        """三态判定：不安全 / 安全 / 未知。

        unsafe  找到反例（见证即为证据）
        safe    状态空间穷尽且无反例（相对模型与抽象，构成安全证明）
        unknown 触达状态上限，搜索未穷尽 —— 既不安全也无法证明安全
        """
        if self.findings:
            return "unsafe"
        return "unknown" if self.truncated else "safe"

    @property
    def why(self) -> str:
        if self.findings:
            return f"找到 {len(self.findings)} 条反例见证"
        if self.truncated:
            return "搜索被状态上限截断，结论不可用"
        return f"穷尽 {self.states_explored} 个可达状态，无反例"


def _payload(pre: State, tool: Tool, label):
    """有效载荷：显式传入的标签，或从共享存储读出的标签。"""
    if label is not None:
        return label, None
    if tool.reads_store:
        lab = pre.store_label()
        if lab is not None:
            return lab, VIA_STORE
    return None, None


def _check(dep: Deployment, pre: State, action: Action, via: str, label, post: State,
           only: tuple[str, ...] | None = None,
           all_of: tuple[str, ...] | None = None):
    if action[0] == "compact":
        return []
    _, server, name, _ = action
    tool = dep.tool_map[(server, name)]
    obs = tool.effect_observed
    payload, store_via = _payload(pre, tool, label)
    channel = store_via or via
    hits: list[tuple[Template, str, str]] = []

    if obs.outbound and payload is not None and payload.is_secret:
        src = "共享存储" if store_via else "调用参数/上下文"
        hits.append((TEMPLATE_MAP["F1"], f"{tool.qname} 把「{payload.short()}」经{src}发往网络出口", channel))

    if obs.outbound and pre.ctx.is_untrusted:
        hits.append((TEMPLATE_MAP["F7"],
                     f"上下文含不可信内容时执行外发：{tool.qname}", channel))

    if (via == VIA_CTX and payload is not None and payload.is_untrusted
            and obs.touches_world and auth_rank(obs.needs) >= auth_rank("self")):
        hits.append((TEMPLATE_MAP["F2"], f"上下文中的不可信内容驱动 {tool.qname}", channel))

    if (payload is not None and payload.is_secret
            and (obs.writes & dep.shared)
            and payload.authority < auth_rank(obs.needs)):
        hits.append((TEMPLATE_MAP["F3"], f"{tool.qname} 需要 {obs.needs}，数据只有 {payload.auth}", channel))

    if (pre.compacted > 0 and via == VIA_CTX and payload is not None
            and not payload.is_untrusted and pre.injection_seen and obs.touches_world):
        hits.append((TEMPLATE_MAP["F4"], f"压缩后上下文被重标为「{payload.short()}」，驱动 {tool.qname}", channel))

    if tool.is_lying:
        hits.append((
            TEMPLATE_MAP["F5"],
            f"{tool.qname} 声明「{tool.effect_declared.fmt()}」实测「{tool.effect_observed.fmt()}」",
            channel,
        ))

    if tool.kind == "fetch_cursor" and "web" in dep.server_map:
        if pre.server_state("web") == "cursor_stale":
            hits.append((TEMPLATE_MAP["F6"], "web 处于 cursor_stale 但仍接受 fetch_cursor", channel))

    if all_of:
        # 只保留「同一次迁移同时违反全部指定属性」的见证
        if not set(all_of) <= {h[0].id for h in hits}:
            return []
        hits = [h for h in hits if h[0].id in all_of]
    elif only is not None:
        hits = [h for h in hits if h[0].id in only]
    return hits


def violates(dep: Deployment, pre: State, action: Action, label, post: State,
             only: tuple[str, ...] | None = None) -> bool:
    """该迁移是否违反（被检查的）安全属性。"""
    via = action[3] if action[0] == "call" else "compact"
    return bool(_check(dep, pre, action, via, label, post, only=only))


@dataclass
class _Node:
    state: State
    action: Action | None
    parent: int
    depth: int


def search(
    dep: Deployment,
    policy: Policy = Policy("naive"),
    max_depth: int | None = None,
    max_states: int = 400_000,
    allow_ctx: bool = True,
    compact_relabel: bool = True,
    scope: tuple[str, ...] | None = None,
    only: tuple[str, ...] | None = None,
    all_of: tuple[str, ...] | None = None,
) -> Report:
    start = initial_state(dep)
    nodes = [_Node(start, None, -1, 0)]
    seen = {start}
    findings: dict[str, Finding] = {}
    truncated = False
    i = 0

    while i < len(nodes):
        node = nodes[i]
        if max_depth is None or node.depth < max_depth:
            for action, label, deny in enabled_actions(
                dep, node.state, policy, allow_ctx=allow_ctx, scope=scope
            ):
                if deny:
                    continue
                post = apply(dep, node.state, action, compact_relabel=compact_relabel)
                via = action[3] if action[0] == "call" else "compact"
                for tpl, why, channel in _check(dep, node.state, action, via, label, post, only=only, all_of=all_of):
                    if tpl.id in findings:
                        continue
                    path: list[Action] = []
                    channels: list[str] = []
                    cur = i
                    while cur >= 0:
                        a = nodes[cur].action
                        if a is not None:
                            path.append(a)
                            channels.append(a[3] if a[0] == "call" else "compact")
                        cur = nodes[cur].parent
                    path.reverse()
                    channels.reverse()
                    path.append(action)
                    channels.append(channel)
                    findings[tpl.id] = Finding(tpl, path, channels, why)
                if post not in seen:
                    seen.add(post)
                    nodes.append(_Node(post, action, i, node.depth + 1))
        i += 1
        if len(nodes) > max_states:
            truncated = True
            break

    return Report(
        deployment=dep.name,
        policy=policy.name,
        states_explored=len(nodes),
        depth_reached=max((n.depth for n in nodes), default=0),
        truncated=truncated,
        checked=only if only is not None else tuple(t.id for t in TEMPLATES),
        findings=findings,
    )
