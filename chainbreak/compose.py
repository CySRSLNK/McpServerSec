"""组合图：服务器 EFSM × 上下文 × 共享存储。

三类边，同一张图：
  参数边   (模式A) 值以调用参数直接传下去
  上下文边 (模式B) 值先进上下文，再影响下一次调用
  存储边   (模式C) 值写进共享外部存储（文件系统/共享图），由另一服务器读出

第三类是你举的 A读→B写→C发 场景的实际通道：路径走参数，内容走存储。
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .lattice import CLEAN, Label, auth_rank, compact, join
from .model import Deployment, Tool, eff  # noqa: F401


@dataclass(frozen=True)
class State:
    servers: tuple[tuple[str, str], ...]
    ctx: Label
    injection_seen: bool
    last_ret: Label | None
    last_ret_srv: str | None
    store: tuple[tuple[str, Label], ...]
    compacted: int

    def server_state(self, name: str) -> str:
        for n, s in self.servers:
            if n == name:
                return s
        raise KeyError(name)

    def with_server(self, name: str, new_state: str) -> "State":
        return replace(
            self,
            servers=tuple(sorted((n, new_state if n == name else s) for n, s in self.servers)),
        )

    def store_label(self) -> Label | None:
        acc: Label | None = None
        for _, lab in self.store:
            acc = lab if acc is None else join(acc, lab)
        return acc


def initial_state(dep: Deployment) -> State:
    return State(
        servers=tuple(sorted((s.name, s.start) for s in dep.servers)),
        ctx=CLEAN,
        injection_seen=False,
        last_ret=None,
        last_ret_srv=None,
        store=(),
        compacted=0,
    )


# ---------------------------------------------------------------- 策略

@dataclass(frozen=True)
class Policy:
    name: str
    label_aware: bool = False
    validate_annotations: bool = False
    track_cursor: bool = False
    influence_aware: bool = False
    name_scope: str = "bare"

    def deny(self, dep: Deployment, tool: Tool, payload: Label | None, st: State) -> str | None:
        if self.validate_annotations:
            believed = tool if self.name_scope == "qualified" else dep.bare_map.get(tool.name, tool)
            if believed.effect_declared != believed.effect_observed:
                return f"注解与实测不一致：{believed.qname}"

        if self.track_cursor and tool.kind == "fetch_cursor":
            if st.server_state("web") == "cursor_stale":
                return "句柄已失效仍被使用"

        if self.influence_aware and tool.effect_observed.outbound and st.ctx.is_untrusted:
            return "上下文含不可信内容时发起外发"

        if self.label_aware and payload is not None:
            obs = tool.effect_observed
            if obs.outbound and payload.is_secret:
                return "敏感数据流向网络出口"
            if payload.is_untrusted and obs.touches_world and auth_rank(obs.needs) >= 1:
                return "不可信内容驱动特权动作"
            # 跨服务器数据流规则：这条不可能由任何单个服务器实现
            if payload.is_secret and (obs.writes & dep.shared):
                return "敏感数据写入跨服务器共享域"
        return None


NAIVE = Policy("naive")
PARTIAL = Policy("partial", validate_annotations=True, name_scope="qualified")
HARDENED = Policy(
    "hardened", label_aware=True, validate_annotations=True,
    track_cursor=True, influence_aware=True, name_scope="qualified",
)
# 两种只做一半的防御，用来对比
DATA_ONLY = Policy("data-only", label_aware=True, name_scope="qualified")
INFLUENCE_ONLY = Policy("influence-only", influence_aware=True, name_scope="qualified")
POLICIES = (NAIVE, PARTIAL, HARDENED)


# ---------------------------------------------------------------- 动作

Action = tuple

VIA_PARAM = "param"
VIA_CTX = "ctx"
VIA_STORE = "store"
VIA_NONE = "none"

VIA_CN = {
    VIA_PARAM: "参数边/模式A",
    VIA_CTX: "上下文边/模式B",
    VIA_STORE: "存储边/模式C",
    VIA_NONE: "无数据参数",
}


def _payload_of(st: State, tool: Tool, via: str) -> Label | None:
    if via == VIA_PARAM:
        return st.last_ret
    if via == VIA_CTX:
        return st.ctx
    if tool.reads_store:
        return st.store_label()
    return None


def enabled_actions(
    dep: Deployment,
    st: State,
    policy: Policy,
    allow_ctx: bool = True,
    scope: tuple[str, ...] | None = None,
) -> list[tuple[Action, Label | None, str | None]]:
    out: list[tuple[Action, Label | None, str | None]] = [(("compact",), None, None)]
    for tool in dep.tools:
        if scope is not None and tool.server not in scope:
            continue
        if st.server_state(tool.server) not in tool.src:
            continue
        candidates: list[tuple[str, Label | None]] = [(VIA_NONE, None)]
        if tool.consumes and st.last_ret is not None:
            candidates.append((VIA_PARAM, st.last_ret))
        if tool.consumes and allow_ctx:
            candidates.append((VIA_CTX, st.ctx))
        for via, label in candidates:
            out.append((("call", tool.server, tool.name, via), label, policy.deny(dep, tool, label, st)))
    return out


def apply_call(dep: Deployment, st: State, tool: Tool, via: str, input_label: Label | None) -> State:
    nxt = st
    if tool.dst is not None:
        nxt = nxt.with_server(tool.server, tool.dst)

    if tool.passthrough:
        out: Label | None = input_label if input_label is not None else CLEAN
    elif tool.reads_store:
        out = nxt.store_label()
    else:
        out = tool.out

    if tool.writes_store:
        key = f"{tool.server}:{tool.name}"
        payload = input_label if input_label is not None else CLEAN
        nxt = replace(nxt, store=tuple(sorted({**dict(nxt.store), key: payload}.items())))

    ctx = nxt.ctx
    injection = nxt.injection_seen
    if out is not None:
        ctx = join(ctx, out)
        injection = injection or out.is_untrusted

    return replace(
        nxt,
        ctx=ctx,
        injection_seen=injection,
        last_ret=out,
        last_ret_srv=tool.server if out is not None else None,
    )


def apply(dep: Deployment, st: State, action: Action, compact_relabel: bool = True) -> State:
    if action[0] == "compact":
        new_ctx = compact(st.ctx) if compact_relabel else st.ctx
        # compact 是幂等的：再压一次状态不变。把计数截到 1，
        # 状态空间才有限，搜索才能穷尽 —— 这是"安全"结论成立的前提。
        return replace(st, ctx=new_ctx, compacted=min(1, st.compacted + 1))
    _, server, name, via = action
    tool = dep.tool_map[(server, name)]
    return apply_call(dep, st, tool, via, _payload_of(st, tool, via))


def describe(action: Action) -> str:
    if action[0] == "compact":
        return "context.compact()  「上下文压缩」"
    _, server, name, via = action
    return f"{server}.{name}  「{VIA_CN[via]}」"
