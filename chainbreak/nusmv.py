"""把可达状态图导出为 NuSMV 模型，供外部模型检查器独立复验。

导出的是展平后的 Kripke 结构（state 枚举 + ASSIGN next），
非法状态 bad 用 DEFINE 定义，性质写成 CTLSPEC AG !bad。
"""

from __future__ import annotations

from pathlib import Path

from .check import violates
from .compose import Policy, apply, enabled_actions, initial_state
from .model import Deployment


def explore(dep: Deployment, policy: Policy, only: tuple[str, ...] | None = None,
            max_states: int = 200_000):
    """枚举可达状态图，返回 (states, edges, bad) —— bad 是违反属性的目标态下标。"""
    start = initial_state(dep)
    states = [start]
    index = {start: 0}
    edges: set[tuple[int, int]] = set()
    bad: set[int] = set()
    i = 0
    while i < len(states) and len(states) <= max_states:
        st = states[i]
        for action, label, deny in enabled_actions(dep, st, policy):
            if deny:
                continue
            post = apply(dep, st, action)
            j = index.get(post)
            if j is None:
                j = len(states)
                states.append(post)
                index[post] = j
            edges.add((i, j))
            if violates(dep, st, action, label, post, only=only):
                bad.add(j)
        i += 1
    return states, sorted(edges), bad


def export(dep: Deployment, policy: Policy, only: tuple[str, ...] | None,
           path: str | Path, witness: str = "") -> Path:
    states, edges, bad = explore(dep, policy, only)
    succ: dict[int, list[int]] = {}
    for i, j in edges:
        succ.setdefault(i, []).append(j)

    lines = [
        "-- NuSMV model exported by ChainBreak",
        f"-- deployment={dep.name} policy={policy.name} states={len(states)} bad={len(bad)}",
    ]
    if witness:
        lines.append(f"-- witness: {witness}")
    lines += [
        "MODULE main",
        f"  VAR state : 0..{len(states) - 1};",
        "  INIT state = 0;",
        "",
        "  ASSIGN",
        "    next(state) := case",
    ]
    for i in range(len(states)):
        nxt = succ.get(i)
        target = "{" + ", ".join(str(j) for j in sorted(nxt)) + "}" if nxt else "state"
        lines.append(f"      state = {i} : {target};")
    lines += [
        "      TRUE : state;",
        "    esac;",
        "",
        "  -- 违反安全属性的状态",
        "  DEFINE bad := " + (" | ".join(f"state = {j}" for j in sorted(bad)) or "FALSE") + ";",
        "",
        "  -- 组合安全性质：永远不进入 bad",
        "  CTLSPEC AG !bad;",
        "",
    ]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines), encoding="utf-8")
    return p
