"""场景加载器：把演示从"写代码"变成"写 JSON"。

场景可以引用内置部署（INJECT / ABC / MAIN），也可以内联定义，
这样答辩时加一个新场景不需要改 Python。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .compose import (
    DATA_ONLY, HARDENED, INFLUENCE_ONLY, NAIVE, PARTIAL, Policy,
)
from .lattice import Label
from .model import ABC, INJECT, MAIN, Deployment, Server, Tool, eff

BUILTIN = {"INJECT": INJECT, "ABC": ABC, "MAIN": MAIN}

POLICIES = {
    "naive": NAIVE,
    "partial": PARTIAL,
    "hardened": HARDENED,
    "data-only": DATA_ONLY,
    "influence-only": INFLUENCE_ONLY,
}


def _label(d: dict | None) -> Label | None:
    if not d:
        return None
    return Label(d.get("prov", "user"), d.get("integ", "trusted"),
                 d.get("sens", "public"), d.get("auth", "none"))


def _effect(d: dict | None):
    d = d or {}
    return eff(
        reads=d.get("reads", ()),
        writes=d.get("writes", ()),
        outbound=d.get("outbound", False),
        inbound=d.get("inbound", False),
        needs=d.get("needs", "none"),
    )


def build_deployment(spec: dict) -> Deployment:
    servers = tuple(
        Server(s["name"], tuple(s["states"]), s["start"], s.get("archetype", "stateless"))
        for s in spec["servers"]
    )
    tools = []
    for t in spec["tools"]:
        observed = _effect(t.get("observed") or t)
        declared = _effect(t["declared"]) if t.get("declared") else observed
        tools.append(Tool(
            server=t["server"],
            name=t["name"],
            kind=t.get("kind", "noop"),
            src=tuple(t["src"]),
            dst=t.get("dst"),
            effect_declared=declared,
            effect_observed=observed,
            consumes=t.get("consumes", False),
            out=_label(t.get("out")),
            passthrough=t.get("passthrough", False),
            writes_store=t.get("writes_store", False),
            reads_store=t.get("reads_store", False),
        ))
    return Deployment(
        spec["name"], servers, tuple(tools),
        note=spec.get("note", ""),
        shared=frozenset(spec.get("shared", ())),
    )


@dataclass
class Scenario:
    name: str
    title: str
    deployment: Deployment
    policy: Policy
    invariants: tuple[str, ...]
    all_of: tuple[str, ...] | None = None
    scope: tuple[str, ...] | None = None
    expect: str = "unsafe"
    note: str = ""
    source: str = ""
    raw: dict = field(default_factory=dict)


def load(path: str | Path) -> Scenario:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))

    if "deployment" in data:
        dep = BUILTIN[data["deployment"]]
    else:
        dep = build_deployment(data["deployment_inline"])

    pol_name = data.get("policy", "naive")
    if pol_name not in POLICIES:
        raise KeyError(f"未知策略: {pol_name}")
    pol = POLICIES[pol_name]

    scope = data.get("scope")
    return Scenario(
        name=data["name"],
        title=data.get("title", data["name"]),
        deployment=dep,
        policy=pol,
        invariants=tuple(data.get("invariants", ())),
        all_of=tuple(data["all_of"]) if data.get("all_of") else None,
        scope=tuple(scope) if scope else None,
        expect=data.get("expect", "unsafe"),
        note=data.get("note", ""),
        source=str(p),
        raw=data,
    )


def load_all(directory: str | Path) -> list[Scenario]:
    files = sorted(Path(directory).glob("*.json"))
    return [load(f) for f in files]
