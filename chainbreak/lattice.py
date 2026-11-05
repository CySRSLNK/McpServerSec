"""标签格：来源 × 完整性 × 敏感度 × 权限域。

所有数据（工具返回值、上下文条目）都以这个四元组抽象，
不建模具体字符串——这是让组合状态空间可穷举的关键工程决定。
"""

from __future__ import annotations

from dataclasses import dataclass

# 来源：谁"写过"这个值。unknown = 来源标注已丢失（压缩/跨会话装载）。
PROV_ORDER = ("user", "srv", "external", "unknown")
INTEG_ORDER = ("trusted", "untrusted")
SENS_ORDER = ("public", "secret")
AUTH_ORDER = ("none", "self", "cross", "admin")


def auth_rank(level: str) -> int:
    return AUTH_ORDER.index(level)


@dataclass(frozen=True)
class Label:
    prov: str = "user"
    integ: str = "trusted"
    sens: str = "public"
    auth: str = "none"

    def __post_init__(self) -> None:
        if self.prov not in PROV_ORDER:
            raise ValueError(f"bad prov: {self.prov}")
        if self.integ not in INTEG_ORDER:
            raise ValueError(f"bad integ: {self.integ}")
        if self.sens not in SENS_ORDER:
            raise ValueError(f"bad sens: {self.sens}")
        if self.auth not in AUTH_ORDER:
            raise ValueError(f"bad auth: {self.auth}")

    # --- 便捷判定 ---
    @property
    def is_secret(self) -> bool:
        return self.sens == "secret"

    @property
    def is_untrusted(self) -> bool:
        return self.integ == "untrusted"

    @property
    def authority(self) -> int:
        return auth_rank(self.auth)

    def with_(self, **kw: str) -> "Label":
        return Label(
            prov=kw.get("prov", self.prov),
            integ=kw.get("integ", self.integ),
            sens=kw.get("sens", self.sens),
            auth=kw.get("auth", self.auth),
        )

    def short(self) -> str:
        return f"{self.prov}/{self.integ}/{self.sens}/{self.auth}"

    display = short


CLEAN = Label()  # 用户直接给出、可信、公开、无权限域


def join(a: Label, b: Label | None) -> Label:
    """格的并：混合来源降级为 unknown，任一不可信即不可信，敏感取并，权限取高。"""
    if b is None:
        return a
    prov = a.prov if a.prov == b.prov else "unknown"
    integ = "untrusted" if (a.integ == "untrusted" or b.integ == "untrusted") else "trusted"
    sens = "secret" if (a.sens == "secret" or b.sens == "secret") else "public"
    auth = a.auth if auth_rank(a.auth) >= auth_rank(b.auth) else b.auth
    return Label(prov=prov, integ=integ, sens=sens, auth=auth)


def compact(label: Label) -> Label:
    """上下文压缩的语义：保留敏感度，但丢失来源与完整性标注。

    这是整个演示里最关键的一条规则——压缩把"外部不可信"洗成"用户可信"，
    而敏感度仍在。检测器若只靠来源判定，就会在压缩之后彻底失明。
    """
    return Label(prov="user", integ="trusted", sens=label.sens, auth=label.auth)
