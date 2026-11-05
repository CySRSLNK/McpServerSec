#!/usr/bin/env python3
"""交付版入口：一键跑完所有场景，生成判定报告与 NuSMV 模型。

    python3 deliver.py                # 控制台报告 + 写入 report.md
    python3 deliver.py --no-write     # 只看控制台
"""

from __future__ import annotations

import sys
import time
import unicodedata
from pathlib import Path

from chainbreak import TEMPLATES, search
from chainbreak.compose import describe
from chainbreak.nusmv import export as export_smv
from chainbreak.scenario import Scenario, load_all

ROOT = Path(__file__).parent
SCEN = ROOT / "scenarios"
OUT = ROOT / "reports"
RULE = "─" * 80


def dw(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WFA" else 1 for c in s)


def pad(s: str, n: int, align: str = "<") -> str:
    gap = max(0, n - dw(s))
    if align == "^":
        left = gap // 2
        return " " * left + s + " " * (gap - left)
    return s + " " * gap


def trunc(s: str, n: int) -> str:
    if dw(s) <= n:
        return s
    out, w = [], 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in "WFA" else 1
        if w + cw > n - 1:
            break
        out.append(ch)
        w += cw
    return "".join(out) + "…"


def verdict_word(v: str) -> str:
    return {"unsafe": "UNSAFE", "safe": "SAFE", "unknown": "UNKNOWN"}[v]


def locality(sc: Scenario, tid: str) -> tuple[str, str | None]:
    """判定一条发现是「局部缺陷」还是「组合漏洞」。

    做法：把见证里出现的服务器逐个单独跑一遍，若单台就能复现同一属性违例，
    说明它不是组合产生的——这条检查能挡住最常见的审稿质疑。
    """
    f = search(sc.deployment, sc.policy, scope=sc.scope,
               only=sc.invariants or None, all_of=sc.all_of).findings.get(tid)
    if f is None:
        return "?", None
    servers = {a[1] for a in f.path if a[0] == "call"}
    for s in sorted(servers):
        r = search(sc.deployment, sc.policy, scope=(s,), only=(tid,))
        if r.has(tid):
            return "局部", s
    return "组合", None


def run(sc: Scenario) -> dict:
    r = search(sc.deployment, sc.policy, scope=sc.scope,
               only=sc.invariants or None, all_of=sc.all_of)
    return {"scenario": sc, "report": r}


def main(argv: list[str]) -> int:
    t0 = time.perf_counter()
    scenarios = load_all(SCEN)
    results = [run(s) for s in scenarios]

    print("ChainBreak 交付版 — MCP 跨服务器组合调用的安全性判定")
    print(f"共 {len(scenarios)} 个场景，覆盖 3 个部署与 4 种客户端策略")
    print(RULE)

    head = (pad("编号", 6) + pad("场景", 40) + pad("覆盖", 20)
            + pad("判定", 10) + pad("期望", 10) + "结论")
    print(head)
    print("─" * dw(head))

    fails = 0
    for item in results:
        sc, r = item["scenario"], item["report"]
        cover = "+".join(sc.scope) if sc.scope else sc.deployment.name
        ok = r.verdict == sc.expect
        if not ok:
            fails += 1
        mark = "✓" if ok else "✗ 不符"
        print(pad(sc.name.split("_")[0], 6) + pad(trunc(sc.title, 38), 40) + pad(cover, 20)
              + pad(verdict_word(r.verdict), 10) + pad(sc.expect, 10) + mark)

    print(RULE)
    unsafe = [i for i in results if i["report"].verdict == "unsafe"]
    safe = [i for i in results if i["report"].verdict == "safe"]
    print(f"UNSAFE {len(unsafe)} 个 / SAFE {len(safe)} 个 / 期望不符 {fails} 个")

    # ---- 发现细节 + 局部性判定 ----
    if unsafe:
        print(f"\n发现细节与「是否真由组合产生」：")
        for item in unsafe:
            sc, r = item["scenario"], item["report"]
            print(f"\n  ── {sc.name.split('_')[0]} {sc.title}  [{sc.policy.name}]")
            for tid, f in sorted(r.findings.items()):
                kind, single = locality(sc, tid)
                tag = "组合漏洞" if kind == "组合" else f"局部缺陷（{single} 单独即可复现）"
                print(f"  [{tid}] {f.template.name}   —— {tag}")
                print(f"        链路: {' → '.join(describe(a).split('  ')[0] for a in f.path)}")
                print(f"        命中: {f.detail}\n")

    # ---- NuSMV 导出 ----
    OUT.mkdir(exist_ok=True)
    exported = []
    for item in results:
        sc, r = item["scenario"], item["report"]
        if r.verdict == "safe":
            continue
        witness = next(iter(r.findings.values()))
        path = export_smv(
            sc.deployment, sc.policy, sc.invariants or None,
            OUT / f"{sc.name}.smv",
            witness=" → ".join(describe(a).split("  ")[0] for a in witness.path),
        )
        exported.append(path)
    print(RULE)
    print(f"已导出 {len(exported)} 个 NuSMV 模型到 {OUT.name}/（属性: CTLSPEC AG !bad）")

    # ---- 报告文件 ----
    if "--no-write" not in argv:
        md = render_markdown(results, fails, (time.perf_counter() - t0) * 1000)
        (ROOT / "report.md").write_text(md, encoding="utf-8")
        print(f"已写入 report.md（{len(md.splitlines())} 行）")

    print(RULE)
    print(f"耗时 {(time.perf_counter() - t0) * 1000:.0f} ms")
    return 0 if fails == 0 else 1


def render_markdown(results: list[dict], fails: int, ms: float) -> str:
    L = ["# ChainBreak 判定报告", ""]
    L.append("> 自动化生成。安全属性 G 的判定结果：UNSAFE 有见证，SAFE 为状态空间穷尽后的证明。")
    L.append("")
    L.append("| 编号 | 场景 | 部署 | 策略 | 判定 | 期望 | 状态数 |")
    L.append("|---|---|---|---|---|---|---|")
    for item in results:
        sc, r = item["scenario"], item["report"]
        L.append(f"| {sc.name.split('_')[0]} | {sc.title} | {sc.deployment.name} | "
                 f"{sc.policy.name} | **{verdict_word(r.verdict)}** | {sc.expect} | {r.states_explored} |")
    L += ["", f"共 {len(results)} 个场景，期望不符 {fails} 个，耗时 {ms:.0f} ms。", ""]

    L += ["## 发现", ""]
    for item in results:
        sc, r = item["scenario"], item["report"]
        if r.verdict != "unsafe":
            continue
        L.append(f"### {sc.name.split('_')[0]} · {sc.title}")
        L.append("")
        L.append(f"- 策略：`{sc.policy.name}`")
        L.append(f"- 备注：{sc.note}")
        for tid, f in sorted(r.findings.items()):
            kind, single = locality(sc, tid)
            tag = "组合漏洞" if kind == "组合" else f"局部缺陷（{single} 单独即可复现）"
            L.append(f"- **[{tid}] {f.template.name}** — {tag}")
            L.append(f"  - 链路：`{' → '.join(describe(a).split('  ')[0] for a in f.path)}`")
            L.append(f"  - 依据：{f.detail}")
        L.append("")

    L += ["## 判定口径", "",
          "| 判定 | 条件 | 证据强度 |", "|---|---|---|",
          "| UNSAFE | 找到全合规反例 | 见证即证据 |",
          "| SAFE | 状态空间穷尽且无反例 | 相对模型与过近似抽象的证明 |",
          "| UNKNOWN | 触达状态上限 | 既不能说不安全，也不能说安全 |", ""]
    L += ["## 限制", "",
          "1. 标签是抽象格，只能给 may-dependency；",
          "2. F7 用「上下文含不可信内容」近似「指令来自不可信内容」，会误伤正常链式操作；",
          "3. 服务器 EFSM 由模板实例化，不是从真实实现自动学习；",
          "4. 单服务器隔离检测模拟的是该服务器的测试套件，不是全部行为；",
          "5. SAFE 只相对被检验的属性集合。", ""]
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
