"""场景级回归测试：每个 JSON 场景的判定必须等于它声明的 expect。

运行: python3 -m unittest discover -s tests -v
"""

import unittest
from pathlib import Path

from chainbreak import TEMPLATES, search
from chainbreak.scenario import load_all

SCEN = Path(__file__).resolve().parent.parent / "scenarios"


class TestScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = load_all(SCEN)

    def test_all_scenarios_present(self):
        self.assertGreaterEqual(len(self.scenarios), 10)

    def test_every_scenario_matches_its_expectation(self):
        for sc in self.scenarios:
            with self.subTest(scenario=sc.name):
                r = search(sc.deployment, sc.policy, scope=sc.scope,
                           only=sc.invariants or None, all_of=sc.all_of)
                self.assertEqual(r.verdict, sc.expect,
                                 f"{sc.name}: 期望 {sc.expect}，实际 {r.verdict}")

    def test_safe_scenarios_are_exhaustive(self):
        # SAFE 必须是"穷尽后无反例"，不能是被截断
        for sc in self.scenarios:
            if sc.expect != "safe":
                continue
            r = search(sc.deployment, sc.policy, scope=sc.scope,
                       only=sc.invariants or None, all_of=sc.all_of)
            self.assertFalse(r.truncated, f"{sc.name} 被截断却报了 SAFE")

    def test_invariants_are_known(self):
        ids = {t.id for t in TEMPLATES}
        for sc in self.scenarios:
            for inv in sc.invariants:
                self.assertIn(inv, ids, f"{sc.name} 引用了未知属性 {inv}")

    def test_shadow_tool_is_local_not_compositional(self):
        sc = next(s for s in self.scenarios if s.name == "09_shadow_tool")
        r = search(sc.deployment, sc.policy, only=sc.invariants)
        self.assertTrue(r.has("F5"))
        # 单台 net 单独就能复现 → 不是组合漏洞
        single = search(sc.deployment, sc.policy, scope=("net",), only=("F5",))
        self.assertTrue(single.has("F5"))

    def test_injection_chain_spans_three_servers(self):
        sc = next(s for s in self.scenarios if s.name == "01_search_upload")
        r = search(sc.deployment, sc.policy, only=sc.invariants, all_of=sc.all_of)
        servers = [a[1] for a in r.findings["F1"].path]
        self.assertEqual(servers, ["search", "envfs", "upload"])


if __name__ == "__main__":
    unittest.main()
