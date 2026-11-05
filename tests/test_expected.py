"""断言型回归测试：锁住模拟原型的全部结论。

运行: python3 -m unittest discover -s tests -v
"""

import unittest

from chainbreak import ABC, DATA_ONLY, HARDENED, INFLUENCE_ONLY, INJECT, MAIN, NAIVE, PARTIAL, search


class TestLocalVsGlobal(unittest.TestCase):
    """核心命题：局部安全不蕴含全局安全。"""

    def test_each_server_alone_is_safe(self):
        for scope in ("docs", "staging", "egress"):
            r = search(ABC, NAIVE, scope=(scope,))
            self.assertEqual(r.findings, {}, f"{scope} 单独检测不应有发现")
            self.assertFalse(r.truncated)

    def test_composition_finds_the_abc_chain(self):
        r = search(ABC, NAIVE)
        self.assertIn("F1", r.findings)
        f = r.findings["F1"]
        self.assertEqual(f.depth, 3)
        servers = [a[1] for a in f.path]
        self.assertEqual(servers, ["docs", "staging", "egress"])

    def test_chain_uses_both_argument_and_storage_channels(self):
        f = search(ABC, NAIVE).findings["F1"]
        self.assertIn("模式A", f.mode)  # 路径走参数
        self.assertIn("模式C", f.mode)  # 内容走共享存储

    def test_cross_server_flow_policy_cuts_the_chain(self):
        r = search(ABC, HARDENED)
        self.assertEqual(len(r.findings), 0)
        self.assertFalse(r.truncated)

    def test_removing_one_server_restores_local_safety(self):
        # A⊗B 没有出口，A⊗C 没有共享介质，B⊗C 没有敏感源
        for scope in (("docs", "staging"), ("docs", "egress"), ("staging", "egress")):
            r = search(ABC, NAIVE, scope=scope)
            self.assertEqual(r.findings, {}, f"{scope} 组合不应有发现")


class TestMainDeployment(unittest.TestCase):
    def test_naive_finds_all_seven(self):
        r = search(MAIN, NAIVE)
        self.assertEqual(sorted(r.findings), ["F1", "F2", "F3", "F4", "F5", "F6", "F7"])

    def test_partial_blocks_only_annotation_lie(self):
        r = search(MAIN, PARTIAL)
        self.assertNotIn("F5", r.findings)
        self.assertEqual(len(r.findings), 6)

    def test_hardened_leaves_only_provenance_loss(self):
        r = search(MAIN, HARDENED)
        self.assertEqual(sorted(r.findings), ["F4"])
        self.assertFalse(r.truncated)

    def test_mode_a_and_mode_b_are_distinct_channels(self):
        r = search(MAIN, NAIVE)
        self.assertEqual(r.findings["F1"].mode, "模式A")
        self.assertEqual(r.findings["F2"].mode, "模式B")

    def test_ablation_without_context_edges_loses_mode_b(self):
        r = search(MAIN, NAIVE, allow_ctx=False)
        self.assertNotIn("F2", r.findings)
        self.assertNotIn("F4", r.findings)

    def test_ablation_without_relabel_loses_laundering(self):
        r = search(MAIN, NAIVE, compact_relabel=False)
        self.assertNotIn("F4", r.findings)

    def test_depth_monotone(self):
        prev = set()
        for k in range(1, 7):
            cur = set(search(MAIN, NAIVE, max_depth=k).findings)
            self.assertTrue(prev <= cur, f"depth {k} 丢了发现")
            prev = cur

    def test_witness_length_matches_depth(self):
        for f in search(MAIN, NAIVE).findings.values():
            self.assertEqual(len(f.path), f.depth)
            self.assertEqual(len(f.channels), f.depth)


class TestInjectionChain(unittest.TestCase):
    """你的例子：search 恶意页面 → 诱导 upload 传走 .env。"""

    G = ("F1", "F7")

    def test_each_server_alone_is_safe(self):
        for scope in ("search", "envfs", "upload"):
            r = search(INJECT, NAIVE, scope=(scope,), only=self.G)
            self.assertEqual(r.verdict, "safe", f"{scope} 单独应安全")

    def test_full_chain_violates_both_properties(self):
        r = search(INJECT, NAIVE, only=self.G, all_of=self.G)
        self.assertEqual(r.verdict, "unsafe")
        servers = [a[1] for a in r.findings["F1"].path]
        self.assertEqual(servers, ["search", "envfs", "upload"])

    def test_data_only_defense_leaves_injection_open(self):
        r = search(INJECT, DATA_ONLY, only=self.G)
        self.assertFalse(r.has("F1"))   # 数据标签挡住了泄露
        self.assertTrue(r.has("F7"))    # 但挡不住"上传非敏感内容到恶意地址"
        self.assertEqual(r.verdict, "unsafe")

    def test_influence_only_defense_leaves_plain_leak_open(self):
        r = search(INJECT, INFLUENCE_ONLY, only=self.G)
        self.assertTrue(r.has("F1"))
        self.assertFalse(r.has("F7"))
        self.assertEqual(r.verdict, "unsafe")

    def test_both_defenses_are_necessary_and_sufficient(self):
        r = search(INJECT, HARDENED, only=self.G)
        self.assertEqual(r.verdict, "safe")

    def test_without_search_there_is_no_attacker(self):
        # 数据流上同样泄露，但没有不可信内容 → 只有 F1，没有 F7
        r = search(INJECT, NAIVE, scope=("envfs", "upload"), only=self.G)
        self.assertTrue(r.has("F1"))
        self.assertFalse(r.has("F7"))

    def test_search_is_inbound_not_outbound(self):
        # 检索是取数据，不是外发数据 —— 单独运行必须安全
        r = search(INJECT, NAIVE, scope=("search",), only=("F7",))
        self.assertEqual(r.verdict, "safe")


class TestVerdict(unittest.TestCase):
    """三态判定：unsafe / safe / unknown 各自成立的条件。"""

    def test_alone_is_safe(self):
        for scope in ("docs", "staging", "egress"):
            r = search(ABC, NAIVE, scope=(scope,), only=("F1",))
            self.assertEqual(r.verdict, "safe")

    def test_combined_is_unsafe(self):
        r = search(ABC, NAIVE, only=("F1",))
        self.assertEqual(r.verdict, "unsafe")
        self.assertIn("F1", r.findings)

    def test_hardened_is_safe_and_exhaustive(self):
        r = search(ABC, HARDENED, only=("F1",))
        self.assertEqual(r.verdict, "safe")
        self.assertFalse(r.truncated)

    def test_truncated_search_is_unknown_not_safe(self):
        # 被截断且无发现 → unknown（不能报 safe）
        r = search(ABC, NAIVE, only=("F6",), max_states=2)
        self.assertTrue(r.truncated)
        self.assertEqual(r.findings, {})
        self.assertEqual(r.verdict, "unknown")

    def test_witness_beats_truncation(self):
        # 有见证就是不安全，截断与否不影响这个结论
        r = search(MAIN, NAIVE, max_states=5)
        self.assertTrue(r.truncated)
        self.assertEqual(r.verdict, "unsafe")

    def test_safe_is_relative_to_checked_property(self):
        # 只查 F5 时，组合部署"安全"，但这不是绝对安全
        r = search(ABC, NAIVE, only=("F5",))
        self.assertEqual(r.verdict, "safe")
        self.assertEqual(r.checked, ("F5",))
        self.assertIn("F1", search(ABC, NAIVE, only=("F1",)).findings)


if __name__ == "__main__":
    unittest.main()
