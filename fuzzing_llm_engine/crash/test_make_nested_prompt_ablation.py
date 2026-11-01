import unittest
from pathlib import Path

from crash.make_nested_prompt_ablation import (
    CORE_COMPARISON,
    p0_direct,
    p1_core_differential,
    p2_structured_audit,
)
from crash.make_prompt_ablation import load_jsonl


SOURCE = Path(
    "results/frozen_models_20261030/qwen3-coder-flash_v4_source/"
    "frozen_v4_prompts_96.jsonl"
)


class NestedPromptAblationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prompt = str(load_jsonl(SOURCE)[0]["prompt"])

    def test_p1_adds_comparison_to_p0(self):
        p0 = p0_direct(self.prompt)
        p1 = p1_core_differential(self.prompt)

        self.assertEqual(p1.count(CORE_COMPARISON), 1)
        self.assertGreater(len(p1), len(p0))

    def test_p2_adds_structured_audit(self):
        p1 = p1_core_differential(self.prompt)
        p2 = p2_structured_audit(self.prompt)

        self.assertIn("Hard misuse requires", p2)
        self.assertIn("generally soft concerns", p2)
        self.assertGreater(len(p2), len(p1))

    def test_structured_audit_requires_consistency_fields(self):
        p2 = p2_structured_audit(self.prompt)

        self.assertIn("driver_misuse_evidence_strength", p2)
        self.assertIn("caller_precondition_verdict", p2)
        self.assertIn("is_api_bug", p2)


if __name__ == "__main__":
    unittest.main()
