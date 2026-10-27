"""Tests for the controlled run/prompt compatibility matrix."""
from __future__ import annotations

import unittest

from crash.run_variant_config import get_variant_config, validate_run_prompt_variant


class RunVariantConfigTest(unittest.TestCase):
    def test_variant_pipeline_is_incremental(self) -> None:
        v0 = get_variant_config("V0")
        v1 = get_variant_config("V1")
        v2 = get_variant_config("V2")
        v3 = get_variant_config("V3")
        v4 = get_variant_config("V4")

        self.assertEqual(v0.analysis_engine, "ckgfuzzer")
        self.assertFalse(v0.use_triage)
        self.assertFalse(v0.use_representatives)
        self.assertFalse(v0.include_reconstruction_context)

        self.assertTrue(v1.filter_reports)
        self.assertFalse(v1.use_representatives)
        self.assertFalse(v1.include_reconstruction_context)

        self.assertTrue(v2.use_representatives)
        self.assertFalse(v2.include_static_context)
        self.assertFalse(v2.include_runtime_context)

        self.assertTrue(v3.include_static_context)
        self.assertTrue(v3.include_runtime_context)
        self.assertEqual(v3.prompt_variant, "direct_v1")

        self.assertEqual(v3.evidence_variant, v4.evidence_variant)
        self.assertEqual(v4.prompt_variant, "differential")

    def test_v0_supports_the_clean_direct_prompt_without_context(self) -> None:
        validate_run_prompt_variant("V0", "direct_v1")

    def test_v2_supports_the_clean_direct_prompt_without_context(self) -> None:
        validate_run_prompt_variant("V2", "direct_v1")

    def test_existing_controlled_pairs_remain_valid(self) -> None:
        for run_variant, prompt_variant in (
            ("V0", "direct_v1"),
            ("V1", "direct_v1"),
            ("V2", "direct_v1"),
            ("V3", "direct_v1"),
            ("V4", "differential"),
        ):
            with self.subTest(run_variant=run_variant, prompt_variant=prompt_variant):
                validate_run_prompt_variant(run_variant, prompt_variant)

    def test_invalid_pair_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "V4 requires"):
            validate_run_prompt_variant("V4", "direct_v1")

        with self.assertRaisesRegex(ValueError, "V0 requires"):
            validate_run_prompt_variant("V0", "differential")


if __name__ == "__main__":
    unittest.main()
