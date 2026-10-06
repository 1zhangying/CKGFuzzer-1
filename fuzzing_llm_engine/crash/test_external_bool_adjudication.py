"""Offline prompt-contract checks for the external V4 adjudication runner."""
from __future__ import annotations

import contextlib
import io
import unittest

from crash import external_bool_adjudication as adjudication


class ExternalBoolAdjudicationPromptTest(unittest.TestCase):
    def test_direct_v1_is_a_clean_and_versioned_prompt(self) -> None:
        prompt = adjudication.build_prompt(
            {"crash": {"summary": "demo"}},
            max_prompt_chars=10_000,
            prompt_variant="direct_v1",
        )

        self.assertIn("State the final decision directly", prompt)
        self.assertNotIn("Explicitly compare", prompt)
        self.assertNotIn("hypothesis", prompt.lower())
        self.assertNotIn("checklist", prompt.lower())

    def test_differential_prompt_keeps_its_comparison_instruction(self) -> None:
        prompt = adjudication.build_prompt(
            {"crash": {"summary": "demo"}},
            max_prompt_chars=10_000,
            prompt_variant="differential",
        )

        self.assertIn("Explicitly compare", prompt)

    def test_cli_accepts_only_the_versioned_direct_prompt(self) -> None:
        args = adjudication.parse_args(["--output", "out", "--prompt-variant", "direct_v1"])
        self.assertEqual(args.prompt_variant, "direct_v1")
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                adjudication.parse_args(["--output", "out", "--prompt-variant", "direct"])


if __name__ == "__main__":
    unittest.main()
