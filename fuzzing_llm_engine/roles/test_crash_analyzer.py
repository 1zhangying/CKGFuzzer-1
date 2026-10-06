"""Unit tests for deterministic primary-response parsing in CrashAnalyzer."""
from __future__ import annotations

import unittest

from roles.crash_analyzer import (
    _DIFFERENTIAL_ANALYSIS_INSTRUCTIONS,
    _DIRECT_V1_ANALYSIS_INSTRUCTIONS,
    _parse_enhanced_json_response,
)


class CrashAnalyzerStructuredResponseTest(unittest.TestCase):
    def _response(self, is_api_bug: bool = True) -> str:
        return """{
          "is_api_bug": %s,
          "crash_category": "Stack Overflow",
          "root_cause_type": "stack-overflow",
          "root_cause_location": "src/parser.c:42",
          "root_cause_trigger": "deep recursive input",
          "severity": "high",
          "data_flow": ["input", "parser", "recursive call"],
          "fix_suggestion": "bound recursion depth",
          "confidence": 0.85,
          "decision_basis": "target_evidence",
          "evidence_summary": "The first faulting project frame is parser.c:42."
        }""" % ("true" if is_api_bug else "false")

    def test_primary_json_preserves_false_without_another_llm_call(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        self.assertFalse(parsed.is_api_bug)
        self.assertEqual(parsed.decision_basis, "target_evidence")
        self.assertAlmostEqual(parsed.confidence, 0.85)

    def test_primary_json_accepts_a_markdown_fence(self) -> None:
        parsed = _parse_enhanced_json_response("```json\n" + self._response() + "\n```")
        self.assertTrue(parsed.is_api_bug)
        self.assertEqual(parsed.crash_category, "Stack Overflow")

    def test_primary_json_rejects_incomplete_response(self) -> None:
        with self.assertRaises(ValueError):
            _parse_enhanced_json_response('{"is_api_bug": true}')

    def test_direct_v1_instruction_is_not_a_differential_checklist(self) -> None:
        direct = _DIRECT_V1_ANALYSIS_INSTRUCTIONS.format(
            triage_label="needs_review",
            triage_confidence=0.8,
        ).lower()
        differential = _DIFFERENTIAL_ANALYSIS_INSTRUCTIONS.format(
            triage_label="needs_review",
            triage_confidence=0.8,
            init_crash="heap-overflow",
        ).lower()

        self.assertIn("state the final attribution directly", direct)
        self.assertNotIn("hypothesis", direct)
        self.assertNotIn("checklist", direct)
        self.assertIn("explicitly compare", differential)


if __name__ == "__main__":
    unittest.main()
