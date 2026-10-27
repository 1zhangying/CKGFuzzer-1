"""Unit tests for deterministic primary-response parsing in CrashAnalyzer."""
from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from roles.crash_analyzer import (
    CrashAnalyzer,
    _DIFFERENTIAL_ANALYSIS_INSTRUCTIONS,
    _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS,
    _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS,
    _DIFFERENTIAL_V5_ANALYSIS_INSTRUCTIONS,
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

    def test_v0_uses_ckgfuzzer_evidence_without_crashsage_context(self) -> None:
        response_text = self._response(True)

        class _Completion:
            text = response_text

        class _LLM:
            def complete(self, _prompt: str) -> _Completion:
                return _Completion()

        analyzer = object.__new__(CrashAnalyzer)
        analyzer.api_src = {}
        analyzer.llm = _LLM()
        analyzer.extract_potential_error_patterns = lambda _code: ["pattern"]
        analyzer.query_cwe_vulnerabilities = lambda _crash: "CWE-120"

        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "driver.cc"
            driver.write_text("int LLVMFuzzerTestOneInput() { return 0; }")
            result, category, _text, enhanced = analyzer.analyze_crash_ckgfuzzer(
                "ERROR: AddressSanitizer: heap-buffer-overflow",
                str(driver),
                [],
                capture_prompt=True,
            )

        self.assertTrue(result)
        self.assertEqual(category, "Stack Overflow")
        metadata = enhanced["_experiment_metadata"]
        self.assertEqual(metadata["analysis_engine"], "ckgfuzzer")
        self.assertFalse(metadata["include_triage"])
        self.assertFalse(metadata["include_reconstruction_context"])
        self.assertIn("Potential error patterns in API", metadata["prompt"])
        self.assertNotIn("SECTION 1: STATIC ANALYSIS", metadata["prompt"])

    def test_v1_disables_reconstruction_context_even_with_driver_oracle_source(self) -> None:
        response_text = self._response(False)

        class _Completion:
            text = response_text

        class _LLM:
            def complete(self, _prompt: str) -> _Completion:
                return _Completion()

        analyzer = object.__new__(CrashAnalyzer)
        analyzer.api_src = {}
        analyzer.llm = _LLM()
        analyzer.use_memory = False
        analyzer.init_crash = list(CrashAnalyzer.init_crash)
        analyzer.extract_potential_error_patterns = lambda _code: ["pattern"]
        analyzer.query_cwe_vulnerabilities = lambda _crash: "CWE-120"

        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "driver.cc"
            driver.write_text(
                "int LLVMFuzzerTestOneInput() { if (1) __builtin_trap(); return 0; }"
            )
            _result, _category, _text, enhanced = analyzer.analyze_crash_enhanced(
                "ERROR: AddressSanitizer: heap-buffer-overflow",
                str(driver),
                [],
                include_triage=False,
                include_static_context=False,
                include_runtime_context=False,
                include_reconstruction_context=False,
                prompt_variant="direct_v1",
                capture_prompt=True,
            )

        prompt = enhanced["_experiment_metadata"]["prompt"]
        self.assertIn("Reconstruction context is disabled for this variant", prompt)
        self.assertNotIn("POST-CALL ORACLE DETECTED", prompt)

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

    def test_v3_differential_distinguishes_hard_and_soft_misuse(self) -> None:
        prompt = _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS

        self.assertIn("Hard misuse requires exact evidence", prompt)
        self.assertIn("soft concerns, not hard misuse", prompt)
        self.assertIn("Do not return false merely because", prompt)

    def test_v3_differential_contains_no_project_specific_case(self) -> None:
        prompt = _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS.lower()

        for forbidden in (
            "c-ares",
            "cjson",
            "expat",
            "faad2",
            "jansson",
            "json-c",
            "libpcap",
            "libsndfile",
            "libmad",
            "libmspack",
            "tinyxml2",
            "zlib",
            "cve-",
        ):
            self.assertNotIn(forbidden, prompt)

    def test_v4_preserves_positive_boundary_arbitration(self) -> None:
        prompt = _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS

        self.assertIn("target-produced", prompt)
        self.assertIn("target-created state", prompt)
        self.assertIn('decision_basis="target_evidence"', prompt)

    def test_v4_differential_contains_no_project_specific_case(self) -> None:
        prompt = _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS.lower()

        for forbidden in (
            "c-ares",
            "cjson",
            "expat",
            "faad2",
            "jansson",
            "json-c",
            "libpcap",
            "libsndfile",
            "libmad",
            "libmspack",
            "tinyxml2",
            "zlib",
            "cve-",
        ):
            self.assertNotIn(forbidden, prompt)

    def test_v5_starts_from_direct_prompt_with_compact_counterfactual(self) -> None:
        prompt = _DIFFERENTIAL_V5_ANALYSIS_INSTRUCTIONS

        self.assertIn("state the final attribution directly", prompt.lower())
        self.assertIn("compare the target-defect and driver-misuse", prompt)
        self.assertLess(len(prompt), len(_DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS))


if __name__ == "__main__":
    unittest.main()
