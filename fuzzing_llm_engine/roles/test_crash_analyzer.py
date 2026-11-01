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
    EnhancedCrashAnalysis,
    _apply_v4_evidence_calibration,
    _apply_prior_decision,
    _deterministic_decision_consistency_violation,
    _extract_decisive_evidence_context,
    _extract_precondition_risk_context,
    _parse_enhanced_json_response,
    _promote_target_state_memory_safety,
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

    def test_low_confidence_revision_inherits_prior_decision(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        arbitration = _apply_prior_decision(
            parsed,
            "ordinary crash evidence",
            False,
            prompt_variant="direct_v1",
        )
        self.assertTrue(arbitration["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_high_confidence_revision_is_accepted(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 1.0
        arbitration = _apply_prior_decision(
            parsed,
            "ordinary crash evidence",
            False,
            prompt_variant="direct_v1",
        )
        self.assertFalse(arbitration["applied"])
        self.assertTrue(parsed.is_api_bug)

    def test_post_call_oracle_requires_further_support(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="direct_v1",
        )
        self.assertTrue(arbitration["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_differential_driver_oracle_is_accepted(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.95
        parsed.root_cause_type = "Target-side assertion failure"
        parsed.root_cause_location = "target API returned an invalid value"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="differential",
        )
        self.assertFalse(arbitration["applied"])
        self.assertTrue(parsed.is_api_bug)

    def test_high_confidence_target_evidence_overrides_prior_with_oracle(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.98
        parsed.crash_category = "global-buffer-overflow"
        parsed.driver_misuse_evidence_strength = "none"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="differential",
        )
        self.assertFalse(arbitration["applied"])
        self.assertEqual(
            arbitration["reason"],
            "supported_high_confidence_target_evidence",
        )
        self.assertTrue(parsed.is_api_bug)

    def test_complete_target_evidence_does_not_depend_on_model_confidence(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.72
        parsed.crash_category = "namespace confusion"
        parsed.driver_misuse_evidence_strength = "none"
        parsed.caller_precondition_verdict = "valid"
        parsed.target_surface_evidence = (
            "The public parser produced an invalid namespace-separated name."
        )
        parsed.tolerance_contract_evidence = (
            "The public API documents that the separator delimits URI and local name."
        )
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="differential",
        )
        self.assertFalse(arbitration["applied"])
        self.assertEqual(
            arbitration["reason"],
            "complete_post_call_target_evidence",
        )
        self.assertTrue(parsed.is_api_bug)

    def test_v4_rejects_documented_masked_hash_overread(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.crash_category = "heap-buffer-overflow"
        parsed.root_cause_type = "intentional masked word-at-a-time overread"
        parsed.evidence_summary = (
            "The target documents that the masked word-at-a-time overread "
            "is safe and reports no write or corruption."
        )
        audit = _apply_v4_evidence_calibration(
            parsed,
            "ordinary prompt",
            True,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit["reason"], "documented_masked_hash_overread")
        self.assertFalse(parsed.is_api_bug)

    def test_v4_keeps_soft_driver_verdict_for_post_call_oracle(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.driver_misuse_evidence_strength = "soft"
        audit = _apply_v4_evidence_calibration(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(audit["reason"], "explicit_soft_driver_oracle")
        self.assertFalse(parsed.is_api_bug)

    def test_v4_rejects_low_confidence_post_call_target_claim(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.75
        parsed.crash_category = "namespace invariant violation"
        audit = _apply_v4_evidence_calibration(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(
            audit["reason"],
            "low_confidence_post_call_target_claim",
        )
        self.assertFalse(parsed.is_api_bug)

    def test_v4_accepts_high_confidence_unchecked_error_target(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.96
        parsed.crash_category = "null-pointer dereference"
        parsed.root_cause_type = "missing error check after resource open"
        audit = _apply_v4_evidence_calibration(
            parsed,
            "ordinary prompt",
            False,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(
            audit["reason"],
            "high_confidence_unchecked_error_result",
        )
        self.assertTrue(parsed.is_api_bug)

    def test_v4_keeps_confident_hard_driver_stack_verdict(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.confidence = 0.98
        parsed.crash_category = "stack-overflow"
        parsed.driver_misuse_evidence_strength = "hard"
        parsed.decision_basis = "driver_evidence"
        audit = _apply_v4_evidence_calibration(
            parsed,
            (
                "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
                "[CRASH] bug_type=stack-overflow\n"
                "SECTION 3: PRECISE CODE LOCATION"
            ),
            True,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(
            audit["reason"],
            "confident_hard_driver_stack_evidence",
        )
        self.assertFalse(parsed.is_api_bug)

    def test_v4_rejects_low_confidence_stack_exhaustion_claim(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.72
        parsed.crash_category = "stack-overflow"
        parsed.driver_misuse_evidence_strength = "none"
        parsed.decision_basis = "target_evidence"
        audit = _apply_v4_evidence_calibration(
            parsed,
            (
                "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
                "[CRASH] bug_type=stack-overflow\n"
                "SECTION 3: PRECISE CODE LOCATION"
            ),
            True,
        )
        self.assertIsNotNone(audit)
        self.assertEqual(
            audit["reason"],
            "low_confidence_stack_exhaustion_claim",
        )
        self.assertFalse(parsed.is_api_bug)

    def test_target_stack_exhaustion_evidence_overrides_low_confidence_false(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.confidence = 0.72
        parsed.crash_category = "stack-overflow"
        parsed.decision_basis = "driver_evidence"
        parsed.driver_misuse_evidence_strength = "hard"
        parsed.evidence_summary = (
            "The public parser recursively processes attacker-controlled nested "
            "input. The library should enforce a recursion depth limit."
        )
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
                "[CRASH] bug_type=stack-overflow\n"
                "SECTION 3: PRECISE CODE LOCATION"
            ),
            True,
            prompt_variant="differential",
        )
        self.assertTrue(arbitration["applied"])
        self.assertEqual(
            arbitration["reason"],
            "target_stack_exhaustion_evidence",
        )
        self.assertTrue(parsed.is_api_bug)
        self.assertEqual(parsed.driver_misuse_evidence_strength, "soft")

    def test_complete_memory_safety_evidence_does_not_depend_on_confidence(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.85
        parsed.crash_category = "global-buffer-overflow"
        parsed.driver_misuse_evidence_strength = "soft"
        parsed.caller_precondition_verdict = "valid"
        parsed.target_surface_evidence = (
            "A decoder-derived index reads outside a target-owned lookup table."
        )
        parsed.tolerance_contract_evidence = (
            "The public decoder API must reject an out-of-range sampling index."
        )
        parsed.root_cause_type = (
            "missing bounds validation before a global table index"
        )
        arbitration = _apply_prior_decision(
            parsed,
            "ordinary crash evidence",
            False,
            prompt_variant="differential",
        )
        self.assertFalse(arbitration["applied"])
        self.assertEqual(
            arbitration["reason"],
            "complete_target_memory_safety_evidence",
        )
        self.assertTrue(parsed.is_api_bug)

    def test_high_confidence_assertion_does_not_override_prior(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.98
        parsed.crash_category = "assertion_failure"
        parsed.driver_misuse_evidence_strength = "none"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="differential",
        )
        self.assertTrue(arbitration["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_v3_does_not_apply_v4_target_evidence_override(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(True))
        parsed.confidence = 0.98
        parsed.crash_category = "global-buffer-overflow"
        parsed.driver_misuse_evidence_strength = "none"
        parsed.target_surface_evidence = "target parser consumed fuzz input"
        parsed.tolerance_contract_evidence = "public API accepts this input"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "POST-CALL ORACLE DETECTED\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="direct_v1",
        )
        self.assertTrue(arbitration["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_target_created_boundary_overrides_false_model_result(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.confidence = 0.95
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "Target-created exposed object boundary-state candidate\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            False,
            prompt_variant="direct_v1",
        )
        self.assertTrue(arbitration["applied"])
        self.assertTrue(parsed.is_api_bug)

    def test_low_confidence_false_revision_is_rejected(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.confidence = 0.94
        parsed.decision_basis = "driver_evidence"
        parsed.driver_misuse_evidence_strength = "hard"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "Fixed-buffer/fuzz-derived index-count mismatch risk\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            True,
            prompt_variant="direct_v1",
        )
        self.assertTrue(arbitration["applied"])
        self.assertTrue(parsed.is_api_bug)

    def test_supported_high_confidence_false_revision_is_accepted(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.confidence = 0.96
        parsed.decision_basis = "driver_evidence"
        parsed.driver_misuse_evidence_strength = "hard"
        arbitration = _apply_prior_decision(
            parsed,
            (
                "SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT\n"
                "Fixed-buffer/fuzz-derived index-count mismatch risk\n"
                "SECTION 6: TARGET API SOURCE CODE"
            ),
            True,
            prompt_variant="direct_v1",
        )
        self.assertFalse(arbitration["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_memory_safety_with_only_unchecked_init_is_promoted(self) -> None:
        for crash_type in (
            "global-buffer-overflow",
            "heap-buffer-overflow",
            "use-after-free",
        ):
            with self.subTest(crash_type=crash_type):
                parsed = _parse_enhanced_json_response(self._response(False))
                parsed.crash_category = crash_type
                parsed.decision_basis = "driver_evidence"
                parsed.driver_misuse_evidence_strength = "hard"
                parsed.root_cause_location = "src/parser.c:42"
                parsed.evidence_summary = (
                    "The driver ignores the init status, leaving an uninitialized "
                    "decoder state that triggers a target memory failure."
                )
                prompt = (
                    "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
                    f"[CRASH] bug_type={crash_type}\n"
                    "#0 [PROJECT] process_frame @ src/parser.c:42\n"
                    "#1 [PROJECT] parse_frame @ src/parser.c:77\n"
                    "SECTION 3: PRECISE CODE LOCATION\n"
                    "SECTION 5C: CALLER PRECONDITION RISK CONTEXT\n"
                    "Unchecked state/status result risk\n"
                    "SECTION 5D: DECISIVE EVIDENCE AUDIT\n"
                )
                audit = _promote_target_state_memory_safety(
                    parsed,
                    prompt,
                    prompt_variant="differential",
                )
                self.assertTrue(audit["applied"])
                self.assertTrue(parsed.is_api_bug)
                self.assertEqual(
                    parsed.driver_misuse_evidence_strength,
                    "soft",
                )

    def test_memory_safety_repair_keeps_concrete_pointer_error(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.crash_category = "global-buffer-overflow"
        parsed.decision_basis = "driver_evidence"
        parsed.driver_misuse_evidence_strength = "hard"
        parsed.root_cause_location = "src/parser.c:42"
        parsed.evidence_summary = (
            "The driver ignores init status and sets next_in outside the input allocation."
        )
        prompt = (
            "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
            "[CRASH] bug_type=global-buffer-overflow\n"
            "#0 [PROJECT] window_grouping_info @ src/parser.c:42\n"
            "#1 [PROJECT] parse_frame @ src/parser.c:77\n"
            "SECTION 3: PRECISE CODE LOCATION\n"
            "SECTION 5C: CALLER PRECONDITION RISK CONTEXT\n"
            "Unchecked state/status result risk\n"
            "SECTION 5D: DECISIVE EVIDENCE AUDIT\n"
        )
        audit = _promote_target_state_memory_safety(
            parsed,
            prompt,
            prompt_variant="differential",
        )
        self.assertFalse(audit["applied"])
        self.assertFalse(parsed.is_api_bug)

    def test_v3_memory_safety_is_promoted(self) -> None:
        parsed = _parse_enhanced_json_response(self._response(False))
        parsed.crash_category = "global-buffer-overflow"
        parsed.decision_basis = "driver_evidence"
        parsed.driver_misuse_evidence_strength = "hard"
        parsed.root_cause_location = "src/parser.c:42"
        parsed.evidence_summary = "The driver ignores an unchecked init status."
        prompt = (
            "SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)\n"
            "[CRASH] bug_type=global-buffer-overflow\n"
            "#0 [PROJECT] window_grouping_info @ src/parser.c:42\n"
            "#1 [PROJECT] parse_frame @ src/parser.c:77\n"
            "SECTION 3: PRECISE CODE LOCATION\n"
            "SECTION 5C: CALLER PRECONDITION RISK CONTEXT\n"
            "Unchecked state/status result risk\n"
            "SECTION 5D: DECISIVE EVIDENCE AUDIT\n"
        )
        audit = _promote_target_state_memory_safety(
            parsed,
            prompt,
            prompt_variant="direct_v1",
        )
        self.assertTrue(audit["applied"])
        self.assertTrue(parsed.is_api_bug)

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

    def test_complete_v4_analysis_applies_memory_safety_repair(self) -> None:
        response_text = """{
          "caller_precondition_verdict": "violated",
          "driver_misuse_evidence_strength": "hard",
          "driver_misuse_location": "driver.cc:8",
          "precondition_violations": ["init status ignored"],
          "tolerance_contract_evidence": "",
          "is_api_bug": false,
          "crash_category": "global-buffer-overflow",
          "root_cause_type": "invalid-state-decode",
          "root_cause_location": "src/project/lib/parser.c:42",
          "root_cause_trigger": "unchecked initialization",
          "severity": "high",
          "data_flow": ["init", "decode", "index"],
          "fix_suggestion": "check init status",
          "confidence": 0.98,
          "decision_basis": "driver_evidence",
          "evidence_summary": "The driver ignores init status, causing an uninitialized decoder state to index a target-owned array."
        }"""

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
        analyzer.query_cwe_vulnerabilities = lambda _crash: "CWE-125"

        crash_info = """ERROR: AddressSanitizer: global-buffer-overflow
READ of size 1
#0 0x1000 in process_frame /src/project/lib/parser.c:42:1
#1 0x2000 in parse_frame /src/project/lib/parser.c:77:1
#2 0x3000 in LLVMFuzzerTestOneInput /src/project/test/driver.cc:10:1
DEDUP_TOKEN: process_frame--parse_frame
SUMMARY: AddressSanitizer: global-buffer-overflow /src/project/lib/parser.c:42
"""
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "driver.cc"
            driver.write_text(
                """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    int init_result = target_Init(data, size);
    target_Decode(data, size);
    (void)init_result;
    return 0;
}
""",
                encoding="utf-8",
            )
            result, _category, _text, enhanced = analyzer.analyze_crash_enhanced(
                crash_info,
                str(driver),
                [],
                include_triage=False,
                include_static_context=False,
                include_runtime_context=False,
                include_reconstruction_context=True,
                prompt_variant="differential",
                prior_prediction=False,
            )

        self.assertTrue(result)
        repair = enhanced["_experiment_metadata"][
            "target_state_memory_safety_repair"
        ]
        self.assertTrue(repair["applied"])

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

    def test_precondition_context_tracks_fixed_buffer_and_fuzz_index(self) -> None:
        driver = """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    uint8_t* destination = (uint8_t*)malloc(10);
    uint16_t nibble_index = (data[0] << 8) | data[1];
    uint8_t value = data[2];
    set_nibble(nibble_index, value, destination, 10);
    free(destination);
    return 0;
}
"""
        context = _extract_precondition_risk_context(driver)

        self.assertIn(
            "Fixed-buffer/fuzz-derived index-count mismatch risk",
            context,
        )
        self.assertIn("capacity 10", context)
        self.assertIn("nibble_index", context)
        self.assertIn("set_nibble", context)

    def test_hard_driver_misuse_cannot_remain_api_bug(self) -> None:
        result = EnhancedCrashAnalysis(
            caller_precondition_verdict="violated",
            driver_misuse_evidence_strength="hard",
            decision_basis="driver_evidence",
            is_api_bug=True,
            crash_category="stack-buffer-overflow",
            root_cause_type="out-of-bounds",
            root_cause_location="target.c:42",
            root_cause_trigger="invalid caller index",
            severity="high",
            data_flow=["input", "invalid API call"],
            fix_suggestion="validate the caller index",
        )
        violation = _deterministic_decision_consistency_violation(
            result,
            "SECTION 5C: CALLER PRECONDITION RISK CONTEXT\nfixed buffer risk",
        )
        self.assertIn("decision_basis=driver_evidence", violation)

    def test_concrete_tolerance_contract_is_not_overridden(self) -> None:
        result = EnhancedCrashAnalysis(
            caller_precondition_verdict="violated",
            driver_misuse_evidence_strength="hard",
            decision_basis="target_evidence",
            tolerance_contract_evidence=(
                "The public API contract explicitly requires the target to "
                "accept this documented boundary value."
            ),
            is_api_bug=True,
            crash_category="stack-buffer-overflow",
            root_cause_type="out-of-bounds",
            root_cause_location="target.c:42",
            root_cause_trigger="public boundary value",
            severity="high",
            data_flow=["input", "public API"],
            fix_suggestion="validate the boundary",
        )
        self.assertEqual(
            _deterministic_decision_consistency_violation(result, ""),
            "",
        )

    def test_decisive_context_promotes_fixed_buffer_index_mismatch(self) -> None:
        driver = """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t destination[16] = {0};
    uint16_t index = data[0];
    set_nibble(index, data[1], destination, 16);
    return 0;
}
"""
        precondition = _extract_precondition_risk_context(driver)
        decisive = _extract_decisive_evidence_context(
            structured_summary="",
            call_chain_context="",
            driver_oracle_context="",
            precondition_risk_context=precondition,
        )

        self.assertIn("High-priority negative evidence to resolve:", decisive)
        self.assertIn("fixed-size destination", decisive)
        self.assertIn("fuzz-derived index/count", decisive)

    def test_visible_range_guard_keeps_fixed_buffer_candidate_conditional(self) -> None:
        driver = """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t destination[16] = {0};
    uint16_t index = data[0];
    if (index < 16) {
        set_nibble(index, data[1], destination, 16);
    }
    return 0;
}
"""
        context = _extract_precondition_risk_context(driver)

        self.assertIn(
            "Guarded fixed-buffer/fuzz-derived index-count candidate",
            context,
        )
        self.assertNotIn(
            "Fixed-buffer/fuzz-derived index-count mismatch risk",
            context,
        )

    def test_v3_prompt_exposes_fixed_buffer_index_evidence(self) -> None:
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
        analyzer.extract_potential_error_patterns = lambda _code: []
        analyzer.query_cwe_vulnerabilities = lambda _crash: "CWE-787"

        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "driver.cc"
            driver.write_text(
                """
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t* destination = (uint8_t*)malloc(10);
    uint16_t nibble_index = (data[0] << 8) | data[1];
    set_nibble(nibble_index, data[2], destination, 10);
    free(destination);
    return 0;
}
""",
                encoding="utf-8",
            )
            _result, _category, _text, enhanced = analyzer.analyze_crash_enhanced(
                "ERROR: AddressSanitizer: heap-buffer-overflow in copy_bits",
                str(driver),
                [],
                include_triage=False,
                include_static_context=False,
                include_runtime_context=False,
                include_reconstruction_context=True,
                prompt_variant="direct_v1",
                capture_prompt=True,
            )

        prompt = enhanced["_experiment_metadata"]["prompt"]
        self.assertIn(
            "Fixed-buffer/fuzz-derived index-count mismatch risk",
            prompt,
        )
        self.assertIn(
            "fixed-size destination with fuzz-derived index/count",
            prompt,
        )


if __name__ == "__main__":
    unittest.main()
