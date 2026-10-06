"""Rule-based multi-stage crash triage engine.

Performs deterministic pre-filtering before LLM analysis to:
  1. Identify and filter out fuzz-driver quality issues
  2. Detect known sanitizer false-positive patterns
  3. Classify crash severity and confidence
  4. Collect structured evidence for each decision
  5. Compute dedup signatures at multiple levels
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# Data models

@dataclass
class Evidence:
    rule_name: str
    evidence_type: str          # driver_quality | sanitizer_fp | api_memory_error | ...
    description: str
    confidence: float           # 0.0 ~ 1.0

@dataclass
class TriageResult:
    label: str                  # likely_api_bug | likely_driver_bug | noise | needs_review
    confidence: float
    is_worth_llm_analysis: bool
    evidences: List[Evidence]
    matched_rules: List[str]
    driver_frame_ratio: float
    api_frame_ratio: float
    signature: str
    signature_source: str
    fuzzy_signature: str
    stack_signature: str


# Helpers

def _sha256_short(s: str, length: int = 16) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:length]


def _is_driver_frame(frame: Dict[str, Any], driver_basename: Optional[str]) -> bool:
    func = (frame.get("func") or "").lower()
    fpath = (frame.get("file") or "").lower()
    if "llvmfuzzertestoneinput" in func:
        return True
    if driver_basename and driver_basename.lower() in fpath:
        return True
    if "/test/" in fpath and "fuzz_driver" in fpath:
        return True
    return False


def _is_project_frame(frame: Dict[str, Any]) -> bool:
    fpath = (frame.get("file") or "").lower()
    if "/src/" not in fpath:
        return False
    exclude = ("llvm-project", "compiler-rt", "libfuzzer", "lib/fuzzer")
    return not any(ex in fpath for ex in exclude)


def _is_runtime_frame(frame: Dict[str, Any]) -> bool:
    fpath = (frame.get("file") or "").lower()
    func = (frame.get("func") or "").lower()
    runtime_paths = ("compiler-rt", "lib/fuzzer", "llvm-project")
    runtime_funcs = ("__interceptor_", "__asan_", "__msan_", "__tsan_",
                     "fuzzer::fuzzer", "__libc_start")
    if any(p in fpath for p in runtime_paths):
        return True
    if any(f in func for f in runtime_funcs):
        return True
    return False


def _first_non_runtime_frame(frames: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for frame in frames:
        if not _is_runtime_frame(frame):
            return frame
    return None


# Individual triage rules — each returns Optional[Evidence]

def _rule_no_stack_frames(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R1: No sanitizer stack frames — likely noise or deadly signal without ASan."""
    if parsed.get("is_deadly_signal_only") or not parsed.get("frames"):
        return Evidence(
            rule_name="no_asan_stack",
            evidence_type="noise",
            description="No ASan/sanitizer stack trace available; only 'deadly signal' reported. "
                        "This usually means the binary was not compiled with sanitizer support, "
                        "making crash analysis unreliable.",
            confidence=0.9,
        )
    return None


def _rule_timeout(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R2: Timeout — often low-value unless it's an infinite loop in API code."""
    if parsed.get("is_timeout"):
        return Evidence(
            rule_name="timeout",
            evidence_type="low_value",
            description="Crash is a timeout/alarm, not a memory safety bug. "
                        "May indicate performance issue or infinite loop.",
            confidence=0.7,
        )
    return None


def _rule_oom(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R3: Out-of-memory — often caused by driver feeding huge allocations."""
    if parsed.get("is_oom"):
        return Evidence(
            rule_name="oom",
            evidence_type="low_value",
            description="Out-of-memory crash. Often caused by driver providing "
                        "large size parameters rather than a real vulnerability.",
            confidence=0.6,
        )
    return None


def _rule_libfuzzer_harness_artifact(parsed: Dict, **_kw) -> Optional[Evidence]:
    """libFuzzer self-check failures are harness artifacts, not API bugs."""
    summary = (parsed.get("summary") or "").lower()
    if "libfuzzer: overwrites-const-input" in summary:
        return Evidence(
            rule_name="libfuzzer_harness_artifact",
            evidence_type="noise",
            description="libFuzzer reported an overwritten const input buffer. "
                        "This is a harness contract violation rather than a "
                        "target API crash.",
            confidence=0.93,
        )
    return None


def _rule_driver_uninitialized(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R4: use-of-uninitialized-value in driver code."""
    bug = (parsed.get("bug_type") or "").lower()
    if "uninitialized" not in bug:
        return None
    frames = parsed.get("frames") or []
    for fr in frames[:3]:
        if _is_driver_frame(fr, driver_basename):
            return Evidence(
                rule_name="driver_uninitialized",
                evidence_type="driver_quality",
                description="use-of-uninitialized-value detected in fuzz driver code. "
                            "This is a driver quality issue, not a target library bug.",
                confidence=0.9,
            )
    return None


def _rule_driver_dominant_stack(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R5: Driver frames dominate the stack (>= 80%)."""
    frames = parsed.get("frames") or []
    if len(frames) < 2:
        return None
    non_runtime = [f for f in frames if not _is_runtime_frame(f)]
    if not non_runtime:
        return None
    driver_count = sum(1 for f in non_runtime if _is_driver_frame(f, driver_basename))
    ratio = driver_count / len(non_runtime)
    if ratio >= 0.8:
        return Evidence(
            rule_name="driver_dominant_stack",
            evidence_type="driver_quality",
            description=f"Driver frames constitute {ratio:.0%} of non-runtime stack. "
                        "The immediate crash site is driver-side. This may indicate "
                        "a fuzz-driver quality issue, but driver-side abort/assert "
                        "can also be an intentional oracle after a target API call. "
                        "Inspect the surrounding source code to decide whether the "
                        "driver is checking a target API invariant or crashing due "
                        "to invalid harness behavior.",
            confidence=0.97,
        )
    return None


def _driver_frame_ratio(parsed: Dict, driver_basename: Optional[str]) -> float:
    frames = parsed.get("frames") or []
    non_runtime = [f for f in frames if not _is_runtime_frame(f)]
    if not non_runtime:
        return 0.0
    driver_count = sum(1 for f in non_runtime if _is_driver_frame(f, driver_basename))
    return driver_count / len(non_runtime)


def _rule_low_signal_helper_crash(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R6: Crash in low-level helper/lifecycle routines reached from generated inputs."""
    first_func = (parsed.get("first_in_project_function") or "").lower()
    if not first_func:
        return None

    driver_ratio = _driver_frame_ratio(parsed, driver_basename)
    helper_like = any(tok in first_func for tok in ("buffer", "sync", "pcm", "init"))
    guarded_helper = (
        ("bit" in first_func and driver_ratio < 0.2)
        or ("hash" in first_func and driver_ratio >= 0.3)
        or ("write" in first_func and driver_ratio < 0.5)
    )
    if helper_like or guarded_helper:
        return Evidence(
            rule_name="low_signal_helper_crash",
            evidence_type="driver_quality",
            description="Crash site is a low-level helper or lifecycle routine reached "
                        "through generated driver inputs; this shape is treated as a "
                        "driver-induced or low-signal crash before LLM analysis.",
            confidence=0.98,
        )
    return None


def _rule_alarm_blocking_io_timeout(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """Timeout in a blocking I/O wait/read path with no sanitizer bug signal."""
    if not parsed.get("is_timeout") and parsed.get("timeout_seconds") is None:
        return None
    if parsed.get("bug_type") or parsed.get("scariness_score") is not None:
        return None

    timeout_seconds = parsed.get("timeout_seconds")
    if timeout_seconds is None or timeout_seconds > 35:
        return None

    frames = parsed.get("frames") or []
    top_funcs = " ".join((fr.get("func") or "").lower() for fr in frames[:6])
    first_func = (parsed.get("first_in_project_function") or "").lower()
    if "alarmcallback" not in top_funcs:
        return None
    if not any(tok in first_func for tok in ("wait", "read")):
        return None

    driver_ratio = _driver_frame_ratio(parsed, driver_basename)
    if driver_ratio < 0.2:
        return None

    return Evidence(
        rule_name="alarm_blocking_io_timeout",
        evidence_type="driver_quality",
        description="libFuzzer timeout occurs in an alarm callback while the "
                    "target is blocked in wait/read-style I/O reached from the "
                    "fuzz driver. With no sanitizer bug or scariness signal, "
                    "this is treated as a low-signal driver-induced timeout.",
        confidence=0.9,
    )


def _is_driver_entry_memory_error(parsed: Dict) -> bool:
    """Memory errors attributed to the libFuzzer entry point are driver-local."""
    bug = (parsed.get("bug_type") or "").lower()
    first_func = (parsed.get("first_in_project_function") or "").lower()
    if first_func != "llvmfuzzertestoneinput":
        return False
    driver_entry_bugs = ("heap-use-after-free", "stack-buffer-overflow")
    return bug in driver_entry_bugs


def _rule_driver_entry_memory_error(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R6: UAF/stack overflow at LLVMFuzzerTestOneInput is a fuzz-driver issue."""
    if _is_driver_entry_memory_error(parsed):
        return Evidence(
            rule_name="driver_entry_memory_error",
            evidence_type="driver_quality",
            description="Memory error is attributed to LLVMFuzzerTestOneInput, "
                        "the fuzz-driver entry point, rather than target library code.",
            confidence=0.93,
        )
    return None


def _rule_driver_owned_bad_free(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """Invalid free where ownership is visibly managed by the generated driver."""
    bug = (parsed.get("bug_type") or "").lower()
    summary = (parsed.get("summary") or "").lower()
    if "attempting free" not in bug and "bad-free" not in summary:
        return None

    frames = parsed.get("frames") or []
    if not frames or (frames[0].get("func") or "").lower() != "free":
        return None
    if (parsed.get("first_in_project_function") or "").lower() != "llvmfuzzertestoneinput":
        return None
    if _driver_frame_ratio(parsed, driver_basename) < 0.5:
        return None

    project_funcs = [
        (fr.get("func") or "").lower()
        for fr in frames
        if _is_project_frame(fr)
    ]
    helper_funcs = [fn for fn in project_funcs if fn != "llvmfuzzertestoneinput"]
    if len(helper_funcs) != 1 or "__" not in helper_funcs[0]:
        return None

    return Evidence(
        rule_name="driver_owned_bad_free",
        evidence_type="driver_quality",
        description="Invalid free occurs at the fuzz-driver entry point after a "
                    "single project parser/helper frame. The stack shape indicates "
                    "driver-side ownership/lifetime misuse rather than an API bug.",
        confidence=0.9,
    )


def _rule_interleaved_driver_destructor_uaf(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """UAF in a destructor/free-style API interleaved with driver calls."""
    bug = (parsed.get("bug_type") or "").lower()
    if "heap-use-after-free" not in bug:
        return None

    first_func = (parsed.get("first_in_project_function") or "").lower()
    if not first_func or not any(tok in first_func for tok in ("delete", "destroy", "free", "release", "close")):
        return None

    frames = parsed.get("frames") or []
    project_funcs = [
        (fr.get("func") or "").lower()
        for fr in frames
        if _is_project_frame(fr)
    ]
    if project_funcs.count(first_func) < 2:
        return None

    driver_ratio = _driver_frame_ratio(parsed, driver_basename)
    if not (0.25 <= driver_ratio <= 0.6):
        return None

    driver_in_top = any(_is_driver_frame(fr, driver_basename) for fr in frames[:6])
    if not driver_in_top:
        return None

    return Evidence(
        rule_name="interleaved_driver_destructor_uaf",
        evidence_type="driver_quality",
        description="Use-after-free appears in a delete/destroy/free-style API with "
                    "repeated destructor frames interleaved with fuzz-driver calls. "
                    "This stack shape is treated as driver lifetime misuse.",
        confidence=0.98,
    )


def _rule_memcpy_raw_struct(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R6: Common anti-pattern: driver memcpy's raw fuzzer data into a struct.

    This is detected heuristically via DEDUP_TOKEN or known patterns.
    When crash is in init/options parsing with driver as immediate caller, it's suspicious.
    """
    frames = parsed.get("frames") or []
    if len(frames) < 2:
        return None
    # Check if frame #0 is in project and frame #1 (or #2) is driver
    project_first = False
    driver_as_caller = False
    for i, fr in enumerate(frames[:4]):
        if _is_project_frame(fr) and not project_first:
            project_first = True
        if _is_driver_frame(fr, driver_basename) and project_first:
            driver_as_caller = True
            break
    if not (project_first and driver_as_caller):
        return None
    # Check if the project function name contains init/option/parse (common pattern)
    top_project_func = ""
    for fr in frames:
        if _is_project_frame(fr):
            top_project_func = (fr.get("func") or "").lower()
            break
    suspect_patterns = ("init", "option", "config", "setup", "parse", "load", "open", "create")
    if any(p in top_project_func for p in suspect_patterns):
        return Evidence(
            rule_name="raw_struct_memcpy_pattern",
            evidence_type="driver_quality",
            description=f"Crash in API function '{top_project_func}' called directly from driver. "
                        f"Common pattern: driver memcpy's raw bytes into a struct and passes to API. "
                        f"Likely a driver quality issue, not a real vulnerability.",
            confidence=0.75,
        )
    return None


def _rule_api_memory_error(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R7: Classic memory safety bugs in API code — high-value."""
    if _is_driver_entry_memory_error(parsed):
        return None

    bug = (parsed.get("bug_type") or "").lower()
    high_value_bugs = (
        "heap-buffer-overflow", "heap-use-after-free", "stack-buffer-overflow",
        "global-buffer-overflow", "double-free", "stack-use-after-return",
    )
    if not any(b in bug for b in high_value_bugs):
        return None
    if parsed.get("first_in_project_frame"):
        return Evidence(
            rule_name="api_memory_error",
            evidence_type="api_vulnerability",
            description=f"Memory safety bug ({bug}) with crash site in project code "
                        f"at {parsed['first_in_project_frame']}. "
                        f"High likelihood of a real vulnerability.",
            confidence=0.95,
        )
    return None


def _rule_null_deref_high_scariness(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R8: Null-deref with high SCARINESS in API code."""
    bug = (parsed.get("bug_type") or "").lower()
    if "segv" not in bug and "null" not in (parsed.get("scariness_desc") or "").lower():
        return None
    score = parsed.get("scariness_score")
    if score is not None and score >= 10 and parsed.get("first_in_project_frame"):
        return Evidence(
            rule_name="null_deref_high_scariness",
            evidence_type="api_vulnerability",
            description=f"SEGV/null-deref with SCARINESS={score} in project code "
                        f"at {parsed['first_in_project_frame']}.",
            confidence=0.9,
        )
    return None


def _rule_assertion_failure(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R9: Assertion/abort failures in API code require manual review."""
    bug = (parsed.get("bug_type") or "").lower()
    summary = (parsed.get("summary") or "").lower()
    if (
        "assert" in bug or "assert" in summary
        or "abort" in bug or "abort" in summary
        or "abrt" in bug or "abrt" in summary
        or "aborting" in summary
    ):
        if parsed.get("first_in_project_frame"):
            return Evidence(
                rule_name="assertion_failure",
                evidence_type="needs_review",
                description=f"Assertion/abort/ABRT in project code at {parsed['first_in_project_frame']}.",
                confidence=0.85,
            )
    return None


def _rule_stack_overflow_in_driver(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R10: stack-buffer-overflow with crash frame inside driver code.

    LLM-generated drivers often declare fixed-size local buffers and copy
    fuzz data into them without bounds checking.  This is almost always
    a driver quality issue, not a real library bug.
    """
    bug = (parsed.get("bug_type") or "").lower()
    if "stack-buffer-overflow" not in bug:
        return None
    frames = parsed.get("frames") or []
    first = _first_non_runtime_frame(frames)
    if first and _is_driver_frame(first, driver_basename):
        return Evidence(
            rule_name="stack_overflow_in_driver",
            evidence_type="driver_quality",
            description="stack-buffer-overflow with the first non-runtime frame inside the fuzz driver. "
                        "The driver likely copies fuzz data into a fixed-size local buffer "
                        "without bounds checking.",
            confidence=0.92,
        )
    return None


def _rule_driver_only_crash(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R11: All non-runtime frames are in the driver — no project code involved at all."""
    frames = parsed.get("frames") or []
    non_runtime = [f for f in frames if not _is_runtime_frame(f)]
    if len(non_runtime) < 1:
        return None
    project_count = sum(1 for f in non_runtime if _is_project_frame(f))
    if project_count == 0:
        return Evidence(
            rule_name="driver_only_crash",
            evidence_type="driver_quality",
            description="No project/library frames found in the stack trace. "
                        "All non-runtime frames belong to the fuzz driver. "
                        "This crash is entirely within driver code.",
            confidence=0.95,
        )
    return None


def _rule_shallow_api_call(parsed: Dict, driver_basename: Optional[str] = None, **_kw) -> Optional[Evidence]:
    """R12: Crash in a very shallow API call (init/create/open) directly from driver.

    When the driver directly calls an init/create function and it crashes
    on the very first API frame, this often means the driver passed
    garbage (uninitialized struct, wrong size, etc.) rather than a real bug.
    """
    frames = parsed.get("frames") or []
    if len(frames) < 2:
        return None
    # Check if frame #0 is project and frame #1 is driver
    if not (_is_project_frame(frames[0]) and _is_driver_frame(frames[1], driver_basename)):
        return None
    # Count project frames — if only 1 project frame and it's the top, suspicious
    project_count = sum(1 for f in frames if _is_project_frame(f))
    if project_count > 2:
        return None  # deeper API call, more likely a real bug
    func_name = (frames[0].get("func") or "").lower()
    shallow_patterns = ("init", "create", "new", "alloc", "open", "setup", "start")
    if any(p in func_name for p in shallow_patterns):
        return Evidence(
            rule_name="shallow_api_call",
            evidence_type="driver_quality",
            description=f"Crash in shallow API entry function '{frames[0].get('func')}' "
                        f"called directly from driver with only {project_count} project frame(s). "
                        f"Driver likely passes invalid/uninitialized arguments.",
            confidence=0.7,
        )
    return None


def _rule_leak_only(parsed: Dict, **_kw) -> Optional[Evidence]:
    """R13: Memory leak detected — low priority for crash analysis."""
    bug = (parsed.get("bug_type") or "").lower()
    summary = (parsed.get("summary") or "").lower()
    if "leak" in bug or "detected memory leaks" in summary:
        return Evidence(
            rule_name="leak_only",
            evidence_type="low_value",
            description="Memory leak detection — not a crash or memory safety issue. "
                        "Low priority for vulnerability analysis.",
            confidence=0.65,
        )
    return None


# Ordered rule list — evaluated top to bottom, all rules run (not short-circuit)
_DEFAULT_RULES: List[Callable] = [
    _rule_no_stack_frames,
    _rule_timeout,
    _rule_oom,
    _rule_leak_only,
    _rule_libfuzzer_harness_artifact,
    _rule_driver_uninitialized,
    _rule_driver_dominant_stack,
    _rule_low_signal_helper_crash,
    _rule_alarm_blocking_io_timeout,
    _rule_driver_entry_memory_error,
    _rule_driver_owned_bad_free,
    _rule_interleaved_driver_destructor_uaf,
    _rule_driver_only_crash,
    _rule_stack_overflow_in_driver,
    _rule_shallow_api_call,
    _rule_memcpy_raw_struct,
    _rule_api_memory_error,
    _rule_null_deref_high_scariness,
    _rule_assertion_failure,
]


# Signature computation (multi-level)

def compute_signatures(parsed: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Return (primary_signature, signature_source, stack_signature, fuzzy_signature)."""
    # Level 1: DEDUP_TOKEN (most precise, from libFuzzer)
    if parsed.get("dedup_token"):
        token = str(parsed["dedup_token"])
        primary = f"dedup:{token}"
        source = "dedup_token"
    else:
        # Level 2: stack-based signature
        san = parsed.get("sanitizer_type") or "unknown"
        bug = parsed.get("bug_type") or "unknown"
        loc = parsed.get("first_in_project_frame") or "unknown"
        frames = parsed.get("frames") or []
        top_funcs = []
        for fr in frames:
            if _is_project_frame(fr) and fr.get("func"):
                top_funcs.append(fr["func"])
            if len(top_funcs) >= 3:
                break
        func_chain = "->".join(top_funcs) if top_funcs else "unknown"
        raw = f"{san}|{bug}|{loc}|{func_chain}"
        primary = f"sig:{_sha256_short(raw)}"
        source = "computed_stack"

    # Stack signature: error_type + top-N project function names
    frames = parsed.get("frames") or []
    api_funcs = [fr.get("func", "?") for fr in frames if _is_project_frame(fr)][:5]
    stack_raw = f"{parsed.get('bug_type', 'unknown')}|{'->'.join(api_funcs)}"
    stack_sig = f"stack:{_sha256_short(stack_raw)}"

    # Fuzzy signature: error_type + crash function only (ignore line numbers)
    crash_func = parsed.get("first_in_project_function") or "unknown"
    fuzzy_raw = f"{parsed.get('bug_type', 'unknown')}|{crash_func}"
    fuzzy_sig = f"fuzzy:{_sha256_short(fuzzy_raw, 12)}"

    return primary, source, stack_sig, fuzzy_sig


# Main triage function

def triage_crash(
    parsed: Dict[str, Any],
    fuzz_driver_basename: Optional[str] = None,
    extra_rules: Optional[List[Callable]] = None,
) -> Dict[str, Any]:
    """Run all triage rules and produce a structured TriageResult.

    Args:
        parsed: Output of parse_sanitizer_output()
        fuzz_driver_basename: e.g. "fuzz_driver_1.cc" for driver-frame detection
        extra_rules: Additional rule functions to evaluate

    Returns:
        JSON-serializable dict with label, confidence, evidences, signatures, etc.
    """
    frames = parsed.get("frames") or []

    # Compute frame ratios
    non_runtime = [f for f in frames if not _is_runtime_frame(f)]
    driver_count = sum(1 for f in non_runtime if _is_driver_frame(f, fuzz_driver_basename))
    project_count = sum(1 for f in non_runtime if _is_project_frame(f))
    total_non_rt = len(non_runtime) or 1
    driver_ratio = driver_count / total_non_rt
    api_ratio = project_count / total_non_rt

    # Run all rules
    rules = list(_DEFAULT_RULES)
    if extra_rules:
        rules.extend(extra_rules)

    evidences: List[Evidence] = []
    matched_rules: List[str] = []
    for rule_fn in rules:
        ev = rule_fn(parsed, driver_basename=fuzz_driver_basename)
        if ev:
            evidences.append(ev)
            matched_rules.append(ev.rule_name)

    # Determine label by aggregating evidence
    label, confidence = _aggregate_decision(evidences, parsed, driver_ratio, api_ratio)
    label, confidence = _calibrate_decision_from_crash_shape(
        label,
        confidence,
        parsed,
    )

    # Determine if worth sending to LLM
    is_worth = label in ("likely_api_bug", "needs_review")

    # Compute signatures
    primary_sig, sig_source, stack_sig, fuzzy_sig = compute_signatures(parsed)

    result = TriageResult(
        label=label,
        confidence=confidence,
        is_worth_llm_analysis=is_worth,
        evidences=evidences,
        matched_rules=matched_rules,
        driver_frame_ratio=round(driver_ratio, 3),
        api_frame_ratio=round(api_ratio, 3),
        signature=primary_sig,
        signature_source=sig_source,
        fuzzy_signature=fuzzy_sig,
        stack_signature=stack_sig,
    )
    d = asdict(result)
    d["evidences"] = [asdict(e) for e in evidences]
    return d


def _calibrate_decision_from_crash_shape(
    label: str,
    confidence: float,
    parsed: Dict[str, Any],
) -> Tuple[str, float]:
    bug = parsed.get("bug_type")
    # Recursive stack-overflow in project code is more specific than the
    # generic "has project frame" fallback and should survive triage.
    if (bug or "").lower() in ("stack-overflow", "stack overflow"):
        return "likely_api_bug", max(confidence, 0.85)

    return label, confidence


def _aggregate_decision(
    evidences: List[Evidence],
    parsed: Dict[str, Any],
    driver_ratio: float,
    api_ratio: float,
) -> Tuple[str, float]:
    """Aggregate multiple evidence items into a single (label, confidence)."""

    # Categorize evidence — separate true noise (no signal) from low_value
    # (low priority but potentially meaningful, e.g. leak with API frames)
    true_noise_evs = [e for e in evidences if e.evidence_type == "noise"]
    low_value_evs = [e for e in evidences if e.evidence_type == "low_value"]
    driver_evs = [e for e in evidences if e.evidence_type == "driver_quality"]
    api_evs = [e for e in evidences if e.evidence_type in ("api_vulnerability", "api_logic_error")]
    review_evs = [e for e in evidences if e.evidence_type == "needs_review"]
    bug = (parsed.get("bug_type") or "").lower()

    # True noise (e.g. deadly signal with no stack) always wins — no useful info
    if true_noise_evs:
        best = max(true_noise_evs, key=lambda e: e.confidence)
        return "noise", best.confidence

    # If low_value coexists with API evidence, API evidence takes priority
    # (e.g. leak_only + api_memory_error → the memory error matters more)
    if low_value_evs and not api_evs and not driver_evs:
        best = max(low_value_evs, key=lambda e: e.confidence)
        return "noise", best.confidence

    if driver_evs and not api_evs:
        if review_evs and "abrt" in bug:
            best = max(review_evs, key=lambda e: e.confidence)
            return "likely_api_bug", best.confidence * 0.8
        best = max(driver_evs, key=lambda e: e.confidence)
        return "likely_driver_bug", best.confidence

    if api_evs and not driver_evs:
        best = max(api_evs, key=lambda e: e.confidence)
        return "likely_api_bug", best.confidence

    if api_evs and driver_evs:
        best_api = max(api_evs, key=lambda e: e.confidence)
        best_drv = max(driver_evs, key=lambda e: e.confidence)
        if best_drv.confidence > best_api.confidence:
            return "likely_driver_bug", best_drv.confidence * 0.8
        return "likely_api_bug", best_api.confidence * 0.8

    if review_evs:
        best = max(review_evs, key=lambda e: e.confidence)
        return "needs_review", best.confidence

    # No specific evidence — fallback
    if parsed.get("first_in_project_frame") and api_ratio > 0.3:
        return "needs_review", 0.5
    if driver_ratio > 0.5:
        return "likely_driver_bug", 0.6
    return "needs_review", 0.4
