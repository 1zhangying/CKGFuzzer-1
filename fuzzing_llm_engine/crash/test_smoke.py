#!/usr/bin/env python3
"""Smoke test for the enhanced crash analysis pipeline.

Tests all modules against real crash data from the c-ares experiments.
Run: python -m crash.test_smoke  (from fuzzing_llm_engine/)
"""
import json
import sys
import os

# Ensure the parent directory is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.sanitizer_parser import parse_sanitizer_output, format_crash_summary
from crash.triage import triage_crash, compute_signatures
from crash.locator import locate_crash_site, format_call_chain_for_llm
from crash.dedup import DeduplicationEngine
from crash.report import build_crash_report


# --- Real crash samples from c-ares experiments ---

CRASH_DEADLY_SIGNAL_ONLY = """\
ERROR: libFuzzer: deadly signal
NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 5 InsertByte-InsertRepeatedBytes-ChangeByte-ChangeBinInt-InsertByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
artifact_prefix='./'; Test unit written to ./crash-fcb7c559c2ac92f39cb84ab75fca110de30501f1
"""

CRASH_ASAN_SEGV = """\
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55a43fabfe88 bp 0x7ffe4c9ecdd0 sp 0x7ffe4c9ecbe0 T0)
==12==The signal is caused by a READ memory access.
==12==Hint: address points to the zero page.
SCARINESS: 10 (null-deref)
    #0 0x55a43fabfe88 in init_by_options /src/c-ares/src/lib/ares_init.c:428:31
    #1 0x55a43fabfe88 in ares_init_options /src/c-ares/src/lib/ares_init.c:175:12
    #2 0x55a43fabe8b8 in LLVMFuzzerTestOneInput /src/c-ares/test/c-ares_fuzz_driver_False_qwen3-coder-plus_10.cc:81:23
    #3 0x55a43f95be7d in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:619:13
    #4 0x55a43f95b4b5 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:516:7
    #5 0x55a43f95d7f2 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:834:7
    #6 0x55a43f95daf8 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, std::__Fuzzer::allocator<fuzzer::SizedFile>>&) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:872:3
    #7 0x55a43f94c985 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:917:6
    #8 0x55a43f9785f2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #9 0x7ff5c99ff082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)
    #10 0x55a43f93fcdd in _start (/out/c-ares_fuzz_driver_False_qwen3-coder-plus_10+0x48cdd)

DEDUP_TOKEN: init_by_options--ares_init_options--LLVMFuzzerTestOneInput
==12==Register values:
rax = 0x0000000000000000  rbx = 0x00007ffe4c9ecbe0  rcx = 0x0000000000000000  rdx = 0x000055a43fb52000
rdi = 0x00000000000005a8  rsi = 0x0000000000000001  rbp = 0x00007ffe4c9ecdd0  rsp = 0x00007ffe4c9ecbe0
SUMMARY: AddressSanitizer: SEGV /src/c-ares/src/lib/ares_init.c:428:31 in init_by_options
==12==ABORTING
artifact_prefix='./'; Test unit written to ./crash-601508730ba6091bbee742eee7ab68b559ee9aa9
"""

DRIVER_BASENAME = "c-ares_fuzz_driver_False_qwen3-coder-plus_10.cc"

def _sep(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def test_sanitizer_parser():
    _sep("TEST: sanitizer_parser — deadly signal only")
    parsed = parse_sanitizer_output(CRASH_DEADLY_SIGNAL_ONLY)
    assert parsed["is_deadly_signal_only"] is True, f"Expected deadly_signal_only=True, got {parsed['is_deadly_signal_only']}"
    assert parsed["has_asan_stack"] is False
    assert parsed["artifact_path_hint"] is not None
    print(f"  sanitizer_type = {parsed['sanitizer_type']}")
    print(f"  bug_type       = {parsed['bug_type']}")
    print(f"  deadly_signal  = {parsed['is_deadly_signal_only']}")
    print(f"  artifact       = {parsed['artifact_path_hint']}")
    print(f"  frames         = {len(parsed['frames'])}")
    print("  PASS\n")

    _sep("TEST: sanitizer_parser — ASan SEGV with full stack")
    parsed = parse_sanitizer_output(CRASH_ASAN_SEGV)
    assert parsed["sanitizer_type"] == "AddressSanitizer"
    assert parsed["crash_address"] == "0x000000000000"
    assert parsed["scariness_score"] == 10
    assert parsed["dedup_token"] == "init_by_options--ares_init_options--LLVMFuzzerTestOneInput"
    assert len(parsed["frames"]) >= 3
    assert parsed["first_in_project_frame"] == "/src/c-ares/src/lib/ares_init.c:428"
    assert parsed["first_in_project_function"] == "init_by_options"
    assert parsed["has_asan_stack"] is True
    assert len(parsed["registers"]) >= 4
    print(f"  sanitizer_type = {parsed['sanitizer_type']}")
    print(f"  bug_type       = {parsed['bug_type']}")
    print(f"  crash_address  = {parsed['crash_address']}")
    print(f"  scariness      = {parsed['scariness_score']} ({parsed['scariness_desc']})")
    print(f"  dedup_token    = {parsed['dedup_token']}")
    print(f"  frames         = {len(parsed['frames'])}")
    print(f"  first_project  = {parsed['first_in_project_frame']}")
    print(f"  registers      = {len(parsed['registers'])} regs")
    print("  PASS\n")

    _sep("TEST: format_crash_summary")
    summary = format_crash_summary(parsed)
    assert "[CRASH]" in summary
    assert "init_by_options" in summary
    print(summary)
    print("  PASS")


def test_triage():
    _sep("TEST: triage — deadly signal only → noise")
    parsed = parse_sanitizer_output(CRASH_DEADLY_SIGNAL_ONLY)
    triage = triage_crash(parsed, fuzz_driver_basename=DRIVER_BASENAME)
    assert triage["label"] == "noise", f"Expected 'noise', got '{triage['label']}'"
    assert triage["is_worth_llm_analysis"] is False
    assert "no_asan_stack" in triage["matched_rules"]
    print(f"  label      = {triage['label']}")
    print(f"  confidence = {triage['confidence']}")
    print(f"  rules      = {triage['matched_rules']}")
    print(f"  worth_llm  = {triage['is_worth_llm_analysis']}")
    print("  PASS\n")

    _sep("TEST: triage — ASan SEGV → likely_api_bug or needs_review")
    parsed = parse_sanitizer_output(CRASH_ASAN_SEGV)
    triage = triage_crash(parsed, fuzz_driver_basename=DRIVER_BASENAME)
    # This crash has API frames at top + SCARINESS=10 + driver as caller
    # The triage should recognize it as worth analyzing
    print(f"  label      = {triage['label']}")
    print(f"  confidence = {triage['confidence']}")
    print(f"  rules      = {triage['matched_rules']}")
    print(f"  worth_llm  = {triage['is_worth_llm_analysis']}")
    print(f"  driver_ratio = {triage['driver_frame_ratio']}")
    print(f"  api_ratio    = {triage['api_frame_ratio']}")
    print(f"  evidences:")
    for ev in triage.get("evidences", []):
        print(f"    [{ev['evidence_type']}] {ev['rule_name']}: {ev['description'][:80]}...")
    assert triage["is_worth_llm_analysis"] is True
    assert triage["signature"] is not None
    print("  PASS")


def test_signatures():
    _sep("TEST: multi-level signatures")
    parsed = parse_sanitizer_output(CRASH_ASAN_SEGV)
    primary, source, stack, fuzzy = compute_signatures(parsed)
    print(f"  primary = {primary} (source: {source})")
    print(f"  stack   = {stack}")
    print(f"  fuzzy   = {fuzzy}")
    assert primary.startswith("dedup:")
    assert source == "dedup_token"
    assert stack.startswith("stack:")
    assert fuzzy.startswith("fuzzy:")

    # Determinism check
    p2, _, s2, f2 = compute_signatures(parsed)
    assert primary == p2
    assert stack == s2
    assert fuzzy == f2
    print("  Determinism: PASS")
    print("  PASS")


def test_locator():
    _sep("TEST: locator — crash site extraction")
    parsed = parse_sanitizer_output(CRASH_ASAN_SEGV)
    loc = locate_crash_site(parsed, driver_basename=DRIVER_BASENAME)
    print(f"  crash_file     = {loc['crash_file']}")
    print(f"  crash_line     = {loc['crash_line']}")
    print(f"  crash_function = {loc['crash_function']}")
    print(f"  symbolized     = {loc['symbolized']}")
    print(f"  project_frames = {loc['project_frames']}")
    print(f"  driver_frames  = {loc['driver_frames']}")
    print(f"  call_chain     = {len(loc['call_chain_context'])} frames")
    assert loc["crash_file"] == "/src/c-ares/src/lib/ares_init.c"
    assert loc["crash_line"] == 428
    assert loc["crash_function"] == "init_by_options"
    assert loc["project_frames"] >= 2
    assert loc["driver_frames"] >= 1

    chain_str = format_call_chain_for_llm(loc)
    assert "init_by_options" in chain_str
    print("\n  Call chain preview:")
    for line in chain_str.split("\n")[:8]:
        print(f"    {line}")
    print("  PASS")


def test_dedup():
    _sep("TEST: dedup engine")
    engine = DeduplicationEngine()

    parsed1 = parse_sanitizer_output(CRASH_ASAN_SEGV)
    triage1 = triage_crash(parsed1, fuzz_driver_basename=DRIVER_BASENAME)

    res1 = engine.add_crash("crash_1", triage1, parsed1)
    print(f"  crash_1: duplicate={res1['is_duplicate']}, cluster={res1['cluster_id']}")
    assert res1["is_duplicate"] is False

    # Same crash again → should be duplicate
    res2 = engine.add_crash("crash_2", triage1, parsed1)
    print(f"  crash_2: duplicate={res2['is_duplicate']}, of={res2['duplicate_of']}")
    assert res2["is_duplicate"] is True
    assert res2["duplicate_of"] == "crash_1"

    # Different crash
    parsed3 = parse_sanitizer_output(CRASH_DEADLY_SIGNAL_ONLY)
    triage3 = triage_crash(parsed3)
    res3 = engine.add_crash("crash_3", triage3, parsed3)
    print(f"  crash_3: duplicate={res3['is_duplicate']}, cluster={res3['cluster_id']}")
    assert res3["is_duplicate"] is False

    stats = engine.get_dedup_stats()
    print(f"  total={stats['total_crashes']}, unique={stats['unique_crashes']}, "
          f"dedup_ratio={stats['dedup_ratio']}")
    assert stats["total_crashes"] == 3
    assert stats["unique_crashes"] == 2
    print("  PASS")


def test_report():
    _sep("TEST: report generation")
    parsed = parse_sanitizer_output(CRASH_ASAN_SEGV)
    triage = triage_crash(parsed, fuzz_driver_basename=DRIVER_BASENAME)
    loc = locate_crash_site(parsed, driver_basename=DRIVER_BASENAME)

    report = build_crash_report(
        "test_crash_001",
        parsed=parsed,
        triage=triage,
        location=loc,
        enhanced_result={
            "is_api_bug": True,
            "crash_category": "Null Pointer Dereference",
            "root_cause_type": "null-pointer-dereference",
            "root_cause_location": "ares_init.c:428",
            "root_cause_trigger": "unvalidated options struct",
            "severity": "medium",
            "data_flow": ["memcpy(raw) → options struct → init_by_options → deref"],
            "fix_suggestion": "Validate pointer fields before dereferencing",
        },
        dedup_info={"is_duplicate": False, "cluster_id": "cluster_1", "cluster_size": 1},
    )

    assert report["crash_id"] == "test_crash_001"
    assert report["verdict"] == "CONFIRMED_VULNERABILITY"
    assert report["sanitizer"]["bug_type"] is not None
    assert report["location"]["crash_function"] == "init_by_options"
    assert report["analysis"]["severity"] == "medium"
    print(f"  crash_id = {report['crash_id']}")
    print(f"  verdict  = {report['verdict']}")
    print(f"  location = {report['location']['crash_function']} @ {report['location']['crash_file']}:{report['location']['crash_line']}")
    print(f"  severity = {report['analysis']['severity']}")
    print(f"  root_cause = {report['analysis']['root_cause_type']}")
    print(f"  dedup    = cluster={report['dedup']['cluster_id']}, dup={report['dedup']['is_duplicate']}")
    print("  PASS")


def main():
    print("=" * 60)
    print("  Enhanced Crash Analysis Pipeline — Smoke Test")
    print("=" * 60)

    tests = [
        test_sanitizer_parser,
        test_triage,
        test_signatures,
        test_locator,
        test_dedup,
        test_report,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"\n  FAILED: {test_fn.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"  Results: {passed} passed, {failed} failed")
    print(f"{'='*60}")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
