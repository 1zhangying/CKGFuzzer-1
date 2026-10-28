"""Contract tests for validating runtime context against the retained crash."""
from __future__ import annotations

import unittest

from crash.context_validation import (
    parsed_crashes_match,
    runtime_context_matches_parsed,
    static_context_is_complete,
)
from crash.debugger import (
    _generate_gdb_script,
    _parse_gdb_marked_output,
    _sanitizer_environment,
    gdb_runtime_image,
)
from crash.triage import historical_runtime_context_is_compatible


def _parsed() -> dict:
    return {
        "frames": [
            {
                "idx": 0,
                "func": "doContent",
                "file": "/src/example/parser.c",
                "line": 42,
            },
            {
                "idx": 1,
                "func": "LLVMFuzzerTestOneInput",
                "file": "/src/example/test/driver.cc",
                "line": 99,
            },
        ],
        "first_in_project_frame": "/src/example/parser.c:42",
        "first_in_project_function": "doContent",
    }


class HistoricalRuntimeContextValidationTest(unittest.TestCase):
    def test_matching_first_target_frame_is_accepted(self) -> None:
        context = {
            "reproduced": True,
            "call_stack": [
                {"function": "ReportGenericError", "file": "", "line": None},
                {
                    "function": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 42,
                },
                {
                    "function": "LLVMFuzzerTestOneInput",
                    "file": "/src/example/test/driver.cc",
                    "line": 99,
                },
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            _parsed(),
            "driver.cc",
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "matched")
        self.assertTrue(
            historical_runtime_context_is_compatible(
                context,
                _parsed(),
                "driver.cc",
            )
        )

    def test_target_function_with_wrong_location_is_rejected(self) -> None:
        context = {
            "reproduced": True,
            "call_stack": [
                {
                    "function": "other_target_crash",
                    "file": "/src/example/other.c",
                    "line": 7,
                },
                {
                    "function": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 999,
                },
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            _parsed(),
            "driver.cc",
        )
        self.assertFalse(matched)
        self.assertIn("anchor_function_or_location_mismatch", reason)

    def test_following_target_stack_must_match(self) -> None:
        parsed = _parsed()
        parsed["frames"].append(
            {
                "idx": 2,
                "func": "parse_document",
                "file": "/src/example/parser.c",
                "line": 81,
            }
        )
        context = {
            "reproduced": True,
            "call_stack": [
                {
                    "function": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 42,
                },
                {
                    "function": "unrelated_target_path",
                    "file": "/src/example/other.c",
                    "line": 7,
                },
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            parsed,
            "driver.cc",
        )
        self.assertFalse(matched)
        self.assertEqual(reason, "following_stack_mismatch")

    def test_legacy_target_frame_may_omit_debug_location(self) -> None:
        context = {
            "reproduced": True,
            "call_stack": [
                {"function": "__GI_raise", "file": "/lib/libc.so.6", "line": 1},
                {"function": "doContent", "file": None, "line": None},
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            _parsed(),
            "driver.cc",
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "matched")

    def test_libc_memcpy_is_not_a_target_frame(self) -> None:
        context = {
            "reproduced": True,
            "call_stack": [
                {
                    "function": "__memcpy_avx_unaligned_erms",
                    "file": "../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S",
                    "line": 318,
                },
                {
                    "function": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 42,
                },
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            _parsed(),
            "driver.cc",
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "matched")

    def test_driver_anchor_requires_matching_location(self) -> None:
        parsed = {
            "frames": [
                {
                    "idx": 0,
                    "func": "LLVMFuzzerTestOneInput",
                    "file": "/src/example/test/driver.cc",
                    "line": 99,
                }
            ],
            "first_in_project_function": "LLVMFuzzerTestOneInput",
        }
        context = {
            "reproduced": True,
            "call_stack": [
                {"function": "__GI_raise"},
                {"function": "LLVMFuzzerTestOneInput"},
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            parsed,
            "driver.cc",
        )
        self.assertFalse(matched)
        self.assertIn("anchor_function_or_location_mismatch", reason)

    def test_non_reproduced_context_is_rejected(self) -> None:
        context = {
            "reproduced": False,
            "call_stack": [{"function": "doContent"}],
        }
        self.assertFalse(
            historical_runtime_context_is_compatible(
                context,
                _parsed(),
                "driver.cc",
            )
        )

    def test_frameless_stack_overflow_uses_signal_identity(self) -> None:
        parsed = {"bug_type": "stack-overflow", "frames": []}
        context = {
            "reproduced": True,
            "stop_reason": "signal:SIGSEGV",
            "exit_signal": "SIGSEGV",
            "call_stack": [
                {"function": "parse_value", "file": "/src/example/load.c", "line": 30},
            ],
        }
        matched, reason = runtime_context_matches_parsed(
            context,
            parsed,
            "driver.cc",
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "stack_overflow_signal_matched")


class GdbCollectionContractTest(unittest.TestCase):
    def test_docker_collection_uses_gdb_enabled_runner(self) -> None:
        self.assertEqual(
            gdb_runtime_image("libpcap"),
            "gcr.io/oss-fuzz-base/base-runner-debug",
        )

    def test_gdb_script_stops_at_sanitizer_report(self) -> None:
        script = _generate_gdb_script("/tmp/poc", env={})
        self.assertIn("break __asan::ReportGenericError", script)
        self.assertIn("bt 32", script)
        self.assertNotIn("bt 32 full", script)
        self.assertNotIn("set debuginfod enabled off", script)
        self.assertIn("ASAN_OPTIONS", script)
        self.assertIn("abort_on_error=1", script)

    def test_parser_uses_target_frame_and_validates_original(self) -> None:
        output = """\
Thread 1 hit Breakpoint 1, ReportGenericError ()
===GDB_BACKTRACE_START===
#0  0x0000000000000010 in ReportGenericError () at /src/llvm-project/compiler-rt/lib/asan/asan_report.cpp:516
#1  0x0000000000000020 in doContent (buf=0x1) at /src/example/parser.c:42
#2  0x0000000000000030 in LLVMFuzzerTestOneInput () at /src/example/test/driver.cc:99
===GDB_BACKTRACE_END===
===GDB_REGISTERS_START===
rax            0x1
===GDB_REGISTERS_END===
===GDB_FRAME_0_START===
---ARGS---
---LOCALS---
===GDB_FRAME_0_END===
===GDB_FRAME_1_START===
---ARGS---
buf = 0x1
---LOCALS---
length = 16
===GDB_FRAME_1_END===
"""
        context = _parse_gdb_marked_output(
            output,
            expected_crash=_parsed(),
            driver_basename="driver.cc",
        )
        self.assertTrue(context["reproduced"])
        self.assertTrue(context["matches_original"])
        self.assertEqual(context["stop_reason"], "sanitizer_report")
        self.assertEqual(context["crash_frame"]["function"], "doContent")
        self.assertEqual(context["crash_frame"]["locals"]["length"], "16")

    def test_inline_or_secondary_frame_differences_are_normalized(self) -> None:
        expected = {
            "bug_type": "SEGV",
            "frames": [
                {
                    "func": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 42,
                },
                {
                    "func": "parseDocument",
                    "file": "/src/example/parser.c",
                    "line": 60,
                },
                {
                    "func": "LLVMFuzzerTestOneInput",
                    "file": "/src/example/test/driver.cc",
                    "line": 99,
                },
            ],
        }
        observed = {
            "bug_type": "SEGV",
            "frames": [
                {
                    "func": "helper",
                    "file": "/src/example/parser.c",
                    "line": 41,
                },
                {
                    "func": "doContent",
                    "file": "/src/example/parser.c",
                    "line": 42,
                },
                {
                    "func": "parseDocument",
                    "file": "/src/example/parser.c",
                    "line": 60,
                },
                {
                    "func": "LLVMFuzzerTestOneInput",
                    "file": "/src/example/test/driver.cc",
                    "line": 99,
                },
            ],
        }
        matched, reason = parsed_crashes_match(
            expected,
            observed,
            "driver.cc",
        )
        self.assertTrue(matched)
        self.assertEqual(reason, "anchor_and_stack_matched")

    def test_sanitizer_environment_preserves_existing_options(self) -> None:
        env = _sanitizer_environment(
            {"ASAN_OPTIONS": "detect_leaks=1:symbolize=1"}
        )
        self.assertIn("detect_leaks=1", env["ASAN_OPTIONS"])
        self.assertIn("symbolize=1", env["ASAN_OPTIONS"])
        self.assertIn("abort_on_error=1", env["ASAN_OPTIONS"])


class StaticContextContractTest(unittest.TestCase):
    def test_static_context_requires_site_and_chain_source(self) -> None:
        self.assertFalse(
            static_context_is_complete(
                {
                    "crash_code_snippet": "42| vulnerable();",
                    "call_chain_context": [{"code_snippet": None}],
                }
            )
        )
        self.assertTrue(
            static_context_is_complete(
                {
                    "crash_code_snippet": "42| vulnerable();",
                    "call_chain_context": [
                        {"code_snippet": "42| vulnerable();"}
                    ],
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
