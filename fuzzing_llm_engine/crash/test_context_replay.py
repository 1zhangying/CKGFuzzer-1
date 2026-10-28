"""Tests for the context-only replay workflow."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crash.context_replay import (
    CrashSelection,
    _compact_runtime_context,
    _first_stack_block,
    _load_manifest_selections,
    _resolve_poc,
    _run_once,
    _update_entry,
    replay_context,
)
from crash.sanitizer_parser import parse_sanitizer_output


CRASH_OUTPUT = """\
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
READ of size 1 at 0x1 thread T0
    #0 0x1000 in doContent /src/example/parser.c:42:3
    #1 0x2000 in LLVMFuzzerTestOneInput /src/example/test/driver.cc:99:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/example/parser.c:42:3 in doContent
"""


class ContextReplayTest(unittest.TestCase):
    def test_poc_falls_back_to_sanitizer_artifact_hint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "build" / "out" / "project" / "crash-abc"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"poc")
            entry = {
                "sanitizer_parsed": {"artifact_path_hint": "./crash-abc"},
            }
            with patch(
                "crash.context_replay._engine_root",
                return_value=root,
            ):
                self.assertEqual(
                    _resolve_poc(entry, "project"),
                    artifact,
                )

    def test_only_first_sanitizer_stack_is_used(self) -> None:
        output = """\
ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x1000 (binary+0x10)
    #1 0x2000 (binary+0x20)

Address 0x1 is located in stack of thread T0
    #0 0x3000 (binary+0x30)
ERROR: libFuzzer: deadly signal
    #0 0x4000 (binary+0x40)
"""
        self.assertEqual(
            _first_stack_block(output),
            "    #0 0x1000 (binary+0x10)\n"
            "    #1 0x2000 (binary+0x20)",
        )

    def test_persisted_runtime_context_is_bounded(self) -> None:
        context = {
            "call_stack": [{"frame_id": index} for index in range(100)],
            "backtrace_text": "x" * 40000,
        }
        compact = _compact_runtime_context(context)
        self.assertEqual(len(compact["call_stack"]), 32)
        self.assertLess(len(compact["backtrace_text"]), 33000)
        self.assertIn("truncated by context_replay", compact["backtrace_text"])

    def test_manifest_selection_is_exact_and_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "representatives.csv"
            manifest.write_text(
                "Project,Driver,CrashID\n"
                "p1,driver_1,p1_driver_1_crash_1\n"
                "p1,driver_1.cc,p1_driver_1_crash_2\n",
                encoding="utf-8",
            )
            selections = _load_manifest_selections(manifest)
        self.assertEqual(
            [(item.project, item.driver, item.crash_id) for item in selections],
            [
                ("p1", "driver_1", "p1_driver_1_crash_1"),
                ("p1", "driver_1", "p1_driver_1_crash_2"),
            ],
        )

    def test_direct_replay_uses_paper_crash_key(self) -> None:
        parsed = parse_sanitizer_output(CRASH_OUTPUT)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "target"
            binary.write_text(
                "#!/bin/sh\n"
                "cat <<'EOF'\n"
                f"{CRASH_OUTPUT}"
                "EOF\n"
                "exit 1\n",
                encoding="utf-8",
            )
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            poc = Path(directory) / "poc"
            poc.write_bytes(b"x")
            result = _run_once(binary, poc, parsed, "driver.cc", 5, {})
        self.assertTrue(result["replay_consistent"])
        self.assertEqual(result["replay_key"]["location"], "/src/example/parser.c:42")

    def test_context_update_only_replaces_context_fields(self) -> None:
        entry = {
            "is_api_bug": True,
            "crash_category": "keep-me",
            "location": {"crash_file": "stale.c"},
        }
        result = {
            "status": "ok",
            "static_context": {
                "status": "available",
                "location": {
                    "crash_file": "/src/example/parser.c",
                    "crash_line": 42,
                    "crash_function": "doContent",
                    "crash_code_snippet": "42| vulnerable();",
                    "call_chain_context": [
                        {"code_snippet": "42| vulnerable();"}
                    ],
                    "symbolized": True,
                },
            },
            "runtime_context": {"reproduced": True},
            "runtime_status": {"status": "available"},
            "direct_replay": {
                "runs": [{"replay_consistent": True}],
                "repro_rate": "1/1",
            },
            "generated_at": "2026-10-28T00:00:00",
        }
        _update_entry(entry, result)
        self.assertTrue(entry["is_api_bug"])
        self.assertEqual(entry["crash_category"], "keep-me")
        self.assertEqual(entry["location"]["crash_function"], "doContent")
        self.assertTrue(entry["gdb_runtime_context"]["reproduced"])

    def test_failed_attempt_does_not_overwrite_valid_runtime_context(self) -> None:
        entry = {"gdb_runtime_context": {"reproduced": True, "stable": True}}
        result = {
            "status": "partial",
            "static_context": {"status": "unavailable", "location": None},
            "runtime_context": {
                "reproduced": False,
                "error_message": "collection failed",
            },
            "runtime_status": {"status": "unavailable"},
            "direct_replay": {"runs": [], "repro_rate": "0/0"},
            "generated_at": "2026-10-28T00:00:00",
        }
        _update_entry(entry, result)
        self.assertTrue(entry["gdb_runtime_context"]["reproduced"])
        self.assertEqual(
            entry["context_replay"]["runtime_context_attempt"]["error_message"],
            "collection failed",
        )

    def test_runtime_collection_is_not_gated_by_direct_replay(self) -> None:
        driver = "driver_1"
        crash_id = f"{driver}_crash_1"
        entry = {
            "sanitizer_parsed": {
                "bug_type": "heap-buffer-overflow",
                "frames": [
                    {
                        "idx": 0,
                        "func": "copy_bits",
                        "file": "/src/example/bitarray.c",
                        "line": 73,
                    }
                ],
            },
            "poc_paths": {"poc": "/tmp/poc"},
        }
        failed_replay = {
            "replay_consistent": False,
            "bug_type": None,
            "first_in_project_frame": None,
            "output_excerpt": "host library mismatch",
        }
        with (
            patch(
                "crash.context_replay._resolve_record_path",
                return_value=(Path("/tmp/crash_analysis.yaml"), driver),
            ),
            patch(
                "crash.context_replay._load_yaml",
                return_value=[{ "crash_1": entry }],
            ),
            patch(
                "crash.context_replay._static_context",
                return_value={"status": "available", "location": {}},
            ),
            patch(
                "crash.context_replay._resolve_binary",
                return_value=(Path("/tmp/target"), "snapshot"),
            ),
            patch(
                "crash.context_replay._resolve_poc",
                return_value=Path("/tmp/poc"),
            ),
            patch(
                "crash.context_replay._run_once",
                return_value=failed_replay,
            ),
            patch(
                "crash.context_replay.collect_runtime_context",
                return_value={
                    "reproduced": False,
                    "error_message": "not reproduced",
                    "collection_method": "docker_gdb",
                },
            ) as collect,
        ):
            replay_context(
                CrashSelection("project", driver, crash_id),
                db_root=Path("/tmp"),
                replay_attempts=1,
                gdb_attempts=1,
                prefer_docker=False,
            )

        collect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
