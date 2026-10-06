"""Tests for frozen-prompt corpus validation and replay invariants."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from crash.freeze_v3_prompts import load_frozen_records, write_frozen_records
import replay_frozen_prompts as replay
from replay_frozen_prompts import run_replay


def response_json(is_api_bug: bool = True) -> str:
    return json.dumps({
        "is_api_bug": is_api_bug,
        "crash_category": "Buffer Overflow",
        "root_cause_type": "buffer-overflow",
        "root_cause_location": "src/x.c:1",
        "root_cause_trigger": "input reaches invalid write",
        "severity": "high",
        "data_flow": ["input", "write"],
        "fix_suggestion": "validate length",
    })


class FrozenPromptReplayTest(unittest.TestCase):
    def test_v0_minimal_json_contract_preserves_frozen_prefix(self) -> None:
        prompt = replay.build_replay_prompt("fixed frozen prompt", "v0_minimal_json")
        self.assertTrue(prompt.startswith("fixed frozen prompt"))
        self.assertEqual(
            replay.finalize_v0_minimal_json_response('{"is_api_bug": false}')["is_api_bug"],
            False,
        )

    def test_legacy_v0_direct_verdict_uses_one_model_call(self) -> None:
        result = replay.finalize_legacy_v0_response(
            None,
            "1. Is this an API bug? True\nCrash category: Buffer Overflow",
        )

        self.assertTrue(result["is_api_bug"])
        self.assertEqual(result["crash_category"], "Buffer Overflow")
        self.assertEqual(result["call_count"], 1)
        self.assertEqual(result["decision_parse_mode"], "legacy_local_regex")

    def _prepare(self, root: Path) -> tuple[Path, Path, Path]:
        manifest = root / "manifest.csv"
        artifact_dir = root / "artifacts"
        artifact_dir.mkdir()
        prompt = "fixed prompt text"
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        with manifest.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["Project", "CrashID"])
            writer.writeheader()
            writer.writerow({"Project": "demo", "CrashID": "crash_1"})
        with (artifact_dir / "crash_1.json").open("w", encoding="utf-8") as handle:
            json.dump({
                "project": "demo",
                "crash_id": "crash_1",
                "driver": "driver_1",
                "prompt": prompt,
                "prompt_sha256": prompt_hash,
                "experiment_metadata": {
                    "prompt_variant": "differential",
                    "include_triage": True,
                    "include_static_context": True,
                    "include_runtime_context": True,
                },
            }, handle)
        config = root / "db" / "demo"
        config.mkdir(parents=True)
        (config / "config.yaml").write_text(
            "llm_analyzer:\n  model: qwen-test\n  base_url: http://example.invalid\n  api_key: test\n  temperature: 1.0\n",
            encoding="utf-8",
        )
        return manifest, artifact_dir, root / "db"

    def test_freeze_and_replay_make_one_call_without_rebuilding_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, artifact_dir, db_root = self._prepare(root)
            records = load_frozen_records(manifest, artifact_dir, expected_count=1)
            frozen = root / "frozen.jsonl"
            write_frozen_records(frozen, records, force=False)

            calls: list[str] = []

            class FakeModel:
                def complete(self, prompt: str) -> SimpleNamespace:
                    calls.append(prompt)
                    return SimpleNamespace(text=response_json())

            with patch("replay_frozen_prompts.create_model", return_value=FakeModel()):
                run_replay(Namespace(
                    frozen_prompts=frozen,
                    out_dir=root / "out",
                    db_root=db_root,
                    temperature=0.0,
                    expected_count=1,
                    dry_run=False,
                    resume=False,
                ))

            self.assertEqual(calls, ["fixed prompt text"])
            with (root / "out" / "llm_bool_results.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["Status"], "ok")
            self.assertEqual(rows[0]["PromptSHA256"], records[0]["prompt_sha256"])
            self.assertEqual(rows[0]["FinalCallCount"], "1")
            self.assertEqual(rows[0]["ArchiveMetadataRepairApplied"], "false")
            self.assertEqual(rows[0]["NegativeBoundaryRepairApplied"], "false")

    def test_archive_repair_changes_final_decision_and_is_counted(self) -> None:
        primary = replay._parse_enhanced_json_response(response_json(True))
        repaired = replay._parse_enhanced_json_response(response_json(False))

        def archive_repair(*args, **kwargs):
            return repaired, response_json(False), "test archive boundary"

        with patch("replay_frozen_prompts._repair_archive_metadata_consistency_with_llm", archive_repair), \
             patch("replay_frozen_prompts._repair_negative_boundary_consistency_with_llm", return_value=(repaired, "", "")):
            result = replay.finalize_v3_response(object(), "fixed prompt", response_json(True))

        self.assertFalse(result["is_api_bug"])
        self.assertEqual(result["decision_parse_mode"], "primary_json+archive_metadata_repair")
        self.assertEqual(result["call_count"], 2)
        self.assertTrue(result["archive_metadata_repair"]["applied"])


if __name__ == "__main__":
    unittest.main()
