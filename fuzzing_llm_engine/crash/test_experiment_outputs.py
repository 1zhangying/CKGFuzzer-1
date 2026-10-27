#!/usr/bin/env python3
"""Tests for project-filtered, non-overwriting experiment exports."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from crash import experiment


def _report(project: str) -> dict:
    return {
        "project": project,
        "analysis_timestamp": "2026-10-25T12:00:00",
        "summary": {
            "total_crashes": 2,
            "old_api_bug_count": 1,
            "new_api_bug_count": 1,
            "judgments_changed": 0,
            "false_positive_rate_old": 0.5,
            "triage_label_distribution": {"target_crash": 1, "noise": 1},
            "unique_crashes_after_dedup": 2,
            "total_crashes_before_dedup": 2,
            "dedup_reduction_ratio": 0.0,
            "llm_calls_saved": 1,
            "llm_calls_saved_ratio": 0.5,
            "ablation_variants": {},
        },
        "crashes": [],
    }


class ExperimentOutputsTest(unittest.TestCase):
    def test_project_filter_and_dated_outputs_preserve_legacy_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db = root / "external_database"
            results = root / "results"
            for project in ("p1", "p2"):
                crash_dir = db / project / "crash" / "driver_1"
                crash_dir.mkdir(parents=True)
                (crash_dir / "crash_analysis.yaml").write_text("[]\n")
            results.mkdir()
            legacy = results / "per_project_summary.csv"
            legacy.write_text("legacy-content\n", encoding="utf-8")

            argv = [
                "crash.experiment",
                "--db-root", str(db),
                "--output", str(results),
                "--mode", "retroanalyze",
                "--project", "p1",
                "--run-tag", "20261025_120000",
            ]
            with (
                mock.patch.object(experiment.sys, "argv", argv),
                mock.patch.object(
                    experiment,
                    "retroanalyze_dir",
                    side_effect=lambda _crash_dir: _report("p1"),
                ),
                mock.patch.object(experiment, "print_summary"),
                mock.patch.object(experiment, "print_aggregate"),
            ):
                experiment.main()

            self.assertEqual(legacy.read_text(encoding="utf-8"), "legacy-content\n")
            self.assertTrue((results / "p1_retro_20261025_120000.yaml").is_file())
            self.assertFalse((results / "p2_retro_20261025_120000.yaml").exists())
            self.assertTrue(
                (results / "per_project_summary_20261025_120000.csv").is_file()
            )
            self.assertTrue(
                (results / "per_crash_detail_20261025_120000.csv").is_file()
            )
            aggregate = yaml.safe_load(
                (results / "aggregate_summary_20261025_120000.yaml").read_text()
            )
            self.assertEqual(aggregate["num_projects"], 1)
            self.assertEqual(aggregate["per_project"][0]["project"], "p1")


if __name__ == "__main__":
    unittest.main()
