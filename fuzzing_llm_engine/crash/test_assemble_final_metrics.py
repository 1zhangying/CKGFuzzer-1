#!/usr/bin/env python3
"""Contract tests for fail-closed 1217-row metric assembly."""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from crash import assemble_final_1217_metrics as assembly


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _result(
    crash_id: str,
    result: bool,
    *,
    prompt: str,
    evidence: str,
    run_variant: str,
    engine: str,
) -> dict:
    return {
        "Project": "p1",
        "CrashID": crash_id,
        "Status": "ok",
        "Result": str(result).lower(),
        "LLMModel": "model-a",
        "PromptVariant": prompt,
        "EvidenceVariant": evidence,
        "RunVariant": run_variant,
        "AnalysisEngine": engine,
        "PromptSHA256": f"sha-{crash_id}-{prompt}",
        "ExperimentFingerprint": "fingerprint-a",
        "InputFingerprint": "input-fingerprint-a",
    }


class AssembleFinalMetricsTest(unittest.TestCase):
    def test_member_ground_truth_is_used_and_missing_results_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.csv"
            mapping = root / "mapping.csv"
            _write_csv(baseline, [
                {"Project": "p1", "CrashID": "a", "GroundTruth": "true"},
                {"Project": "p1", "CrashID": "b", "GroundTruth": "false"},
                {"Project": "p1", "CrashID": "c", "GroundTruth": "true"},
            ])
            _write_csv(mapping, [
                {"Project": "p1", "CrashID": "a", "RepresentativeCrashID": "a"},
                {"Project": "p1", "CrashID": "b", "RepresentativeCrashID": "a"},
                {"Project": "p1", "CrashID": "c", "RepresentativeCrashID": "a"},
            ])
            v0 = root / "v0.csv"
            v1 = root / "v1.csv"
            v3 = root / "v3.csv"
            v4 = root / "v4.csv"
            _write_csv(v0, [
                _result(
                    crash_id,
                    False,
                    prompt="direct_v1",
                    evidence="raw_no_context",
                    run_variant="V0",
                    engine="ckgfuzzer",
                )
                for crash_id in ("a", "b", "c")
            ])
            _write_csv(v1, [
                _result("a", True, prompt="direct_v1", evidence="triage_no_context", run_variant="V1", engine="crashsage"),
                _result("b", False, prompt="direct_v1", evidence="triage_no_context", run_variant="V1", engine="crashsage"),
                _result("c", True, prompt="direct_v1", evidence="triage_no_context", run_variant="V1", engine="crashsage"),
            ])
            _write_csv(v3, [
                _result("a", True, prompt="direct_v1", evidence="full", run_variant="V3", engine="crashsage"),
            ])
            _write_csv(v4, [
                _result("a", True, prompt="differential", evidence="full", run_variant="V4", engine="crashsage"),
            ])
            output = root / "output"
            argv = [
                "assemble",
                "--baseline", str(baseline),
                "--mapping", str(mapping),
                "--output", str(output),
                "--v0-result", str(v0),
                "--v1-result", str(v1),
                "--v3-result", str(v3),
                "--v4-result", str(v4),
            ]
            with mock.patch.object(assembly.sys, "argv", argv):
                assembly.main()

            with (output / "final_v2_expanded_1217.csv").open(
                encoding="utf-8"
            ) as handle:
                v2_rows = list(csv.DictReader(handle))
            self.assertEqual(
                [row["GroundTruth"] for row in v2_rows],
                ["true", "false", "true"],
            )
            self.assertEqual(
                {row["RepresentativeGroundTruth"] for row in v2_rows},
                {"true"},
            )
            self.assertEqual(
                [row["Prediction"] for row in v2_rows],
                ["true", "false", "true"],
            )

            with (output / "final_overall_metrics_v0_v4_1217.csv").open(
                encoding="utf-8"
            ) as handle:
                metrics = {row["Variant"]: row for row in csv.DictReader(handle)}
            self.assertEqual(metrics["V2"]["TP"], "2")
            self.assertEqual(metrics["V2"]["FP"], "0")
            self.assertEqual(metrics["V2"]["TN"], "1")

            _write_csv(v3, [
                _result("b", True, prompt="direct_v1", evidence="full", run_variant="V3", engine="crashsage"),
            ])
            with (
                mock.patch.object(assembly.sys, "argv", argv),
                mock.patch.object(assembly, "load", wraps=assembly.load),
            ):
                with self.assertRaises(ValueError):
                    assembly.main()


if __name__ == "__main__":
    unittest.main()
