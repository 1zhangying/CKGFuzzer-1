"""Offline checks for the isolated paper-revision experiment tooling."""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from crash import revision_experiment as revision


class RevisionExperimentTest(unittest.TestCase):
    def _write_source(self, path: Path) -> None:
        fields = [
            "Project", "CrashID", "Driver", "DuplicateOf", "GroundTruth",
            "V1_SentToLLM", "V1_IsApiBug", "V1_SkipReason",
            "V2_SentToLLM", "V2_IsApiBug", "V2_SkipReason",
        ]
        rows = [
            {
                "Project": "demo", "CrashID": "driver_1_crash_1", "Driver": "driver_1",
                "DuplicateOf": "", "GroundTruth": "TRUE", "V1_SentToLLM": "TRUE",
                "V1_IsApiBug": "TRUE", "V1_SkipReason": "none", "V2_SentToLLM": "TRUE",
                "V2_IsApiBug": "TRUE", "V2_SkipReason": "none",
            },
            {
                "Project": "demo", "CrashID": "driver_1_crash_2", "Driver": "driver_1",
                "DuplicateOf": "driver_1_crash_1", "GroundTruth": "FALSE", "V1_SentToLLM": "TRUE",
                "V1_IsApiBug": "TRUE", "V1_SkipReason": "none", "V2_SentToLLM": "FALSE",
                "V2_IsApiBug": "TRUE", "V2_SkipReason": "duplicate",
            },
        ]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _write_predictions(self, path: Path, value: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = ["Project", "CrashID", "Result", "Status"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerow({"Project": "demo", "CrashID": "driver_1_crash_1", "Result": value, "Status": "ok"})

    def test_prepare_merge_and_evaluate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.csv"
            output = root / "revision"
            self._write_source(source)
            revision.main(["prepare", "--source", str(source), "--output", str(output)])

            labels = revision._read_csv(output / "ground_truth_v2.csv")
            self.assertEqual(labels[1]["GroundTruthStatus"], revision.STATUS_UNRESOLVED)
            labels[1]["GroundTruthStatus"] = revision.STATUS_NON_TARGET
            labels[1]["IncludeInMetrics"] = "TRUE"
            labels[1]["EvidenceType"] = "driver_root_cause"
            revision._write_csv(output / "ground_truth_v2.csv", revision.GROUND_TRUTH_FIELDS, labels)

            v3 = root / "v3" / "results.csv"
            v4 = root / "v4" / "results.csv"
            self._write_predictions(v3, "true")
            self._write_predictions(v4, "false")
            revision.main([
                "merge", "--output", str(output), "--v3", str(v3), "--v4", str(v4),
            ])
            revision.main(["evaluate", "--output", str(output)])
            results = revision._read_csv(output / "controlled_ablation_results.csv")
            self.assertEqual({row["Variant"] for row in results}, {"V1", "V2", "V3", "V4"})
            v4_result = next(row for row in results if row["Variant"] == "V4")
            self.assertEqual(v4_result["TP"], "0")
            self.assertEqual(v4_result["TN"], "1")

if __name__ == "__main__":
    unittest.main()
