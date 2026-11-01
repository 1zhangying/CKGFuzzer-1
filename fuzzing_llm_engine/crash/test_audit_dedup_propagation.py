from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from crash.audit_dedup_propagation import audit


class DedupAuditTest(unittest.TestCase):
    def test_representative_flip_propagates_to_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.csv"
            mapping = root / "mapping.csv"
            with baseline.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["Project", "CrashID", "Prediction", "GroundTruth"],
                )
                writer.writeheader()
                writer.writerow(
                    {"Project": "p", "CrashID": "r", "Prediction": "true", "GroundTruth": "true"}
                )
                writer.writerow(
                    {"Project": "p", "CrashID": "d", "Prediction": "true", "GroundTruth": "true"}
                )
            with mapping.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "Project",
                        "CrashID",
                        "RepresentativeCrashID",
                        "MatchLevel",
                        "Signature",
                        "StackSignature",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Project": "p",
                        "CrashID": "r",
                        "RepresentativeCrashID": "r",
                        "MatchLevel": "",
                        "Signature": "s",
                        "StackSignature": "k",
                    }
                )
                writer.writerow(
                    {
                        "Project": "p",
                        "CrashID": "d",
                        "RepresentativeCrashID": "r",
                        "MatchLevel": "exact",
                        "Signature": "s",
                        "StackSignature": "k",
                    }
                )
            group_rows, flip_rows, summary = audit(baseline, mapping)
        self.assertEqual(group_rows[0]["GroupSize"], 2)
        self.assertEqual(flip_rows[0]["TP"], 0)
        self.assertEqual(flip_rows[0]["FN"], 2)
        self.assertEqual(summary["original_metrics"]["TP"], 2)


if __name__ == "__main__":
    unittest.main()
