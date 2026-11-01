from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from crash.audit_cve_rootcause import audit


class CveRootCauseAuditTest(unittest.TestCase):
    def test_detects_mixed_cve_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = root / "mapping.csv"
            evidence = root / "evidence.csv"
            with mapping.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["Project", "CrashID", "RepresentativeCrashID"],
                )
                writer.writeheader()
                writer.writerow(
                    {"Project": "p", "CrashID": "a", "RepresentativeCrashID": "a"}
                )
                writer.writerow(
                    {"Project": "p", "CrashID": "b", "RepresentativeCrashID": "a"}
                )
            with evidence.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "Project",
                        "CrashID",
                        "PublicReference",
                        "CrashFile",
                        "CrashFunction",
                        "BugType",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Project": "p",
                        "CrashID": "a",
                        "PublicReference": "CVE-2020-0001",
                        "CrashFile": "a.c",
                        "CrashFunction": "f",
                        "BugType": "SEGV",
                    }
                )
                writer.writerow(
                    {
                        "Project": "p",
                        "CrashID": "b",
                        "PublicReference": "CVE-2020-0002",
                        "CrashFile": "b.c",
                        "CrashFunction": "g",
                        "BugType": "SEGV",
                    }
                )
            group_rows, _, _, summary = audit(mapping, evidence)
        self.assertEqual(group_rows[0]["MixedCVE"], "true")
        self.assertEqual(summary["mixed_cve_groups"], 1)


if __name__ == "__main__":
    unittest.main()
