from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from crash import run_raw_only_baseline as raw


class RawOnlyBaselineTests(unittest.TestCase):
    def test_prompt_contains_only_the_raw_report(self) -> None:
        prompt = raw.build_raw_only_prompt(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in target_func /src/lib.c:10"
        )
        self.assertEqual(prompt.count("RAW SANITIZER OUTPUT:"), 1)
        self.assertIn("heap-buffer-overflow", prompt)
        self.assertIn('"is_api_bug"', prompt)
        self.assertNotIn("STATIC ANALYSIS", prompt)
        self.assertNotIn("call_chain_context", prompt)
        self.assertNotIn("triage", prompt.lower())

    def test_parse_accepts_the_frozen_boolean_contract(self) -> None:
        result, reason = raw.parse_raw_only_response(
            '{"is_api_bug": true, "reason": "target-side bounds check failed"}'
        )
        self.assertTrue(result)
        self.assertEqual(reason, "target-side bounds check failed")
        self.assertFalse(raw.parse_raw_only_response("```json\n{\"is_api_bug\": false}\n```")[0])
        with self.assertRaises(ValueError):
            raw.parse_raw_only_response("not a decision")

    def test_prepare_bundle_is_complete_and_does_not_embed_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db = root / "db"
            crash_dir = db / "demo" / "crash" / "demo_driver"
            crash_dir.mkdir(parents=True)
            entries = [
                {
                    "crash_1": {
                        "crash_info": "\u001b[31mERROR: AddressSanitizer: heap-buffer-overflow\u001b[0m",
                        "is_api_bug": True,
                    }
                },
                {
                    "crash_2": {
                        "crash_info": "ERROR: AddressSanitizer: use-after-free",
                        "is_api_bug": False,
                    }
                },
            ]
            (crash_dir / "crash_analysis.yaml").write_text(
                yaml.safe_dump(entries),
                encoding="utf-8",
            )
            labels = root / "labels.csv"
            with labels.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["Project", "CrashID", "GroundTruth"],
                )
                writer.writeheader()
                writer.writerow({
                    "Project": "demo",
                    "CrashID": "demo_driver_crash_1",
                    "GroundTruth": "TRUE",
                })
                writer.writerow({
                    "Project": "demo",
                    "CrashID": "demo_driver_crash_2",
                    "GroundTruth": "FALSE",
                })

            output = root / "prepared"
            summary = raw.prepare_bundle(
                label_manifest=labels,
                db_root=db,
                output_dir=output,
                expected_count=2,
                overwrite=False,
            )
            self.assertEqual(summary["count"], 2)
            records = raw.load_prompt_records(output / "prompts.jsonl", 2)
            self.assertEqual(len(records), 2)
            for record in records:
                self.assertNotIn("GroundTruth", record)
                self.assertNotIn(": True", record["prompt"])
                self.assertNotIn("\u001b", record["prompt"])

    def test_metrics_require_exact_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            labels = root / "labels.csv"
            with labels.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["Project", "CrashID", "GroundTruth"],
                )
                writer.writeheader()
                writer.writerow({"Project": "p", "CrashID": "a", "GroundTruth": "TRUE"})
                writer.writerow({"Project": "p", "CrashID": "b", "GroundTruth": "FALSE"})
            results = root / "results.csv"
            with results.open("w", encoding="utf-8", newline="") as handle:
                fields = [
                    "Project",
                    "CrashID",
                    "Status",
                    "Result",
                    "LatencyMs",
                    "NetworkCalls",
                ]
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "Project": "p",
                    "CrashID": "a",
                    "Status": "ok",
                    "Result": "true",
                    "LatencyMs": "100",
                    "NetworkCalls": "1",
                })
                writer.writerow({
                    "Project": "p",
                    "CrashID": "b",
                    "Status": "ok",
                    "Result": "false",
                    "LatencyMs": "200",
                    "NetworkCalls": "1",
                })
            prompts = [
                {"project": "p", "crash_id": "a"},
                {"project": "p", "crash_id": "b"},
            ]
            metric = raw.evaluate_run(prompts, results, labels)
            self.assertEqual((metric["TP"], metric["FP"], metric["TN"], metric["FN"]), (1, 0, 1, 0))
            self.assertEqual(metric["F1"], 1.0)
            self.assertEqual(metric["PrimaryLLMSubmissions"], 2)
            self.assertEqual(metric["NetworkCalls"], 2)

    def test_result_csv_drops_jsonl_only_audit_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            jsonl_path = root / "results.jsonl"
            jsonl_path.write_text(
                json.dumps({
                    **{
                        field: "x"
                        for field in raw.RESULT_FIELDS
                    },
                    "Status": "ok",
                    "RawResponse": '{"is_api_bug": true}',
                    "ForceJSONResponseFormat": "false",
                }) + "\n",
                encoding="utf-8",
            )
            csv_path = root / "results.csv"
            self.assertEqual(raw._write_results_csv(jsonl_path, csv_path), 1)
            rows = raw._read_csv(csv_path)
            self.assertEqual(len(rows), 1)
            self.assertNotIn("RawResponse", rows[0])


if __name__ == "__main__":
    unittest.main()
