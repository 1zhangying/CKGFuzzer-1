from pathlib import Path

import csv

from crash.known_vuln_validation import OUTPUT_COLUMNS, run


def _read_csv(path: Path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def test_known_vuln_validation_outputs(tmp_path):
    summary = run(Path("fuzzing_llm_engine/results"), tmp_path)

    assert summary["validation"]["errors"] == []
    assert summary["per_crash_summary"]["total"] == 123
    assert summary["cluster_summary"]["total"] == 36

    cluster_path = tmp_path / "known_vuln_cluster_validation.csv"
    per_crash_path = tmp_path / "known_vuln_per_crash_validation.csv"
    assert cluster_path.exists()
    assert per_crash_path.exists()

    cluster_rows = _read_csv(cluster_path)
    per_crash_rows = _read_csv(per_crash_path)

    assert len(per_crash_rows) == 123
    assert set(cluster_rows[0]) == set(OUTPUT_COLUMNS)
    assert set(per_crash_rows[0]) == set(OUTPUT_COLUMNS)

    cjson_issue_rows = [
        row for row in cluster_rows if row["MatchedKnownID"] == "GitHub issue #833"
    ]
    assert {row["CrashFunction"] for row in cjson_issue_rows} == {"cJSON_Delete"}

    for row in cluster_rows:
        if row["KnownStatus"] == "confirmed_known":
            assert row["MatchedURL"]
        if row["KnownStatus"] == "not_found":
            assert "searched_queries=" in row["Evidence"]
