#!/usr/bin/env python3
"""Rebuild representative mappings and reconstruct V2 from frozen V1 results."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

import yaml

from crash.dedup import DeduplicationEngine
from crash.sanitizer_parser import parse_sanitizer_output
from crash.triage import compute_signatures


def _truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _timestamp_key(value: Any) -> Tuple[int, float, str]:
    text = str(value or "").strip()
    if not text:
        return 2, 0.0, ""
    try:
        return (
            0,
            datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp(),
            text,
        )
    except (TypeError, ValueError):
        return 1, 0.0, text


def _metrics(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    total = 0
    for row in rows:
        total += 1
        predicted = _truth(row["Prediction"])
        expected = _truth(row["GroundTruth"])
        if predicted and expected:
            tp += 1
        elif predicted:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "Samples": total,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def rebuild(args: argparse.Namespace) -> None:
    db_root = Path(args.db_root)
    baseline_path = Path(args.baseline)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    baseline_rows = list(csv.DictReader(
        baseline_path.open(encoding="utf-8-sig")
    ))
    baseline_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in baseline_rows
    }
    old_representatives = {
        (row["Project"], row["CrashID"])
        for row in baseline_rows
        if row.get("DedupStatus") == "representative"
    }

    mapping_rows: List[Dict[str, Any]] = []
    representative_rows: List[Dict[str, Any]] = []
    project_summaries: List[Dict[str, Any]] = []
    projects = [
        path for path in sorted(db_root.iterdir())
        if (path / "crash").is_dir()
    ]
    if len(projects) != args.expected_projects:
        raise ValueError(
            f"Expected {args.expected_projects} projects, found {len(projects)}"
        )

    for project_dir in projects:
        project = project_dir.name
        crashes: List[Dict[str, Any]] = []

        for yaml_path in sorted(
            (project_dir / "crash").glob("*/crash_analysis.yaml")
        ):
            driver = yaml_path.parent.name
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or []
            for item_index, item in enumerate(data):
                if not isinstance(item, dict):
                    continue
                for crash_key, entry in item.items():
                    if not isinstance(entry, dict):
                        continue
                    raw = str(entry.get("crash_info") or "")
                    if not raw.strip():
                        continue
                    if raw.startswith("|"):
                        raw = raw[1:].lstrip("\n")
                    parsed = entry.get("sanitizer_parsed")
                    if not isinstance(parsed, dict):
                        parsed = parse_sanitizer_output(raw)
                    triage = entry.get("triage")
                    if not isinstance(triage, dict):
                        raise ValueError(
                            f"{project}/{driver}/{crash_key}: missing triage"
                        )
                    exact, basis, stack, fuzzy = compute_signatures(parsed)
                    stored = (
                        triage.get("signature") or "",
                        triage.get("stack_signature") or "",
                        triage.get("fuzzy_signature") or "",
                    )
                    if stored != (exact, stack, fuzzy):
                        raise ValueError(
                            f"{project}/{driver}/{crash_key}: stale signatures"
                        )
                    crashes.append({
                        "timestamp": entry.get("timestamp"),
                        "item_index": item_index,
                        "driver": driver,
                        "crash_key": str(crash_key),
                        "crash_id": f"{driver}_{crash_key}",
                        "parsed": parsed,
                        "triage": triage,
                    })

        crashes.sort(key=lambda row: (
            *_timestamp_key(row["timestamp"]),
            row["item_index"],
            row["crash_key"],
        ))

        engine = DeduplicationEngine()
        retained = 0
        for discovery_index, crash in enumerate(crashes):
            if crash["triage"].get("label") in {"noise", "likely_driver_bug"}:
                continue
            retained += 1
            info = engine.add_crash(
                crash["crash_id"],
                crash["triage"],
                crash["parsed"],
                timestamp=crash["timestamp"],
                discovery_index=discovery_index,
            )
            row = {
                "Project": project,
                "Driver": crash["driver"],
                "CrashID": crash["crash_id"],
                "RepresentativeCrashID": info["representative"],
                "IsDuplicate": str(info["is_duplicate"]).lower(),
                "MatchLevel": info.get("match_level") or "",
                "ClusterID": info["cluster_id"],
                "ClusterSize": info["cluster_size"],
                "TriageLabel": crash["triage"].get("label", ""),
                "BugType": crash["parsed"].get("bug_type", ""),
                "Signature": crash["triage"].get("signature", ""),
                "StackSignature": crash["triage"].get("stack_signature", ""),
            }
            mapping_rows.append(row)
            if not info["is_duplicate"]:
                representative_rows.append({
                    "Project": project,
                    "CrashID": crash["crash_id"],
                    "Driver": crash["driver"],
                    "ClusterSize": info["cluster_size"],
                    "TriageLabel": crash["triage"].get("label", ""),
                    "Signature": crash["triage"].get("signature", ""),
                    "StackSignature": crash["triage"].get("stack_signature", ""),
                })

        issues = engine.validate_state()
        if issues:
            raise ValueError(f"{project}: {issues[:10]}")
        if args.write_dedup_db:
            engine.save_to_file(str(project_dir / "crash" / "dedup_db.yaml"))
        project_summaries.append({
            "Project": project,
            "Crashes": len(crashes),
            "Retained": retained,
            "Representatives": engine.get_unique_crash_count(),
            "Duplicates": retained - engine.get_unique_crash_count(),
        })

    mapping_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in mapping_rows
    }
    new_representatives = {
        (row["Project"], row["CrashID"]): row
        for row in representative_rows
    }
    new_only = new_representatives.keys() - old_representatives
    removed = old_representatives - new_representatives.keys()

    new_manifest = [
        {
            "Project": project,
            "CrashID": crash_id,
            "Driver": new_representatives[(project, crash_id)]["Driver"],
        }
        for project, crash_id in sorted(new_only)
    ]

    v2_rows: List[Dict[str, Any]] = []
    for baseline in baseline_rows:
        key = (baseline["Project"], baseline["CrashID"])
        if key not in mapping_by_id:
            prediction = False
            representative = ""
            sent = False
            skip_reason = f"triage:{baseline.get('TriageLabel', '')}"
        else:
            representative = mapping_by_id[key]["RepresentativeCrashID"]
            representative_key = (baseline["Project"], representative)
            representative_baseline = baseline_by_id[representative_key]
            prediction = _truth(representative_baseline["V1_IsApiBug"])
            sent = representative == baseline["CrashID"]
            skip_reason = "none" if sent else "duplicate"
        v2_rows.append({
            "Project": baseline["Project"],
            "CrashID": baseline["CrashID"],
            "RepresentativeCrashID": representative,
            "Prediction": str(prediction).lower(),
            "SentToLLM": str(sent).lower(),
            "SkipReason": skip_reason,
            "GroundTruth": baseline["GroundTruth"],
        })

    metrics = _metrics(v2_rows)

    _write_csv(output / "dedup_mapping_14projects.csv", mapping_rows)
    _write_csv(output / "representatives_all_14projects.csv", representative_rows)
    _write_csv(output / "new_representatives_for_v3_v4.csv", new_manifest)
    _write_csv(output / "dedup_project_summary_14projects.csv", project_summaries)
    _write_csv(output / "v2_from_v1_14projects.csv", v2_rows)
    _write_csv(output / "v2_metrics_14projects.csv", [{"Variant": "V2", **metrics}])

    print(f"projects={len(projects)}")
    print(f"mapping={len(mapping_rows)}")
    print(f"representatives={len(representative_rows)}")
    print(f"old_representatives={len(old_representatives)}")
    print(f"new_only_representatives={len(new_manifest)}")
    print(f"removed_old_representatives={len(removed)}")
    print(f"v2={metrics}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-root", default="external_database")
    parser.add_argument(
        "--baseline",
        default="results/all_crashes_v0_v4_groundtruth.csv",
    )
    parser.add_argument(
        "--output",
        default="results/dedup_schema2_14projects_20261027",
    )
    parser.add_argument("--expected-projects", type=int, default=14)
    parser.add_argument(
        "--write-dedup-db",
        action="store_true",
        help="Atomically replace each project's crash/dedup_db.yaml.",
    )
    rebuild(parser.parse_args())


if __name__ == "__main__":
    main()
