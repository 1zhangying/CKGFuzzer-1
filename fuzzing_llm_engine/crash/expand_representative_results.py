#!/usr/bin/env python3
"""Materialize representative LLM decisions onto retained metric samples."""

from __future__ import annotations

import argparse
import csv
import glob
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

import yaml


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def truth(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def load_retro_clusters(retro_pattern: str) -> Dict[str, str]:
    clusters = {}
    for retro_path in glob.glob(retro_pattern):
        with open(retro_path, encoding="utf-8") as handle:
            report = yaml.safe_load(handle)
        for crash in report["crashes"]:
            crash_id = crash["crash_id"]
            cluster_id = crash.get("cluster_id")
            if cluster_id:
                clusters[crash_id] = str(cluster_id)
    return clusters


def build_representative_mapping(
    retained_rows: Sequence[Mapping[str, str]],
    retro_clusters: Mapping[str, str],
    max_cluster_size: int,
) -> Dict[str, str]:
    groups: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    for row in retained_rows:
        crash_id = row["CrashID"]
        try:
            cluster_id = retro_clusters[crash_id]
        except KeyError as exc:
            raise KeyError(f"No retro cluster for retained crash {crash_id}") from exc
        groups[(row["Project"], row["Driver"], cluster_id)].append(crash_id)

    representative_by_crash = {}
    for members in groups.values():
        for offset in range(0, len(members), max_cluster_size):
            representative = members[offset]
            for crash_id in members[offset:offset + max_cluster_size]:
                representative_by_crash[crash_id] = representative
    return representative_by_crash


def compute_metrics(rows: Sequence[Mapping[str, str]]) -> Dict[str, int | float]:
    true_positive = false_positive = true_negative = false_negative = 0
    for row in rows:
        prediction = truth(row["Result"])
        ground_truth = truth(row["GroundTruth"])
        if prediction and ground_truth:
            true_positive += 1
        elif prediction:
            false_positive += 1
        elif ground_truth:
            false_negative += 1
        else:
            true_negative += 1
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "TP": true_positive,
        "FP": false_positive,
        "TN": true_negative,
        "FN": false_negative,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def expand(args: argparse.Namespace) -> None:
    manifest_rows = read_csv(Path(args.manifest))
    controlled_rows = {row["CrashID"]: row for row in read_csv(Path(args.controlled))}
    predictions = {row["CrashID"]: row for row in read_csv(Path(args.results)) if row["Status"] == "ok"}
    expected_ids = {row["CrashID"] for row in manifest_rows}
    missing = expected_ids.difference(predictions)
    if missing:
        raise ValueError(f"Missing successful representative results: {sorted(missing)}")

    retained_rows = [
        row for row in controlled_rows.values()
        if row["IncludeInMetrics"] == "TRUE" and row["V1_SentToLLM"] == "TRUE"
    ]
    representative_by_crash = build_representative_mapping(
        retained_rows,
        load_retro_clusters(args.retro_pattern),
        args.max_cluster_size,
    )
    computed_representatives = set(representative_by_crash.values())
    if computed_representatives != expected_ids:
        missing = sorted(expected_ids.difference(computed_representatives))
        unexpected = sorted(computed_representatives.difference(expected_ids))
        raise ValueError(
            "Computed representatives do not match manifest; "
            f"missing={missing}, unexpected={unexpected}"
        )

    expanded_rows = []
    for source in retained_rows:
        crash_id = source["CrashID"]
        source_id = representative_by_crash[crash_id]
        prediction = predictions[source_id]
        expanded_rows.append({
            "Project": source["Project"],
            "CrashID": crash_id,
            "Driver": source["Driver"],
            "RepresentativeCrashID": source_id,
            "PropagationMethod": "retro_cluster_bounded_7",
            "Result": prediction["Result"].strip().lower(),
            "Reason": prediction["Reason"],
            "LLMModel": prediction["LLMModel"],
            "GroundTruth": source["GroundTruth"],
            "GroundTruthStatus": source["GroundTruthStatus"],
        })

    if len(expanded_rows) != args.expected_count:
        raise ValueError(f"Expected {args.expected_count} retained samples, got {len(expanded_rows)}")
    write_csv(Path(args.output), list(expanded_rows[0]), expanded_rows)
    metrics = compute_metrics(expanded_rows)
    print(f"Expanded {len(expanded_rows)} rows to {args.output}")
    print(" ".join(f"{key}={value:.3f}" if isinstance(value, float) else f"{key}={value}" for key, value in metrics.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--controlled", default="results/revision_20260722/controlled_ablation_per_crash.csv")
    parser.add_argument("--retro-pattern", default="results/*_retro.yaml")
    parser.add_argument("--expected-count", type=int, default=258)
    parser.add_argument("--max-cluster-size", type=int, default=7)
    expand(parser.parse_args())


if __name__ == "__main__":
    main()
