#!/usr/bin/env python3
"""Audit representative-label propagation without rerunning the LLM.

This script uses the saved CrashSage representative mapping and the frozen
V4 predictions.  It reports group composition and flips each representative
decision in turn to measure how a representative-level error changes the
expanded 1,217-report metrics.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence


GROUP_FIELDS = [
    "Project",
    "RepresentativeCrashID",
    "GroupSize",
    "RepresentativePrediction",
    "RepresentativeGroundTruth",
    "ExactSignatureCount",
    "StackSignatureCount",
    "ExactMatchMembers",
    "StackMatchMembers",
]
FLIP_FIELDS = [
    "Project",
    "RepresentativeCrashID",
    "GroupSize",
    "OriginalPrediction",
    "FlippedPrediction",
    "TP",
    "FP",
    "TN",
    "FN",
    "Precision",
    "Recall",
    "F1",
    "DeltaTP",
    "DeltaFP",
    "DeltaTN",
    "DeltaFN",
    "DeltaF1",
]


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _metrics(
    labels: Sequence[bool],
    predictions: Sequence[bool],
) -> Dict[str, float | int]:
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, predictions):
        if prediction and label:
            tp += 1
        elif prediction:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def audit(
    baseline_path: Path,
    mapping_path: Path,
) -> tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, object]]:
    baseline_rows = _read_csv(baseline_path)
    required_baseline = {"Project", "CrashID", "Prediction", "GroundTruth"}
    missing = required_baseline.difference(
        baseline_rows[0].keys() if baseline_rows else []
    )
    if missing:
        raise ValueError(f"Prediction file is missing columns: {sorted(missing)}")
    baseline = {
        (row["Project"], row["CrashID"]): row for row in baseline_rows
    }

    mapping_rows = _read_csv(mapping_path)
    required_mapping = {
        "Project",
        "CrashID",
        "RepresentativeCrashID",
        "MatchLevel",
        "Signature",
        "StackSignature",
    }
    missing = required_mapping.difference(
        mapping_rows[0].keys() if mapping_rows else []
    )
    if missing:
        raise ValueError(f"Dedup mapping is missing columns: {sorted(missing)}")

    groups: Dict[tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
    row_indices: Dict[tuple[str, str], int] = {}
    for index, row in enumerate(baseline_rows):
        row_indices[(row["Project"], row["CrashID"])] = index
    for row in mapping_rows:
        key = (row["Project"], row["CrashID"])
        if key not in baseline:
            raise ValueError(f"Mapped crash is missing from predictions: {key}")
        groups[(row["Project"], row["RepresentativeCrashID"])].append(row)

    labels = [
        _truth(row.get("MemberGroundTruth") or row["GroundTruth"])
        for row in baseline_rows
    ]
    original_predictions = [_truth(row["Prediction"]) for row in baseline_rows]
    original_metrics = _metrics(labels, original_predictions)

    group_rows = []
    flip_rows = []
    for (project, representative), members in sorted(groups.items()):
        representative_key = (project, representative)
        if representative_key not in baseline:
            raise ValueError(f"Missing representative prediction: {representative}")
        representative_row = baseline[representative_key]
        member_indices = [
            row_indices[(row["Project"], row["CrashID"])] for row in members
        ]
        exact_signatures = {
            row["Signature"] for row in members if row["Signature"]
        }
        stack_signatures = {
            row["StackSignature"] for row in members if row["StackSignature"]
        }
        match_levels = Counter(row["MatchLevel"] or "representative" for row in members)
        group_rows.append(
            {
                "Project": project,
                "RepresentativeCrashID": representative,
                "GroupSize": len(members),
                "RepresentativePrediction": str(
                    _truth(representative_row["Prediction"])
                ).lower(),
                "RepresentativeGroundTruth": str(
                    _truth(
                        representative_row.get("MemberGroundTruth")
                        or representative_row["GroundTruth"]
                    )
                ).lower(),
                "ExactSignatureCount": len(exact_signatures),
                "StackSignatureCount": len(stack_signatures),
                "ExactMatchMembers": match_levels["exact"],
                "StackMatchMembers": match_levels["stack"],
            }
        )

        flipped = list(original_predictions)
        original = original_predictions[representative_index := row_indices[representative_key]]
        for index in member_indices:
            flipped[index] = not original
        metrics = _metrics(labels, flipped)
        flip_rows.append(
            {
                "Project": project,
                "RepresentativeCrashID": representative,
                "GroupSize": len(members),
                "OriginalPrediction": str(original).lower(),
                "FlippedPrediction": str(not original).lower(),
                **metrics,
                "DeltaTP": metrics["TP"] - original_metrics["TP"],
                "DeltaFP": metrics["FP"] - original_metrics["FP"],
                "DeltaTN": metrics["TN"] - original_metrics["TN"],
                "DeltaFN": metrics["FN"] - original_metrics["FN"],
                "DeltaF1": metrics["F1"] - original_metrics["F1"],
            }
        )

    nonempty_exact_counts = [
        row["ExactSignatureCount"] for row in group_rows if row["ExactSignatureCount"]
    ]
    nonempty_stack_counts = [
        row["StackSignatureCount"] for row in group_rows if row["StackSignatureCount"]
    ]
    changes = sorted(
        flip_rows,
        key=lambda row: abs(float(row["DeltaF1"])),
        reverse=True,
    )
    worst = changes[0] if changes else None
    summary = {
        "samples": len(baseline_rows),
        "mapped_reports": len(mapping_rows),
        "representative_groups": len(groups),
        "original_metrics": original_metrics,
        "groups_with_mixed_exact_signatures": sum(
            count > 1 for count in nonempty_exact_counts
        ),
        "groups_with_mixed_stack_signatures": sum(
            count > 1 for count in nonempty_stack_counts
        ),
        "representative_flips_changing_f1": sum(
            abs(float(row["DeltaF1"])) > 0 for row in flip_rows
        ),
        "max_absolute_f1_change": abs(float(worst["DeltaF1"])) if worst else 0.0,
        "worst_representative": worst["RepresentativeCrashID"] if worst else "",
        "worst_flip_metrics": {
            field: worst[field]
            for field in ("TP", "FP", "TN", "FN", "Precision", "Recall", "F1", "DeltaF1")
        }
        if worst
        else {},
    }
    return group_rows, flip_rows, summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(
            "results/paper_aligned_20261028_arbitrated/final_v4_expanded_1217.csv"
        ),
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/dedup_audit_20261030"),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    group_rows, flip_rows, summary = audit(args.baseline, args.mapping)
    _write_csv(args.output_dir / "dedup_group_audit.csv", GROUP_FIELDS, group_rows)
    _write_csv(
        args.output_dir / "dedup_flip_sensitivity.csv",
        FLIP_FIELDS,
        flip_rows,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "dedup_audit_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"audited {summary['representative_groups']} groups; "
        f"max |delta F1|={summary['max_absolute_f1_change']:.6f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
