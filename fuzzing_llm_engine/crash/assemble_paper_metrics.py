#!/usr/bin/env python3
"""Deprecated legacy assembler for the obsolete binary-evaluable population.

Use ``python -m crash.assemble_final_1217_metrics`` for paper results.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Set, Tuple


def _truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _load(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _metrics(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    samples = 0
    for row in rows:
        samples += 1
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
        "Samples": samples,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def assemble(args: argparse.Namespace) -> None:
    output = Path(args.output)
    baseline = _load(Path(args.baseline))
    controlled = _load(Path(args.controlled))
    mapping = _load(Path(args.mapping))
    manifest = _load(Path(args.new_manifest))

    included_ids = {
        (row["Project"], row["CrashID"])
        for row in controlled
        if _truth(row.get("IncludeInMetrics"))
    }
    baseline_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in baseline
    }
    mapping_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in mapping
    }
    new_representatives = {
        (row["Project"], row["CrashID"])
        for row in manifest
    }
    v3_results = {
        (row["Project"], row["CrashID"]): row
        for row in _load(Path(args.v3_results))
        if row.get("Status") == "ok"
    }
    v4_results = {
        (row["Project"], row["CrashID"]): row
        for row in _load(Path(args.v4_results))
        if row.get("Status") == "ok"
    }
    for variant, results in (("V3", v3_results), ("V4", v4_results)):
        missing = new_representatives - set(results)
        if missing:
            raise ValueError(
                f"{variant}: missing successful new representative results: "
                f"{sorted(missing)[:10]}"
            )

    # Map only the affected new-leader groups. Existing final V3/V4 predictions
    # remain untouched for all other reports.
    overridden_prediction: Dict[Tuple[str, str], Tuple[str, bool]] = {}
    for crash_id, row in mapping_by_id.items():
        representative = (row["Project"], row["RepresentativeCrashID"])
        if representative in new_representatives:
            overridden_prediction["V3", crash_id[0] + "|" + crash_id[1]] = (
                representative[0],
                _truth(v3_results[representative]["Result"]),
            )
            overridden_prediction["V4", crash_id[0] + "|" + crash_id[1]] = (
                representative[0],
                _truth(v4_results[representative]["Result"]),
            )

    summaries: List[Dict[str, Any]] = []
    for variant in ("V0", "V1", "V2", "V3", "V4"):
        expanded: List[Dict[str, Any]] = []
        for key in sorted(included_ids):
            row = baseline_by_id[key]
            representative = ""
            if variant in {"V0", "V1"}:
                prediction = _truth(row[f"{variant}_IsApiBug"])
            elif variant == "V2":
                prediction = _truth(row["V1_IsApiBug"])
            else:
                prediction = _truth(row[f"{variant}_IsApiBug"])
                override_key = f"{key[0]}|{key[1]}"
                if (variant, key[0] + "|" + key[1]) in overridden_prediction:
                    representative, prediction = overridden_prediction[
                        (variant, key[0] + "|" + key[1])
                    ]
                else:
                    mapping_row = mapping_by_id.get(key)
                    if mapping_row:
                        representative = mapping_row["RepresentativeCrashID"]

            expanded.append({
                "Project": key[0],
                "CrashID": key[1],
                "RepresentativeCrashID": representative,
                "Prediction": str(prediction).lower(),
                "GroundTruth": row["GroundTruth"],
                "Variant": variant,
            })

        metrics = _metrics(expanded)
        summaries.append({
            "Variant": variant,
            "Population": "binary_evaluable",
            **metrics,
        })
        _write(output / f"paper_{variant.lower()}_expanded_876.csv", expanded)

    _write(output / "paper_overall_metrics_v0_v4.csv", summaries)
    _write(output / "overall_metrics_v0_v4.csv", summaries)
    print("variant,samples,tp,fp,tn,fn,precision,recall,f1")
    for row in summaries:
        print(
            f"{row['Variant']},{row['Samples']},{row['TP']},{row['FP']},"
            f"{row['TN']},{row['FN']},{row['Precision']:.6f},"
            f"{row['Recall']:.6f},{row['F1']:.6f}"
        )


def main() -> None:
    raise SystemExit(
        "assemble_paper_metrics is deprecated because it uses obsolete mixed "
        "and historical predictions; use crash.assemble_final_1217_metrics"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default="results/all_crashes_v0_v4_groundtruth.csv",
    )
    parser.add_argument(
        "--controlled",
        default="results/revision_20260722/controlled_ablation_per_crash.csv",
    )
    parser.add_argument(
        "--mapping",
        default="results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv",
    )
    parser.add_argument(
        "--new-manifest",
        default="results/dedup_schema2_14projects_20261027/new_representatives_for_v3_v4.csv",
    )
    parser.add_argument(
        "--v3-results",
        default="results/dedup_schema2_14projects_20261027/llm_v3_new_representatives_coder_flash/llm_bool_results.csv",
    )
    parser.add_argument(
        "--v4-results",
        default="results/dedup_schema2_14projects_20261027/llm_v4_new_representatives_coder_flash/llm_bool_results.csv",
    )
    parser.add_argument(
        "--output",
        default="results/dedup_schema2_14projects_20261027",
    )
    assemble(parser.parse_args())


if __name__ == "__main__":
    main()
