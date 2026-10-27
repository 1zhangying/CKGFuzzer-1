#!/usr/bin/env python3
"""Deprecated legacy assembler that allowed mixed historical predictions.

Use ``python -m crash.assemble_final_1217_metrics`` for paper results.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple


def _truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
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


def _result_map(path: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    return {
        (row["Project"], row["CrashID"]): row
        for row in _load_csv(path)
        if row.get("Status") == "ok"
    }


def assemble(args: argparse.Namespace) -> None:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    baseline_rows = _load_csv(Path(args.baseline))
    baseline_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in baseline_rows
    }
    mapping_rows = _load_csv(Path(args.mapping))
    mapping_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in mapping_rows
    }
    new_manifest = _load_csv(Path(args.new_manifest))
    expected_new = {
        (row["Project"], row["CrashID"])
        for row in new_manifest
    }
    v3_new = _result_map(Path(args.v3_results))
    v4_new = _result_map(Path(args.v4_results))

    for label, results in (("V3", v3_new), ("V4", v4_new)):
        missing = expected_new - set(results)
        if missing:
            raise ValueError(
                f"{label}: {len(missing)} new representatives lack successful results"
            )

    summary: List[Dict[str, Any]] = []
    expanded_by_variant: Dict[str, List[Dict[str, Any]]] = {
        variant: [] for variant in ("V0", "V1", "V2", "V3", "V4")
    }

    for baseline in baseline_rows:
        key = (baseline["Project"], baseline["CrashID"])
        mapping = mapping_by_id.get(key)
        if mapping is None:
            representative = ""
            representative_name = ""
        else:
            representative = mapping["RepresentativeCrashID"]
            representative_name = representative

        for variant in expanded_by_variant:
            if variant in {"V0", "V1"}:
                prediction = _truth(baseline.get(f"{variant}_IsApiBug"))
            elif mapping is None:
                prediction = False
            else:
                representative_key = (baseline["Project"], representative)
                if variant == "V2":
                    representative_row = baseline_by_id[representative_key]
                    prediction = _truth(representative_row["V1_IsApiBug"])
                elif variant == "V3":
                    new_row = v3_new.get(representative_key)
                    if new_row is not None:
                        prediction = _truth(new_row["Result"])
                    else:
                        prediction = _truth(
                            baseline_by_id[representative_key]["V3_IsApiBug"]
                        )
                else:
                    new_row = v4_new.get(representative_key)
                    if new_row is not None:
                        prediction = _truth(new_row["Result"])
                    else:
                        prediction = _truth(
                            baseline_by_id[representative_key]["V4_IsApiBug"]
                        )

            expanded_by_variant[variant].append({
                "Project": baseline["Project"],
                "CrashID": baseline["CrashID"],
                "RepresentativeCrashID": representative_name,
                "Prediction": str(prediction).lower(),
                "GroundTruth": baseline["GroundTruth"],
                "Variant": variant,
            })

    for variant, rows in expanded_by_variant.items():
        metrics = _metrics(rows)
        summary.append({"Variant": variant, **metrics})
        _write_csv(output / f"{variant.lower()}_expanded_14projects.csv", rows)

    _write_csv(output / "overall_metrics_v0_v4.csv", summary)
    print("variant,samples,tp,fp,tn,fn,precision,recall,f1")
    for row in summary:
        print(
            f"{row['Variant']},{row['Samples']},{row['TP']},{row['FP']},"
            f"{row['TN']},{row['FN']},{row['Precision']:.6f},"
            f"{row['Recall']:.6f},{row['F1']:.6f}"
        )


def main() -> None:
    raise SystemExit(
        "assemble_variant_metrics is deprecated because it silently falls back "
        "to historical predictions; use crash.assemble_final_1217_metrics"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default="results/all_crashes_v0_v4_groundtruth.csv",
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
