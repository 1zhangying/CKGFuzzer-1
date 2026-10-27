#!/usr/bin/env python3
"""Assemble final V0-V4 metrics over all 1217 crashes."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple


def truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def load(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def metrics(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = samples = 0
    for row in rows:
        samples += 1
        predicted = truth(row["Prediction"])
        expected = truth(row["GroundTruth"])
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


def result_map(paths: Iterable[Path]) -> Dict[Tuple[str, str], Dict[str, str]]:
    result = {}
    for path in paths:
        for row in load(path):
            if row.get("Status") == "ok":
                result[(row["Project"], row["CrashID"])] = row
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--v3-result", action="append", default=[])
    parser.add_argument("--v4-result", action="append", default=[])
    args = parser.parse_args()

    output = Path(args.output)
    baseline = load(Path(args.baseline))
    mapping = load(Path(args.mapping))
    baseline_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in baseline
    }
    mapping_by_id = {
        (row["Project"], row["CrashID"]): row
        for row in mapping
    }
    v3 = result_map((Path(path) for path in args.v3_result))
    v4 = result_map((Path(path) for path in args.v4_result))

    summaries = []
    for variant in ("V0", "V1", "V2", "V3", "V4"):
        expanded = []
        for key, baseline_row in baseline_by_id.items():
            mapping_row = mapping_by_id.get(key)
            representative = mapping_row["RepresentativeCrashID"] if mapping_row else ""
            if variant in {"V0", "V1"}:
                prediction = truth(baseline_row[f"{variant}_IsApiBug"])
            elif variant == "V2":
                # V2 only removes repeated LLM calls; its prediction is the
                # already-frozen V1 prediction.
                prediction = truth(baseline_row["V1_IsApiBug"])
            elif mapping_row is None:
                prediction = False
            else:
                representative_key = (key[0], representative)
                new_results = v3 if variant == "V3" else v4
                if representative_key in new_results:
                    prediction = truth(new_results[representative_key]["Result"])
                else:
                    prediction = truth(
                        baseline_by_id[representative_key][f"{variant}_IsApiBug"]
                    )

            expanded.append({
                "Project": key[0],
                "CrashID": key[1],
                "RepresentativeCrashID": representative,
                "Prediction": str(prediction).lower(),
                "GroundTruth": baseline_row["GroundTruth"],
                "Variant": variant,
            })

        summary = {"Variant": variant, "Population": "all_1217", **metrics(expanded)}
        summaries.append(summary)
        write(output / f"final_{variant.lower()}_expanded_1217.csv", expanded)

    write(output / "final_overall_metrics_v0_v4_1217.csv", summaries)
    print("variant,samples,tp,fp,tn,fn,precision,recall,f1")
    for row in summaries:
        print(
            f"{row['Variant']},{row['Samples']},{row['TP']},{row['FP']},"
            f"{row['TN']},{row['FN']},{row['Precision']:.6f},"
            f"{row['Recall']:.6f},{row['F1']:.6f}"
        )


if __name__ == "__main__":
    main()
