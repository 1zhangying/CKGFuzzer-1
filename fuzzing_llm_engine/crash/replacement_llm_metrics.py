#!/usr/bin/env python3
"""Summarize replacement-LLM V4 results on representatives and all crashes."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, List, Mapping

from crash.assemble_final_1217_metrics import (
    load,
    metrics,
    require_complete,
    result_map,
    truth,
    write,
)


def representative_metrics(
    results: Mapping[tuple[str, str], Mapping[str, str]],
    baseline: Mapping[tuple[str, str], Mapping[str, str]],
) -> List[Dict[str, Any]]:
    rows = []
    for key, result in results.items():
        rows.append(
            {
                "Project": key[0],
                "CrashID": key[1],
                "Prediction": truth(result["Result"]),
                "GroundTruth": truth(baseline[key]["GroundTruth"]),
            }
        )
    return rows


def expanded_metrics(
    results: Mapping[tuple[str, str], Mapping[str, str]],
    baseline: Mapping[tuple[str, str], Mapping[str, str]],
    mapping: Mapping[tuple[str, str], Mapping[str, str]],
) -> List[Dict[str, Any]]:
    rows = []
    for key, baseline_row in baseline.items():
        mapping_row = mapping.get(key)
        representative = mapping_row["RepresentativeCrashID"] if mapping_row else ""
        prediction = (
            truth(results[(key[0], representative)]["Result"])
            if representative
            else False
        )
        rows.append(
            {
                "Project": key[0],
                "CrashID": key[1],
                "RepresentativeCrashID": representative,
                "Prediction": prediction,
                "GroundTruth": truth(baseline_row["GroundTruth"]),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--result", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    baseline = {
        (row["Project"], row["CrashID"]): row for row in load(Path(args.baseline))
    }
    mapping = {
        (row["Project"], row["CrashID"]): row for row in load(Path(args.mapping))
    }
    results = result_map(
        (Path(path) for path in args.result),
        label="V4",
        expected_prompt="differential",
        expected_evidence="full",
        expected_engine="crashsage",
    )
    representative_keys = {
        (row["Project"], row["RepresentativeCrashID"]) for row in mapping.values()
    }
    require_complete(results, representative_keys, "V4")

    models = {row.get("LLMModel", "") for row in results.values()}
    if "" in models or len(models) != 1:
        raise ValueError(f"V4 results must use one model, found {sorted(models)}")
    model = next(iter(models))

    output = Path(args.output)
    representative_rows = representative_metrics(results, baseline)
    expanded_rows = expanded_metrics(results, baseline, mapping)
    representative_summary = metrics(representative_rows)
    overall_summary = metrics(expanded_rows)
    write(output / "representative_decisions.csv", representative_rows)
    write(output / "expanded_decisions_1217.csv", expanded_rows)
    write(
        output / "metrics.csv",
        [
            {
                "Model": model,
                "Population": "representatives",
                **representative_summary,
            },
            {
                "Model": model,
                "Population": "all_1217",
                **overall_summary,
            },
        ],
    )
    for row in (
        {"Model": model, "Population": "representatives", **representative_summary},
        {"Model": model, "Population": "all_1217", **overall_summary},
    ):
        print(
            f"{row['Model']},{row['Population']},{row['Samples']},"
            f"{row['TP']},{row['FP']},{row['TN']},{row['FN']},"
            f"{row['Precision']:.6f},{row['Recall']:.6f},{row['F1']:.6f}"
        )


if __name__ == "__main__":
    main()
