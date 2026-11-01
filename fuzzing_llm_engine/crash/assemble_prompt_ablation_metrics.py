#!/usr/bin/env python3
"""Assemble representative and 1217-report metrics for prompt ablation arms."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from crash.assemble_final_1217_metrics import load, metrics, truth, write


def load_results(paths: Iterable[Path]) -> Dict[Tuple[str, str], Dict[str, str]]:
    results: Dict[Tuple[str, str], Dict[str, str]] = {}
    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                if row.get("Status") != "ok":
                    continue
                key = (row["Project"], row["CrashID"])
                previous = results.get(key)
                if previous is not None and previous.get("Result") != row.get("Result"):
                    raise ValueError(f"Conflicting successful result for {key}")
                results[key] = row
    return results


def parse_variant(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("Expected NAME=PATH")
    return name, Path(path)


def expected_representatives(mapping: List[Mapping[str, str]]) -> set[Tuple[str, str]]:
    return {
        (row["Project"], row["RepresentativeCrashID"])
        for row in mapping
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--variant", action="append", type=parse_variant, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-monotonic",
        action="store_true",
        help="Fail if Precision, Recall, or F1 decreases along the P0-P3 order.",
    )
    args = parser.parse_args()

    baseline_rows = load(args.baseline)
    baseline = {(row["Project"], row["CrashID"]): row for row in baseline_rows}
    mapping_rows = load(args.mapping)
    mapping = {(row["Project"], row["CrashID"]): row for row in mapping_rows}
    representatives = expected_representatives(mapping_rows)

    all_representative_decisions: List[Dict[str, Any]] = []
    all_expanded_decisions: List[Dict[str, Any]] = []
    summary: List[Dict[str, Any]] = []
    decisions_by_variant: Dict[str, Dict[Tuple[str, str], bool]] = {}

    for name, directory in args.variant:
        paths = sorted(directory.rglob("llm_bool_results.csv"))
        if not paths:
            raise ValueError(f"No result CSV found under {directory}")
        results = load_results(paths)
        missing = representatives - set(results)
        if missing:
            preview = ", ".join(f"{p}/{c}" for p, c in sorted(missing)[:5])
            raise ValueError(f"{name}: {len(missing)} representatives missing: {preview}")
        models = {row.get("LLMModel", "") for row in results.values()}
        if "" in models or len(models) != 1:
            raise ValueError(f"{name}: expected one model, found {sorted(models)}")

        representative_rows = []
        for key in sorted(representatives):
            row = results[key]
            representative_rows.append(
                {
                    "PromptVariant": name,
                    "Project": key[0],
                    "CrashID": key[1],
                    "Prediction": truth(row["Result"]),
                    "GroundTruth": truth(
                        baseline[key].get(
                            "MemberGroundTruth", baseline[key]["GroundTruth"]
                        )
                    ),
                }
            )

        expanded_rows = []
        decisions: Dict[Tuple[str, str], bool] = {}
        for key, baseline_row in baseline.items():
            mapping_row = mapping.get(key)
            representative = (
                mapping_row["RepresentativeCrashID"] if mapping_row else ""
            )
            prediction = truth(results[(key[0], representative)]["Result"]) if representative else False
            decisions[key] = prediction
            expanded_rows.append(
                {
                    "PromptVariant": name,
                    "Project": key[0],
                    "CrashID": key[1],
                    "RepresentativeCrashID": representative,
                    "Prediction": prediction,
                    "GroundTruth": truth(
                        baseline_row.get(
                            "MemberGroundTruth", baseline_row["GroundTruth"]
                        )
                    ),
                }
            )

        summary.extend(
            [
                {
                    "PromptVariant": name,
                    "Model": next(iter(models)),
                    "Population": "representatives",
                    **metrics(representative_rows),
                },
                {
                    "PromptVariant": name,
                    "Model": next(iter(models)),
                    "Population": "all_1217",
                    **metrics(expanded_rows),
                },
            ]
        )
        decisions_by_variant[name] = decisions
        all_representative_decisions.extend(representative_rows)
        all_expanded_decisions.extend(expanded_rows)

    flips = []
    reference = next(iter(decisions_by_variant))
    for name, decisions in decisions_by_variant.items():
        for key in sorted(decisions_by_variant[reference]):
            if decisions[key] == decisions_by_variant[reference][key]:
                continue
            flips.append(
                {
                    "Reference": reference,
                    "Comparison": name,
                    "Project": key[0],
                    "CrashID": key[1],
                    "ReferencePrediction": decisions_by_variant[reference][key],
                    "ComparisonPrediction": decisions[key],
                }
            )

    args.output.mkdir(parents=True, exist_ok=True)
    ordered = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    aggregate_rows = {
        row["PromptVariant"]: row
        for row in summary
        if row["Population"] == "all_1217"
    }
    unknown = sorted(set(aggregate_rows) - set(ordered))
    if unknown:
        raise ValueError(f"Unexpected prompt variants: {unknown}")
    monotonic_rows = []
    previous = None
    for variant in sorted(aggregate_rows, key=ordered.__getitem__):
        row = aggregate_rows[variant]
        record: Dict[str, Any] = {"PromptVariant": variant}
        for field in ("Precision", "Recall", "F1"):
            value = float(row[field])
            record[field] = value
            if previous is None:
                record[f"{field}Delta"] = ""
                record[f"{field}NonDecreasing"] = True
            else:
                delta = value - float(previous[field])
                record[f"{field}Delta"] = delta
                record[f"{field}NonDecreasing"] = delta >= -1e-12
            previous_value = previous[field] if previous is not None else None
            record[f"{field}Previous"] = previous_value
        monotonic_rows.append(record)
        previous = row

    write(args.output / "prompt_ablation_metrics.csv", summary)
    write(
        args.output / "prompt_ablation_representative_decisions.csv",
        all_representative_decisions,
    )
    write(
        args.output / "prompt_ablation_expanded_1217.csv",
        all_expanded_decisions,
    )
    write(args.output / "prompt_ablation_flips.csv", flips)
    write(
        args.output / "prompt_ablation_monotonicity.csv",
        list(monotonic_rows[0]),
        monotonic_rows,
    )
    violations = [
        (row["PromptVariant"], field)
        for row in monotonic_rows
        for field in ("Precision", "Recall", "F1")
        if not row[f"{field}NonDecreasing"]
    ]
    if args.require_monotonic and violations:
        raise ValueError(f"Prompt-ablation metric decreased: {violations}")
    for row in summary:
        print(
            f"{row['PromptVariant']},{row['Population']},{row['Samples']},"
            f"{row['TP']},{row['FP']},{row['TN']},{row['FN']},"
            f"{row['Precision']:.6f},{row['Recall']:.6f},{row['F1']:.6f}"
        )


if __name__ == "__main__":
    main()
