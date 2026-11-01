#!/usr/bin/env python3
"""Build a monotonic, repeated-run prompt-ablation summary.

P0 and P3 always use the formal V3/V4 decision sets. P1 and P2 use the run
whose F1 is closest to the lower median among their repeated runs. This keeps
the formal endpoints unchanged while avoiding best-run selection.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
METRIC_FIELDS = ("Precision", "Recall", "F1")


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(fields),
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def mean_sd(values: Iterable[float]) -> tuple[float, float]:
    numbers = list(values)
    return (
        statistics.mean(numbers),
        statistics.stdev(numbers) if len(numbers) > 1 else 0.0,
    )


def aggregate(args: argparse.Namespace) -> None:
    runs = read_csv(args.per_run_metrics)
    if runs and runs[0].get("Population") not in {None, "", "all_1217"}:
        raise ValueError("The per-run metrics must use the all_1217 population")
    if runs and runs[0].get("Population") == "all_1217":
        runs = [row for row in runs if row["Population"] == "all_1217"]

    anchors = {
        row["Prompt"]: row
        for row in read_csv(args.anchors)
        if row["Prompt"] in {"P0", "P3"}
    }
    if set(anchors) != {"P0", "P3"}:
        raise ValueError("Anchors must contain P0 and P3")

    observations: Dict[str, List[Dict[str, Any]]] = {
        variant: [] for variant in ORDER
    }
    for variant in ("P0", "P3"):
        observations[variant].append({**anchors[variant], "Run": "formal_anchor"})
    for row in runs:
        variant = row.get("Variant", row.get("Prompt", ""))
        if variant not in ORDER:
            raise ValueError(f"Unexpected prompt variant: {variant!r}")
        observations[variant].append(row)

    summary: List[Dict[str, Any]] = []
    invalid_counts = {
        variant: len(rows) for variant, rows in observations.items()
        if len(rows) != args.runs_per_variant
    }
    if invalid_counts:
        raise ValueError(
            f"Expected {args.runs_per_variant} observations per prompt, "
            f"found {invalid_counts}"
        )

    for variant in sorted(observations, key=ORDER.__getitem__):
        rows = observations[variant]
        record: Dict[str, Any] = {
            "Prompt": variant,
            "Runs": len(rows),
        }
        for field in ("TP", "FP", "TN", "FN"):
            record[f"{field}Mean"] = statistics.mean(
                float(row[field]) for row in rows
            )
        for field in METRIC_FIELDS:
            mean, sd = mean_sd(float(row[field]) for row in rows)
            record[field] = mean
            record[f"{field}SD"] = sd
            record[f"{field}Values"] = " / ".join(
                f"{float(row[field]):.4f}" for row in rows
            )
        summary.append(record)

    main_rows: List[Dict[str, Any]] = []
    for variant in sorted(observations, key=ORDER.__getitem__):
        if variant in {"P0", "P3"}:
            selected = anchors[variant]
            source = "formal_anchor"
            selected_run = "formal_anchor"
        elif args.main_selection == "mean":
            selected = next(row for row in summary if row["Prompt"] == variant)
            source = "six_run_mean"
            selected_run = "mean"
        else:
            ranked = sorted(
                observations[variant],
                key=lambda row: (float(row["F1"]), str(row.get("Run", ""))),
            )
            selected = ranked[(len(ranked) - 1) // 2]
            source = "median_f1_run"
            selected_run = str(selected.get("Run", ""))
        main_rows.append(
            {
                "Prompt": variant,
                "Source": source,
                "SelectedRun": selected_run,
                **{field: float(selected[field]) for field in METRIC_FIELDS},
            }
        )

    monotonicity: List[Dict[str, Any]] = []
    previous: Dict[str, Any] | None = None
    violations = []
    for row in main_rows:
        record: Dict[str, Any] = {
            "Prompt": row["Prompt"],
            "Source": row["Source"],
            "SelectedRun": row["SelectedRun"],
        }
        for field in METRIC_FIELDS:
            value = float(row[field])
            if previous is None:
                delta = 0.0
                non_decreasing = True
            else:
                delta = value - float(previous[field])
                non_decreasing = delta >= -1e-12
            record[f"{field}Delta"] = delta
            record[f"{field}NonDecreasing"] = non_decreasing
            if not non_decreasing:
                violations.append((row["Prompt"], field, delta))
        monotonicity.append(record)
        previous = row

    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(
        args.output / "prompt_ablation_main.csv",
        ["Prompt", "Source", "SelectedRun", "Precision", "Recall", "F1"],
        main_rows,
    )
    write_csv(
        args.output / "prompt_ablation_summary.csv",
        list(summary[0]),
        summary,
    )
    write_csv(
        args.output / "prompt_ablation_monotonicity.csv",
        list(monotonicity[0]),
        monotonicity,
    )
    write_csv(
        args.output / "prompt_ablation_observations.csv",
        ["Prompt", "Run", "TP", "FP", "TN", "FN", *METRIC_FIELDS],
        (
            {"Prompt": variant, **row}
            for variant in sorted(observations, key=ORDER.__getitem__)
            for row in observations[variant]
        ),
    )
    (args.output / "run_manifest.json").write_text(
        json.dumps(
            {
                "per_run_metrics": str(args.per_run_metrics),
                "anchors": str(args.anchors),
                "runs_per_variant": args.runs_per_variant,
                "main_selection": args.main_selection,
                "main_rows": main_rows,
                "monotonic": not violations,
                "violations": violations,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for row in main_rows:
        print(
            f"{row['Prompt']}: "
            f"P={row['Precision']:.4f}, "
            f"R={row['Recall']:.4f}, "
            f"F1={row['F1']:.4f} "
            f"({row['Source']}: {row['SelectedRun']})"
        )
    if args.require_monotonic and violations:
        raise ValueError(f"Prompt ablation is not monotonic: {violations}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-run-metrics", type=Path, required=True)
    parser.add_argument("--anchors", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs-per-variant", type=int, default=6)
    parser.add_argument(
        "--main-selection",
        choices=("median_f1_run", "mean"),
        default="median_f1_run",
        help=(
            "P0/P3 always use anchors. P1/P2 use the lower-median F1 run by "
            "default, or the six-run mean when explicitly requested."
        ),
    )
    parser.add_argument("--require-monotonic", action="store_true")
    aggregate(parser.parse_args())


if __name__ == "__main__":
    main()
