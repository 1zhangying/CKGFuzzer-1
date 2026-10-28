#!/usr/bin/env python3
"""Apply the V3/V4 prior-decision gate to saved representative artifacts."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from crash.assemble_final_1217_metrics import metrics
from roles.crash_analyzer import EnhancedCrashAnalysis, _apply_prior_decision


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _truth(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def arbitrate(args: argparse.Namespace) -> None:
    prior = {
        (row["Project"], row["CrashID"]): _truth(row["Prediction"])
        for row in _read_csv(Path(args.prior))
    }
    candidate = _read_csv(Path(args.candidate))
    artifact_dir = Path(args.artifacts)
    representative_decisions = {}
    representative_audit = {}

    for path in artifact_dir.rglob("*.json"):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        crash_id = artifact["crash_id"]
        project = artifact["project"]
        decision = EnhancedCrashAnalysis.model_validate(
            artifact["structured_decision"]
        )
        audit = _apply_prior_decision(
            decision,
            artifact.get("prompt", ""),
            prior.get((project, crash_id)),
            prompt_variant=(
                "direct_v1" if args.variant == "V3" else "differential"
            ),
        )
        representative_decisions[(project, crash_id)] = decision.is_api_bug
        representative_audit[(project, crash_id)] = audit

    output_rows = []
    for row in candidate:
        project = row["Project"]
        representative = row["RepresentativeCrashID"]
        if not representative:
            prediction = False
            audit = {"applied": False, "reason": "not_retained"}
            prior_prediction = False
        else:
            key = (project, representative)
            prior_prediction = prior.get(key)
            if prior_prediction is None:
                raise ValueError(f"missing prior prediction for {key}")
            prediction = representative_decisions.get(
                key,
                _truth(row["Prediction"]),
            )
            audit = representative_audit.get(
                key,
                {"applied": False, "reason": "artifact_missing"},
            )
        output_rows.append(
            {
                **row,
                "Prediction": str(prediction).lower(),
                "PriorPrediction": str(prior_prediction).lower(),
                "ArbitrationApplied": str(audit.get("applied", False)).lower(),
                "ArbitrationReason": audit.get("reason", ""),
            }
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output_rows[0]))
        writer.writeheader()
        writer.writerows(output_rows)

    summary = metrics(output_rows)
    print(
        f"{args.variant}: TP={summary['TP']} FP={summary['FP']} "
        f"TN={summary['TN']} FN={summary['FN']} "
        f"P={summary['Precision']:.6f} R={summary['Recall']:.6f} "
        f"F1={summary['F1']:.6f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", required=True, choices=("V3", "V4"))
    parser.add_argument("--prior", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--output", required=True)
    arbitrate(parser.parse_args())


if __name__ == "__main__":
    main()
