#!/usr/bin/env python3
"""Apply the formal V4 prior gate to saved prompt-ablation responses offline."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Tuple

from roles.crash_analyzer import (
    _apply_prior_decision,
    _deterministic_decision_consistency_violation,
    _parse_enhanced_json_response,
    _promote_target_state_memory_safety,
)


def truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def load_prompts(path: Path) -> Dict[Tuple[str, str], str]:
    prompts = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        prompts[(record["project"], record["crash_id"])] = record["prompt"]
    return prompts


def load_priors(path: Path) -> Dict[Tuple[str, str], bool]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return {
            (row["Project"], row["CrashID"]): truth(
                row.get("Prediction", row.get("Result"))
            )
            for row in csv.DictReader(handle)
        }


def load_responses(root: Path) -> Dict[Tuple[str, str], Dict[str, object]]:
    responses = {}
    for path in sorted(root.rglob("llm_bool_results.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not record.get("primary_model_response"):
                continue
            responses.setdefault(
                (record["project"], record["crash_id"]),
                record,
            )
    return responses


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--prior-results", type=Path, required=True)
    parser.add_argument("--prompt-mode", choices=("direct_v1", "differential"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    prompts = load_prompts(args.prompts)
    priors = load_priors(args.prior_results)
    responses = load_responses(args.responses)
    missing = set(prompts) - set(responses)
    if missing:
        raise ValueError(f"{len(missing)} prompts have no saved response")

    fields = [
        "Project",
        "CrashID",
        "LLMModel",
        "Result",
        "Status",
        "DecisionParseMode",
        "DecisionParseError",
        "FinalCallCount",
        "ConsistencyRepair",
        "PriorApplied",
        "TargetStatePromotion",
    ]
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    for key in sorted(prompts):
        record = responses[key]
        result = _parse_enhanced_json_response(
            str(record["primary_model_response"])
        )
        violation = _deterministic_decision_consistency_violation(
            result,
            prompts[key],
        )
        if violation:
            result.is_api_bug = False
            result.decision_basis = "driver_evidence"
            if str(getattr(result, "driver_misuse_evidence_strength", "")).lower() == "none":
                result.driver_misuse_evidence_strength = "soft"
        arbitration = _apply_prior_decision(
            result,
            prompts[key],
            priors.get(key),
            prompt_variant=args.prompt_mode,
        )
        promotion = _promote_target_state_memory_safety(
            result,
            prompts[key],
            prompt_variant=args.prompt_mode,
        )
        rows.append(
            {
                "Project": key[0],
                "CrashID": key[1],
                "LLMModel": record.get("llm_model", ""),
                "Result": str(bool(result.is_api_bug)).lower(),
                "Status": "ok",
                "DecisionParseMode": "primary_json+prior",
                "DecisionParseError": "",
                "FinalCallCount": 1,
                "ConsistencyRepair": str(bool(violation)).lower(),
                "PriorApplied": str(bool(arbitration.get("applied"))).lower(),
                "TargetStatePromotion": str(bool(promotion.get("applied"))).lower(),
            }
        )

    with (args.output / "llm_bool_results.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(
        f"wrote {len(rows)} canonical decisions; "
        f"prior_applied={sum(row['PriorApplied'] == 'true' for row in rows)}"
    )


if __name__ == "__main__":
    main()
