#!/usr/bin/env python3
"""Assemble paper-defined V0-V4 metrics over all 1217 crashes.

The aggregation is fail-closed: V0 must cover every crash, V1 must cover every
retained crash, and V3/V4 must cover every current representative. Missing
results never fall back to historical predictions.
"""
from __future__ import annotations

import argparse
import csv
import sys
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
        # Expanded historical files retain both the representative label and
        # the original member label. Metrics are always computed on the latter.
        expected = truth(row.get("MemberGroundTruth", row["GroundTruth"]))
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


def result_map(
    paths: Iterable[Path],
    *,
    label: str,
    expected_prompt: str,
    expected_evidence: str,
    expected_engine: str,
) -> Dict[Tuple[str, str], Dict[str, str]]:
    result: Dict[Tuple[str, str], Dict[str, str]] = {}
    for path in paths:
        for row in load(path):
            if row.get("Status") != "ok":
                continue
            key = (row["Project"], row["CrashID"])
            if row.get("PromptVariant") != expected_prompt:
                raise ValueError(
                    f"{label} result {key} has prompt {row.get('PromptVariant')!r}, "
                    f"expected {expected_prompt!r}"
                )
            if row.get("EvidenceVariant") != expected_evidence:
                raise ValueError(
                    f"{label} result {key} has evidence {row.get('EvidenceVariant')!r}, "
                    f"expected {expected_evidence!r}"
                )
            if row.get("RunVariant") != label:
                raise ValueError(
                    f"{label} result {key} has run variant {row.get('RunVariant')!r}"
                )
            if row.get("AnalysisEngine") != expected_engine:
                raise ValueError(
                    f"{label} result {key} has analysis engine "
                    f"{row.get('AnalysisEngine')!r}, expected {expected_engine!r}"
                )
            previous = result.get(key)
            if previous is not None:
                fields = (
                    "Result",
                    "LLMModel",
                    "PromptSHA256",
                    "ExperimentFingerprint",
                    "InputFingerprint",
                )
                if any(previous.get(field) != row.get(field) for field in fields):
                    raise ValueError(f"conflicting {label} results for {key}")
            result[key] = row
    return result


def require_complete(
    results: Mapping[Tuple[str, str], Dict[str, str]],
    expected: Iterable[Tuple[str, str]],
    label: str,
) -> None:
    missing = sorted(set(expected) - set(results))
    if missing:
        preview = ", ".join(f"{project}/{crash}" for project, crash in missing[:5])
        raise ValueError(f"{label}: {len(missing)} required results missing: {preview}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--v0-result", action="append", required=True)
    parser.add_argument("--v1-result", action="append", required=True)
    parser.add_argument("--v3-result", action="append", required=True)
    parser.add_argument("--v4-result", action="append", required=True)
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

    v0 = result_map(
        (Path(path) for path in args.v0_result),
        label="V0",
        expected_prompt="direct_v1",
        expected_evidence="raw_no_context",
        expected_engine="ckgfuzzer",
    )
    v1 = result_map(
        (Path(path) for path in args.v1_result),
        label="V1",
        expected_prompt="direct_v1",
        expected_evidence="triage_no_context",
        expected_engine="crashsage",
    )
    v3 = result_map(
        (Path(path) for path in args.v3_result),
        label="V3",
        expected_prompt="direct_v1",
        expected_evidence="full",
        expected_engine="crashsage",
    )
    v4 = result_map(
        (Path(path) for path in args.v4_result),
        label="V4",
        expected_prompt="differential",
        expected_evidence="full",
        expected_engine="crashsage",
    )

    retained_keys = set(mapping_by_id)
    representative_keys = {
        (row["Project"], row["RepresentativeCrashID"])
        for row in mapping
    }
    require_complete(v0, baseline_by_id, "V0")
    require_complete(v1, retained_keys, "V1")
    require_complete(v3, representative_keys, "V3")
    require_complete(v4, representative_keys, "V4")

    models = set()
    input_fingerprints = set()
    for label, results in (("V0", v0), ("V1", v1), ("V3", v3), ("V4", v4)):
        variant_models = {row.get("LLMModel", "") for row in results.values()}
        variant_fingerprints = {
            row.get("ExperimentFingerprint", "") for row in results.values()
        }
        variant_input_fingerprints = {
            row.get("InputFingerprint", "") for row in results.values()
        }
        if "" in variant_models or len(variant_models) != 1:
            raise ValueError(
                f"{label} results must use exactly one model, "
                f"found {sorted(variant_models)}"
            )
        if "" in variant_fingerprints or len(variant_fingerprints) != 1:
            raise ValueError(
                f"{label} results must use exactly one experiment fingerprint, "
                f"found {len(variant_fingerprints)}"
            )
        if "" in variant_input_fingerprints or len(variant_input_fingerprints) != 1:
            raise ValueError(
                f"{label} results must use exactly one input fingerprint, "
                f"found {len(variant_input_fingerprints)}"
            )
        models.update(variant_models)
        input_fingerprints.update(variant_input_fingerprints)
    if len(models) != 1:
        raise ValueError(f"variants must use one model, found {sorted(models)}")
    if len(input_fingerprints) != 1:
        raise ValueError(
            "variants must share one input fingerprint, "
            f"found {len(input_fingerprints)}"
        )
    summaries = []
    for variant in ("V0", "V1", "V2", "V3", "V4"):
        expanded = []
        for key, baseline_row in baseline_by_id.items():
            mapping_row = mapping_by_id.get(key)
            representative = mapping_row["RepresentativeCrashID"] if mapping_row else ""
            representative_key = (key[0], representative)
            ground_truth = baseline_row["GroundTruth"]
            representative_ground_truth = (
                baseline_by_id[representative_key]["GroundTruth"]
                if mapping_row
                else ground_truth
            )

            if variant == "V0":
                prediction = truth(v0[key]["Result"])
            elif mapping_row is None:
                prediction = False
            elif variant == "V1":
                prediction = truth(v1[key]["Result"])
            elif variant == "V2":
                # V2 introduces representative selection without changing an
                # already-computed crash-level judgment. Reusing the member's
                # V1 result keeps the classification ablation controlled while
                # the mapping separately reports the representative workload.
                prediction = truth(v1[key]["Result"])
            elif variant == "V3":
                prediction = truth(v3[representative_key]["Result"])
            else:
                prediction = truth(v4[representative_key]["Result"])

            expanded.append({
                "Project": key[0],
                "CrashID": key[1],
                "RepresentativeCrashID": representative,
                "Prediction": str(prediction).lower(),
                "GroundTruth": ground_truth,
                "MemberGroundTruth": ground_truth,
                "RepresentativeGroundTruth": representative_ground_truth,
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
