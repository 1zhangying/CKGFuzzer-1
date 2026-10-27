#!/usr/bin/env python3
"""Read-only revision experiment tooling for the CrashSage paper.

This module never writes to ``external_database`` or the legacy ``results``
directory.  It prepares a self-contained revision directory, merges new LLM
ablation outputs, evaluates three-state ground truth, and summarizes recorded
costs.  All paths supplied with ``--output`` are expected to be new folders.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml


STATUS_TARGET = "confirmed_target"
STATUS_NON_TARGET = "confirmed_non_target"
STATUS_UNRESOLVED = "unresolved_candidate"
EVALUABLE_STATUSES = {STATUS_TARGET, STATUS_NON_TARGET}
DEFAULT_VARIANTS = ("V1", "V2", "V3", "V4")

GROUND_TRUTH_FIELDS = [
    "Project", "CrashID", "RepresentativeCrashID", "GroundTruthStatus",
    "IncludeInMetrics", "EvidenceType", "PublicReference",
    "ReproductionStatus", "RootCauseSummary", "DecisionNote",
]
COST_FIELDS = [
    "Project", "CrashID", "RepresentativeCrashID", "Variant", "Stage",
    "StartTimestamp", "ElapsedMs", "Status", "RetryCount", "PromptChars",
    "PromptTokens", "CompletionTokens", "TotalTokens", "ApiCost",
    "RuntimeContextStatus", "RuntimeEvidenceQuality",
]


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _falsey(value: Any) -> bool:
    return str(value).strip().lower() in {"false", "0", "no", "n"}


def _row_key(row: Mapping[str, str]) -> Tuple[str, str]:
    return row.get("Project", ""), row.get("CrashID", "")


def _legacy_status(row: Mapping[str, str]) -> Dict[str, str]:
    """Create conservative initial labels; legacy negatives are never reused as false."""
    legacy = row.get("GroundTruth", "")
    if _truthy(legacy):
        return {
            "GroundTruthStatus": STATUS_TARGET,
            "IncludeInMetrics": "TRUE",
            "EvidenceType": "legacy_public_reference_pending",
            "PublicReference": "REQUIRED: add CVE/advisory/issue/patch reference before submission",
            "ReproductionStatus": "legacy_true: verify local reproduction",
            "RootCauseSummary": "",
            "DecisionNote": "Imported from legacy positive label; verify and record the public reference.",
        }
    return {
        "GroundTruthStatus": STATUS_UNRESOLVED,
        "IncludeInMetrics": "FALSE",
        "EvidenceType": "needs_author_review",
        "PublicReference": "N/A",
        "ReproductionStatus": "unknown",
        "RootCauseSummary": "",
        "DecisionNote": "Legacy false is intentionally not reused as a negative label. Confirm driver/noise evidence or keep unresolved.",
    }


def _representative_id(row: Mapping[str, str]) -> str:
    duplicate_of = (row.get("DuplicateOf") or "").strip()
    return duplicate_of or row.get("CrashID", "")


def prepare(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    if output.exists() and any(output.iterdir()) and not args.resume:
        raise RuntimeError(f"Refusing to reuse non-empty output directory: {output}. Use --resume explicitly.")
    output.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(source)
    if not rows:
        raise RuntimeError(f"No rows in {source}")
    required = {"Project", "CrashID", "Driver", "V2_SentToLLM"}
    missing = required.difference(rows[0])
    if missing:
        raise RuntimeError(f"Source manifest missing columns: {sorted(missing)}")

    frozen_manifest = output / "legacy_ablation_per_crash.csv"
    _write_csv(frozen_manifest, list(rows[0]), rows)

    label_path = output / "ground_truth_v2.csv"
    if not (args.resume and label_path.is_file()):
        labels: List[Dict[str, str]] = []
        for row in rows:
            label = _legacy_status(row)
            labels.append({
                "Project": row["Project"],
                "CrashID": row["CrashID"],
                "RepresentativeCrashID": _representative_id(row),
                **label,
            })
        _write_csv(label_path, GROUND_TRUTH_FIELDS, labels)

    representatives = [row for row in rows if _truthy(row.get("V2_SentToLLM"))]
    _write_csv(output / "representatives_v1.csv", list(rows[0]), representatives)
    _write_csv(output / "cost_per_invocation.csv", COST_FIELDS, [])

    manifest = {
        "created_at": datetime.now().isoformat(),
        "source_manifest": str(source),
        "source_rows": len(rows),
        "representative_rows": len(representatives),
        "legacy_positive_rows_imported_as_confirmed_target": sum(
            1 for row in rows if _truthy(row.get("GroundTruth"))
        ),
        "legacy_negative_rows_initialized_as_unresolved": sum(
            1 for row in rows if not _truthy(row.get("GroundTruth"))
        ),
        "output_policy": "All revision artifacts are written only under this directory.",
    }
    (output / "revision_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "README.md").write_text(
        "# Revision experiment output\n\n"
        "This directory is intentionally isolated from legacy results.\n\n"
        "1. Complete `ground_truth_v2.csv`. Legacy negatives start as `unresolved_candidate`; "
        "only explicit driver/noise evidence may change them to `confirmed_non_target`.\n"
        "2. Run the following two commands from `fuzzing_llm_engine` when the API is reachable:\n\n"
        "```bash\n"
        "python -m crash.external_bool_adjudication --manifest results/revision_20260722/representatives_v1.csv --db-root external_database --llm-config configs/external_bool_adjudication.yaml --output results/revision_20260722/llm_v3_full_direct_v1 --evidence-variant full --prompt-variant direct_v1\n"
        "python -m crash.external_bool_adjudication --manifest results/revision_20260722/representatives_v1.csv --db-root external_database --llm-config configs/external_bool_adjudication.yaml --output results/revision_20260722/llm_v4_full_differential --evidence-variant full --prompt-variant differential\n"
        "```\n\n"
        "3. Successful calls resume automatically. Failed calls are retried on the next invocation; do not delete the JSONL files.\n"
        "4. After both CSV files contain successful representative predictions, merge and evaluate:\n\n"
        "```bash\n"
        "python -m crash.revision_experiment merge --output results/revision_20260722 --v3 results/revision_20260722/llm_v3_full_direct_v1/llm_bool_results.csv --v4 results/revision_20260722/llm_v4_full_differential/llm_bool_results.csv\n"
        "python -m crash.revision_experiment record-llm-cost --output results/revision_20260722 --input results/revision_20260722/llm_v3_full_direct_v1/llm_bool_results.csv --variant V3\n"
        "python -m crash.revision_experiment record-llm-cost --output results/revision_20260722 --input results/revision_20260722/llm_v4_full_differential/llm_bool_results.csv --variant V4\n"
        "python -m crash.revision_experiment evaluate --output results/revision_20260722\n"
        "python -m crash.revision_experiment summarize-cost --output results/revision_20260722\n"
        "```\n\n"
        "The merge/evaluate commands intentionally fail if an LLM condition is incomplete or if no `confirmed_non_target` labels exist. This prevents dry-run output from entering paper tables.\n",
        encoding="utf-8",
    )
    print(f"Prepared isolated revision directory: {output}")
    print(f"  crashes={len(rows)} representatives={len(representatives)}")
    return 0


def _load_labels(path: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    labels = {}
    for row in _read_csv(path):
        status = row.get("GroundTruthStatus", "")
        if status not in {STATUS_TARGET, STATUS_NON_TARGET, STATUS_UNRESOLVED}:
            raise ValueError(f"Invalid GroundTruthStatus for {_row_key(row)}: {status!r}")
        expected = "TRUE" if status in EVALUABLE_STATUSES else "FALSE"
        if row.get("IncludeInMetrics", "").upper() != expected:
            raise ValueError(f"IncludeInMetrics must be {expected} for {_row_key(row)}")
        labels[_row_key(row)] = row
    return labels


def _load_llm_predictions(path: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    predictions = {}
    for row in _read_csv(path):
        if row.get("Status") not in {"ok", "dry_run"}:
            continue
        result = row.get("Result", "").strip().lower()
        if result not in {"true", "false"}:
            continue
        predictions[_row_key(row)] = row
    return predictions


def merge(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    base_path = output / "legacy_ablation_per_crash.csv"
    if not base_path.is_file():
        raise FileNotFoundError(f"Run prepare first: {base_path}")
    rows = _read_csv(base_path)
    labels = _load_labels(output / "ground_truth_v2.csv")

    variant_inputs = {
        "V3": Path(args.v3).resolve(),
        "V4": Path(args.v4).resolve(),
    }
    prediction_maps = {name: _load_llm_predictions(path) for name, path in variant_inputs.items()}
    row_by_key = {_row_key(row): row for row in rows}
    representative_keys = {_row_key(row) for row in rows if _truthy(row.get("V2_SentToLLM"))}
    for variant, predictions in prediction_maps.items():
        missing = representative_keys.difference(predictions)
        if missing:
            raise RuntimeError(
                f"{variant} is incomplete: {len(predictions)}/{len(representative_keys)} successful representative "
                f"predictions. Do not merge dry-run or failed API output into paper metrics."
            )

    def representative_key(row: Mapping[str, str]) -> Tuple[str, str]:
        project = row.get("Project", "")
        current = row
        seen = set()
        while current.get("DuplicateOf"):
            candidate = (project, current["DuplicateOf"])
            if candidate in seen or candidate not in row_by_key:
                break
            seen.add(candidate)
            current = row_by_key[candidate]
        return _row_key(current)

    fields = list(rows[0])
    for variant in ("V3", "V4"):
        for suffix in ("SentToLLM", "IsApiBug", "SkipReason"):
            column = f"{variant}_{suffix}"
            if column not in fields:
                fields.insert(fields.index("GroundTruth"), column)
    for field in ("GroundTruthStatus", "IncludeInMetrics", "RepresentativeCrashID"):
        if field not in fields:
            fields.append(field)

    merged: List[Dict[str, str]] = []
    for row in rows:
        key = _row_key(row)
        label = labels.get(key)
        if label is None:
            raise KeyError(f"Missing ground-truth label for {key}")
        out = dict(row)
        out.update({field: label[field] for field in ("GroundTruthStatus", "IncludeInMetrics", "RepresentativeCrashID")})
        for variant in ("V3", "V4"):
            rep_key = representative_key(row)
            prediction = prediction_maps[variant].get(rep_key)
            if prediction is None:
                out[f"{variant}_SentToLLM"] = "FALSE"
                out[f"{variant}_IsApiBug"] = ""
                out[f"{variant}_SkipReason"] = "not_representative_or_missing"
                continue
            result = prediction["Result"].strip().lower()
            inherited = rep_key != key
            out[f"{variant}_SentToLLM"] = "FALSE" if inherited else "TRUE"
            out[f"{variant}_IsApiBug"] = result.upper()
            out[f"{variant}_SkipReason"] = "duplicate_inherited" if inherited else "none"
        merged.append(out)

    _write_csv(output / "controlled_ablation_per_crash.csv", fields, merged)
    print(f"Merged controlled ablation rows: {len(merged)}")
    return 0


def _metric_rows(rows: Sequence[Mapping[str, str]], variant: str) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    evaluable = target = non_target = unresolved = 0
    for row in rows:
        status = row.get("GroundTruthStatus", "")
        if status == STATUS_UNRESOLVED:
            unresolved += 1
            continue
        if status not in EVALUABLE_STATUSES:
            continue
        evaluable += 1
        truth = status == STATUS_TARGET
        target += int(truth)
        non_target += int(not truth)
        prediction = _truthy(row.get(f"{variant}_IsApiBug"))
        if prediction and truth:
            tp += 1
        elif prediction:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "Variant": variant, "EvaluableCrashes": evaluable, "ConfirmedTarget": target,
        "ConfirmedNonTarget": non_target, "UnresolvedCandidates": unresolved,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn, "Precision": f"{precision:.4f}",
        "Recall": f"{recall:.4f}", "F1": f"{f1:.4f}",
        "LLMCalls": sum(_truthy(row.get(f"{variant}_SentToLLM")) for row in rows),
    }


def evaluate(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    path = output / "controlled_ablation_per_crash.csv"
    if not path.is_file():
        raise FileNotFoundError(f"Run merge first: {path}")
    rows = _read_csv(path)
    status_counts = Counter(row.get("GroundTruthStatus", "") for row in rows)
    if status_counts[STATUS_NON_TARGET] == 0:
        raise RuntimeError(
            "No confirmed_non_target labels are available. Complete ground_truth_v2.csv before computing paper metrics."
        )
    variants = [variant for variant in DEFAULT_VARIANTS if f"{variant}_IsApiBug" in rows[0]]
    incomplete = [
        variant for variant in variants
        if any(not row.get(f"{variant}_IsApiBug", "").strip() for row in rows if row.get("GroundTruthStatus") in EVALUABLE_STATUSES)
    ]
    if incomplete:
        raise RuntimeError(f"Incomplete predictions for evaluable rows: {', '.join(incomplete)}")
    result_rows = [_metric_rows(rows, variant) for variant in variants]
    fields = list(result_rows[0]) if result_rows else []
    _write_csv(output / "controlled_ablation_results.csv", fields, result_rows)

    status_rows = []
    for (project, status), count in sorted(Counter((r["Project"], r["GroundTruthStatus"]) for r in rows).items()):
        status_rows.append({"Project": project, "GroundTruthStatus": status, "Count": count})
    _write_csv(output / "ground_truth_status_summary.csv", ["Project", "GroundTruthStatus", "Count"], status_rows)
    print(f"Evaluated {len(rows)} crashes; results: {output / 'controlled_ablation_results.csv'}")
    return 0


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def summarize_cost(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    records = [
        record for record in _read_csv(output / "cost_per_invocation.csv")
        if record.get("Status") != "dry_run"
    ]
    groups: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
    for record in records:
        groups[(record.get("Variant", ""), record.get("Stage", ""))].append(record)
    summary = []
    for (variant, stage), group in sorted(groups.items()):
        elapsed = [float(r["ElapsedMs"]) for r in group if r.get("ElapsedMs") not in {"", None}]
        succeeded = sum(r.get("Status") == "success" for r in group)
        skipped = sum(r.get("Status") == "skipped" for r in group)
        failed = len(group) - succeeded - skipped
        attempted = succeeded + failed
        prompt = sum(int(float(r.get("PromptTokens") or 0)) for r in group)
        completion = sum(int(float(r.get("CompletionTokens") or 0)) for r in group)
        summary.append({
            "Variant": variant, "Stage": stage, "Invocations": len(group),
            "Skipped": skipped, "Failed": failed,
            "SuccessRate": f"{(succeeded / attempted) if attempted else 0:.4f}",
            "MedianMs": f"{statistics.median(elapsed) if elapsed else 0:.1f}",
            "P95Ms": f"{_percentile(elapsed, 0.95):.1f}",
            "TotalMs": f"{sum(elapsed):.1f}", "PromptTokens": prompt,
            "CompletionTokens": completion, "TotalTokens": prompt + completion,
            "ApiCost": f"{sum(float(r.get('ApiCost') or 0) for r in group):.6f}",
        })
    fields = ["Variant", "Stage", "Invocations", "Skipped", "Failed", "SuccessRate", "MedianMs", "P95Ms", "TotalMs", "PromptTokens", "CompletionTokens", "TotalTokens", "ApiCost"]
    _write_csv(output / "cost_summary.csv", fields, summary)
    print(f"Cost summary: {output / 'cost_summary.csv'}")
    return 0


def record_llm_cost(args: argparse.Namespace) -> int:
    """Append one output row per external adjudication invocation to the cost log."""
    output = Path(args.output).resolve()
    path = output / "cost_per_invocation.csv"
    existing = _read_csv(path) if path.is_file() else []
    completed = {
        (r.get("Project"), r.get("CrashID"), r.get("Variant"), r.get("Stage"))
        for r in existing
    }
    additions = []
    for record in _read_csv(Path(args.input).resolve()):
        key = (record.get("Project"), record.get("CrashID"), args.variant, "llm_analysis")
        if key in completed:
            continue
        status = "success" if record.get("Status") == "ok" else (record.get("Status") or "unknown")
        additions.append({
            "Project": record.get("Project", ""), "CrashID": record.get("CrashID", ""),
            "RepresentativeCrashID": record.get("CrashID", ""), "Variant": args.variant,
            "Stage": "llm_analysis", "StartTimestamp": "", "ElapsedMs": record.get("LatencyMs", "0"),
            "Status": status, "RetryCount": record.get("RetryCount", "0"),
            "PromptChars": record.get("PromptChars", "0"), "PromptTokens": record.get("PromptTokens", "0"),
            "CompletionTokens": record.get("CompletionTokens", "0"), "TotalTokens": record.get("TotalTokens", "0"),
            "ApiCost": "", "RuntimeContextStatus": record.get("EvidenceVariant", ""),
            "RuntimeEvidenceQuality": "",
        })
    _write_csv(path, COST_FIELDS, [*existing, *additions])
    print(f"Added {len(additions)} LLM cost rows to {path}")
    return 0


def extract_legacy_cost(args: argparse.Namespace) -> int:
    """Copy existing timing metadata into the isolated cost log without mutation."""
    output = Path(args.output).resolve()
    db_root = Path(args.db_root).resolve()
    path = output / "cost_per_invocation.csv"
    existing = _read_csv(path) if path.is_file() else []
    existing_keys = {(r.get("Project"), r.get("CrashID"), r.get("Variant"), r.get("Stage")) for r in existing}
    additions: List[Dict[str, Any]] = []
    stage_specs = (
        ("triage", "stage2_triage_ms", "stage2_skipped", "stage2_skip_reason"),
        ("static_context", "stage3_locate_ms", "stage3_skipped", "stage3_skip_reason"),
        ("runtime_reconstruction", "stage4_runtime_ms", "stage4_skipped", "stage4_skip_reason"),
        ("dedup", "stage5_dedup_ms", "stage5_skipped", "stage5_skip_reason"),
        ("llm_analysis", "stage6_llm_ms", "llm_skipped", "llm_skip_reason"),
    )
    for project_dir in sorted(db_root.iterdir() if db_root.is_dir() else []):
        crash_root = project_dir / "crash"
        if not crash_root.is_dir():
            continue
        for driver_dir in sorted(path for path in crash_root.iterdir() if path.is_dir()):
            yaml_path = driver_dir / "crash_analysis.yaml"
            if not yaml_path.is_file():
                continue
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or []
            except yaml.YAMLError:
                continue
            if not isinstance(data, list):
                continue
            for item in data:
                if not isinstance(item, dict):
                    continue
                for local_id, entry in item.items():
                    if not isinstance(entry, dict):
                        continue
                    timings = entry.get("timings") or {}
                    crash_id = f"{driver_dir.name}_{local_id}"
                    runtime = entry.get("gdb_runtime_context") or {}
                    for stage, elapsed_field, skipped_field, reason_field in stage_specs:
                        key = (project_dir.name, crash_id, "legacy_V3", stage)
                        if key in existing_keys or elapsed_field not in timings:
                            continue
                        skipped = bool(timings.get(skipped_field))
                        additions.append({
                            "Project": project_dir.name, "CrashID": crash_id,
                            "RepresentativeCrashID": entry.get("duplicate_of") or crash_id,
                            "Variant": "legacy_V3", "Stage": stage, "StartTimestamp": "",
                            "ElapsedMs": timings.get(elapsed_field, ""),
                            "Status": "skipped" if skipped else "success",
                            "RetryCount": "", "PromptChars": "", "PromptTokens": "",
                            "CompletionTokens": "", "TotalTokens": "", "ApiCost": "",
                            "RuntimeContextStatus": (
                                "reproduced" if runtime.get("reproduced") else runtime.get("error_message", "")
                            ) if stage == "runtime_reconstruction" else "",
                            "RuntimeEvidenceQuality": runtime.get("evidence_quality", "") if stage == "runtime_reconstruction" else "",
                        })
    _write_csv(path, COST_FIELDS, [*existing, *additions])
    print(f"Copied {len(additions)} legacy timing rows to {path}")
    return 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Isolated CrashSage paper revision tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare", help="Create the isolated revision result directory")
    prepare_parser.add_argument("--source", default="results/ablation_per_crash.csv")
    prepare_parser.add_argument("--output", required=True)
    prepare_parser.add_argument("--resume", action="store_true")
    merge_parser = subparsers.add_parser("merge", help="Merge V3/V4 LLM results")
    merge_parser.add_argument("--output", required=True)
    merge_parser.add_argument("--v3", required=True)
    merge_parser.add_argument("--v4", required=True)
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate the confirmed subset only")
    evaluate_parser.add_argument("--output", required=True)
    cost_parser = subparsers.add_parser("summarize-cost", help="Summarize cost_per_invocation.csv")
    cost_parser.add_argument("--output", required=True)
    llm_cost_parser = subparsers.add_parser("record-llm-cost", help="Append external LLM usage to the cost log")
    llm_cost_parser.add_argument("--output", required=True)
    llm_cost_parser.add_argument("--input", required=True)
    llm_cost_parser.add_argument("--variant", required=True, choices=["V3", "V4"])
    legacy_cost_parser = subparsers.add_parser("extract-legacy-cost", help="Copy existing timing metadata without writing source YAML")
    legacy_cost_parser.add_argument("--output", required=True)
    legacy_cost_parser.add_argument("--db-root", default="external_database")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "prepare":
        return prepare(args)
    if args.command == "merge":
        return merge(args)
    if args.command == "evaluate":
        return evaluate(args)
    if args.command == "record-llm-cost":
        return record_llm_cost(args)
    if args.command == "extract-legacy-cost":
        return extract_legacy_cost(args)
    return summarize_cost(args)


if __name__ == "__main__":
    raise SystemExit(main())
