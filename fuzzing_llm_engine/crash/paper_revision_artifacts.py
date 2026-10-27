#!/usr/bin/env python3
"""Generate paper-ready revision artifacts without editing the manuscript.

Outputs are written under results/revision_20260722:

* paper_stage_ablation_results.csv
* paper_controlled_ablation_results.csv
* paper_cost_summary.csv
* manual_adjudication_summary.csv
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Sequence


LEGACY_VARIANTS = ("V0", "V1", "V2", "V3")
LEGACY_DESCRIPTIONS = {
    "V0": "Raw LLM",
    "V1": "Rule-guided LLM",
    "V2": "Rule-guided LLM with representative selection",
    "V3": "Full CrashSage",
}

CONTROLLED_DESCRIPTIONS = {
    "V1": "Rule-guided filtering + direct prompt",
    "V2": "Filtering + representative selection + direct prompt",
    "V3": "Representatives + static/runtime context + direct prompt",
    "V4": "Representatives + context + differential prompt",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def truth(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def compute_metrics(rows: Sequence[Mapping[str, str]], pred_fn: Callable[[Mapping[str, str]], bool]) -> Dict[str, object]:
    tp = fp = tn = fn = 0
    for row in rows:
        gt = truth(row.get("GroundTruth", ""))
        pred = pred_fn(row)
        if pred and gt:
            tp += 1
        elif pred and not gt:
            fp += 1
        elif not pred and gt:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "Precision": f"{precision:.3f}",
        "Recall": f"{recall:.3f}",
        "F1": f"{f1:.3f}",
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
    }


def legacy_predicate(variant: str) -> Callable[[Mapping[str, str]], bool]:
    return lambda row: truth(row.get(f"{variant}_IsApiBug", ""))


def legacy_llm_calls(rows: Sequence[Mapping[str, str]], variant: str) -> int:
    return sum(1 for row in rows if truth(row.get(f"{variant}_SentToLLM", "")))


def build_stage_ablation(results_dir: Path, output_dir: Path) -> None:
    rows = read_csv(results_dir / "ablation_per_crash.csv")
    labels = {row["CrashID"]: row for row in read_csv(output_dir / "ground_truth_v2.csv")}
    evaluable_rows = []
    for row in rows:
        status = labels.get(row["CrashID"], {}).get("GroundTruthStatus", "")
        if status in {"confirmed_target", "confirmed_non_target"}:
            merged = dict(row)
            merged["GroundTruth"] = "TRUE" if status == "confirmed_target" else "FALSE"
            evaluable_rows.append(merged)
    out_rows = []
    for variant in LEGACY_VARIANTS:
        metrics = compute_metrics(evaluable_rows, legacy_predicate(variant))
        out_rows.append({
            "Variant": variant,
            "Description": LEGACY_DESCRIPTIONS[variant],
            **metrics,
            "LLMInvocations": legacy_llm_calls(rows, variant),
        })
    write_csv(
        output_dir / "paper_stage_ablation_results.csv",
        ["Variant", "Description", "Precision", "Recall", "F1", "LLMInvocations", "TP", "FP", "TN", "FN"],
        out_rows,
    )


def build_controlled_paper_table(output_dir: Path) -> None:
    rows = read_csv(output_dir / "controlled_ablation_results.csv")
    out_rows = []
    for row in rows:
        variant = row["Variant"]
        out_rows.append({
            "Variant": variant,
            "Description": CONTROLLED_DESCRIPTIONS.get(variant, ""),
            "Precision": f"{float(row['Precision']):.3f}",
            "Recall": f"{float(row['Recall']):.3f}",
            "F1": f"{float(row['F1']):.3f}",
            "LLMInvocations": row.get("LLMCalls", ""),
            "TP": row.get("TP", ""),
            "FP": row.get("FP", ""),
            "TN": row.get("TN", ""),
            "FN": row.get("FN", ""),
            "EvaluableCrashes": row.get("EvaluableCrashes", ""),
            "ConfirmedTarget": row.get("ConfirmedTarget", ""),
            "ConfirmedNonTarget": row.get("ConfirmedNonTarget", ""),
            "UnresolvedCandidates": row.get("UnresolvedCandidates", ""),
        })
    write_csv(
        output_dir / "paper_controlled_ablation_results.csv",
        [
            "Variant", "Description", "Precision", "Recall", "F1", "LLMInvocations",
            "TP", "FP", "TN", "FN", "EvaluableCrashes", "ConfirmedTarget",
            "ConfirmedNonTarget", "UnresolvedCandidates",
        ],
        out_rows,
    )


def build_cost_table(output_dir: Path) -> None:
    rows = read_csv(output_dir / "cost_summary.csv")
    out_rows = []
    for row in rows:
        variant = row["Variant"]
        stage = row["Stage"]
        if stage == "llm_analysis" and variant in {"V3", "V4"}:
            category = "LLM adjudication"
        elif variant == "legacy_V3" and stage == "runtime_reconstruction":
            category = "Runtime reconstruction"
        elif variant == "legacy_V3" and stage == "static_context":
            category = "Static context reconstruction"
        elif variant == "legacy_V3" and stage == "triage":
            category = "Rule-based triage"
        elif variant == "legacy_V3" and stage == "dedup":
            category = "Deduplication"
        else:
            category = "Legacy LLM analysis"
        prompt_tokens = int(float(row.get("PromptTokens") or 0))
        completion_tokens = int(float(row.get("CompletionTokens") or 0))
        qwen_cost_rmb = (prompt_tokens / 1_000_000) * 4.0 + (completion_tokens / 1_000_000) * 16.0
        out_rows.append({
            "Category": category,
            **row,
            "QwenCostRMB": f"{qwen_cost_rmb:.4f}",
        })
    write_csv(
        output_dir / "paper_cost_summary.csv",
        [
            "Category", "Variant", "Stage", "Invocations", "Skipped", "Failed", "SuccessRate",
            "MedianMs", "P95Ms", "TotalMs", "PromptTokens", "CompletionTokens", "TotalTokens",
            "QwenCostRMB", "ApiCost",
        ],
        out_rows,
    )


def build_manual_adjudication_summary(output_dir: Path) -> None:
    evidence_rows = read_csv(output_dir / "manual_ground_truth_evidence.csv")
    metric_rows = read_csv(output_dir / "ground_truth_v2.csv")
    manual_counts = Counter(row["ManualGroundTruthStatus"] for row in evidence_rows)
    metric_counts = Counter(row["GroundTruthStatus"] for row in metric_rows)
    evidence_counts = Counter(row["EvidenceType"] for row in evidence_rows)
    rows = [
        {
            "Item": "confirmed public target crashes",
            "Count": manual_counts["confirmed_target"],
            "UseInMainMetrics": "yes",
            "Note": "legacy TRUE rows; author-confirmed public driver+PoC reproductions",
        },
        {
            "Item": "confirmed non-target crashes",
            "Count": manual_counts["confirmed_non_target"],
            "UseInMainMetrics": "yes",
            "Note": "evidence-supported non-target or not publicly confirmed target-component vulnerabilities after manual audit",
        },
        {
            "Item": "potential unpublished API bugs",
            "Count": sum(count for evidence, count in evidence_counts.items() if evidence.startswith("potential_unpublished_api_bug")),
            "UseInMainMetrics": "no",
            "Note": "single unresolved category; kept separate from confirmed target and confirmed non-target labels",
        },
        {
            "Item": "main metric evaluable crashes",
            "Count": metric_counts["confirmed_target"] + metric_counts["confirmed_non_target"],
            "UseInMainMetrics": "yes",
            "Note": f"{metric_counts['confirmed_target']} confirmed target + {metric_counts['confirmed_non_target']} confirmed non-target",
        },
    ]
    write_csv(output_dir / "manual_adjudication_summary.csv", ["Item", "Count", "UseInMainMetrics", "Note"], rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-dir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    engine_dir = args.engine_dir.resolve()
    output_dir = (args.output_dir or engine_dir / "results" / "revision_20260722").resolve()
    build_stage_ablation(engine_dir / "results", output_dir)
    build_controlled_paper_table(output_dir)
    build_cost_table(output_dir)
    build_manual_adjudication_summary(output_dir)
    print(f"Paper-ready artifacts written to {output_dir}")


if __name__ == "__main__":
    main()
