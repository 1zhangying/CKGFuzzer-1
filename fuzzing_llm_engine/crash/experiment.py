#!/usr/bin/env python3
"""Batch experiment runner & paper-ready comparison table generator.

Scans ALL project crash directories, runs retroanalyze on each, and aggregates
results into a single summary that can be directly used in the paper.

Three modes:
  1. retroanalyze (default): Run deterministic triage on all projects, compare
     against stored LLM judgments.  No LLM calls — completely free.
  2. summary: Just aggregate previously saved retroanalyze results.
  3. csv: Output a CSV table suitable for paper figures.

Usage:
    cd fuzzing_llm_engine

    # Run retroanalyze on ALL projects that have crash data
    python -m crash.experiment --db-root external_database --output results/

    # Re-aggregate existing results
    python -m crash.experiment --db-root external_database --output results/ --mode summary

    # Export CSV for paper
    python -m crash.experiment --db-root external_database --output results/ --mode csv
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import sys
import yaml
from datetime import datetime
from typing import Any, Dict, List

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.retroanalyze import retroanalyze_dir, print_summary

ABLATION_VARIANTS = ("V0", "V1", "V2", "V3", "V4")
ABLATION_DESCRIPTIONS = {
    "V0": "Raw LLM",
    "V1": "Rule-guided filtering",
    "V2": "Filtering + representatives",
    "V3": "Representatives + context",
    "V4": "Full CrashSage",
}

# ── helpers ──────────────────────────────────────────────────────────────────

def _csv_bool(value: Any) -> Any:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if value is None:
        return ""
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return "TRUE"
        if lowered in ("false", "0", "no"):
            return "FALSE"
    return value


def discover_projects(db_root: str) -> List[str]:
    """Find all project directories under db_root that have a crash/ subfolder."""
    projects = []
    if not os.path.isdir(db_root):
        return projects
    for name in sorted(os.listdir(db_root)):
        crash_dir = os.path.join(db_root, name, "crash")
        if os.path.isdir(crash_dir):
            # Must have at least one crash_analysis.yaml inside
            has_yaml = any(
                os.path.isfile(os.path.join(crash_dir, d, "crash_analysis.yaml"))
                for d in os.listdir(crash_dir)
                if os.path.isdir(os.path.join(crash_dir, d))
            )
            if has_yaml:
                projects.append(name)
    return projects


def _output_path(output_dir: str, filename: str, run_tag: str | None) -> str:
    """Return a dated sibling path without replacing the legacy filename."""
    if not run_tag:
        return os.path.join(output_dir, filename)
    stem, ext = os.path.splitext(filename)
    return os.path.join(output_dir, f"{stem}_{run_tag}{ext}")


def run_all_retroanalyze(
    db_root: str,
    output_dir: str,
    project: str | None = None,
    run_tag: str | None = None,
) -> Dict[str, Any]:
    """Run retroanalyze on every discovered project and save individual + aggregate results."""
    projects = discover_projects(db_root)
    if project:
        if project not in projects:
            raise ValueError(f"Project not found under {db_root}: {project}")
        projects = [project]
    if not projects:
        print(f"[!] No projects with crash data found under {db_root}")
        return {}

    print(f"\n{'='*70}")
    print(f"  BATCH EXPERIMENT: {len(projects)} projects found")
    print(f"  DB root: {db_root}")
    print(f"  Output:  {output_dir}")
    print(f"{'='*70}\n")

    os.makedirs(output_dir, exist_ok=True)

    all_reports = {}
    for proj in projects:
        crash_dir = os.path.join(db_root, proj, "crash")
        print(f"\n>>> Processing: {proj}")
        print(f"    Crash dir: {crash_dir}")
        try:
            report = retroanalyze_dir(crash_dir)
            report["project"] = proj
            all_reports[proj] = report

            # Save individual result
            out_file = _output_path(output_dir, f"{proj}_retro.yaml", run_tag)
            with open(out_file, "w") as f:
                yaml.dump(report, f, default_flow_style=False, allow_unicode=True, width=120)
            print(f"    Saved: {out_file}")

            print_summary(report)
        except Exception as e:
            print(f"    [ERROR] {e}")
            import traceback; traceback.print_exc()

    return all_reports


# ── Aggregate summary ────────────────────────────────────────────────────────

def aggregate_summary(all_reports: Dict[str, Dict]) -> Dict[str, Any]:
    """Produce a cross-project aggregate summary."""
    if not all_reports:
        return {}

    total_crashes = 0
    total_old_api = 0
    total_new_api = 0
    total_changed = 0
    total_unique = 0
    total_llm_saved = 0
    per_project = []

    # Aggregate per-variant ablation metrics across projects
    agg_ablation: Dict[str, Dict[str, int]] = {
        v: {"llm_invocations": 0, "llm_saved": 0, "classified_as_api_bug": 0}
        for v in ABLATION_VARIANTS
    }

    for proj, report in all_reports.items():
        s = report["summary"]
        tc = s["total_crashes"]
        total_crashes += tc
        total_old_api += s["old_api_bug_count"]
        total_new_api += s["new_api_bug_count"]
        total_changed += s["judgments_changed"]
        total_unique += s["unique_crashes_after_dedup"]
        total_llm_saved += s["llm_calls_saved"]

        proj_ablation = s.get("ablation_variants", {})
        for v in ABLATION_VARIANTS:
            vs = proj_ablation.get(v, {})
            agg_ablation[v]["llm_invocations"] += vs.get("llm_invocations", 0)
            agg_ablation[v]["llm_saved"] += vs.get("llm_saved", 0)
            agg_ablation[v]["classified_as_api_bug"] += vs.get("classified_as_api_bug", 0)

        per_project.append({
            "project": proj,
            "total_crashes": tc,
            "old_api_bug": s["old_api_bug_count"],
            "new_api_bug": s["new_api_bug_count"],
            "judgments_changed": s["judgments_changed"],
            "fp_rate_old": s["false_positive_rate_old"],
            "unique_after_dedup": s["unique_crashes_after_dedup"],
            "dedup_ratio": s["dedup_reduction_ratio"],
            "llm_saved": s["llm_calls_saved"],
            "llm_saved_ratio": s["llm_calls_saved_ratio"],
            "triage_dist": s["triage_label_distribution"],
            "ablation_variants": proj_ablation,
        })

    # Compute ablation ratios
    for v in ABLATION_VARIANTS:
        a = agg_ablation[v]
        a["llm_saved_ratio"] = round(a["llm_saved"] / total_crashes, 3) if total_crashes else 0

    agg = {
        "timestamp": datetime.now().isoformat(),
        "num_projects": len(all_reports),
        "total_crashes": total_crashes,
        "total_old_api_bug": total_old_api,
        "total_new_api_bug": total_new_api,
        "total_judgments_changed": total_changed,
        "aggregate_fp_rate_old": round(total_old_api / total_crashes, 3) if total_crashes else 0,
        "total_unique_after_dedup": total_unique,
        "aggregate_dedup_ratio": round(1 - total_unique / total_crashes, 3) if total_crashes else 0,
        "total_llm_saved": total_llm_saved,
        "aggregate_llm_saved_ratio": round(total_llm_saved / total_crashes, 3) if total_crashes else 0,
        "per_project": per_project,
        "ablation_aggregate": agg_ablation,
    }
    return agg


def print_aggregate(agg: Dict[str, Any]):
    """Pretty-print cross-project aggregate."""
    if not agg:
        print("[!] No aggregate data.")
        return

    print("\n" + "=" * 70)
    print("  CROSS-PROJECT AGGREGATE SUMMARY")
    print("=" * 70)
    print(f"  Projects analyzed:             {agg['num_projects']}")
    print(f"  Total crashes:                 {agg['total_crashes']}")
    print(f"  Old LLM 'is_api_bug=True':     {agg['total_old_api_bug']}")
    print(f"  New triage 'is_api_bug':        {agg['total_new_api_bug']}")
    print(f"  Judgments changed:              {agg['total_judgments_changed']}")
    print(f"  Aggregate old FP rate:          {agg['aggregate_fp_rate_old']:.1%}")
    print(f"  Unique after dedup:             {agg['total_unique_after_dedup']}")
    print(f"  Aggregate dedup ratio:          {agg['aggregate_dedup_ratio']:.1%}")
    print(f"  LLM calls saved:               {agg['total_llm_saved']} / {agg['total_crashes']}"
          f" ({agg['aggregate_llm_saved_ratio']:.1%})")
    print()

    # Per-project table
    header = f"  {'Project':15s} {'Crashes':>8s} {'OldAPI':>7s} {'NewAPI':>7s} {'Changed':>8s} {'FP%':>6s} {'Unique':>7s} {'Dedup%':>7s} {'LLMSaved':>9s}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for p in agg["per_project"]:
        print(f"  {p['project']:15s} "
              f"{p['total_crashes']:8d} "
              f"{p['old_api_bug']:7d} "
              f"{p['new_api_bug']:7d} "
              f"{p['judgments_changed']:8d} "
              f"{p['fp_rate_old']:5.1%} "
              f"{p['unique_after_dedup']:7d} "
              f"{p['dedup_ratio']:6.1%} "
              f"{p['llm_saved']:4d}/{p['total_crashes']:<4d}")

    # Ablation variant comparison (Paper Table 5 / Fig 9)
    ablation_agg = agg.get("ablation_aggregate")
    if ablation_agg:
        tc = agg["total_crashes"]
        print()
        print("  " + "-" * 68)
        print("  ABLATION VARIANT COMPARISON (Paper RQ5)")
        print("  " + "-" * 68)
        print(f"    {'Variant':10s} {'Description':28s} {'LLMCalls':>9s} {'Saved':>7s} {'SavedRatio':>11s} {'ApiBugs':>8s}")
        for v in ABLATION_VARIANTS:
            a = ablation_agg.get(v, {})
            print(f"    {v:10s} {ABLATION_DESCRIPTIONS.get(v, ''):28s} "
                  f"{a.get('llm_invocations', 0):9d} "
                  f"{a.get('llm_saved', 0):7d} "
                  f"{a.get('llm_saved_ratio', 0):10.1%} "
                  f"{a.get('classified_as_api_bug', 0):8d}")

    print("=" * 70)


# ── CSV export ───────────────────────────────────────────────────────────────

def export_per_project_csv(
    agg: Dict[str, Any], output_dir: str, run_tag: str | None = None,
):
    """Export per-project summary as CSV (Table 1 in paper)."""
    csv_path = _output_path(output_dir, "per_project_summary.csv", run_tag)
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "Project", "TotalCrashes", "OldApiBug", "NewApiBug",
            "JudgmentsChanged", "OldFPRate", "UniqueAfterDedup",
            "DedupRatio", "LLMCallsSaved", "LLMSavedRatio",
        ])
        for p in agg["per_project"]:
            w.writerow([
                p["project"], p["total_crashes"], p["old_api_bug"],
                p["new_api_bug"], p["judgments_changed"],
                f"{p['fp_rate_old']:.3f}", p["unique_after_dedup"],
                f"{p['dedup_ratio']:.3f}", p["llm_saved"],
                f"{p['llm_saved_ratio']:.3f}",
            ])
    print(f"  CSV saved: {csv_path}")
    return csv_path


def export_per_crash_csv(
    all_reports: Dict[str, Dict], output_dir: str, run_tag: str | None = None,
):
    """Export per-crash detail as CSV (for detailed ground-truth labeling).

    Columns include THREE judgments for comparison:
      - BaselineIsApiBug: old LLM without triage (ablation or old-format data)
      - TriageIsApiBug:   deterministic triage rules judgment
      - EnhancedIsApiBug: stored is_api_bug from YAML (enhanced LLM or old LLM)
    """
    csv_path = _output_path(output_dir, "per_crash_detail.csv", run_tag)
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "Project", "CrashID", "Driver", "BugType", "Sanitizer",
            "BaselineIsApiBug", "TriageLabel", "TriageIsApiBug",
            "EnhancedIsApiBug", "HasAblation",
            "TriageRules", "TriageConfidence",
            "JudgmentChanged", "IsDuplicate", "DuplicateOf",
            "Signature", "CrashFile", "CrashFunction",
            "GroundTruth",
        ])
        for proj, report in sorted(all_reports.items()):
            for c in report["crashes"]:
                w.writerow([
                    proj,
                    c["crash_id"],
                    c.get("driver", ""),
                    c.get("parsed_bug_type", ""),
                    c.get("parsed_sanitizer", ""),
                    c.get("baseline_is_api_bug", c["old_is_api_bug"]),
                    c["triage_label"],
                    c["new_is_api_bug"],
                    c["old_is_api_bug"],
                    c.get("has_ablation_baseline", False),
                    ",".join(c.get("triage_rules") or []),
                    c.get("triage_confidence", ""),
                    c["judgment_changed"],
                    c.get("is_duplicate", ""),
                    c.get("duplicate_of", ""),
                    c.get("signature", ""),
                    c.get("crash_file", ""),
                    c.get("crash_function", ""),
                    "",
                ])
    print(f"  CSV saved: {csv_path}")
    print(f"  ↑ Fill the GroundTruth column with True/False for evaluation")
    print(f"  ↑ 三列对比: BaselineIsApiBug / TriageIsApiBug / EnhancedIsApiBug")
    return csv_path


def export_triage_distribution_csv(
    all_reports: Dict[str, Dict], output_dir: str, run_tag: str | None = None,
):
    """Export triage label distribution per project (for paper figure)."""
    csv_path = _output_path(output_dir, "triage_distribution.csv", run_tag)

    # Collect all labels
    all_labels = set()
    for report in all_reports.values():
        for lbl in report["summary"]["triage_label_distribution"]:
            all_labels.add(lbl)
    all_labels = sorted(all_labels)

    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Project"] + all_labels + ["Total"])
        for proj, report in sorted(all_reports.items()):
            dist = report["summary"]["triage_label_distribution"]
            row = [proj] + [dist.get(lbl, 0) for lbl in all_labels] + [report["summary"]["total_crashes"]]
            w.writerow(row)
    print(f"  CSV saved: {csv_path}")
    return csv_path


# ── Ablation CSV export ──────────────────────────────────────────────────────

def export_ablation_csv(
    all_reports: Dict[str, Dict], output_dir: str, run_tag: str | None = None,
):
    """Export per-variant ablation comparison as CSV (Paper Table 5 / Fig 9).

    Two files:
      - ablation_per_project.csv: per-project per-variant LLM calls and api_bug counts
      - ablation_per_crash.csv:   per-crash per-variant sent_to_llm and is_api_bug
    """
    # Per-project ablation CSV
    csv1 = _output_path(output_dir, "ablation_per_project.csv", run_tag)
    with open(csv1, "w", newline="") as f:
        w = csv.writer(f)
        header = ["Project", "TotalCrashes"]
        for v in ABLATION_VARIANTS:
            header.extend([f"{v}_LLMCalls", f"{v}_LLMSaved", f"{v}_SavedRatio", f"{v}_ApiBugs"])
        w.writerow(header)
        for proj, report in sorted(all_reports.items()):
            s = report["summary"]
            row = [proj, s["total_crashes"]]
            ablation = s.get("ablation_variants", {})
            for v in ABLATION_VARIANTS:
                a = ablation.get(v, {})
                row.extend([
                    a.get("llm_invocations", 0),
                    a.get("llm_saved", 0),
                    f"{a.get('llm_saved_ratio', 0):.3f}",
                    a.get("classified_as_api_bug", 0),
                ])
            w.writerow(row)
    print(f"  Ablation per-project CSV saved: {csv1}")

    # Per-crash ablation CSV
    csv2 = _output_path(output_dir, "ablation_per_crash.csv", run_tag)
    with open(csv2, "w", newline="") as f:
        w = csv.writer(f)
        header = ["Project", "CrashID", "Driver", "BugType", "TriageLabel",
                   "IsDuplicate", "DuplicateOf"]
        for v in ABLATION_VARIANTS:
            header.extend([f"{v}_SentToLLM", f"{v}_IsApiBug", f"{v}_SkipReason"])
        header.append("GroundTruth")
        w.writerow(header)
        for proj, report in sorted(all_reports.items()):
            for c in report["crashes"]:
                row = [
                    proj,
                    c["crash_id"],
                    c.get("driver", ""),
                    c.get("parsed_bug_type", ""),
                    c.get("triage_label", ""),
                    _csv_bool(c.get("is_duplicate", False)),
                    c.get("duplicate_of", ""),
                ]
                av = c.get("ablation_variants", {})
                for v in ABLATION_VARIANTS:
                    vd = av.get(v, {})
                    row.extend([
                        _csv_bool(vd.get("sent_to_llm", "")),
                        _csv_bool(vd.get("is_api_bug", "")),
                        vd.get("skip_reason", ""),
                    ])
                row.append("")
                w.writerow(row)
    print(f"  Ablation per-crash CSV saved: {csv2}")
    print(f"  ↑ Fill the GroundTruth column, then run --evaluate-ablation {csv2}")
    return csv1, csv2


# ── Ground truth evaluation ──────────────────────────────────────────────────

def _compute_metrics(rows, pred_fn):
    """Compute TP/FP/TN/FN/Precision/Recall/F1 for a prediction function."""
    tp = fp = tn = fn = 0
    for r in rows:
        gt = r["_gt"]
        pred = pred_fn(r)
        if pred and gt:
            tp += 1
        elif pred and not gt:
            fp += 1
        elif not pred and gt:
            fn += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / total if total else 0
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": precision, "recall": recall,
        "f1": f1, "accuracy": accuracy,
    }


def _ground_truth_value(row: Dict[str, str]) -> str:
    """Read the current GroundTruth column, with LLMLabel fallback for old CSVs."""
    return (row.get("GroundTruth") or row.get("LLMLabel") or "").strip().lower()


def evaluate_ground_truth(csv_path: str):
    """Read per_crash_detail.csv with GroundTruth, compute precision/recall/F1."""
    if not os.path.isfile(csv_path):
        print(f"[!] {csv_path} not found. Run experiment first, then label GroundTruth column.")
        return

    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt = _ground_truth_value(row)
            if gt in ("true", "false", "1", "0", "yes", "no"):
                row["_gt"] = gt in ("true", "1", "yes")
                rows.append(row)

    if not rows:
        print(f"[!] No GroundTruth labels found in {csv_path}.")
        print(f"    Please open the CSV and fill in True/False in the GroundTruth column.")
        return

    print(f"\n{'='*70}")
    print(f"  GROUND TRUTH EVALUATION ({len(rows)} labeled crashes)")
    print(f"{'='*70}\n")

    methods = {
        "Baseline LLM":       lambda r: r["BaselineIsApiBug"].strip().lower() in ("true", "1"),
        "Triage rules":       lambda r: r["TriageLabel"] in ("likely_api_bug", "needs_review"),
        "Triage (is_api)":    lambda r: r["TriageIsApiBug"].strip().lower() in ("true", "1"),
        "Enhanced LLM":       lambda r: r["EnhancedIsApiBug"].strip().lower() in ("true", "1"),
    }

    for method_name, pred_fn in methods.items():
        m = _compute_metrics(rows, pred_fn)
        print(f"  Method: {method_name}")
        print(f"    TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}")
        print(f"    Precision: {m['precision']:.3f}  Recall: {m['recall']:.3f}  "
              f"F1: {m['f1']:.3f}  Accuracy: {m['accuracy']:.3f}")
        print()

    print("=" * 70)


def evaluate_ablation_ground_truth(csv_path: str):
    """Read ablation_per_crash.csv with GroundTruth, compute per-variant metrics.

    This produces the key table for paper RQ5 (Ablation Study):
      Variant | Precision | Recall | F1 | LLM Invocations

    V2 uses the V1 judgment while saving calls through deduplication. Duplicate
    judgments are materialized in the CSV before evaluation.
    """
    if not os.path.isfile(csv_path):
        print(f"[!] {csv_path} not found.")
        return

    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt = _ground_truth_value(row)
            if gt in ("true", "false", "1", "0", "yes", "no"):
                row["_gt"] = gt in ("true", "1", "yes")
                rows.append(row)

    if not rows:
        print(f"[!] No GroundTruth labels found in {csv_path}.")
        print(f"    Fill the GroundTruth column with True/False first.")
        return

    def _make_pred_fn(v):
        """Build prediction function for each ablation variant."""
        def pred_fn(r):
            val = r.get(f"{v}_IsApiBug", "").strip().lower()
            return val in ("true", "1")
        return pred_fn

    print(f"\n{'='*78}")
    print(f"  ABLATION STUDY — GROUND TRUTH EVALUATION ({len(rows)} labeled crashes)")
    print(f"{'='*78}\n")
    print(f"  {'Variant':10s} {'Description':22s} {'Prec':>6s} {'Rec':>6s} {'F1':>6s} "
          f"{'LLMCalls':>9s} {'TP':>4s} {'FP':>4s} {'TN':>4s} {'FN':>4s}")
    print(f"  {'-'*76}")

    results = []
    for v in ABLATION_VARIANTS:
        pred_fn = _make_pred_fn(v)
        m = _compute_metrics(rows, pred_fn)
        llm_calls = sum(
            1 for r in rows
            if r.get(f"{v}_SentToLLM", "").strip().lower() in ("true", "1")
        )
        print(f"  {v:10s} {ABLATION_DESCRIPTIONS.get(v, ''):22s} "
              f"{m['precision']:6.3f} {m['recall']:6.3f} {m['f1']:6.3f} "
              f"{llm_calls:9d} "
              f"{m['TP']:4d} {m['FP']:4d} {m['TN']:4d} {m['FN']:4d}")
        results.append((v, m, llm_calls))

    print(f"\n  {'='*76}")
    print(f"  Note: duplicate predictions are materialized per crash before evaluation.")
    print(f"  LLMCalls counts only non-skipped invocations (dedup+triage saves).")
    print(f"{'='*78}")

    out_csv = csv_path.replace(".csv", "_results.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Variant", "Description", "Precision", "Recall", "F1",
                     "LLMInvocations", "TP", "FP", "TN", "FN"])
        for v, m, llm_calls in results:
            w.writerow([v, ABLATION_DESCRIPTIONS.get(v, ""), f"{m['precision']:.3f}",
                         f"{m['recall']:.3f}", f"{m['f1']:.3f}",
                         llm_calls, m["TP"], m["FP"], m["TN"], m["FN"]])
    print(f"\n  Results CSV: {out_csv}")


# ── main ─────────────────────────────────────────────────────────────────────

def _load_reports_from_yaml(
    db_root: str,
    output_dir: str,
    project: str | None = None,
    run_tag: str | None = None,
) -> Dict[str, Dict]:
    """Load previously saved retroanalyze YAML results."""
    projects = [project] if project else discover_projects(db_root)
    all_reports = {}
    for proj in projects:
        if run_tag:
            candidates = [
                _output_path(output_dir, f"{proj}_retro.yaml", run_tag),
            ]
        else:
            candidates = [
                os.path.join(output_dir, f"{proj}_retro.yaml"),
                *glob.glob(os.path.join(output_dir, f"{proj}_retro_*.yaml")),
            ]
        existing = [path for path in candidates if os.path.isfile(path)]
        if not existing:
            continue
        retro_path = max(
            existing,
            key=lambda path: (os.path.getmtime(path), path),
        )
        with open(retro_path) as f:
            all_reports[proj] = yaml.safe_load(f)
    return all_reports


def main():
    parser = argparse.ArgumentParser(
        description="Batch experiment runner for crash analysis comparison",
    )
    parser.add_argument("--db-root", default="external_database",
                        help="Root directory containing project subdirs (default: external_database)")
    parser.add_argument("--output", default="results/",
                        help="Output directory for results (default: results/)")
    parser.add_argument("--project", default=None,
                        help="Only analyze/load this specific project")
    parser.add_argument("--run-tag", default=None,
                        help="Output timestamp tag; defaults to the current time for "
                             "retroanalyze/ablation and to the latest saved run for "
                             "summary/csv")
    parser.add_argument("--mode", choices=["retroanalyze", "summary", "csv", "ablation"],
                        default="retroanalyze",
                        help="Mode: retroanalyze (full run), summary (re-aggregate), "
                             "csv (export tables), ablation (export ablation CSVs)")
    parser.add_argument("--evaluate", default=None,
                        help="Path to per_crash_detail.csv with GroundTruth for evaluation")
    parser.add_argument("--evaluate-ablation", default=None,
                        help="Path to ablation_per_crash.csv with GroundTruth for per-variant evaluation")
    args = parser.parse_args()

    # Ground truth evaluation modes
    if args.evaluate:
        evaluate_ground_truth(args.evaluate)
        return
    if args.evaluate_ablation:
        evaluate_ablation_ground_truth(args.evaluate_ablation)
        return

    os.makedirs(args.output, exist_ok=True)
    run_tag = args.run_tag or datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.mode == "retroanalyze":
        # Full run
        try:
            all_reports = run_all_retroanalyze(
                args.db_root, args.output, project=args.project, run_tag=run_tag,
            )
        except ValueError as exc:
            print(f"[!] {exc}")
            sys.exit(1)
        if not all_reports:
            print("[!] No projects with crash data found.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)

        # Save aggregate
        agg_path = _output_path(args.output, "aggregate_summary.yaml", run_tag)
        with open(agg_path, "w") as f:
            yaml.dump(agg, f, default_flow_style=False, allow_unicode=True, width=120)
        print(f"\n  Aggregate saved: {agg_path}")

        # Export CSVs
        print("\n  Exporting CSVs for paper...")
        export_per_project_csv(agg, args.output, run_tag=run_tag)
        export_per_crash_csv(all_reports, args.output, run_tag=run_tag)
        export_triage_distribution_csv(all_reports, args.output, run_tag=run_tag)
        export_ablation_csv(all_reports, args.output, run_tag=run_tag)

    elif args.mode == "summary":
        all_reports = _load_reports_from_yaml(
            args.db_root, args.output, project=args.project,
            run_tag=args.run_tag,
        )
        if not all_reports:
            print("[!] No saved retroanalyze results found. Run --mode retroanalyze first.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)

    elif args.mode == "csv":
        all_reports = _load_reports_from_yaml(
            args.db_root, args.output, project=args.project,
            run_tag=args.run_tag,
        )
        if not all_reports:
            print("[!] No saved retroanalyze results found. Run --mode retroanalyze first.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)
        export_per_project_csv(agg, args.output, run_tag=run_tag)
        export_per_crash_csv(all_reports, args.output, run_tag=run_tag)
        export_triage_distribution_csv(all_reports, args.output, run_tag=run_tag)
        export_ablation_csv(all_reports, args.output, run_tag=run_tag)

    elif args.mode == "ablation":
        # Always re-run retroanalyze to ensure ablation_variants are computed
        try:
            all_reports = run_all_retroanalyze(
                args.db_root, args.output, project=args.project, run_tag=run_tag,
            )
        except ValueError as exc:
            print(f"[!] {exc}")
            sys.exit(1)
        if not all_reports:
            print("[!] No projects with crash data found.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)
        export_ablation_csv(all_reports, args.output, run_tag=run_tag)


if __name__ == "__main__":
    main()
