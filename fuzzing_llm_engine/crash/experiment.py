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
import os
import sys
import yaml
from datetime import datetime
from typing import Any, Dict, List

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.retroanalyze import retroanalyze_dir, print_summary


# ── helpers ──────────────────────────────────────────────────────────────────

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


def run_all_retroanalyze(db_root: str, output_dir: str) -> Dict[str, Any]:
    """Run retroanalyze on every discovered project and save individual + aggregate results."""
    projects = discover_projects(db_root)
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
            out_file = os.path.join(output_dir, f"{proj}_retro.yaml")
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

    for proj, report in all_reports.items():
        s = report["summary"]
        tc = s["total_crashes"]
        total_crashes += tc
        total_old_api += s["old_api_bug_count"]
        total_new_api += s["new_api_bug_count"]
        total_changed += s["judgments_changed"]
        total_unique += s["unique_crashes_after_dedup"]
        total_llm_saved += s["llm_calls_saved"]

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
        })

    agg = {
        "timestamp": datetime.now().isoformat(),
        "num_projects": len(all_reports),
        "total_crashes": total_crashes,
        "total_old_api_bug": total_old_api,
        "total_new_api_bug": total_new_api,
        "total_judgments_changed": total_changed,
        "aggregate_fp_rate_old": round(1 - total_new_api / total_old_api, 3) if total_old_api else 0,
        "total_unique_after_dedup": total_unique,
        "aggregate_dedup_ratio": round(1 - total_unique / total_crashes, 3) if total_crashes else 0,
        "total_llm_saved": total_llm_saved,
        "aggregate_llm_saved_ratio": round(total_llm_saved / total_crashes, 3) if total_crashes else 0,
        "per_project": per_project,
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
    print("=" * 70)


# ── CSV export ───────────────────────────────────────────────────────────────

def export_per_project_csv(agg: Dict[str, Any], output_dir: str):
    """Export per-project summary as CSV (Table 1 in paper)."""
    csv_path = os.path.join(output_dir, "per_project_summary.csv")
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


def export_per_crash_csv(all_reports: Dict[str, Dict], output_dir: str):
    """Export per-crash detail as CSV (for detailed analysis / ground-truth labeling).

    Columns include THREE judgments for comparison:
      - BaselineIsApiBug: old LLM without triage (ablation or old-format data)
      - TriageIsApiBug:   deterministic triage rules judgment
      - EnhancedIsApiBug: stored is_api_bug from YAML (enhanced LLM or old LLM)
    """
    csv_path = os.path.join(output_dir, "per_crash_detail.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "Project", "CrashID", "Driver", "BugType", "Sanitizer",
            "BaselineIsApiBug", "TriageLabel", "TriageIsApiBug",
            "EnhancedIsApiBug", "HasAblation",
            "TriageRules", "TriageConfidence",
            "JudgmentChanged", "IsDuplicate", "DuplicateOf",
            "Signature", "CrashFile", "CrashFunction",
            "GroundTruth",  # Empty — for human labeling
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
                    "",  # GroundTruth: 留给人工标注
                ])
    print(f"  CSV saved: {csv_path}")
    print(f"  ↑ 打开这个CSV，在 GroundTruth 列填入 True/False 进行人工标注")
    print(f"  ↑ 三列对比: BaselineIsApiBug / TriageIsApiBug / EnhancedIsApiBug")
    return csv_path


def export_triage_distribution_csv(all_reports: Dict[str, Dict], output_dir: str):
    """Export triage label distribution per project (for paper figure)."""
    csv_path = os.path.join(output_dir, "triage_distribution.csv")

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


# ── Ground truth evaluation ──────────────────────────────────────────────────

def evaluate_ground_truth(csv_path: str):
    """Read per_crash_detail.csv with human-labeled GroundTruth, compute precision/recall/F1."""
    if not os.path.isfile(csv_path):
        print(f"[!] {csv_path} not found. Run experiment first, then label GroundTruth column.")
        return

    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt = row.get("GroundTruth", "").strip().lower()
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
        "Old LLM (baseline)": lambda r: r["OldIsApiBug"].strip().lower() in ("true", "1"),
        "Triage rules":       lambda r: r["TriageLabel"] in ("likely_api_bug", "needs_review"),
        "Triage (new_is_api)": lambda r: r["NewIsApiBug"].strip().lower() in ("true", "1"),
    }

    for method_name, pred_fn in methods.items():
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

        print(f"  Method: {method_name}")
        print(f"    TP={tp} FP={fp} TN={tn} FN={fn}")
        print(f"    Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f}  Accuracy: {accuracy:.3f}")
        print()

    print("=" * 70)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Batch experiment runner for crash analysis comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run retroanalyze on all projects
  python -m crash.experiment --db-root external_database --output results/

  # Export CSV tables for paper
  python -m crash.experiment --db-root external_database --output results/ --mode csv

  # Evaluate after human labeling ground truth
  python -m crash.experiment --evaluate results/per_crash_detail.csv
        """,
    )
    parser.add_argument("--db-root", default="external_database",
                        help="Root directory containing project subdirs (default: external_database)")
    parser.add_argument("--output", default="results/",
                        help="Output directory for results (default: results/)")
    parser.add_argument("--mode", choices=["retroanalyze", "summary", "csv"], default="retroanalyze",
                        help="Mode: retroanalyze (full run), summary (re-aggregate), csv (export tables)")
    parser.add_argument("--evaluate", default=None,
                        help="Path to per_crash_detail.csv with GroundTruth labels for evaluation")
    args = parser.parse_args()

    # Ground truth evaluation mode
    if args.evaluate:
        evaluate_ground_truth(args.evaluate)
        return

    os.makedirs(args.output, exist_ok=True)

    if args.mode == "retroanalyze":
        # Full run
        all_reports = run_all_retroanalyze(args.db_root, args.output)
        if not all_reports:
            print("[!] No projects with crash data found.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)

        # Save aggregate
        agg_path = os.path.join(args.output, "aggregate_summary.yaml")
        with open(agg_path, "w") as f:
            yaml.dump(agg, f, default_flow_style=False, allow_unicode=True, width=120)
        print(f"\n  Aggregate saved: {agg_path}")

        # Export CSVs
        print("\n  Exporting CSVs for paper...")
        export_per_project_csv(agg, args.output)
        export_per_crash_csv(all_reports, args.output)
        export_triage_distribution_csv(all_reports, args.output)

    elif args.mode == "summary":
        # Re-aggregate from saved YAML files
        projects = discover_projects(args.db_root)
        all_reports = {}
        for proj in projects:
            retro_path = os.path.join(args.output, f"{proj}_retro.yaml")
            if os.path.isfile(retro_path):
                with open(retro_path) as f:
                    all_reports[proj] = yaml.safe_load(f)
        if not all_reports:
            print("[!] No saved retroanalyze results found. Run --mode retroanalyze first.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)

    elif args.mode == "csv":
        # Re-aggregate and export CSVs
        projects = discover_projects(args.db_root)
        all_reports = {}
        for proj in projects:
            retro_path = os.path.join(args.output, f"{proj}_retro.yaml")
            if os.path.isfile(retro_path):
                with open(retro_path) as f:
                    all_reports[proj] = yaml.safe_load(f)
        if not all_reports:
            print("[!] No saved retroanalyze results found. Run --mode retroanalyze first.")
            sys.exit(1)
        agg = aggregate_summary(all_reports)
        print_aggregate(agg)
        export_per_project_csv(agg, args.output)
        export_per_crash_csv(all_reports, args.output)
        export_triage_distribution_csv(all_reports, args.output)


if __name__ == "__main__":
    main()
