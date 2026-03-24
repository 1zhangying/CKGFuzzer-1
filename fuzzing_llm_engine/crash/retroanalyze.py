#!/usr/bin/env python3
"""Retrospective analysis: apply the enhanced crash pipeline to EXISTING crash data.

Works on BOTH old-format and new-format crash_analysis.yaml files:

  OLD format (before enhancement):
    - crash_info, is_api_bug, crash_category, crash_analysis
    - The "old" column = LLM judgment without triage
    - The "new" column = our triage rules applied to the same crash_info

  NEW format (after enhancement):
    - Additionally contains: triage, signature, location, sanitizer_parsed, ...
    - The "old" column = what LLM said (with or without triage context)
    - The "new" column = our triage rules (re-verified independently)

In BOTH cases the comparison logic is the same:
  1. Extract the raw crash_info (sanitizer output)
  2. Apply the deterministic pipeline (parse → triage → locate → dedup)
  3. Compare the deterministic triage label against the stored is_api_bug

This gives you the paper's key comparison:
  "Rule-based triage judgment" vs "LLM judgment" on the SAME crash data.

Usage:
    cd fuzzing_llm_engine
    python -m crash.retroanalyze --crash-dir external_database/c-ares/crash
    python -m crash.retroanalyze --crash-dir external_database/c-ares/crash --output results/c-ares_retro.yaml
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import yaml
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.sanitizer_parser import parse_sanitizer_output, format_crash_summary
from crash.triage import triage_crash, compute_signatures
from crash.locator import locate_crash_site, format_call_chain_for_llm
from crash.dedup import DeduplicationEngine


def _clean_crash_info(raw: str) -> str:
    """Remove YAML literal-block markers and un-escape the crash_info text."""
    if not raw:
        return ""
    text = str(raw)
    # Strip leading '|' or '|-' YAML markers
    text = re.sub(r"^\|\-?\s*\n?", "", text)
    # Unescape \\r\\n → \r\n  (they were double-escaped during YAML dump)
    text = text.replace("\\r\\n", "\r\n").replace("\\r", "\r").replace("\\n", "\n")
    text = text.replace("\\e", "\x1b")  # ANSI escape
    return text.strip()


def _extract_driver_basename(driver_dir_name: str) -> str:
    """Guess the fuzz driver .cc filename from the directory name."""
    return driver_dir_name + ".cc"


def retroanalyze_one(
    crash_info_raw: str,
    driver_basename: Optional[str],
    old_is_api_bug: bool,
    old_category: str,
    crash_id: str,
    dedup_engine: Optional[DeduplicationEngine] = None,
    baseline_is_api_bug: Optional[bool] = None,
) -> Dict[str, Any]:
    """Run deterministic pipeline stages on a single crash entry.

    old_is_api_bug:      stored LLM judgment (old or enhanced)
    baseline_is_api_bug: if available, the old LLM (no triage) judgment (from ablation)
    """

    crash_text = _clean_crash_info(crash_info_raw)
    parsed = parse_sanitizer_output(crash_text)
    triage = triage_crash(parsed, fuzz_driver_basename=driver_basename)
    location = locate_crash_site(parsed, driver_basename=driver_basename)

    # Dedup
    dedup_info = None
    if dedup_engine is not None:
        dedup_info = dedup_engine.add_crash(crash_id, triage, parsed)

    # Compare old vs new judgment
    new_is_api_bug = triage.get("label") in ("likely_api_bug", "needs_review")
    judgment_changed = (old_is_api_bug != new_is_api_bug)

    # Determine the "baseline" value for comparison:
    # If ablation baseline exists → use it (most accurate old-method simulation)
    # Otherwise → use old_is_api_bug from YAML (for old-format data, this IS the baseline)
    effective_baseline = baseline_is_api_bug if baseline_is_api_bug is not None else old_is_api_bug

    return {
        "crash_id": crash_id,
        # Old / baseline analysis
        "old_is_api_bug": old_is_api_bug,
        "baseline_is_api_bug": effective_baseline,
        "has_ablation_baseline": baseline_is_api_bug is not None,
        "old_category": old_category,
        # New deterministic analysis
        "parsed_bug_type": parsed.get("bug_type"),
        "parsed_sanitizer": parsed.get("sanitizer_type"),
        "parsed_frames": len(parsed.get("frames") or []),
        "parsed_first_project_frame": parsed.get("first_in_project_frame"),
        "scariness_score": parsed.get("scariness_score"),
        "is_deadly_signal_only": parsed.get("is_deadly_signal_only", False),
        # Triage
        "triage_label": triage.get("label"),
        "triage_confidence": triage.get("confidence"),
        "triage_rules": triage.get("matched_rules"),
        "triage_worth_llm": triage.get("is_worth_llm_analysis"),
        "driver_frame_ratio": triage.get("driver_frame_ratio"),
        "api_frame_ratio": triage.get("api_frame_ratio"),
        # Signature
        "signature": triage.get("signature"),
        "stack_signature": triage.get("stack_signature"),
        "fuzzy_signature": triage.get("fuzzy_signature"),
        # Location
        "crash_file": location.get("crash_file"),
        "crash_line": location.get("crash_line"),
        "crash_function": location.get("crash_function"),
        # Dedup
        "is_duplicate": dedup_info.get("is_duplicate") if dedup_info else None,
        "duplicate_of": dedup_info.get("duplicate_of") if dedup_info else None,
        "cluster_id": dedup_info.get("cluster_id") if dedup_info else None,
        # Comparison
        "judgment_changed": judgment_changed,
        "new_is_api_bug": new_is_api_bug,
    }


def retroanalyze_dir(crash_dir: str) -> Dict[str, Any]:
    """Scan a crash directory and retroanalyze all YAML files."""

    dedup = DeduplicationEngine()
    results = []
    driver_dirs = sorted(os.listdir(crash_dir))

    for dname in driver_dirs:
        yaml_path = os.path.join(crash_dir, dname, "crash_analysis.yaml")
        if not os.path.isfile(yaml_path):
            continue

        driver_basename = _extract_driver_basename(dname)

        with open(yaml_path) as f:
            raw = f.read()

        # Parse the YAML — handle the non-standard '|' markers
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            # Fallback: manual parse
            data = None

        if data is None:
            # Try raw parsing
            entries = raw.split("\n- crash_")
            for i, entry_text in enumerate(entries):
                if i == 0 and not entry_text.strip().startswith("crash_"):
                    continue
                crash_id = f"{dname}_crash_{i}"
                # Extract crash_info via regex
                m = re.search(r'crash_info:\s*"([^"]*)"', entry_text, re.DOTALL)
                crash_info_raw = m.group(1) if m else ""
                m2 = re.search(r'is_api_bug:\s*(true|false)', entry_text, re.IGNORECASE)
                old_api = m2.group(1).lower() == "true" if m2 else False
                m3 = re.search(r'crash_category:\s*(.+)', entry_text)
                old_cat = m3.group(1).strip() if m3 else "Unknown"

                r = retroanalyze_one(crash_info_raw, driver_basename, old_api, old_cat, crash_id, dedup)
                r["driver"] = dname
                results.append(r)
            continue

        # Normal YAML parse
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                for cid, entry in item.items():
                    if not isinstance(entry, dict):
                        continue
                    crash_info_raw = entry.get("crash_info", "")
                    old_api = entry.get("is_api_bug", False)
                    old_cat = entry.get("crash_category", "Unknown")
                    full_id = f"{dname}_{cid}"

                    # Check for ablation baseline (new-format YAML from enhanced pipeline)
                    bl = entry.get("baseline_llm", {})
                    bl_api = bl.get("is_api_bug") if isinstance(bl, dict) else None

                    r = retroanalyze_one(crash_info_raw, driver_basename, old_api, old_cat,
                                         full_id, dedup, baseline_is_api_bug=bl_api)
                    r["driver"] = dname
                    results.append(r)

    # Summary statistics
    total = len(results)
    judgments_changed = sum(1 for r in results if r["judgment_changed"])
    old_api_bugs = sum(1 for r in results if r["old_is_api_bug"])
    new_api_bugs = sum(1 for r in results if r["new_is_api_bug"])
    triage_labels = {}
    for r in results:
        lbl = r["triage_label"] or "unknown"
        triage_labels[lbl] = triage_labels.get(lbl, 0) + 1

    dedup_stats = dedup.get_dedup_stats()
    unique = dedup_stats.get("unique_crashes", total)

    summary = {
        "total_crashes": total,
        "old_api_bug_count": old_api_bugs,
        "new_api_bug_count": new_api_bugs,
        "judgments_changed": judgments_changed,
        "false_positive_rate_old": round(1 - new_api_bugs / old_api_bugs, 3) if old_api_bugs else 0,
        "triage_label_distribution": triage_labels,
        "unique_crashes_after_dedup": unique,
        "total_crashes_before_dedup": total,
        "dedup_reduction_ratio": round(1 - unique / total, 3) if total else 0,
        "llm_calls_saved": sum(1 for r in results if not r["triage_worth_llm"]),
        "llm_calls_saved_ratio": round(sum(1 for r in results if not r["triage_worth_llm"]) / total, 3) if total else 0,
    }

    return {
        "project": os.path.basename(os.path.dirname(crash_dir)) if "crash" in crash_dir else "unknown",
        "analysis_timestamp": datetime.now().isoformat(),
        "summary": summary,
        "crashes": results,
    }


def print_summary(report: Dict[str, Any]):
    """Pretty-print the retroanalysis summary."""
    s = report["summary"]
    print("=" * 60)
    print(f"  Retrospective Analysis: {report['project']}")
    print("=" * 60)
    print(f"  Total crashes analyzed:        {s['total_crashes']}")
    print(f"  Old LLM 'is_api_bug=True':     {s['old_api_bug_count']}")
    print(f"  New triage 'is_api_bug':        {s['new_api_bug_count']}")
    print(f"  Judgments changed:              {s['judgments_changed']}")
    print(f"  Estimated old FP rate:          {s['false_positive_rate_old']:.1%}")
    print()
    print(f"  Triage label distribution:")
    for lbl, cnt in sorted(s["triage_label_distribution"].items()):
        print(f"    {lbl:25s} {cnt}")
    print()
    print(f"  Unique crashes (after dedup):   {s['unique_crashes_after_dedup']}")
    print(f"  Dedup reduction ratio:          {s['dedup_reduction_ratio']:.1%}")
    print()
    print(f"  LLM calls that would be saved:  {s['llm_calls_saved']} / {s['total_crashes']}"
          f" ({s['llm_calls_saved_ratio']:.1%})")
    print()

    # Per-crash detail
    print("-" * 60)
    print(f"  {'ID':40s} {'Old→New':15s} {'Triage':20s} {'Rules'}")
    print("-" * 60)
    for c in report["crashes"]:
        old = "API_BUG" if c["old_is_api_bug"] else "driver"
        new = "API_BUG" if c["new_is_api_bug"] else "driver"
        changed = " ← CHANGED" if c["judgment_changed"] else ""
        label = c["triage_label"] or "?"
        rules = ",".join(c["triage_rules"] or [])
        cid = c["crash_id"][-38:]
        print(f"  {cid:40s} {old}→{new}{changed:10s} {label:20s} {rules}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Retrospective crash analysis")
    parser.add_argument("--crash-dir", required=True, help="Path to crash directory (e.g. external_database/c-ares/crash)")
    parser.add_argument("--output", default=None, help="Save full results to YAML file")
    args = parser.parse_args()

    if not os.path.isdir(args.crash_dir):
        print(f"Error: {args.crash_dir} is not a directory")
        sys.exit(1)

    report = retroanalyze_dir(args.crash_dir)
    print_summary(report)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            yaml.dump(report, f, default_flow_style=False, allow_unicode=True, width=120)
        print(f"\nFull results saved to: {args.output}")


if __name__ == "__main__":
    main()
