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
    python -m crash.retroanalyze --crash-dir external_database/<project>/crash
    python -m crash.retroanalyze --crash-dir external_database/<project>/crash --output results/<project>_retro.yaml
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

ABLATION_VARIANTS = ("V0", "V1", "V2", "V3", "V4")


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


def _triage_filters_llm(triage_label: Optional[str]) -> bool:
    return triage_label in ("noise", "likely_driver_bug")


def _normalize_ablation_result(vd: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(vd, dict):
        return None
    if not {"sent_to_llm", "is_api_bug", "skip_reason"}.issubset(vd):
        return None
    return {
        "sent_to_llm": bool(vd.get("sent_to_llm", False)),
        "is_api_bug": bool(vd.get("is_api_bug", False)),
        "skip_reason": vd.get("skip_reason") or "",
    }


def _load_saved_ablation_variants(entry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Load real variant results saved by the ablation runner."""
    raw = entry.get("ablation_results")
    if not isinstance(raw, dict):
        return {}

    variants: Dict[str, Dict[str, Any]] = {}
    for vname in ABLATION_VARIANTS:
        normalized = _normalize_ablation_result(raw.get(vname))
        if normalized is not None:
            variants[vname] = normalized
    return variants


def _default_v4_result(entry: Dict[str, Any], triage_label: Optional[str]) -> Optional[Dict[str, Any]]:
    if _triage_filters_llm(triage_label):
        return {
            "sent_to_llm": False,
            "is_api_bug": False,
            "skip_reason": f"triage:{triage_label}",
        }

    if entry.get("duplicate_of"):
        return {
            "sent_to_llm": False,
            "is_api_bug": False,
            "skip_reason": "duplicate",
        }

    timings = entry.get("timings") or {}
    skip_reason = timings.get("llm_skip_reason")
    llm_skipped = bool(timings.get("llm_skipped")) or bool(skip_reason and skip_reason != "none")
    if skip_reason == "duplicate":
        skip_reason = None
        llm_skipped = False
    if entry.get("is_api_bug") is None:
        return None
    return {
        "sent_to_llm": not llm_skipped,
        "is_api_bug": bool(entry.get("is_api_bug")),
        "skip_reason": skip_reason or ("skipped" if llm_skipped else "none"),
    }


def _overlay_saved_pipeline_fields(result: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """Attach cached LLM ablation judgments without overriding recomputed stages."""
    parsed = entry.get("sanitizer_parsed")
    if isinstance(parsed, dict):
        result["parsed_bug_type"] = parsed.get("bug_type") or result.get("parsed_bug_type") or "Unknown"
        result["parsed_sanitizer"] = parsed.get("sanitizer_type")
        result["parsed_frames"] = len(parsed.get("frames") or [])
        result["parsed_first_project_frame"] = parsed.get("first_in_project_frame")
        result["scariness_score"] = parsed.get("scariness_score")
        result["is_deadly_signal_only"] = parsed.get("is_deadly_signal_only", False)

    variants = _load_saved_ablation_variants(entry)
    raw_ablation = entry.get("ablation_results")
    raw_v3 = raw_ablation.get("V3") if isinstance(raw_ablation, dict) else None
    raw_v3_is_paper_v3 = (
        isinstance(raw_v3, dict) and raw_v3.get("prompt_variant") == "direct_v1"
    )
    if "V4" not in variants:
        # Compatibility with old data where the full CrashSage result was
        # incorrectly stored under V3.
        variants["V4"] = None if raw_v3_is_paper_v3 else variants.get("V3")
        if variants["V4"] is None:
            v4 = _default_v4_result(entry, result.get("triage_label"))
            if v4 is not None:
                variants["V4"] = v4
        else:
            variants["V4"] = dict(variants["V4"])
    variants.pop("V3", None)
    if raw_v3_is_paper_v3:
        normalized = _normalize_ablation_result(raw_v3)
        if normalized is not None:
            variants["V3"] = normalized
    if _triage_filters_llm(result.get("triage_label")):
        skip_reason = f"triage:{result.get('triage_label')}"
        for vname in ("V1", "V2", "V3", "V4"):
            variants[vname] = {
                "sent_to_llm": False,
                "is_api_bug": False,
                "skip_reason": skip_reason,
            }
    else:
        duplicate = bool(result.get("is_duplicate"))
        if "V1" in variants:
            v1 = variants["V1"]
            variants["V2"] = {
                "sent_to_llm": not duplicate,
                "is_api_bug": bool(v1.get("is_api_bug", False)),
                "skip_reason": "duplicate" if duplicate else "none",
            }
        if "V3" in variants:
            variants["V3"] = {
                **variants["V3"],
                "sent_to_llm": not duplicate,
                "skip_reason": "duplicate" if duplicate else "none",
            }
        if "V4" in variants:
            variants["V4"] = {
                **variants["V4"],
                "sent_to_llm": not duplicate,
                "skip_reason": "duplicate" if duplicate else "none",
            }

    missing = [v for v in ABLATION_VARIANTS if v not in variants]
    result["ablation_variants"] = variants
    result["has_real_ablation"] = bool(variants)
    result["has_complete_real_ablation"] = not missing
    result["missing_real_ablation_variants"] = missing


def retroanalyze_one(
    crash_info_raw: str,
    driver_basename: Optional[str],
    old_is_api_bug: bool,
    old_category: str,
    crash_id: str,
    dedup_engine: Optional[DeduplicationEngine] = None,
) -> Dict[str, Any]:
    """Run deterministic pipeline stages on a single crash entry.

    old_is_api_bug: stored legacy judgment, kept only for old/new summary output.
    """

    crash_text = _clean_crash_info(crash_info_raw)
    parsed = parse_sanitizer_output(crash_text)
    triage = triage_crash(parsed, fuzz_driver_basename=driver_basename)
    location = locate_crash_site(parsed, driver_basename=driver_basename)

    # Dedup
    dedup_info = {
        "is_duplicate": False,
        "duplicate_of": None,
        "cluster_id": None,
    }
    if dedup_engine is not None and not _triage_filters_llm(triage.get("label")):
        dedup_info = dedup_engine.add_crash(
            crash_id,
            triage,
            parsed,
        )

    # Compare old vs new judgment
    new_is_api_bug = triage.get("label") in ("likely_api_bug", "needs_review")
    judgment_changed = (old_is_api_bug != new_is_api_bug)

    return {
        "crash_id": crash_id,
        # Old / baseline analysis
        "old_is_api_bug": old_is_api_bug,
        "baseline_is_api_bug": None,
        "enhanced_is_api_bug": old_is_api_bug,
        "has_ablation_baseline": False,
        "old_category": old_category,
        # New deterministic analysis
        "parsed_bug_type": parsed.get("bug_type") or old_category,
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
        "ablation_variants": {},
        "has_real_ablation": False,
        "has_complete_real_ablation": False,
        "missing_real_ablation_variants": list(ABLATION_VARIANTS),
    }


def _inherit_duplicate_predictions(
    result: Dict[str, Any],
    result_by_id: Dict[str, Dict[str, Any]],
) -> None:
    # Variant judgments stored in crash_analysis.yaml are already materialized
    # per crash.  Dedup affects whether a variant calls the LLM, but this
    # exporter must not rewrite saved boolean judgments during retroanalysis.
    return


def retroanalyze_dir(crash_dir: str) -> Dict[str, Any]:
    """Scan a crash directory and retroanalyze all YAML files."""

    dedup = DeduplicationEngine()
    results = []
    result_by_id: Dict[str, Dict[str, Any]] = {}
    driver_dirs = sorted(os.listdir(crash_dir))
    project_name = os.path.basename(os.path.dirname(crash_dir)) if "crash" in crash_dir else None

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

                r = retroanalyze_one(
                    crash_info_raw,
                    driver_basename,
                    old_api,
                    old_cat,
                    crash_id,
                    dedup,
                )
                r["driver"] = dname
                _inherit_duplicate_predictions(r, result_by_id)
                results.append(r)
                result_by_id[crash_id] = r
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

                    r = retroanalyze_one(
                        crash_info_raw,
                        driver_basename,
                        old_api,
                        old_cat,
                        full_id,
                        dedup,
                    )
                    r["driver"] = dname

                    _overlay_saved_pipeline_fields(r, entry)
                    _inherit_duplicate_predictions(r, result_by_id)
                    results.append(r)
                    result_by_id[full_id] = r

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

    # Per-variant ablation metrics
    ablation_summary = {}
    for vname in ABLATION_VARIANTS:
        sent = sum(1 for r in results if r.get("ablation_variants", {}).get(vname, {}).get("sent_to_llm", False))
        api_bugs = sum(1 for r in results if r.get("ablation_variants", {}).get(vname, {}).get("is_api_bug", False))
        ablation_summary[vname] = {
            "llm_invocations": sent,
            "llm_saved": total - sent,
            "llm_saved_ratio": round((total - sent) / total, 3) if total else 0,
            "classified_as_api_bug": api_bugs,
        }

    summary = {
        "total_crashes": total,
        "old_api_bug_count": old_api_bugs,
        "new_api_bug_count": new_api_bugs,
        "judgments_changed": judgments_changed,
        "false_positive_rate_old": round(old_api_bugs / total, 3) if total else 0,
        "triage_label_distribution": triage_labels,
        "unique_crashes_after_dedup": unique,
        "total_crashes_before_dedup": total,
        "dedup_reduction_ratio": round(1 - unique / total, 3) if total else 0,
        "llm_calls_saved": sum(1 for r in results if not r["triage_worth_llm"]),
        "llm_calls_saved_ratio": round(sum(1 for r in results if not r["triage_worth_llm"]) / total, 3) if total else 0,
        "ablation_variants": ablation_summary,
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

    # Ablation variant comparison
    ablation = s.get("ablation_variants")
    if ablation:
        print(f"  Ablation variant comparison:")
        print(f"    {'Variant':8s} {'LLM Calls':>10s} {'Saved':>8s} {'SavedRatio':>11s} {'ApiBugs':>8s}")
        print(f"    {'-'*50}")
        for vname in ABLATION_VARIANTS:
            v = ablation.get(vname, {})
            print(f"    {vname:8s} {v.get('llm_invocations', 0):10d} "
                  f"{v.get('llm_saved', 0):8d} "
                  f"{v.get('llm_saved_ratio', 0):10.1%} "
                  f"{v.get('classified_as_api_bug', 0):8d}")
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
    parser.add_argument("--crash-dir", required=True, help="Path to crash directory (e.g. external_database/<project>/crash)")
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
