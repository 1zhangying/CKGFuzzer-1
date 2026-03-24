"""Structured crash report generation.

Aggregates all analysis stages into a final report:
  - Sanitizer parse results
  - Triage verdict
  - Precise code location
  - Runtime context (if available)
  - LLM analysis + structured extraction
  - Deduplication info
  - Minimization results
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml
from loguru import logger


def build_crash_report(
    crash_id: str,
    *,
    parsed: Optional[Dict[str, Any]] = None,
    triage: Optional[Dict[str, Any]] = None,
    location: Optional[Dict[str, Any]] = None,
    runtime_ctx: Optional[Dict[str, Any]] = None,
    llm_analysis_text: Optional[str] = None,
    enhanced_result: Optional[Dict[str, Any]] = None,
    dedup_info: Optional[Dict[str, Any]] = None,
    minimize_info: Optional[Dict[str, Any]] = None,
    fuzz_driver_file: Optional[str] = None,
    poc_paths: Optional[Dict[str, str]] = None,
    repro_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a comprehensive crash report aggregating all stages."""

    report: Dict[str, Any] = {
        "crash_id": crash_id,
        "timestamp": datetime.now().isoformat(),
    }

    # --- Verdict ---
    verdict = "UNKNOWN"
    confidence = 0.0
    if triage:
        label = triage.get("label", "")
        confidence = triage.get("confidence", 0.0)
        if label == "noise":
            verdict = "NOISE"
        elif label == "likely_driver_bug":
            verdict = "DRIVER_BUG"
        elif label == "likely_api_bug":
            verdict = "POTENTIAL_VULNERABILITY"
        else:
            verdict = "NEEDS_REVIEW"

        # Override with LLM result if available and triage was uncertain
        if enhanced_result and verdict in ("NEEDS_REVIEW", "POTENTIAL_VULNERABILITY"):
            if enhanced_result.get("is_api_bug") is True:
                verdict = "CONFIRMED_VULNERABILITY"
            elif enhanced_result.get("is_api_bug") is False:
                verdict = "DRIVER_BUG"

    report["verdict"] = verdict
    report["confidence"] = round(confidence, 3)

    # --- Sanitizer summary ---
    if parsed:
        report["sanitizer"] = {
            "type": parsed.get("sanitizer_type"),
            "bug_type": parsed.get("bug_type"),
            "crash_address": parsed.get("crash_address"),
            "access_type": parsed.get("access_type"),
            "scariness": parsed.get("scariness_score"),
            "has_asan_stack": parsed.get("has_asan_stack", False),
            "is_deadly_signal_only": parsed.get("is_deadly_signal_only", False),
            "dedup_token": parsed.get("dedup_token"),
            "stack_depth": len(parsed.get("frames") or []),
        }

    # --- Triage details ---
    if triage:
        report["triage"] = {
            "label": triage.get("label"),
            "confidence": triage.get("confidence"),
            "is_worth_llm_analysis": triage.get("is_worth_llm_analysis"),
            "matched_rules": triage.get("matched_rules"),
            "driver_frame_ratio": triage.get("driver_frame_ratio"),
            "api_frame_ratio": triage.get("api_frame_ratio"),
            "evidences": [
                {
                    "rule": ev.get("rule_name"),
                    "type": ev.get("evidence_type"),
                    "desc": ev.get("description"),
                    "confidence": ev.get("confidence"),
                }
                for ev in (triage.get("evidences") or [])
            ],
        }

    # --- Code location ---
    if location:
        report["location"] = {
            "crash_file": location.get("crash_file"),
            "crash_line": location.get("crash_line"),
            "crash_function": location.get("crash_function"),
            "symbolized": location.get("symbolized", False),
            "project_frames": location.get("project_frames", 0),
            "driver_frames": location.get("driver_frames", 0),
        }
        if location.get("crash_code_snippet"):
            report["location"]["code_snippet"] = location["crash_code_snippet"]

    # --- Runtime context ---
    if runtime_ctx:
        report["runtime"] = {
            "reproduced": runtime_ctx.get("reproduced", False),
            "exit_signal": runtime_ctx.get("exit_signal"),
        }
        if runtime_ctx.get("reproduced") and runtime_ctx.get("crash_frame"):
            cf = runtime_ctx["crash_frame"]
            report["runtime"]["crash_frame"] = {
                "function": cf.get("function"),
                "file": cf.get("file"),
                "line": cf.get("line"),
                "arguments": cf.get("arguments", {}),
                "locals": cf.get("locals", {}),
            }

    # --- LLM analysis ---
    if enhanced_result:
        report["analysis"] = {
            "is_api_bug": enhanced_result.get("is_api_bug"),
            "crash_category": enhanced_result.get("crash_category"),
            "root_cause_type": enhanced_result.get("root_cause_type"),
            "root_cause_location": enhanced_result.get("root_cause_location"),
            "root_cause_trigger": enhanced_result.get("root_cause_trigger"),
            "severity": enhanced_result.get("severity"),
            "data_flow": enhanced_result.get("data_flow"),
            "fix_suggestion": enhanced_result.get("fix_suggestion"),
        }
    if llm_analysis_text:
        report["analysis_text"] = llm_analysis_text

    # --- Signatures / dedup ---
    if triage:
        report["signatures"] = {
            "primary": triage.get("signature"),
            "source": triage.get("signature_source"),
            "stack": triage.get("stack_signature"),
            "fuzzy": triage.get("fuzzy_signature"),
        }

    if dedup_info:
        report["dedup"] = {
            "is_duplicate": dedup_info.get("is_duplicate", False),
            "duplicate_of": dedup_info.get("duplicate_of"),
            "match_level": dedup_info.get("match_level"),
            "cluster_id": dedup_info.get("cluster_id"),
            "cluster_size": dedup_info.get("cluster_size"),
        }

    # --- Minimization ---
    if minimize_info:
        report["minimization"] = {
            "success": minimize_info.get("success", False),
            "method": minimize_info.get("method"),
            "original_size": minimize_info.get("original_size"),
            "minimized_size": minimize_info.get("minimized_size"),
            "reduction_ratio": minimize_info.get("reduction_ratio"),
            "verification_passed": minimize_info.get("verification_passed"),
        }

    # --- Reproduction ---
    if repro_info:
        report["reproduction"] = repro_info

    # --- PoC paths ---
    if poc_paths:
        report["poc_paths"] = poc_paths

    # --- Driver info ---
    if fuzz_driver_file:
        report["fuzz_driver_file"] = fuzz_driver_file

    return report


def save_crash_report(report: Dict[str, Any], output_dir: str) -> str:
    """Save crash report as YAML file."""
    os.makedirs(output_dir, exist_ok=True)
    crash_id = report.get("crash_id", "unknown")
    path = os.path.join(output_dir, f"{crash_id}_report.yaml")

    class literal_str(str):
        pass

    def literal_presenter(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

    yaml.add_representer(literal_str, literal_presenter)

    def _convert_multiline(obj):
        if isinstance(obj, dict):
            return {k: _convert_multiline(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_convert_multiline(v) for v in obj]
        elif isinstance(obj, str) and '\n' in obj:
            return literal_str(obj)
        return obj

    report = _convert_multiline(report)

    with open(path, 'w') as f:
        yaml.dump(report, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    logger.info(f"Crash report saved to {path}")
    return path


def generate_summary_table(reports: List[Dict[str, Any]]) -> str:
    """Generate a Markdown summary table from multiple crash reports."""
    lines = [
        "| Crash ID | Verdict | Bug Type | Location | Severity | Duplicate | Min Ratio |",
        "|----------|---------|----------|----------|----------|-----------|-----------|",
    ]
    for r in reports:
        cid = r.get("crash_id", "?")
        verdict = r.get("verdict", "?")
        san = r.get("sanitizer", {})
        bug = san.get("bug_type", "?")
        loc = r.get("location", {})
        loc_str = f"{loc.get('crash_function', '?')}@{loc.get('crash_file', '?')}:{loc.get('crash_line', '?')}" if loc else "?"
        analysis = r.get("analysis", {})
        severity = analysis.get("severity", "?")
        dedup = r.get("dedup", {})
        dup_str = dedup.get("duplicate_of", "-") or "-"
        mini = r.get("minimization", {})
        ratio_str = f"{mini.get('reduction_ratio', 0):.0%}" if mini.get("success") else "-"

        lines.append(f"| {cid} | {verdict} | {bug} | {loc_str[:30]} | {severity} | {dup_str} | {ratio_str} |")

    return "\n".join(lines)
