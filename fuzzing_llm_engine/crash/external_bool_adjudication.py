#!/usr/bin/env python3
"""External boolean adjudication for CrashSage crash reports.

This script reads the frozen per-crash manifest, builds one evidence package
per crash, and asks the LLM configured in a dedicated YAML file whether the
evidence supports target-component attribution.

It intentionally does not read project config.yaml files and does not write
back to any crash_analysis.yaml file.

Usage:
    cd fuzzing_llm_engine
    python -m crash.external_bool_adjudication \
      --manifest results/per_crash_detail.csv \
      --db-root external_database \
      --llm-config configs/external_bool_adjudication.yaml \
      --output results/external_bool_adjudication/current_run
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


LEAKY_KEYS = {
    "is_api_bug",
    "verdict",
    "crash_analysis",
    "baseline_llm",
    "enhanced_analysis",
    "enhanced_result",
    "ablation_results",
    "ablation_variants",
    "old_is_api_bug",
    "baseline_is_api_bug",
    "enhanced_is_api_bug",
    "new_is_api_bug",
    "judgment_changed",
    "known_cve_ground_truth",
}

LEAKY_MANIFEST_KEYS = {
    "BaselineIsApiBug",
    "TriageIsApiBug",
    "EnhancedIsApiBug",
    "TriageLabel",
    "JudgmentChanged",
    "HasAblation",
    "LLMLabel",
}

CSV_FIELDS = [
    "Project",
    "CrashID",
    "Driver",
    "LLMName",
    "LLMModel",
    "LLMBaseURL",
    "Result",
    "Reason",
    "Status",
    "PromptSHA256",
    "LatencyMs",
    "RetryCount",
    "PromptChars",
    "PromptTokens",
    "CompletionTokens",
    "TotalTokens",
    "EvidenceVariant",
    "PromptVariant",
]


class AdjudicationError(Exception):
    """Raised for recoverable per-crash adjudication failures."""


def _is_leaky_key(key: Any) -> bool:
    """Return True for final labels or prior-LLM outputs that would leak answers."""
    normalized = str(key).strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", normalized)
    if normalized in LEAKY_KEYS:
        return True
    if "is_api_bug" in normalized or "isapibug" in compact:
        return True
    return normalized in {
        "verdict",
        "crash_analysis",
        "baseline_llm",
        "enhanced_analysis",
        "enhanced_result",
        "ablation_results",
        "ablation_variants",
        "has_ablation",
        "has_ablation_baseline",
        "has_real_ablation",
        "judgment_changed",
        "known_cve_ground_truth",
        "llmlabel",
        "llm_label",
        "triagelabel",
        "triage_label",
        "triage_worth_llm",
        "is_worth_llm_analysis",
    }


def load_llm_config(path: str, *, validate: bool = True) -> Dict[str, Any]:
    """Load the dedicated LLM configuration.

    This is the only LLM configuration source used by the script.
    """
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    if not isinstance(config, dict) or not isinstance(config.get("llm"), dict):
        raise ValueError(f"Invalid LLM config: {path}. Missing top-level 'llm'.")

    llm = config["llm"]
    llm.setdefault("name", "external-judge")
    llm.setdefault("temperature", 0.0)
    llm.setdefault("timeout", 300)
    llm.setdefault("max_retries", 3)
    llm.setdefault("context_window", 1000000)

    run = config.setdefault("run", {})
    run.setdefault("max_prompt_chars", 120000)
    run.setdefault("save_prompts", True)
    run.setdefault("resume", True)
    run.setdefault("force_json_response_format", True)

    if validate:
        missing = [k for k in ("api_key", "model", "base_url") if not llm.get(k)]
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"Invalid LLM config: missing llm.{joined}")

    return config


def load_manifest_rows(manifest_path: str) -> List[Dict[str, str]]:
    with open(manifest_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    required = {"Project", "CrashID", "Driver"}
    missing = required.difference(rows[0].keys() if rows else [])
    if missing:
        raise ValueError(f"Manifest is missing required columns: {sorted(missing)}")
    return rows


def _local_crash_id(driver: str, crash_id: str) -> str:
    prefix = f"{driver}_"
    if crash_id.startswith(prefix):
        return crash_id[len(prefix):]
    match = re.search(r"(crash_\d+)$", crash_id)
    if match:
        return match.group(1)
    raise AdjudicationError(f"Cannot derive local crash id from {crash_id}")


def load_crash_entry(
    db_root: str,
    project: str,
    driver: str,
    crash_id: str,
) -> Tuple[Dict[str, Any], str, str]:
    """Locate the entry for one crash in crash_analysis.yaml."""
    local_id = _local_crash_id(driver, crash_id)
    driver_dir = os.path.join(db_root, project, "crash", driver)
    yaml_path = os.path.join(driver_dir, "crash_analysis.yaml")
    if not os.path.isfile(yaml_path):
        found = _find_crash_entry_in_project(db_root, project, crash_id, local_id)
        if found is not None:
            return found
        raise AdjudicationError(f"Missing crash_analysis.yaml: {yaml_path}")

    return _load_entry_from_yaml(yaml_path, driver_dir, crash_id, local_id)


def _load_entry_from_yaml(
    yaml_path: str,
    driver_dir: str,
    crash_id: str,
    local_id: str,
) -> Tuple[Dict[str, Any], str, str]:
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, list):
        raise AdjudicationError(f"Unexpected YAML format in {yaml_path}")

    for item in data:
        if isinstance(item, dict) and local_id in item:
            entry = item[local_id]
            if not isinstance(entry, dict):
                raise AdjudicationError(f"Invalid entry for {crash_id} in {yaml_path}")
            return entry, driver_dir, yaml_path

    raise AdjudicationError(f"Cannot find {local_id} in {yaml_path}")


def _find_crash_entry_in_project(
    db_root: str,
    project: str,
    crash_id: str,
    local_id: str,
) -> Optional[Tuple[Dict[str, Any], str, str]]:
    """Fallback search for manifests whose driver names drifted from crash dirs."""
    crash_root = os.path.join(db_root, project, "crash")
    if not os.path.isdir(crash_root):
        return None

    candidates: List[Tuple[Dict[str, Any], str, str]] = []
    for name in sorted(os.listdir(crash_root)):
        driver_dir = os.path.join(crash_root, name)
        yaml_path = os.path.join(driver_dir, "crash_analysis.yaml")
        if not os.path.isfile(yaml_path):
            continue
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            for cid, entry in item.items():
                if not isinstance(entry, dict):
                    continue
                full = f"{name}_{cid}"
                if full == crash_id:
                    return entry, driver_dir, yaml_path
                if cid == local_id:
                    candidates.append((entry, driver_dir, yaml_path))

    if len(candidates) == 1:
        return candidates[0]
    return None


def sanitize_entry_for_external_judge(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively remove final labels and prior LLM outputs."""
    def clean(obj: Any) -> Any:
        if isinstance(obj, dict):
            cleaned = {}
            for key, value in obj.items():
                if _is_leaky_key(key):
                    continue
                cleaned[key] = clean(value)
            return cleaned
        if isinstance(obj, list):
            return [clean(v) for v in obj]
        return obj

    sanitized = clean(deepcopy(entry))

    triage = sanitized.get("triage")
    if isinstance(triage, dict):
        triage.pop("label", None)
        triage.pop("is_worth_llm_analysis", None)

    return sanitized


def _manifest_metadata(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        k: v
        for k, v in row.items()
        if k not in LEAKY_MANIFEST_KEYS and v not in ("", None)
    }


def _read_text_file(path: str, limit: Optional[int] = None) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    if limit is not None and len(text) > limit:
        return text[:limit] + f"\n[TRUNCATED: {len(text) - limit} chars omitted]"
    return text


def _find_driver_source(entry: Dict[str, Any], driver_dir: str, local_id: str) -> Tuple[Optional[str], Optional[str]]:
    candidates: List[str] = []
    fuzz_driver_file = entry.get("fuzz_driver_file")
    if isinstance(fuzz_driver_file, str) and fuzz_driver_file:
        candidates.append(os.path.join(driver_dir, fuzz_driver_file))

    base = os.path.basename(driver_dir)
    candidates.append(os.path.join(driver_dir, f"{base}_{local_id}.cc"))
    candidates.append(os.path.join(driver_dir, f"{base}_{local_id}.cpp"))

    for name in os.listdir(driver_dir) if os.path.isdir(driver_dir) else []:
        if name.endswith((".cc", ".cpp", ".cxx", ".c")):
            candidates.append(os.path.join(driver_dir, name))

    seen = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path):
            return path, _read_text_file(path)
    return None, None


def _find_project_driver_source(db_root: str, project: str, driver: str) -> Tuple[Optional[str], Optional[str]]:
    """Find a generated fuzz driver when the per-crash directory is absent."""
    engine_root = os.path.dirname(os.path.abspath(db_root))
    candidates = [
        os.path.join(db_root, project, "fuzz_driver", f"{driver}.cc"),
        os.path.join(db_root, project, "fuzz_driver", f"{driver}.cpp"),
        os.path.join("build", "out", project, "src", project, "test", f"{driver}.cc"),
        os.path.join("build", "out", project, "src", project, "test", f"{driver}.cpp"),
        os.path.join(engine_root, "build", "out", project, "src", project, "test", f"{driver}.cc"),
        os.path.join(engine_root, "build", "out", project, "src", project, "test", f"{driver}.cpp"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path, _read_text_file(path)

    build_root = os.path.join(engine_root, "build", "out", project)
    if os.path.isdir(build_root):
        for root, _, files in os.walk(build_root):
            for name in files:
                if name == f"{driver}.cc" or name == f"{driver}.cpp":
                    path = os.path.join(root, name)
                    return path, _read_text_file(path)

    return None, None


def _load_retro_crash(manifest_path: str, project: str, crash_id: str) -> Optional[Dict[str, Any]]:
    """Load optional retro metadata for rows missing a crash_analysis.yaml."""
    results_dir = os.path.dirname(manifest_path)
    retro_path = os.path.join(results_dir, f"{project}_retro.yaml")
    if not os.path.isfile(retro_path):
        return None
    with open(retro_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    crashes = data.get("crashes") if isinstance(data, dict) else None
    if not isinstance(crashes, list):
        return None
    for item in crashes:
        if isinstance(item, dict) and item.get("crash_id") == crash_id:
            return sanitize_entry_for_external_judge(item)
    return None


def _clean_long_crash_text(text: str, soft_limit: int) -> str:
    if not isinstance(text, str):
        return text
    text = re.sub(r"(Base64:\s*)[A-Za-z0-9+/=]{120,}", r"\1[TRUNCATED_BASE64]", text)
    if len(text) <= soft_limit:
        return text
    head = int(soft_limit * 0.7)
    tail = soft_limit - head
    omitted = len(text) - soft_limit
    return text[:head] + f"\n[TRUNCATED: {omitted} chars omitted]\n" + text[-tail:]


def _compact_runtime_context(ctx: Any) -> Any:
    if not isinstance(ctx, dict):
        return ctx
    compact = deepcopy(ctx)
    if isinstance(compact.get("backtrace_text"), str):
        compact["backtrace_text"] = _clean_long_crash_text(compact["backtrace_text"], 20000)
    return compact


def build_evidence_package(
    row: Dict[str, str],
    entry: Dict[str, Any],
    driver_dir: str,
    *,
    include_static_context: bool = True,
    include_runtime_context: bool = True,
) -> Tuple[Dict[str, Any], List[str]]:
    """Build a complete evidence package without leaking final labels."""
    sanitized = sanitize_entry_for_external_judge(entry)
    driver = row["Driver"]
    local_id = _local_crash_id(driver, row["CrashID"])
    driver_source_path, driver_source = _find_driver_source(entry, driver_dir, local_id)

    crash_info = sanitized.get("crash_info", "")
    if isinstance(crash_info, str):
        crash_info = _clean_long_crash_text(crash_info, 45000)

    triage = sanitized.get("triage") if isinstance(sanitized.get("triage"), dict) else {}
    triage_evidence = {
        "confidence": triage.get("confidence"),
        "matched_rules": triage.get("matched_rules"),
        "evidences": triage.get("evidences"),
        "driver_frame_ratio": triage.get("driver_frame_ratio"),
        "api_frame_ratio": triage.get("api_frame_ratio"),
        "signature": triage.get("signature"),
        "signature_source": triage.get("signature_source"),
        "fuzzy_signature": triage.get("fuzzy_signature"),
        "stack_signature": triage.get("stack_signature"),
    }

    evidence = {
        "task_boundary": {
            "question": "Does the available evidence support attributing this crash to the target component?",
            "true_meaning": "Evidence supports target-component attribution.",
            "false_meaning": "Evidence does not support target-component attribution, points to generated-driver behavior/noise, or is insufficient.",
            "not_claimed": "This is not a known-vulnerability, zero-day, CVE, exploitability, or security-impact confirmation.",
        },
        "manifest_metadata": _manifest_metadata(row),
        "raw_sanitizer_report": crash_info,
        "sanitizer_parsed": sanitized.get("sanitizer_parsed"),
        "static_location": sanitized.get("location") if include_static_context else None,
        "triage_evidence_without_label": triage_evidence,
        "dedup_evidence": {
            "signature": sanitized.get("signature"),
            "group_id": sanitized.get("group_id"),
            "dedup": sanitized.get("dedup"),
        },
        "reproduction_evidence": {
            "poc_locate": sanitized.get("poc_locate"),
            "poc_copy": sanitized.get("poc_copy"),
            "poc_paths": sanitized.get("poc_paths"),
            "repro": sanitized.get("repro"),
        },
        "runtime_context": (
            _compact_runtime_context(sanitized.get("gdb_runtime_context"))
            if include_runtime_context else None
        ),
        "driver_source": {
            "path": driver_source_path,
            "missing": driver_source is None,
            "content": driver_source,
        },
    }

    fields = [
        "crash_info",
        "sanitizer_parsed",
        "location",
        "triage_evidence",
        "dedup",
        "repro",
        "gdb_runtime_context",
        "driver_source",
    ]
    if not include_static_context:
        fields.remove("location")
    if not include_runtime_context:
        fields.remove("gdb_runtime_context")
    return evidence, fields


def build_fallback_evidence_package(
    row: Dict[str, str],
    retro_entry: Optional[Dict[str, Any]],
    driver_source_path: Optional[str],
    driver_source: Optional[str],
) -> Tuple[Dict[str, Any], List[str]]:
    """Build conservative evidence when the full crash_analysis.yaml is missing."""
    retro = sanitize_entry_for_external_judge(retro_entry or {})
    manifest = _manifest_metadata(row)

    triage_evidence = {
        "confidence": retro.get("triage_confidence") or manifest.get("TriageConfidence"),
        "matched_rules": retro.get("triage_rules") or manifest.get("TriageRules"),
        "driver_frame_ratio": retro.get("driver_frame_ratio"),
        "api_frame_ratio": retro.get("api_frame_ratio"),
        "signature": retro.get("signature") or manifest.get("Signature"),
        "fuzzy_signature": retro.get("fuzzy_signature"),
        "stack_signature": retro.get("stack_signature"),
    }

    sanitizer_parsed = {
        "bug_type": retro.get("parsed_bug_type") or manifest.get("BugType"),
        "sanitizer": retro.get("parsed_sanitizer") or manifest.get("Sanitizer"),
        "frames_count": retro.get("parsed_frames"),
        "first_project_frame": retro.get("parsed_first_project_frame"),
        "scariness_score": retro.get("scariness_score"),
    }

    static_location = {
        "crash_file": retro.get("crash_file") or manifest.get("CrashFile"),
        "crash_function": retro.get("crash_function") or manifest.get("CrashFunction"),
        "crash_line": retro.get("crash_line"),
        "first_project_frame": retro.get("parsed_first_project_frame"),
    }

    evidence = {
        "task_boundary": {
            "question": "Does the available evidence support attributing this crash to the target component?",
            "true_meaning": "Evidence supports target-component attribution.",
            "false_meaning": "Evidence does not support target-component attribution, points to generated-driver behavior/noise, or is insufficient.",
            "not_claimed": "This is not a known-vulnerability, zero-day, CVE, exploitability, or security-impact confirmation.",
        },
        "fallback_notice": {
            "source": "manifest_retro_fallback",
            "reason": "The full per-crash YAML report was not found, so this package uses the frozen manifest, optional retro metadata, and the generated driver source.",
            "raw_sanitizer_report_available": False,
            "instruction": "If this fallback evidence is insufficient for target-component attribution, return false.",
        },
        "manifest_metadata": manifest,
        "retro_metadata_without_final_labels": retro,
        "raw_sanitizer_report": None,
        "sanitizer_parsed": sanitizer_parsed,
        "static_location": static_location,
        "triage_evidence_without_label": triage_evidence,
        "dedup_evidence": {
            "signature": retro.get("signature") or manifest.get("Signature"),
            "group_id": retro.get("cluster_id"),
            "dedup": {
                "is_duplicate": retro.get("is_duplicate") or manifest.get("IsDuplicate"),
                "duplicate_of": retro.get("duplicate_of") or manifest.get("DuplicateOf"),
            },
        },
        "reproduction_evidence": {
            "poc_locate": None,
            "poc_copy": None,
            "poc_paths": None,
            "repro": None,
        },
        "runtime_context": None,
        "driver_source": {
            "path": driver_source_path,
            "missing": driver_source is None,
            "content": driver_source,
        },
    }

    fields = [
        "manifest_metadata",
        "retro_metadata",
        "fallback_notice",
        "sanitizer_parsed",
        "location",
        "triage_evidence",
        "dedup",
        "driver_source",
    ]
    return evidence, fields


def _dump_evidence(evidence: Dict[str, Any]) -> str:
    return yaml.safe_dump(
        evidence,
        sort_keys=False,
        allow_unicode=True,
        width=120,
        default_flow_style=False,
    )


def build_prompt(
    evidence_package: Dict[str, Any],
    max_prompt_chars: int,
    *,
    prompt_variant: str = "differential",
) -> str:
    evidence_text = _dump_evidence(evidence_package)
    if prompt_variant == "differential":
        header = """You are an independent crash-attribution adjudicator.

Your only task is to decide whether the evidence supports attributing this crash to the target component.

Return exactly one JSON object only. The first character must be "{" and the last character must be "}".

Required schema:
{"result": true, "reason": "one short sentence"}
or
{"result": false, "reason": "one short sentence"}

Rules:
- true means the available evidence supports target-component attribution.
- false means the evidence points to generated-driver behavior, noise/low-value report, duplicate evidence that does not support target attribution, or insufficient evidence.
- Explicitly compare the target-component-defect hypothesis against the generated-driver-misuse hypothesis.
- Return true only when the target-component hypothesis is better supported by the supplied evidence.
- Do not judge whether this is a known vulnerability, zero-day, CVE, exploitability issue, or confirmed security bug.
- Do not add extra fields.
- Do not wrap the JSON in markdown fences.
- Do not include any explanation before or after the JSON object.
- Keep reason to one short sentence.

Evidence:
"""
    elif prompt_variant == "direct_v1":
        header = """You are a crash-attribution adjudicator.

Decide whether the supplied evidence supports attributing this crash to the target component.

Return exactly one JSON object only. The first character must be "{" and the last character must be "}".

Required schema:
{"result": true, "reason": "one short sentence"}
or
{"result": false, "reason": "one short sentence"}

true means target-component attribution is supported. false means it is not supported. State the final decision directly from the supplied evidence.
Do not add extra fields or markdown fences.

Evidence:
"""
    else:
        raise ValueError(f"Unknown prompt variant: {prompt_variant}")
    budget = max_prompt_chars - len(header)
    if budget < 1000:
        budget = 1000
    if len(evidence_text) > budget:
        evidence_text = evidence_text[:budget] + f"\n[TRUNCATED: {len(evidence_text) - budget} chars omitted]"
    return header + evidence_text


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _response_excerpt(text: str, limit: int = 500) -> str:
    excerpt = " ".join((text or "").split())
    if len(excerpt) > limit:
        return excerpt[:limit] + "..."
    return excerpt


def _coerce_bool_value(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes", "y", "1", "supported", "target", "target_component"):
            return True
        if normalized in (
            "false",
            "no",
            "n",
            "0",
            "unsupported",
            "insufficient",
            "driver",
            "noise",
            "driver_bug",
            "generated_driver",
        ):
            return False
    return None


def parse_bool_response(text: str) -> Tuple[Optional[bool], str]:
    """Parse JSON or plain true/false responses."""
    raw = _strip_code_fence(text or "")
    low = raw.strip().lower()
    direct = _coerce_bool_value(low)
    if direct is not None:
        return direct, ""

    json_candidates = [raw]
    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match:
        json_candidates.append(match.group(0))

    for candidate in json_candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "result" not in data:
            continue
        result = _coerce_bool_value(data["result"])
        if result is None:
            continue
        reason = data.get("reason", "")
        if not isinstance(reason, str):
            reason = str(reason)
        reason = " ".join(reason.split())
        if len(reason) > 300:
            reason = reason[:300] + "..."
        return result, reason

    result_match = re.search(r'["\']?result["\']?\s*:\s*["\']?(true|false|yes|no)["\']?', raw, flags=re.IGNORECASE)
    if result_match:
        result = _coerce_bool_value(result_match.group(1))
        reason = ""
        reason_match = re.search(r'["\']?reason["\']?\s*:\s*["\']([^"\']{1,300})["\']', raw, flags=re.IGNORECASE)
        if reason_match:
            reason = " ".join(reason_match.group(1).split())
        return result, reason

    first_line = next((line.strip() for line in raw.splitlines() if line.strip()), "")
    line_match = re.match(r"^(true|false|yes|no)\b[:：,\-\s]*(.*)$", first_line, flags=re.IGNORECASE)
    if line_match:
        result = _coerce_bool_value(line_match.group(1))
        reason = " ".join(line_match.group(2).split())
        if len(reason) > 300:
            reason = reason[:300] + "..."
        return result, reason

    return None, ""


def _extract_message_text(response: Any) -> str:
    choice = response.choices[0]
    message = choice.message
    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")
    return content or ""


def _call_openai_compatible(
    messages: List[Dict[str, str]],
    llm: Dict[str, Any],
    *,
    force_json_response_format: bool = False,
) -> Tuple[str, Dict[str, int]]:
    """Call an OpenAI-compatible chat-completions endpoint using stdlib only."""
    base_url = str(llm["base_url"]).rstrip("/")
    url = f"{base_url}/chat/completions"
    payload = {
        "model": llm["model"],
        "messages": messages,
        "temperature": float(llm.get("temperature", 0.0)),
        "max_tokens": 256,
    }
    request_extra = llm.get("request_extra")
    if isinstance(request_extra, dict):
        payload.update(request_extra)
    thinking = llm.get("thinking")
    if thinking is not None:
        payload["thinking"] = thinking
    if force_json_response_format:
        payload["response_format"] = {"type": "json_object"}
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {llm['api_key']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    timeout = float(llm.get("timeout", 300))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {error_body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed: {exc.reason}") from exc

    data = json.loads(raw)
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM response has no choices: {raw[:500]}")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if content is None:
        raise RuntimeError(f"LLM response has no message content: {raw[:500]}")
    usage_raw = data.get("usage") or {}
    usage = {
        "prompt_tokens": int(usage_raw.get("prompt_tokens") or usage_raw.get("input_tokens") or 0),
        "completion_tokens": int(usage_raw.get("completion_tokens") or usage_raw.get("output_tokens") or 0),
    }
    usage["total_tokens"] = int(usage_raw.get("total_tokens") or (usage["prompt_tokens"] + usage["completion_tokens"]))
    return str(content), usage


def call_llm_bool(prompt: str, llm_config: Dict[str, Any]) -> Tuple[Optional[bool], str, str, int, int, Dict[str, int]]:
    """Call the configured LLM and return result, reason, status, latency_ms."""
    llm = llm_config["llm"]
    run = llm_config.get("run", {})
    retries = int(llm.get("max_retries", 3))
    force_json_response_format = bool(run.get("force_json_response_format", True))
    messages = [
        {
            "role": "system",
            "content": (
                "You are a strict JSON generator. Return exactly one valid JSON object and no other text. "
                "The object must match this schema: {\"result\": true|false, \"reason\": \"...\"}."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    start = time.time()
    last_error = ""
    last_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for attempt in range(1, retries + 1):
        try:
            text, usage = _call_openai_compatible(
                messages,
                llm,
                force_json_response_format=force_json_response_format,
            )
            last_usage = usage
            result, reason = parse_bool_response(text)
            if result is not None:
                return result, reason, "ok", int((time.time() - start) * 1000), attempt, last_usage

            repair_messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a strict JSON repair tool. Return exactly one valid JSON object and no other text."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Return exactly one JSON object with a boolean result and one-sentence reason. "
                        "Schema: {\"result\": true|false, \"reason\": \"...\"}\n\n"
                        f"Previous answer:\n{text}"
                    ),
                },
            ]
            repaired, repair_usage = _call_openai_compatible(
                repair_messages,
                llm,
                force_json_response_format=force_json_response_format,
            )
            last_usage = {
                "prompt_tokens": last_usage["prompt_tokens"] + repair_usage["prompt_tokens"],
                "completion_tokens": last_usage["completion_tokens"] + repair_usage["completion_tokens"],
                "total_tokens": last_usage["total_tokens"] + repair_usage["total_tokens"],
            }
            result, reason = parse_bool_response(repaired)
            if result is not None:
                return result, reason, "ok", int((time.time() - start) * 1000), attempt, last_usage
            last_error = f"parse_error: {_response_excerpt(repaired or text)}"
        except Exception as exc:  # noqa: BLE001 - keep per-crash batch running
            last_error = f"api_error: {exc}"
            if attempt < retries:
                time.sleep(min(2 * attempt, 10))

    status = "parse_error" if last_error.startswith("parse_error") else "api_error"
    reason = last_error[:300] if last_error else status
    return None, reason, status, int((time.time() - start) * 1000), retries, last_usage


def _judge_key(llm: Dict[str, Any]) -> Tuple[str, str]:
    """Return the stable judge identity for resume checks."""
    return str(llm.get("model", "")), str(llm.get("base_url", "")).rstrip("/")


def load_jsonl_records(jsonl_path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not os.path.isfile(jsonl_path):
        return records
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def load_completed_records(jsonl_path: str, llm: Dict[str, Any]) -> Dict[Tuple[str, str, str, str, str, str], Dict[str, Any]]:
    completed: Dict[Tuple[str, str, str, str, str, str], Dict[str, Any]] = {}
    model, base_url = _judge_key(llm)
    for record in load_jsonl_records(jsonl_path):
        if record.get("status") != "ok":
            continue
        record_model = str(record.get("model", ""))
        record_base_url = str(record.get("base_url", "")).rstrip("/")
        if (record_model, record_base_url) != (model, base_url):
            continue
        key = (
            record.get("project", ""), record.get("crash_id", ""), record_model,
            record_base_url, record.get("evidence_variant", "full"), record.get("prompt_variant", "differential"),
        )
        completed[key] = record
    return completed


def jsonl_to_csv_record(record: Dict[str, Any]) -> Dict[str, Any]:
    result = record.get("result")
    if result is True:
        result_text = "true"
    elif result is False:
        result_text = "false"
    else:
        result_text = ""
    return {
        "Project": record.get("project", ""),
        "CrashID": record.get("crash_id", ""),
        "Driver": record.get("driver", ""),
        "LLMName": record.get("llm_name", ""),
        "LLMModel": record.get("model", ""),
        "LLMBaseURL": record.get("base_url", ""),
        "Result": result_text,
        "Reason": record.get("reason", ""),
        "Status": record.get("status", ""),
        "PromptSHA256": record.get("prompt_sha256", ""),
        "LatencyMs": record.get("latency_ms", ""),
        "RetryCount": record.get("retry_count", ""),
        "PromptChars": record.get("prompt_chars", ""),
        "PromptTokens": record.get("prompt_tokens", ""),
        "CompletionTokens": record.get("completion_tokens", ""),
        "TotalTokens": record.get("total_tokens", ""),
        "EvidenceVariant": record.get("evidence_variant", ""),
        "PromptVariant": record.get("prompt_variant", ""),
    }


def write_csv(path: str, records: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for record in records:
            writer.writerow(jsonl_to_csv_record(record))


def append_jsonl(path: str, record: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def save_prompt(output_dir: str, row: Dict[str, str], prompt: str) -> None:
    prompts_dir = os.path.join(output_dir, "prompts")
    os.makedirs(prompts_dir, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", row["CrashID"])
    path = os.path.join(prompts_dir, f"{safe_name}.prompt.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(prompt)


def write_run_info(path: str, args: argparse.Namespace, config: Dict[str, Any], count: int) -> None:
    llm = config["llm"]
    run_info = {
        "timestamp": datetime.now().isoformat(),
        "manifest": args.manifest,
        "db_root": args.db_root,
        "llm_config": args.llm_config,
        "output": args.output,
        "sample_count": count,
        "dry_run": args.dry_run,
        "evidence_variant": args.evidence_variant,
        "prompt_variant": args.prompt_variant,
        "llm": {
            "name": llm.get("name"),
            "model": llm.get("model"),
            "base_url": llm.get("base_url"),
            "temperature": llm.get("temperature"),
            "timeout": llm.get("timeout"),
            "max_retries": llm.get("max_retries"),
            "context_window": llm.get("context_window"),
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(run_info, f, sort_keys=False, allow_unicode=True)


def adjudicate_one(
    row: Dict[str, str],
    args: argparse.Namespace,
    config: Dict[str, Any],
    *,
    dry_run: bool,
    save_prompts_flag: bool,
) -> Dict[str, Any]:
    try:
        entry, driver_dir, _ = load_crash_entry(args.db_root, row["Project"], row["Driver"], row["CrashID"])
        include_runtime_context = args.evidence_variant == "full"
        evidence, fields = build_evidence_package(
            row,
            entry,
            driver_dir,
            include_static_context=True,
            include_runtime_context=include_runtime_context,
        )
    except AdjudicationError:
        retro_entry = _load_retro_crash(args.manifest, row["Project"], row["CrashID"])
        driver_source_path, driver_source = _find_project_driver_source(args.db_root, row["Project"], row["Driver"])
        if retro_entry is None and driver_source is None:
            raise
        evidence, fields = build_fallback_evidence_package(row, retro_entry, driver_source_path, driver_source)
    prompt = build_prompt(
        evidence,
        int(config["run"].get("max_prompt_chars", 120000)),
        prompt_variant=args.prompt_variant,
    )
    sha = prompt_hash(prompt)
    if save_prompts_flag:
        save_prompt(args.output, row, prompt)

    llm = config["llm"]
    if dry_run:
        result = None
        reason = "dry_run"
        status = "dry_run"
        latency_ms = 0
        retry_count = 0
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    else:
        result, reason, status, latency_ms, retry_count, usage = call_llm_bool(prompt, config)

    return {
        "project": row["Project"],
        "crash_id": row["CrashID"],
        "driver": row["Driver"],
        "llm_name": llm.get("name", "external-judge"),
        "model": llm.get("model", ""),
        "base_url": str(llm.get("base_url", "")).rstrip("/"),
        "result": result,
        "reason": reason,
        "status": status,
        "prompt_sha256": sha,
        "latency_ms": latency_ms,
        "evidence_fields_used": fields,
        "retry_count": retry_count,
        "prompt_chars": len(prompt),
        "prompt_tokens": usage["prompt_tokens"],
        "completion_tokens": usage["completion_tokens"],
        "total_tokens": usage["total_tokens"],
        "evidence_variant": args.evidence_variant,
        "prompt_variant": args.prompt_variant,
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="External boolean crash adjudication")
    parser.add_argument("--manifest", default="results/per_crash_detail.csv")
    parser.add_argument("--db-root", default="external_database")
    parser.add_argument("--llm-config", default="configs/external_bool_adjudication.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--crash-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--evidence-variant",
        choices=["static", "full"],
        default="full",
        help="static omits runtime context; full includes static and runtime evidence.",
    )
    parser.add_argument(
        "--prompt-variant",
        choices=["differential", "direct_v1"],
        default="differential",
        help="direct_v1 is used by V0-V3; differential is used by full CrashSage V4.",
    )
    parser.add_argument("--save-prompts", action="store_true", help="Force prompt saving")
    parser.add_argument("--no-save-prompts", action="store_true", help="Disable prompt saving")
    parser.add_argument("--no-resume", action="store_true", help="Ignore completed records")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config = load_llm_config(args.llm_config, validate=not args.dry_run)

    rows = load_manifest_rows(args.manifest)
    if args.project:
        rows = [r for r in rows if r.get("Project") == args.project]
    if args.crash_id:
        rows = [r for r in rows if r.get("CrashID") == args.crash_id]
    if args.limit is not None:
        rows = rows[: args.limit]

    os.makedirs(args.output, exist_ok=True)
    jsonl_path = os.path.join(args.output, "llm_bool_results.jsonl")
    csv_path = os.path.join(args.output, "llm_bool_results.csv")
    run_info_path = os.path.join(args.output, "run_info.yaml")

    llm = config["llm"]
    run = config["run"]
    resume = bool(run.get("resume", True)) and not args.no_resume
    save_prompts_flag = args.save_prompts or (bool(run.get("save_prompts", True)) and not args.no_save_prompts)
    completed = load_completed_records(jsonl_path, llm) if resume else {}

    print(f"Loaded {len(rows)} crashes from {args.manifest}")
    print(f"LLM config: {args.llm_config}")
    print(f"LLM: {llm.get('name', 'external-judge')} / {llm.get('model', '')}")
    print(f"Output: {args.output}")

    all_records: List[Dict[str, Any]] = []
    counts = {"ok": 0, "dry_run": 0, "skipped": 0, "parse_error": 0, "api_error": 0, "missing": 0}

    for idx, row in enumerate(rows, start=1):
        model, base_url = _judge_key(llm)
        key = (
            row["Project"], row["CrashID"], model, base_url,
            args.evidence_variant, args.prompt_variant,
        )
        if key in completed:
            record = completed[key]
            all_records.append(record)
            counts["skipped"] += 1
            result = record.get("result")
            result_text = "true" if result is True else "false" if result is False else ""
            print(f"[{idx}/{len(rows)}] {row['Project']}/{row['CrashID']} -> {result_text} (resume)")
            continue

        try:
            record = adjudicate_one(
                row,
                args,
                config,
                dry_run=args.dry_run,
                save_prompts_flag=save_prompts_flag,
            )
        except Exception as exc:  # noqa: BLE001 - keep batch progressing
            record = {
                "project": row.get("Project", ""),
                "crash_id": row.get("CrashID", ""),
                "driver": row.get("Driver", ""),
                "llm_name": llm.get("name", "external-judge"),
                "model": llm.get("model", ""),
                "base_url": str(llm.get("base_url", "")).rstrip("/"),
                "result": None,
                "reason": str(exc)[:300],
                "status": "missing" if isinstance(exc, AdjudicationError) else "error",
                "prompt_sha256": "",
                "latency_ms": 0,
                "evidence_fields_used": [],
                "retry_count": 0,
                "prompt_chars": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "evidence_variant": args.evidence_variant,
                "prompt_variant": args.prompt_variant,
            }

        all_records.append(record)
        append_jsonl(jsonl_path, record)
        status = record["status"]
        counts[status] = counts.get(status, 0) + 1
        result = record.get("result")
        result_text = "true" if result is True else "false" if result is False else ""
        suffix = f" ({status})" if status != "ok" else ""
        print(f"[{idx}/{len(rows)}] {row['Project']}/{row['CrashID']} -> {result_text}{suffix}")

    write_csv(csv_path, load_jsonl_records(jsonl_path))
    write_run_info(run_info_path, args, config, len(rows))

    print(
        "Done. "
        f"ok={counts.get('ok', 0)} "
        f"dry_run={counts.get('dry_run', 0)} "
        f"skipped={counts.get('skipped', 0)} "
        f"parse_error={counts.get('parse_error', 0)} "
        f"api_error={counts.get('api_error', 0)} "
        f"missing={counts.get('missing', 0)}"
    )
    print(f"CSV: {csv_path}")
    print(f"JSONL: {jsonl_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
