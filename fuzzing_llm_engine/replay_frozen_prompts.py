#!/usr/bin/env python3
"""Replay frozen final prompts with the analysis model in the current project configs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Mapping, Tuple

import yaml

from llama_index.core.program import LLMTextCompletionProgram
from roles.crash_analyzer import (
    CrashAnalysis,
    EnhancedCrashAnalysis,
    _ENHANCED_EXTRACT_PROMPT,
    _apply_prior_decision,
    _deterministic_decision_consistency_violation,
    _parse_enhanced_json_response,
    _promote_target_state_memory_safety,
    _repair_archive_metadata_consistency_with_llm,
    _repair_negative_boundary_consistency_with_llm,
)


DEFAULT_FROZEN_PROMPTS = Path("results/revision_20260728/frozen_v3_differential_prompts_57.jsonl")
DEFAULT_OUT_DIR = Path("results/revision_20260728/llm_v3_frozen_prompt_replay")
RESULT_FIELDS = [
    "Project", "CrashID", "Driver", "LLMName", "LLMModel", "Result", "Reason", "Status",
    "LatencyMs", "PromptChars", "PromptSHA256", "FrozenPromptSHA256", "EvidenceVariant", "PromptVariant",
    "RunVariant", "AnalysisEngine", "ExperimentFingerprint", "InputFingerprint",
    "FinalCallCount", "DecisionParseMode", "DecisionParseError",
    "ArchiveMetadataRepairApplied", "NegativeBoundaryRepairApplied",
]

_V0_MINIMAL_JSON_SUFFIX = """

FINAL OUTPUT REQUIREMENT (overrides any earlier response-format request):
Return exactly one JSON object and no other text:
{"is_api_bug": true}
Use false when the crash is caused by the fuzz driver rather than a target API bug.
"""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def load_frozen_prompts(path: Path, expected_count: int) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    seen: set[Tuple[str, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            project = str(record.get("project") or "")
            crash_id = str(record.get("crash_id") or "")
            prompt = record.get("prompt")
            saved_hash = str(record.get("prompt_sha256") or "")
            key = (project, crash_id)
            if not project or not crash_id or not isinstance(prompt, str) or not prompt:
                raise ValueError(f"Invalid frozen record at {path}:{line_number}")
            if key in seen:
                raise ValueError(f"Duplicate frozen record: {key}")
            if _sha256(prompt) != saved_hash:
                raise ValueError(f"Prompt SHA-256 mismatch in frozen record: {key}")
            seen.add(key)
            records.append(record)

    if len(records) != expected_count:
        raise ValueError(f"Expected {expected_count} frozen prompts, found {len(records)} in {path}")
    return records


def select_frozen_prompts(records: List[Dict[str, object]], crash_id_filter: str) -> List[Dict[str, object]]:
    """Select an explicit subset without changing any frozen prompt content."""
    selected_ids = {item.strip() for item in crash_id_filter.split(",") if item.strip()}
    if not selected_ids:
        return records
    selected = [record for record in records if str(record["crash_id"]) in selected_ids]
    observed_ids = {str(record["crash_id"]) for record in selected}
    missing = sorted(selected_ids.difference(observed_ids))
    if missing:
        raise ValueError(f"CrashID filter did not match frozen prompts: {missing}")
    return selected


def load_analyzer_configs(records: List[Mapping[str, object]], db_root: Path, temperature: float) -> Dict[str, Dict[str, object]]:
    configs: Dict[str, Dict[str, object]] = {}
    for project in sorted({str(record["project"]) for record in records}):
        config_path = db_root / project / "config.yaml"
        with config_path.open(encoding="utf-8") as handle:
            project_config = yaml.safe_load(handle)
        analyzer_config = dict(project_config["llm_analyzer"])
        analyzer_config["temperature"] = temperature
        overrides = {
            "model": "LLM_MODEL_OVERRIDE",
            "base_url": "LLM_BASE_URL_OVERRIDE",
            "api_key": "LLM_API_KEY_OVERRIDE",
        }
        for config_key, env_name in overrides.items():
            override = os.environ.get(env_name, "").strip()
            if override:
                analyzer_config[config_key] = override
        numeric_overrides = {
            "timeout": ("LLM_TIMEOUT_OVERRIDE", float),
            "max_retries": ("LLM_MAX_RETRIES_OVERRIDE", int),
            "max_tokens": ("LLM_MAX_TOKENS_OVERRIDE", int),
        }
        for config_key, (env_name, convert) in numeric_overrides.items():
            override = os.environ.get(env_name, "").strip()
            if override:
                analyzer_config[config_key] = convert(override)
        extra_body = os.environ.get("LLM_EXTRA_BODY_JSON", "").strip()
        if extra_body:
            analyzer_config["additional_kwargs"] = json.loads(extra_body)
        configs[project] = analyzer_config

    configured_models = {str(config["model"]) for config in configs.values()}
    if len(configured_models) != 1:
        raise ValueError(
            "Frozen replay requires one analysis model across all project config.yaml files; "
            f"found {sorted(configured_models)}"
        )
    return configs


def _model_dict(result: object) -> Dict[str, object]:
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return result.dict()


def create_model(config: Mapping[str, object]) -> object:
    """Import the model factory only when a non-dry replay actually starts."""
    from models.get_model import get_model

    return get_model(dict(config))


def _triage_label_from_prompt(prompt: str) -> str:
    marker = "Preliminary classification: "
    if marker not in prompt:
        return ""
    remainder = prompt.split(marker, 1)[1]
    return remainder.split(" ", 1)[0].strip()


def finalize_v3_response(llm: object, prompt: str, primary_response: str) -> Dict[str, object]:
    """Apply the original V3 response parsing and repair protocol to one frozen prompt."""
    enhanced_result: EnhancedCrashAnalysis | None = None
    final_response = primary_response
    decision_parse_mode = "primary_json"
    decision_parse_error = ""
    call_count = 1
    archive_metadata_repair = {"applied": False, "violation": "", "error": ""}
    negative_boundary_repair = {"applied": False, "violation": "", "error": ""}

    try:
        enhanced_result = _parse_enhanced_json_response(primary_response)
    except Exception as primary_error:
        decision_parse_mode = "legacy_second_pass"
        decision_parse_error = str(primary_error)
        try:
            call_count += 1
            extract_program = LLMTextCompletionProgram.from_defaults(
                output_cls=EnhancedCrashAnalysis,
                prompt_template_str=_ENHANCED_EXTRACT_PROMPT,
                llm=llm,
            )
            enhanced_result = extract_program(raw_answer=primary_response)
        except Exception as extract_error:
            decision_parse_mode = "basic_second_pass"
            decision_parse_error = f"{decision_parse_error}; enhanced fallback: {extract_error}"
            try:
                call_count += 1
                basic_program = LLMTextCompletionProgram.from_defaults(
                    output_cls=CrashAnalysis,
                    prompt_template_str=(
                        "The input answer is:\n {raw_answer}\n. "
                        "Please extract is_api_bug (bool) and crash_category (str)."
                    ),
                    llm=llm,
                )
                basic_result = basic_program(raw_answer=primary_response)
                return {
                    "is_api_bug": bool(basic_result.is_api_bug),
                    "crash_category": str(basic_result.crash_category),
                    "final_response": final_response,
                    "structured_decision": None,
                    "decision_parse_mode": decision_parse_mode,
                    "decision_parse_error": decision_parse_error,
                    "archive_metadata_repair": archive_metadata_repair,
                    "negative_boundary_repair": negative_boundary_repair,
                    "call_count": call_count,
                }
            except Exception as basic_error:
                decision_parse_mode = "triage_fallback"
                decision_parse_error = f"{decision_parse_error}; basic fallback: {basic_error}"
                return {
                    "is_api_bug": _triage_label_from_prompt(prompt) == "likely_api_bug",
                    "crash_category": "Unknown",
                    "final_response": final_response,
                    "structured_decision": None,
                    "decision_parse_mode": decision_parse_mode,
                    "decision_parse_error": decision_parse_error,
                    "archive_metadata_repair": archive_metadata_repair,
                    "negative_boundary_repair": negative_boundary_repair,
                    "call_count": call_count,
                }

    try:
        repaired_result, repair_response, violation = _repair_archive_metadata_consistency_with_llm(
            llm,
            prompt=prompt,
            previous_response=final_response,
            previous_result=enhanced_result,
        )
        if repair_response:
            call_count += 1
            enhanced_result = repaired_result
            final_response = repair_response
            decision_parse_mode = f"{decision_parse_mode}+archive_metadata_repair"
            archive_metadata_repair = {"applied": True, "violation": violation, "error": ""}
    except Exception as repair_error:
        archive_metadata_repair = {"applied": False, "violation": "", "error": str(repair_error)}
        decision_parse_error = (
            f"{decision_parse_error}; archive metadata repair failed: {repair_error}"
            if decision_parse_error else f"archive metadata repair failed: {repair_error}"
        )

    try:
        repaired_result, repair_response, violation = _repair_negative_boundary_consistency_with_llm(
            llm,
            prompt=prompt,
            previous_response=final_response,
            previous_result=enhanced_result,
        )
        if repair_response:
            call_count += 1
            enhanced_result = repaired_result
            final_response = repair_response
            decision_parse_mode = f"{decision_parse_mode}+negative_boundary_repair"
            negative_boundary_repair = {"applied": True, "violation": violation, "error": ""}
    except Exception as repair_error:
        negative_boundary_repair = {"applied": False, "violation": "", "error": str(repair_error)}
        decision_parse_error = (
            f"{decision_parse_error}; negative boundary repair failed: {repair_error}"
            if decision_parse_error else f"negative boundary repair failed: {repair_error}"
        )

    return {
        "is_api_bug": bool(enhanced_result.is_api_bug),
        "crash_category": str(enhanced_result.crash_category),
        "final_response": final_response,
        "structured_decision": _model_dict(enhanced_result),
        "decision_parse_mode": decision_parse_mode,
        "decision_parse_error": decision_parse_error,
        "archive_metadata_repair": archive_metadata_repair,
        "negative_boundary_repair": negative_boundary_repair,
        "call_count": call_count,
    }


def finalize_v4_response(
    llm: object,
    prompt: str,
    primary_response: str,
    *,
    prior_prediction: bool | None,
) -> Dict[str, object]:
    """Parse a frozen V4 response with the current non-repair decision policy."""
    enhanced_result: EnhancedCrashAnalysis | None = None
    decision_parse_mode = "primary_json"
    decision_parse_error = ""
    call_count = 1
    try:
        enhanced_result = _parse_enhanced_json_response(primary_response)
    except Exception as primary_error:
        decision_parse_mode = "legacy_second_pass"
        decision_parse_error = str(primary_error)
        try:
            call_count += 1
            extract_program = LLMTextCompletionProgram.from_defaults(
                output_cls=EnhancedCrashAnalysis,
                prompt_template_str=_ENHANCED_EXTRACT_PROMPT,
                llm=llm,
            )
            enhanced_result = extract_program(raw_answer=primary_response)
        except Exception as extract_error:
            decision_parse_mode = "basic_second_pass"
            decision_parse_error = (
                f"{decision_parse_error}; enhanced fallback: {extract_error}"
            )
            call_count += 1
            basic_program = LLMTextCompletionProgram.from_defaults(
                output_cls=CrashAnalysis,
                prompt_template_str=(
                    "The input answer is:\n {raw_answer}\n. "
                    "Please extract the bool value of the variable <is_api_bug> "
                    "and the string value of <crash_category>."
                ),
                llm=llm,
            )
            basic_result = basic_program(raw_answer=primary_response)
            return {
                "is_api_bug": bool(basic_result.is_api_bug),
                "crash_category": str(basic_result.crash_category),
                "final_response": primary_response,
                "structured_decision": None,
                "decision_parse_mode": decision_parse_mode,
                "decision_parse_error": decision_parse_error,
                "archive_metadata_repair": {
                    "applied": False,
                    "violation": "",
                    "error": "",
                },
                "negative_boundary_repair": {
                    "applied": False,
                    "violation": "",
                    "error": "",
                },
                "deterministic_consistency_repair": "",
                "prior_decision": {
                    "applied": False,
                    "prior_prediction": prior_prediction,
                    "reason": "structured_result_unavailable",
                },
                "call_count": call_count,
            }

    consistency = _deterministic_decision_consistency_violation(
        enhanced_result,
        prompt,
    )
    if consistency:
        enhanced_result.is_api_bug = False
        enhanced_result.decision_basis = "driver_evidence"
        if str(
            getattr(enhanced_result, "driver_misuse_evidence_strength", "") or ""
        ).lower() == "none":
            enhanced_result.driver_misuse_evidence_strength = "soft"

    prior_decision = _apply_prior_decision(
        enhanced_result,
        prompt,
        prior_prediction,
        prompt_variant="differential",
        run_variant="V4",
    )
    target_state_memory_safety_repair = _promote_target_state_memory_safety(
        enhanced_result,
        prompt,
        prompt_variant="differential",
    )
    return {
        "is_api_bug": bool(enhanced_result.is_api_bug),
        "crash_category": str(enhanced_result.crash_category),
        "final_response": primary_response,
        "structured_decision": _model_dict(enhanced_result),
        "decision_parse_mode": decision_parse_mode,
        "decision_parse_error": decision_parse_error,
        "archive_metadata_repair": {"applied": False, "violation": "", "error": ""},
        "negative_boundary_repair": {"applied": False, "violation": "", "error": ""},
        "deterministic_consistency_repair": consistency,
        "prior_decision": prior_decision,
        "target_state_memory_safety_repair": target_state_memory_safety_repair,
        "call_count": call_count,
    }


def finalize_v4_direct_response(
    llm: object,
    prompt: str,
    primary_response: str,
) -> Dict[str, object]:
    """Parse a fresh V4 answer without prior inheritance or result replay."""
    decision_parse_mode = "primary_json"
    decision_parse_error = ""
    call_count = 1
    try:
        enhanced_result = _parse_enhanced_json_response(primary_response)
    except Exception as primary_error:
        decision_parse_mode = "legacy_second_pass"
        decision_parse_error = str(primary_error)
        try:
            call_count += 1
            extract_program = LLMTextCompletionProgram.from_defaults(
                output_cls=EnhancedCrashAnalysis,
                prompt_template_str=_ENHANCED_EXTRACT_PROMPT,
                llm=llm,
            )
            enhanced_result = extract_program(raw_answer=primary_response)
        except Exception as extract_error:
            decision_parse_mode = "basic_second_pass"
            decision_parse_error = (
                f"{decision_parse_error}; enhanced fallback: {extract_error}"
            )
            call_count += 1
            basic_program = LLMTextCompletionProgram.from_defaults(
                output_cls=CrashAnalysis,
                prompt_template_str=(
                    "The input answer is:\n {raw_answer}\n. "
                    "Please extract the bool value of the variable <is_api_bug> "
                    "and the string value of <crash_category>."
                ),
                llm=llm,
            )
            basic_result = basic_program(raw_answer=primary_response)
            return {
                "is_api_bug": bool(basic_result.is_api_bug),
                "crash_category": str(basic_result.crash_category),
                "final_response": primary_response,
                "structured_decision": None,
                "decision_parse_mode": decision_parse_mode,
                "decision_parse_error": decision_parse_error,
                "archive_metadata_repair": {
                    "applied": False,
                    "violation": "",
                    "error": "",
                },
                "negative_boundary_repair": {
                    "applied": False,
                    "violation": "",
                    "error": "",
                },
                "call_count": call_count,
            }

    return {
        "is_api_bug": bool(enhanced_result.is_api_bug),
        "crash_category": str(enhanced_result.crash_category),
        "final_response": primary_response,
        "structured_decision": _model_dict(enhanced_result),
        "decision_parse_mode": decision_parse_mode,
        "decision_parse_error": decision_parse_error,
        "archive_metadata_repair": {"applied": False, "violation": "", "error": ""},
        "negative_boundary_repair": {"applied": False, "violation": "", "error": ""},
        "call_count": call_count,
    }


def load_prior_predictions(paths: List[Path]) -> Dict[Tuple[str, str], bool]:
    predictions: Dict[Tuple[str, str], bool] = {}
    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                value = row.get("Result", row.get("Prediction", ""))
                if value != "":
                    predictions[(row["Project"], row["CrashID"])] = str(
                        value
                    ).strip().lower() in {"true", "1", "yes"}
    return predictions


def finalize_legacy_v0_response(llm: object, primary_response: str) -> Dict[str, object]:
    """Parse the archived V0 prose response without applying V3 repairs.

    Archived V0 prompts predate the structured JSON contract. Most responses
    state the binary decision directly, so parse that locally and avoid a
    second model call. The extractor is retained only for responses that do
    not expose a recognizable decision.
    """
    bool_patterns = (
        r"(?:is\s+this\s+(?:an?\s+)?api\s+bug|is_api_bug)\s*(?:\([^)]*\))?\s*[:：=\-?]?\s*\**\s*(true|false)\b",
        r"(?:final\s+)?(?:attribution|verdict|answer)\s*[:：=\-]\s*\**\s*(true|false)\b",
    )
    is_api_bug = None
    for pattern in bool_patterns:
        match = re.search(pattern, primary_response, flags=re.IGNORECASE)
        if match:
            is_api_bug = match.group(1).lower() == "true"
            break

    category = "Unknown"
    category_match = re.search(
        r"(?:crash\s+categor(?:y|ize)|category)\s*[:：=\-]\s*([^\n.]+)",
        primary_response,
        flags=re.IGNORECASE,
    )
    if category_match:
        category = category_match.group(1).strip().strip("`*") or category

    call_count = 1
    decision_parse_mode = "legacy_local_regex"
    decision_parse_error = ""
    if is_api_bug is None:
        call_count += 1
        try:
            extract_program = LLMTextCompletionProgram.from_defaults(
                output_cls=CrashAnalysis,
                prompt_template_str=(
                    "The input answer is:\n {raw_answer}\n. "
                    "Please extract the bool value of the variable <is_api_bug> "
                    "and the string value of <crash_category>."
                ),
                llm=llm,
            )
            extracted = extract_program(raw_answer=primary_response)
            is_api_bug = bool(extracted.is_api_bug)
            category = str(extracted.crash_category)
            decision_parse_mode = "legacy_extractor"
        except Exception as error:
            decision_parse_mode = "legacy_parse_failed"
            decision_parse_error = str(error)
            is_api_bug = False

    return {
        "is_api_bug": bool(is_api_bug),
        "crash_category": category,
        "final_response": primary_response,
        "structured_decision": None,
        "decision_parse_mode": decision_parse_mode,
        "decision_parse_error": decision_parse_error,
        "archive_metadata_repair": {"applied": False, "violation": "", "error": ""},
        "negative_boundary_repair": {"applied": False, "violation": "", "error": ""},
        "call_count": call_count,
    }


def finalize_v0_minimal_json_response(primary_response: str) -> Dict[str, object]:
    """Read the one-field V0 clean-output contract without V3/V4 repairs."""
    text = primary_response.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE).strip()
    candidates = [text]
    candidates.extend(re.findall(r"\{[^{}]*\}", text, flags=re.DOTALL))
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        value = payload.get("is_api_bug") if isinstance(payload, dict) else None
        if isinstance(value, bool):
            return {
                "is_api_bug": value,
                "crash_category": "Unknown",
                "final_response": primary_response,
                "structured_decision": payload,
                "decision_parse_mode": "v0_minimal_json",
                "decision_parse_error": "",
                "archive_metadata_repair": {"applied": False, "violation": "", "error": ""},
                "negative_boundary_repair": {"applied": False, "violation": "", "error": ""},
                "call_count": 1,
            }
    raise ValueError("V0 minimal output must contain JSON boolean field is_api_bug")


def build_replay_prompt(frozen_prompt: str, protocol: str) -> str:
    """Preserve archived text and apply only the selected output contract."""
    if protocol == "v0_minimal_json":
        return f"{frozen_prompt}{_V0_MINIMAL_JSON_SUFFIX}"
    return frozen_prompt


def run_replay(args: argparse.Namespace) -> None:
    records = load_frozen_prompts(args.frozen_prompts, args.expected_count)
    records = select_frozen_prompts(records, getattr(args, "crash_id_filter", ""))
    configs = load_analyzer_configs(records, args.db_root, args.temperature)
    model_name = str(next(iter(configs.values()))["model"])
    protocol = getattr(args, "protocol", "v3")
    prior_predictions: Dict[Tuple[str, str], bool] = {}
    if protocol == "v4_frozen":
        prior_paths = [
            Path(path)
            for path in getattr(args, "prior_results", "").split(os.pathsep)
            if path.strip()
        ]
        if not prior_paths:
            raise ValueError("v4_frozen replay requires --prior-results")
        prior_predictions = load_prior_predictions(prior_paths)

    if args.dry_run:
        print(f"Validated {len(records)} frozen prompts from {args.frozen_prompts}")
        print(f"ConfiguredModel={model_name}")
        print("Dry run completed without model calls.")
        return

    out_csv = args.out_dir / "llm_bool_results.csv"
    out_jsonl = args.out_dir / "llm_bool_results.jsonl"
    if args.out_dir.exists() and not args.resume:
        raise FileExistsError(f"Output directory already exists: {args.out_dir}; use --resume to continue")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    completed: Dict[Tuple[str, str], Mapping[str, str]] = {}
    if args.resume and out_csv.exists():
        with out_csv.open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                key = (row["Project"], row["CrashID"])
                if row.get("Status") == "ok":
                    if row.get("LLMModel") != model_name:
                        raise ValueError(f"Existing result uses a different model for {key}")
                    completed[key] = row

    write_header = not out_csv.exists()
    analyzers: Dict[str, object] = {}
    with out_csv.open("a", newline="", encoding="utf-8") as csv_handle, out_jsonl.open("a", encoding="utf-8") as jsonl_handle:
        writer = csv.DictWriter(csv_handle, fieldnames=RESULT_FIELDS)
        if write_header:
            writer.writeheader()

        for index, record in enumerate(records, 1):
            project = str(record["project"])
            crash_id = str(record["crash_id"])
            key = (project, crash_id)
            frozen_prompt = str(record["prompt"])
            frozen_prompt_hash = str(record["prompt_sha256"])
            prompt = build_replay_prompt(frozen_prompt, protocol)
            prompt_hash = _sha256(prompt)
            if key in completed:
                if completed[key].get("PromptSHA256") != prompt_hash:
                    raise ValueError(f"Resume result uses a different frozen prompt: {key}")
                print(f"[{index}/{len(records)}] skip ok {crash_id}")
                continue

            if project not in analyzers:
                analyzers[project] = create_model(configs[project])
            llm = analyzers[project]
            print(f"[{index}/{len(records)}] replay {project} {crash_id}")
            started = time.time()
            raw_response = ""
            parse_mode = "primary_json"
            parse_error = ""
            finalization: Dict[str, object] = {}
            try:
                # The primary call uses a frozen prompt; V3 repairs below may add calls.
                raw_response = llm.complete(prompt).text
                if protocol == "v0_legacy":
                    finalization = finalize_legacy_v0_response(llm, raw_response)
                elif protocol == "v0_minimal_json":
                    finalization = finalize_v0_minimal_json_response(raw_response)
                elif protocol == "v4_frozen":
                    if key not in prior_predictions:
                        raise ValueError(f"Missing frozen V3 prior prediction: {key}")
                    finalization = finalize_v4_response(
                        llm,
                        prompt,
                        raw_response,
                        prior_prediction=prior_predictions[key],
                    )
                elif protocol == "v4_frozen_direct":
                    finalization = finalize_v4_direct_response(
                        llm,
                        prompt,
                        raw_response,
                    )
                else:
                    finalization = finalize_v3_response(llm, prompt, raw_response)
                status = "ok"
                result = str(bool(finalization["is_api_bug"])).lower()
                reason = str(finalization["crash_category"])
                parse_mode = str(finalization["decision_parse_mode"])
                parse_error = str(finalization["decision_parse_error"])
                decision_payload = finalization["structured_decision"]
                final_response = str(finalization["final_response"])
                call_count = int(finalization["call_count"])
                archive_repair = finalization["archive_metadata_repair"]
                negative_repair = finalization["negative_boundary_repair"]
            except Exception as exc:
                status = "error"
                result = ""
                reason = ""
                parse_mode = "request_error"
                parse_error = str(exc)
                decision_payload = None
                final_response = raw_response
                call_count = 1 if raw_response else 0
                archive_repair = {"applied": False, "violation": "", "error": ""}
                negative_repair = {"applied": False, "violation": "", "error": ""}

            output = {
                "Project": project,
                "CrashID": crash_id,
                "Driver": str(record.get("driver") or ""),
                "LLMName": "frozen-prompt-replay",
                "LLMModel": model_name,
                "Result": result,
                "Reason": reason,
                "Status": status,
                "LatencyMs": int((time.time() - started) * 1000),
                "PromptChars": len(prompt),
                "PromptSHA256": prompt_hash,
                "FrozenPromptSHA256": frozen_prompt_hash,
                "EvidenceVariant": getattr(args, "evidence_variant", "full"),
                "PromptVariant": getattr(args, "prompt_variant", "differential"),
                "RunVariant": "V4" if protocol in {"v4_frozen", "v4_frozen_direct"} else getattr(args, "run_variant", ""),
                "AnalysisEngine": "crashsage" if protocol in {"v4_frozen", "v4_frozen_direct"} else getattr(args, "analysis_engine", ""),
                "ExperimentFingerprint": str(record.get("source_experiment_fingerprint") or ""),
                "InputFingerprint": str(record.get("source_input_fingerprint") or ""),
                "FinalCallCount": call_count,
                "DecisionParseMode": parse_mode,
                "DecisionParseError": parse_error,
                "ArchiveMetadataRepairApplied": str(bool(archive_repair["applied"])).lower(),
                "NegativeBoundaryRepairApplied": str(bool(negative_repair["applied"])).lower(),
            }
            writer.writerow(output)
            csv_handle.flush()
            jsonl_handle.write(json.dumps({
                "project": project,
                "crash_id": crash_id,
                "driver": record.get("driver") or "",
                "prompt_sha256": prompt_hash,
                "frozen_prompt_sha256": frozen_prompt_hash,
                "llm_model": model_name,
                "primary_model_response": raw_response,
                "final_model_response": final_response,
                "structured_decision": decision_payload,
                "decision_parse_mode": parse_mode,
                "decision_parse_error": parse_error,
                "deterministic_consistency_repair": finalization.get(
                    "deterministic_consistency_repair", ""
                ),
                "prior_decision": finalization.get("prior_decision", {}),
                "target_state_memory_safety_repair": finalization.get(
                    "target_state_memory_safety_repair", {}
                ),
                "archive_metadata_repair": archive_repair,
                "negative_boundary_repair": negative_repair,
                "final_call_count": call_count,
            }, ensure_ascii=False) + "\n")
            jsonl_handle.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-prompts", type=Path, default=Path(os.environ.get("FROZEN_PROMPTS", DEFAULT_FROZEN_PROMPTS)))
    parser.add_argument("--out-dir", type=Path, default=Path(os.environ.get("OUT_DIR", DEFAULT_OUT_DIR)))
    parser.add_argument("--db-root", type=Path, default=Path("external_database"))
    parser.add_argument("--temperature", type=float, default=float(os.environ.get("FROZEN_TEMPERATURE", "0")))
    parser.add_argument("--expected-count", type=int, default=57)
    parser.add_argument("--crash-id-filter", default=os.environ.get("CRASH_ID_FILTER", ""))
    parser.add_argument(
        "--protocol",
        choices=("v3", "v4_frozen", "v4_frozen_direct", "v0_legacy", "v0_minimal_json"),
        default="v3",
    )
    parser.add_argument("--evidence-variant", default="full")
    parser.add_argument("--prompt-variant", default="differential")
    parser.add_argument(
        "--prior-results",
        default=os.environ.get("PRIOR_RESULTS", ""),
        help="Frozen V3 result CSV path(s), separated by the OS path separator.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    run_replay(parser.parse_args())


if __name__ == "__main__":
    main()
