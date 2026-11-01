#!/usr/bin/env python3
"""Prepare, run, and evaluate the full-population raw-only LLM baseline.

The raw-only condition intentionally bypasses filtering, representative
selection, source lookup, rule attribution, and runtime-context reconstruction.
Each of the frozen crash reports is sent to the LLM exactly as a standalone
sanitizer report.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml


DEFAULT_LABEL_MANIFEST = Path(
    "results/dedup_schema2_14projects_20261027/final_v0_expanded_1217.csv"
)
DEFAULT_DB_ROOT = Path("external_database")
DEFAULT_V4_METRICS = Path(
    "results/paper_aligned_20261028_arbitrated/"
    "final_overall_metrics_v0_v4_1217.csv"
)
DEFAULT_EXPECTED_COUNT = 1217
DEFAULT_MODEL = "qwen3-coder-flash"
EVIDENCE_VARIANT = "raw_only"
PROMPT_VARIANT = "raw_only_direct"

PROMPT_TEMPLATE = """You are an independent crash-attribution adjudicator.

Your task is to decide whether this crash is caused by a defect in the target
library or by incorrect usage in the generated fuzz driver.

Use only the original sanitizer output below. It is the complete evidence
available to you. Do not assume access to source code, API documentation,
filtering metadata, deduplication metadata, or reconstructed runtime state.

Return exactly one valid JSON object and no other text:
{"is_api_bug": true}
or
{"is_api_bug": false}

Use true only when the raw crash report itself supports target-library
attribution. Use false when the report points to generated-driver behavior,
does not support target attribution, or is insufficient.

RAW SANITIZER OUTPUT:
__RAW_REPORT__
"""

RESULT_FIELDS = [
    "Project",
    "CrashID",
    "Driver",
    "LLMName",
    "LLMModel",
    "LLMBaseURL",
    "Temperature",
    "Result",
    "Reason",
    "Status",
    "PromptSHA256",
    "PromptChars",
    "RawReportChars",
    "LatencyMs",
    "NetworkCalls",
    "EvidenceVariant",
    "PromptVariant",
]


def _truth(value: Any) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ValueError(f"Expected a boolean label, found {value!r}")


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _driver_from_crash_id(crash_id: str) -> str:
    driver = re.sub(r"_crash_\d+$", "", crash_id)
    if driver == crash_id:
        raise ValueError(f"Cannot derive Driver from CrashID: {crash_id}")
    return driver


def _normalize_raw_report(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing non-empty crash_info")
    text = value
    if text.startswith("|"):
        text = text[1:].lstrip("\n")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(
        char for char in text
        if char in {"\n", "\t"} or not (ord(char) < 32 or ord(char) == 127)
    )
    text = text.strip()
    if not text:
        raise ValueError("crash_info is empty after normalization")
    return text


def build_raw_only_prompt(raw_report: str) -> str:
    return PROMPT_TEMPLATE.replace("__RAW_REPORT__", raw_report)


def load_label_manifest(
    path: Path,
    *,
    expected_count: int,
) -> List[Dict[str, str]]:
    rows = _read_csv(path)
    required = {"Project", "CrashID", "GroundTruth"}
    missing = required.difference(rows[0].keys() if rows else [])
    if missing:
        raise ValueError(f"Label manifest is missing columns: {sorted(missing)}")
    if expected_count > 0 and len(rows) != expected_count:
        raise ValueError(
            f"Expected {expected_count} crash reports in {path}, found {len(rows)}"
        )
    result = []
    seen = set()
    for row in rows:
        project = str(row.get("Project") or "").strip()
        crash_id = str(row.get("CrashID") or "").strip()
        if not project or not crash_id:
            raise ValueError("Label manifest contains an empty Project or CrashID")
        key = (project, crash_id)
        if key in seen:
            raise ValueError(f"Duplicate crash key in label manifest: {key}")
        seen.add(key)
        _truth(row["GroundTruth"])
        result.append({
            "Project": project,
            "CrashID": crash_id,
            "Driver": _driver_from_crash_id(crash_id),
            "GroundTruth": str(row["GroundTruth"]).strip(),
        })
    return result


def build_crash_info_index(
    db_root: Path,
    projects: Iterable[str],
) -> Dict[Tuple[str, str], Tuple[Any, Path]]:
    index: Dict[Tuple[str, str], Tuple[Any, Path]] = {}
    for project in sorted(set(projects)):
        crash_root = db_root / project / "crash"
        if not crash_root.is_dir():
            raise FileNotFoundError(f"Missing crash root: {crash_root}")
        for yaml_path in sorted(crash_root.glob("*/crash_analysis.yaml")):
            with yaml_path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            if not isinstance(data, list):
                raise ValueError(f"Expected a list in {yaml_path}")
            driver = yaml_path.parent.name
            for item in data:
                if not isinstance(item, dict):
                    continue
                for local_id, entry in item.items():
                    if not isinstance(entry, dict):
                        continue
                    key = (project, f"{driver}_{local_id}")
                    if key in index:
                        raise ValueError(f"Duplicate crash_info entry for {key}")
                    index[key] = (entry, yaml_path)
    return index


def prepare_bundle(
    *,
    label_manifest: Path,
    db_root: Path,
    output_dir: Path,
    expected_count: int,
    overwrite: bool,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = [
        output_dir / "manifest_1217.csv",
        output_dir / "prompts.jsonl",
        output_dir / "prepare_summary.json",
    ]
    if not overwrite and any(path.exists() for path in outputs):
        raise FileExistsError(
            f"Prepared files already exist in {output_dir}; use --overwrite to replace them"
        )

    labels = load_label_manifest(label_manifest, expected_count=expected_count)
    index = build_crash_info_index(db_root, (row["Project"] for row in labels))
    expected_keys = {(row["Project"], row["CrashID"]) for row in labels}
    missing = sorted(expected_keys.difference(index))
    if missing:
        preview = ", ".join(f"{project}/{crash}" for project, crash in missing[:5])
        raise ValueError(f"Missing crash_info for {len(missing)} reports: {preview}")

    prompts = []
    for row in labels:
        key = (row["Project"], row["CrashID"])
        entry, source_yaml = index[key]
        raw_report = _normalize_raw_report(entry.get("crash_info"))
        prompt = build_raw_only_prompt(raw_report)
        prompts.append({
            "project": row["Project"],
            "crash_id": row["CrashID"],
            "driver": row["Driver"],
            "prompt": prompt,
            "prompt_sha256": _sha256(prompt),
            "prompt_chars": len(prompt),
            "raw_report_chars": len(raw_report),
            "source_yaml": str(source_yaml),
        })

    _write_csv(
        output_dir / "manifest_1217.csv",
        ["Project", "CrashID", "Driver", "GroundTruth"],
        labels,
    )
    with (output_dir / "prompts.jsonl").open("w", encoding="utf-8") as handle:
        for record in prompts:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label_manifest": str(label_manifest),
        "db_root": str(db_root),
        "count": len(prompts),
        "positive_labels": sum(_truth(row["GroundTruth"]) for row in labels),
        "negative_labels": sum(not _truth(row["GroundTruth"]) for row in labels),
        "prompt_chars_min": min(record["prompt_chars"] for record in prompts),
        "prompt_chars_max": max(record["prompt_chars"] for record in prompts),
        "raw_report_chars_min": min(record["raw_report_chars"] for record in prompts),
        "raw_report_chars_max": max(record["raw_report_chars"] for record in prompts),
        "prompt_corpus_sha256": _sha256(
            "".join(record["prompt_sha256"] for record in prompts)
        ),
        "evidence_policy": [
            "raw sanitizer report only",
            "no filtering or triage metadata",
            "no representative or deduplication metadata",
            "no source, API, CWE, driver, or runtime-context evidence",
        ],
    }
    (output_dir / "prepare_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def load_prompt_records(path: Path, expected_count: int) -> List[Dict[str, Any]]:
    records = []
    seen = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            key = (str(record.get("project") or ""), str(record.get("crash_id") or ""))
            prompt = record.get("prompt")
            if not all(key) or not isinstance(prompt, str) or not prompt:
                raise ValueError(f"Invalid prompt record at {path}:{line_number}")
            if key in seen:
                raise ValueError(f"Duplicate prompt record for {key}")
            if _sha256(prompt) != record.get("prompt_sha256"):
                raise ValueError(f"Prompt hash mismatch for {key}")
            seen.add(key)
            records.append(record)
    if expected_count > 0 and len(records) != expected_count:
        raise ValueError(f"Expected {expected_count} prompts in {path}, found {len(records)}")
    return records


def load_llm_config(
    path: Path,
    *,
    model: str,
    base_url: str,
    temperature: float,
    timeout: Optional[float],
    retries: Optional[int],
) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    llm = config.get("llm")
    if not isinstance(llm, dict):
        raise ValueError(f"Invalid LLM config: {path}")
    llm = dict(llm)
    llm["model"] = model
    llm["temperature"] = temperature
    if base_url:
        llm["base_url"] = base_url
    if timeout is not None:
        llm["timeout"] = timeout
    if retries is not None:
        llm["max_retries"] = retries
    missing = [name for name in ("api_key", "model", "base_url") if not llm.get(name)]
    if missing:
        raise ValueError(f"LLM config is missing: {', '.join(missing)}")
    return llm


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def parse_raw_only_response(text: str) -> Tuple[bool, str]:
    raw = _strip_code_fence(text or "")
    candidates = [raw]
    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        for field in ("is_api_bug", "result"):
            value = payload.get(field)
            if isinstance(value, bool):
                reason = payload.get("reason", "")
                return value, " ".join(str(reason).split())[:300]
            if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
                reason = payload.get("reason", "")
                return value.strip().lower() == "true", " ".join(str(reason).split())[:300]
    bool_match = re.search(
        r'["\']?(?:is_api_bug|result)["\']?\s*:\s*["\']?(true|false)["\']?',
        raw,
        flags=re.IGNORECASE,
    )
    if bool_match:
        return bool_match.group(1).lower() == "true", ""
    if raw.strip().lower() in {"true", "false"}:
        return raw.strip().lower() == "true", ""
    raise ValueError(f"Could not parse a boolean decision from response: {raw[:300]!r}")


def _openai_compatible_request(
    prompt: str,
    llm: Mapping[str, Any],
    *,
    force_json_response_format: bool,
) -> str:
    url = f"{str(llm['base_url']).rstrip('/')}/chat/completions"
    payload: Dict[str, Any] = {
        "model": llm["model"],
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a strict JSON generator. Return exactly one JSON "
                    "object with a boolean is_api_bug field."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": float(llm.get("temperature", 0.0)),
        "max_tokens": int(llm.get("max_tokens") or 128),
    }
    if force_json_response_format:
        payload["response_format"] = {"type": "json_object"}
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {llm['api_key']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(
            request,
            timeout=float(llm.get("timeout", 300)),
        ) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed: {exc.reason}") from exc
    data = json.loads(raw)
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM response has no choices: {raw[:500]}")
    content = (choices[0].get("message") or {}).get("content")
    if content is None:
        raise RuntimeError(f"LLM response has no message content: {raw[:500]}")
    return str(content)


def call_raw_only(
    prompt: str,
    llm: Mapping[str, Any],
    *,
    force_json_response_format: bool,
) -> Tuple[Optional[bool], str, str, int, int, str]:
    started = time.time()
    attempts = max(1, int(llm.get("max_retries", 3)))
    last_error = ""
    last_response = ""
    for attempt in range(1, attempts + 1):
        try:
            last_response = _openai_compatible_request(
                prompt,
                llm,
                force_json_response_format=force_json_response_format,
            )
            result, reason = parse_raw_only_response(last_response)
            return (
                result,
                reason,
                "ok",
                int((time.time() - started) * 1000),
                attempt,
                last_response,
            )
        except Exception as exc:  # noqa: BLE001 - batch runner must record failures
            last_error = str(exc)
            if attempt < attempts:
                time.sleep(min(2 * attempt, 10))
    status = "parse_error" if "Could not parse" in last_error else "api_error"
    return (
        None,
        last_error[:500] or status,
        status,
        int((time.time() - started) * 1000),
        attempts,
        last_response,
    )


def _result_record(
    record: Mapping[str, Any],
    llm: Mapping[str, Any],
    *,
    result: Optional[bool],
    reason: str,
    status: str,
    latency_ms: int,
    network_calls: int,
    raw_response: str,
    force_json_response_format: bool,
) -> Dict[str, Any]:
    return {
        "Project": record["project"],
        "CrashID": record["crash_id"],
        "Driver": record["driver"],
        "LLMName": "raw-only-baseline",
        "LLMModel": llm["model"],
        "LLMBaseURL": str(llm["base_url"]).rstrip("/"),
        "Temperature": llm.get("temperature", 0),
        "Result": "" if result is None else str(result).lower(),
        "Reason": reason,
        "Status": status,
        "PromptSHA256": record["prompt_sha256"],
        "PromptChars": record["prompt_chars"],
        "RawReportChars": record["raw_report_chars"],
        "LatencyMs": latency_ms,
        "NetworkCalls": network_calls,
        "EvidenceVariant": EVIDENCE_VARIANT,
        "PromptVariant": PROMPT_VARIANT,
        "RawResponse": raw_response,
        "ForceJSONResponseFormat": str(force_json_response_format).lower(),
    }


def _load_completed(
    path: Path,
    *,
    prompts_by_key: Mapping[Tuple[str, str], Mapping[str, Any]],
    llm: Mapping[str, Any],
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    completed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if not path.exists():
        return completed
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("Status") != "ok":
                continue
            key = (row.get("Project", ""), row.get("CrashID", ""))
            expected = prompts_by_key.get(key)
            if expected is None:
                raise ValueError(f"Existing result contains unknown crash: {key}")
            if row.get("LLMModel") != llm["model"]:
                raise ValueError(
                    f"Existing result model mismatch for {key}: "
                    f"{row.get('LLMModel')} != {llm['model']}"
                )
            if row.get("PromptSHA256") != expected["prompt_sha256"]:
                raise ValueError(f"Existing result prompt mismatch for {key}")
            if row.get("Temperature") not in (llm.get("temperature"), str(llm.get("temperature"))):
                raise ValueError(f"Existing result temperature mismatch for {key}")
            previous = completed.get(key)
            if previous is not None and previous.get("Result") != row.get("Result"):
                raise ValueError(f"Conflicting completed results for {key}")
            completed[key] = row
    return completed


def _write_results_csv(jsonl_path: Path, csv_path: Path) -> int:
    rows = []
    with jsonl_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    ok_rows = [row for row in rows if row.get("Status") == "ok"]
    _write_csv(
        csv_path,
        RESULT_FIELDS,
        ({field: row.get(field, "") for field in RESULT_FIELDS} for row in ok_rows),
    )
    return len(ok_rows)


def run_baseline(
    *,
    prepared_dir: Path,
    output_dir: Path,
    llm_config: Path,
    model: str,
    base_url: str,
    temperature: float,
    timeout: Optional[float],
    retries: Optional[int],
    workers: int,
    expected_count: int,
    resume: bool,
    dry_run: bool,
    force_json_response_format: bool,
) -> List[Dict[str, Any]]:
    records = load_prompt_records(prepared_dir / "prompts.jsonl", expected_count)
    prompts_by_key = {
        (record["project"], record["crash_id"]): record for record in records
    }
    llm = load_llm_config(
        llm_config,
        model=model,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        retries=retries,
    )
    if dry_run:
        print(f"Validated {len(records)} raw-only prompts from {prepared_dir}")
        print(f"ConfiguredModel={llm['model']}")
        print(f"Temperature={llm['temperature']}")
        print("Dry run completed without model calls.")
        return []
    if workers < 1:
        raise ValueError("--workers must be at least 1")

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "llm_bool_results.jsonl"
    csv_path = output_dir / "llm_bool_results.csv"
    completed = _load_completed(
        jsonl_path,
        prompts_by_key=prompts_by_key,
        llm=llm,
    ) if resume else {}
    if not resume and jsonl_path.exists():
        raise FileExistsError(
            f"{jsonl_path} already exists; use --resume or choose a new output directory"
        )
    pending = [
        record for record in records
        if (record["project"], record["crash_id"]) not in completed
    ]
    print(
        f"pending={len(pending)} completed={len(completed)} model={llm['model']}"
    )
    with jsonl_path.open("a", encoding="utf-8") as output_handle:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    call_raw_only,
                    record["prompt"],
                    llm,
                    force_json_response_format=force_json_response_format,
                ): record
                for record in pending
            }
            finished = 0
            for future in as_completed(futures):
                record = futures[future]
                try:
                    result, reason, status, latency_ms, network_calls, raw_response = (
                        future.result()
                    )
                except Exception as exc:  # noqa: BLE001
                    result = None
                    reason = str(exc)
                    status = "api_error"
                    latency_ms = 0
                    network_calls = 0
                    raw_response = ""
                row = _result_record(
                    record,
                    llm,
                    result=result,
                    reason=reason,
                    status=status,
                    latency_ms=latency_ms,
                    network_calls=network_calls,
                    raw_response=raw_response,
                    force_json_response_format=force_json_response_format,
                )
                output_handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                output_handle.flush()
                finished += 1
                print(
                    f"{finished}/{len(pending)} "
                    f"{record['project']}/{record['crash_id']} -> "
                    f"{row['Result'] or row['Status']}"
                )
    ok_count = _write_results_csv(jsonl_path, csv_path)
    if ok_count != len(records):
        raise RuntimeError(
            f"Raw-only baseline has {ok_count}/{len(records)} successful decisions; "
            "rerun with --resume after inspecting parse/API errors"
        )
    metric = evaluate_run(records, csv_path, prepared_dir / "manifest_1217.csv")
    _write_csv(output_dir / "metrics.csv", list(metric), [metric])
    _write_csv(output_dir / "raw_only_summary.csv", list(metric), [metric])
    return [metric]


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def evaluate_run(
    prompt_records: Sequence[Mapping[str, Any]],
    results_csv: Path,
    label_manifest: Path,
) -> Dict[str, Any]:
    labels = {
        (row["Project"], row["CrashID"]): row
        for row in _read_csv(label_manifest)
    }
    expected_keys = {(record["project"], record["crash_id"]) for record in prompt_records}
    results = {}
    latencies = []
    network_calls = 0
    for row in _read_csv(results_csv):
        key = (row["Project"], row["CrashID"])
        if row.get("Status") != "ok":
            continue
        if key in results:
            raise ValueError(f"Duplicate successful result for {key}")
        results[key] = row
        latencies.append(float(row["LatencyMs"]))
        network_calls += int(row.get("NetworkCalls") or 0)
    missing = sorted(expected_keys.difference(results))
    extra = sorted(set(results).difference(expected_keys))
    if missing or extra:
        raise ValueError(
            f"Result coverage mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    tp = fp = tn = fn = 0
    for key, row in results.items():
        if key not in labels:
            raise ValueError(f"Missing ground truth for {key}")
        predicted = _truth(row["Result"])
        expected = _truth(labels[key]["GroundTruth"])
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
        "Method": "Raw-only LLM",
        "Samples": len(results),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "PrimaryLLMSubmissions": len(prompt_records),
        "NetworkCalls": network_calls,
        "MeanLatencySeconds": statistics.mean(latencies) / 1000 if latencies else 0.0,
        "MedianLatencySeconds": statistics.median(latencies) / 1000 if latencies else 0.0,
        "P95LatencySeconds": _percentile(latencies, 0.95) / 1000 if latencies else 0.0,
    }


def write_comparison(
    *,
    prepared_dir: Path,
    output_dir: Path,
    v4_metrics_path: Path,
    crashsage_submissions: int,
) -> None:
    summary_rows = _read_csv(output_dir / "raw_only_summary.csv")
    if len(summary_rows) != 1:
        raise ValueError("Expected one raw-only summary row")
    raw = summary_rows[0]
    v4_rows = [
        row
        for row in _read_csv(v4_metrics_path)
        if row.get("Variant") == "V4" and row.get("Population") == "all_1217"
    ]
    if len(v4_rows) != 1:
        raise ValueError(f"Expected one V4 all_1217 row in {v4_metrics_path}")
    v4 = v4_rows[0]
    comparison = [
        {
            "Method": "Raw-only LLM",
            "Samples": "1217",
            "PrimaryLLMSubmissions": "1217",
            "Precision": f"{float(raw['Precision']):.4f}",
            "Recall": f"{float(raw['Recall']):.4f}",
            "F1": f"{float(raw['F1']):.4f}",
            "MeanLLMLatencySeconds": f"{float(raw['MeanLatencySeconds']):.2f}",
        },
        {
            "Method": "CrashSage",
            "Samples": "1217",
            "PrimaryLLMSubmissions": str(crashsage_submissions),
            "Precision": f"{float(v4['Precision']):.4f}",
            "Recall": f"{float(v4['Recall']):.4f}",
            "F1": f"{float(v4['F1']):.4f}",
            "MeanLLMLatencySeconds": "",
        },
    ]
    fields = list(comparison[0])
    _write_csv(output_dir / "raw_only_vs_crashsage.csv", fields, comparison)
    markdown = [
        "# Raw-only LLM baseline vs CrashSage",
        "",
        "| Method | Samples | Primary LLM submissions | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in comparison:
        markdown.append(
            f"| {row['Method']} | {row['Samples']} | "
            f"{row['PrimaryLLMSubmissions']} | {row['Precision']} | "
            f"{row['Recall']} | {row['F1']} |"
        )
    markdown.extend([
        "",
        "Raw-only is a single full-population baseline run. The CrashSage anchor "
        "is read from the formal V4 all-1217 metrics file.",
        "",
        f"- V4 source: `{v4_metrics_path}`",
        f"- Prompt bundle: `{prepared_dir / 'prompts.jsonl'}`",
    ])
    (output_dir / "raw_only_vs_crashsage.md").write_text(
        "\n".join(markdown) + "\n",
        encoding="utf-8",
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Build the frozen raw-only prompt bundle")
    prepare.add_argument("--label-manifest", type=Path, default=DEFAULT_LABEL_MANIFEST)
    prepare.add_argument("--db-root", type=Path, default=DEFAULT_DB_ROOT)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--expected-count", type=int, default=DEFAULT_EXPECTED_COUNT)
    prepare.add_argument("--overwrite", action="store_true")

    run = subparsers.add_parser("run", help="Run and summarize the raw-only baseline")
    run.add_argument("--prepared-dir", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument(
        "--llm-config",
        type=Path,
        default=Path("configs/external_bool_adjudication.yaml"),
    )
    run.add_argument("--model", default=DEFAULT_MODEL)
    run.add_argument("--base-url", default="")
    run.add_argument("--temperature", type=float, default=0.0)
    run.add_argument("--timeout", type=float, default=None)
    run.add_argument("--retries", type=_positive_int, default=None)
    run.add_argument("--workers", type=_positive_int, default=8)
    run.add_argument("--expected-count", type=int, default=DEFAULT_EXPECTED_COUNT)
    run.add_argument("--no-resume", action="store_true")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--json-response-format", action="store_true")

    metrics = subparsers.add_parser("metrics", help="Recompute raw-only metrics and compare with V4")
    metrics.add_argument("--prepared-dir", type=Path, required=True)
    metrics.add_argument("--output-dir", type=Path, required=True)
    metrics.add_argument("--v4-metrics", type=Path, default=DEFAULT_V4_METRICS)
    metrics.add_argument("--crashsage-submissions", type=int, default=96)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "prepare":
        summary = prepare_bundle(
            label_manifest=args.label_manifest,
            db_root=args.db_root,
            output_dir=args.output_dir,
            expected_count=args.expected_count,
            overwrite=args.overwrite,
        )
        print(f"Prepared {summary['count']} raw-only prompts in {args.output_dir}")
        print(f"Positive={summary['positive_labels']} Negative={summary['negative_labels']}")
        print(f"Prompt corpus SHA256={summary['prompt_corpus_sha256']}")
        return 0

    if args.command == "metrics":
        records = load_prompt_records(
            args.prepared_dir / "prompts.jsonl",
            DEFAULT_EXPECTED_COUNT,
        )
        result_csv = args.output_dir / "llm_bool_results.csv"
        if not result_csv.exists():
            raise FileNotFoundError(result_csv)
        metric = evaluate_run(
            records,
            result_csv,
            args.prepared_dir / "manifest_1217.csv",
        )
        _write_csv(args.output_dir / "metrics.csv", list(metric), [metric])
        _write_csv(args.output_dir / "raw_only_summary.csv", list(metric), [metric])
        write_comparison(
            prepared_dir=args.prepared_dir,
            output_dir=args.output_dir,
            v4_metrics_path=args.v4_metrics,
            crashsage_submissions=args.crashsage_submissions,
        )
        print(f"Wrote raw-only metrics to {args.output_dir}")
        return 0

    run_metrics = run_baseline(
        prepared_dir=args.prepared_dir,
        output_dir=args.output_dir,
        llm_config=args.llm_config,
        model=args.model,
        base_url=args.base_url,
        temperature=args.temperature,
        timeout=args.timeout,
        retries=args.retries,
        workers=args.workers,
        expected_count=args.expected_count,
        resume=not args.no_resume,
        dry_run=args.dry_run,
        force_json_response_format=args.json_response_format,
    )
    if run_metrics:
        write_comparison(
            prepared_dir=args.prepared_dir,
            output_dir=args.output_dir,
            v4_metrics_path=DEFAULT_V4_METRICS,
            crashsage_submissions=96,
        )
        print(f"Completed raw-only baseline in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
