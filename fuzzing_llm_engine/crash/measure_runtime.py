"""Measure CrashSage runtime without invoking an LLM.

The command has two deliberately separate phases:

* ``measure-base`` times sanitizer parsing, rule-guided attribution, and
  representative selection over the report population.
* ``summarize`` combines those measurements with instrumented context-replay
  results and previously recorded LLM latencies.

Context replay is kept out of this module so that expensive Docker/GDB runs
can be resumed and audited independently.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .dedup import DeduplicationEngine
from .external_bool_adjudication import (
    build_evidence_package,
    build_prompt,
    load_crash_entry,
)
from .sanitizer_parser import parse_sanitizer_output
from .triage import triage_crash


_BASE_FIELDS = [
    "Project",
    "CrashID",
    "Driver",
    "Stage",
    "ElapsedMs",
    "Status",
    "Extra",
]
_SUMMARY_FIELDS = [
    "Stage",
    "Scope",
    "Invocations",
    "Succeeded",
    "Failed",
    "SuccessRate",
    "MedianMs",
    "P95Ms",
    "TotalSeconds",
]


def _engine_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else _engine_root() / candidate


def _elapsed_ms(start_ns: int) -> float:
    return round((time.perf_counter_ns() - start_ns) / 1_000_000, 6)


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _load_unique_reports(path: Path) -> List[Dict[str, str]]:
    """Prefer a successful row when an input log contains retries."""
    selected: Dict[Tuple[str, str], Dict[str, str]] = {}
    for row in _read_csv(path):
        project = str(row.get("Project") or "").strip()
        crash_id = str(row.get("CrashID") or "").strip()
        if not project or not crash_id:
            continue
        key = (project, crash_id)
        existing = selected.get(key)
        if existing is None or (
            existing.get("Status") not in {"", "ok"}
            and row.get("Status") == "ok"
        ):
            selected[key] = row
    return list(selected.values())


def _project_driver_index(db_root: Path, projects: Iterable[str]) -> Dict[Tuple[str, str], str]:
    index: Dict[Tuple[str, str], str] = {}
    for project in sorted(set(projects)):
        crash_root = db_root / project / "crash"
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
                for local_id in item:
                    index[(project, f"{driver_dir.name}_{local_id}")] = driver_dir.name
    return index


def _record_index(
    db_root: Path,
    driver_index: Dict[Tuple[str, str], str],
) -> Dict[Tuple[str, str], Tuple[Dict[str, Any], str]]:
    by_yaml: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    result: Dict[Tuple[str, str], Tuple[Dict[str, Any], str]] = {}
    for (project, crash_id), driver in driver_index.items():
        key = (project, driver)
        if key not in by_yaml:
            path = db_root / project / "crash" / driver / "crash_analysis.yaml"
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            by_yaml[key] = data if isinstance(data, list) else []
        local_id = crash_id[len(driver) + 1 :]
        for item in by_yaml[key]:
            if isinstance(item, dict) and local_id in item:
                result[(project, crash_id)] = (item[local_id], driver)
                break
    return result


def measure_base(args: argparse.Namespace) -> int:
    reports_csv = _resolve(args.reports_csv)
    db_root = _resolve(args.db_root)
    output = _resolve(args.output)
    rows = _load_unique_reports(reports_csv)
    if args.limit:
        rows = rows[: args.limit]

    driver_index = _project_driver_index(
        db_root,
        (row["Project"] for row in rows),
    )
    records = _record_index(db_root, driver_index)
    missing = [
        (row["Project"], row["CrashID"])
        for row in rows
        if (row["Project"], row["CrashID"]) not in records
    ]
    if missing:
        raise ValueError(
            f"{len(missing)} input reports are missing from the database; "
            f"first missing key: {missing[0]}"
        )

    dedup = DeduplicationEngine()
    measurements: List[Dict[str, Any]] = []
    retained_reports = 0
    started = time.perf_counter_ns()
    for position, row in enumerate(rows, 1):
        project = row["Project"]
        crash_id = row["CrashID"]
        entry, driver = records[(project, crash_id)]
        crash_info = str(entry.get("crash_info") or "")
        if crash_info.startswith("|"):
            crash_info = crash_info[1:].lstrip("\n")

        parse_started = time.perf_counter_ns()
        parsed = parse_sanitizer_output(crash_info)
        parse_ms = _elapsed_ms(parse_started)
        measurements.append({
            "Project": project,
            "CrashID": crash_id,
            "Driver": driver,
            "Stage": "sanitizer_parse",
            "ElapsedMs": parse_ms,
            "Status": "success" if parsed.get("frames") else "no_stack",
            "Extra": parsed.get("bug_type") or "",
        })

        triage_started = time.perf_counter_ns()
        triage = triage_crash(parsed, fuzz_driver_basename=f"{driver}.cc")
        triage_ms = _elapsed_ms(triage_started)
        measurements.append({
            "Project": project,
            "CrashID": crash_id,
            "Driver": driver,
            "Stage": "rule_guided_attribution",
            "ElapsedMs": triage_ms,
            "Status": "success",
            "Extra": triage.get("label") or "",
        })

        if row.get("RepresentativeCrashID"):
            retained_reports += 1
            dedup_started = time.perf_counter_ns()
            dedup_result = dedup.add_crash(
                crash_id,
                triage,
                parsed,
                discovery_index=position,
            )
            dedup_ms = _elapsed_ms(dedup_started)
            measurements.append({
                "Project": project,
                "CrashID": crash_id,
                "Driver": driver,
                "Stage": "representative_selection",
                "ElapsedMs": dedup_ms,
                "Status": "success",
                "Extra": (
                    "duplicate"
                    if dedup_result.get("is_duplicate")
                    else "representative"
                ),
            })
        if position % 100 == 0 or position == len(rows):
            print(f"base stages: {position}/{len(rows)}")

    _write_csv(output, _BASE_FIELDS, measurements)
    stats = dedup.get_dedup_stats()
    metadata = {
        "input": str(reports_csv),
        "db_root": str(db_root),
        "reports": len(rows),
        "retained_reports": retained_reports,
        "representatives": len(dedup.get_representatives()),
        "dedup_stats": stats,
        "wall_clock_ms": _elapsed_ms(started),
        "generated_at": datetime.now().isoformat(),
    }
    output.with_suffix(".summary.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"measured {len(rows)} reports -> {len(dedup.get_representatives())} "
        f"representatives in {metadata['wall_clock_ms'] / 1000:.3f}s"
    )
    return 0


def measure_prompts(args: argparse.Namespace) -> int:
    """Build the final evidence package and prompt without calling an LLM."""
    manifest = _resolve(args.manifest)
    db_root = _resolve(args.db_root)
    output = _resolve(args.output)
    rows = _read_csv(manifest)
    measurements: List[Dict[str, Any]] = []
    for position, row in enumerate(rows, 1):
        project = row["Project"]
        crash_id = row["CrashID"]
        driver = row["Driver"]
        total_started = time.perf_counter_ns()

        evidence_started = time.perf_counter_ns()
        entry, driver_dir, _ = load_crash_entry(
            str(db_root),
            project,
            driver,
            crash_id,
        )
        evidence, _fields = build_evidence_package(
            row,
            entry,
            driver_dir,
            include_static_context=True,
            include_runtime_context=True,
        )
        evidence_ms = _elapsed_ms(evidence_started)

        prompt_started = time.perf_counter_ns()
        prompt = build_prompt(
            evidence,
            args.max_prompt_chars,
            prompt_variant="differential",
        )
        prompt_ms = _elapsed_ms(prompt_started)
        total_ms = _elapsed_ms(total_started)
        for stage, elapsed, extra in (
            ("evidence_package_construction", evidence_ms, ""),
            ("prompt_serialization", prompt_ms, str(len(prompt))),
            ("total_prompt_construction", total_ms, str(len(prompt))),
        ):
            measurements.append({
                "Project": project,
                "CrashID": crash_id,
                "Driver": driver,
                "Stage": stage,
                "ElapsedMs": elapsed,
                "Status": "success",
                "Extra": extra,
            })
        if position % 20 == 0 or position == len(rows):
            print(f"prompt construction: {position}/{len(rows)}")

    _write_csv(output, _BASE_FIELDS, measurements)
    print(f"measured {len(rows)} prompts -> {output}")
    return 0


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[min(rank, len(ordered) - 1)]


def _summaries(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["Stage"]), str(row.get("Scope") or ""))].append(row)
    result = []
    for (stage, scope), group in sorted(grouped.items()):
        values = [
            float(row["ElapsedMs"])
            for row in group
            if row.get("ElapsedMs") not in {"", None}
        ]
        succeeded = sum(row.get("Status") == "success" for row in group)
        result.append({
            "Stage": stage,
            "Scope": scope,
            "Invocations": len(group),
            "Succeeded": succeeded,
            "Failed": len(group) - succeeded,
            "SuccessRate": f"{succeeded / len(group):.4f}" if group else "0.0000",
            "MedianMs": f"{statistics.median(values):.3f}" if values else "0.000",
            "P95Ms": f"{_percentile(values, 0.95):.3f}" if values else "0.000",
            "TotalSeconds": f"{sum(values) / 1000:.3f}",
        })
    return result


def _status_summaries(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(
            str(row["Stage"]),
            str(row.get("Scope") or ""),
            str(row.get("Status") or ""),
        )].append(row)
    result = []
    for (stage, scope, status), group in sorted(grouped.items()):
        values = [float(row["ElapsedMs"]) for row in group]
        result.append({
            "Stage": stage,
            "Scope": scope,
            "Status": status,
            "Invocations": len(group),
            "MedianMs": f"{statistics.median(values):.3f}",
            "P95Ms": f"{_percentile(values, 0.95):.3f}",
            "TotalSeconds": f"{sum(values) / 1000:.3f}",
        })
    return result


def _llm_latencies(path: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    result: Dict[Tuple[str, str], Dict[str, str]] = {}
    files = sorted(path.glob("chunk_*/llm_bool_results.csv"))
    if not files and path.is_file():
        files = [path]
    for file_path in files:
        for row in _read_csv(file_path):
            if row.get("Status") != "ok" or not row.get("LatencyMs"):
                continue
            result[(row["Project"], row["CrashID"])] = row
    return result


def _prompt_totals(path: Path) -> Dict[Tuple[str, str], float]:
    result: Dict[Tuple[str, str], float] = {}
    for row in _read_csv(path):
        if row.get("Stage") != "total_prompt_construction":
            continue
        key = (row["Project"], row["CrashID"])
        result[key] = float(row["ElapsedMs"])
    return result


def summarize(args: argparse.Namespace) -> int:
    base_path = _resolve(args.base)
    prompt_path = _resolve(args.prompts)
    context_dir = _resolve(args.context_dir)
    output_dir = _resolve(args.output_dir)
    llm_dir = _resolve(args.llm_results)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_rows: List[Dict[str, Any]] = []
    for row in _read_csv(base_path):
        all_rows.append({**row, "Scope": "report"})
    for row in _read_csv(prompt_path):
        all_rows.append({**row, "Scope": "representative"})

    context_rows: List[Dict[str, Any]] = []
    end_to_end: List[Dict[str, Any]] = []
    llm = _llm_latencies(llm_dir)
    prompts = _prompt_totals(prompt_path)
    for path in sorted(context_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        project = str(data.get("project") or "")
        crash_id = str(data.get("crash_id") or "")
        timings = data.get("measurement_timings_ms") or {}
        runtime_attempt = data.get("runtime_context_attempt") or {}
        status_by_stage = {
            "record_lookup": "success",
            "sanitizer_parse": "success",
            "static_context": (
                "success"
                if (data.get("static_context") or {}).get("status") == "available"
                else "failed"
            ),
            "seed_and_binary_resolution": (
                "success" if data.get("binary") and data.get("poc") else "failed"
            ),
            "direct_replay": (
                "success"
                if int((data.get("direct_replay") or {}).get("consistent") or 0) > 0
                else "failed"
            ),
            "gdb_runtime_collection": (
                "success" if runtime_attempt.get("reproduced") else "failed"
            ),
            "runtime_validation": (
                "success"
                if (data.get("runtime_status") or {}).get("status") == "available"
                else "failed"
            ),
            "total_context_replay": "success",
        }
        for stage, elapsed in timings.items():
            row = {
                "Project": project,
                "CrashID": crash_id,
                "Driver": data.get("driver") or "",
                "Stage": stage,
                "ElapsedMs": elapsed,
                "Status": status_by_stage.get(stage, "success"),
                "Extra": data.get("runtime_source") or "",
                "Scope": "representative",
            }
            context_rows.append(row)
            all_rows.append(row)

        llm_row = llm.get((project, crash_id))
        llm_ms = float(llm_row["LatencyMs"]) if llm_row else None
        context_ms = float(timings.get("total_context_replay") or 0)
        prompt_ms = prompts.get((project, crash_id))
        end_to_end_ms = (
            context_ms + prompt_ms + llm_ms
            if prompt_ms is not None and llm_ms is not None
            else None
        )
        end_to_end.append({
            "Project": project,
            "CrashID": crash_id,
            "ContextMs": f"{context_ms:.3f}",
            "LLMStatus": llm_row.get("Status", "missing") if llm_row else "missing",
            "LLMLatencyMs": f"{llm_ms:.3f}" if llm_ms is not None else "",
            "ContextPlusLLMMs": f"{context_ms + llm_ms:.3f}" if llm_ms is not None else "",
            "PromptMs": f"{prompt_ms:.3f}" if prompt_ms is not None else "",
            "EndToEndMs": f"{end_to_end_ms:.3f}" if end_to_end_ms is not None else "",
            "RuntimeSource": data.get("runtime_source") or "",
            "RuntimeStatus": (data.get("runtime_status") or {}).get("status") or "",
        })
        if llm_row:
            all_rows.append({
                "Project": project,
                "CrashID": crash_id,
                "Driver": data.get("driver") or "",
                "Stage": "llm_analysis",
                "ElapsedMs": llm_ms,
                "Status": "success",
                "Extra": llm_row.get("LLMModel") or "",
                "Scope": "representative",
            })

    _write_csv(output_dir / "runtime_timing.csv", [
        "Project", "CrashID", "Driver", "Stage", "ElapsedMs", "Status", "Extra", "Scope",
    ], all_rows)
    _write_csv(output_dir / "runtime_stage_summary.csv", _SUMMARY_FIELDS, _summaries(all_rows))
    _write_csv(output_dir / "runtime_status_breakdown.csv", [
        "Stage", "Scope", "Status", "Invocations",
        "MedianMs", "P95Ms", "TotalSeconds",
    ], _status_summaries(all_rows))
    _write_csv(output_dir / "runtime_end_to_end.csv", [
        "Project", "CrashID", "ContextMs", "LLMStatus", "LLMLatencyMs",
        "ContextPlusLLMMs", "PromptMs", "EndToEndMs",
        "RuntimeSource", "RuntimeStatus",
    ], end_to_end)
    project_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in end_to_end:
        project_groups[str(row["Project"])].append(row)
    project_summary = []
    for project, group in sorted(project_groups.items()):
        context_values = [float(row["ContextMs"]) for row in group]
        end_to_end_values = [
            float(row["EndToEndMs"])
            for row in group
            if row.get("EndToEndMs")
        ]
        project_summary.append({
            "Project": project,
            "Representatives": len(group),
            "RuntimeAvailable": sum(row["RuntimeStatus"] == "available" for row in group),
            "RuntimeFresh": sum(row["RuntimeSource"] == "fresh" for row in group),
            "RuntimeHistorical": sum(row["RuntimeSource"] == "historical" for row in group),
            "ContextMedianMs": f"{statistics.median(context_values):.3f}",
            "ContextP95Ms": f"{_percentile(context_values, 0.95):.3f}",
            "EndToEndMedianMs": (
                f"{statistics.median(end_to_end_values):.3f}"
                if end_to_end_values
                else ""
            ),
            "EndToEndP95Ms": (
                f"{_percentile(end_to_end_values, 0.95):.3f}"
                if end_to_end_values
                else ""
            ),
        })
    _write_csv(output_dir / "runtime_project_summary.csv", [
        "Project", "Representatives", "RuntimeAvailable", "RuntimeFresh",
        "RuntimeHistorical", "ContextMedianMs", "ContextP95Ms",
        "EndToEndMedianMs", "EndToEndP95Ms",
    ], project_summary)
    context_outcomes = {
        "processed": len(end_to_end),
        "runtime_available": sum(row["RuntimeStatus"] == "available" for row in end_to_end),
        "runtime_fresh": sum(row["RuntimeSource"] == "fresh" for row in end_to_end),
        "runtime_historical": sum(row["RuntimeSource"] == "historical" for row in end_to_end),
        "runtime_unavailable": sum(row["RuntimeStatus"] != "available" for row in end_to_end),
    }
    _write_csv(
        output_dir / "runtime_outcome_summary.csv",
        list(context_outcomes),
        [context_outcomes],
    )
    metadata = {
        "base_measurement": str(base_path),
        "context_results": str(context_dir),
        "llm_results": str(llm_dir),
        "reports": sum(row["Scope"] == "report" and row["Stage"] == "sanitizer_parse" for row in all_rows),
        "context_representatives": len(end_to_end),
        "llm_joined": sum(bool(row["LLMLatencyMs"]) for row in end_to_end),
        "prompt_joined": sum(bool(row["PromptMs"]) for row in end_to_end),
        "llm_calls_made_by_this_measurement": 0,
        "generated_at": datetime.now().isoformat(),
    }
    (output_dir / "runtime_measurement_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    base = subparsers.add_parser("measure-base")
    base.add_argument(
        "--reports-csv",
        default="results/dedup_schema2_14projects_20261027/final_v4_expanded_1217.csv",
    )
    base.add_argument("--db-root", default="external_database")
    base.add_argument(
        "--output",
        default="results/runtime_measurement_20261030/base_stage_measurements.csv",
    )
    base.add_argument("--limit", type=int, default=0)
    base.set_defaults(func=measure_base)

    prompts = subparsers.add_parser("measure-prompts")
    prompts.add_argument(
        "--manifest",
        default="results/dedup_schema2_14projects_20261027/representatives_all_14projects.csv",
    )
    prompts.add_argument("--db-root", default="external_database")
    prompts.add_argument(
        "--output",
        default="results/runtime_measurement_20261030/prompt_stage_measurements.csv",
    )
    prompts.add_argument("--max-prompt-chars", type=int, default=120000)
    prompts.set_defaults(func=measure_prompts)

    summary = subparsers.add_parser("summarize")
    summary.add_argument(
        "--base",
        default="results/runtime_measurement_20261030/base_stage_measurements.csv",
    )
    summary.add_argument(
        "--context-dir",
        default="results/runtime_measurement_20261030/context_96",
    )
    summary.add_argument(
        "--prompts",
        default="results/runtime_measurement_20261030/prompt_stage_measurements.csv",
    )
    summary.add_argument(
        "--llm-results",
        default="results/frozen_models_20261030/qwen3-coder-flash",
    )
    summary.add_argument(
        "--output-dir",
        default="results/runtime_measurement_20261030",
    )
    summary.set_defaults(func=summarize)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
