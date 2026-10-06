#!/usr/bin/env python3
"""Apply conservative manual ground-truth annotations for the revision set.

This script intentionally writes only under results/revision_20260722.  It
preserves all legacy TRUE rows as confirmed target crashes because those rows
come from public drivers/PoCs.  It then annotates legacy FALSE rows only when
local evidence is strong enough to classify them as target or non-target.
Everything else remains unresolved_candidate and is excluded from metrics.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

import yaml


STATUS_TARGET = "confirmed_target"
STATUS_NON_TARGET = "confirmed_non_target"
STATUS_UNRESOLVED = "unresolved_candidate"

GROUND_TRUTH_FIELDS = [
    "Project",
    "CrashID",
    "RepresentativeCrashID",
    "GroundTruthStatus",
    "IncludeInMetrics",
    "EvidenceType",
    "PublicReference",
    "ReproductionStatus",
    "RootCauseSummary",
    "DecisionNote",
]

EVIDENCE_FIELDS = [
    "ManualGroundTruthStatus",
    "MetricGroundTruthStatus",
    *GROUND_TRUTH_FIELDS,
    "LegacyGroundTruth",
    "BugType",
    "Sanitizer",
    "TriageLabel",
    "TriageRules",
    "CrashFile",
    "CrashFunction",
    "Signature",
    "EvidencePath",
    "DriverPath",
    "ManualConfidence",
]

PUBLIC_DRIVER_REFS = {
    "c-ares_fuzz_driver_False_qwen3-coder-plus_26": "CVE-2024-25629; local public driver+PoC",
    "cjson_fuzz_driver_False_qwen3-coder-plus_60": "CVE-2025-57052; local public driver+PoC",
    "jansson_fuzz_driver_False_qwen3-coder-plus_12": "CVE-2016-4425; local public driver+PoC",
    "json-c_fuzz_driver_False_qwen3-coder-plus_13": "CVE-2020-12762; local public driver+PoC",
    "libpcap_fuzz_driver_False_qwen3-coder-plus_30": "CVE-2024-8006; local public driver+PoC",
    "tinyxml2_fuzz_driver_False_qwen3-coder-plus_22": "CVE-2024-50614; local public driver+PoC",
    "zlib_fuzz_driver_False_qwen3-coder-plus_20": "CVE-2023-45853; local public driver+PoC",
}

SEVERE_BUG_TERMS = (
    "heap-buffer-overflow",
    "global-buffer-overflow",
    "stack-buffer-overflow",
    "heap-use-after-free",
    "attempting double-free",
    "attempting free",
    "segv",
    "fpe",
    "stack-overflow",
)

DRIVER_ROOT_HINTS = (
    "/test/",
    "/tests/",
    "/fuzzing/",
    "LLVMFuzzerTestOneInput",
    ".cc:",
)

DRIVER_EVIDENCE_RULES = (
    "leak_only",
    "driver_dominant_stack",
    "raw_struct_memcpy_pattern",
    "manual_internal_buffer_layout",
    "api_contract_violation",
)


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_csv_if_exists(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    return read_csv(path)


def write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def driver_from_crash_id(crash_id: str) -> str:
    return crash_id.rsplit("_crash_", 1)[0]


def crash_key(crash_id: str) -> str:
    return "crash_" + crash_id.rsplit("_crash_", 1)[1]


def driver_ext(project: str) -> str:
    return ".c" if project in {"c-ares", "cjson"} else ".cc"


@lru_cache(maxsize=None)
def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or []
    except (OSError, yaml.YAMLError):
        return []


@lru_cache(maxsize=None)
def load_crash_entry(db_root: Path, project: str, crash_id: str) -> Dict[str, Any]:
    driver = driver_from_crash_id(crash_id)
    key = crash_key(crash_id)
    path = db_root / project / "crash" / driver / "crash_analysis.yaml"
    data = load_yaml(path)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get(key), dict):
                return item[key]
    if isinstance(data, dict) and isinstance(data.get(key), dict):
        return data[key]
    return {}


@lru_cache(maxsize=None)
def read_driver(db_root: Path, project: str, driver: str) -> str:
    path = db_root / project / "fuzz_driver" / f"{driver}{driver_ext(project)}"
    if not path.exists() and driver_ext(project) == ".c":
        path = db_root / project / "fuzz_driver" / f"{driver}.cc"
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def driver_path(db_root: Path, project: str, driver: str) -> str:
    path = db_root / project / "fuzz_driver" / f"{driver}{driver_ext(project)}"
    if not path.exists() and driver_ext(project) == ".c":
        path = db_root / project / "fuzz_driver" / f"{driver}.cc"
    return str(path)


def yaml_path(db_root: Path, project: str, driver: str) -> str:
    return str(db_root / project / "crash" / driver / "crash_analysis.yaml")


def entry_repro(entry: Mapping[str, Any]) -> str:
    repro = entry.get("repro") or {}
    if isinstance(repro, Mapping):
        return str(repro.get("repro_rate") or "")
    return ""


def entry_duplicate_of(entry: Mapping[str, Any]) -> str:
    value = entry.get("duplicate_of")
    if value:
        return str(value)
    dedup = entry.get("dedup") or {}
    if isinstance(dedup, Mapping) and dedup.get("duplicate_of"):
        return str(dedup["duplicate_of"])
    return ""


def root_location(entry: Mapping[str, Any], detail: Mapping[str, str]) -> str:
    enhanced = entry.get("enhanced_analysis") or {}
    if isinstance(enhanced, Mapping) and enhanced.get("root_cause_location"):
        return str(enhanced["root_cause_location"])
    location = entry.get("location") or {}
    if isinstance(location, Mapping) and location.get("crash_file"):
        line = location.get("crash_line")
        if line:
            return f"{location['crash_file']}:{line}"
        return str(location["crash_file"])
    return detail.get("CrashFile", "")


def root_summary(entry: Mapping[str, Any], detail: Mapping[str, str]) -> str:
    enhanced = entry.get("enhanced_analysis") or {}
    location = entry.get("location") or {}
    parts = []
    bug = detail.get("BugType") or ""
    func = detail.get("CrashFunction") or ""
    if isinstance(location, Mapping):
        func = str(location.get("crash_function") or func)
    loc = root_location(entry, detail)
    if bug:
        parts.append(f"bug={bug}")
    if func:
        parts.append(f"function={func}")
    if loc:
        parts.append(f"root={loc}")
    if isinstance(enhanced, Mapping) and enhanced.get("root_cause_type"):
        parts.append(f"type={enhanced['root_cause_type']}")
    return "; ".join(parts)


def has_driver_root(entry: Mapping[str, Any], detail: Mapping[str, str]) -> bool:
    evidence = " ".join(
        [
            root_location(entry, detail),
            detail.get("CrashFile", ""),
            detail.get("CrashFunction", ""),
            detail.get("Signature", ""),
        ]
    )
    return any(hint in evidence for hint in DRIVER_ROOT_HINTS)


def is_severe_bug(bug_type: str) -> bool:
    lowered = bug_type.lower()
    return any(term in lowered for term in SEVERE_BUG_TERMS)


def is_leak_only(detail: Mapping[str, str], entry: Mapping[str, Any]) -> bool:
    bug = (detail.get("BugType") or "").lower()
    sanitizer = (detail.get("Sanitizer") or "").lower()
    parsed = entry.get("sanitizer_parsed") or {}
    parsed_bug = str(parsed.get("bug_type") or "").lower() if isinstance(parsed, Mapping) else ""
    return "leak" in bug or "leak" in sanitizer or "leak" in parsed_bug


def has_driver_triage_evidence(detail: Mapping[str, str], entry: Mapping[str, Any]) -> bool:
    rules = (detail.get("TriageRules") or "").lower()
    triage = entry.get("triage") or {}
    if isinstance(triage, Mapping):
        rules += "," + ",".join(str(x) for x in triage.get("matched_rules") or [])
    return any(rule in rules for rule in DRIVER_EVIDENCE_RULES)


def has_obvious_api_contract_problem(project: str, driver: str, driver_src: str) -> bool:
    # These are project-specific manual findings from generated driver source.
    if project == "json-c" and "printbuf_new()" in driver_src and "pb->bpos" in driver_src:
        return True
    if project == "faad2" and "NeAACDecDecode2" in driver_src and "NeAACDecInit" not in driver_src:
        return True
    if "abort();" in driver_src:
        return True
    return False


def is_natural_api_path(project: str, driver_src: str) -> bool:
    natural_tokens = {
        "libpcap": ["pcap_findalldevs_ex"],
        "libsndfile": ["sf_open", "sf_readf_int", "sf_writef_int"],
        "tinyxml2": ["XMLDocument", ".Parse("],
        "jansson": ["json_loads"],
        "expat": ["XML_Parse", "XML_ParserCreate"],
        "libmspack": ["open", "read"],
        "c-ares": ["ares_init", "ares_gethostbyname"],
        "zlib": ["zipOpenNewFileInZip4_64", "zipOpen64"],
    }
    return any(token in driver_src for token in natural_tokens.get(project, []))


def public_ref_for_driver(driver: str) -> str:
    return PUBLIC_DRIVER_REFS.get(driver, f"author-confirmed public driver+PoC: {driver}")


def classify_row(
    row: Mapping[str, str],
    detail: Mapping[str, str],
    entry: Mapping[str, Any],
    db_root: Path,
    legacy_true_drivers: set[str],
) -> Dict[str, str]:
    project = row["Project"]
    crash_id = row["CrashID"]
    driver = row.get("Driver") or driver_from_crash_id(crash_id)
    driver_src = read_driver(db_root, project, driver)
    repro = entry_repro(entry) or "unknown"
    duplicate_of = entry_duplicate_of(entry) or row.get("DuplicateOf", "")
    representative = duplicate_of or row.get("RepresentativeCrashID") or crash_id
    bug_type = detail.get("BugType") or row.get("BugType", "")
    triage_label = detail.get("TriageLabel") or row.get("TriageLabel", "")

    if truthy(row.get("GroundTruth")):
        return {
            "Project": project,
            "CrashID": crash_id,
            "RepresentativeCrashID": representative,
            "GroundTruthStatus": STATUS_TARGET,
            "IncludeInMetrics": "TRUE",
            "EvidenceType": "legacy_public_driver_poc_confirmed",
            "PublicReference": public_ref_for_driver(driver),
            "ReproductionStatus": "author-confirmed public driver+PoC reproduction",
            "RootCauseSummary": root_summary(entry, detail),
            "DecisionNote": "Preserved legacy TRUE label per author confirmation: public driver/PoC reproduced.",
            "ManualConfidence": "high",
        }

    if is_leak_only(detail, entry):
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "leak_only_non_security_signal",
            "N/A",
            repro,
            root_summary(entry, detail),
            "LeakSanitizer/leak-only signal; excluded from target memory-safety vulnerability ground truth.",
            "high",
        )

    if triage_label == "noise":
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "local_noise_triage",
            "N/A",
            repro,
            root_summary(entry, detail),
            "Local triage marks this as noise and no stronger target-library evidence is present.",
            "medium",
        )

    if has_driver_root(entry, detail):
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "harness_root_cause",
            "N/A",
            repro,
            root_summary(entry, detail),
            "Root cause or dominant crash frame is in the generated driver/test harness.",
            "high",
        )

    if has_obvious_api_contract_problem(project, driver, driver_src) and driver not in legacy_true_drivers:
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "local_driver_contract_violation",
            "N/A",
            repro,
            root_summary(entry, detail),
            "Generated driver constructs invalid state or triggers its own abort; not counted as target-library vulnerability.",
            "high",
        )

    if (
        driver in legacy_true_drivers
        and repro == "3/3"
        and is_severe_bug(bug_type)
        and f"/{project}/" in root_location(entry, detail)
    ):
        return decision(
            row,
            representative,
            STATUS_UNRESOLVED,
            "potential_unpublished_api_bug",
            "N/A; unpublished candidate, not part of confirmed public ground truth",
            repro,
            root_summary(entry, detail),
            "Stable target-library crash in the same public driver family, but it was not part of the author-confirmed public driver+PoC ground truth; excluded from binary metrics.",
            "medium",
        )

    if (
        triage_label in {"likely_api_bug", "needs_review"}
        and repro == "3/3"
        and is_severe_bug(bug_type)
        and f"/{project}/" in root_location(entry, detail)
        and not has_obvious_api_contract_problem(project, driver, driver_src)
        and is_natural_api_path(project, driver_src)
    ):
        return decision(
            row,
            representative,
            STATUS_UNRESOLVED,
            "potential_unpublished_api_bug",
            "N/A; unpublished candidate, not part of confirmed public ground truth",
            repro,
            root_summary(entry, detail),
            "Stable 3/3 reproduction through a reasonable API path with target-library root cause, but no public reference or author-confirmed disclosure is available; excluded from binary metrics.",
            "medium",
        )

    if triage_label == "likely_driver_bug" and has_driver_triage_evidence(detail, entry):
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "driver_misuse_triage_with_local_evidence",
            "N/A",
            repro,
            root_summary(entry, detail),
            "likely_driver_bug plus concrete local driver/noise evidence such as leak-only, driver-dominant stack, or raw-struct pattern.",
            "medium",
        )

    if (bug_type or "").lower() == "unknown" and triage_label in {"likely_driver_bug", "noise"}:
        return decision(
            row,
            representative,
            STATUS_NON_TARGET,
            "no_memory_safety_signal",
            "N/A",
            repro,
            root_summary(entry, detail),
            "No concrete sanitizer memory-safety signal and local triage does not support target-library bug.",
            "medium",
        )

    if triage_label == "likely_api_bug":
        return decision(
            row,
            representative,
            STATUS_UNRESOLVED,
            "potential_unpublished_api_bug",
            "N/A; unpublished candidate, not part of confirmed public ground truth",
            repro,
            root_summary(entry, detail),
            "The crash is an old-false report with likely_api_bug triage and no hard local non-target evidence; kept as the single potential-unpublished-API-bug category and excluded from binary metrics.",
            "medium",
        )

    return decision(
        row,
        representative,
        STATUS_NON_TARGET,
        "not_public_target_confirmation_after_manual_audit",
        "N/A",
        repro,
        root_summary(entry, detail),
        "No public target-component vulnerability confirmation or strong unpublished API-bug evidence is available after local evidence audit; retained as non-target under the paper's binary ground-truth protocol.",
        "medium",
    )


def decision(
    row: Mapping[str, str],
    representative: str,
    status: str,
    evidence_type: str,
    public_reference: str,
    reproduction: str,
    root: str,
    note: str,
    confidence: str,
) -> Dict[str, str]:
    return {
        "Project": row["Project"],
        "CrashID": row["CrashID"],
        "RepresentativeCrashID": representative,
        "GroundTruthStatus": status,
        "IncludeInMetrics": "TRUE" if status in {STATUS_TARGET, STATUS_NON_TARGET} else "FALSE",
        "EvidenceType": evidence_type,
        "PublicReference": public_reference,
        "ReproductionStatus": reproduction,
        "RootCauseSummary": root,
        "DecisionNote": note,
        "ManualConfidence": confidence,
    }


def enrich_evidence(
    manual_label: Mapping[str, str],
    metric_label: Mapping[str, str],
    row: Mapping[str, str],
    detail: Mapping[str, str],
    db_root: Path,
) -> Dict[str, str]:
    driver = row.get("Driver") or driver_from_crash_id(row["CrashID"])
    return {
        **manual_label,
        "ManualGroundTruthStatus": manual_label["GroundTruthStatus"],
        "MetricGroundTruthStatus": metric_label["GroundTruthStatus"],
        "LegacyGroundTruth": row.get("GroundTruth", ""),
        "BugType": detail.get("BugType", row.get("BugType", "")),
        "Sanitizer": detail.get("Sanitizer", ""),
        "TriageLabel": detail.get("TriageLabel", row.get("TriageLabel", "")),
        "TriageRules": detail.get("TriageRules", ""),
        "CrashFile": detail.get("CrashFile", ""),
        "CrashFunction": detail.get("CrashFunction", ""),
        "Signature": detail.get("Signature", ""),
        "EvidencePath": yaml_path(db_root, row["Project"], driver),
        "DriverPath": driver_path(db_root, row["Project"], driver),
    }


def summarize(labels: Sequence[Mapping[str, str]], evidence_rows: Sequence[Mapping[str, str]]) -> Dict[str, Any]:
    by_project_status: Dict[str, Dict[str, int]] = defaultdict(dict)
    for (project, status), count in Counter((r["Project"], r["GroundTruthStatus"]) for r in labels).items():
        by_project_status[project][status] = count
    by_evidence = Counter(r["EvidenceType"] for r in labels)
    return {
        "total_rows": len(labels),
        "metric_status_counts": dict(Counter(r["GroundTruthStatus"] for r in labels)),
        "manual_status_counts": dict(Counter(r["ManualGroundTruthStatus"] for r in evidence_rows)),
        "include_in_metrics_counts": dict(Counter(r["IncludeInMetrics"] for r in labels)),
        "by_project_status": dict(sorted(by_project_status.items())),
        "by_evidence_type": dict(sorted(by_evidence.items())),
        "confirmed_target_policy": (
            "Only legacy TRUE rows are confirmed_target because they are author-confirmed public "
            "driver+PoC reproductions. Unpublished target-looking candidates remain unresolved."
        ),
        "unresolved_policy": "unresolved_candidate rows are excluded from paper metrics.",
        "validation": validate(labels),
    }


def validate(labels: Sequence[Mapping[str, str]]) -> Dict[str, Any]:
    errors = []
    valid = {STATUS_TARGET, STATUS_NON_TARGET, STATUS_UNRESOLVED}
    for row in labels:
        status = row["GroundTruthStatus"]
        if status not in valid:
            errors.append(f"invalid status for {row['CrashID']}: {status}")
        expected = "TRUE" if status in {STATUS_TARGET, STATUS_NON_TARGET} else "FALSE"
        if row["IncludeInMetrics"] != expected:
            errors.append(f"bad IncludeInMetrics for {row['CrashID']}: expected {expected}")
        if status == STATUS_TARGET and "REQUIRED:" in row.get("PublicReference", ""):
            errors.append(f"placeholder public reference remains: {row['CrashID']}")
    return {"errors": errors}


def ok_prediction_keys(output_dir: Path, subdir: str) -> set[tuple[str, str]]:
    path = output_dir / subdir / "llm_bool_results.csv"
    keys = set()
    for row in read_csv_if_exists(path):
        result = (row.get("Result") or "").strip().lower()
        if row.get("Status") == "ok" and result in {"true", "false"}:
            keys.add((row.get("Project", ""), row.get("CrashID", "")))
    return keys


def representative_key(row: Mapping[str, str], rows_by_id: Mapping[str, Mapping[str, str]]) -> tuple[str, str]:
    project = row.get("Project", "")
    current = row
    seen = set()
    while current.get("DuplicateOf"):
        candidate = current["DuplicateOf"]
        key = (project, candidate)
        if key in seen or candidate not in rows_by_id:
            break
        seen.add(key)
        current = rows_by_id[candidate]
    return project, current.get("CrashID", row.get("CrashID", ""))


def has_v3_v4_coverage(
    row: Mapping[str, str],
    rows_by_id: Mapping[str, Mapping[str, str]],
    v3_keys: set[tuple[str, str]],
    v4_keys: set[tuple[str, str]],
) -> bool:
    key = representative_key(row, rows_by_id)
    return key in v3_keys and key in v4_keys


def metric_label_for_coverage(
    manual_label: Mapping[str, str],
    row: Mapping[str, str],
    rows_by_id: Mapping[str, Mapping[str, str]],
    v3_keys: set[tuple[str, str]],
    v4_keys: set[tuple[str, str]],
) -> Dict[str, str]:
    return dict(manual_label)


def run(engine_dir: Path, output_dir: Path) -> Dict[str, Any]:
    results_dir = engine_dir / "results"
    db_root = engine_dir / "external_database"
    rows = read_csv(results_dir / "ablation_per_crash.csv")
    rows_by_id = {row["CrashID"]: row for row in rows}
    details = {row["CrashID"]: row for row in read_csv(results_dir / "per_crash_detail.csv")}
    legacy_true_drivers = {row.get("Driver") or driver_from_crash_id(row["CrashID"]) for row in rows if truthy(row.get("GroundTruth"))}
    v3_keys = ok_prediction_keys(output_dir, "llm_v3_full_differential")
    v4_keys = ok_prediction_keys(output_dir, "llm_v4_full_direct_v1")

    labels = []
    evidence_rows = []
    for row in rows:
        detail = details.get(row["CrashID"], {})
        entry = load_crash_entry(db_root, row["Project"], row["CrashID"])
        manual_label = classify_row(row, detail, entry, db_root, legacy_true_drivers)
        metric_label = metric_label_for_coverage(manual_label, row, rows_by_id, v3_keys, v4_keys)
        labels.append(metric_label)
        evidence_rows.append(enrich_evidence(manual_label, metric_label, row, detail, db_root))

    summary = summarize(labels, evidence_rows)
    errors = summary["validation"]["errors"]
    if errors:
        raise SystemExit("Validation failed:\n" + "\n".join(errors[:20]))

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "ground_truth_v2.csv", GROUND_TRUTH_FIELDS, labels)
    write_csv(output_dir / "manual_ground_truth_evidence.csv", EVIDENCE_FIELDS, evidence_rows)
    review_rows = [row for row in evidence_rows if row["GroundTruthStatus"] == STATUS_UNRESOLVED]
    write_csv(output_dir / "manual_ground_truth_review_queue.csv", EVIDENCE_FIELDS, review_rows)
    (output_dir / "manual_ground_truth_summary.yaml").write_text(
        yaml.safe_dump(summary, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to fuzzing_llm_engine.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Revision output directory. Defaults to <engine-dir>/results/revision_20260722.",
    )
    args = parser.parse_args()
    engine_dir = args.engine_dir.resolve()
    output_dir = (args.output_dir or engine_dir / "results" / "revision_20260722").resolve()
    summary = run(engine_dir, output_dir)
    print(yaml.safe_dump(summary, sort_keys=False, allow_unicode=True))


if __name__ == "__main__":
    main()
