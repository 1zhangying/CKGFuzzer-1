#!/usr/bin/env python3
"""Stricter validation of which crashes are real target-library vulnerabilities.

This pass answers a different question from known_vuln_validation.py:

  "Is this crash a real, confirmable target-library vulnerability/bug under a
   reasonable API or input model?"

It uses local crash reports and generated drivers to distinguish target bugs
from harness-created invalid states.  The output is intentionally conservative:
only local known-CVE sanity cases or natural parser/API paths with strong
evidence are marked confirmed.
"""
from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml


PROJECT_VERSIONS = {
    "c-ares": "1.18.0",
    "cjson": "1.7.18",
    "libpcap": "1.10.4",
    "zlib": "1.3",
}

STATUS_VALUES = {
    "confirmed_real_vulnerability",
    "likely_real_vulnerability",
    "known_but_not_dataset_crash",
    "driver_or_harness_bug",
    "not_enough_evidence",
    "not_security_relevant",
}

OUTPUT_COLUMNS = [
    "Project",
    "Version",
    "CrashID",
    "RepresentativeCrashID",
    "IsDuplicate",
    "DuplicateOf",
    "BugType",
    "Sanitizer",
    "TriageLabel",
    "CrashFile",
    "CrashFunction",
    "Signature",
    "RealVulnStatus",
    "KnownReference",
    "Confidence",
    "DriverEvidence",
    "LibraryEvidence",
    "Reasoning",
    "RecommendedAction",
]


KNOWN_REFERENCES = {
    "c-ares": {
        "CVE-2016-5180": {
            "functions": {"ares_create_query", "ares_mkquery"},
            "affected": "c-ares 1.0.0 through 1.11.0",
            "url": "https://c-ares.org/adv_20160929.html",
        }
    },
    "cjson": {
        "GitHub issue #833": {
            "functions": {"cJSON_Delete"},
            "url": "https://github.com/DaveGamble/cJSON/issues/833",
        },
        "CVE-2025-57052": {
            "functions": {"cJSONUtils_GetPointer", "decode_array_index_from_pointer"},
            "url": "https://github.com/DaveGamble/cJSON/issues/956",
        },
    },
    "zlib": {
        "CVE-2026-27171": {
            "functions": {"crc32_combine_gen64", "x2nmodp"},
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-27171",
        }
    },
}

INTERNAL_STATE_HINTS = (
    "memcpy(",
    "reinterpret_cast",
    "ares_channeldata",
    "struct ares_options",
    "cJSON v",
    "cJSON item",
    "pcap_t *",
    "pcap_t v",
    "z_stream v",
    "inflate_state",
    "deflate_state",
)

NATURAL_API_HINTS = (
    "cJSON_Parse",
    "cJSON_ParseWithLength",
    "ares_create_query",
    "ares_mkquery",
    "pcap_compile",
    "inflate(",
    "deflate(",
    "inflateBack",
    "uncompress",
)

SEVERE_BUG_TERMS = (
    "heap-buffer-overflow",
    "heap-use-after-free",
    "attempting double-free",
    "attempting free",
    "segv",
    "fpe",
    "stack-overflow",
)

HARNESS_ROOT_HINTS = (
    "fuzz driver",
    "/fuzzing/",
    "/tests/",
    "driver:",
    ".cc:",
)


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _load_yaml(path: Path) -> Any:
    with path.open() as f:
        return yaml.safe_load(f)


def _driver_from_crash_id(crash_id: str) -> str:
    return crash_id.rsplit("_crash_", 1)[0]


def _crash_number(crash_id: str) -> str:
    return crash_id.rsplit("_crash_", 1)[1]


def _representative_id(row: Dict[str, str], rows_by_id: Dict[str, Dict[str, str]]) -> str:
    current = row
    seen = set()
    while _truthy(current.get("IsDuplicate")) and current.get("DuplicateOf") in rows_by_id:
        next_id = current["DuplicateOf"]
        if next_id in seen:
            break
        seen.add(next_id)
        current = rows_by_id[next_id]
    return current.get("CrashID", row.get("CrashID", ""))


def _crash_dir(row: Dict[str, str]) -> Path:
    return Path("fuzzing_llm_engine/external_database") / row["Project"] / "crash" / _driver_from_crash_id(row["CrashID"])


def _load_crash_report(row: Dict[str, str]) -> Dict[str, Any]:
    path = _crash_dir(row) / "crash_analysis.yaml"
    if not path.exists():
        return {}
    data = _load_yaml(path)
    key = f"crash_{_crash_number(row['CrashID'])}"
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and key in item:
                return item[key] or {}
    if isinstance(data, dict):
        return data.get(key, data) or {}
    return {}


def _read_driver(row: Dict[str, str]) -> str:
    path = _crash_dir(row) / f"{row['CrashID']}.cc"
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def _source_driver_path(row: Dict[str, str]) -> Path:
    ext = ".c" if row["Project"] in {"cjson", "c-ares"} else ".cc"
    return Path("fuzzing_llm_engine/external_database") / row["Project"] / "fuzz_driver" / (_driver_from_crash_id(row["CrashID"]) + ext)


def _read_source_driver(row: Dict[str, str]) -> str:
    path = _source_driver_path(row)
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(n.lower() in lowered for n in needles if n)


def _project_source_prefix(project: str) -> str:
    return f"/src/{project}/"


def _root_cause_location(report: Dict[str, Any]) -> str:
    enh = report.get("enhanced_analysis") or {}
    loc = report.get("location") or {}
    return str(enh.get("root_cause_location") or loc.get("crash_file") or "")


def _root_cause_trigger(report: Dict[str, Any]) -> str:
    enh = report.get("enhanced_analysis") or {}
    return str(enh.get("root_cause_trigger") or "")


def _has_target_library_root_cause(row: Dict[str, str], report: Dict[str, Any]) -> bool:
    root_loc = _root_cause_location(report)
    if not root_loc:
        return False
    if not root_loc.startswith(_project_source_prefix(row["Project"])):
        return False
    lowered = root_loc.lower()
    return not any(hint in lowered for hint in HARNESS_ROOT_HINTS)


def _has_harness_root_cause(report: Dict[str, Any]) -> bool:
    root_loc = _root_cause_location(report).lower()
    trigger = _root_cause_trigger(report).lower()
    evidence = f"{root_loc} {trigger}"
    return any(hint in evidence for hint in HARNESS_ROOT_HINTS)


def _driver_evidence(row: Dict[str, str], driver_src: str) -> str:
    if not driver_src:
        return "No generated crash driver source found for this representative."
    hits = [hint for hint in INTERNAL_STATE_HINTS if hint in driver_src]
    natural = [hint for hint in NATURAL_API_HINTS if hint in driver_src]
    details = []
    if hits:
        details.append("internal_state_or_raw_struct_hints=" + ",".join(hits[:8]))
    if natural:
        details.append("natural_api_hints=" + ",".join(natural[:8]))
    allocation_patterns = len(re.findall(r"malloc\s*\(|memcpy\s*\(", driver_src))
    if allocation_patterns:
        details.append(f"malloc_or_memcpy_count={allocation_patterns}")
    return "; ".join(details) if details else "No obvious harness-misuse pattern detected in generated crash driver."


def _library_evidence(row: Dict[str, str], report: Dict[str, Any]) -> str:
    parts = []
    loc = report.get("location") or {}
    if loc:
        parts.append(
            "location="
            + ":".join(
                str(x)
                for x in [loc.get("crash_file"), loc.get("crash_line"), loc.get("crash_function")]
                if x is not None
            )
        )
    enh = report.get("enhanced_analysis") or {}
    for key in ("root_cause_type", "root_cause_location", "root_cause_trigger", "severity"):
        if enh.get(key):
            parts.append(f"{key}={str(enh[key])[:260]}")
    known = report.get("known_cve_ground_truth") or {}
    if known:
        parts.append(f"known_cve={known.get('cve')}; sources={','.join(known.get('official_sources') or [])}")
    return "; ".join(parts) if parts else "No detailed crash report evidence beyond CSV/retro metadata."


def _known_reference(row: Dict[str, str]) -> str:
    project_refs = KNOWN_REFERENCES.get(row["Project"], {})
    func = row.get("CrashFunction") or ""
    sig = row.get("Signature") or ""
    for ref, meta in project_refs.items():
        funcs = meta.get("functions", set())
        if func in funcs or any(f in sig for f in funcs):
            return f"{ref} ({meta.get('url', '')})"
    if row.get("MatchedKnownID"):
        return row["MatchedKnownID"]
    return ""


def _is_known_cve_sanity(row: Dict[str, str], report: Dict[str, Any]) -> bool:
    return bool(report.get("known_cve_ground_truth")) or "known_cve_sanity" in row["CrashID"]


def classify_representative(row: Dict[str, str]) -> Dict[str, str]:
    report = _load_crash_report(row)
    driver_src = _read_driver(row) or _read_source_driver(row)
    bug = (row.get("BugType") or "").lower()
    label = (row.get("TriageLabel") or "").lower()
    function = row.get("CrashFunction") or ""
    signature = row.get("Signature") or ""
    known_ref = _known_reference(row)
    driver_ev = _driver_evidence(row, driver_src)
    library_ev = _library_evidence(row, report)

    if _is_known_cve_sanity(row, report):
        return {
            "RealVulnStatus": "confirmed_real_vulnerability",
            "KnownReference": known_ref or str((report.get("known_cve_ground_truth") or {}).get("cve", "")),
            "Confidence": "high",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": "Local known-CVE sanity report contains explicit public ground truth and replay notes.",
            "RecommendedAction": "Keep as confirmed known vulnerability sanity case, separate from newly found crashes.",
        }

    if known_ref and row["Project"] == "c-ares" and "CVE-2016-5180" in known_ref:
        return {
            "RealVulnStatus": "known_but_not_dataset_crash",
            "KnownReference": known_ref,
            "Confidence": "medium",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "The signature mentions ares_create_query/ares_mkquery, but the local crash location is "
                f"{function or 'unknown'} and the tested c-ares version is 1.18.0, outside the CVE-2016-5180 affected range."
            ),
            "RecommendedAction": "Do not count as confirmed real vulnerability without differential reproduction against an affected version.",
        }

    internal_misuse = _contains_any(driver_src, INTERNAL_STATE_HINTS)
    natural_api = _contains_any(driver_src, NATURAL_API_HINTS)
    severe = any(term in bug for term in SEVERE_BUG_TERMS)
    target_library_root_cause = _has_target_library_root_cause(row, report)
    harness_root_cause = _has_harness_root_cause(report)

    if "memory-leak" in bug or "leak" in bug:
        return {
            "RealVulnStatus": "not_security_relevant",
            "KnownReference": known_ref,
            "Confidence": "medium",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": "Leak-only signal is not treated as a confirmed security vulnerability in this stricter pass.",
            "RecommendedAction": "Exclude from confirmed vulnerability count unless a public advisory proves security impact.",
        }

    if label in {"noise", "likely_driver_bug"}:
        return {
            "RealVulnStatus": "driver_or_harness_bug",
            "KnownReference": known_ref,
            "Confidence": "high" if internal_misuse else "medium",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": "Existing triage marks this as noise/likely driver bug; no stronger library-vulnerability evidence is present.",
            "RecommendedAction": "Exclude from confirmed target-library vulnerability set.",
        }

    if harness_root_cause:
        return {
            "RealVulnStatus": "driver_or_harness_bug",
            "KnownReference": known_ref,
            "Confidence": "high",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "Crash analysis places the root cause in the generated fuzz driver or test harness, not in the target library."
            ),
            "RecommendedAction": "Exclude from confirmed target-library vulnerability set.",
        }

    if internal_misuse and not natural_api:
        return {
            "RealVulnStatus": "driver_or_harness_bug",
            "KnownReference": known_ref,
            "Confidence": "high",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "Generated crash driver appears to fabricate internal/pointer-rich state rather than feed a documented parser/API path."
            ),
            "RecommendedAction": "Exclude unless a minimized PoC using only documented API calls reproduces the crash.",
        }

    if known_ref and row["Project"] == "cjson" and function == "cJSON_Delete":
        return {
            "RealVulnStatus": "driver_or_harness_bug",
            "KnownReference": known_ref,
            "Confidence": "medium",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "The crash is related to a public cJSON_Delete fuzz report, but cJSON_Delete requires a valid cJSON ownership graph; "
                "the generated driver constructs cJSON objects directly, so this is not confirmed as a target-library vulnerability."
            ),
            "RecommendedAction": "Keep as public-related harness finding; require a parser/API-only PoC before counting as real.",
        }

    if severe and natural_api and not internal_misuse and target_library_root_cause:
        return {
            "RealVulnStatus": "likely_real_vulnerability",
            "KnownReference": known_ref,
            "Confidence": "medium",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "Crash uses a natural API/input path, has a severe sanitizer signal, and the local analysis places the root cause in target-library code; it still lacks public/differential confirmation."
            ),
            "RecommendedAction": "Prioritize for minimization and fixed-version differential reproduction.",
        }

    if severe and natural_api and not internal_misuse:
        return {
            "RealVulnStatus": "not_enough_evidence",
            "KnownReference": known_ref,
            "Confidence": "low",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "Natural API use and a severe sanitizer signal are present, but local evidence does not confirm a target-library root cause."
            ),
            "RecommendedAction": "Require a minimized documented-API PoC plus differential reproduction before claiming a real vulnerability.",
        }

    if severe:
        return {
            "RealVulnStatus": "not_enough_evidence",
            "KnownReference": known_ref,
            "Confidence": "low",
            "DriverEvidence": driver_ev,
            "LibraryEvidence": library_ev,
            "Reasoning": (
                "Severe sanitizer signal exists, but current evidence does not rule out harness misuse or prove a valid target-library input model."
            ),
            "RecommendedAction": "Inspect driver manually and build a documented-API PoC before claiming a real vulnerability.",
        }

    return {
        "RealVulnStatus": "not_enough_evidence",
        "KnownReference": known_ref,
        "Confidence": "low",
        "DriverEvidence": driver_ev,
        "LibraryEvidence": library_ev,
        "Reasoning": "No strong confirmation of target-library vulnerability is available.",
        "RecommendedAction": "Keep for manual review only if project-specific impact matters.",
    }


def _base_row(row: Dict[str, str], representative: str) -> Dict[str, str]:
    return {
        "Project": row.get("Project", ""),
        "Version": PROJECT_VERSIONS.get(row.get("Project", ""), ""),
        "CrashID": row.get("CrashID", ""),
        "RepresentativeCrashID": representative,
        "IsDuplicate": str(_truthy(row.get("IsDuplicate"))),
        "DuplicateOf": row.get("DuplicateOf", ""),
        "BugType": row.get("BugType", ""),
        "Sanitizer": row.get("Sanitizer", ""),
        "TriageLabel": row.get("TriageLabel", ""),
        "CrashFile": row.get("CrashFile", ""),
        "CrashFunction": row.get("CrashFunction", ""),
        "Signature": row.get("Signature", ""),
    }


def _write_csv(path: Path, rows: Sequence[Dict[str, str]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _summarize(rows: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    by_project_status: Dict[str, Dict[str, int]] = defaultdict(dict)
    for (project, status), count in Counter((r["Project"], r["RealVulnStatus"]) for r in rows).items():
        by_project_status[project][status] = count
    return {
        "total": len(rows),
        "by_status": dict(Counter(r["RealVulnStatus"] for r in rows)),
        "by_project_status": dict(sorted(by_project_status.items())),
    }


def run(results_dir: Path, output_dir: Path) -> Dict[str, Any]:
    known_rows = _load_csv(results_dir / "known_vuln_cluster_validation.csv")
    per_crash_input = _load_csv(results_dir / "known_vuln_per_crash_validation.csv")
    known_by_id = {row["CrashID"]: row for row in known_rows}
    per_by_id = {row["CrashID"]: row for row in per_crash_input}

    cluster_rows: List[Dict[str, str]] = []
    cluster_verdicts: Dict[str, Dict[str, str]] = {}
    for row in known_rows:
        rep = row["CrashID"]
        verdict = classify_representative(row)
        out = {**_base_row(row, rep), **verdict}
        cluster_rows.append(out)
        cluster_verdicts[rep] = verdict

    per_rows: List[Dict[str, str]] = []
    for row in per_crash_input:
        rep = _representative_id(row, per_by_id)
        rep_verdict = cluster_verdicts.get(rep) or classify_representative(row)
        per_rows.append({**_base_row(row, rep), **rep_verdict})

    errors: List[str] = []
    if len(per_rows) != 123:
        errors.append(f"Expected 123 per-crash rows, found {len(per_rows)}")
    for row in cluster_rows:
        if row["RealVulnStatus"] not in STATUS_VALUES:
            errors.append(f"Invalid status {row['RealVulnStatus']} for {row['CrashID']}")
    confirmed = [r for r in cluster_rows if r["RealVulnStatus"] == "confirmed_real_vulnerability"]
    if confirmed:
        for row in confirmed:
            if not row["KnownReference"]:
                errors.append(f"Confirmed row lacks KnownReference: {row['CrashID']}")

    output_dir.mkdir(parents=True, exist_ok=True)
    cluster_path = output_dir / "real_vuln_cluster_validation.csv"
    per_path = output_dir / "real_vuln_per_crash_validation.csv"
    summary_path = output_dir / "real_vuln_validation_summary.yaml"
    _write_csv(cluster_path, cluster_rows)
    _write_csv(per_path, per_rows)

    priority = [
        {
            "Project": row["Project"],
            "CrashID": row["CrashID"],
            "RealVulnStatus": row["RealVulnStatus"],
            "BugType": row["BugType"],
            "CrashFunction": row["CrashFunction"],
            "RecommendedAction": row["RecommendedAction"],
        }
        for row in cluster_rows
        if row["RealVulnStatus"] in {"confirmed_real_vulnerability", "likely_real_vulnerability", "not_enough_evidence"}
    ]
    summary = {
        "input": str(results_dir / "known_vuln_cluster_validation.csv"),
        "outputs": {
            "cluster": str(cluster_path),
            "per_crash": str(per_path),
            "summary": str(summary_path),
        },
        "status_definitions": {
            "confirmed_real_vulnerability": "Confirmed target-library vulnerability with public ground truth or equivalent differential evidence.",
            "likely_real_vulnerability": "Natural API/input path with severe target-code crash, but not yet publicly/differentially confirmed.",
            "known_but_not_dataset_crash": "Known public vulnerability is related but not confirmed to be this dataset crash.",
            "driver_or_harness_bug": "Crash depends on generated harness misuse or fabricated invalid state.",
            "not_enough_evidence": "Severe signal remains but evidence is insufficient for a real-vulnerability claim.",
            "not_security_relevant": "Leak/noise/timeout without security evidence.",
        },
        "cluster_summary": _summarize(cluster_rows),
        "per_crash_summary": _summarize(per_rows),
        "priority_review": priority,
        "validation": {"errors": errors},
    }
    with summary_path.open("w") as f:
        yaml.safe_dump(summary, f, sort_keys=False, allow_unicode=True)
    if errors:
        raise SystemExit("Validation failed:\n" + "\n".join(errors))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", default="fuzzing_llm_engine/results", type=Path)
    parser.add_argument("--output-dir", default="fuzzing_llm_engine/results", type=Path)
    args = parser.parse_args()
    summary = run(args.results_dir, args.output_dir)
    print(yaml.safe_dump(summary, sort_keys=False, allow_unicode=True))


if __name__ == "__main__":
    main()
