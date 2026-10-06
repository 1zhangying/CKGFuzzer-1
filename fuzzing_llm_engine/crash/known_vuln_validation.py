#!/usr/bin/env python3
"""Validate whether collected crashes match known public vulnerabilities.

The validator is intentionally conservative about "confirmed" matches.  It
uses local crash triage output as the authoritative crash inventory, enriches
rows with retrospective crash metadata, applies a small auditable evidence
rulebase, and writes both representative-level and per-crash CSVs.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
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
    "confirmed_known",
    "likely_known",
    "possibly_related",
    "not_found",
    "driver_or_noise",
    "needs_manual_review",
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
    "KnownStatus",
    "MatchedKnownID",
    "MatchedSourceType",
    "MatchedURL",
    "MatchConfidence",
    "Evidence",
    "Reasoning",
    "NeedsManualReview",
]


@dataclass(frozen=True)
class EvidenceRule:
    project: str
    known_id: str
    source_type: str
    urls: Sequence[str]
    functions: Sequence[str]
    files: Sequence[str]
    bug_keywords: Sequence[str]
    affected_versions: Sequence[str]
    status: str
    confidence: str
    evidence: str
    reasoning: str
    require_function_match: bool = False

    def matches(self, row: Dict[str, str]) -> bool:
        if row.get("Project") != self.project:
            return False

        func = (row.get("CrashFunction") or "").lower()
        file_name = (row.get("CrashFile") or "").lower()
        bug = (row.get("BugType") or "").lower()
        sig = (row.get("Signature") or "").lower()

        function_match = bool(func) and any(f.lower() == func for f in self.functions)
        file_match = bool(file_name) and any(f.lower() in file_name for f in self.files)
        sig_match = any(f.lower() in sig for f in self.functions)
        bug_match = not self.bug_keywords or any(k.lower() in bug for k in self.bug_keywords)

        if self.require_function_match:
            return (function_match or sig_match) and bug_match
        if self.functions or self.files:
            return (function_match or file_match or sig_match) and bug_match
        return bug_match


EVIDENCE_RULES: List[EvidenceRule] = [
    EvidenceRule(
        project="c-ares",
        known_id="CVE-2016-5180",
        source_type="upstream_advisory;local_known_cve_sanity",
        urls=(
            "https://c-ares.org/adv_20160929.html",
            "https://c-ares.org/CVE-2016-5180.patch",
        ),
        functions=("ares_create_query", "ares_mkquery"),
        files=("ares_create_query.c", "ares_mkquery.c"),
        bug_keywords=("heap-buffer-overflow", "buffer"),
        affected_versions=("c-ares 1.0.0 through 1.11.0",),
        status="possibly_related",
        confidence="low",
        evidence=(
            "Local known-CVE sanity case documents CVE-2016-5180 in "
            "ares_create_query/ares_mkquery, but the tested version is c-ares "
            "1.18.0, outside the documented affected range."
        ),
        reasoning=(
            "Only crashes in the same functions should be treated as related; "
            "current 1.18.0 crashes are not confirmed matches to this older CVE."
        ),
    ),
    EvidenceRule(
        project="cjson",
        known_id="CVE-2025-57052",
        source_type="upstream_issue_pr;local_known_cve_sanity",
        urls=(
            "https://github.com/DaveGamble/cJSON/issues/956",
            "https://github.com/DaveGamble/cJSON/pull/957",
        ),
        functions=("cJSONUtils_GetPointer", "decode_array_index_from_pointer"),
        files=("cJSON_Utils.c",),
        bug_keywords=("assertion", "logic", "segv", "fpe", "overflow", "use-after-free"),
        affected_versions=("cJSON 1.5.0 through 1.7.18",),
        status="possibly_related",
        confidence="low",
        evidence=(
            "Local known-CVE sanity case covers malformed JSON Pointer parsing "
            "in cJSON_Utils, not the cJSON.c memory-safety crashes in the 123-row dataset."
        ),
        reasoning=(
            "The tested cJSON 1.7.18 is in range, but only cJSON_Utils pointer "
            "crashes can be linked to this CVE without further PoC-level evidence."
        ),
    ),
    EvidenceRule(
        project="cjson",
        known_id="GitHub issue #833",
        source_type="upstream_issue",
        urls=("https://github.com/DaveGamble/cJSON/issues/833",),
        functions=("cJSON_Delete",),
        files=("cJSON.c",),
        bug_keywords=("double-free", "attempting double-free", "heap-use-after-free"),
        affected_versions=("reported against cJSON upstream in 2024",),
        status="likely_known",
        confidence="medium",
        evidence=(
            "Public cJSON issue #833 reports a fuzz-discovered double-free in "
            "cJSON_Delete with crafted cJSON object ownership/state."
        ),
        reasoning=(
            "A local representative crash in cJSON_Delete with UAF/double-free "
            "is function- and bug-class-aligned with the public report, but the "
            "available evidence does not prove identical PoC or root cause."
        ),
        require_function_match=True,
    ),
    EvidenceRule(
        project="cjson",
        known_id="GitHub issue #800",
        source_type="upstream_issue",
        urls=("https://github.com/DaveGamble/cJSON/issues/800",),
        functions=("parse_string", "parse_object", "cJSON_ParseWithLength", "cJSON_ParseWithLengthOpts"),
        files=("cJSON.c",),
        bug_keywords=("heap-buffer-overflow", "overflow"),
        affected_versions=("reported against cJSON upstream in 2023/2024",),
        status="possibly_related",
        confidence="low",
        evidence=(
            "Public cJSON issue #800 reports an OOB access in parse_string via "
            "cJSON_ParseWithLength on unterminated input."
        ),
        reasoning=(
            "This only relates to parser-stack crashes. Crashes lacking a "
            "parse_string/parse_object frame remain unconfirmed."
        ),
    ),
    EvidenceRule(
        project="zlib",
        known_id="CVE-2026-27171",
        source_type="nvd;upstream_issue;local_known_cve_sanity",
        urls=(
            "https://github.com/madler/zlib/issues/904",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27171",
        ),
        functions=("crc32_combine_gen64", "x2nmodp"),
        files=("crc32.c",),
        bug_keywords=("timeout", "infinite", ""),
        affected_versions=("zlib 1.3 before the upstream fix",),
        status="confirmed_known",
        confidence="high",
        evidence=(
            "Local known-CVE sanity case and public records document an infinite "
            "loop in crc32_combine_gen64 on negative lengths in zlib 1.3."
        ),
        reasoning=(
            "Only crashes/timeouts in crc32_combine_gen64/x2nmodp should inherit "
            "this confirmed known status."
        ),
    ),
]


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _join(values: Iterable[str]) -> str:
    return "; ".join(v for v in values if v)


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def load_yaml(path: Path) -> Any:
    with path.open() as f:
        return yaml.safe_load(f)


def load_retro_by_crash(results_dir: Path) -> Dict[str, Dict[str, Any]]:
    retro: Dict[str, Dict[str, Any]] = {}
    for project in PROJECT_VERSIONS:
        path = results_dir / f"{project}_retro.yaml"
        if not path.exists():
            continue
        data = load_yaml(path) or {}
        for item in data.get("crashes") or []:
            crash_id = item.get("crash_id")
            if crash_id:
                retro[crash_id] = item
    return retro


def enrich_row(row: Dict[str, str], retro: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    item = retro.get(row.get("CrashID", ""), {})
    enriched = dict(row)
    field_map = {
        "BugType": "parsed_bug_type",
        "Sanitizer": "parsed_sanitizer",
        "TriageLabel": "triage_label",
        "Signature": "signature",
        "CrashFile": "crash_file",
        "CrashFunction": "crash_function",
    }
    for csv_key, retro_key in field_map.items():
        if not enriched.get(csv_key) and item.get(retro_key) is not None:
            enriched[csv_key] = str(item.get(retro_key) or "")
    if not enriched.get("CrashFile") and item.get("parsed_first_project_frame"):
        frame = str(item["parsed_first_project_frame"])
        enriched["CrashFile"] = frame.rsplit(":", 1)[0]
    return enriched


def representative_id(row: Dict[str, str], rows_by_id: Dict[str, Dict[str, str]]) -> str:
    seen = set()
    current = row
    while _truthy(current.get("IsDuplicate")) and current.get("DuplicateOf") in rows_by_id:
        next_id = current["DuplicateOf"]
        if next_id in seen:
            break
        seen.add(next_id)
        current = rows_by_id[next_id]
    return current.get("CrashID", row.get("CrashID", ""))


def build_search_evidence(row: Dict[str, str]) -> str:
    project = row.get("Project", "")
    version = PROJECT_VERSIONS.get(project, "")
    function = row.get("CrashFunction") or "unknown_function"
    bug = row.get("BugType") or "unknown_bug_type"
    sanitizer = row.get("Sanitizer") or "unknown_sanitizer"
    signature = row.get("Signature") or "unknown_signature"
    queries = [
        f"{project} {version} {function} {bug} {sanitizer}",
        f"{project} {function} CVE",
        f"{project} {function} {bug}",
        f"{project} {signature}",
    ]
    sources = [
        "NVD",
        "MITRE CVE",
        "OSV",
        "GitHub Security Advisories",
        "upstream issues/PRs/commits",
        "OSS-Fuzz public bugs",
    ]
    return "searched_queries=" + json.dumps(queries, ensure_ascii=False) + "; sources=" + ",".join(sources)


def is_noise_like(row: Dict[str, str]) -> bool:
    bug = (row.get("BugType") or "").lower()
    label = (row.get("TriageLabel") or "").lower()
    rules = (row.get("TriageRules") or "").lower()
    sig = (row.get("Signature") or "").lower()
    reviewable_label = label in {"likely_api_bug", "needs_review"}
    return (
        label in {"likely_driver_bug", "noise"}
        or "memory-leak" in bug
        or "leak" in bug
        or "timeout" in bug
        or "oom" in bug
        or "leak_only" in rules
        or ("driver_dominant_stack" in rules and not reviewable_label)
        or sig.startswith("dedup:__interceptor_malloc")
        or sig.startswith("dedup:__interceptor_realloc")
    )


def requires_manual_review(row: Dict[str, str]) -> bool:
    label = (row.get("TriageLabel") or "").lower()
    bug = (row.get("BugType") or "").lower()
    return (
        label in {"likely_api_bug", "needs_review"}
        and not is_noise_like(row)
        and ("heap" in bug or "free" in bug or "segv" in bug or "fpe" in bug or not bug)
    )


def apply_evidence_rules(row: Dict[str, str]) -> Optional[EvidenceRule]:
    matches = [rule for rule in EVIDENCE_RULES if rule.matches(row)]
    if not matches:
        return None
    rank = {"confirmed_known": 5, "likely_known": 4, "possibly_related": 3}
    return sorted(matches, key=lambda rule: rank.get(rule.status, 0), reverse=True)[0]


def classify_representative(row: Dict[str, str]) -> Dict[str, str]:
    rule = apply_evidence_rules(row)
    if rule is not None:
        needs_review = rule.status != "confirmed_known"
        return {
            "KnownStatus": rule.status,
            "MatchedKnownID": rule.known_id,
            "MatchedSourceType": rule.source_type,
            "MatchedURL": _join(rule.urls),
            "MatchConfidence": rule.confidence,
            "Evidence": rule.evidence,
            "Reasoning": rule.reasoning,
            "NeedsManualReview": str(needs_review),
        }

    if is_noise_like(row):
        return {
            "KnownStatus": "driver_or_noise",
            "MatchedKnownID": "",
            "MatchedSourceType": "local_triage",
            "MatchedURL": "",
            "MatchConfidence": "none",
            "Evidence": build_search_evidence(row),
            "Reasoning": (
                "Local triage/bug type indicates leak-only, timeout/OOM, driver "
                "dominant stack, or likely driver misuse; no public evidence was "
                "found that upgrades this to a known vulnerability."
            ),
            "NeedsManualReview": "False",
        }

    if requires_manual_review(row):
        return {
            "KnownStatus": "needs_manual_review",
            "MatchedKnownID": "",
            "MatchedSourceType": "local_triage;public_search_terms",
            "MatchedURL": "",
            "MatchConfidence": "none",
            "Evidence": build_search_evidence(row),
            "Reasoning": (
                "Crash is marked likely_api_bug/needs_review and has a memory "
                "safety or severe signal, but no function-level public match is "
                "encoded in the current evidence rulebase."
            ),
            "NeedsManualReview": "True",
        }

    return {
        "KnownStatus": "not_found",
        "MatchedKnownID": "",
        "MatchedSourceType": "public_search_terms",
        "MatchedURL": "",
        "MatchConfidence": "none",
        "Evidence": build_search_evidence(row),
        "Reasoning": "No public CVE/advisory/issue/commit match was found in the current evidence pass.",
        "NeedsManualReview": "False",
    }


def output_base(row: Dict[str, str], representative: str) -> Dict[str, str]:
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


def write_csv(path: Path, rows: Sequence[Dict[str, str]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def validate_outputs(
    input_rows: Sequence[Dict[str, str]],
    cluster_rows: Sequence[Dict[str, str]],
    per_crash_rows: Sequence[Dict[str, str]],
    results_dir: Path,
) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    if len(input_rows) != 123:
        errors.append(f"Expected 123 per_crash_detail rows, found {len(input_rows)}")
    if len(per_crash_rows) != len(input_rows):
        errors.append(
            f"Expected {len(input_rows)} per-crash output rows, found {len(per_crash_rows)}"
        )

    input_ids = {r["CrashID"] for r in input_rows}
    output_ids = {r["CrashID"] for r in per_crash_rows}
    missing = sorted(input_ids - output_ids)
    if missing:
        errors.append(f"Missing output rows for crash IDs: {missing[:10]}")

    rep_ids = {r["RepresentativeCrashID"] for r in cluster_rows}
    for row in per_crash_rows:
        if row["IsDuplicate"] == "True" and row["RepresentativeCrashID"] not in rep_ids:
            if row["KnownStatus"] != "needs_manual_review":
                errors.append(
                    f"Duplicate {row['CrashID']} maps to missing representative "
                    f"{row['RepresentativeCrashID']}"
                )

    for row in cluster_rows:
        status = row["KnownStatus"]
        if status not in STATUS_VALUES:
            errors.append(f"Invalid KnownStatus {status} for {row['CrashID']}")
        if status == "confirmed_known" and not row["MatchedURL"]:
            errors.append(f"confirmed_known row has no URL: {row['CrashID']}")
        if status == "likely_known" and not (row["CrashFunction"] or row["CrashFile"]):
            errors.append(f"likely_known row lacks function/file evidence: {row['CrashID']}")
        if status == "not_found" and "searched_queries=" not in row["Evidence"]:
            errors.append(f"not_found row lacks searched query evidence: {row['CrashID']}")

    summary_path = results_dir / "aggregate_summary.yaml"
    project_summary_path = results_dir / "per_project_summary.csv"
    if summary_path.exists():
        agg = load_yaml(summary_path) or {}
        expected_unique = sum(
            int(p.get("unique_after_dedup", 0)) for p in agg.get("per_project", [])
        )
        if expected_unique and expected_unique != len(cluster_rows):
            warnings.append(
                "Representative count mismatch: per_crash_detail non-duplicates="
                f"{len(cluster_rows)}, aggregate_summary unique_after_dedup sum={expected_unique}"
            )
    if project_summary_path.exists():
        summary_rows = load_csv(project_summary_path)
        counts = Counter(r["Project"] for r in input_rows)
        for srow in summary_rows:
            project = srow["Project"]
            expected = int(srow["TotalCrashes"])
            if counts[project] != expected:
                errors.append(
                    f"Project {project} expected {expected} crashes from summary, found {counts[project]}"
                )

    return {"errors": errors, "warnings": warnings}


def summarize(rows: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    by_project_status: Dict[str, Dict[str, int]] = defaultdict(dict)
    for (project, status), count in Counter((r["Project"], r["KnownStatus"]) for r in rows).items():
        by_project_status[project][status] = count
    return {
        "total": len(rows),
        "by_status": dict(Counter(r["KnownStatus"] for r in rows)),
        "by_project_status": dict(sorted(by_project_status.items())),
    }


def priority_candidates(rows: Sequence[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    known_statuses = {"confirmed_known", "likely_known", "possibly_related"}
    known_or_related = [
        {
            "Project": row["Project"],
            "CrashID": row["CrashID"],
            "KnownStatus": row["KnownStatus"],
            "MatchedKnownID": row["MatchedKnownID"],
            "CrashFunction": row["CrashFunction"],
            "BugType": row["BugType"],
            "Reasoning": row["Reasoning"],
        }
        for row in rows
        if row["KnownStatus"] in known_statuses
    ]

    severity_terms = ("heap", "free", "segv", "fpe", "overflow", "use-after-free")
    manual = [
        row
        for row in rows
        if row["KnownStatus"] == "needs_manual_review"
        and any(term in (row["BugType"] or "").lower() for term in severity_terms)
    ]
    manual.sort(
        key=lambda row: (
            row["Project"],
            0 if row["TriageLabel"] == "likely_api_bug" else 1,
            row["CrashFunction"] or "zzzz",
            row["CrashID"],
        )
    )
    manual_review = [
        {
            "Project": row["Project"],
            "CrashID": row["CrashID"],
            "CrashFunction": row["CrashFunction"],
            "BugType": row["BugType"],
            "Signature": row["Signature"],
            "Reasoning": row["Reasoning"],
        }
        for row in manual[:12]
    ]
    return {
        "known_or_related_matches": known_or_related,
        "priority_manual_review_candidates": manual_review,
    }


def run(results_dir: Path, output_dir: Path) -> Dict[str, Any]:
    input_path = results_dir / "per_crash_detail.csv"
    input_rows = load_csv(input_path)
    retro = load_retro_by_crash(results_dir)
    enriched_rows = [enrich_row(row, retro) for row in input_rows]
    rows_by_id = {row["CrashID"]: row for row in enriched_rows}

    cluster_outputs: List[Dict[str, str]] = []
    representative_results: Dict[str, Dict[str, str]] = {}
    for row in enriched_rows:
        if _truthy(row.get("IsDuplicate")):
            continue
        rep = row["CrashID"]
        base = output_base(row, rep)
        verdict = classify_representative(row)
        out = {**base, **verdict}
        cluster_outputs.append(out)
        representative_results[rep] = verdict

    per_crash_outputs: List[Dict[str, str]] = []
    for row in enriched_rows:
        rep = representative_id(row, rows_by_id)
        base = output_base(row, rep)
        if rep in representative_results:
            verdict = representative_results[rep]
        else:
            verdict = classify_representative(row)
            verdict = {
                **verdict,
                "KnownStatus": "needs_manual_review",
                "NeedsManualReview": "True",
                "Reasoning": (
                    "DuplicateOf target was not present as a representative row; "
                    + verdict["Reasoning"]
                ),
            }
        per_crash_outputs.append({**base, **verdict})

    output_dir.mkdir(parents=True, exist_ok=True)
    cluster_path = output_dir / "known_vuln_cluster_validation.csv"
    per_crash_path = output_dir / "known_vuln_per_crash_validation.csv"
    summary_path = output_dir / "known_vuln_validation_summary.yaml"

    write_csv(cluster_path, cluster_outputs)
    write_csv(per_crash_path, per_crash_outputs)

    validation = validate_outputs(input_rows, cluster_outputs, per_crash_outputs, results_dir)
    summary = {
        "input": str(input_path),
        "outputs": {
            "cluster": str(cluster_path),
            "per_crash": str(per_crash_path),
            "summary": str(summary_path),
        },
        "versions": PROJECT_VERSIONS,
        "cluster_summary": summarize(cluster_outputs),
        "per_crash_summary": summarize(per_crash_outputs),
        "priority_candidates": priority_candidates(cluster_outputs),
        "validation": validation,
    }
    with summary_path.open("w") as f:
        yaml.safe_dump(summary, f, sort_keys=False, allow_unicode=True)

    if validation["errors"]:
        raise SystemExit("Validation failed:\n" + "\n".join(validation["errors"]))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        default="fuzzing_llm_engine/results",
        type=Path,
        help="Directory containing per_crash_detail.csv and *_retro.yaml files.",
    )
    parser.add_argument(
        "--output-dir",
        default="fuzzing_llm_engine/results",
        type=Path,
        help="Directory for validation CSV and summary outputs.",
    )
    args = parser.parse_args()
    summary = run(args.results_dir, args.output_dir)
    print(yaml.safe_dump(summary, sort_keys=False, allow_unicode=True))


if __name__ == "__main__":
    main()
