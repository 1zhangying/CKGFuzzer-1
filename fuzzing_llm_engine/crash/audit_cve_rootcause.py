#!/usr/bin/env python3
"""Audit CVE and crash-site/root-fingerprint consistency of CrashSage groups.

The audit uses only labels with explicit public evidence in the saved manual
ground-truth table. It makes no LLM calls.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

import yaml

from .sanitizer_parser import parse_sanitizer_output


CVE_RE = re.compile(r"CVE-\d{4}-\d+")
GROUP_FIELDS = [
    "Project",
    "RepresentativeCrashID",
    "GroupSize",
    "EvidenceCoveredMembers",
    "KnownCVEReports",
    "KnownCVECount",
    "KnownCVEs",
    "MixedCVE",
    "RootFingerprintCount",
    "RootFingerprints",
    "MixedRootFingerprint",
    "ConfirmedTargetReports",
    "TargetRootFingerprintCount",
    "MixedTargetRootFingerprint",
]
PAIRWISE_FIELDS = [
    "Reference",
    "ComparedReports",
    "ReferenceClasses",
    "PredictedGroups",
    "TruePositivePairs",
    "FalsePositivePairs",
    "FalseNegativePairs",
    "PairwisePrecision",
    "PairwiseRecall",
    "PairwiseF1",
]
CVE_FIELDS = [
    "CVE",
    "Project",
    "Reports",
    "CrashSageGroups",
]


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def root_fingerprint(row: Mapping[str, str]) -> Tuple[str, str, str, str] | None:
    project = str(row.get("Project") or "").strip()
    crash_file = str(row.get("CrashFile") or "").strip()
    function = str(row.get("CrashFunction") or "").strip()
    bug_type = str(row.get("BugType") or "").strip()
    if not all((project, crash_file, function, bug_type)):
        return None
    return project, crash_file, function, bug_type


def _truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _load_current_fingerprints(
    mapping_rows: Sequence[Mapping[str, str]],
    db_root: Path,
) -> Dict[str, Tuple[str, str, str, str]]:
    entries: Dict[Tuple[str, str], Mapping[str, object]] = {}
    for project in sorted({row["Project"] for row in mapping_rows}):
        for yaml_path in sorted(
            (db_root / project / "crash").glob("*/crash_analysis.yaml")
        ):
            driver = yaml_path.parent.name
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or []
            for item in data:
                if isinstance(item, dict):
                    for local_id, entry in item.items():
                        if isinstance(entry, dict):
                            entries[(project, f"{driver}_{local_id}")] = entry

    fingerprints = {}
    for row in mapping_rows:
        key = (row["Project"], row["CrashID"])
        entry = entries.get(key)
        if entry is None:
            raise ValueError(f"Missing crash entry: {key}")
        crash_info = str(entry.get("crash_info") or "")
        if crash_info.startswith("|"):
            crash_info = crash_info[1:].lstrip("\n")
        parsed = parse_sanitizer_output(crash_info)
        crash_file = re.sub(
            r":\d+(?::\d+)?$",
            "",
            str(parsed.get("first_in_project_frame") or ""),
        )
        fingerprints[row["CrashID"]] = (
            row["Project"],
            str(parsed.get("bug_type") or row.get("BugType") or ""),
            crash_file,
            str(parsed.get("first_in_project_function") or ""),
        )
    return fingerprints


def _pairwise_metrics(
    reference_name: str,
    ids: Sequence[str],
    reference: Mapping[str, str],
    groups: Mapping[str, str],
) -> Dict[str, object]:
    tp = fp = fn = 0
    for left, right in itertools.combinations(ids, 2):
        same_reference = reference[left] == reference[right]
        same_group = groups[left] == groups[right]
        if same_reference and same_group:
            tp += 1
        elif same_group:
            fp += 1
        elif same_reference:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "Reference": reference_name,
        "ComparedReports": len(ids),
        "ReferenceClasses": len(set(reference.values())),
        "PredictedGroups": len({groups[index] for index in ids}),
        "TruePositivePairs": tp,
        "FalsePositivePairs": fp,
        "FalseNegativePairs": fn,
        "PairwisePrecision": round(precision, 6),
        "PairwiseRecall": round(recall, 6),
        "PairwiseF1": round(f1, 6),
    }


def audit(
    crashsage_mapping: Path,
    evidence_path: Path,
    baseline_path: Path | None = None,
    db_root: Path | None = None,
) -> tuple[List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]], Dict[str, object]]:
    crashsage_rows = _read_csv(crashsage_mapping)
    evidence_rows = _read_csv(evidence_path)
    evidence = {row["CrashID"]: row for row in evidence_rows}
    crashsage = {
        row["CrashID"]: row["RepresentativeCrashID"] for row in crashsage_rows
    }
    ids = list(crashsage)
    cves: Dict[str, str] = {}
    for crash_id in ids:
        match = CVE_RE.search(str(evidence.get(crash_id, {}).get("PublicReference") or ""))
        if match:
            cves[crash_id] = match.group(0)
    fingerprints = {
        crash_id: fingerprint
        for crash_id in ids
        if (fingerprint := root_fingerprint(evidence.get(crash_id, {}))) is not None
    }
    target_ids: List[str] = []
    structural_fingerprints: Dict[str, Tuple[str, str, str, str]] = {}
    if baseline_path is not None:
        baseline = {
            row["CrashID"]: row for row in _read_csv(baseline_path)
        }
        target_ids = [
            crash_id
            for crash_id in ids
            if crash_id in baseline
            and _truth(
                baseline[crash_id].get("MemberGroundTruth")
                or baseline[crash_id]["GroundTruth"]
            )
        ]
    if db_root is not None:
        structural_fingerprints = _load_current_fingerprints(
            crashsage_rows,
            db_root,
        )

    group_rows = []
    pairwise_rows = []
    grouped = defaultdict(list)
    for crash_id in ids:
        grouped[crashsage[crash_id]].append(crash_id)
    for representative, members in sorted(grouped.items()):
        member_cves = {
            cves[member] for member in members if member in cves
        }
        member_fingerprints = {
            fingerprints[member] for member in members if member in fingerprints
        }
        target_members = [member for member in members if member in target_ids]
        target_fingerprints = {
            structural_fingerprints[member]
            for member in target_members
            if structural_fingerprints.get(member)
        }
        project = str(evidence.get(representative, {}).get("Project") or "")
        if not project:
            project = next(
                (
                    str(evidence[member].get("Project") or "")
                    for member in members
                    if member in evidence
                ),
                "",
            )
        group_rows.append(
            {
                "Project": project,
                "RepresentativeCrashID": representative,
                "GroupSize": len(members),
                "EvidenceCoveredMembers": sum(member in evidence for member in members),
                "KnownCVEReports": sum(member in cves for member in members),
                "KnownCVECount": len(member_cves),
                "KnownCVEs": ";".join(sorted(member_cves)),
                "MixedCVE": str(len(member_cves) > 1).lower(),
                "RootFingerprintCount": len(member_fingerprints),
                "RootFingerprints": ";".join(
                    "|".join(value) for value in sorted(member_fingerprints)
                ),
                "MixedRootFingerprint": str(len(member_fingerprints) > 1).lower(),
                "ConfirmedTargetReports": len(target_members),
                "TargetRootFingerprintCount": len(target_fingerprints),
                "MixedTargetRootFingerprint": str(
                    len(target_fingerprints) > 1
                ).lower(),
            }
        )
    if cves:
        pairwise_rows.append(
            _pairwise_metrics("public CVE", list(cves), cves, crashsage)
        )
    if fingerprints:
        pairwise_rows.append(
            _pairwise_metrics(
                "crash-site root fingerprint",
                list(fingerprints),
                fingerprints,
                crashsage,
            )
        )
    if target_ids and structural_fingerprints:
        pairwise_rows.append(
            _pairwise_metrics(
                "confirmed-target structural root fingerprint",
                target_ids,
                {
                    crash_id: structural_fingerprints[crash_id]
                    for crash_id in target_ids
                },
                crashsage,
            )
        )

    cve_rows = []
    for cve in sorted(set(cves.values())):
        members = [crash_id for crash_id, value in cves.items() if value == cve]
        project = str(evidence[members[0]].get("Project") or "")
        cve_rows.append(
            {
                "CVE": cve,
                "Project": project,
                "Reports": len(members),
                "CrashSageGroups": len({crashsage[index] for index in members}),
            }
        )

    summary = {
        "population_reports": len(ids),
        "manual_evidence_covered_reports": sum(crash_id in evidence for crash_id in ids),
        "public_cve_covered_reports": len(cves),
        "public_cves": sorted(set(cves.values())),
        "root_fingerprint_covered_reports": len(fingerprints),
        "confirmed_target_reports": len(target_ids),
        "confirmed_target_structural_fingerprints": len(
            {structural_fingerprints[crash_id] for crash_id in target_ids}
        )
        if target_ids
        else 0,
        "groups_containing_confirmed_targets": sum(
            int(row["ConfirmedTargetReports"]) > 0 for row in group_rows
        ),
        "mixed_confirmed_target_root_groups": sum(
            row["MixedTargetRootFingerprint"] == "true" for row in group_rows
        ),
        "groups": len(group_rows),
        "groups_with_known_cve": sum(
            int(row["KnownCVEReports"]) > 0 for row in group_rows
        ),
        "mixed_cve_groups": sum(
            row["MixedCVE"] == "true" for row in group_rows
        ),
        "root_evidence_covered_reports": len(fingerprints),
        "mixed_root_fingerprint_groups": sum(
            row["MixedRootFingerprint"] == "true" for row in group_rows
        ),
        "pairwise_metrics": pairwise_rows,
        "limitations": [
            "CVE consistency is measured only on reports linked to explicit public CVE evidence.",
            "Root fingerprints are available only where saved manual evidence provides project, crash file, function, and bug type.",
            "Absence of a mixed-evidence group does not prove root-cause correctness for groups outside the covered subset.",
        ],
    }
    return group_rows, pairwise_rows, cve_rows, summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--crashsage-mapping",
        type=Path,
        default=Path(
            "results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv"
        ),
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path(
            "results/revision_20260722/manual_ground_truth_evidence.csv"
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(
            "results/paper_aligned_20261028_arbitrated/final_v4_expanded_1217.csv"
        ),
    )
    parser.add_argument(
        "--db-root",
        type=Path,
        default=Path("external_database"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/cve_rootcause_audit_20261030"),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    group_rows, pairwise_rows, cve_rows, summary = audit(
        args.crashsage_mapping,
        args.evidence,
        args.baseline,
        args.db_root,
    )
    _write_csv(args.output_dir / "cve_root_group_audit.csv", GROUP_FIELDS, group_rows)
    _write_csv(
        args.output_dir / "cve_root_pairwise_metrics.csv",
        PAIRWISE_FIELDS,
        pairwise_rows,
    )
    _write_csv(args.output_dir / "cve_coverage.csv", CVE_FIELDS, cve_rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "cve_rootcause_audit_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"audited {summary['public_cve_covered_reports']} public-CVE reports "
        f"across {len(summary['public_cves'])} CVEs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
