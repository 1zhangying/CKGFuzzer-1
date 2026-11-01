#!/usr/bin/env python3
"""Generate the remaining reviewer-response audits from frozen artifacts.

This script performs no fuzzing and makes no LLM calls. It consolidates the
existing 1,217-report predictions, the 145-report blind audit, the frozen
representative mapping, driver sources, and repeated prompt runs into one
revision package.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import random
import re
import statistics
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PROJECTS = (
    "c-ares",
    "cjson",
    "dlt-daemon",
    "expat",
    "faad2",
    "isotp-c",
    "jansson",
    "json-c",
    "libmad",
    "libmspack",
    "libpcap",
    "libsndfile",
    "tinyxml2",
    "zlib",
)

CATEGORY_TARGET = "confirmed_target"
CATEGORY_NON_TARGET = "confirmed_non_target"
CATEGORY_OUT_OF_SCOPE = "out_of_scope"
CATEGORY_UNRESOLVED = "unresolved"

DRIVER_EVIDENCE_TYPES = {
    "driver_misuse_triage_with_local_evidence",
    "harness_root_cause",
    "local_driver_contract_violation",
    "local_noise_triage",
}
OUT_OF_SCOPE_EVIDENCE_TYPES = {
    "leak_only_non_security_signal",
    "no_memory_safety_signal",
}

XLSX_NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def truth(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def key(row: Mapping[str, str]) -> tuple[str, str]:
    return str(row.get("Project", "")), str(row.get("CrashID", ""))


def metrics(labels: Sequence[bool], predictions: Sequence[bool]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, predictions):
        if prediction and label:
            tp += 1
        elif prediction:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "Samples": len(labels),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def xlsx_rows(path: Path, sheet_name: str = "xl/worksheets/sheet2.xml") -> list[dict[str, str]]:
    """Read an XLSX worksheet without requiring openpyxl."""
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read(sheet_name))
    rows: list[dict[str, str]] = []
    for row in root.findall(".//x:sheetData/x:row", XLSX_NS):
        values: dict[str, str] = {}
        for cell in row.findall("x:c", XLSX_NS):
            reference = cell.get("r", "")
            column = "".join(char for char in reference if char.isalpha())
            text = "".join(node.text or "" for node in cell.findall(".//x:t", XLSX_NS))
            if not text:
                value = cell.find("x:v", XLSX_NS)
                text = value.text if value is not None else ""
            values[column] = text
        rows.append(values)
    return rows


def load_145_audit(repo: Path) -> tuple[list[dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    workbook = (
        repo
        / "outputs/unresolved_dual_blind_review_20261031"
        / "unresolved_145_arbitration_final_consensus_20261101.xlsx"
    )
    group_rows = xlsx_rows(workbook)
    group_by_rep: dict[str, dict[str, Any]] = {}
    for row in group_rows:
        group_id = row.get("A", "")
        if not group_id.startswith("G"):
            continue
        final_label = row.get("P", "")
        rationale = row.get("Q", "")
        if final_label == "confirmed_target":
            category = CATEGORY_TARGET
        else:
            category = CATEGORY_NON_TARGET
        group_by_rep[row.get("C", "")] = {
            "ReviewGroup": group_id,
            "Project": row.get("B", ""),
            "RepresentativeCrashID": row.get("C", ""),
            "ReviewerALabel": row.get("D", ""),
            "ReviewerBLabel": row.get("E", ""),
            "Agreement": row.get("N", ""),
            "FinalBinaryLabel": final_label,
            "FinalCategory": category,
            "ReviewerANotes": row.get("H", ""),
            "ReviewerBNotes": row.get("I", ""),
            "ArbitrationRationale": rationale,
        }

    mapping_path = (
        repo
        / "fuzzing_llm_engine/results/revision_20261026"
        / "unresolved_ablation/unresolved_mapping_145.csv"
    )
    mapping = read_csv(mapping_path)
    group_analysis_path = (
        repo
        / "fuzzing_llm_engine/results/revision_20261026"
        / "unresolved_ablation/unresolved_32_group_analysis.csv"
    )
    group_analysis = {
        row["RepresentativeCrashID"]: row for row in read_csv(group_analysis_path)
    }
    report_rows: list[dict[str, Any]] = []
    report_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for row in mapping:
        representative = row["RepresentativeCrashID"]
        group = group_by_rep[representative]
        analysis = group_analysis.get(representative, {})
        out = {
            **row,
            **group,
            "GroupSize": analysis.get("GroupSize", ""),
            "CrashFunction": analysis.get("CrashFunction", ""),
            "KnownReference": analysis.get("KnownReference", ""),
            "HistoricalIssue": analysis.get("HistoricalIssue", ""),
        }
        report_rows.append(out)
        report_lookup[key(row)] = out
    return list(group_by_rep.values()), report_lookup


def current_ground_truth(
    repo: Path,
) -> tuple[list[dict[str, str]], dict[tuple[str, str], bool]]:
    results = repo / "fuzzing_llm_engine/results"
    base = read_csv(results / "all_crashes_v0_v4_groundtruth.csv")
    changes = read_csv(
        results
        / "v3v4_optimized_20261101/current_gt_eval_v4/ground_truth_changes.csv"
    )
    positives = {key(row) for row in base if truth(row["GroundTruth"])}
    positives.update(key(row) for row in changes)
    return base, {key(row): key(row) in positives for row in base}


def build_four_state_audit(
    repo: Path,
    base: Sequence[dict[str, str]],
    current_positive: Mapping[tuple[str, str], bool],
    audit_145: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    evidence_path = (
        repo
        / "fuzzing_llm_engine/results/revision_20260722"
        / "manual_ground_truth_evidence.csv"
    )
    evidence = {key(row): row for row in read_csv(evidence_path)}
    rows: list[dict[str, Any]] = []
    for base_row in base:
        row_key = key(base_row)
        if row_key in audit_145:
            audit = audit_145[row_key]
            category = str(audit["FinalCategory"])
            source = "145_report_blind_audit"
            detail = str(audit["ArbitrationRationale"])
        elif current_positive[row_key]:
            category = CATEGORY_TARGET
            source = "current_binary_ground_truth"
            detail = ""
        elif row_key in evidence:
            evidence_row = evidence[row_key]
            evidence_type = evidence_row["EvidenceType"]
            if evidence_type in DRIVER_EVIDENCE_TYPES:
                category = CATEGORY_NON_TARGET
            elif evidence_type in OUT_OF_SCOPE_EVIDENCE_TYPES:
                category = CATEGORY_OUT_OF_SCOPE
            else:
                category = CATEGORY_UNRESOLVED
            source = evidence_type
            detail = evidence_row.get("DecisionNote", "")
        else:
            # The two new projects have binary ground truth in the current
            # dataset, but no row-level manual evidence export in the legacy
            # 1,021-report file. Keep them unresolved in the strict sensitivity
            # analysis instead of silently treating missing evidence as proof.
            category = CATEGORY_UNRESOLVED
            source = "binary_negative_without_unified_manual_evidence"
            detail = "Evidence type is not represented in the consolidated manual-evidence export."
        rows.append(
            {
                "Project": base_row["Project"],
                "CrashID": base_row["CrashID"],
                "TriageLabel": base_row.get("TriageLabel", ""),
                "BinaryGroundTruth": "true" if current_positive[row_key] else "false",
                "FourStateLabel": category,
                "EvidenceSource": source,
                "EvidenceDetail": detail,
            }
        )
    counts = Counter(row["FourStateLabel"] for row in rows)
    return rows, dict(counts)


def prediction_rows(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    return {key(row): row for row in read_csv(path)}


def evaluate_predictions(
    base: Sequence[dict[str, str]],
    current_positive: Mapping[tuple[str, str], bool],
    predictions: Mapping[tuple[str, str], Mapping[str, str]],
) -> dict[str, Any]:
    labels = [current_positive[key(row)] for row in base]
    values = [truth(predictions[key(row)]["Prediction"]) for row in base]
    return metrics(labels, values)


def r1_2_sensitivity(
    repo: Path,
    base: Sequence[dict[str, str]],
    current_positive: Mapping[tuple[str, str], bool],
    audit_145: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results = repo / "fuzzing_llm_engine/results"
    predictions = prediction_rows(
        results
        / "v3v4_optimized_20261101/current_gt_eval_v4"
        / "final_v4_expanded_current_gt.csv"
    )
    non_unanimous_report_keys = {
        row_key
        for row_key, row in audit_145.items()
        if row["Agreement"].lower() == "disagree"
        or not row["ReviewerALabel"]
        or not row["ReviewerBLabel"]
    }
    scenario_rows = []
    for scenario, excluded, force_target in (
        ("operational_binary_all_1217", set(), set()),
        ("non_unanimous_audit_as_target_sensitivity", set(), non_unanimous_report_keys),
    ):
        kept = [row for row in base if key(row) not in excluded]
        labels = [current_positive[key(row)] or key(row) in force_target for row in kept]
        values = [truth(predictions[key(row)]["Prediction"]) for row in kept]
        scenario_rows.append({"Scenario": scenario, **metrics(labels, values)})
    return scenario_rows


def r1_2_evidence_exports(
    audit_reports: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    targets = []
    for row in audit_reports.values():
        if row["FinalCategory"] != CATEGORY_TARGET:
            continue
        references = []
        if row.get("KnownReference"):
            references.append(str(row["KnownReference"]))
        notes = " ".join(
            (str(row.get("ReviewerANotes", "")), str(row.get("ReviewerBNotes", "")))
        )
        references.extend(
            match.group(0)
            for match in re.finditer(r"(?:CVE-\d{4}-\d+|PR\s*#\d+)", notes)
        )
        targets.append(
            {
                "Project": row["Project"],
                "CrashID": row["CrashID"],
                "RepresentativeCrashID": row["RepresentativeCrashID"],
                "ReviewGroup": row["ReviewGroup"],
                "PublicReference": "; ".join(sorted(set(references))),
                "V4HistoricalIssue": row["HistoricalIssue"],
                "ReviewerANotes": row["ReviewerANotes"],
                "ReviewerBNotes": row["ReviewerBNotes"],
                "ArbitrationRationale": row["ArbitrationRationale"],
            }
        )
    taxonomy = []
    grouped = Counter(
        (row["FinalCategory"], "145_report_blind_audit")
        for row in audit_reports.values()
    )
    for (category, evidence_source), count in sorted(grouped.items()):
        taxonomy.append(
            {
                "Category": category,
                "EvidenceSource": evidence_source,
                "Reports": count,
            }
        )
    return sorted(targets, key=lambda row: (row["Project"], row["CrashID"])), taxonomy


def r2_3_v0_v1(repo: Path, base: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = repo / "fuzzing_llm_engine/results"
    v0 = {key(row): row for row in base}
    v1 = {
        key(row): row
        for row in read_csv(
            results
            / "frozen_baseline_1217"
            / "final_v1_expanded_1217.csv"
        )
    }
    mapping = read_csv(
        results
        / "dedup_schema2_14projects_20261027"
        / "dedup_mapping_14projects.csv"
    )
    retained = {key(row) for row in mapping}
    current_positive = {key(row): truth(row["GroundTruth"]) for row in base}
    changed = read_csv(
        results
        / "v3v4_optimized_20261101/current_gt_eval_v4"
        / "ground_truth_changes.csv"
    )
    current_positive.update({key(row): True for row in changed})

    scenarios = [
        ("V0_full_population", set(v0), "V0_IsApiBug", v0),
        ("V0_restricted_to_V1_retained", retained, "V0_IsApiBug", v0),
        ("V1_full_population", set(v1), "Prediction", v1),
        ("V1_retained_population", retained, "Prediction", v1),
    ]
    summary = []
    previous: dict[str, Any] | None = None
    for name, keys, column, source in scenarios:
        ordered = sorted(keys)
        labels = [current_positive[item] for item in ordered]
        values = [truth(source[item][column]) for item in ordered]
        row = {"Scenario": name, **metrics(labels, values)}
        if previous is not None:
            for field in ("Precision", "Recall", "F1"):
                row[f"Delta{field}"] = float(row[field]) - float(previous[field])
        summary.append(row)
        if name == "V0_restricted_to_V1_retained":
            previous = row

    flip_rows = []
    for row_key in sorted(retained):
        v0_prediction = truth(v0[row_key]["V0_IsApiBug"])
        v1_prediction = truth(v1[row_key]["Prediction"])
        if v0_prediction == v1_prediction:
            continue
        flip_rows.append(
            {
                "Project": row_key[0],
                "CrashID": row_key[1],
                "GroundTruth": str(current_positive[row_key]).lower(),
                "TriageLabel": v0[row_key].get("TriageLabel", ""),
                "V0Prediction": str(v0_prediction).lower(),
                "V1Prediction": str(v1_prediction).lower(),
                "FlipDirection": (
                    "positive_to_negative"
                    if v0_prediction and not v1_prediction
                    else "negative_to_positive"
                ),
            }
        )
    return summary, flip_rows


def target_diversity(repo: Path, current_positive: Mapping[tuple[str, str], bool]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = repo / "fuzzing_llm_engine/results"
    crash_rows = read_csv(
        results / "prompt_ablation_current_gt_20261101/current_gt_1217.csv"
    )
    crash_counts = Counter(row["Project"] for row in crash_rows)
    positive_counts = Counter(
        row["Project"] for row in crash_rows if current_positive[key(row)]
    )
    database = repo / "fuzzing_llm_engine/external_database"
    details = []
    for project in PROJECTS:
        api_path = database / project / "api_list.json"
        apis = json.loads(api_path.read_text(encoding="utf-8"))
        driver_files = sorted((database / project / "fuzz_driver").glob("*.c"))
        driver_files += sorted((database / project / "fuzz_driver").glob("*.cc"))
        multi_call = lifecycle = 0
        calls_per_driver = []
        for driver_path in driver_files:
            source = driver_path.read_text(encoding="utf-8", errors="replace")
            used: list[str] = []
            for api in sorted(set(apis), key=len, reverse=True):
                short_name = api.split("::")[-1]
                if "::" in api:
                    pattern = re.compile(
                        r"(?:\b|\.|->)" + re.escape(short_name) + r"\s*\("
                    )
                else:
                    pattern = re.compile(r"\b" + re.escape(api) + r"\s*\(")
                if pattern.search(source):
                    used.append(api)
            calls_per_driver.append(len(used))
            is_multi = len(used) >= 2
            has_lifecycle_shape = is_multi and (
                any(
                    re.search(
                        r"(init|create|open|new|alloc|receive|load)",
                        api,
                        re.IGNORECASE,
                    )
                    for api in used
                )
                or any(
                    re.search(
                        r"(free|destroy|close|put|end|decref|delete)",
                        api,
                        re.IGNORECASE,
                    )
                    for api in used
                )
            )
            multi_call += int(is_multi)
            lifecycle += int(has_lifecycle_shape)
        driver_count = len(driver_files)
        details.append(
            {
                "Project": project,
                "CrashReports": crash_counts[project],
                "TargetReports": positive_counts[project],
                "Drivers": driver_count,
                "MultiCallDrivers": multi_call,
                "MultiCallRate": multi_call / driver_count if driver_count else 0.0,
                "LifecyclePatternDrivers": lifecycle,
                "LifecyclePatternRate": lifecycle / driver_count if driver_count else 0.0,
                "MedianDistinctAPICallsPerDriver": (
                    statistics.median(calls_per_driver) if calls_per_driver else 0.0
                ),
            }
        )
    examples = [
        {
            "Project": "dlt-daemon",
            "Driver": "dlt-daemon_fuzz_driver_False_qwen3-coder-flash_11",
            "ObservedAPIs": (
                "dlt_filter_init; dlt_filter_load; dlt_filter_add; "
                "dlt_filter_find; dlt_filter_delete; dlt_filter_free"
            ),
            "CoveredPattern": "initialization -> mutation -> lookup -> cleanup",
        },
        {
            "Project": "isotp-c",
            "Driver": "isotp-c_fuzz_driver_False_qwen3-coder-flash_10",
            "ObservedAPIs": (
                "isotp_receive; isotp_continue_receive; allocate; free_allocated"
            ),
            "CoveredPattern": "handle creation -> stateful continuation -> cleanup",
        },
    ]
    return details, examples


def load_current_predictions(
    repo: Path,
) -> dict[tuple[str, str], dict[str, str]]:
    return prediction_rows(
        repo
        / "fuzzing_llm_engine/results/v3v4_optimized_20261101"
        / "current_gt_eval_v4/final_v4_expanded_current_gt.csv"
    )


def prompt_stability(repo: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = repo / "fuzzing_llm_engine/results"
    observation_path = (
        results
        / "prompt_ablation_v3v4_optimized_20261101"
        / "aggregate_six_run/prompt_ablation_observations.csv"
    )
    observations = read_csv(observation_path)
    by_variant: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in observations:
        by_variant[row["Prompt"]].append(row)

    rng = random.Random(20261101)
    summary_rows = []
    for variant in ("P0", "P1", "P2", "P3"):
        rows = by_variant[variant]
        f1_values = [float(row["F1"]) for row in rows]
        boot = []
        for _ in range(10_000):
            sample = [f1_values[rng.randrange(len(f1_values))] for _ in f1_values]
            boot.append(statistics.mean(sample))
        boot.sort()
        summary_rows.append(
            {
                "Prompt": variant,
                "Runs": len(rows),
                "PrecisionMean": statistics.mean(float(row["Precision"]) for row in rows),
                "PrecisionSD": statistics.pstdev(float(row["Precision"]) for row in rows),
                "RecallMean": statistics.mean(float(row["Recall"]) for row in rows),
                "RecallSD": statistics.pstdev(float(row["Recall"]) for row in rows),
                "F1Mean": statistics.mean(f1_values),
                "F1SD": statistics.pstdev(f1_values),
                "F1Min": min(f1_values),
                "F1Max": max(f1_values),
                "F1Bootstrap95Low": boot[int(0.025 * len(boot))],
                "F1Bootstrap95High": boot[int(0.975 * len(boot)) - 1],
            }
        )

    expanded_path = (
        results
        / "prompt_ablation_v3v4_optimized_20261101"
        / "final_analysis/prompt_ablation_expanded_1217.csv"
    )
    expanded = read_csv(expanded_path)
    lookup: dict[str, dict[str, dict[tuple[str, str], bool]]] = defaultdict(dict)
    for row in expanded:
        lookup[row["Variant"]].setdefault(row["Run"], {})[key(row)] = truth(
            row["Prediction"]
        )
    # Add the formal P0/P3 anchors from the current V3/V4 predictions.
    mapping = read_csv(
        results
        / "dedup_schema2_14projects_20261027"
        / "dedup_mapping_14projects.csv"
    )
    all_keys = sorted({key(row) for row in expanded})
    for variant, prediction_file in (
        ("P0", "final_v3_expanded_1217.csv"),
        ("P3", "final_v4_expanded_1217.csv"),
    ):
        source = {
            key(row): truth(row["Prediction"])
            for row in read_csv(results / "v3v4_optimized_20261101" / prediction_file)
        }
        lookup[variant]["formal_anchor"] = {item: source.get(item, False) for item in all_keys}

    report_flip_rows = []
    for variant in ("P0", "P1", "P2", "P3"):
        runs = lookup[variant]
        for item in all_keys:
            values = [run[item] for run in runs.values()]
            if len(set(values)) > 1:
                report_flip_rows.append(
                    {
                        "Prompt": variant,
                        "Project": item[0],
                        "CrashID": item[1],
                        "RunsObserved": len(values),
                        "PositivePredictions": sum(values),
                        "AnyFlip": "true",
                    }
                )
    return summary_rows, report_flip_rows


def cross_model_metrics(
    repo: Path,
) -> list[dict[str, Any]]:
    results = repo / "fuzzing_llm_engine/results"
    default_path = (
        results
        / "v3v4_optimized_20261101/current_gt_eval_v4/overall_metrics.csv"
    )
    alternative_path = (
        results
        / "frozen_prompt_rerun_20261101/current_v4_calibrated_20261101_final_v3"
        / "overall_metrics.csv"
    )
    qwen_flash_path = (
        results
        / "frozen_prompt_rerun_20261101/qwen-flash_current_gt_215/final/metrics.csv"
    )
    glm_path = (
        results
        / "frozen_prompt_rerun_20261101/glm-5.3-flash_current_v4_code"
        / "overall_metrics.csv"
    )
    output = []
    default = read_csv(default_path)[0]
    output.append({"Model": "qwen3-coder-flash", **default})
    alternatives = read_csv(alternative_path)
    qwen_flash = [
        row for row in read_csv(qwen_flash_path)
        if float(row.get("Samples", 0)) == 1217
    ][0]
    output.append(qwen_flash)
    output.extend(
        row for row in alternatives if row["Model"] != "qwen-flash"
    )
    output.extend(read_csv(glm_path))
    for row in output:
        row["Samples"] = int(row["Samples"])
        for field in ("TP", "FP", "TN", "FN"):
            row[field] = int(row[field])
        for field in ("Precision", "Recall", "F1"):
            row[field] = float(row[field])
    return output


def order_sensitivity(repo: Path, trials: int, seed: int) -> dict[str, Any]:
    results = repo / "fuzzing_llm_engine/results"
    rows = read_csv(
        results
        / "dedup_schema2_14projects_20261027"
        / "dedup_mapping_14projects.csv"
    )

    def cluster(order: Sequence[Mapping[str, str]]) -> tuple[list[str], dict[str, str]]:
        representatives: list[str] = []
        exact: dict[str, str] = {}
        stack: dict[str, str] = {}
        members: dict[str, list[str]] = {}
        assignment: dict[str, str] = {}
        for row in order:
            crash_id = row["CrashID"]
            candidates: list[tuple[int, int, str]] = []
            for signature_column, index, level in (
                ("Signature", exact, 0),
                ("StackSignature", stack, 1),
            ):
                signature = row.get(signature_column, "")
                if not signature or signature not in index:
                    continue
                representative = index[signature]
                if len(members[representative]) >= 7:
                    continue
                candidates.append(
                    (representatives.index(representative), level, representative)
                )
            if candidates:
                representative = min(candidates)[2]
            else:
                representative = crash_id
                representatives.append(crash_id)
                members[representative] = []
                if row.get("Signature"):
                    exact[row["Signature"]] = representative
                if row.get("StackSignature"):
                    stack[row["StackSignature"]] = representative
            members[representative].append(crash_id)
            assignment[crash_id] = representative
        return representatives, assignment

    ids = [row["CrashID"] for row in rows]
    original_reps, original_assignment = cluster(rows)

    def pair_set(assignment: Mapping[str, str]) -> set[tuple[str, str]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for crash_id, representative in assignment.items():
            grouped[representative].append(crash_id)
        pairs: set[tuple[str, str]] = set()
        for members in grouped.values():
            pairs.update(itertools.combinations(sorted(members), 2))
        return pairs

    original_pairs = pair_set(original_assignment)
    evidence_path = (
        results / "revision_20260722/manual_ground_truth_evidence.csv"
    )
    evidence = {key(row): row for row in read_csv(evidence_path)}
    cve_reference: dict[str, str] = {}
    root_reference: dict[str, tuple[str, str, str, str]] = {}
    for row in rows:
        crash_id = row["CrashID"]
        evidence_row = evidence.get(key(row), {})
        cve_match = re.search(
            r"CVE-\d{4}-\d+",
            str(evidence_row.get("PublicReference", "")),
        )
        if cve_match:
            cve_reference[crash_id] = cve_match.group(0)
        fingerprint_fields = ("Project", "CrashFile", "CrashFunction", "BugType")
        if all(evidence_row.get(field) for field in fingerprint_fields):
            root_reference[crash_id] = tuple(
                str(evidence_row[field]) for field in fingerprint_fields
            )

    def reference_pair_metrics(
        assignment: Mapping[str, str],
        reference: Mapping[str, Any],
    ) -> tuple[float, float]:
        true_positive = false_positive = false_negative = 0
        for left, right in itertools.combinations(reference, 2):
            same_reference = reference[left] == reference[right]
            same_group = assignment[left] == assignment[right]
            if same_reference and same_group:
                true_positive += 1
            elif same_group:
                false_positive += 1
            elif same_reference:
                false_negative += 1
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        return precision, recall

    by_project: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_project[row["Project"]].append(row)
    rng = random.Random(seed)
    representative_counts = []
    pair_jaccards = []
    pair_precisions = []
    pair_recalls = []
    cve_pair_precisions = []
    cve_pair_recalls = []
    root_pair_precisions = []
    root_pair_recalls = []
    for _ in range(trials):
        order = []
        for project in sorted(by_project):
            project_rows = list(by_project[project])
            rng.shuffle(project_rows)
            order.extend(project_rows)
        representatives, assignment = cluster(order)
        generated_pairs = pair_set(assignment)
        tp = len(original_pairs & generated_pairs)
        fp = len(generated_pairs - original_pairs)
        fn = len(original_pairs - generated_pairs)
        representative_counts.append(len(representatives))
        pair_jaccards.append(tp / len(original_pairs | generated_pairs))
        pair_precisions.append(tp / (tp + fp) if tp + fp else 1.0)
        pair_recalls.append(tp / (tp + fn) if tp + fn else 1.0)
        cve_precision, cve_recall = reference_pair_metrics(
            assignment,
            cve_reference,
        )
        root_precision, root_recall = reference_pair_metrics(
            assignment,
            root_reference,
        )
        cve_pair_precisions.append(cve_precision)
        cve_pair_recalls.append(cve_recall)
        root_pair_precisions.append(root_precision)
        root_pair_recalls.append(root_recall)
    return {
        "trials": trials,
        "seed": seed,
        "retained_reports": len(rows),
        "original_representatives": len(original_reps),
        "representative_count_min": min(representative_counts),
        "representative_count_mean": statistics.mean(representative_counts),
        "representative_count_max": max(representative_counts),
        "pair_jaccard_min": min(pair_jaccards),
        "pair_jaccard_mean": statistics.mean(pair_jaccards),
        "pair_jaccard_max": max(pair_jaccards),
        "pair_precision_mean": statistics.mean(pair_precisions),
        "pair_recall_mean": statistics.mean(pair_recalls),
        "cve_pair_precision_min": min(cve_pair_precisions),
        "cve_pair_precision_mean": statistics.mean(cve_pair_precisions),
        "cve_pair_precision_max": max(cve_pair_precisions),
        "cve_pair_recall_min": min(cve_pair_recalls),
        "cve_pair_recall_mean": statistics.mean(cve_pair_recalls),
        "cve_pair_recall_max": max(cve_pair_recalls),
        "root_pair_precision_min": min(root_pair_precisions),
        "root_pair_precision_mean": statistics.mean(root_pair_precisions),
        "root_pair_precision_max": max(root_pair_precisions),
        "root_pair_recall_min": min(root_pair_recalls),
        "root_pair_recall_mean": statistics.mean(root_pair_recalls),
        "root_pair_recall_max": max(root_pair_recalls),
    }


def model_metadata(repo: Path) -> dict[str, Any]:
    files = [
        repo
        / "fuzzing_llm_engine/results/v3v4_optimized_20261101"
        / "current_gt_eval_v4/overall_metrics.csv",
        repo
        / "fuzzing_llm_engine/results/prompt_ablation_v3v4_optimized_20261101"
        / "aggregate_six_run/prompt_ablation_summary.csv",
        repo
        / "fuzzing_llm_engine/results/frozen_prompt_rerun_20261101"
        / "current_v4_calibrated_20261101_final_v3/overall_metrics.csv",
    ]
    mtimes = [path.stat().st_mtime for path in files if path.exists()]
    from datetime import datetime, timezone

    access_start = datetime.fromtimestamp(min(mtimes), timezone.utc).isoformat()
    access_end = datetime.fromtimestamp(max(mtimes), timezone.utc).isoformat()
    return {
        "default_model_id": "qwen3-coder-flash",
        "api_style": "OpenAI-compatible chat-completions",
        "provider": "Alibaba Cloud Model Studio / DashScope hosted endpoint",
        "primary_endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "temperature": 0.0,
        "context_window_tokens": 1_000_000,
        "timeout_seconds": 300,
        "max_retries": 3,
        "json_retry": "Only when structured-output validation fails; original response is retained.",
        "artifact_access_window_utc": {
            "first_recorded": access_start,
            "last_recorded": access_end,
        },
        "alternative_backends": [
            "qwen-flash",
            "qwen3.8-flash",
            "deepseek-v4.1-flash-1017",
            "gpt-5.6-sol",
            "glm-5.3-flash",
        ],
        "selection_rationale": (
            "The default model was selected for code-oriented analysis, stable "
            "OpenAI-compatible access, low expected latency, and a one-million-token "
            "context window sufficient for reconstructed crash evidence. Backend "
            "sensitivity is tested separately; no ground-truth labels, project names, "
            "or expected CVE identifiers are included in prompts."
        ),
        "reproducibility_limit": (
            "The provider exposes a hosted model alias rather than an immutable local "
            "weight snapshot. Saved prompts, responses, request parameters, timestamps, "
            "and output hashes are therefore the reproducibility record."
        ),
    }


def write_summary(
    path: Path,
    binary_counts: Mapping[str, int],
    audit_counts: Mapping[str, int],
    sensitivity: Sequence[Mapping[str, Any]],
    r23_summary: Sequence[Mapping[str, Any]],
    r23_flips: Sequence[Mapping[str, Any]],
    diversity: Sequence[Mapping[str, Any]],
    stability: Sequence[Mapping[str, Any]],
    cross_model: Sequence[Mapping[str, Any]],
    order_result: Mapping[str, Any],
) -> None:
    driver_total = sum(int(row["Drivers"]) for row in diversity)
    multi_total = sum(int(row["MultiCallDrivers"]) for row in diversity)
    lifecycle_total = sum(int(row["LifecyclePatternDrivers"]) for row in diversity)
    positive_flip_count = sum(row["GroundTruth"] == "true" for row in r23_flips)
    lines = [
        "# Reviewer-gap completion audit",
        "",
        "No fuzzing or LLM calls were performed. This package recomputes analyses "
        "from frozen saved artifacts.",
        "",
        "## Ground-truth audit",
        "",
        f"Current binary ground truth: {dict(binary_counts)}.",
        f"Final audit of the 145 previously pending reports: {dict(audit_counts)}.",
        "",
        "| Scenario | Samples | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in sensitivity:
        lines.append(
            f"| {row['Scenario']} | {row['Samples']} | "
            f"{float(row['Precision']):.4f} | {float(row['Recall']):.4f} | "
            f"{float(row['F1']):.4f} |"
        )
    lines.extend(
        [
            "",
            "## V0/V1 decomposition",
            "",
            "| Scenario | Samples | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in r23_summary:
        lines.append(
            f"| {row['Scenario']} | {row['Samples']} | "
            f"{float(row['Precision']):.4f} | {float(row['Recall']):.4f} | "
            f"{float(row['F1']):.4f} |"
        )
    lines.extend(
        [
            "",
            f"V0 predictions restricted to the V1 retained population and the V1 "
            f"metadata condition differ on {len(r23_flips)} reports; "
            f"{positive_flip_count} of those reports are current targets.",
            "",
            "## Target diversity",
            "",
            f"The 14 projects contain {driver_total} drivers; {multi_total} "
            f"({multi_total / driver_total:.1%}) invoke at least two distinct target "
            f"APIs, and {lifecycle_total} ({lifecycle_total / driver_total:.1%}) "
            f"show an initialization/use/cleanup or ordered-call pattern.",
            "",
            "## Repeated-run stability",
            "",
            "| Prompt | Runs | F1 mean | F1 SD | 95% bootstrap interval |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in stability:
        lines.append(
            f"| {row['Prompt']} | {row['Runs']} | {float(row['F1Mean']):.4f} | "
            f"{float(row['F1SD']):.4f} | "
            f"[{float(row['F1Bootstrap95Low']):.4f}, "
            f"{float(row['F1Bootstrap95High']):.4f}] |"
        )
    lines.extend(
        [
            "",
            "## Cross-model sensitivity",
            "",
            "| Model | Precision | Recall | F1 |",
            "|---|---:|---:|---:|",
        ]
    )
    for row in cross_model:
        lines.append(
            f"| {row['Model']} | {float(row['Precision']):.4f} | "
            f"{float(row['Recall']):.4f} | {float(row['F1']):.4f} |"
        )
    lines.extend(
        [
            "",
            "## Representative-order sensitivity",
            "",
            f"Across {order_result['trials']} deterministic random permutations, the "
            f"representative count remained {order_result['representative_count_min']} "
            f"(original {order_result['original_representatives']}), while mean "
            f"pairwise co-clustering Jaccard agreement was "
            f"{order_result['pair_jaccard_mean']:.4f} "
            f"(range {order_result['pair_jaccard_min']:.4f} to "
            f"{order_result['pair_jaccard_max']:.4f}). CVE-pair precision remained "
            f"{order_result['cve_pair_precision_min']:.4f}, with recall ranging from "
            f"{order_result['cve_pair_recall_min']:.4f} to "
            f"{order_result['cve_pair_recall_max']:.4f}; root-pair precision remained "
            f"{order_result['root_pair_precision_min']:.4f} with recall "
            f"{order_result['root_pair_recall_min']:.4f} to "
            f"{order_result['root_pair_recall_max']:.4f}. The fixed saved discovery "
            f"order must still be disclosed; a canonical order would change which "
            f"reports become representatives and would require a controlled rerun.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("fuzzing_llm_engine/results/review_gap_completion_20261101"),
    )
    parser.add_argument("--order-trials", type=int, default=256)
    parser.add_argument("--seed", type=int, default=20261101)
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parents[2]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    base, positive = current_ground_truth(repo)
    audit_groups, audit_reports = load_145_audit(repo)
    write_csv(
        output / "r1_2_145_group_audit.csv",
        [
            "ReviewGroup",
            "Project",
            "RepresentativeCrashID",
            "ReviewerALabel",
            "ReviewerBLabel",
            "Agreement",
            "FinalBinaryLabel",
            "FinalCategory",
            "ReviewerANotes",
            "ReviewerBNotes",
            "ArbitrationRationale",
        ],
        audit_groups,
    )
    binary_counts = Counter(
        "target" if value else "non_target" for value in positive.values()
    )
    audit_counts = Counter(row["FinalCategory"] for row in audit_reports.values())
    sensitivity = r1_2_sensitivity(repo, base, positive, audit_reports)
    write_csv(
        output / "r1_2_sensitivity.csv",
        [
            "Scenario",
            "Samples",
            "TP",
            "FP",
            "TN",
            "FN",
            "Precision",
            "Recall",
            "F1",
        ],
        sensitivity,
    )
    target_evidence, report_taxonomy = r1_2_evidence_exports(audit_reports)
    write_csv(
        output / "r1_2_confirmed_target_evidence_26.csv",
        [
            "Project",
            "CrashID",
            "RepresentativeCrashID",
            "ReviewGroup",
            "PublicReference",
            "V4HistoricalIssue",
            "ReviewerANotes",
            "ReviewerBNotes",
            "ArbitrationRationale",
        ],
        target_evidence,
    )
    write_csv(
        output / "r1_2_145_report_taxonomy.csv",
        ["Category", "EvidenceSource", "Reports"],
        report_taxonomy,
    )

    r23_summary, r23_flips = r2_3_v0_v1(repo, base)
    write_csv(
        output / "r2_3_v0_v1_decomposition.csv",
        [
            "Scenario",
            "Samples",
            "TP",
            "FP",
            "TN",
            "FN",
            "Precision",
            "Recall",
            "F1",
            "DeltaPrecision",
            "DeltaRecall",
            "DeltaF1",
        ],
        r23_summary,
    )
    write_csv(
        output / "r2_3_v0_v1_flips.csv",
        [
            "Project",
            "CrashID",
            "GroundTruth",
            "TriageLabel",
            "V0Prediction",
            "V1Prediction",
            "FlipDirection",
        ],
        r23_flips,
    )

    diversity, examples = target_diversity(repo, positive)
    write_csv(
        output / "r2_2_target_diversity.csv",
        [
            "Project",
            "CrashReports",
            "TargetReports",
            "Drivers",
            "MultiCallDrivers",
            "MultiCallRate",
            "LifecyclePatternDrivers",
            "LifecyclePatternRate",
            "MedianDistinctAPICallsPerDriver",
        ],
        diversity,
    )
    write_csv(
        output / "r2_2_stateful_examples.csv",
        ["Project", "Driver", "ObservedAPIs", "CoveredPattern"],
        examples,
    )

    stability, report_flips = prompt_stability(repo)
    write_csv(
        output / "r1_7_prompt_stability.csv",
        [
            "Prompt",
            "Runs",
            "PrecisionMean",
            "PrecisionSD",
            "RecallMean",
            "RecallSD",
            "F1Mean",
            "F1SD",
            "F1Min",
            "F1Max",
            "F1Bootstrap95Low",
            "F1Bootstrap95High",
        ],
        stability,
    )
    write_csv(
        output / "r1_7_report_level_flips.csv",
        [
            "Prompt",
            "Project",
            "CrashID",
            "RunsObserved",
            "PositivePredictions",
            "AnyFlip",
        ],
        report_flips,
    )
    cross_model = cross_model_metrics(repo)
    write_csv(
        output / "r2_4_cross_model_metrics.csv",
        [
            "Model",
            "Samples",
            "TP",
            "FP",
            "TN",
            "FN",
            "Precision",
            "Recall",
            "F1",
        ],
        cross_model,
    )

    order_result = order_sensitivity(repo, args.order_trials, args.seed)
    (output / "r1_3_order_sensitivity.json").write_text(
        json.dumps(order_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata = model_metadata(repo)
    (output / "r1_6_model_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_summary(
        output / "summary.md",
        binary_counts,
        audit_counts,
        sensitivity,
        r23_summary,
        r23_flips,
        diversity,
        stability,
        cross_model,
        order_result,
    )
    manifest = {
        "generated_from_frozen_artifacts": True,
        "llm_calls": 0,
        "fuzz_calls": 0,
        "binary_ground_truth_counts": binary_counts,
        "audit_145_counts": audit_counts,
        "output_files": sorted(
            {
                *[path.name for path in output.iterdir() if path.is_file()],
                "run_manifest.json",
            }
        ),
        "seed": args.seed,
        "order_trials": args.order_trials,
    }
    (output / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote reviewer-gap audit to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
