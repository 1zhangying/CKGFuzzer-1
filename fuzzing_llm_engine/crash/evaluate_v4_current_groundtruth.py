#!/usr/bin/env python3
"""Evaluate saved V4 predictions against the consensus-expanded ground truth."""
from __future__ import annotations

import argparse
import csv
import json
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


TRUTHY = {"true", "1", "yes", "y", "t"}
MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def truth(value: object) -> bool:
    return str(value).strip().lower() in TRUTHY


def _xlsx_sheet_rows(path: Path, sheet_name: str) -> List[Dict[str, str]]:
    with zipfile.ZipFile(path) as archive:
        shared: List[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = [
                "".join(
                    node.text or ""
                    for node in item.iter(f"{{{MAIN_NS}}}t")
                )
                for item in root.findall(f"{{{MAIN_NS}}}si")
            ]

        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(
            archive.read("xl/_rels/workbook.xml.rels")
        )
        targets = {
            item.attrib["Id"]: item.attrib["Target"]
            for item in relationships.findall(f"{{{PKG_REL_NS}}}Relationship")
        }
        sheet_path = ""
        for sheet in workbook.findall(f".//{{{MAIN_NS}}}sheet"):
            if sheet.attrib.get("name") != sheet_name:
                continue
            relationship_id = sheet.attrib[f"{{{DOC_REL_NS}}}id"]
            target = targets[relationship_id].lstrip("/")
            sheet_path = target if target.startswith("xl/") else f"xl/{target}"
            break
        if not sheet_path:
            raise ValueError(f"Sheet {sheet_name!r} not found in {path}")

        root = ET.fromstring(archive.read(sheet_path))
        rows: List[Dict[str, str]] = []
        for row in root.findall(f".//{{{MAIN_NS}}}sheetData/{{{MAIN_NS}}}row"):
            values: Dict[str, str] = {}
            for cell in row.findall(f"{{{MAIN_NS}}}c"):
                column = "".join(
                    char
                    for char in cell.attrib.get("r", "")
                    if char.isalpha()
                )
                cell_type = cell.attrib.get("t")
                inline = "".join(
                    node.text or ""
                    for node in cell.iter(f"{{{MAIN_NS}}}t")
                )
                raw = cell.find(f"{{{MAIN_NS}}}v")
                if inline:
                    value = inline
                elif raw is None:
                    value = ""
                elif cell_type == "s":
                    value = shared[int(raw.text or "0")]
                else:
                    value = raw.text or ""
                values[column] = value
            rows.append(values)
        return rows


def consensus_target_ids(
    workbook: Path,
    mapping_path: Path,
    sheet_name: str,
) -> tuple[set[str], Dict[str, str]]:
    rows = _xlsx_sheet_rows(workbook, sheet_name)
    header_index = next(
        (
            index
            for index, row in enumerate(rows)
            if row.get("A") == "Review group"
        ),
        None,
    )
    if header_index is None:
        raise ValueError("Consensus sheet has no 'Review group' header")

    representative_labels = {
        row["C"]: row.get("P", "")
        for row in rows[header_index + 1 :]
        if row.get("C")
    }
    mapping = load_csv(mapping_path)
    target_ids = {
        row["CrashID"]
        for row in mapping
        if representative_labels.get(row["RepresentativeCrashID"])
        == "confirmed_target"
    }
    return target_ids, representative_labels


def metric_rows(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        expected = truth(row["GroundTruth"])
        predicted = truth(row["Prediction"])
        if predicted and expected:
            tp += 1
        elif predicted:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1
    samples = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "Samples": samples,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
    }


def write_csv(
    path: Path,
    fields: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument(
        "--baseline-ground-truth",
        type=Path,
        default=Path("results/all_crashes_v0_v4_groundtruth.csv"),
    )
    parser.add_argument("--review-workbook", type=Path, required=True)
    parser.add_argument("--review-mapping", type=Path, required=True)
    parser.add_argument("--sheet-name", default="Arbitration")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    baseline = load_csv(args.baseline_ground_truth)
    predictions = load_csv(args.predictions)
    targets, representative_labels = consensus_target_ids(
        args.review_workbook,
        args.review_mapping,
        args.sheet_name,
    )

    previous = {
        (row["Project"], row["CrashID"]): truth(row.get("GroundTruth"))
        for row in baseline
    }
    prediction_by_key = {
        (row["Project"], row["CrashID"]): truth(row["Prediction"])
        for row in predictions
    }
    if set(prediction_by_key) != set(previous):
        missing = sorted(set(previous) - set(prediction_by_key))
        extra = sorted(set(prediction_by_key) - set(previous))
        raise ValueError(
            f"Prediction keys do not match baseline: missing={len(missing)}, "
            f"extra={len(extra)}"
        )

    output_rows: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    for row in predictions:
        key = (row["Project"], row["CrashID"])
        old_label = previous[key]
        is_consensus_target = row["CrashID"] in targets
        current_label = old_label or is_consensus_target
        output = {
            **row,
            "GroundTruth": str(current_label).lower(),
            "PreviousGroundTruth": str(old_label).lower(),
            "ConsensusTarget": str(is_consensus_target).lower(),
        }
        output_rows.append(output)
        if old_label != current_label:
            changed.append(output)

    overall = metric_rows(output_rows)
    per_project = []
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in output_rows:
        grouped[row["Project"]].append(row)
    for project, rows in sorted(grouped.items()):
        per_project.append({"Project": project, **metric_rows(rows)})

    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(
        args.output / "final_v4_expanded_current_gt.csv",
        list(output_rows[0]),
        output_rows,
    )
    write_csv(
        args.output / "ground_truth_changes.csv",
        list(changed[0]) if changed else list(output_rows[0]),
        changed,
    )
    write_csv(
        args.output / "per_project_metrics.csv",
        ["Project", "Samples", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1"],
        per_project,
    )
    write_csv(
        args.output / "overall_metrics.csv",
        ["Samples", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1"],
        [overall],
    )
    (args.output / "evaluation_manifest.json").write_text(
        json.dumps(
            {
                "predictions": str(args.predictions),
                "baseline_ground_truth": str(args.baseline_ground_truth),
                "review_workbook": str(args.review_workbook),
                "review_mapping": str(args.review_mapping),
                "baseline_true": sum(previous.values()),
                "consensus_target_reports": len(targets),
                "current_true": overall["TP"] + overall["FN"],
                "changed_labels": len(changed),
                "metrics": overall,
                "representative_label_counts": dict(
                    Counter(representative_labels.values())
                ),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"V4 current GT: TP={overall['TP']} FP={overall['FP']} "
        f"TN={overall['TN']} FN={overall['FN']} "
        f"P={overall['Precision']:.6f} R={overall['Recall']:.6f} "
        f"F1={overall['F1']:.6f}"
    )


if __name__ == "__main__":
    main()
