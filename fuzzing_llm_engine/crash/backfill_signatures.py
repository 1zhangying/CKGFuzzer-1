#!/usr/bin/env python3
"""Recompute CrashSage matching signatures without rerunning triage or LLM analysis.

The command preserves triage labels, confidence values, evidence entries, and
all other crash metadata. Only these fields are replaced:

* ``triage.signature``
* ``triage.signature_source``
* ``triage.stack_signature``
* ``triage.fuzzy_signature``
* top-level ``signature`` when that field already exists

Example:
    python -m crash.backfill_signatures --db-root external_database --write
"""
from __future__ import annotations

import argparse
import copy
import csv
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from crash.sanitizer_parser import parse_sanitizer_output
from crash.triage import compute_signatures, triage_crash


SIGNATURE_KEYS = {
    "signature",
    "signature_source",
    "stack_signature",
    "fuzzy_signature",
}


def _clean_crash_info(raw: Any) -> str:
    text = str(raw or "")
    if text.startswith("|"):
        text = text[1:].lstrip("\n")
    return text


def _without_signatures(entry: Dict[str, Any]) -> Dict[str, Any]:
    retained = copy.deepcopy(entry)
    triage = retained.get("triage")
    if isinstance(triage, dict):
        for key in SIGNATURE_KEYS:
            triage.pop(key, None)
    retained.pop("signature", None)
    return retained


def _iter_entries(path: Path) -> Iterable[tuple[Any, Dict[str, Any]]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        return
    for item in data:
        if not isinstance(item, dict):
            continue
        for crash_key, entry in item.items():
            if isinstance(entry, dict):
                yield crash_key, entry


def _backfill_file(path: Path, write: bool) -> List[Dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a YAML list")

    driver = path.parent.name
    rows: List[Dict[str, Any]] = []

    for item in data:
        if not isinstance(item, dict):
            continue
        for crash_key, entry in item.items():
            if not isinstance(entry, dict):
                continue

            before = _without_signatures(entry)
            crash_info = _clean_crash_info(entry.get("crash_info"))
            if not crash_info.strip():
                rows.append({
                    "crash_key": crash_key,
                    "status": "skipped_no_crash_info",
                    "exact_basis": "",
                })
                continue

            parsed = entry.get("sanitizer_parsed")
            if not isinstance(parsed, dict):
                parsed = parse_sanitizer_output(crash_info)
            exact, basis, stack, fuzzy = compute_signatures(parsed)

            triage = entry.get("triage")
            if not isinstance(triage, dict):
                triage = triage_crash(
                    parsed,
                    fuzz_driver_basename=f"{driver}.cc",
                )
                entry["triage"] = triage

            triage["signature"] = exact
            triage["signature_source"] = basis
            triage["stack_signature"] = stack
            triage["fuzzy_signature"] = fuzzy
            if "signature" in entry:
                entry["signature"] = exact

            if _without_signatures(entry) != before:
                raise ValueError(
                    f"{path}: non-signature fields changed for {crash_key}"
                )

            rows.append({
                "crash_key": crash_key,
                "status": "updated",
                "exact_basis": basis,
            })

    if write:
        temporary = f"{path}.tmp.{os.getpid()}"
        try:
            temporary_path = Path(temporary)
            temporary_path.write_text(
                yaml.safe_dump(
                    data,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            os.replace(temporary_path, path)
        finally:
            if Path(temporary).exists():
                Path(temporary).unlink()

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db-root",
        default="external_database",
        help="Root containing <project>/crash/<driver>/crash_analysis.yaml",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Atomically replace YAML files. No backup copies are created.",
    )
    parser.add_argument(
        "--summary",
        default="",
        help="Optional CSV path for per-crash signature backfill results.",
    )
    args = parser.parse_args()

    db_root = Path(args.db_root)
    paths = sorted(db_root.glob("*/crash/*/crash_analysis.yaml"))
    if not paths:
        raise SystemExit(f"No crash_analysis.yaml files under {db_root}")

    summary_rows: List[Dict[str, Any]] = []
    for path in paths:
        project = path.parts[-4]
        driver = path.parent.name
        for row in _backfill_file(path, args.write):
            summary_rows.append({
                "Project": project,
                "Driver": driver,
                **row,
            })

    updated = sum(row["status"] == "updated" for row in summary_rows)
    skipped = len(summary_rows) - updated
    print(
        f"files={len(paths)} entries={len(summary_rows)} "
        f"updated={updated} skipped={skipped} write={args.write}"
    )

    if args.summary:
        output = Path(args.summary)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
            writer.writeheader()
            writer.writerows(summary_rows)
        print(f"summary={output}")


if __name__ == "__main__":
    main()
