#!/usr/bin/env python3
"""Build the frozen P0-P3 prompt bundles for the prompt-only ablation."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Sequence

from roles.crash_analyzer import (
    _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS,
    _DIFFERENTIAL_V4_DECISION_OUTPUT_CONTRACT,
    _DIRECT_V1_ANALYSIS_INSTRUCTIONS,
    _DIRECT_V1_OUTPUT_CONTRACT,
)


DEFAULT_SOURCE = Path(
    "results/frozen_models_20261030/qwen3-coder-flash_v4_source/"
    "frozen_v4_prompts_96.jsonl"
)
DEFAULT_OUTPUT = Path("results/prompt_ablation_20261030/prompts")
ANALYSIS_MARKER = (
    "============================================================\n"
    "ANALYSIS INSTRUCTIONS\n"
    "============================================================"
)
MINIMAL_JSON_SUFFIX = """

PROMPT-ABLATION OUTPUT CONTRACT (overrides all earlier output-format instructions):
Return exactly one JSON object and no surrounding text:
{"is_api_bug": true}
Use false when the crash is caused by the fuzz driver rather than a target API bug.
Do not include evidence_summary, decision_basis, or any other JSON field.
"""
RATIONALE_REMOVAL_SUFFIX = """

PROMPT-ABLATION CONSTRAINT:
The evidence_summary field and the requirement to provide a separate narrative
evidence rationale are intentionally disabled for this variant. Do not include
evidence_summary in the JSON response. Keep all remaining fields and decision
rules unchanged.
"""


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def load_jsonl(path: Path) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    keys: set[tuple[str, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            project = str(record.get("project") or "")
            crash_id = str(record.get("crash_id") or "")
            prompt = record.get("prompt")
            key = (project, crash_id)
            if not project or not crash_id or not isinstance(prompt, str):
                raise ValueError(f"Invalid record at {path}:{line_number}")
            if key in keys:
                raise ValueError(f"Duplicate record at {path}:{line_number}: {key}")
            if sha256(prompt) != str(record.get("prompt_sha256") or ""):
                raise ValueError(f"Source prompt hash mismatch: {key}")
            keys.add(key)
            records.append(record)
    if len(records) != 96:
        raise ValueError(f"Expected 96 frozen prompts, found {len(records)}")
    return records


def split_analysis_instructions(prompt: str) -> tuple[str, str]:
    index = prompt.rfind(ANALYSIS_MARKER)
    if index < 0:
        raise ValueError("Frozen prompt has no analysis-instructions marker")
    return prompt[:index], prompt[index + len(ANALYSIS_MARKER):]


def direct_prompt(prompt: str) -> str:
    prefix, _ = split_analysis_instructions(prompt)
    match = re.search(
        r"Preliminary classification:\s*([^\s(]+)\s*\(confidence:\s*([0-9.]+)\)",
        prompt,
    )
    if not match:
        raise ValueError("Frozen prompt has no triage classification")
    instructions = _DIRECT_V1_ANALYSIS_INSTRUCTIONS.format(
        triage_label=match.group(1),
        triage_confidence=float(match.group(2)),
    )
    return prefix + ANALYSIS_MARKER + "\n" + instructions + _DIRECT_V1_OUTPUT_CONTRACT


def no_rationale_prompt(prompt: str) -> str:
    _, instructions = split_analysis_instructions(prompt)
    if instructions.strip() != (
        _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS
        + _DIFFERENTIAL_V4_DECISION_OUTPUT_CONTRACT
    ).strip():
        raise ValueError("Unexpected differential instruction block in frozen prompt")

    pattern = re.compile(
        r'(\"decision_basis\": \"[^\"]*\")(,\s*'
        r'\"evidence_summary\": \"[^\"]*\")(\s*})',
        flags=re.DOTALL,
    )
    updated, replacements = pattern.subn(r"\1\3", prompt, count=1)
    if replacements != 1:
        raise ValueError("Could not remove evidence_summary from differential schema")
    return updated.rstrip() + "\n" + RATIONALE_REMOVAL_SUFFIX


def minimal_json_prompt(prompt: str) -> str:
    return prompt.rstrip() + "\n" + MINIMAL_JSON_SUFFIX


def write_bundle(
    output: Path,
    variant: str,
    source_records: List[Mapping[str, object]],
    prompt_fn,
    *,
    components: Sequence[str] = (),
) -> List[Dict[str, object]]:
    path = output / f"{variant}.jsonl"
    written: List[Dict[str, object]] = []
    with path.open("w", encoding="utf-8") as handle:
        for source in source_records:
            prompt = prompt_fn(str(source["prompt"]))
            record = {
                "project": source["project"],
                "crash_id": source["crash_id"],
                "driver": source["driver"],
                "prompt": prompt,
                "prompt_chars": len(prompt),
                "prompt_sha256": sha256(prompt),
                "source_prompt_sha256": source["prompt_sha256"],
                "prompt_variant": variant,
                "prompt_components": list(components),
            }
            written.append(record)
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    source_records = load_jsonl(args.source)
    args.output.mkdir(parents=True, exist_ok=True)
    variants = {
        "P0_direct": direct_prompt,
        "P1_no_rationale": no_rationale_prompt,
        "P2_minimal_json": minimal_json_prompt,
        "P3_full_differential": lambda prompt: prompt,
    }
    manifest: Dict[str, object] = {
        "source": str(args.source),
        "source_sha256": sha256(args.source.read_text(encoding="utf-8")),
        "count": len(source_records),
        "variants": {},
    }
    for variant, prompt_fn in variants.items():
        records = write_bundle(args.output, variant, source_records, prompt_fn)
        manifest["variants"][variant] = {
            "prompt_count": len(records),
            "mean_prompt_chars": sum(int(row["prompt_chars"]) for row in records)
            / len(records),
            "prompt_min_chars": min(int(row["prompt_chars"]) for row in records),
            "prompt_max_chars": max(int(row["prompt_chars"]) for row in records),
            "corpus_sha256": sha256(
                "".join(str(row["prompt_sha256"]) for row in records)
            ),
        }
        print(
            f"{variant}: count={len(records)} "
            f"mean_chars={manifest['variants'][variant]['mean_prompt_chars']:.1f} "
            f"corpus={manifest['variants'][variant]['corpus_sha256']}"
        )
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
