#!/usr/bin/env python3
"""Build nested P0-P3 prompts that add one prompt component at each step."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from crash.make_prompt_ablation import (
    ANALYSIS_MARKER,
    DEFAULT_SOURCE,
    direct_prompt,
    load_jsonl,
    sha256,
    split_analysis_instructions,
    write_bundle,
)
from roles.crash_analyzer import (
    _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS,
    _DIFFERENTIAL_V3_DECISION_OUTPUT_CONTRACT,
    _DIRECT_V1_ANALYSIS_INSTRUCTIONS,
    _DIRECT_V1_OUTPUT_CONTRACT,
)


CORE_COMPARISON = """

Before making the final attribution, compare exactly two hypotheses once:
- The driver-misuse hypothesis: the generated driver violated an API
  precondition or constructed an invalid object state that explains the crash.
- The target-defect hypothesis: the driver satisfied the relevant preconditions
  and a target-side operation or invariant still fails.

Attribute the crash to the target component only when the target-defect
hypothesis is better supported by the supplied evidence.
"""

COMPONENT_DIRECT = "direct_prompt"
COMPONENT_COMPARISON = "symmetric_target_driver_comparison"
COMPONENT_AUDIT = "hard_soft_misuse_and_precondition_audit"
COMPONENT_BOUNDARY = "boundary_arbitration_and_consistency_constraints"


def prefix_from(prompt: str) -> str:
    prefix, _ = split_analysis_instructions(prompt)
    return prefix


def function_components(prompt: str) -> tuple[str, float]:
    match = re.search(
        r"Preliminary classification:\s*([^\s(]+)\s*\(confidence:\s*([0-9.]+)\)",
        prompt,
    )
    if not match:
        raise ValueError("Missing triage classification")
    return match.group(1), float(match.group(2))


def p0_direct(prompt: str) -> str:
    return direct_prompt(prompt)


def p1_core_differential(prompt: str) -> str:
    """P0 plus one symmetric target-versus-driver comparison."""
    return _direct_prompt_with_components(prompt, CORE_COMPARISON)


def _direct_prompt_with_components(
    prompt: str,
    *components: str,
) -> str:
    triage_label, triage_confidence = function_components(prompt)
    instructions = _DIRECT_V1_ANALYSIS_INSTRUCTIONS.format(
        triage_label=triage_label,
        triage_confidence=triage_confidence,
    )
    return (
        prefix_from(prompt)
        + ANALYSIS_MARKER
        + "\n"
        + instructions
        + "".join(components)
        + _DIRECT_V1_OUTPUT_CONTRACT
    )


def p2_structured_audit(prompt: str) -> str:
    """P1's comparison plus the formal hard/soft and precondition audit."""
    return (
        prefix_from(prompt)
        + ANALYSIS_MARKER
        + "\n"
        + _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS
        + _DIFFERENTIAL_V3_DECISION_OUTPUT_CONTRACT
    )


def p3_full(prompt: str) -> str:
    return prompt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/prompt_ablation_20261030/nested_prompts"),
    )
    args = parser.parse_args()

    records = load_jsonl(args.source)
    args.output.mkdir(parents=True, exist_ok=True)
    variants = {
        "P0_direct": (
            p0_direct,
            [COMPONENT_DIRECT],
        ),
        "P1_core_differential": (
            p1_core_differential,
            [COMPONENT_DIRECT, COMPONENT_COMPARISON],
        ),
        "P2_structured_audit": (
            p2_structured_audit,
            [COMPONENT_DIRECT, COMPONENT_COMPARISON, COMPONENT_AUDIT],
        ),
        "P3_full_differential": (
            p3_full,
            [
                COMPONENT_DIRECT,
                COMPONENT_COMPARISON,
                COMPONENT_AUDIT,
                COMPONENT_BOUNDARY,
            ],
        ),
    }
    manifest = {
        "source": str(args.source),
        "source_sha256": sha256(args.source.read_text(encoding="utf-8")),
        "count": len(records),
        "variants": {},
    }
    for variant, (prompt_fn, components) in variants.items():
        rows = write_bundle(
            args.output,
            variant,
            records,
            prompt_fn,
            components=components,
        )
        manifest["variants"][variant] = {
            "prompt_count": len(rows),
            "components": components,
            "mean_prompt_chars": sum(int(row["prompt_chars"]) for row in rows)
            / len(rows),
            "prompt_min_chars": min(int(row["prompt_chars"]) for row in rows),
            "prompt_max_chars": max(int(row["prompt_chars"]) for row in rows),
            "corpus_sha256": sha256(
                "".join(str(row["prompt_sha256"]) for row in rows)
            ),
        }
        print(
            f"{variant}: count={len(rows)} "
            f"mean_chars={manifest['variants'][variant]['mean_prompt_chars']:.1f}"
        )
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
