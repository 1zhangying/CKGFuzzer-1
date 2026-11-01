#!/usr/bin/env python3
"""Freeze the exact final V3 prompts captured for a representative manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple


DEFAULT_ARTIFACT_DIR = Path(
    "results/revision_20260725/llm_v3_57_representatives_full_rerun/analysis_artifacts"
)
DEFAULT_MANIFEST = Path("results/revision_20260725/representatives_57_v3_current_dedup.csv")
DEFAULT_OUTPUT = Path("results/revision_20260728/frozen_v3_differential_prompts_57.jsonl")


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def load_frozen_records(
    manifest_path: Path,
    artifact_dir: Path | Iterable[Path],
    expected_count: int,
    *,
    expected_run_variant: str = "",
    expected_analysis_engine: str = "",
) -> List[Dict[str, object]]:
    """Validate captured prompts from one or more artifact directories."""
    manifest = read_csv(manifest_path)
    expected: List[Tuple[str, str]] = []
    for row in manifest:
        key = (row["Project"], row["CrashID"])
        if key in expected:
            raise ValueError(f"Duplicate manifest entry: {key}")
        expected.append(key)

    if len(expected) != expected_count:
        raise ValueError(
            f"Expected {expected_count} manifest representatives, found {len(expected)} in {manifest_path}"
        )

    if isinstance(artifact_dir, Path):
        artifact_dirs = [artifact_dir]
    else:
        artifact_dirs = [Path(path) for path in artifact_dir]
    artifact_paths = [
        artifact_path
        for directory in artifact_dirs
        for artifact_path in sorted(directory.glob("*.json"))
    ]

    records: Dict[Tuple[str, str], Dict[str, object]] = {}
    for artifact_path in artifact_paths:
        with artifact_path.open(encoding="utf-8") as handle:
            artifact = json.load(handle)

        project = str(artifact.get("project") or "")
        crash_id = str(artifact.get("crash_id") or "")
        key = (project, crash_id)
        if not project or not crash_id:
            raise ValueError(f"Artifact missing project or crash_id: {artifact_path}")
        if key in records:
            raise ValueError(f"Duplicate artifact entry: {key}")

        prompt = artifact.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError(f"Artifact has no captured final prompt: {artifact_path}")
        saved_hash = str(artifact.get("prompt_sha256") or "")
        actual_hash = _sha256(prompt)
        if saved_hash != actual_hash:
            raise ValueError(
                f"Prompt SHA-256 mismatch for {key}: saved={saved_hash}, actual={actual_hash}"
            )

        metadata = artifact.get("experiment_metadata") or {}
        if metadata.get("prompt_variant") != "differential":
            raise ValueError(f"Artifact is not a differential prompt: {key}")
        if (
            expected_run_variant
            and metadata.get("run_variant") != expected_run_variant
        ):
            raise ValueError(
                f"Artifact run variant mismatch for {key}: "
                f"{metadata.get('run_variant')!r}, expected {expected_run_variant!r}"
            )
        if (
            expected_analysis_engine
            and metadata.get("analysis_engine") != expected_analysis_engine
        ):
            raise ValueError(
                f"Artifact analysis engine mismatch for {key}: "
                f"{metadata.get('analysis_engine')!r}, "
                f"expected {expected_analysis_engine!r}"
            )
        required_context_flags = [
            "include_triage",
            "include_static_context",
            "include_runtime_context",
        ]
        if (
            metadata.get("run_variant") in {"V3", "V4"}
            or "include_reconstruction_context" in metadata
        ):
            required_context_flags.append("include_reconstruction_context")
        if not all(metadata.get(field) is True for field in required_context_flags):
            raise ValueError(f"Artifact is not a complete contextual evidence prompt: {key}")

        records[key] = {
            "project": project,
            "crash_id": crash_id,
            "driver": str(artifact.get("driver") or ""),
            "prompt": prompt,
            "prompt_sha256": actual_hash,
            "prompt_chars": len(prompt),
            "source_artifact": str(artifact_path),
            "source_prompt_variant": metadata["prompt_variant"],
            "source_run_variant": str(metadata.get("run_variant") or ""),
            "source_analysis_engine": str(metadata.get("analysis_engine") or ""),
            "source_experiment_fingerprint": str(
                metadata.get("experiment_fingerprint") or ""
            ),
            "source_input_fingerprint": str(metadata.get("input_fingerprint") or ""),
        }

    expected_keys = set(expected)
    observed_keys = set(records)
    missing = sorted(expected_keys.difference(observed_keys))
    unexpected = sorted(observed_keys.difference(expected_keys))
    if missing or unexpected:
        raise ValueError(f"Artifact/manifest mismatch: missing={missing}, unexpected={unexpected}")

    return [records[key] for key in expected]


def write_frozen_records(output_path: Path, records: Sequence[Mapping[str, object]], force: bool) -> None:
    if output_path.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing frozen corpus: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        action="append",
        default=None,
        help="Artifact directory; repeat to combine independently generated chunks.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--expected-count", type=int, default=57)
    parser.add_argument("--expected-run-variant", default="")
    parser.add_argument("--expected-analysis-engine", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    artifact_dirs = args.artifact_dir or [DEFAULT_ARTIFACT_DIR]
    records = load_frozen_records(
        args.manifest,
        artifact_dirs,
        args.expected_count,
        expected_run_variant=args.expected_run_variant,
        expected_analysis_engine=args.expected_analysis_engine,
    )
    write_frozen_records(args.output, records, args.force)
    corpus_hash = _sha256("".join(str(record["prompt_sha256"]) for record in records))
    print(f"Frozen {len(records)} differential contextual prompts to {args.output}")
    print(f"CorpusSHA256={corpus_hash}")


if __name__ == "__main__":
    main()
