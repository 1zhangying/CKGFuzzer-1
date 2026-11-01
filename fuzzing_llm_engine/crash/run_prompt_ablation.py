#!/usr/bin/env python3
"""Run the fresh P0/P1/P2 prompt-ablation calls in bounded chunks."""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml


DEFAULT_PROMPTS = Path("results/prompt_ablation_20261030/nested_prompts")
DEFAULT_OUTPUT = Path("results/prompt_ablation_20261030/nested_runs_20261030")
VARIANTS = {
    "P0_direct": "v4_frozen_direct",
    "P1_core_differential": "v4_frozen_direct",
    "P2_structured_audit": "v4_frozen_direct",
    "P3_full_differential": "v4_frozen_direct",
}
DEFAULT_VARIANTS = ("P1_core_differential", "P2_structured_audit")


def load_ids(path: Path) -> list[str]:
    ids = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                record = json.loads(line)
                ids.append(str(record["crash_id"]))
    if len(ids) != 96 or len(set(ids)) != 96:
        raise ValueError(f"Expected 96 unique crash IDs in {path}")
    return ids


def count_ok(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return sum(
            row.get("Status") == "ok" for row in csv.DictReader(handle)
        )


def run_chunk(
    variant: str,
    protocol: str,
    crash_ids: list[str],
    prompt_path: Path,
    output_root: Path,
    index: int,
    llm_env: dict[str, str],
) -> tuple[str, int, str]:
    output_dir = output_root / variant / f"chunk_{index}"
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "replay_frozen_prompts.py",
        "--frozen-prompts",
        str(prompt_path),
        "--out-dir",
        str(output_dir),
        "--expected-count",
        "96",
        "--crash-id-filter",
        ",".join(crash_ids),
        "--protocol",
        protocol,
        "--prompt-variant",
        variant,
        "--temperature",
        "0",
        "--resume",
    ]
    env = dict(os.environ)
    for name in ("ALL_PROXY", "all_proxy"):
        env.pop(name, None)
    env.update(llm_env)
    log_path = output_root / variant / f"chunk_{index}.log"
    with log_path.open("a", encoding="utf-8") as log:
        result = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=1800,
            check=False,
        )
    ok = count_ok(output_dir / "llm_bool_results.csv")
    return variant, index, f"exit={result.returncode} ok={ok}/{len(crash_ids)}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompts", type=Path, default=DEFAULT_PROMPTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--chunks", type=int, default=8)
    parser.add_argument("--llm-config", type=Path, default=None)
    parser.add_argument("--model-override", default="")
    parser.add_argument("--base-url-override", default="")
    parser.add_argument(
        "--variants",
        nargs="+",
        choices=tuple(VARIANTS),
        default=list(DEFAULT_VARIANTS),
    )
    args = parser.parse_args()

    llm_env: dict[str, str] = {}
    if args.llm_config is not None:
        config = yaml.safe_load(args.llm_config.read_text(encoding="utf-8"))
        llm = config["llm"]
        llm_env = {
            "LLM_MODEL_OVERRIDE": str(llm["model"]),
            "LLM_BASE_URL_OVERRIDE": str(llm["base_url"]),
            "LLM_API_KEY_OVERRIDE": str(llm["api_key"]),
        }
        if args.model_override:
            llm_env["LLM_MODEL_OVERRIDE"] = args.model_override
        if args.base_url_override:
            llm_env["LLM_BASE_URL_OVERRIDE"] = args.base_url_override
        if llm.get("temperature") is not None:
            llm_env["FROZEN_TEMPERATURE"] = str(llm["temperature"])
        if llm.get("timeout") is not None:
            llm_env["LLM_TIMEOUT_OVERRIDE"] = str(llm["timeout"])
        if llm.get("max_tokens") is not None:
            llm_env["LLM_MAX_TOKENS_OVERRIDE"] = str(llm["max_tokens"])

    all_ids = load_ids(args.prompts / "P3_full_differential.jsonl")
    size = (len(all_ids) + args.chunks - 1) // args.chunks
    chunks = [all_ids[i : i + size] for i in range(0, len(all_ids), size)]
    for variant in args.variants:
        prompt_path = args.prompts / f"{variant}.jsonl"
        print(f"[{variant}] starting {len(chunks)} chunks", flush=True)
        with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
            futures = [
                executor.submit(
                    run_chunk,
                    variant,
                    VARIANTS[variant],
                    chunk,
                    prompt_path,
                    args.output,
                    index,
                    llm_env,
                )
                for index, chunk in enumerate(chunks)
            ]
            results = [future.result() for future in as_completed(futures)]
        for _, index, status in sorted(results, key=lambda item: item[1]):
            print(f"[{variant}] chunk {index}: {status}", flush=True)
        total_ok = sum(
            count_ok(args.output / variant / f"chunk_{index}" / "llm_bool_results.csv")
            for index in range(len(chunks))
        )
        if total_ok != len(all_ids):
            raise RuntimeError(f"{variant} completed {total_ok}/{len(all_ids)}")
        print(f"[{variant}] complete: {total_ok}/{len(all_ids)}", flush=True)


if __name__ == "__main__":
    main()
