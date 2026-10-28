"""Single source of truth for the controlled V0-V4 experiment matrix."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_RUN_VARIANTS = frozenset({"V0", "V1", "V2", "V3", "V4"})
SUPPORTED_PROMPT_VARIANTS = frozenset({"differential", "direct_v1"})


@dataclass(frozen=True)
class VariantConfig:
    """Fixed processing policy for one paper-defined ablation variant."""

    name: str
    analysis_engine: str
    use_triage: bool
    filter_reports: bool
    use_representatives: bool
    include_static_context: bool
    include_runtime_context: bool
    include_reconstruction_context: bool
    prompt_variant: str
    evidence_variant: str


VARIANTS = {
    # V0 is the CKGFuzzer baseline with the paper's clean direct prompt. It
    # must not enter any CrashSage stage, including parsing for triage.
    "V0": VariantConfig(
        name="V0",
        analysis_engine="ckgfuzzer",
        use_triage=False,
        filter_reports=False,
        use_representatives=False,
        include_static_context=False,
        include_runtime_context=False,
        include_reconstruction_context=False,
        prompt_variant="direct_v1",
        evidence_variant="raw_no_context",
    ),
    "V1": VariantConfig(
        name="V1",
        analysis_engine="crashsage",
        use_triage=True,
        filter_reports=True,
        use_representatives=False,
        include_static_context=False,
        include_runtime_context=False,
        include_reconstruction_context=False,
        prompt_variant="direct_v1",
        evidence_variant="triage_no_context",
    ),
    "V2": VariantConfig(
        name="V2",
        analysis_engine="crashsage",
        use_triage=True,
        filter_reports=True,
        use_representatives=True,
        include_static_context=False,
        include_runtime_context=False,
        include_reconstruction_context=False,
        prompt_variant="direct_v1",
        evidence_variant="triage_dedup_no_context",
    ),
    "V3": VariantConfig(
        name="V3",
        analysis_engine="crashsage",
        use_triage=True,
        filter_reports=True,
        use_representatives=True,
        include_static_context=True,
        include_runtime_context=True,
        include_reconstruction_context=True,
        prompt_variant="direct_v1",
        evidence_variant="full",
    ),
    "V4": VariantConfig(
        name="V4",
        analysis_engine="crashsage",
        use_triage=True,
        filter_reports=True,
        use_representatives=True,
        include_static_context=True,
        include_runtime_context=True,
        include_reconstruction_context=True,
        prompt_variant="differential",
        evidence_variant="full",
    ),
}


def experiment_fingerprint() -> str:
    """Hash the code paths that determine crash-analysis semantics."""
    engine_root = Path(__file__).resolve().parents[1]
    sources = (
        "crash/run_variant_config.py",
        "crash/sanitizer_parser.py",
        "crash/triage.py",
        "crash/dedup.py",
        "crash/locator.py",
        "crash/debugger.py",
        "crash/context_validation.py",
        "crash/context_sources.py",
        "crash/retro_enrich.py",
        "roles/crash_analyzer.py",
        "roles/run_fuzzer.py",
        "fuzzing.py",
        "run.py",
    )
    digest = hashlib.sha256()
    for relative in sources:
        path = engine_root / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def get_variant_config(run_variant: str) -> VariantConfig:
    normalized = str(run_variant).strip().upper()
    if normalized not in VARIANTS:
        raise ValueError(
            "RUN_VARIANT must be one of V0, V1, V2, V3, V4, "
            f"got {run_variant!r}"
        )
    return VARIANTS[normalized]


def validate_run_prompt_variant(run_variant: str, prompt_variant: str) -> None:
    """Reject run/prompt combinations outside the controlled experiment matrix."""
    config = get_variant_config(run_variant)
    if prompt_variant not in SUPPORTED_PROMPT_VARIANTS:
        raise ValueError(
            "PROMPT_VARIANT must be differential or direct_v1, "
            f"got {prompt_variant!r}"
        )
    if prompt_variant != config.prompt_variant:
        raise ValueError(
            f"{config.name} requires PROMPT_VARIANT in {{{config.prompt_variant}}}"
        )
