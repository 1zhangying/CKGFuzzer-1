"""Compatibility rules for controlled run and prompt variants."""
from __future__ import annotations


SUPPORTED_RUN_VARIANTS = frozenset({"V0", "V1", "V2", "V3", "V4"})
SUPPORTED_PROMPT_VARIANTS = frozenset({"differential", "direct_v1"})

_ALLOWED_PROMPTS = {
    "V0": frozenset({"direct_v1"}),
    "V1": frozenset({"direct_v1"}),
    "V2": frozenset({"direct_v1"}),
    "V3": frozenset({"direct_v1"}),
    "V4": frozenset({"differential"}),
}


def validate_run_prompt_variant(run_variant: str, prompt_variant: str) -> None:
    """Reject run/prompt combinations outside the controlled experiment matrix."""
    if run_variant not in SUPPORTED_RUN_VARIANTS:
        raise ValueError(
            "RUN_VARIANT must be one of V0, V1, V2, V3, V4, "
            f"got {run_variant!r}"
        )
    if prompt_variant not in SUPPORTED_PROMPT_VARIANTS:
        raise ValueError(
            "PROMPT_VARIANT must be differential or direct_v1, "
            f"got {prompt_variant!r}"
        )
    if prompt_variant not in _ALLOWED_PROMPTS[run_variant]:
        allowed = ", ".join(sorted(_ALLOWED_PROMPTS[run_variant]))
        raise ValueError(f"{run_variant} requires PROMPT_VARIANT in {{{allowed}}}")
