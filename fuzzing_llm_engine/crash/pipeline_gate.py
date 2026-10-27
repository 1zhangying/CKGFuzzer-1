"""Shared gating helpers for the enhanced crash pipeline."""
from __future__ import annotations

from typing import Any, Dict


TRIAGE_BLOCKING_LABELS = {"noise", "likely_driver_bug"}


def triage_blocks_context_reconstruction(triage: Dict[str, Any] | None) -> bool:
    """Return True when triage should stop downstream deterministic stages."""
    if not triage:
        return False
    return (triage.get("label") or "") in TRIAGE_BLOCKING_LABELS


def replay_match_count(repro_info: Dict[str, Any] | None) -> int:
    """Count replay attempts that reproduced the same crash signature."""
    if not repro_info:
        return 0
    runs = repro_info.get("runs") or []
    return sum(1 for run in runs if run.get("replay_consistent"))


def replay_consistency_passed(
    repro_info: Dict[str, Any] | None,
    *,
    min_matches: int = 1,
) -> bool:
    """Return True when replay evidence confirms the retained crash.

    The runtime-collection gate only needs one replay-confirmed match to treat the
    PoC as reproducing the same crash manifestation. Callers may raise
    ``min_matches`` if they want a stricter policy.
    """
    if not repro_info:
        return False
    if not repro_info.get("enabled") or not repro_info.get("prepared"):
        return False
    return replay_match_count(repro_info) >= max(1, min_matches)
