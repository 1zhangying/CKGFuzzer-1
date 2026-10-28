"""Resolve evidence files associated with one crash record."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


def find_driver_source(
    db_root: str | Path,
    project: str,
    driver: str,
    entry: Optional[Mapping[str, Any]] = None,
    *,
    extra_candidates: Iterable[str | Path] = (),
) -> Optional[str]:
    """Return the driver source used by the retained crash.

    The per-crash source named by ``fuzz_driver_file`` is authoritative.
    Shared driver files are fallback candidates only because generated drivers
    can be repaired or regenerated after a crash was recorded.
    """
    db_root_path = Path(db_root)
    crash_dir = db_root_path / project / "crash" / driver
    engine_root = Path(__file__).resolve().parents[1]
    candidates = []

    saved_name = os.path.basename(
        str((entry or {}).get("fuzz_driver_file") or "").strip()
    )
    if saved_name:
        candidates.extend(
            [
                crash_dir / saved_name,
                engine_root / "build" / "out" / project / "src" / project / "test" / saved_name,
                engine_root / "build" / "out" / project / "src" / project / saved_name,
                engine_root / "build" / "out" / project / "src" / saved_name,
            ]
        )

    candidates.extend(
        [
            crash_dir / f"{driver}.cc",
            *extra_candidates,
            db_root_path / project / "fuzz_driver" / f"{driver}.cc",
            engine_root / "build" / "out" / project / "src" / project / "test" / f"{driver}.cc",
            Path("/home/cc/CKGFuzzer-1/docker_shared/fuzz_driver")
            / project
            / "compilation_pass_rag"
            / f"{driver}.cc",
        ]
    )
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return str(path)
    return None


def filter_api_names(
    driver_source: str,
    candidate_apis: Iterable[str],
    required_apis: Iterable[str] = (),
) -> list[str]:
    """Keep target APIs referenced by the crash-time driver source."""
    selected = []
    seen = set()
    required = {
        str(name or "").strip().rsplit("()", 1)[0]
        for name in required_apis
        if str(name or "").strip()
    }
    for raw_name in candidate_apis:
        name = str(raw_name or "").strip()
        if not name or name in seen:
            continue
        short_name = name.rsplit("::", 1)[-1]
        patterns = [
            rf"\b{re.escape(name)}\b",
            rf"(?:->|\.)\s*{re.escape(short_name)}\s*\(",
        ]
        normalized = name.rsplit("()", 1)[0]
        if (
            normalized in required
            or short_name.rsplit("()", 1)[0] in required
            or any(re.search(pattern, driver_source) for pattern in patterns)
        ):
            selected.append(name)
            seen.add(name)
    return selected
