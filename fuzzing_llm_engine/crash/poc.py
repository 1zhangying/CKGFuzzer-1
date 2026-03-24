from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class PocLocateResult:
    kind: str  # artifact_hint | base_unit_hash | none
    host_path: Optional[str]
    exists: bool


def _repo_root() -> Path:
    # fuzzing_llm_engine/crash/poc.py -> fuzzing_llm_engine -> repo root
    return Path(__file__).resolve().parents[2]


def _oss_fuzz_out_dir(project_name: str) -> Path:
    # Matches fuzzing_llm_engine/utils/check_gen_fuzzer.py BUILD_DIR layout.
    return _repo_root() / "fuzzing_llm_engine" / "build" / "out" / project_name


def locate_poc_on_host(
    parsed: Dict[str, Any],
    project_name: str,
    corpus_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Try to locate a PoC file on the host.
    Priority:
      1) sanitizer artifact_path_hint (e.g., ./crash-xxxx, ./leak-xxxx) in build/out/<project>
      2) base_unit_hash in corpus_dir (libFuzzer corpus file name)
    """
    out_dir = _oss_fuzz_out_dir(project_name)

    hint = parsed.get("artifact_path_hint")
    if hint:
        # hint can be "./leak-xxxx" or "leak-xxxx"
        name = Path(hint).name
        candidate = out_dir / name
        return asdict(
            PocLocateResult(
                kind="artifact_hint",
                host_path=str(candidate),
                exists=candidate.exists(),
            )
        )

    base_unit = parsed.get("base_unit_hash")
    if base_unit and corpus_dir:
        candidate = Path(corpus_dir) / base_unit
        return asdict(
            PocLocateResult(
                kind="base_unit_hash",
                host_path=str(candidate),
                exists=candidate.exists(),
            )
        )

    return asdict(PocLocateResult(kind="none", host_path=None, exists=False))


def safe_copy_poc(src_path: str, dst_path: str) -> Tuple[bool, Optional[str]]:
    src = Path(src_path)
    dst = Path(dst_path)
    try:
        if not src.exists() or not src.is_file():
            return False, "src_missing"
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Copy bytes (don't assume text).
        dst.write_bytes(src.read_bytes())
        return True, None
    except Exception as e:
        return False, str(e)

