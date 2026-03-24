"""Deterministic parser for sanitizer (ASan/MSan/UBSan/TSan/LSan) + libFuzzer output.

Extracts structured fields from raw crash text without any LLM involvement.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Compiled regexes for the various fields we extract
# ---------------------------------------------------------------------------

# Split the ERROR header into multiple regexes to avoid lazy+optional interaction.
_ERROR_HEADER_RE = re.compile(
    r"ERROR:\s*(?P<sanitizer>\w+Sanitizer)\s*:\s*(?P<detail>.+?)$",
    re.MULTILINE,
)
_CRASH_ADDR_RE = re.compile(
    r"on unknown address\s+(?P<addr>0x[0-9a-fA-F]+)\s*"
    r"\(pc\s+(?P<pc>0x[0-9a-fA-F]+)\s+bp\s+(?P<bp>0x[0-9a-fA-F]+)\s+"
    r"sp\s+(?P<sp>0x[0-9a-fA-F]+)\s+T(?P<thread>\d+)\)",
    re.MULTILINE,
)
_SIGNAL_RE = re.compile(
    r"The signal is caused by a (?P<access_type>\w+) memory access", re.MULTILINE
)
_SCARINESS_RE = re.compile(
    r"SCARINESS:\s*(?P<score>\d+)\s*\((?P<desc>[^)]+)\)", re.MULTILINE
)
_DEDUP_TOKEN_RE = re.compile(r"^\s*DEDUP_TOKEN:\s*(?P<token>\S+)\s*$", re.MULTILINE)
_SUMMARY_RE = re.compile(r"^\s*SUMMARY:\s*(?P<summary>.+)\s*$", re.MULTILINE)
_TEST_UNIT_RE = re.compile(
    r"Test unit written to\s+(?P<path>\S+)", re.MULTILINE
)
_BASE_UNIT_RE = re.compile(
    r"MS:\s*\d+.*?base unit:\s*(?P<hash>[0-9a-fA-F]{8,64})", re.MULTILINE
)
_HINT_RE = re.compile(
    r"Hint:\s*(?P<hint>.+?)$", re.MULTILINE
)

# Stack frame with source info
_FRAME_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+in\s+(?P<func>\S+)\s+(?P<file>[^:\s]+):(?P<line>\d+)(?::(?P<col>\d+))?\s*$",
    re.MULTILINE,
)
# Stack frame without source info (e.g. stripped binary)
_FRAME_NO_SRC_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+in\s+(?P<func>\S+)\s*$",
    re.MULTILINE,
)
# Stack frame with only address (e.g. .so offset)
_FRAME_ADDR_ONLY_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+\((?P<module>[^+]+)\+(?P<offset>0x[0-9a-fA-F]+)\)",
    re.MULTILINE,
)

_REGISTER_RE = re.compile(
    r"(?P<reg>r[a-z0-9]+|[re][abcds][xip])\s*=\s*(?P<val>0x[0-9a-fA-F]+)",
    re.MULTILINE,
)

_DEADLY_SIGNAL_RE = re.compile(r"libFuzzer:\s*deadly signal", re.MULTILINE)
_TIMEOUT_RE = re.compile(r"ALARM:\s*working on the last", re.MULTILINE)
_OOM_RE = re.compile(r"out-of-memory|oom|rss limit exhausted", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CrashFrame:
    idx: int
    func: str
    file: Optional[str]
    line: Optional[int]
    col: Optional[int] = None
    address: Optional[str] = None
    module: Optional[str] = None


@dataclass
class SanitizerParseResult:
    sanitizer_type: Optional[str] = None
    bug_type: Optional[str] = None
    crash_address: Optional[str] = None
    pc: Optional[str] = None
    access_type: Optional[str] = None
    signal_hint: Optional[str] = None
    scariness_score: Optional[int] = None
    scariness_desc: Optional[str] = None
    summary: Optional[str] = None
    dedup_token: Optional[str] = None
    artifact_path_hint: Optional[str] = None
    base_unit_hash: Optional[str] = None
    frames: List[CrashFrame] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    first_in_project_frame: Optional[str] = None
    first_in_project_function: Optional[str] = None
    is_deadly_signal_only: bool = False
    is_timeout: bool = False
    is_oom: bool = False
    has_asan_stack: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BUG_TYPE_MAP = {
    "LeakSanitizer": "memory-leak",
}

def _normalize_bug_type(sanitizer_type: Optional[str], detail: Optional[str]) -> Optional[str]:
    if not sanitizer_type and not detail:
        return None
    if sanitizer_type in _BUG_TYPE_MAP:
        return _BUG_TYPE_MAP[sanitizer_type]
    if detail:
        core = detail.split(" on ")[0].split("(")[0].strip()
        return core if core else detail.strip()
    return sanitizer_type


def _is_project_frame(file_path: str) -> bool:
    """Heuristic: /src/<project>/... is project code; exclude compiler-rt, llvm, libfuzzer."""
    if not file_path:
        return False
    lowered = file_path.lower()
    if "/src/" not in lowered:
        return False
    exclude = ("llvm-project", "compiler-rt", "libfuzzer", "lib/fuzzer")
    return not any(ex in lowered for ex in exclude)


def _is_runtime_frame(file_path: str, func: str) -> bool:
    """Identify sanitizer/fuzzer runtime frames."""
    lowered_file = (file_path or "").lower()
    lowered_func = (func or "").lower()
    runtime_paths = ("compiler-rt", "lib/fuzzer", "llvm-project", "libfuzzer")
    runtime_funcs = ("__interceptor_", "__asan_", "__msan_", "__tsan_", "__lsan_",
                     "fuzzer::fuzzer", "__libc_start")
    if any(p in lowered_file for p in runtime_paths):
        return True
    if any(f in lowered_func for f in runtime_funcs):
        return True
    return False


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_sanitizer_output(crash_info: str) -> Dict[str, Any]:
    """Parse sanitizer + libFuzzer textual output into structured fields.

    Returns a JSON-serializable dict.
    """
    result = SanitizerParseResult()

    # --- Error header ---
    m = _ERROR_HEADER_RE.search(crash_info)
    if m:
        result.sanitizer_type = m.group("sanitizer")
        detail = (m.group("detail") or "").strip()
        result.bug_type = _normalize_bug_type(result.sanitizer_type, detail)

    # --- Crash address / pc (separate regex) ---
    m = _CRASH_ADDR_RE.search(crash_info)
    if m:
        result.crash_address = m.group("addr")
        result.pc = m.group("pc")

    # --- Signal / access type ---
    m = _SIGNAL_RE.search(crash_info)
    if m:
        result.access_type = m.group("access_type")

    m = _HINT_RE.search(crash_info)
    if m:
        result.signal_hint = m.group("hint").strip()

    # --- SCARINESS ---
    m = _SCARINESS_RE.search(crash_info)
    if m:
        result.scariness_score = int(m.group("score"))
        result.scariness_desc = m.group("desc")

    # --- DEDUP_TOKEN ---
    m = _DEDUP_TOKEN_RE.search(crash_info)
    if m:
        result.dedup_token = m.group("token")

    # --- SUMMARY ---
    m = _SUMMARY_RE.search(crash_info)
    if m:
        result.summary = m.group("summary").strip()

    # --- Artifact / test unit path ---
    m = _TEST_UNIT_RE.search(crash_info)
    if m:
        result.artifact_path_hint = m.group("path").strip()

    # --- Base unit hash ---
    m = _BASE_UNIT_RE.search(crash_info)
    if m:
        result.base_unit_hash = m.group("hash").strip()

    # --- Stack frames (multiple formats) ---
    seen_idx: set = set()
    frames: List[CrashFrame] = []

    for fm in _FRAME_RE.finditer(crash_info):
        idx = int(fm.group("idx"))
        if idx in seen_idx:
            continue
        seen_idx.add(idx)
        col_raw = fm.group("col")
        frames.append(CrashFrame(
            idx=idx,
            func=fm.group("func"),
            file=fm.group("file"),
            line=int(fm.group("line")),
            col=int(col_raw) if col_raw else None,
            address=fm.group("addr"),
        ))

    for fm in _FRAME_NO_SRC_RE.finditer(crash_info):
        idx = int(fm.group("idx"))
        if idx in seen_idx:
            continue
        seen_idx.add(idx)
        frames.append(CrashFrame(
            idx=idx, func=fm.group("func"), file=None, line=None,
            address=fm.group("addr"),
        ))

    for fm in _FRAME_ADDR_ONLY_RE.finditer(crash_info):
        idx = int(fm.group("idx"))
        if idx in seen_idx:
            continue
        seen_idx.add(idx)
        frames.append(CrashFrame(
            idx=idx, func="??", file=None, line=None,
            address=fm.group("addr"), module=fm.group("module").strip(),
        ))

    frames.sort(key=lambda f: f.idx)
    result.frames = frames
    result.has_asan_stack = len(frames) > 0

    # --- Registers ---
    for rm in _REGISTER_RE.finditer(crash_info):
        result.registers[rm.group("reg")] = rm.group("val")

    # --- First in-project frame ---
    for fr in frames:
        if fr.file and _is_project_frame(fr.file):
            result.first_in_project_frame = f"{fr.file}:{fr.line}"
            result.first_in_project_function = fr.func
            break

    # --- Special conditions ---
    result.is_deadly_signal_only = bool(_DEADLY_SIGNAL_RE.search(crash_info)) and not result.has_asan_stack
    result.is_timeout = bool(_TIMEOUT_RE.search(crash_info))
    result.is_oom = bool(_OOM_RE.search(crash_info))

    d = asdict(result)
    d["frames"] = [asdict(f) for f in frames]
    return d


def format_crash_summary(parsed: Dict[str, Any], max_frames: int = 8) -> str:
    """Create a short deterministic summary for LLM context."""
    lines = []
    san = parsed.get("sanitizer_type") or "UnknownSanitizer"
    bug = parsed.get("bug_type") or "unknown"
    lines.append(f"[CRASH] sanitizer={san}  bug_type={bug}")

    if parsed.get("crash_address"):
        lines.append(f"[CRASH] crash_address={parsed['crash_address']}")
    if parsed.get("access_type"):
        lines.append(f"[CRASH] access_type={parsed['access_type']}")
    if parsed.get("signal_hint"):
        lines.append(f"[CRASH] hint={parsed['signal_hint']}")
    if parsed.get("scariness_score") is not None:
        lines.append(f"[CRASH] scariness={parsed['scariness_score']} ({parsed.get('scariness_desc', '')})")

    loc = parsed.get("first_in_project_frame") or "unknown"
    func = parsed.get("first_in_project_function") or "unknown"
    lines.append(f"[CRASH] first_project_location={loc}  function={func}")

    if parsed.get("dedup_token"):
        lines.append(f"[CRASH] dedup_token={parsed['dedup_token']}")

    if parsed.get("is_deadly_signal_only"):
        lines.append("[CRASH] WARNING: deadly signal only, no ASan stack trace")
    if parsed.get("is_timeout"):
        lines.append("[CRASH] WARNING: timeout detected")
    if parsed.get("is_oom"):
        lines.append("[CRASH] WARNING: out-of-memory detected")

    frames = parsed.get("frames") or []
    if frames:
        lines.append(f"[CRASH] stack_depth={len(frames)}  showing_top={min(len(frames), max_frames)}")
        for fr in frames[:max_frames]:
            loc_str = f"{fr.get('file', '??')}:{fr.get('line', '?')}" if fr.get('file') else "(no source)"
            tag = "PROJECT" if (fr.get("file") and _is_project_frame(fr["file"])) else "runtime"
            lines.append(f"  #{fr.get('idx')}  [{tag}] {fr.get('func', '??')} @ {loc_str}")

    regs = parsed.get("registers") or {}
    if regs:
        reg_strs = [f"{k}={v}" for k, v in list(regs.items())[:8]]
        lines.append(f"[CRASH] registers: {', '.join(reg_strs)}")

    return "\n".join(lines)
