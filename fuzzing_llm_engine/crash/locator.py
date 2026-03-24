"""Precise crash locator — extracts source code context from stack frames.

Uses sanitizer-parsed stack frames to:
  1. Read the actual source file at the crash location
  2. Extract surrounding code context (N lines before/after)
  3. Build a call-chain context for all relevant frames
  4. Distinguish project frames from driver/runtime frames
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


@dataclass
class FrameContext:
    frame_idx: int
    function: str
    file: Optional[str]
    line: Optional[int]
    col: Optional[int]
    frame_type: str               # "project" | "driver" | "runtime"
    code_snippet: Optional[str]   # source code around the crash line
    snippet_start_line: int = 0
    snippet_end_line: int = 0


@dataclass
class LocationResult:
    crash_file: Optional[str]
    crash_line: Optional[int]
    crash_function: Optional[str]
    crash_code_snippet: Optional[str]
    call_chain_context: List[FrameContext]
    total_frames: int
    project_frames: int
    driver_frames: int
    symbolized: bool


# Source code reading

_SOURCE_SEARCH_ROOTS: List[str] = []

def set_source_search_roots(roots: List[str]):
    """Configure directories to search for source files.

    Call this once at startup with paths like ["/src", project_src_dir].
    """
    global _SOURCE_SEARCH_ROOTS
    _SOURCE_SEARCH_ROOTS = list(roots)


def _find_source_file(file_path: str) -> Optional[str]:
    """Try to locate a source file on the host filesystem.

    Sanitizer paths are container-internal (e.g. /src/c-ares/src/lib/foo.c).
    We try several strategies to map them to the host.
    """
    if not file_path:
        return None

    # Direct path
    if os.path.isfile(file_path):
        return file_path

    # Try search roots
    for root in _SOURCE_SEARCH_ROOTS:
        candidate = os.path.join(root, file_path.lstrip("/"))
        if os.path.isfile(candidate):
            return candidate
        # Try with just the basename
        candidate = os.path.join(root, os.path.basename(file_path))
        if os.path.isfile(candidate):
            return candidate

    # Try stripping leading /src/<project>/ and searching
    parts = file_path.split("/")
    for i in range(len(parts)):
        sub = "/".join(parts[i:])
        for root in _SOURCE_SEARCH_ROOTS:
            candidate = os.path.join(root, sub)
            if os.path.isfile(candidate):
                return candidate

    return None


def _read_code_context(file_path: str, line: int, before: int = 10, after: int = 10) -> Optional[str]:
    """Read source file and extract lines around the given line number."""
    host_path = _find_source_file(file_path)
    if not host_path:
        return None

    try:
        with open(host_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except (IOError, OSError) as e:
        logger.warning(f"Cannot read source file {host_path}: {e}")
        return None

    total = len(all_lines)
    if line < 1 or line > total:
        return None

    start = max(0, line - 1 - before)
    end = min(total, line + after)

    snippet_lines = []
    for i in range(start, end):
        marker = " >>>" if (i + 1) == line else "    "
        snippet_lines.append(f"{marker} {i + 1:>5}| {all_lines[i].rstrip()}")

    return "\n".join(snippet_lines)


# Frame classification

def _classify_frame(frame: Dict[str, Any], driver_basename: Optional[str]) -> str:
    func = (frame.get("func") or "").lower()
    fpath = (frame.get("file") or "").lower()

    # Driver
    if "llvmfuzzertestoneinput" in func:
        return "driver"
    if driver_basename and driver_basename.lower() in fpath:
        return "driver"
    if "/test/" in fpath and "fuzz_driver" in fpath:
        return "driver"

    # Runtime
    runtime_markers = ("compiler-rt", "lib/fuzzer", "llvm-project", "libfuzzer",
                       "__libc_start", "__interceptor_")
    if any(m in fpath for m in runtime_markers) or any(m in func for m in runtime_markers):
        return "runtime"

    # Project
    if "/src/" in fpath:
        return "project"

    return "runtime"


# addr2line / llvm-symbolizer fallback

def symbolize_address(binary_path: str, address: str) -> Optional[Dict[str, str]]:
    """Use addr2line or llvm-symbolizer to resolve an address."""
    for tool in ("llvm-symbolizer", "addr2line"):
        try:
            cmd = [tool, "-e", binary_path, "-f", address]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().split("\n")
                if len(lines) >= 2:
                    func = lines[0].strip()
                    loc = lines[1].strip()
                    if ":" in loc and "??" not in func:
                        parts = loc.split(":")
                        return {"func": func, "file": parts[0], "line": parts[1]}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


# Main locator

def locate_crash_site(
    parsed: Dict[str, Any],
    driver_basename: Optional[str] = None,
    context_lines_before: int = 10,
    context_lines_after: int = 10,
    max_context_frames: int = 6,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Locate crash site and build call-chain context from parsed sanitizer output.

    Args:
        parsed: Output of parse_sanitizer_output()
        driver_basename: Fuzz driver filename for frame classification
        context_lines_before/after: How many lines of code context to extract
        max_context_frames: Max number of frames to extract code context for
        binary_path: Optional binary path for addr2line symbolization

    Returns:
        JSON-serializable dict with crash location and call-chain context.
    """
    frames = parsed.get("frames") or []

    crash_file = None
    crash_line = None
    crash_func = None
    crash_snippet = None
    symbolized = False

    call_chain: List[FrameContext] = []
    project_count = 0
    driver_count = 0

    context_extracted = 0
    for fr in frames:
        ftype = _classify_frame(fr, driver_basename)
        if ftype == "project":
            project_count += 1
        elif ftype == "driver":
            driver_count += 1

        # Skip runtime frames for context extraction
        if ftype == "runtime":
            continue

        fpath = fr.get("file")
        fline = fr.get("line")
        ffunc = fr.get("func", "??")

        # Try to extract code context
        snippet = None
        if fpath and fline and context_extracted < max_context_frames:
            snippet = _read_code_context(
                fpath, fline, context_lines_before, context_lines_after
            )
            if snippet:
                context_extracted += 1
                symbolized = True

        # If no source but we have address + binary, try symbolization
        if not snippet and not fpath and fr.get("address") and binary_path:
            sym = symbolize_address(binary_path, fr["address"])
            if sym:
                fpath = sym.get("file")
                try:
                    fline = int(sym["line"])
                except (ValueError, KeyError):
                    pass
                ffunc = sym.get("func", ffunc)
                if fpath and fline:
                    snippet = _read_code_context(
                        fpath, fline, context_lines_before, context_lines_after
                    )
                    if snippet:
                        context_extracted += 1
                        symbolized = True

        fc = FrameContext(
            frame_idx=fr.get("idx", 0),
            function=ffunc,
            file=fpath,
            line=fline,
            col=fr.get("col"),
            frame_type=ftype,
            code_snippet=snippet,
        )
        call_chain.append(fc)

        # First project frame is the primary crash site
        if ftype == "project" and crash_file is None:
            crash_file = fpath
            crash_line = fline
            crash_func = ffunc
            crash_snippet = snippet

    result = LocationResult(
        crash_file=crash_file,
        crash_line=crash_line,
        crash_function=crash_func,
        crash_code_snippet=crash_snippet,
        call_chain_context=call_chain,
        total_frames=len(frames),
        project_frames=project_count,
        driver_frames=driver_count,
        symbolized=symbolized,
    )

    d = asdict(result)
    d["call_chain_context"] = [asdict(fc) for fc in call_chain]
    return d


def format_call_chain_for_llm(location: Dict[str, Any], max_frames: int = 5) -> str:
    """Format call-chain context into a readable string for the LLM prompt."""
    lines = []
    chain = location.get("call_chain_context") or []

    if location.get("crash_file"):
        lines.append(f"=== CRASH SITE: {location['crash_function']}() "
                     f"at {location['crash_file']}:{location['crash_line']} ===")
    else:
        lines.append("=== CRASH SITE: (could not determine precise location) ===")

    if location.get("crash_code_snippet"):
        lines.append(location["crash_code_snippet"])
        lines.append("")

    shown = 0
    for fc in chain:
        if shown >= max_frames:
            lines.append(f"  ... ({len(chain) - shown} more frames omitted)")
            break
        tag = fc.get("frame_type", "?").upper()
        loc = f"{fc.get('file', '??')}:{fc.get('line', '?')}" if fc.get("file") else "(no source)"
        lines.append(f"--- Frame #{fc['frame_idx']} [{tag}] {fc['function']}() @ {loc} ---")
        if fc.get("code_snippet"):
            lines.append(fc["code_snippet"])
            lines.append("")
        shown += 1

    return "\n".join(lines)
