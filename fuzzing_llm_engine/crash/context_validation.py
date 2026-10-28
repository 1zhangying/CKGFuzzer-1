"""Shared validation for static and runtime crash context.

The context pipeline must not treat "some crash happened under the provided
PoC" as reproduction of the retained crash.  This module implements the
paper-aligned crash identity check used by both legacy-context reuse and fresh
GDB collection.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


_RUNTIME_FILE_MARKERS = (
    "/compiler-rt/",
    "/llvm-project/",
    "/lib/fuzzer/",
    "/libfuzzer/",
    "sanitizer_common",
    "/sysdeps/",
    "/lib/x86_64-linux-gnu/",
    "/lib64/",
    "/usr/lib/",
)
_RUNTIME_FUNCTION_PREFIXES = (
    "__asan_",
    "__msan_",
    "__ubsan_",
    "__tsan_",
    "__lsan_",
    "__sanitizer",
    "__interceptor_",
    "___interceptor_",
    "__gi_",
    "__libc_",
    "__pthread_",
    "__memcpy",
    "__memmove",
    "__memset",
    "__strcmp",
    "__strlen",
    "fuzzer::",
)
_RUNTIME_FUNCTIONS = {
    "abort",
    "main",
    "malloc_printerr",
    "_int_free",
    "reportgenericerror",
    "reportgenericerrorwrapper",
    "scanf_common",
}
_DRIVER_FUNCTIONS = {
    "llvmfuzzertestoneinput",
}


def _function(frame: Dict[str, Any]) -> str:
    return str(frame.get("function") or frame.get("func") or "").strip()


def _file(frame: Dict[str, Any]) -> str:
    return str(frame.get("file") or "").replace("\\", "/")


def _line(frame: Dict[str, Any]) -> Optional[int]:
    value = frame.get("line")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _normalized_basename(path: str) -> str:
    return Path(path).name.lower()


def is_runtime_frame(frame: Dict[str, Any]) -> bool:
    """Return whether a sanitizer/GDB frame belongs to crash plumbing."""
    function = _function(frame).lower()
    file_name = _file(frame).lower()
    if any(marker in file_name for marker in _RUNTIME_FILE_MARKERS):
        return True
    if function in _RUNTIME_FUNCTIONS:
        return True
    return any(function.startswith(prefix) for prefix in _RUNTIME_FUNCTION_PREFIXES)


def is_driver_frame(
    frame: Dict[str, Any],
    driver_basename: Optional[str] = None,
) -> bool:
    """Return whether a frame is the generated libFuzzer harness."""
    function = _function(frame).lower()
    file_name = _file(frame).lower()
    if function in _DRIVER_FUNCTIONS:
        return True
    if driver_basename:
        expected = Path(driver_basename).name.lower()
        if expected and expected in Path(file_name).name:
            return True
    return "/test/" in file_name and "fuzz_driver" in file_name


def is_target_frame(
    frame: Dict[str, Any],
    driver_basename: Optional[str] = None,
) -> bool:
    """Return whether a frame is a target-library frame."""
    function = _function(frame)
    if not function or function in {"?", "??", "unknown"}:
        return False
    return not is_runtime_frame(frame) and not is_driver_frame(frame, driver_basename)


def first_target_frame(
    frames: Iterable[Dict[str, Any]],
    driver_basename: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the first target-library frame in stack order."""
    for frame in frames:
        if isinstance(frame, dict) and is_target_frame(frame, driver_basename):
            return frame
    return None


def expected_target_frame(
    parsed: Dict[str, Any],
    driver_basename: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the original crash's first target-library frame."""
    return first_target_frame(parsed.get("frames") or [], driver_basename)


def _frame_kind(
    frame: Dict[str, Any],
    driver_basename: Optional[str],
) -> Optional[str]:
    if is_target_frame(frame, driver_basename):
        return "target"
    if is_driver_frame(frame, driver_basename):
        return "driver"
    return None


def _ordered_kind_frames(
    frames: Iterable[Dict[str, Any]],
    kind: str,
    driver_basename: Optional[str],
) -> list[Dict[str, Any]]:
    return [
        frame
        for frame in frames
        if isinstance(frame, dict)
        and _frame_kind(frame, driver_basename) == kind
    ]


def _expected_anchor(
    parsed: Dict[str, Any],
    driver_basename: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    frames = parsed.get("frames") or []
    target = first_target_frame(frames, driver_basename)
    if target is not None:
        return target, "target"
    driver = next(
        (
            frame
            for frame in frames
            if isinstance(frame, dict)
            and is_driver_frame(frame, driver_basename)
        ),
        None,
    )
    if driver is not None:
        return driver, "driver"
    return None, None


def static_context_is_complete(location: Optional[Dict[str, Any]]) -> bool:
    """Return whether a static context contains both site and chain source."""
    if not isinstance(location, dict) or not location.get("crash_code_snippet"):
        return False
    return any(
        isinstance(frame, dict) and frame.get("code_snippet")
        for frame in (location.get("call_chain_context") or [])
    )


def static_context_summary(
    location: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return a compact static-context status for experiment artifacts."""
    context = location if isinstance(location, dict) else {}
    return {
        "status": "available" if static_context_is_complete(context) else "unavailable",
        "crash_file": context.get("crash_file"),
        "crash_line": context.get("crash_line"),
        "crash_function": context.get("crash_function"),
        "snippet_frames": sum(
            1
            for frame in (context.get("call_chain_context") or [])
            if isinstance(frame, dict) and frame.get("code_snippet")
        ),
    }


def _same_location(
    expected: Dict[str, Any],
    observed: Dict[str, Any],
) -> bool:
    expected_file = _file(expected)
    observed_file = _file(observed)
    if expected_file:
        if not observed_file:
            return False
        if _normalized_basename(expected_file) != _normalized_basename(observed_file):
            return False
        expected_line = _line(expected)
        observed_line = _line(observed)
        if expected_line is not None:
            return expected_line == observed_line
    return True


def _anchor_position(
    frames: list[Dict[str, Any]],
    expected: Dict[str, Any],
    *,
    max_preceding_frames: int = 5,
    allow_missing_observed_location: bool = False,
) -> Optional[int]:
    expected_function = _function(expected).lower()
    for index, frame in enumerate(frames[:max_preceding_frames]):
        if _function(frame).lower() != expected_function:
            continue
        if _same_location(expected, frame):
            return index
        if (
            allow_missing_observed_location
            and _file(expected)
            and not _file(frame)
        ):
            return index
    return None


def parsed_crashes_match(
    expected: Dict[str, Any],
    observed: Dict[str, Any],
    driver_basename: Optional[str] = None,
) -> Tuple[bool, str]:
    """Match reconstructed and original stacks after inlining normalization."""
    if expected.get("bug_type") != observed.get("bug_type"):
        return False, "bug_type_mismatch"

    anchor, kind = _expected_anchor(expected, driver_basename)
    if anchor is None or kind is None:
        return False, "original_anchor_frame_missing"

    observed_frames = _ordered_kind_frames(
        observed.get("frames") or [],
        kind,
        driver_basename,
    )
    anchor_index = _anchor_position(observed_frames, anchor)
    if anchor_index is None:
        return False, "anchor_function_or_location_mismatch"

    expected_after = [
        _function(frame).lower()
        for frame in _ordered_kind_frames(
            expected.get("frames") or [],
            kind,
            driver_basename,
        )
        if _function(frame).lower() != _function(anchor).lower()
    ]
    if expected_after:
        observed_after = {
            _function(frame).lower()
            for frame in observed_frames[anchor_index + 1:]
        }
        if not any(function in observed_after for function in expected_after):
            return False, "following_target_stack_mismatch"
    return True, "anchor_and_stack_matched"


def runtime_context_matches_parsed(
    runtime_context: Dict[str, Any],
    parsed: Dict[str, Any],
    driver_basename: Optional[str] = None,
) -> Tuple[bool, str]:
    """Check whether a GDB snapshot stopped in the retained crash.

    Matching is intentionally based on the first target-library frame rather
    than any frame in the stack.  The latter would accept unrelated crashes
    merely because they pass through the same generated fuzzer harness.
    """
    if not runtime_context or not runtime_context.get("reproduced"):
        return False, "runtime_context_not_reproduced"

    expected, kind = _expected_anchor(parsed, driver_basename)
    if expected is None or kind is None:
        bug_type = str(parsed.get("bug_type") or "").lower()
        stop_reason = str(runtime_context.get("stop_reason") or "")
        if (
            bug_type in {"stack-overflow", "stack overflow"}
            and (
                str(runtime_context.get("exit_signal") or "").upper() == "SIGSEGV"
                or stop_reason == "signal:SIGSEGV"
            )
        ):
            return True, "stack_overflow_signal_matched"
        return False, "original_anchor_frame_missing"

    observed_frames = _ordered_kind_frames(
        runtime_context.get("call_stack") or [],
        kind,
        driver_basename,
    )
    if not observed_frames:
        return False, f"runtime_{kind}_frame_missing"
    if (
        _anchor_position(
            observed_frames,
            expected,
            allow_missing_observed_location=kind == "target",
        )
        is None
    ):
        observed = observed_frames[0]
        return (
            False,
            "anchor_function_or_location_mismatch:"
            f"{_function(expected)}@{_file(expected)}:{_line(expected)}"
            f"->{_function(observed)}@{_file(observed)}:{_line(observed)}",
        )
    anchor_index = _anchor_position(
        observed_frames,
        expected,
        allow_missing_observed_location=kind == "target",
    )
    expected_after = [
        _function(frame).lower()
        for frame in _ordered_kind_frames(
            parsed.get("frames") or [],
            kind,
            driver_basename,
        )
        if _function(frame).lower() != _function(expected).lower()
    ]
    if expected_after:
        observed_after = {
            _function(frame).lower()
            for frame in observed_frames[anchor_index + 1:]
        }
        if not any(function in observed_after for function in expected_after):
            return False, "following_stack_mismatch"
    return True, "matched"


def runtime_context_summary(
    runtime_context: Optional[Dict[str, Any]],
    parsed: Optional[Dict[str, Any]] = None,
    driver_basename: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a JSON-serializable status summary for experiment artifacts."""
    context = runtime_context if isinstance(runtime_context, dict) else {}
    matched = False
    reason = "runtime_context_missing"
    if context and parsed is not None:
        matched, reason = runtime_context_matches_parsed(
            context,
            parsed,
            driver_basename,
        )
        validation_reason = context.get("validation_reason")
        if not matched and validation_reason not in {None, "", "not_checked"}:
            reason = str(validation_reason)
    elif context and not context.get("reproduced"):
        reason = str(context.get("error_message") or "runtime_context_not_reproduced")
    return {
        "status": "available" if matched else "unavailable",
        "reason": reason,
        "reproduced": bool(context.get("reproduced")),
        "matches_original": (
            matched if parsed is not None else context.get("matches_original")
        ),
        "stable": context.get("stable"),
        "stability_ratio": context.get("stability_ratio"),
        "matching_attempts": context.get("matching_attempts"),
        "collection_method": context.get("collection_method"),
        "stop_reason": context.get("stop_reason"),
        "evidence_quality": context.get("evidence_quality"),
        "crash_frame": (context.get("crash_frame") or {}).get("function"),
    }
