"""Test case minimizer using delta debugging + libFuzzer minimize.

Two-stage minimization:
  1. libFuzzer -minimize_crash=1 (fast, engine-native)
  2. Python delta debugging fallback (if libFuzzer fails or input is still large)

Also provides verification that minimized input triggers the same crash signature.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from loguru import logger


@dataclass
class MinimizationResult:
    success: bool
    method: str                    # "libfuzzer" | "delta_debug" | "none"
    original_size: int
    minimized_size: int
    reduction_ratio: float         # 1.0 - minimized/original
    iterations: int
    verification_passed: bool
    minimized_path: Optional[str]
    error: Optional[str]


# libFuzzer-based minimization

def _run_libfuzzer_minimize(
    binary_path: str,
    poc_path: str,
    output_path: str,
    timeout: int = 60,
    max_runs: int = 100000,
) -> Tuple[bool, str]:
    """Run libFuzzer -minimize_crash=1 on the PoC."""
    cmd = [
        binary_path,
        f"-minimize_crash=1",
        f"-exact_artifact_path={output_path}",
        f"-max_total_time={timeout}",
        f"-runs={max_runs}",
        poc_path,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 10,
            env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
        )
        output = proc.stdout + "\n" + proc.stderr
        if os.path.isfile(output_path):
            return True, output
        return False, output
    except subprocess.TimeoutExpired:
        return os.path.isfile(output_path), "timeout"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Delta debugging
# ---------------------------------------------------------------------------

def delta_debug(
    input_data: bytes,
    test_fn: Callable[[bytes], bool],
    max_iterations: int = 100,
) -> Tuple[bytes, int]:
    """Classic delta debugging: repeatedly try removing chunks.

    Args:
        input_data: Original crash input bytes
        test_fn: Returns True if the input still triggers the crash
        max_iterations: Safety limit

    Returns:
        (minimized_bytes, iterations_used)
    """
    current = input_data
    n = 2
    iterations = 0

    while n <= len(current) and iterations < max_iterations:
        chunk_size = max(1, len(current) // n)
        reduced = False

        for i in range(n):
            start = i * chunk_size
            end = min(start + chunk_size, len(current))
            candidate = current[:start] + current[end:]

            if len(candidate) == 0:
                continue

            iterations += 1
            if test_fn(candidate):
                current = candidate
                reduced = True
                n = max(n - 1, 2)
                break

        if not reduced:
            if n >= len(current):
                break
            n = min(n * 2, len(current))

    return current, iterations


def _make_test_fn(
    binary_path: str,
    original_signature: Optional[str],
    timeout: int = 10,
) -> Callable[[bytes], bool]:
    """Create a test function for delta debugging that checks crash reproduction."""

    def test_fn(data: bytes) -> bool:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as f:
            f.write(data)
            tmp_path = f.name
        try:
            proc = subprocess.run(
                [binary_path, tmp_path],
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
            )
            output = proc.stdout + "\n" + proc.stderr
            # Check if it still crashes
            return "ERROR" in output or proc.returncode != 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return test_fn


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_minimized_crash(
    binary_path: str,
    minimized_path: str,
    original_signature: Optional[str] = None,
    timeout: int = 10,
) -> Tuple[bool, Optional[str]]:
    """Verify that minimized input still triggers a crash.

    Returns (passed, error_message).
    """
    if not os.path.isfile(minimized_path):
        return False, "minimized file not found"

    try:
        proc = subprocess.run(
            [binary_path, minimized_path],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"},
        )
        output = proc.stdout + "\n" + proc.stderr
        crashes = "ERROR" in output or proc.returncode != 0
        if not crashes:
            return False, "minimized input does not trigger crash"

        # Optionally check signature match
        if original_signature:
            from .sanitizer_parser import parse_sanitizer_output
            from .triage import compute_signatures
            parsed = parse_sanitizer_output(output)
            primary, _, _, _ = compute_signatures(parsed)
            if primary != original_signature:
                return False, f"signature mismatch: expected {original_signature}, got {primary}"

        return True, None
    except subprocess.TimeoutExpired:
        return False, "verification timed out"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Main minimize function
# ---------------------------------------------------------------------------

def minimize_testcase(
    binary_path: str,
    poc_path: str,
    output_dir: str,
    crash_id: str,
    original_signature: Optional[str] = None,
    libfuzzer_timeout: int = 60,
    enable_delta_debug: bool = True,
    delta_debug_threshold: int = 1024,
) -> Dict[str, Any]:
    """Two-stage minimization: libFuzzer first, delta debugging fallback.

    Args:
        binary_path: Fuzz target binary
        poc_path: Original PoC path
        output_dir: Directory to save minimized PoC
        crash_id: Crash identifier
        original_signature: Expected crash signature for verification
        libfuzzer_timeout: Timeout for libFuzzer minimization
        enable_delta_debug: Whether to try delta debugging as fallback
        delta_debug_threshold: Only delta-debug if input is smaller than this (bytes)

    Returns:
        JSON-serializable MinimizationResult dict.
    """
    if not os.path.isfile(poc_path):
        return asdict(MinimizationResult(
            success=False, method="none",
            original_size=0, minimized_size=0, reduction_ratio=0.0,
            iterations=0, verification_passed=False,
            minimized_path=None, error="PoC file not found",
        ))

    original_size = os.path.getsize(poc_path)
    os.makedirs(output_dir, exist_ok=True)
    min_path = os.path.join(output_dir, f"{crash_id}_minimized")

    # Stage 1: libFuzzer minimize
    ok, output = _run_libfuzzer_minimize(
        binary_path, poc_path, min_path, timeout=libfuzzer_timeout
    )

    if ok and os.path.isfile(min_path):
        minimized_size = os.path.getsize(min_path)
        verified, verr = verify_minimized_crash(
            binary_path, min_path, original_signature
        )
        if verified:
            ratio = 1.0 - (minimized_size / original_size) if original_size > 0 else 0.0
            return asdict(MinimizationResult(
                success=True, method="libfuzzer",
                original_size=original_size, minimized_size=minimized_size,
                reduction_ratio=round(ratio, 4), iterations=0,
                verification_passed=True, minimized_path=min_path, error=None,
            ))

    # Stage 2: Delta debugging fallback
    if enable_delta_debug and original_size <= delta_debug_threshold:
        logger.info(f"libFuzzer minimize failed/insufficient, trying delta debugging "
                    f"(input size={original_size})")
        try:
            with open(poc_path, "rb") as f:
                original_data = f.read()

            test_fn = _make_test_fn(binary_path, original_signature)

            if test_fn(original_data):
                minimized_data, iterations = delta_debug(
                    original_data, test_fn, max_iterations=100
                )
                with open(min_path, "wb") as f:
                    f.write(minimized_data)

                minimized_size = len(minimized_data)
                verified, verr = verify_minimized_crash(
                    binary_path, min_path, original_signature
                )
                ratio = 1.0 - (minimized_size / original_size) if original_size > 0 else 0.0
                return asdict(MinimizationResult(
                    success=True, method="delta_debug",
                    original_size=original_size, minimized_size=minimized_size,
                    reduction_ratio=round(ratio, 4), iterations=iterations,
                    verification_passed=verified, minimized_path=min_path,
                    error=verr,
                ))
        except Exception as e:
            logger.warning(f"Delta debugging failed: {e}")

    # Both stages failed
    shutil.copy2(poc_path, min_path)
    return asdict(MinimizationResult(
        success=False, method="none",
        original_size=original_size, minimized_size=original_size,
        reduction_ratio=0.0, iterations=0,
        verification_passed=False, minimized_path=min_path,
        error="Both libFuzzer and delta debugging failed",
    ))
