"""GDB-based dynamic debugger for crash reproduction and runtime context collection.

Automates GDB to:
  1. Reproduce a crash using a PoC input
  2. Collect runtime context at the crash point (locals, args, registers, memory)
  3. Walk the call stack and collect per-frame context
  4. Generate a structured runtime snapshot for LLM analysis
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from .context_validation import (
    first_target_frame,
    runtime_context_matches_parsed,
)


@dataclass
class FrameState:
    frame_id: int
    function: str
    file: Optional[str]
    line: Optional[int]
    arguments: Dict[str, str]
    locals: Dict[str, str]


@dataclass
class RuntimeContext:
    reproduced: bool
    exit_signal: Optional[str]
    registers: Dict[str, str]
    crash_frame: Optional[FrameState]
    call_stack: List[FrameState]
    backtrace_text: Optional[str]
    error_message: Optional[str]


_IMPORTANT_REGS = ["rip", "rsp", "rbp", "rax", "rdi", "rsi", "rdx", "rcx"]
_OSS_FUZZ_GDB_RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner-debug"


def gdb_runtime_image(project: Optional[str] = None) -> str:
    """Return the official OSS-Fuzz image that includes GDB."""
    return _OSS_FUZZ_GDB_RUNNER_IMAGE


# GDB script generation

_GDB_SCRIPT_TEMPLATE = """\
set pagination off
set confirm off
set disable-randomization on
set breakpoint pending on
set print elements 200
set print repeats 5
set print pretty on
{environment_commands}

# ASan normally reports the fault and exits without raising a signal.  Stop in
# the sanitizer report entry so the target call chain and locals are still live.
break __asan::ReportGenericError
break __msan::ReportUMR
break __tsan::ReportRace
break __ubsan::ScopedReport::ScopedReport
break __sanitizer::Die

# Run with PoC input
run "{poc_path}"

# If we get here, a sanitizer report or signal stopped the inferior.
echo ===GDB_BACKTRACE_START===\\n
bt {backtrace_limit}
echo ===GDB_BACKTRACE_END===\\n

echo ===GDB_REGISTERS_START===\\n
info registers
echo ===GDB_REGISTERS_END===\\n

echo ===GDB_FRAME_0_START===\\n
frame 0
echo ---ARGS---\\n
info args
echo ---LOCALS---\\n
info locals
echo ===GDB_FRAME_0_END===\\n

# Walk up to N frames
{frame_commands}

echo ===GDB_DONE===\\n
quit
"""

_FRAME_CMD_TEMPLATE = """\
echo ===GDB_FRAME_{idx}_START===\\n
frame {idx}
echo ---ARGS---\\n
info args
echo ---LOCALS---\\n
info locals
echo ===GDB_FRAME_{idx}_END===\\n
"""


def _merge_sanitizer_options(current: str, required: Dict[str, str]) -> str:
    options: Dict[str, str] = {}
    for item in (current or "").split(":"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key:
            options[key] = value
    options.update(required)
    return ":".join(f"{key}={value}" for key, value in options.items())


def _sanitizer_environment(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return deterministic sanitizer settings for interactive collection."""
    provided = dict(env or {})
    defaults = {
        "ASAN_OPTIONS": {
            "abort_on_error": "1",
        },
        "UBSAN_OPTIONS": {
            "halt_on_error": "1",
            "abort_on_error": "1",
            "print_stacktrace": "1",
        },
        "MSAN_OPTIONS": {
            "halt_on_error": "1",
            "abort_on_error": "1",
        },
    }
    for name, required in defaults.items():
        provided[name] = _merge_sanitizer_options(provided.get(name, ""), required)
    return provided


def _generate_gdb_script(
    poc_path: str,
    max_frames: int = 8,
    env: Optional[Dict[str, str]] = None,
) -> str:
    frame_cmds = []
    for i in range(1, max_frames):
        frame_cmds.append(_FRAME_CMD_TEMPLATE.format(idx=i))
    environment_commands = "\n".join(
        f"set environment {name} {value}"
        for name, value in _sanitizer_environment(env).items()
    )
    return _GDB_SCRIPT_TEMPLATE.format(
        poc_path=poc_path,
        frame_commands="\n".join(frame_cmds),
        environment_commands=environment_commands,
        backtrace_limit=max(32, max_frames),
    )



# GDB output parsing

def _extract_section(output: str, start_marker: str, end_marker: str) -> Optional[str]:
    s = output.find(start_marker)
    if s == -1:
        return None
    s += len(start_marker)
    e = output.find(end_marker, s)
    if e == -1:
        return output[s:].strip()
    return output[s:e].strip()


def _parse_registers(reg_text: str) -> Dict[str, str]:
    regs = {}
    if not reg_text:
        return regs
    import re
    for line in reg_text.split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].strip()
            val = parts[1].strip()
            if name and not name.startswith("("):
                regs[name] = val
    return regs


def _parse_frame_vars(frame_text: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    args = {}
    locals_ = {}
    if not frame_text:
        return args, locals_

    current = None
    for line in frame_text.split("\n"):
        stripped = line.strip()
        if "---ARGS---" in stripped:
            current = "args"
            continue
        if "---LOCALS---" in stripped:
            current = "locals"
            continue
        if not stripped or stripped.startswith("No "):
            continue

        if " = " in stripped:
            key, _, val = stripped.partition(" = ")
            key = key.strip()
            val = val.strip()
            if current == "args":
                args[key] = val[:200]
            elif current == "locals":
                locals_[key] = val[:200]

    return args, locals_


def _parse_backtrace(bt_text: str) -> List[FrameState]:
    """Parse GDB 'bt full' output into frame states."""
    frames = []
    if not bt_text:
        return frames

    import re
    frame_re = re.compile(r"#(\d+)\s+(?:0x[0-9a-f]+\s+in\s+)?(\S+)\s*\(([^)]*)\)\s*(?:at\s+(\S+):(\d+))?")

    current_frame_id = None
    current_func = None
    current_file = None
    current_line = None
    current_args_raw = {}
    current_locals_raw = {}
    in_locals = False

    for line in bt_text.split("\n"):
        m = frame_re.match(line.strip())
        if m:
            if current_frame_id is not None:
                frames.append(FrameState(
                    frame_id=current_frame_id,
                    function=current_func or "??",
                    file=current_file,
                    line=current_line,
                    arguments=current_args_raw,
                    locals=current_locals_raw,
                ))
            current_frame_id = int(m.group(1))
            current_func = m.group(2)
            current_file = m.group(4)
            current_line = int(m.group(5)) if m.group(5) else None
            current_args_raw = {}
            current_locals_raw = {}
            in_locals = False
        elif "= " in line.strip() and current_frame_id is not None:
            stripped = line.strip()
            key, _, val = stripped.partition(" = ")
            current_locals_raw[key.strip()] = val.strip()[:200]

    if current_frame_id is not None:
        frames.append(FrameState(
            frame_id=current_frame_id,
            function=current_func or "??",
            file=current_file,
            line=current_line,
            arguments=current_args_raw,
            locals=current_locals_raw,
        ))

    return frames


def _parse_gdb_marked_output(
    output: str,
    max_frames: int = 8,
    *,
    expected_crash: Optional[Dict[str, Any]] = None,
    driver_basename: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse marked GDB output into a RuntimeContext-compatible dict."""
    bt_text = _extract_section(output, "===GDB_BACKTRACE_START===", "===GDB_BACKTRACE_END===")
    reg_text = _extract_section(output, "===GDB_REGISTERS_START===", "===GDB_REGISTERS_END===")

    registers = _parse_registers(reg_text)
    call_stack = _parse_backtrace(bt_text) if bt_text else []
    call_stack = call_stack[:max(32, max_frames)]

    for i in range(max_frames):
        frame_text = _extract_section(output, f"===GDB_FRAME_{i}_START===", f"===GDB_FRAME_{i}_END===")
        if frame_text:
            args, locals_ = _parse_frame_vars(frame_text)
            for fs in call_stack:
                if fs.frame_id == i:
                    fs.arguments.update(args)
                    fs.locals.update(locals_)
                    break

    raw_reproduced = bt_text is not None and len(call_stack) > 0

    exit_signal = None
    sig_match = re.search(
        r"(?:Program received|received signal)\s+(SIG[A-Z0-9]+)",
        output,
    )
    if sig_match:
        exit_signal = sig_match.group(1)

    if "hit Breakpoint" in output:
        stop_reason = "sanitizer_report"
    elif exit_signal:
        stop_reason = f"signal:{exit_signal}"
    elif raw_reproduced:
        stop_reason = "stack_available"
    else:
        stop_reason = "no_stack"

    dict_stack = [asdict(fs) for fs in call_stack]
    crash_frame_data = (
        first_target_frame(dict_stack, driver_basename)
        or (dict_stack[0] if dict_stack else None)
    )

    ctx = RuntimeContext(
        reproduced=raw_reproduced,
        exit_signal=exit_signal,
        registers=registers,
        crash_frame=FrameState(**crash_frame_data) if crash_frame_data else None,
        call_stack=call_stack,
        backtrace_text=bt_text,
        error_message=None if raw_reproduced else "Could not reproduce crash",
    )

    d = asdict(ctx)
    if crash_frame_data:
        d["crash_frame"] = crash_frame_data
    d["call_stack"] = [asdict(fs) for fs in call_stack]
    d["raw_reproduced"] = raw_reproduced
    d["stop_reason"] = stop_reason
    if expected_crash is not None:
        matched, validation_reason = runtime_context_matches_parsed(
            d,
            expected_crash,
            driver_basename,
        )
        d["matches_original"] = matched
        d["validation_reason"] = validation_reason
        if not matched:
            d["reproduced"] = False
            if raw_reproduced:
                d["error_message"] = (
                    "GDB crash does not match the retained crash: "
                    f"{validation_reason}"
                )
    else:
        d["matches_original"] = None
        d["validation_reason"] = "not_checked"
    return d


def _compute_runtime_evidence_quality(ctx: Dict[str, Any]) -> float:
    """Compute a lightweight quality score for runtime evidence [0.0, 1.0]."""
    if not ctx or not ctx.get("reproduced"):
        return 0.0

    score = 0.0
    score += 0.4  # reproduced

    cf = ctx.get("crash_frame") or {}
    if cf.get("function"):
        score += 0.2

    regs = ctx.get("registers") or {}
    reg_hits = sum(1 for r in _IMPORTANT_REGS if r in regs)
    score += min(0.2, 0.025 * reg_hits)  # 8 regs -> 0.2

    stack = ctx.get("call_stack") or []
    score += min(0.1, 0.02 * len(stack))  # >=5 frames -> 0.1

    args_cnt = len(cf.get("arguments") or {})
    locals_cnt = len(cf.get("locals") or {})
    if (args_cnt + locals_cnt) > 0:
        score += 0.1

    return round(min(1.0, score), 3)


def _runtime_stability_key(ctx: Dict[str, Any]) -> Optional[str]:
    """Create a stable key for runtime-context consistency checks."""
    if not ctx or not ctx.get("reproduced"):
        return None
    cf = ctx.get("crash_frame") or {}
    func = cf.get("function") or "?"
    file_ = cf.get("file") or "?"
    line = cf.get("line") or "?"
    sig = ctx.get("exit_signal") or "?"
    return f"{sig}|{func}|{file_}:{line}"


def _docker_exec(container_id: str, cmd: str, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            ["docker", "exec", container_id, "/bin/bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


def _reproduce_with_docker_gdb_once(
    binary_path: str,
    poc_path: str,
    timeout: int = 15,
    max_frames: int = 8,
    *,
    env: Optional[Dict[str, str]] = None,
    expected_crash: Optional[Dict[str, Any]] = None,
    driver_basename: Optional[str] = None,
    docker_image: Optional[str] = None,
    docker_setup_timeout: int = 90,
) -> Dict[str, Any]:
    """Run GDB inside an OSS-Fuzz base-runner container (Docker-first path)."""
    if not os.path.isfile(binary_path):
        d = asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"binary not found: {binary_path}",
        ))
        d["collection_method"] = "docker_gdb"
        return d
    if not os.path.isfile(poc_path):
        d = asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"PoC not found: {poc_path}",
        ))
        d["collection_method"] = "docker_gdb"
        return d

    out_dir = os.path.dirname(os.path.realpath(binary_path))
    binary_name = os.path.basename(binary_path)
    container_id = None

    # Prefer existing gdb in image; fallback to apt install when available.
    start_script = (
        "if command -v gdb >/dev/null 2>&1; then "
        "echo GDB_READY; "
        "else "
        "(apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gdb >/dev/null 2>&1 && echo GDB_READY) "
        "|| echo GDB_MISSING; "
        "fi; sleep 300"
    )
    try:
        start_cmd = [
            "docker", "run", "-d", "--rm", "--privileged", "--shm-size=2g",
            "--platform", "linux/amd64",
            "-v", f"{out_dir}:/out",
            docker_image or _OSS_FUZZ_GDB_RUNNER_IMAGE,
            "/bin/bash", "-c", start_script,
        ]
        container_id = subprocess.check_output(start_cmd, timeout=20).decode().strip()

        ready = False
        gdb_missing = False
        deadline = time.monotonic() + docker_setup_timeout
        while time.monotonic() < deadline:
            try:
                logs = subprocess.check_output(["docker", "logs", container_id], timeout=5).decode()
            except Exception:
                logs = ""
            if "GDB_READY" in logs:
                ready = True
                break
            if "GDB_MISSING" in logs:
                gdb_missing = True
                break
            time.sleep(1)
        if not ready:
            err = "GDB not available in container" if gdb_missing else "Docker GDB setup timed out"
            d = asdict(RuntimeContext(
                reproduced=False, exit_signal=None, registers={},
                crash_frame=None, call_stack=[], backtrace_text=None,
                error_message=err,
            ))
            d["collection_method"] = "docker_gdb"
            return d

        poc_name = f"poc_{os.getpid()}"
        subprocess.run(
            ["docker", "cp", poc_path, f"{container_id}:/tmp/{poc_name}"],
            timeout=10, capture_output=True, check=True,
        )

        gdb_script = _generate_gdb_script(
            f"/tmp/{poc_name}",
            max_frames=max_frames,
            env=env,
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
            f.write(gdb_script)
            local_script = f.name
        try:
            script_name = f"run_{os.getpid()}.gdb"
            subprocess.run(
                ["docker", "cp", local_script, f"{container_id}:/tmp/{script_name}"],
                timeout=10, capture_output=True, check=True,
            )
        finally:
            try:
                os.unlink(local_script)
            except OSError:
                pass

        output = _docker_exec(
            container_id,
            f"timeout {timeout} gdb --batch -x /tmp/{script_name} /out/{binary_name} 2>&1 || true",
            timeout=timeout + 10,
        )
        ctx = _parse_gdb_marked_output(
            output,
            max_frames=max_frames,
            expected_crash=expected_crash,
            driver_basename=driver_basename,
        )
        ctx["collection_method"] = "docker_gdb"
        if not ctx.get("reproduced"):
            ctx["gdb_output_excerpt"] = output[-8000:]
        return ctx
    except Exception as e:
        d = asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"Docker GDB failed: {e}",
        ))
        d["collection_method"] = "docker_gdb"
        return d
    finally:
        if container_id:
            try:
                subprocess.run(["docker", "stop", container_id], timeout=10, capture_output=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main debugger interface
# ---------------------------------------------------------------------------

def reproduce_with_gdb(
    binary_path: str,
    poc_path: str,
    timeout: int = 15,
    max_frames: int = 8,
    env: Optional[Dict[str, str]] = None,
    *,
    expected_crash: Optional[Dict[str, Any]] = None,
    driver_basename: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the binary under GDB with the given PoC and collect runtime context.

    Args:
        binary_path: Path to the fuzz target binary (compiled with debug info + ASan)
        poc_path: Path to the PoC / crash input file
        timeout: Maximum seconds to wait for GDB
        max_frames: Maximum number of call-stack frames to inspect
        env: Extra environment variables

    Returns:
        JSON-serializable dict of RuntimeContext.
    """
    if not os.path.isfile(binary_path):
        return asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"binary not found: {binary_path}",
        ))

    if not os.path.isfile(poc_path):
        return asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"PoC not found: {poc_path}",
        ))

    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    resolved_env = _sanitizer_environment(run_env)
    script = _generate_gdb_script(poc_path, max_frames, env=resolved_env)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        run_env.update(resolved_env)
        cmd = ["gdb", "--batch", "-x", script_path, binary_path]
        logger.info(f"Running GDB: {' '.join(cmd)}")

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env=run_env,
        )
        output = proc.stdout + "\n" + proc.stderr
    except subprocess.TimeoutExpired:
        return asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message=f"GDB timed out after {timeout}s",
        ))
    except FileNotFoundError:
        return asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message="GDB not found on system",
        ))
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

    d = _parse_gdb_marked_output(
        output,
        max_frames=max_frames,
        expected_crash=expected_crash,
        driver_basename=driver_basename,
    )
    d["collection_method"] = "local_gdb"
    if not d.get("reproduced"):
        d["gdb_output_excerpt"] = output[-8000:]
    return d


def collect_runtime_context(
    binary_path: str,
    poc_path: str,
    *,
    attempts: int = 3,
    timeout: int = 15,
    max_frames: int = 8,
    prefer_docker: bool = True,
    env: Optional[Dict[str, str]] = None,
    expected_crash: Optional[Dict[str, Any]] = None,
    driver_basename: Optional[str] = None,
    docker_image: Optional[str] = None,
    docker_setup_timeout: int = 90,
) -> Dict[str, Any]:
    """Collect runtime context with stability checks and quality scoring.

    Strategy:
      1) Docker GDB first (environment closer to fuzzing runtime)
      2) Fallback to local GDB if Docker path fails
      3) Repeat for N attempts, pick best context, and compute stability metadata
    """
    attempts = max(1, attempts)
    attempt_records: List[Dict[str, Any]] = []

    best_ctx: Optional[Dict[str, Any]] = None
    best_quality = -1.0
    docker_available = prefer_docker

    for i in range(attempts):
        ctx = None
        if docker_available:
            ctx = _reproduce_with_docker_gdb_once(
                binary_path,
                poc_path,
                timeout=timeout,
                max_frames=max_frames,
                env=env,
                expected_crash=expected_crash,
                driver_basename=driver_basename,
                docker_image=docker_image,
                docker_setup_timeout=docker_setup_timeout,
            )
            if not ctx.get("reproduced"):
                # Avoid paying the container setup cost again when Docker is
                # unavailable or the container runtime cannot reproduce.
                docker_available = False

        # Fallback to local GDB if Docker path did not reproduce.
        if not ctx or not ctx.get("reproduced"):
            local_ctx = reproduce_with_gdb(
                binary_path,
                poc_path,
                timeout=timeout,
                max_frames=max_frames,
                env=env,
                expected_crash=expected_crash,
                driver_basename=driver_basename,
            )
            if not ctx or local_ctx.get("reproduced"):
                ctx = local_ctx

        quality = _compute_runtime_evidence_quality(ctx or {})
        raw_quality = quality
        if expected_crash is not None and not (ctx or {}).get("matches_original"):
            quality = 0.0
        key = _runtime_stability_key(ctx or {})

        if ctx is None:
            ctx = asdict(RuntimeContext(
                reproduced=False, exit_signal=None, registers={},
                crash_frame=None, call_stack=[], backtrace_text=None,
                error_message="runtime collection failed",
            ))
            ctx["collection_method"] = "none"

        ctx["attempt_index"] = i + 1
        ctx["attempt_quality"] = quality
        ctx["attempt_stability_key"] = key

        attempt_records.append({
            "attempt": i + 1,
            "collection_method": ctx.get("collection_method", "unknown"),
            "reproduced": bool(ctx.get("reproduced")),
            "exit_signal": ctx.get("exit_signal"),
            "crash_function": (ctx.get("crash_frame") or {}).get("function"),
            "stability_key": key,
            "attempt_quality": quality,
            "raw_quality": raw_quality,
            "matches_original": (ctx or {}).get("matches_original"),
            "validation_reason": (ctx or {}).get("validation_reason"),
        })

        if quality > best_quality:
            best_quality = quality
            best_ctx = ctx

    reproduced_attempts = [a for a in attempt_records if a.get("reproduced")]
    if reproduced_attempts:
        key_count: Dict[str, int] = {}
        for a in reproduced_attempts:
            k = a.get("stability_key") or "?"
            key_count[k] = key_count.get(k, 0) + 1
        max_count = max(key_count.values()) if key_count else 0
        stability_ratio = round(max_count / len(reproduced_attempts), 3) if reproduced_attempts else 0.0
        stable = max_count >= 2
    else:
        stability_ratio = 0.0
        stable = False

    if best_ctx is None:
        best_ctx = asdict(RuntimeContext(
            reproduced=False, exit_signal=None, registers={},
            crash_frame=None, call_stack=[], backtrace_text=None,
            error_message="runtime collection failed",
        ))
        best_ctx["collection_method"] = "none"

    # Blend best-sample quality and cross-attempt stability.
    final_quality = round(min(1.0, (0.7 * max(best_quality, 0.0)) + (0.3 * stability_ratio)), 3)
    best_ctx["evidence_quality"] = final_quality
    best_ctx["stable"] = stable
    best_ctx["stability_ratio"] = stability_ratio
    best_ctx["collection_attempts"] = attempt_records
    best_ctx["attempts"] = attempts
    best_ctx["matching_attempts"] = len(reproduced_attempts)
    return best_ctx


def format_runtime_context_for_llm(ctx: Dict[str, Any], max_frames: int = 5) -> str:
    """Format runtime context into a readable string for LLM prompt."""
    if not ctx.get("reproduced"):
        err = ctx.get("error_message", "unknown reason")
        return f"[RUNTIME] Crash reproduction failed: {err}"

    lines = []
    if "evidence_quality" in ctx:
        lines.append(
            f"[RUNTIME] quality={ctx.get('evidence_quality')} "
            f"stable={ctx.get('stable')} "
            f"method={ctx.get('collection_method', 'unknown')}"
        )
    lines.append(f"[RUNTIME] Signal: {ctx.get('exit_signal', 'unknown')}")

    cf = ctx.get("crash_frame")
    if cf:
        loc = f"{cf.get('file', '??')}:{cf.get('line', '?')}" if cf.get("file") else "(unknown)"
        lines.append(f"[RUNTIME] Crash frame: {cf['function']}() at {loc}")
        if cf.get("arguments"):
            for k, v in list(cf["arguments"].items())[:10]:
                lines.append(f"  arg {k} = {v}")
        if cf.get("locals"):
            for k, v in list(cf["locals"].items())[:10]:
                lines.append(f"  local {k} = {v}")

    regs = ctx.get("registers") or {}
    if regs:
        important = _IMPORTANT_REGS
        reg_strs = []
        for r in important:
            if r in regs:
                reg_strs.append(f"{r}={regs[r]}")
        if reg_strs:
            lines.append(f"[RUNTIME] Key registers: {', '.join(reg_strs)}")

    stack = ctx.get("call_stack") or []
    if stack:
        lines.append(f"[RUNTIME] Call stack ({len(stack)} frames):")
        for fs in stack[:max_frames]:
            loc = f"{fs.get('file', '??')}:{fs.get('line', '?')}" if fs.get("file") else "(no src)"
            lines.append(f"  #{fs['frame_id']} {fs['function']}() @ {loc}")
            for k, v in list(fs.get("locals", {}).items())[:5]:
                lines.append(f"       {k} = {v}")

    return "\n".join(lines)
