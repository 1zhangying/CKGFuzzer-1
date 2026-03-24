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
import subprocess
import tempfile
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


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



# GDB script generation

_GDB_SCRIPT_TEMPLATE = """\
set pagination off
set confirm off
set print elements 200
set print repeats 5
set print pretty on

# Run with PoC input
run {poc_path}

# If we get here, the crash happened
echo ===GDB_BACKTRACE_START===\\n
bt full
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


def _generate_gdb_script(poc_path: str, max_frames: int = 8) -> str:
    frame_cmds = []
    for i in range(1, max_frames):
        frame_cmds.append(_FRAME_CMD_TEMPLATE.format(idx=i))
    return _GDB_SCRIPT_TEMPLATE.format(
        poc_path=poc_path,
        frame_commands="\n".join(frame_cmds),
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


# ---------------------------------------------------------------------------
# Main debugger interface
# ---------------------------------------------------------------------------

def reproduce_with_gdb(
    binary_path: str,
    poc_path: str,
    timeout: int = 15,
    max_frames: int = 8,
    env: Optional[Dict[str, str]] = None,
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

    script = _generate_gdb_script(poc_path, max_frames)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        run_env = dict(os.environ)
        if env:
            run_env.update(env)
        # Disable ASLR for reproducibility
        run_env["ASLR"] = "0"

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

    # Parse output
    bt_text = _extract_section(output, "===GDB_BACKTRACE_START===", "===GDB_BACKTRACE_END===")
    reg_text = _extract_section(output, "===GDB_REGISTERS_START===", "===GDB_REGISTERS_END===")

    registers = _parse_registers(reg_text)
    call_stack = _parse_backtrace(bt_text) if bt_text else []

    # Parse individual frame details
    for i in range(max_frames):
        frame_text = _extract_section(output, f"===GDB_FRAME_{i}_START===", f"===GDB_FRAME_{i}_END===")
        if frame_text:
            args, locals_ = _parse_frame_vars(frame_text)
            for fs in call_stack:
                if fs.frame_id == i:
                    fs.arguments.update(args)
                    fs.locals.update(locals_)
                    break

    reproduced = bt_text is not None and len(call_stack) > 0

    # Detect signal
    exit_signal = None
    import re
    sig_match = re.search(r"Program received signal (\w+)", output)
    if sig_match:
        exit_signal = sig_match.group(1)

    crash_frame = call_stack[0] if call_stack else None

    ctx = RuntimeContext(
        reproduced=reproduced,
        exit_signal=exit_signal,
        registers=registers,
        crash_frame=crash_frame,
        call_stack=call_stack,
        backtrace_text=bt_text,
        error_message=None if reproduced else "Could not reproduce crash",
    )

    d = asdict(ctx)
    if crash_frame:
        d["crash_frame"] = asdict(crash_frame)
    d["call_stack"] = [asdict(fs) for fs in call_stack]
    return d


def format_runtime_context_for_llm(ctx: Dict[str, Any], max_frames: int = 5) -> str:
    """Format runtime context into a readable string for LLM prompt."""
    if not ctx.get("reproduced"):
        err = ctx.get("error_message", "unknown reason")
        return f"[RUNTIME] Crash reproduction failed: {err}"

    lines = []
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
        important = ["rip", "rsp", "rbp", "rax", "rdi", "rsi", "rdx", "rcx"]
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
