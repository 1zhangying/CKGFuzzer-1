#!/usr/bin/env python3
"""Retroactive enrichment: fix repro_rate and GDB context in existing crash data.

Scans crash_analysis.yaml files produced by the pipeline and:
  1. Re-runs PoC reproduction inside Docker with multi-level signature matching
  2. Runs GDB inside Docker container to collect runtime context
  3. Updates crash_analysis.yaml with corrected repro / GDB fields
  4. Regenerates report YAML files

This script is designed to be run AFTER all fuzzing is complete.  It does NOT
re-run LLM analysis — that data is preserved as-is.

Usage:
    cd fuzzing_llm_engine
    python -m crash.retro_enrich --db-root external_database --project c-ares
    python -m crash.retro_enrich --db-root external_database              # all projects
    python -m crash.retro_enrich --db-root external_database --dry-run    # preview only
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import yaml
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger

from crash.sanitizer_parser import parse_sanitizer_output
from crash.triage import triage_crash, compute_signatures
from crash.debugger import (
    _generate_gdb_script,
    _extract_section,
    _parse_registers,
    _parse_frame_vars,
    _parse_backtrace,
)


_ENGINE_DIR = Path(__file__).resolve().parents[1]
_BASE_RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _ensure_entry_binary_snapshot(
    entry: Dict[str, Any],
    binary_path: str,
    driver_crash_dir: str,
    fuzzer_name: str,
    crash_id: str,
    *,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    """Persist binary snapshot metadata in entry if missing or stale."""
    meta = entry.get("binary_snapshot") or {}
    snap = meta.get("snapshot_path")
    if not force_refresh and snap and os.path.isfile(snap):
        entry["binary_path_for_repro"] = snap
        return meta

    sha = _sha256_file(binary_path)
    size_bytes = os.path.getsize(binary_path)
    snap_dir = os.path.join(driver_crash_dir, "binary_snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    safe_name = (fuzzer_name or "fuzzer").replace(os.sep, "_")
    snap_path = os.path.join(snap_dir, f"{safe_name}_{sha[:16]}")
    created = False
    if not os.path.exists(snap_path):
        shutil.copy2(binary_path, snap_path)
        created = True

    new_meta = {
        "exists": True,
        "source_path": binary_path,
        "snapshot_path": snap_path,
        "sha256": sha,
        "size_bytes": size_bytes,
        "created": created,
        "captured_at": datetime.now().isoformat(),
        "crash_id": crash_id,
        "error": None,
    }
    entry["binary_snapshot"] = new_meta
    entry["binary_path_for_repro"] = snap_path
    return new_meta


# ---------------------------------------------------------------------------
# Multi-level signature matching (fixes the primary-only comparison bug)
# ---------------------------------------------------------------------------

def _signatures_match(orig_triage: Dict, repro_triage: Dict) -> Tuple[bool, Optional[str]]:
    """Compare crash signatures across three levels.

    Returns (matched: bool, level: str|None).
    The original code only compared primary signatures which use different
    formats (dedup:xxx vs sig:xxx), causing guaranteed mismatch.
    """
    o_sig = orig_triage.get("signature")
    r_sig = repro_triage.get("signature")
    if o_sig and r_sig and o_sig == r_sig:
        return True, "exact"

    o_stack = orig_triage.get("stack_signature")
    r_stack = repro_triage.get("stack_signature")
    if o_stack and r_stack and o_stack == r_stack:
        return True, "stack"

    o_fuzzy = orig_triage.get("fuzzy_signature")
    r_fuzzy = repro_triage.get("fuzzy_signature")
    if o_fuzzy and r_fuzzy and o_fuzzy == r_fuzzy:
        return True, "fuzzy"

    return False, None


def _detect_crash_in_output(output: str) -> bool:
    """Detect whether sanitizer output indicates a genuine crash."""
    if not output:
        return False
    indicators = [
        "ERROR: AddressSanitizer:",
        "ERROR: MemorySanitizer:",
        "ERROR: LeakSanitizer:",
        "SUMMARY: AddressSanitizer:",
        "SUMMARY: MemorySanitizer:",
        "SCARINESS:",
        "deadly signal",
        "ABORTING",
    ]
    return any(ind in output for ind in indicators)


# ---------------------------------------------------------------------------
# ASan binary rebuild (fixes coverage-only binaries in /out/)
# ---------------------------------------------------------------------------

def _is_docker_container_running(project_name: str) -> bool:
    """Check if the compilation-check Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={project_name}_check",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return f"{project_name}_check" in result.stdout
    except Exception:
        return False


def _start_check_container(project_name: str) -> bool:
    """Start the compilation-check Docker container if not running."""
    if _is_docker_container_running(project_name):
        logger.info(f"[Rebuild] Docker '{project_name}_check' already running")
        return True
    logger.info(f"[Rebuild] Starting Docker '{project_name}_check'...")
    shared_dir = str(_ENGINE_DIR.parent / "docker_shared")
    cmd = [
        sys.executable,
        str(_ENGINE_DIR / "utils" / "check_gen_fuzzer.py"),
        "start_docker_check_compilation", project_name,
        "--fuzzing_llm_dir", f"{shared_dir}/",
    ]
    try:
        subprocess.run(cmd, check=True, timeout=120)
        return True
    except Exception as e:
        logger.error(f"[Rebuild] Failed to start container: {e}")
        return False


def rebuild_asan_binaries(
    db_root: str,
    project_name: str,
) -> Dict[str, Any]:
    """Rebuild ASan binaries for all drivers that have crashes.

    The fuzzing pipeline's last build step uses --sanitizer coverage,
    leaving /out/ with coverage-only binaries that can't reproduce
    ASan-detected crashes. This rebuilds them with ASan.
    """
    crash_dir = os.path.join(db_root, project_name, "crash")
    shared_dir = str(_ENGINE_DIR.parent / "docker_shared")
    src_dir = os.path.join(shared_dir, f"fuzz_driver/{project_name}/compilation_pass_rag")

    driver_dirs = sorted(
        d for d in os.listdir(crash_dir)
        if os.path.isdir(os.path.join(crash_dir, d))
        and os.path.isfile(os.path.join(crash_dir, d, "crash_analysis.yaml"))
    )
    if not driver_dirs:
        return {"rebuilt": 0, "failed": 0, "skipped": 0}

    if not _start_check_container(project_name):
        logger.error("[Rebuild] Cannot start Docker container, skipping rebuild")
        return {"rebuilt": 0, "failed": 0, "skipped": len(driver_dirs)}

    stats = {"rebuilt": 0, "failed": 0, "skipped": 0}
    container_name = f"{project_name}_check"
    _LLM_WORK_DIR = "/generated_fuzzer"

    for dname in driver_dirs:
        driver_file = dname + ".cc"
        src_path = os.path.join(src_dir, driver_file)

        if not os.path.isfile(src_path):
            saved = [f for f in os.listdir(os.path.join(crash_dir, dname))
                     if f.endswith(".cc")]
            if saved:
                fallback = os.path.join(crash_dir, dname, saved[0])
                logger.info(f"[Rebuild] {dname}: source missing, "
                            f"copying {saved[0]} to compilation_pass_rag")
                os.makedirs(src_dir, exist_ok=True)
                shutil.copy2(fallback, src_path)
            else:
                logger.warning(f"[Rebuild] {dname}: no source found, skipping")
                stats["skipped"] += 1
                continue

        logger.info(f"[Rebuild] Building ASan binary: {driver_file}")
        compile_cmd = (
            f"source {_LLM_WORK_DIR}/fuzz_driver/{project_name}/scripts/"
            f"entrancy.sh {driver_file} {project_name} "
            f"&& compile && echo 'Compilation succeeded'"
        )
        docker_cmd = [
            "docker", "exec", "-u", "root",
            container_name,
            "/bin/bash", "-c", compile_cmd,
        ]
        try:
            result = subprocess.run(
                docker_cmd, capture_output=True, text=True, timeout=300,
            )
            output = result.stdout + result.stderr
            if "Compilation succeeded" in output:
                logger.info(f"[Rebuild]   {dname}: OK")
                stats["rebuilt"] += 1
            else:
                err_snippet = output.strip()[-300:] if output.strip() else "(no output)"
                logger.warning(f"[Rebuild]   {dname}: build failed "
                               f"(rc={result.returncode}): {err_snippet}")
                stats["failed"] += 1
        except subprocess.TimeoutExpired:
            logger.error(f"[Rebuild]   {dname}: TIMEOUT")
            stats["failed"] += 1
        except Exception as e:
            logger.error(f"[Rebuild]   {dname}: ERROR: {e}")
            stats["failed"] += 1

    logger.info(f"[Rebuild] Done: {stats}")
    return stats


# ---------------------------------------------------------------------------
# Docker session for GDB / repro inside container
# ---------------------------------------------------------------------------

class DockerGDBSession:
    """Persistent Docker container for in-container GDB reproduction."""

    def __init__(self, out_dir: str, *, install_timeout: int = 60):
        self.out_dir = os.path.realpath(out_dir)
        self.container_id: Optional[str] = None
        self._start(install_timeout)

    def _start(self, install_timeout: int):
        cmd = [
            "docker", "run", "-d", "--rm", "--privileged", "--shm-size=2g",
            "--platform", "linux/amd64",
            "-v", f"{self.out_dir}:/out",
            _BASE_RUNNER_IMAGE,
            "/bin/bash", "-c",
            "apt-get update -qq >/dev/null 2>&1 && "
            "apt-get install -y -qq gdb >/dev/null 2>&1 && "
            "echo GDB_READY && sleep 86400",
        ]
        logger.info(f"[DockerGDB] Starting container (installing GDB)...")
        try:
            cid = subprocess.check_output(cmd, timeout=15).decode().strip()
        except Exception as e:
            logger.error(f"[DockerGDB] Failed to start container: {e}")
            self.container_id = None
            return
        self.container_id = cid
        logger.info(f"[DockerGDB] Container {cid[:12]}... started")

        deadline = time.monotonic() + install_timeout
        while time.monotonic() < deadline:
            try:
                logs = subprocess.check_output(
                    ["docker", "logs", cid], timeout=5
                ).decode()
                if "GDB_READY" in logs:
                    logger.info("[DockerGDB] GDB installed successfully")
                    return
            except Exception:
                pass
            time.sleep(2)
        logger.warning("[DockerGDB] GDB install timed out; GDB features may fail")

    def is_alive(self) -> bool:
        if not self.container_id:
            return False
        try:
            out = subprocess.check_output(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_id],
                timeout=5,
            ).decode().strip()
            return out == "true"
        except Exception:
            return False

    def close(self):
        if self.container_id:
            try:
                subprocess.run(
                    ["docker", "stop", self.container_id],
                    timeout=10, capture_output=True,
                )
            except Exception:
                pass
            self.container_id = None

    def _exec(self, cmd_str: str, timeout: int = 30) -> str:
        if not self.container_id:
            return ""
        try:
            result = subprocess.run(
                ["docker", "exec", self.container_id, "/bin/bash", "-c", cmd_str],
                capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout + "\n" + result.stderr
        except subprocess.TimeoutExpired:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR] {e}"

    def reproduce_binary(self, binary_host_path: str, poc_host_path: str,
                         timeout: int = 15) -> str:
        """Run {binary_host_path} {poc} inside Docker and return output."""
        uniq = f"{os.getpid()}_{int(time.time() * 1000)}"
        poc_name = f"poc_{uniq}"
        bin_name = f"bin_{uniq}"
        try:
            subprocess.run(
                ["docker", "cp", poc_host_path,
                 f"{self.container_id}:/tmp/{poc_name}"],
                timeout=10, capture_output=True, check=True,
            )
            subprocess.run(
                ["docker", "cp", binary_host_path,
                 f"{self.container_id}:/tmp/{bin_name}"],
                timeout=10, capture_output=True, check=True,
            )
        except Exception as e:
            return f"[ERROR] Failed to copy PoC/binary: {e}"

        return self._exec(
            f"chmod +x /tmp/{bin_name} >/dev/null 2>&1; "
            f"timeout {timeout} /tmp/{bin_name} /tmp/{poc_name} 2>&1; true",
            timeout=timeout + 5,
        )

    def run_gdb(self, binary_host_path: str, poc_host_path: str,
                max_frames: int = 8, timeout: int = 30) -> str:
        """Run GDB on {binary_host_path} with {poc} inside Docker."""
        uniq = f"{os.getpid()}_{int(time.time() * 1000)}"
        poc_name = f"poc_gdb_{uniq}"
        bin_name = f"bin_gdb_{uniq}"
        gdb_script_name = f"gdb_{uniq}.gdb"

        try:
            subprocess.run(
                ["docker", "cp", poc_host_path,
                 f"{self.container_id}:/tmp/{poc_name}"],
                timeout=10, capture_output=True, check=True,
            )
            subprocess.run(
                ["docker", "cp", binary_host_path,
                 f"{self.container_id}:/tmp/{bin_name}"],
                timeout=10, capture_output=True, check=True,
            )
        except Exception as e:
            return f"[ERROR] Failed to copy PoC/binary: {e}"

        gdb_script = _generate_gdb_script(f"/tmp/{poc_name}", max_frames)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".gdb", delete=False
        ) as f:
            f.write(gdb_script)
            local_script = f.name

        try:
            subprocess.run(
                ["docker", "cp", local_script,
                 f"{self.container_id}:/tmp/{gdb_script_name}"],
                timeout=10, capture_output=True, check=True,
            )
        except Exception as e:
            return f"[ERROR] Failed to copy GDB script: {e}"
        finally:
            os.unlink(local_script)

        return self._exec(
            f"chmod +x /tmp/{bin_name} >/dev/null 2>&1; "
            f"gdb --batch -x /tmp/{gdb_script_name} /tmp/{bin_name} 2>&1",
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# Parse GDB output into runtime context dict (reuse debugger.py parsers)
# ---------------------------------------------------------------------------

def _parse_gdb_output(output: str, max_frames: int = 8) -> Dict[str, Any]:
    """Parse GDB output into a RuntimeContext-compatible dict."""
    bt_text = _extract_section(
        output, "===GDB_BACKTRACE_START===", "===GDB_BACKTRACE_END==="
    )
    reg_text = _extract_section(
        output, "===GDB_REGISTERS_START===", "===GDB_REGISTERS_END==="
    )

    registers = _parse_registers(reg_text)
    call_stack = _parse_backtrace(bt_text) if bt_text else []

    for i in range(max_frames):
        frame_text = _extract_section(
            output, f"===GDB_FRAME_{i}_START===", f"===GDB_FRAME_{i}_END==="
        )
        if frame_text:
            args, locals_ = _parse_frame_vars(frame_text)
            for fs in call_stack:
                if fs.frame_id == i:
                    fs.arguments.update(args)
                    fs.locals.update(locals_)
                    break

    reproduced = bt_text is not None and len(call_stack) > 0

    exit_signal = None
    sig_match = re.search(r"Program received signal (\w+)", output)
    if sig_match:
        exit_signal = sig_match.group(1)

    from dataclasses import asdict
    crash_frame = call_stack[0] if call_stack else None

    result = {
        "reproduced": reproduced,
        "exit_signal": exit_signal,
        "registers": registers,
        "crash_frame": asdict(crash_frame) if crash_frame else None,
        "call_stack": [asdict(fs) for fs in call_stack],
        "backtrace_text": bt_text,
        "error_message": None if reproduced else "Could not reproduce crash in Docker",
    }
    return result


# ---------------------------------------------------------------------------
# Core enrichment logic for one crash entry
# ---------------------------------------------------------------------------

def enrich_one_crash(
    entry: Dict[str, Any],
    session: DockerGDBSession,
    driver_name: str,
    project_name: str,
    binary_path: str,
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Enrich a single crash entry with fixed repro and GDB context.

    Returns the updated entry (original is not mutated).
    """
    entry = deepcopy(entry)
    fuzzer_name = driver_name  # binary name == directory name

    poc_paths = entry.get("poc_paths", {})
    poc_path = poc_paths.get("poc")
    if not poc_path or not os.path.isfile(poc_path):
        logger.warning(f"  PoC not found: {poc_path}")
        return entry

    original_triage = entry.get("triage", {})
    fuzz_driver_file = entry.get("fuzz_driver_file")
    fuzz_driver_basename = fuzz_driver_file if fuzz_driver_file else None

    if dry_run:
        logger.info(f"  [DRY-RUN] Would re-run repro + GDB for {fuzzer_name} (binary={binary_path})")
        return entry

    # ── Step 1: Fix repro_rate ──────────────────────────────────────
    if session.is_alive():
        runs = []
        for attempt in range(3):
            out = session.reproduce_binary(binary_path, poc_path, timeout=15)
            has_crash = _detect_crash_in_output(out)
            p2 = parse_sanitizer_output(out or "")
            t2 = triage_crash(p2, fuzz_driver_basename=fuzz_driver_basename)

            matched, level = _signatures_match(original_triage, t2)

            runs.append({
                "has_error": has_crash,
                "signature": t2.get("signature"),
                "same_signature": matched,
                "match_level": level,
            })

        success_count = sum(1 for r in runs if r.get("same_signature"))
        entry["repro"] = {
            "enabled": True,
            "prepared": True,
            "runs": runs,
            "repro_rate": f"{success_count}/{len(runs)}",
            "method": "retro_enrich_docker",
        }
        logger.info(f"  Repro: {entry['repro']['repro_rate']} "
                     f"(crash_detected: {[r['has_error'] for r in runs]})")
    else:
        logger.warning("  Docker session not alive; skipping repro")

    # ── Step 2: Fix GDB runtime context ─────────────────────────────
    gdb_context = None
    if session.is_alive():
        gdb_out = session.run_gdb(binary_path, poc_path, max_frames=8, timeout=30)
        gdb_context = _parse_gdb_output(gdb_out)

        if gdb_context.get("reproduced"):
            cf = gdb_context.get("crash_frame", {})
            has_useful_data = bool(
                cf.get("arguments") or cf.get("locals") or
                gdb_context.get("registers")
            )
            logger.info(
                f"  GDB: reproduced=True, signal={gdb_context.get('exit_signal')}, "
                f"frames={len(gdb_context.get('call_stack', []))}, "
                f"useful_data={has_useful_data}"
            )
        else:
            logger.info(f"  GDB: reproduced=False "
                        f"({gdb_context.get('error_message', '?')})")

        entry["gdb_runtime_context"] = gdb_context
    else:
        logger.warning("  Docker session not alive; skipping GDB")

    entry["retro_enriched"] = True
    entry["retro_enriched_at"] = datetime.now().isoformat()

    return entry


# ---------------------------------------------------------------------------
# Project-level processing
# ---------------------------------------------------------------------------

def enrich_project(
    db_root: str,
    project_name: str,
    *,
    dry_run: bool = False,
    backup: bool = True,
    prefer_build_out: bool = False,
) -> Dict[str, Any]:
    """Enrich all crashes for one project."""

    crash_dir = os.path.join(db_root, project_name, "crash")
    out_dir = os.path.join(str(_ENGINE_DIR), "build", "out", project_name)

    if not os.path.isdir(crash_dir):
        logger.warning(f"[{project_name}] No crash directory: {crash_dir}")
        return {"project": project_name, "status": "no_crash_dir"}
    out_dir_exists = os.path.isdir(out_dir)
    if not out_dir_exists:
        logger.warning(f"[{project_name}] No build output at {out_dir}; will rely on binary snapshots if present")

    driver_dirs = sorted(
        d for d in os.listdir(crash_dir)
        if os.path.isdir(os.path.join(crash_dir, d))
        and os.path.isfile(os.path.join(crash_dir, d, "crash_analysis.yaml"))
    )

    if not driver_dirs:
        logger.info(f"[{project_name}] No crash_analysis.yaml found")
        return {"project": project_name, "status": "no_crashes"}

    logger.info(f"\n{'='*60}")
    logger.info(f"  Enriching: {project_name} ({len(driver_dirs)} drivers)")
    logger.info(f"  Crash dir: {crash_dir}")
    logger.info(f"  Out dir:   {out_dir} (exists={out_dir_exists})")
    logger.info(f"{'='*60}")

    session = None
    if not dry_run:
        mount_dir = out_dir if out_dir_exists else crash_dir
        session = DockerGDBSession(mount_dir, install_timeout=90)
        if not session.is_alive():
            logger.error(f"[{project_name}] Docker session failed to start")
            return {"project": project_name, "status": "docker_failed"}

    stats = {"total": 0, "enriched": 0, "skipped": 0, "errors": 0}

    try:
        for dname in driver_dirs:
            yaml_path = os.path.join(crash_dir, dname, "crash_analysis.yaml")

            with open(yaml_path) as f:
                raw_text = f.read()
            try:
                data = yaml.safe_load(raw_text)
            except yaml.YAMLError as e:
                logger.error(f"  [{dname}] YAML parse error: {e}")
                stats["errors"] += 1
                continue

            if not isinstance(data, list):
                logger.warning(f"  [{dname}] Unexpected format, skipping")
                stats["skipped"] += 1
                continue

            if backup:
                bak = yaml_path + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(yaml_path, bak)

            modified = False
            for i, item in enumerate(data):
                if not isinstance(item, dict):
                    continue
                for crash_id, entry in item.items():
                    if not isinstance(entry, dict):
                        continue
                    stats["total"] += 1

                    build_out_path = os.path.join(out_dir, dname)
                    binary_snapshot = entry.get("binary_snapshot") or {}
                    snapshot_path = binary_snapshot.get("snapshot_path")

                    if prefer_build_out:
                        binary_path = build_out_path
                        binary_source = "build_out"
                        if not os.path.isfile(binary_path):
                            logger.warning(
                                f"  [{dname}/{crash_id}] Fresh build_out binary missing after rebuild; "
                                "falling back to snapshot if available"
                            )
                            binary_path = snapshot_path
                            binary_source = "snapshot"
                    else:
                        binary_path = snapshot_path
                        binary_source = "snapshot"
                        if not binary_path or not os.path.isfile(binary_path):
                            binary_path = build_out_path
                            binary_source = "build_out"
                    if not binary_path or not os.path.isfile(binary_path):
                        logger.info(f"  [{dname}/{crash_id}] Binary not found (snapshot/build_out), skip")
                        stats["skipped"] += 1
                        continue

                    if dry_run:
                        logger.info(
                            f"  [{dname}/{crash_id}] [DRY-RUN] Would ensure binary snapshot "
                            f"from {binary_source}: {binary_path}"
                        )
                    else:
                        try:
                            snap_meta = _ensure_entry_binary_snapshot(
                                entry,
                                binary_path,
                                os.path.join(crash_dir, dname),
                                dname,
                                crash_id,
                                force_refresh=prefer_build_out and binary_source == "build_out",
                            )
                            logger.info(
                                f"  [{dname}/{crash_id}] Snapshot ready: {snap_meta.get('snapshot_path')} "
                                f"(sha256={str(snap_meta.get('sha256', ''))[:16]}...)"
                            )
                        except Exception as e:
                            logger.warning(f"  [{dname}/{crash_id}] Snapshot update failed: {e}")

                    logger.info(f"  [{dname}/{crash_id}] Enriching... (binary_source={binary_source})")
                    try:
                        updated = enrich_one_crash(
                            entry, session, dname, project_name,
                            binary_path=binary_path,
                            dry_run=dry_run,
                        )
                        item[crash_id] = updated
                        modified = True
                        stats["enriched"] += 1
                    except Exception as e:
                        logger.error(f"  [{dname}/{crash_id}] Error: {e}")
                        stats["errors"] += 1

            if modified and not dry_run:
                _save_yaml(data, yaml_path)
                logger.info(f"  [{dname}] Updated {yaml_path}")

    finally:
        if session:
            session.close()

    logger.info(f"\n[{project_name}] Done: {stats}")
    return {"project": project_name, "status": "ok", "stats": stats}


def _save_yaml(data: list, path: str):
    """Save crash data YAML with multi-line string support."""
    class literal_str(str):
        pass

    def literal_presenter(dumper, d):
        return dumper.represent_scalar("tag:yaml.org,2002:str", d, style="|")

    yaml.add_representer(literal_str, literal_presenter)

    def _convert(obj):
        if isinstance(obj, dict):
            return {k: _convert(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_convert(v) for v in obj]
        elif isinstance(obj, str) and "\n" in obj:
            return literal_str(obj)
        return obj

    data = _convert(data)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def discover_projects(db_root: str) -> List[str]:
    """Find projects with crash data."""
    projects = []
    if not os.path.isdir(db_root):
        return projects
    for name in sorted(os.listdir(db_root)):
        crash_dir = os.path.join(db_root, name, "crash")
        if os.path.isdir(crash_dir):
            has_yaml = any(
                os.path.isfile(os.path.join(crash_dir, d, "crash_analysis.yaml"))
                for d in os.listdir(crash_dir)
                if os.path.isdir(os.path.join(crash_dir, d))
            )
            if has_yaml:
                projects.append(name)
    return projects


def main():
    parser = argparse.ArgumentParser(
        description="Retroactive enrichment: fix repro_rate & GDB context",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enrich one project
  python -m crash.retro_enrich --db-root external_database --project c-ares

  # Enrich all projects
  python -m crash.retro_enrich --db-root external_database

  # Preview without modifying files
  python -m crash.retro_enrich --db-root external_database --dry-run
        """,
    )
    parser.add_argument("--db-root", default="external_database",
                        help="Root directory (default: external_database)")
    parser.add_argument("--project", default=None,
                        help="Specific project to enrich (default: all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview only, do not modify files")
    parser.add_argument("--no-backup", action="store_true",
                        help="Skip creating .bak files")
    parser.add_argument("--rebuild-asan", action="store_true",
                        help="Rebuild ASan binaries before enrichment "
                             "(fixes coverage-only binaries in /out/)")
    args = parser.parse_args()

    if args.project:
        projects = [args.project]
    else:
        projects = discover_projects(args.db_root)

    if not projects:
        print(f"[!] No projects found under {args.db_root}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  RETROACTIVE ENRICHMENT")
    print(f"  Projects: {', '.join(projects)}")
    print(f"  Dry-run:  {args.dry_run}")
    print(f"  Rebuild ASan: {args.rebuild_asan}")
    print(f"{'='*60}\n")

    all_results = {}
    for proj in projects:
        if args.rebuild_asan and not args.dry_run:
            logger.info(f"\n[{proj}] Rebuilding ASan binaries...")
            rebuild_stats = rebuild_asan_binaries(args.db_root, proj)
            logger.info(f"[{proj}] Rebuild stats: {rebuild_stats}")

        result = enrich_project(
            args.db_root, proj,
            dry_run=args.dry_run,
            backup=not args.no_backup,
            prefer_build_out=args.rebuild_asan and not args.dry_run,
        )
        all_results[proj] = result

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for proj, r in all_results.items():
        s = r.get("stats", {})
        print(f"  {proj:20s}  status={r['status']:15s}  "
              f"total={s.get('total', 0)}  enriched={s.get('enriched', 0)}  "
              f"errors={s.get('errors', 0)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
