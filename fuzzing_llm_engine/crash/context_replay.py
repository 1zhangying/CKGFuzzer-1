"""Replay static and runtime context for selected crash records.

This entry point never calls an LLM.  It is intended for validating and
regenerating the evidence used by V3/V4 on explicit project/driver/crash IDs.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .context_validation import (
    parsed_crashes_match,
    runtime_context_summary,
    static_context_summary,
)
from .debugger import (
    _sanitizer_environment,
    collect_runtime_context,
    gdb_runtime_image,
)
from .locator import locate_crash_site
from .sanitizer_parser import parse_sanitizer_output
from .triage import compute_replay_key, replay_keys_compatible


_STACK_MODULE_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+"
    r"\((?P<module>[^()]+?)\+(?P<offset>0x[0-9a-fA-F]+)\)",
    re.MULTILINE,
)
_STACK_FRAME_LINE_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\b")
_SOURCE_RUNTIME_MARKERS = (
    "/compiler-rt/",
    "/llvm-project/",
    "/lib/fuzzer/",
    "sanitizer_common",
)
_SIGNAL_BUG_TYPES = {
    6: "ABRT",
    8: "FPE",
    4: "ILL",
    7: "BUS",
    11: "SEGV",
}
_PERSISTED_STACK_FRAMES = 32
_PERSISTED_BACKTRACE_CHARS = 32000


@dataclass(frozen=True)
class CrashSelection:
    project: str
    driver: str
    crash_id: str


def _engine_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _driver_dir_name(driver: str) -> str:
    name = Path(driver).name
    return name[:-3] if name.endswith(".cc") else name


def _resolve_record_path(
    db_root: Path,
    project: str,
    driver: str,
) -> Tuple[Path, str]:
    driver_dir = _driver_dir_name(driver)
    path = db_root / project / "crash" / driver_dir / "crash_analysis.yaml"
    return path, driver_dir


def _crash_key(driver_dir: str, crash_id: str) -> str:
    return re.sub(rf"^{re.escape(driver_dir)}_", "", crash_id)


def _load_yaml(path: Path) -> List[Dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"unexpected crash YAML shape: {path}")
    return data


def _find_entry(
    data: List[Dict[str, Any]],
    driver_dir: str,
    crash_id: str,
) -> Tuple[Dict[str, Any], str]:
    local_id = _crash_key(driver_dir, crash_id)
    for item in data:
        if isinstance(item, dict) and local_id in item:
            return item[local_id], local_id
    expected = f"{driver_dir}_{local_id}"
    raise KeyError(f"crash record {expected!r} not found")


def _resolve_path(value: Any) -> Optional[Path]:
    if not value:
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = _engine_root() / path
    return path


def _resolve_binary(
    project: str,
    driver_dir: str,
    entry: Dict[str, Any],
) -> Tuple[Optional[Path], str]:
    candidates = (
        (
            (entry.get("binary_snapshot") or {}).get("snapshot_path"),
            "snapshot",
        ),
        (entry.get("binary_path_for_repro"), "snapshot_legacy"),
        (_engine_root() / "build" / "out" / project / driver_dir, "build_out"),
    )
    for value, source in candidates:
        path = Path(value) if value and os.path.isabs(value) else _resolve_path(value)
        if path and path.is_file():
            return path, source
    return None, "missing"


def _resolve_poc(
    entry: Dict[str, Any],
    project: Optional[str] = None,
) -> Optional[Path]:
    candidates = (
        (entry.get("poc_paths") or {}).get("poc"),
        (entry.get("poc_locate") or {}).get("host_path"),
    )
    for value in candidates:
        path = Path(value) if value and os.path.isabs(value) else _resolve_path(value)
        if path and path.is_file():
            return path
    parsed = entry.get("sanitizer_parsed") or {}
    hint = parsed.get("artifact_path_hint")
    if project and hint:
        candidate = (
            _engine_root()
            / "build"
            / "out"
            / project
            / Path(str(hint)).name
        )
        if candidate.is_file():
            return candidate
    return None


def _run_once(
    binary: Path,
    poc: Path,
    parsed: Dict[str, Any],
    driver_basename: str,
    timeout: int,
    env: Dict[str, str],
) -> Dict[str, Any]:
    signal_probe_returncode: Optional[int] = None
    with tempfile.TemporaryDirectory(prefix="ckg-context-replay-") as temp_dir:
        try:
            proc = subprocess.run(
                [str(binary), str(poc)],
                cwd=temp_dir,
                env={**os.environ, **env},
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            timed_out = False
            returncode = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            output = stdout + "\n" + stderr
            timed_out = True
            returncode = None

        # libFuzzer installs signal handlers by default and converts an
        # ordinary ABRT/SEGV into exit code 77 plus "deadly signal". Execute a
        # second, minimal probe with those handlers disabled so the replay key
        # retains the actual signal bug type. The first run still supplies the
        # symbolized stack; the probe supplies only the signal classification.
        if (
            not timed_out
            and returncode not in (None, 0)
            and parsed.get("bug_type") in set(_SIGNAL_BUG_TYPES.values())
        ):
            try:
                probe = subprocess.run(
                    [
                        str(binary),
                        str(poc),
                        "-handle_abrt=0",
                        "-handle_segv=0",
                        "-handle_fpe=0",
                        "-handle_ill=0",
                        "-handle_bus=0",
                    ],
                    cwd=temp_dir,
                    env={**os.environ, **env},
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                signal_probe_returncode = probe.returncode
            except (subprocess.TimeoutExpired, OSError):
                signal_probe_returncode = None

    observed = parse_sanitizer_output(output)
    _symbolize_unresolved_frames(observed, output, binary)
    if observed.get("bug_type") is None and signal_probe_returncode is not None:
        signal_number = (
            -signal_probe_returncode
            if signal_probe_returncode < 0
            else signal_probe_returncode - 128
            if signal_probe_returncode >= 128
            else None
        )
        observed["bug_type"] = _SIGNAL_BUG_TYPES.get(signal_number)
    expected_key = compute_replay_key(parsed)
    observed_key = compute_replay_key(observed)
    consistent = replay_keys_compatible(expected_key, observed_key)
    match_level = "exact" if consistent else None
    if not consistent:
        consistent = _inline_normalized_match(
            parsed,
            observed,
            driver_basename,
        )
        match_level = "inline_normalized" if consistent else None
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "replay_consistent": consistent,
        "match_level": match_level,
        "replay_key": observed_key,
        "bug_type": observed.get("bug_type"),
        "signal_probe_returncode": signal_probe_returncode,
        "first_in_project_frame": observed.get("first_in_project_frame"),
        "first_in_project_function": observed.get("first_in_project_function"),
        "output_excerpt": "" if consistent else output[-4000:],
    }


def _inline_normalized_match(
    expected: Dict[str, Any],
    observed: Dict[str, Any],
    driver_basename: str,
) -> bool:
    """Allow optimizer-generated duplicate/inline frames around one crash site."""
    matched, _reason = parsed_crashes_match(
        expected,
        observed,
        driver_basename,
    )
    return matched


def _symbolize_unresolved_frames(
    parsed: Dict[str, Any],
    output: str,
    binary: Path,
) -> None:
    """Resolve ASan's binary+offset frames without an external symbolizer."""
    # A report can contain multiple stacks: the sanitizer crash stack, the
    # owning-frame block under "Address ... located in stack", and libFuzzer's
    # secondary deadly-signal handler stack. Only the first contiguous stack
    # belongs to the retained crash; later blocks reuse frame indexes and would
    # otherwise overwrite the correct offsets.
    stack_output = _first_stack_block(output)
    offsets: Dict[int, str] = {}
    for match in _STACK_MODULE_RE.finditer(stack_output):
        module = Path(match.group("module").strip())
        if module.name != binary.name:
            continue
        offsets[int(match.group("idx"))] = match.group("offset")
    if not offsets:
        return

    for frame in parsed.get("frames") or []:
        if frame.get("file"):
            continue
        offset = offsets.get(int(frame.get("idx", -1)))
        if not offset:
            continue
        try:
            proc = subprocess.run(
                ["addr2line", "-C", "-e", str(binary), "-f", offset],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        lines = [line.strip() for line in proc.stdout.splitlines()]
        if len(lines) < 2 or lines[0] in {"??", ""} or lines[1].startswith("??"):
            continue
        location = lines[1]
        if ":" not in location:
            continue
        file_name, line_number = location.rsplit(":", 1)
        try:
            frame["line"] = int(line_number)
        except ValueError:
            continue
        frame["func"] = lines[0]
        frame["file"] = file_name

    parsed["first_in_project_frame"] = None
    parsed["first_in_project_function"] = None
    for frame in parsed.get("frames") or []:
        file_name = str(frame.get("file") or "").lower()
        if (
            "/src/" in file_name
            and not any(marker in file_name for marker in _SOURCE_RUNTIME_MARKERS)
        ):
            parsed["first_in_project_frame"] = f"{frame['file']}:{frame['line']}"
            parsed["first_in_project_function"] = frame.get("func")
            break


def _first_stack_block(output: str) -> str:
    """Return the first contiguous sanitizer stack block."""
    lines = output.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if _STACK_FRAME_LINE_RE.match(line)),
        None,
    )
    if start is None:
        return ""
    block = []
    for line in lines[start:]:
        if _STACK_FRAME_LINE_RE.match(line):
            block.append(line)
            continue
        if block:
            break
    return "\n".join(block)


def _static_context(
    parsed: Dict[str, Any],
    driver_dir: str,
) -> Dict[str, Any]:
    location = locate_crash_site(
        parsed,
        driver_basename=f"{driver_dir}.cc",
    )
    return {
        **static_context_summary(location),
        "location": location,
    }


def _compact_runtime_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Bound persisted GDB data, especially for stack-exhaustion crashes."""
    compact = dict(context or {})
    compact["call_stack"] = list(compact.get("call_stack") or [])[
        :_PERSISTED_STACK_FRAMES
    ]
    backtrace = compact.get("backtrace_text")
    if isinstance(backtrace, str) and len(backtrace) > _PERSISTED_BACKTRACE_CHARS:
        compact["backtrace_text"] = (
            backtrace[:_PERSISTED_BACKTRACE_CHARS]
            + "\n[truncated by context_replay]"
        )
    excerpt = compact.get("gdb_output_excerpt")
    if isinstance(excerpt, str) and len(excerpt) > 8000:
        compact["gdb_output_excerpt"] = excerpt[-8000:]
    return compact


def replay_context(
    selection: CrashSelection,
    *,
    db_root: Path,
    replay_attempts: int = 3,
    gdb_attempts: int = 3,
    timeout: int = 15,
    prefer_docker: bool = True,
    force_runtime: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Collect and validate static/runtime context for one crash record."""
    driver_dir = _driver_dir_name(selection.driver)
    yaml_path, driver_dir = _resolve_record_path(
        db_root,
        selection.project,
        selection.driver,
    )
    data = _load_yaml(yaml_path)
    entry, local_id = _find_entry(data, driver_dir, selection.crash_id)

    crash_info = str(entry.get("crash_info") or "")
    if crash_info.startswith("|"):
        crash_info = crash_info[1:].lstrip("\n")
    parsed = entry.get("sanitizer_parsed")
    if not isinstance(parsed, dict):
        parsed = parse_sanitizer_output(crash_info)

    static = _static_context(parsed, driver_dir) if parsed.get("frames") else {
        "status": "unavailable",
        "location": None,
        "reason": "sanitizer_frames_missing",
    }
    binary, binary_source = _resolve_binary(
        selection.project,
        driver_dir,
        entry,
    )
    poc = _resolve_poc(entry, selection.project)
    direct_runs: List[Dict[str, Any]] = []
    if binary and poc and replay_attempts > 0:
        env = _sanitizer_environment(
            {
                name: os.environ.get(name, "")
                for name in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS")
            }
        )
        for _ in range(replay_attempts):
            direct_runs.append(
                _run_once(
                    binary,
                    poc,
                    parsed,
                    f"{driver_dir}.cc",
                    timeout,
                    env,
                )
            )
    replay_count = sum(
        1 for run in direct_runs if run.get("replay_consistent")
    )

    runtime: Dict[str, Any]
    if binary and poc:
        # Direct replay is useful evidence, but it is not a gate: the host
        # runtime may lack the OSS-Fuzz libraries. GDB collection validates the
        # reconstructed crash against the retained crash identity before the
        # result can be marked available.
        runtime = collect_runtime_context(
            str(binary),
            str(poc),
            attempts=gdb_attempts,
            timeout=timeout,
            prefer_docker=prefer_docker,
            expected_crash=parsed,
            driver_basename=f"{driver_dir}.cc",
            docker_image=gdb_runtime_image(selection.project),
        )
    else:
        runtime = {
            "reproduced": False,
            "error_message": (
                "runtime replay skipped: "
                "binary or PoC missing"
            ),
            "collection_method": "not_attempted",
        }
    fresh_runtime = _compact_runtime_context(runtime)

    runtime_status = runtime_context_summary(
        fresh_runtime,
        parsed,
        f"{driver_dir}.cc",
    )
    runtime = fresh_runtime
    runtime_source = "fresh" if runtime_status.get("status") == "available" else "none"
    if runtime_status.get("status") != "available":
        historical = _compact_runtime_context(
            entry.get("gdb_runtime_context") or {}
        )
        historical_status = runtime_context_summary(
            historical,
            parsed,
            f"{driver_dir}.cc",
        )
        if historical_status.get("status") == "available":
            runtime = historical
            runtime_status = historical_status
            runtime_source = "historical"
    result = {
        "project": selection.project,
        "driver": driver_dir,
        "crash_id": f"{driver_dir}_{local_id}",
        "source_yaml": str(yaml_path.resolve()),
        "binary": str(binary) if binary else None,
        "binary_source": binary_source,
        "poc": str(poc) if poc else None,
        "original_crash": parsed,
        "direct_replay": {
            "attempts": len(direct_runs),
            "consistent": replay_count,
            "repro_rate": f"{replay_count}/{len(direct_runs)}" if direct_runs else "0/0",
            "runs": direct_runs,
        },
        "static_context": static,
        "runtime_context": runtime,
        "runtime_context_attempt": fresh_runtime,
        "runtime_status": runtime_status,
        "runtime_source": runtime_source,
        "status": (
            "ok"
            if static.get("status") == "available"
            and runtime_status.get("status") == "available"
            else "partial"
        ),
        "generated_at": datetime.now().isoformat(),
    }
    return result, entry, local_id


def _write_result(output_dir: Path, result: Dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        f"{result['project']}_{result['crash_id']}",
    )
    path = output_dir / f"{safe}.json"
    path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def _update_entry(
    entry: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    static_location = (result.get("static_context") or {}).get("location")
    if isinstance(static_location, dict) and static_location.get("crash_file"):
        entry["location"] = {
            "crash_file": static_location.get("crash_file"),
            "crash_line": static_location.get("crash_line"),
            "crash_function": static_location.get("crash_function"),
            "crash_code_snippet": static_location.get("crash_code_snippet"),
            "call_chain_context": static_location.get("call_chain_context") or [],
            "symbolized": static_location.get("symbolized"),
        }
    runtime_context = result.get("runtime_context") or {}
    if runtime_context.get("reproduced"):
        entry["gdb_runtime_context"] = runtime_context
    direct = result.get("direct_replay") or {}
    runs = direct.get("runs") or []
    if runs:
        entry["repro"] = {
            "enabled": True,
            "prepared": True,
            "runs": runs,
            "repro_rate": direct.get("repro_rate", "0/0"),
            "method": "context_replay_cli",
        }
    entry["context_replay"] = {
        "status": result.get("status"),
        "runtime_status": result.get("runtime_status"),
        "runtime_source": result.get("runtime_source"),
        "static_status": (result.get("static_context") or {}).get("status"),
        "runtime_context_attempt": (
            result.get("runtime_context_attempt")
            or runtime_context
        ),
        "generated_at": result.get("generated_at"),
    }


def _write_yaml(path: Path, data: List[Dict[str, Any]]) -> None:
    class ContextDumper(yaml.SafeDumper):
        pass

    def represent_string(dumper, value):
        style = "|" if "\n" in value else None
        return dumper.represent_scalar(
            "tag:yaml.org,2002:str",
            value,
            style=style,
        )

    ContextDumper.add_representer(str, represent_string)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        yaml.dump(
            data,
            Dumper=ContextDumper,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay static and dynamic context for selected crashes",
    )
    parser.add_argument(
        "--manifest",
        help=(
            "CSV manifest with Project,Driver,CrashID columns; processes "
            "exactly the listed rows and cannot be combined with --project, "
            "--driver, or --crash-id"
        ),
    )
    parser.add_argument("--project")
    parser.add_argument(
        "--driver",
        help="crash driver directory or .cc filename",
    )
    parser.add_argument(
        "--crash-id",
        action="append",
        default=[],
        help="crash_1, driver_crash_1, or comma-separated values",
    )
    parser.add_argument(
        "--db-root",
        default="external_database",
        help="database root relative to fuzzing_llm_engine",
    )
    parser.add_argument(
        "--output-dir",
        default="results/context_replay",
    )
    parser.add_argument("--replay-attempts", type=int, default=3)
    parser.add_argument("--gdb-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument(
        "--prefer-docker",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "run GDB in the OSS-Fuzz base-runner container first; "
            "disabled by default for fast single-sample replay"
        ),
    )
    parser.add_argument(
        "--force-runtime",
        action="store_true",
        help=(
            "deprecated compatibility flag; runtime collection is already "
            "attempted whenever the binary and PoC are available"
        ),
    )
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="write regenerated context back to crash_analysis.yaml",
    )
    return parser.parse_args(argv)


def _selected_ids(raw_ids: Iterable[str]) -> List[str]:
    values: List[str] = []
    for raw in raw_ids:
        values.extend(
            item.strip() for item in raw.split(",") if item.strip()
        )
    return values


def _load_driver_data(
    project: str,
    driver: str,
    db_root: Path,
) -> Tuple[Path, str, List[Dict[str, Any]]]:
    path, driver_dir = _resolve_record_path(db_root, project, driver)
    return path, driver_dir, _load_yaml(path)


def _load_manifest_selections(path: Path) -> List[CrashSelection]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"Project", "Driver", "CrashID"}
    if not rows:
        raise ValueError(f"manifest is empty: {path}")
    missing = required - set(rows[0])
    if missing:
        raise ValueError(
            f"manifest is missing columns {sorted(missing)}: {path}"
        )

    selections: List[CrashSelection] = []
    seen = set()
    for index, row in enumerate(rows, 2):
        project = str(row.get("Project") or "").strip()
        driver = _driver_dir_name(str(row.get("Driver") or "").strip())
        crash_id = str(row.get("CrashID") or "").strip()
        if not project or not driver or not crash_id:
            raise ValueError(f"manifest row {index} has an empty key: {path}")
        key = (project, driver, crash_id)
        if key in seen:
            raise ValueError(f"duplicate manifest row {index}: {key}")
        seen.add(key)
        selections.append(CrashSelection(project, driver, crash_id))
    return selections


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    db_root = Path(args.db_root)
    if not db_root.is_absolute():
        db_root = _engine_root() / db_root
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = _engine_root() / output_dir

    explicit_selection = bool(args.project or args.driver or args.crash_id)
    if args.manifest and explicit_selection:
        raise ValueError(
            "--manifest cannot be combined with --project, --driver, "
            "or --crash-id"
        )
    if not args.manifest and (not args.project or not args.driver):
        raise ValueError("either --manifest or both --project and --driver are required")

    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.is_absolute():
            manifest_path = _engine_root() / manifest_path
        selections = _load_manifest_selections(manifest_path)
    else:
        _, driver_dir, source_data = _load_driver_data(
            args.project,
            args.driver,
            db_root,
        )
        requested = _selected_ids(args.crash_id)
        if not requested:
            requested = [
                key
                for item in source_data
                if isinstance(item, dict)
                for key in item
            ]
        selections = [
            CrashSelection(
                args.project,
                driver_dir,
                f"{driver_dir}_{_crash_key(driver_dir, crash_id)}",
            )
            for crash_id in requested
        ]

    grouped: Dict[Tuple[str, str], List[CrashSelection]] = {}
    for selection in selections:
        key = (
            selection.project,
            _driver_dir_name(selection.driver),
        )
        grouped.setdefault(key, []).append(selection)

    results: List[Dict[str, Any]] = []
    per_driver: List[Dict[str, Any]] = []
    for (project, driver_dir), group in grouped.items():
        yaml_path, _driver_dir, source_data = _load_driver_data(
            project,
            driver_dir,
            db_root,
        )
        group_results: List[Dict[str, Any]] = []
        for selection in grouped[(project, driver_dir)]:
            normalized = (
                f"{driver_dir}_{_crash_key(driver_dir, selection.crash_id)}"
            )
            if normalized == driver_dir:
                raise ValueError(f"invalid crash ID: {selection.crash_id}")
            result, _entry, _local_id = replay_context(
                CrashSelection(project, driver_dir, normalized),
                db_root=db_root,
                replay_attempts=args.replay_attempts,
                gdb_attempts=args.gdb_attempts,
                timeout=args.timeout,
                prefer_docker=args.prefer_docker,
                force_runtime=args.force_runtime,
            )
            path = _write_result(output_dir, result)
            results.append(result)
            group_results.append(result)
            if args.update_db:
                entry, _ = _find_entry(source_data, driver_dir, normalized)
                _update_entry(entry, result)
            print(
                f"{result['crash_id']}: static={result['static_context']['status']} "
                f"runtime={result['runtime_status']['status']}"
                f"({result.get('runtime_source')}) "
                f"replay={result['direct_replay']['repro_rate']} -> {path}"
            )

        if args.update_db:
            _write_yaml(yaml_path, source_data)
            print(f"Updated {yaml_path}")
        per_driver.append({
            "project": project,
            "driver": driver_dir,
            "requested": len(group_results),
            "static_available": sum(
                1
                for item in group_results
                if item["static_context"]["status"] == "available"
            ),
            "runtime_available": sum(
                1
                for item in group_results
                if item["runtime_status"]["status"] == "available"
            ),
            "runtime_fresh": sum(
                1
                for item in group_results
                if item.get("runtime_source") == "fresh"
            ),
            "runtime_historical": sum(
                1
                for item in group_results
                if item.get("runtime_source") == "historical"
            ),
        })

    summary = {
        "manifest": args.manifest,
        "requested": len(selections),
        "processed": len(results),
        "static_available": sum(
            1
            for item in results
            if item["static_context"]["status"] == "available"
        ),
        "runtime_available": sum(
            1
            for item in results
            if item["runtime_status"]["status"] == "available"
        ),
        "runtime_fresh": sum(
            1 for item in results if item.get("runtime_source") == "fresh"
        ),
        "runtime_historical": sum(
            1
            for item in results
            if item.get("runtime_source") == "historical"
        ),
        "runtime_unavailable": sum(
            1
            for item in results
            if item["runtime_status"]["status"] != "available"
        ),
        "per_driver": per_driver,
        "generated_at": datetime.now().isoformat(),
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
