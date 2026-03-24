
from configs.llm_config import LLMConfig
# from models.baseLLM import BaseLLM
import os
import gc
from utils.check_gen_fuzzer import run
from repo.coverage_postproc import *
from .compilation_fix_agent import CompilationFixAgent, extract_code
from .fuzz_generator import FuzzingGenerationAgent
from .input_gen_agent import InputGenerationAgent
from .crash_analyzer import CrashAnalyzer
from .planner import FuzzingPlanner
from loguru import logger
# import shutil
# import re
from datetime import datetime
from typing import Optional
import textwrap

import zipfile
import yaml
import json
import time
import csv
import shutil

import time as _time

from crash.sanitizer_parser import parse_sanitizer_output, format_crash_summary
from crash.triage import triage_crash
from crash.locator import locate_crash_site, format_call_chain_for_llm
from crash.debugger import reproduce_with_gdb, format_runtime_context_for_llm
from crash.dedup import DeduplicationEngine
from crash.poc import locate_poc_on_host, safe_copy_poc
from crash.report import build_crash_report, save_crash_report

_FUZZING_LLM_ENGINE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _get_binary_path(project_name: str, fuzzer_name: str) -> Optional[str]:
    """Return host-side path to the compiled fuzz target binary, or None."""
    path = os.path.join(_FUZZING_LLM_ENGINE_DIR, 'build', 'out', project_name, fuzzer_name)
    if os.path.isfile(path):
        return path
    logger.debug(f"[GDB] Binary not found at {path}")
    return None


# Module-level dedup engine (shared across all crash analyses in a session)
_dedup_engine: Optional[DeduplicationEngine] = None

def _get_dedup_engine(db_path: Optional[str] = None) -> DeduplicationEngine:
    global _dedup_engine
    if _dedup_engine is None:
        _dedup_engine = DeduplicationEngine()
        if db_path and os.path.isfile(db_path):
            _dedup_engine.load_from_file(db_path)
    return _dedup_engine


def _extract_crash_entry(crash: dict):
    crash_id = list(crash.keys())[0]
    return crash_id, crash[crash_id]


def _find_duplicate_of(crash_data: list, signature: str):
    if not signature:
        return None
    for crash in crash_data:
        _id, entry = _extract_crash_entry(crash)
        if entry.get("signature") == signature:
            return _id
    return None


def _run_repro_once(project_name: str, fuzz_driver_file: str, fuzzer_name: str, fuzzing_llm_dir: str, corpus_dir: str, poc_name_in_corpus: str, timeout: str) -> str:
    """Run the fuzzer once with a specific PoC to reproduce a crash.

    Uses '--' to separate fuzzer-level arguments from libFuzzer arguments,
    preventing argparse from rejecting the PoC container path.
    Catches SystemExit from argparse failures to avoid crashing the whole process.
    """
    poc_container_path = f"/tmp/{fuzzer_name}_corpus/{poc_name_in_corpus}"
    run_args = [
        "run_fuzzer",
        project_name,
        "--timeout",
        timeout,
        "--fuzz_driver_file",
        fuzz_driver_file,
        fuzzer_name,
        "--fuzzing_llm_dir",
        fuzzing_llm_dir,
        "--corpus-dir",
        corpus_dir,
        "--",
        poc_container_path,
    ]
    try:
        result = run(run_args)
        return result if isinstance(result, str) else ""
    except SystemExit as e:
        logger.warning(f"[Repro] argparse rejected args (exit code {e.code}), "
                       f"poc={poc_container_path}")
        return ""


def _run_minimize(project_name: str, fuzz_driver_file: str, fuzzer_name: str, fuzzing_llm_dir: str, corpus_dir: str, poc_name_in_corpus: str, out_name_in_corpus: str, timeout: str) -> str:
    """Run libFuzzer minimization on a crash PoC.

    Uses '--' separator so that libFuzzer-specific flags (starting with '-')
    are not misinterpreted by argparse as unknown optional arguments.
    Catches SystemExit from argparse failures to avoid crashing the whole process.
    """
    poc_container_path = f"/tmp/{fuzzer_name}_corpus/{poc_name_in_corpus}"
    out_container_path = f"/tmp/{fuzzer_name}_corpus/{out_name_in_corpus}"
    run_args = [
        "run_fuzzer",
        project_name,
        "--timeout",
        timeout,
        "--fuzz_driver_file",
        fuzz_driver_file,
        fuzzer_name,
        "--fuzzing_llm_dir",
        fuzzing_llm_dir,
        "--corpus-dir",
        corpus_dir,
        "--",
        f"-runs=1",
        f"-minimize_crash=1",
        f"-exact_artifact_path={out_container_path}",
        poc_container_path,
    ]
    try:
        result = run(run_args)
        return result if isinstance(result, str) else ""
    except SystemExit as e:
        logger.warning(f"[Minimize] argparse rejected args (exit code {e.code}), "
                       f"poc={poc_container_path}")
        return ""




def run_enhanced_crash_pipeline(
    crash_info: str,
    fuzz_driver_path: str,
    api_combine: list,
    crash_analyzer: "CrashAnalyzer",
    *,
    project_name: Optional[str] = None,
    fuzzer_name: Optional[str] = None,
    corpus_dir: Optional[str] = None,
    fuzzing_llm_dir: Optional[str] = None,
    binary_path: Optional[str] = None,
    fuzz_project_dir: Optional[str] = None,
    run_baseline: bool = False,
) -> dict:
    """Run the full 6-stage enhanced crash analysis pipeline.

    Stages:
      1. Sanitizer parse (deterministic)
      2. Rule-based triage (deterministic)
      3. Precise code location + call chain context
      4. PoC locate + reproduction + GDB runtime context
      5. Multi-level deduplication
      6. LLM context-enriched analysis (only if triage says worth it)

    Returns a dict with all stage results + final verdict.
    """
    fuzz_driver_basename = os.path.basename(fuzz_driver_path) if fuzz_driver_path else None
    _timings = {}  # collect per-stage wall-clock time for experiment metrics

    # Stage 1: Deterministic sanitizer parse
    _t0 = _time.monotonic()
    parsed = parse_sanitizer_output(crash_info or "")
    _timings["stage1_parse_ms"] = round((_time.monotonic() - _t0) * 1000, 1)
    logger.info(f"[Pipeline] Stage 1 — Parsed: bug_type={parsed.get('bug_type')}, "
                f"frames={len(parsed.get('frames', []))}, "
                f"first_project_frame={parsed.get('first_in_project_frame')} "
                f"({_timings['stage1_parse_ms']}ms)")

    # Stage 2: Rule-based triage
    _t0 = _time.monotonic()
    triage = triage_crash(parsed, fuzz_driver_basename=fuzz_driver_basename)
    _timings["stage2_triage_ms"] = round((_time.monotonic() - _t0) * 1000, 1)
    logger.info(f"[Pipeline] Stage 2 — Triage: label={triage.get('label')}, "
                f"confidence={triage.get('confidence')}, "
                f"rules={triage.get('matched_rules')} "
                f"({_timings['stage2_triage_ms']}ms)")

    # Stage 3: Precise code location
    _t0 = _time.monotonic()
    location = locate_crash_site(parsed, driver_basename=fuzz_driver_basename,
                                 binary_path=binary_path)
    _timings["stage3_locate_ms"] = round((_time.monotonic() - _t0) * 1000, 1)
    logger.info(f"[Pipeline] Stage 3 — Location: {location.get('crash_function')} "
                f"@ {location.get('crash_file')}:{location.get('crash_line')}, "
                f"symbolized={location.get('symbolized')} "
                f"({_timings['stage3_locate_ms']}ms)")

    # Stage 4: PoC locate + reproduce + GDB
    poc_info = None
    poc_paths = {}
    poc_copy = {"copied": False}
    runtime_ctx = None
    repro_info = {"enabled": False}

    if project_name:
        poc_info = locate_poc_on_host(parsed, project_name=project_name, corpus_dir=corpus_dir)
        if poc_info.get("exists") and poc_info.get("host_path"):
            crash_dir = os.path.join(fuzz_project_dir, "crash") if fuzz_project_dir else "/tmp"
            pocs_dir = os.path.join(crash_dir, "pocs")
            poc_dst = os.path.join(pocs_dir, f"poc_{fuzzer_name or 'unknown'}")
            ok, err = safe_copy_poc(poc_info["host_path"], poc_dst)
            poc_copy = {"copied": ok, "error": err, "dst": poc_dst}
            if ok:
                poc_paths["poc"] = poc_dst

    # Try reproduction via container (existing mechanism)
    if poc_copy.get("copied") and fuzzer_name and corpus_dir and fuzzing_llm_dir and project_name:
        repro_info["enabled"] = True
        repro_name = f"repro_{fuzzer_name}"
        try:
            ok, err = safe_copy_poc(poc_copy["dst"], os.path.join(corpus_dir, repro_name))
            repro_info["prepared"] = ok
            if ok:
                runs = []
                for _ in range(3):
                    from utils.check_gen_fuzzer import run as _run
                    fuzz_driver_file = os.path.basename(fuzz_driver_path)
                    out = _run_repro_once(project_name, fuzz_driver_file, fuzzer_name,
                                          fuzzing_llm_dir, corpus_dir, repro_name, timeout="10s")
                    p2 = parse_sanitizer_output(out or "")
                    t2 = triage_crash(p2, fuzz_driver_basename=fuzz_driver_basename)
                    runs.append({
                        "has_error": ("ERROR" in out) if isinstance(out, str) else False,
                        "signature": t2.get("signature"),
                        "same_signature": t2.get("signature") == triage.get("signature"),
                    })
                repro_info["runs"] = runs
                repro_info["repro_rate"] = f"{sum(1 for r in runs if r.get('same_signature'))}/{len(runs)}"
        except (Exception, SystemExit) as e:
            logger.warning(f"[Pipeline] Reproduction failed: {e}")
            repro_info["error"] = str(e)

    # Try GDB if binary is available and PoC exists
    if binary_path and poc_paths.get("poc") and os.path.isfile(binary_path):
        try:
            runtime_ctx = reproduce_with_gdb(binary_path, poc_paths["poc"], timeout=15)
            logger.info(f"[Pipeline] Stage 4 — GDB: reproduced={runtime_ctx.get('reproduced')}")
        except Exception as e:
            logger.warning(f"[Pipeline] GDB failed: {e}")

    # Stage 5: Deduplication
    _t0 = _time.monotonic()
    dedup_db_path = os.path.join(fuzz_project_dir, "crash", "dedup_db.yaml") if fuzz_project_dir else None
    dedup_engine = _get_dedup_engine(dedup_db_path)
    crash_id_for_dedup = f"{fuzzer_name or 'unknown'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    dedup_info = dedup_engine.add_crash(crash_id_for_dedup, triage, parsed)
    _timings["stage5_dedup_ms"] = round((_time.monotonic() - _t0) * 1000, 1)
    logger.info(f"[Pipeline] Stage 5 — Dedup: is_duplicate={dedup_info.get('is_duplicate')}, "
                f"cluster={dedup_info.get('cluster_id')} "
                f"({_timings['stage5_dedup_ms']}ms)")

    # Save dedup DB
    if dedup_db_path:
        try:
            dedup_engine.save_to_file(dedup_db_path)
        except Exception as e:
            logger.warning(f"[Pipeline] Failed to save dedup DB: {e}")

    # Stage 6: LLM analysis (only if worth it and not duplicate)
    is_api_bug = False
    crash_category = parsed.get("bug_type") or "Unknown"
    analysis_text = ""
    enhanced_result = {}

    _t0 = _time.monotonic()
    if triage.get("is_worth_llm_analysis") and not dedup_info.get("is_duplicate"):
        logger.info("[Pipeline] Stage 6 — Running enhanced LLM analysis...")
        try:
            is_api_bug, crash_category, analysis_text, enhanced_result = \
                crash_analyzer.analyze_crash_enhanced(
                    crash_info, fuzz_driver_path, api_combine,
                    triage_result=triage,
                    location_result=location,
                    runtime_context=runtime_ctx,
                )
        except Exception as e:
            logger.error(f"[Pipeline] Enhanced LLM analysis failed, falling back: {e}")
            try:
                is_api_bug, crash_category, analysis_text = \
                    crash_analyzer.analyze_crash(crash_info, fuzz_driver_path, api_combine)
                enhanced_result = {"is_api_bug": is_api_bug, "crash_category": crash_category}
            except Exception as e2:
                logger.error(f"[Pipeline] Fallback analysis also failed: {e2}")
                analysis_text = f"Analysis failed: {e2}"
    elif dedup_info.get("is_duplicate"):
        logger.info(f"[Pipeline] Stage 6 — Skipping LLM (duplicate of {dedup_info.get('duplicate_of')})")
        analysis_text = f"Duplicate crash — same as {dedup_info.get('duplicate_of')}"
    else:
        logger.info(f"[Pipeline] Stage 6 — Skipping LLM (triage: {triage.get('label')})")
        is_api_bug = False
        analysis_text = f"Skipped LLM analysis — triage label: {triage.get('label')}"
    _timings["stage6_llm_ms"] = round((_time.monotonic() - _t0) * 1000, 1)
    _timings["llm_skipped"] = not (triage.get("is_worth_llm_analysis") and not dedup_info.get("is_duplicate"))
    _timings["llm_skip_reason"] = (
        "duplicate" if dedup_info.get("is_duplicate") else
        f"triage:{triage.get('label')}" if not triage.get("is_worth_llm_analysis") else
        "none"
    )
    logger.info(f"[Pipeline] Stage 6 done ({_timings['stage6_llm_ms']}ms, skipped={_timings['llm_skipped']})")

    # ── Ablation baseline: call OLD analyze_crash (no triage context) ────
    # This produces the "baseline LLM" judgment for A/B comparison in the paper.
    # Enabled by run_baseline=True or env ABLATION_BASELINE=1.
    _run_bl = run_baseline or os.environ.get("ABLATION_BASELINE", "") == "1"
    baseline_result = {"enabled": False}
    if _run_bl:
        logger.info("[Pipeline] Ablation — Running OLD analyze_crash (baseline, no triage context)...")
        _tb0 = _time.monotonic()
        try:
            bl_api_bug, bl_category, bl_text = crash_analyzer.analyze_crash(
                crash_info, fuzz_driver_path, api_combine
            )
            baseline_result = {
                "enabled": True,
                "is_api_bug": bl_api_bug,
                "crash_category": bl_category,
                "analysis_text": bl_text[:3000],  # truncate for storage
            }
        except Exception as e:
            logger.error(f"[Pipeline] Baseline analysis failed: {e}")
            baseline_result = {"enabled": True, "error": str(e)}
        _timings["baseline_llm_ms"] = round((_time.monotonic() - _tb0) * 1000, 1)
        logger.info(f"[Pipeline] Ablation baseline done ({_timings.get('baseline_llm_ms')}ms): "
                    f"is_api_bug={baseline_result.get('is_api_bug')}")

    logger.info(f"[Pipeline] === Timing summary: {_timings} ===")

    # Build report
    report = build_crash_report(
        crash_id_for_dedup,
        parsed=parsed,
        triage=triage,
        location=location,
        runtime_ctx=runtime_ctx,
        llm_analysis_text=analysis_text,
        enhanced_result=enhanced_result,
        dedup_info=dedup_info,
        poc_paths=poc_paths,
        repro_info=repro_info,
        fuzz_driver_file=os.path.basename(fuzz_driver_path) if fuzz_driver_path else None,
    )

    return {
        "is_api_bug": is_api_bug,
        "crash_category": crash_category,
        "analysis_text": analysis_text,
        "enhanced_result": enhanced_result,
        "parsed": parsed,
        "triage": triage,
        "location": location,
        "runtime_context": runtime_ctx,
        "dedup_info": dedup_info,
        "poc_paths": poc_paths,
        "repro": repro_info,
        "report": report,
        "timings": _timings,
        "baseline": baseline_result,
    }


def save_crash_analysis(
    fuzz_project_dir,
    fuzz_driver_file,
    is_api_bug,
    crash_category,
    crash_analysis,
    crash_info,
    fuzz_driver_path,
    *,
    project_name=None,
    fuzzer_name=None,
    corpus_dir=None,
    fuzzing_llm_dir=None,
    enable_repro=True,
    enable_minimize=True,
    pipeline_result=None,
):
    crash_dir = os.path.join(fuzz_project_dir, "crash")
    if not os.path.exists(crash_dir):
        os.makedirs(crash_dir)
    
    # Create a subdirectory for this fuzz driver
    fuzz_driver_name = os.path.splitext(fuzz_driver_file)[0]
    fuzz_driver_crash_dir = os.path.join(crash_dir, fuzz_driver_name)
    if not os.path.exists(fuzz_driver_crash_dir):
        os.makedirs(fuzz_driver_crash_dir)
    
    yaml_file_path = os.path.join(fuzz_driver_crash_dir, "crash_analysis.yaml")
    
    # Load existing data if file exists
    if os.path.exists(yaml_file_path):
        with open(yaml_file_path, 'r') as f:
            crash_data = yaml.safe_load(f) or []
    else:
        crash_data = []

    # Create a unique identifier for this crash
    crash_id = f"crash_{len(crash_data) + 1}"

    # Save the fuzz driver file with a unique name
    fuzz_driver_dest = os.path.join(fuzz_driver_crash_dir, f"{fuzz_driver_name}_{crash_id}.cc")
    shutil.copy2(fuzz_driver_path, fuzz_driver_dest)

    # Prepare the crash analysis with proper indentation
    formatted_crash_analysis = textwrap.indent(crash_analysis.strip(), '      ')
    formatted_crash_info = textwrap.indent(crash_info.strip(), '      ')

    fuzz_driver_basename = os.path.basename(fuzz_driver_path) if fuzz_driver_path else None
    sanitizer_parsed = parse_sanitizer_output(crash_info or "")
    triage = triage_crash(sanitizer_parsed, fuzz_driver_basename=fuzz_driver_basename)
    signature = triage.get("signature")

    duplicate_of = _find_duplicate_of(crash_data, signature)
    group_id = signature

    poc = None
    poc_copy = {"copied": False}
    poc_paths = {}

    if project_name:
        poc = locate_poc_on_host(sanitizer_parsed, project_name=project_name, corpus_dir=corpus_dir)
        if poc.get("exists") and poc.get("host_path"):
            pocs_dir = os.path.join(fuzz_driver_crash_dir, "pocs")
            poc_dst = os.path.join(pocs_dir, f"{crash_id}_poc")
            ok, err = safe_copy_poc(poc["host_path"], poc_dst)
            poc_copy = {"copied": ok, "error": err, "dst": poc_dst, "src": poc["host_path"]}
            if ok:
                poc_paths["poc"] = poc_dst

    repro = {"enabled": False}
    minimize = {"enabled": False}
    if enable_repro and project_name and fuzzer_name and corpus_dir and fuzzing_llm_dir and poc_copy.get("copied"):
        repro["enabled"] = True
        repro_name = f"repro_{crash_id}"
        ok, err = safe_copy_poc(poc_copy["dst"], os.path.join(corpus_dir, repro_name))
        repro["prepared"] = ok
        repro["prepare_error"] = err
        if ok:
            runs = []
            for _ in range(3):
                out = _run_repro_once(project_name, fuzz_driver_file, fuzzer_name, fuzzing_llm_dir, corpus_dir, repro_name, timeout="10s")
                parsed2 = parse_sanitizer_output(out or "")
                triage2 = triage_crash(parsed2, fuzz_driver_basename=fuzz_driver_basename)
                runs.append(
                    {
                        "has_error": ("ERROR" in out) if isinstance(out, str) else False,
                        "signature": triage2.get("signature"),
                        "same_signature": triage2.get("signature") == signature,
                    }
                )
            repro["runs"] = runs
            repro["repro_rate"] = f"{sum(1 for r in runs if r.get('same_signature'))}/{len(runs)}"

            if enable_minimize:
                minimize["enabled"] = True
                min_name = f"min_{crash_id}"
                _ = _run_minimize(project_name, fuzz_driver_file, fuzzer_name, fuzzing_llm_dir, corpus_dir, repro_name, min_name, timeout="60s")
                min_host_path = os.path.join(corpus_dir, min_name)
                if os.path.exists(min_host_path):
                    pocs_dir = os.path.join(fuzz_driver_crash_dir, "pocs")
                    min_dst = os.path.join(pocs_dir, f"{crash_id}_min_poc")
                    ok2, err2 = safe_copy_poc(min_host_path, min_dst)
                    minimize["created"] = True
                    minimize["copied"] = ok2
                    minimize["copy_error"] = err2
                    if ok2:
                        poc_paths["min_poc"] = min_dst
                else:
                    minimize["created"] = False

    # Build crash entry
    entry = {
        "is_api_bug": is_api_bug,
        "crash_category": crash_category,
        "crash_analysis": f"|\n{formatted_crash_analysis}",
        "crash_info": f"|\n{formatted_crash_info}",
        "sanitizer_parsed": sanitizer_parsed,
        "triage": triage,
        "signature": signature,
        "group_id": group_id,
        "duplicate_of": duplicate_of,
        "poc_locate": poc,
        "poc_copy": poc_copy,
        "poc_paths": poc_paths,
        "repro": repro,
        "minimize": minimize,
        "fuzz_driver_file": os.path.basename(fuzz_driver_dest),
        "timestamp": datetime.now().isoformat(),
    }

    # Merge enhanced pipeline results if available
    if pipeline_result:
        pr = pipeline_result
        if pr.get("location"):
            entry["location"] = {
                "crash_file": pr["location"].get("crash_file"),
                "crash_line": pr["location"].get("crash_line"),
                "crash_function": pr["location"].get("crash_function"),
                "symbolized": pr["location"].get("symbolized"),
            }
        if pr.get("enhanced_result"):
            entry["enhanced_analysis"] = pr["enhanced_result"]
        if pr.get("dedup_info"):
            entry["dedup"] = pr["dedup_info"]
        if pr.get("report", {}).get("verdict"):
            entry["verdict"] = pr["report"]["verdict"]
        if pr.get("timings"):
            entry["timings"] = pr["timings"]
        # Ablation baseline results (old LLM without triage context)
        bl = pr.get("baseline", {})
        if bl.get("enabled"):
            entry["baseline_llm"] = {
                "is_api_bug": bl.get("is_api_bug"),
                "crash_category": bl.get("crash_category"),
            }

    # Save enhanced report as separate file
    if pipeline_result and pipeline_result.get("report"):
        try:
            reports_dir = os.path.join(fuzz_driver_crash_dir, "reports")
            save_crash_report(pipeline_result["report"], reports_dir)
        except Exception as e:
            logger.warning(f"Failed to save enhanced report: {e}")

    crash_data.append({crash_id: entry})
    
    # Custom YAML dumper to preserve multi-line strings
    class literal_str(str):
        pass

    def literal_presenter(dumper, data):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

    yaml.add_representer(literal_str, literal_presenter)

    # Convert multi-line strings to literal_str
    for crash in crash_data:
        for key, value in crash[list(crash.keys())[0]].items():
            if isinstance(value, str) and '\n' in value:
                crash[list(crash.keys())[0]][key] = literal_str(value)

    # Save the updated data back to the file
    with open(yaml_file_path, 'w') as f:
        yaml.dump(crash_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    logger.info(f"New crash analysis (ID: {crash_id}) for {fuzz_driver_file} appended to {yaml_file_path}")
    logger.info(f"Fuzz driver file saved as {fuzz_driver_dest}")


class Fuzzer():
    def __init__(self, directory,project, fuzz_project_dir, corpus_dir, coverage_dir,report_dir,time_budget,report_target_dir,planner:FuzzingPlanner, fuzz_gen:FuzzingGenerationAgent,compilation_fix_agent:CompilationFixAgent,input_gen_agent:InputGenerationAgent, crash_analyzer:CrashAnalyzer, api_usage_count, max_itr_fuzz_loop=3):
        self.directory = directory
        self.project = project
        self.fuzz_project_dir = fuzz_project_dir
        self.output_dir = corpus_dir
        self.coverage_dir = coverage_dir
        self.report_dir = report_dir
        self.time_budget = time_budget
        self.covered_lines = 0
        self.covered_branches = 0
        self.max_itr_fuzz_loop= max_itr_fuzz_loop
        self.compilation_fix_agent = compilation_fix_agent
        self.planner = planner
        self.fuzz_gen = fuzz_gen
        self.input_gen = input_gen_agent
        self.crash_analyzer = crash_analyzer
        self.api_usage_count = api_usage_count
        self.failed_builds = []
        self.completed_drivers = []  # 记录已完成的驱动
        self.checkpoint_file = os.path.join(fuzz_project_dir, "fuzzing_checkpoint.json")
        self.individual_reports_dir = os.path.join(report_dir, "individual_reports")
        os.makedirs(self.individual_reports_dir, exist_ok=True)

        self.report_target_dir = report_target_dir


    def set_api_combination(self, api_combination):
        self.api_combination = api_combination

    def set_api_code(self, api_code):
        self.api_code = api_code

    def set_api_summary(self, api_summary):
        self.api_summary = api_summary
    
    def set_fuzz_gen_code_output_dir(self, fuzz_gen_code_output_dir):
        self.fuzz_gen_code_output_dir = fuzz_gen_code_output_dir

    def save_checkpoint(self, current_driver=None, status="in_progress"):
        """保存当前进度到checkpoint文件"""
        checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "current_driver": current_driver,
            "completed_drivers": self.completed_drivers,
            "failed_drivers": self.failed_builds,
            "covered_lines": self.covered_lines,
            "covered_branches": self.covered_branches,
            "api_usage_count": self.api_usage_count
        }
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
            logger.info(f"Checkpoint saved: {len(self.completed_drivers)} completed, {len(self.failed_builds)} failed")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def load_checkpoint(self):
        """加载之前的checkpoint（如果存在）"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    checkpoint = json.load(f)
                self.completed_drivers = checkpoint.get("completed_drivers", [])
                self.failed_builds = checkpoint.get("failed_drivers", [])
                self.covered_lines = checkpoint.get("covered_lines", 0)
                self.covered_branches = checkpoint.get("covered_branches", 0)
                self.api_usage_count = checkpoint.get("api_usage_count", self.api_usage_count)
                logger.info(f"Checkpoint loaded: {len(self.completed_drivers)} completed, {len(self.failed_builds)} failed")
                return True
            except Exception as e:
                logger.error(f"Failed to load checkpoint: {e}")
        return False

    def backup_coverage_report(self, fuzzer_name):
        """备份单个驱动的覆盖率报告（防止被OSS-Fuzz覆盖）"""
        backup_dir = os.path.join(self.individual_reports_dir, fuzzer_name)
        os.makedirs(backup_dir, exist_ok=True)
        
        # 备份各种覆盖率相关文件
        sources = [
            (f"{self.coverage_dir}dumps/{fuzzer_name}.profdata", f"{backup_dir}/{fuzzer_name}.profdata"),
            (f"{self.coverage_dir}textcov_reports/{fuzzer_name}.covreport", f"{backup_dir}/{fuzzer_name}.covreport"),
            (f"{self.coverage_dir}fuzzer_stats/{fuzzer_name}.json", f"{backup_dir}/{fuzzer_name}_stats.json"),
            (f"{self.coverage_dir}logs/{fuzzer_name}.log", f"{backup_dir}/{fuzzer_name}.log"),
        ]
        
        for src, dst in sources:
            if os.path.exists(src):
                try:
                    shutil.copy2(src, dst)
                except Exception as e:
                    logger.warning(f"Failed to backup {src}: {e}")
        
        # 备份HTML报告目录
        html_src = f"{self.coverage_dir}report_target/{fuzzer_name}"
        html_dst = f"{backup_dir}/html_report"
        if os.path.exists(html_src):
            try:
                if os.path.exists(html_dst):
                    shutil.rmtree(html_dst)
                shutil.copytree(html_src, html_dst)
            except Exception as e:
                logger.warning(f"Failed to backup HTML report: {e}")
        
        logger.info(f"Coverage report backed up to: {backup_dir}")
    
    def update_api_usage_count(self, api_combination):
        for api in api_combination:
            if api in self.api_usage_count:
                self.api_usage_count[api] += 1
            else:
                self.api_usage_count[api] = 1
        
        logger.info(f"Updated API usage count: {self.api_usage_count}")

    
    def analyze_low_coverage_files(self, threshold,file_coverages):
        merge_dir = os.path.join(self.report_dir, "merge_report")
        api_summary_path = os.path.join(self.fuzz_project_dir, "api_summary", "api_with_summary.json")

        if not os.path.exists(merge_dir):
            logger.warning(f"Merge directory does not exist: {merge_dir}")
            return []

        if not os.path.exists(api_summary_path):
            logger.warning(f"API summary file does not exist: {api_summary_path}")
            return []


        if not file_coverages:
            logger.warning("No coverage data found.")
            return []

        sorted_coverages, low_coverage_files = sort_and_filter_coverages(file_coverages, threshold)

        with open(api_summary_path, 'r') as f:
            api_summary = json.load(f)
   
        low_coverage_apis = []
        for file in low_coverage_files:
            file_name = file.split('.')[0] + '.c'  
            if file_name in api_summary:
                apis = [api for api in api_summary[file_name] if api != 'file_summary']
                low_coverage_apis.extend(apis)

        return low_coverage_apis


    def build_and_fuzz_one_file(self, fuzz_driver_file, fix_fuzz_driver_dir=None):
        if fix_fuzz_driver_dir is None:
            fix_fuzz_driver_dir = os.path.join(self.directory, f"fuzz_driver/{self.project}/compilation_pass_rag/")
        if not os.path.exists(fix_fuzz_driver_dir):
            logger.info(f"No folder {fix_fuzz_driver_dir}")
            return 
        fuzzer_name, _ = os.path.splitext(fuzz_driver_file)

        # Extract the number from fuzzer_name
        fuzzer_number = None
        parts = fuzzer_name.split('_')
        if len(parts) >= 4:
            fuzzer_number = int(parts[-1].split('.')[0])
        api_combine=self.api_combination[fuzzer_number-1]
        api_name=api_combine[-1]
        logger.info(f"Current Fuzzing API Name: {api_name}, its combination: {api_combine}")
        
        # build fuzz driver    
        run_args = ["build_fuzzer_file",self.project, "--fuzz_driver_file", fuzz_driver_file]    
        build_fuzzer_result =  run(run_args) 
        logger.info(f"compile {fuzz_driver_file}, result {build_fuzzer_result}")
          
        # Check if the build was successful
        # if "ERROR" in build_fuzzer_result or "error" in build_fuzzer_result.lower():
        if "Compilation failed" in build_fuzzer_result or "Compilation succeeded" not in build_fuzzer_result:   
            logger.error(f"Failed to build fuzzer {fuzz_driver_file}. Skipping this file.")
            self.failed_builds.append(fuzz_driver_file)
            return
        else:
        # If we've reached this point, the build was successful
            logger.info(f"Successfully built fuzzer {fuzz_driver_file}")
            corpus_dir = os.path.join(self.output_dir, f'{fuzzer_name}_corpus')
            if not os.path.isdir(corpus_dir):
                # empty corpus
                os.makedirs(corpus_dir, exist_ok=True)
            # run fuzzer with libfuzzer
            run_args = ["run_fuzzer", self.project,"--timeout", self.time_budget, "--fuzz_driver_file", fuzz_driver_file, fuzzer_name,"--fuzzing_llm_dir", self.directory,"--corpus-dir",f"{corpus_dir}"]  
            run_fuzzer_result =  run(run_args)  
            logger.info(f"run_fuzzer {fuzz_driver_file}, result {run_fuzzer_result}")

            # if "ERROR" in run_fuzzer_result:
            if run_fuzzer_result is False:
                logger.error(f"Failed to run fuzzer {fuzz_driver_file}. Fuzzer may not exist.")
                self.failed_builds.append(fuzz_driver_file)
                return
            if isinstance(run_fuzzer_result, str) and "ERROR" in run_fuzzer_result:
                logger.info("Crash detected. Running enhanced analysis pipeline...")
                error_index = run_fuzzer_result.index("ERROR")
                crash_info = run_fuzzer_result[error_index:]
                fuzz_driver_fullpath = f"{fix_fuzz_driver_dir}/{fuzz_driver_file}"
                binary_path = _get_binary_path(self.project, fuzzer_name)

                pipeline_result = run_enhanced_crash_pipeline(
                    crash_info,
                    fuzz_driver_fullpath,
                    api_combine,
                    self.crash_analyzer,
                    project_name=self.project,
                    fuzzer_name=fuzzer_name,
                    corpus_dir=corpus_dir,
                    fuzzing_llm_dir=self.directory,
                    binary_path=binary_path,
                    fuzz_project_dir=self.fuzz_project_dir,
                )

                is_api_bug = pipeline_result.get("is_api_bug", False)
                crash_category = pipeline_result.get("crash_category", "Unknown")
                crash_analysis = pipeline_result.get("analysis_text", "")

                save_crash_analysis(
                    self.fuzz_project_dir,
                    fuzz_driver_file,
                    is_api_bug,
                    crash_category,
                    crash_analysis,
                    crash_info,
                    fuzz_driver_fullpath,
                    project_name=self.project,
                    fuzzer_name=fuzzer_name,
                    corpus_dir=corpus_dir,
                    fuzzing_llm_dir=self.directory,
                    pipeline_result=pipeline_result,
                )

            # build fuzzer with coverage to collect the coverage reports
            run_args=['build_fuzzers',self.project, "--sanitizer", "coverage", "--fuzzing_llm_dir", self.directory, "--fuzz_driver_file", fuzz_driver_file]
            build_fuzzers_result =  run(run_args)  
            logger.info(f"build coverage {self.project}, result {build_fuzzers_result}")
            
            # compute coverage
            run_args=['coverage', self.project, "--fuzz-target",fuzzer_name, "--fuzz_driver_file", fuzz_driver_file,"--corpus-dir", f"{corpus_dir}", "--fuzzing_llm_dir", self.directory,"--no_serve"]
            coverage_result =  run(run_args)  
            logger.info(f"coverage {fuzz_driver_file}, result {coverage_result}")

            # 立即备份当前驱动的覆盖率报告（防止被后续运行覆盖）
            self.backup_coverage_report(fuzzer_name)

            logger.info("Computing current coverage...")
            # collect coverage reports
            html2txt(f"{self.coverage_dir}{fuzzer_name}{self.report_target_dir}",f"{self.report_dir}{fuzzer_name}/")  

            update_successful, current_line_coverage, total_lines, covered_lines, current_branch_coverage, total_branches, covered_branches, file_coverages = update_coverage_report(
                f"{self.report_dir}merge_report",
                f"{self.report_dir}{fuzzer_name}/"
            )
            
            if self.covered_lines==0 and self.covered_branches==0:
                self.covered_lines = covered_lines
                self.covered_branches = covered_branches
                logger.info(f"Current covered lines: {self.covered_lines}, Total lines: {total_lines}")
                logger.info(f"Current covered branches: {self.covered_branches}, Total branches: {total_branches}")
                  
                self.update_api_usage_count(api_combine)
                
                # 标记驱动完成并保存checkpoint
                self.completed_drivers.append(fuzz_driver_file)
                self.save_checkpoint(fuzz_driver_file, "completed")
                gc.collect()  # 释放内存

            else:
                if update_successful:
                    self.covered_lines = covered_lines
                    self.covered_branches = covered_branches
                    logger.info(f"Coverage updated. Current covered lines: {self.covered_lines}, Total lines: {total_lines}")
                    logger.info(f"Current covered branches: {self.covered_branches}, Total branches: {total_branches}")
                      
                    self.update_api_usage_count(api_combine)
                    
                    # 标记驱动完成并保存checkpoint
                    self.completed_drivers.append(fuzz_driver_file)
                    self.save_checkpoint(fuzz_driver_file, "completed")
                    gc.collect()  # 释放内存
                else:   
                    i=0
                    while not update_successful and i < self.max_itr_fuzz_loop:
                        if i == 0:
                            current_api_combine = api_combine
                        else:
                            current_api_combine = new_api_combine
                        logger.info(f"No new branches covered. Regenerating API combination. Iteration: {i+1}")
                        
                        low_coverage_apis = self.analyze_low_coverage_files(current_branch_coverage,file_coverages)
                        logger.info(f"Low coverage APIs: {low_coverage_apis}")
     
                        try:
                            new_api_combine = self.planner.generate_single_api_combination(api_name, current_api_combine, low_coverage_apis,)
                        except RuntimeError as e:
                            # 网络异常重试耗尽，放弃优化循环但保留已有 fuzzing 成果
                            logger.warning(f"API combination generation failed: {e}. "
                                           f"Keeping existing results for {fuzz_driver_file}.")
                            new_api_combine = current_api_combine
                            break
                        logger.info(f"New API Combination: {new_api_combine}")
                        
                        self.fuzz_gen.generate_single_fuzz_driver(new_api_combine, fuzz_driver_file, self.api_code, self.api_summary, self.fuzz_gen_code_output_dir)
                        compilation_success = self.compilation_fix_agent.single_fix_compilation(fuzz_driver_file, self.fuzz_gen_code_output_dir, self.project)
                        
                        if not compilation_success:
                            logger.info(f"Compilation check failed after max iterations, continue to fuzzing")
                            os.remove(f"{fix_fuzz_driver_dir}/{fuzz_driver_file}")
                            return
                    
                        self.input_gen.generate_input_fuzz_driver(f"{fix_fuzz_driver_dir}/{fuzz_driver_file}")

                        run_args = ["build_fuzzer_file",self.project, "--fuzz_driver_file", fuzz_driver_file]    
                        build_fuzzer_result =  run(run_args) 
                        logger.info(f"compile {fuzz_driver_file}, result {build_fuzzer_result}")

                        if "Compilation failed" in build_fuzzer_result or "Compilation succeeded" not in build_fuzzer_result:
                            logger.error(f"Failed to build fuzzer {fuzz_driver_file}. Skipping this iteration.")
                            i+=1
                            continue

                        run_args = ["run_fuzzer", self.project,"--timeout", self.time_budget, "--fuzz_driver_file", fuzz_driver_file, fuzzer_name,"--fuzzing_llm_dir", self.directory,"--corpus-dir",f"{corpus_dir}"]  
                        run_fuzzer_result =  run(run_args)  
                        logger.info(f"run_fuzzer {fuzz_driver_file}, result {run_fuzzer_result}")

                        if run_fuzzer_result is False:
                            logger.error(f"Failed to run fuzzer {fuzz_driver_file} in optimization loop. Fuzzer may not exist.")
                            i+=1
                            continue

                        if isinstance(run_fuzzer_result, str) and "ERROR" in run_fuzzer_result:
                            logger.info("Crash detected. Running enhanced analysis pipeline...")
                            error_index = run_fuzzer_result.index("ERROR")
                            crash_info = run_fuzzer_result[error_index:]
                            fuzz_driver_fullpath = f"{fix_fuzz_driver_dir}/{fuzz_driver_file}"
                            binary_path = _get_binary_path(self.project, fuzzer_name)

                            pipeline_result = run_enhanced_crash_pipeline(
                                crash_info,
                                fuzz_driver_fullpath,
                                current_api_combine,
                                self.crash_analyzer,
                                project_name=self.project,
                                fuzzer_name=fuzzer_name,
                                corpus_dir=corpus_dir,
                                fuzzing_llm_dir=self.directory,
                                binary_path=binary_path,
                                fuzz_project_dir=self.fuzz_project_dir,
                            )

                            is_api_bug = pipeline_result.get("is_api_bug", False)
                            crash_category = pipeline_result.get("crash_category", "Unknown")
                            crash_analysis = pipeline_result.get("analysis_text", "")

                            save_crash_analysis(
                                self.fuzz_project_dir,
                                fuzz_driver_file,
                                is_api_bug,
                                crash_category,
                                crash_analysis,
                                crash_info,
                                fuzz_driver_fullpath,
                                project_name=self.project,
                                fuzzer_name=fuzzer_name,
                                corpus_dir=corpus_dir,
                                fuzzing_llm_dir=self.directory,
                                pipeline_result=pipeline_result,
                            )
                      
                        # build fuzzer with coverage to collect the coverage reports
                        run_args=['build_fuzzers',self.project, "--sanitizer", "coverage", "--fuzzing_llm_dir", self.directory, "--fuzz_driver_file", fuzz_driver_file]
                        build_fuzzers_result =  run(run_args)  
                        logger.info(f"build coverage {self.project}, result {build_fuzzers_result}")  

                        run_args=['coverage',self.project, "--fuzz-target",fuzzer_name, "--fuzz_driver_file", fuzz_driver_file,"--corpus-dir", f"{corpus_dir}", "--fuzzing_llm_dir", self.directory,"--no_serve"]
                        coverage_result =  run(run_args)  
                        logger.info(f"coverage {fuzz_driver_file}, result {coverage_result}")


                        html2txt(f"{self.coverage_dir}{fuzzer_name}{self.report_target_dir}",f"{self.report_dir}{fuzzer_name}/")
                        update_successful, current_line_coverage, total_lines, covered_lines,current_branch_coverage, total_branches, covered_branches, file_coverages = update_coverage_report(
                            f"{self.report_dir}merge_report",
                            f"{self.report_dir}{fuzzer_name}/"
                            )
                        if update_successful:
                            self.covered_lines = covered_lines
                            self.covered_branches = covered_branches
                            logger.info(f"Coverage updated. Current covered lines: {self.covered_lines}, Total lines: {total_lines}")
                            logger.info(f"Current covered branches: {self.covered_branches}, Total branches: {total_branches}")
                              
                            self.planner.update_api_usage_count(new_api_combine)
                            
                            # Update api_combine with new_api_combine
                            self.api_combination[fuzzer_number-1] = new_api_combine
                            
                            # Save updated api_combine to JSON file
                            json_file_path = self.fuzz_project_dir+"agents_results/api_combine.json"
                            with open(json_file_path, 'w') as f:
                                json.dump(self.api_combination, f, indent=2)
                            
                            logger.info(f"Updated api_combine saved to {json_file_path}")
                            return
                    
                    # Update api_combine with new_api_combine even if max iterations reached
                    self.api_combination[fuzzer_number-1] = new_api_combine
                    
                    # Save updated api_combine to JSON file
                    json_file_path = self.fuzz_project_dir+"agents_results/api_combine.json"
                    with open(json_file_path, 'w') as f:
                        json.dump(self.api_combination, f, indent=2)
                    self.planner.update_api_usage_count(new_api_combine)
                    
                    logger.info(f"Updated api_combine saved to {json_file_path} after optimization loop ended")
                    logger.info(f"Coverage: covered lines={self.covered_lines}, total lines={total_lines}, "
                                f"covered branches={self.covered_branches}, total branches={total_branches}")

                    # 优化循环结束（达到最大迭代次数或网络异常 break），标记为 completed
                    self.completed_drivers.append(fuzz_driver_file)
                    self.save_checkpoint(fuzz_driver_file, "completed")
                    gc.collect()

    def build_and_fuzz(self, resume=True):
        fix_fuzz_driver_dir = os.path.join(self.directory, f"fuzz_driver/{self.project}/compilation_pass_rag/")
        if not os.path.exists(fix_fuzz_driver_dir):
            logger.info(f"No folder {fix_fuzz_driver_dir}")
            return 
        
        # 尝试从checkpoint恢复
        if resume and self.load_checkpoint():
            logger.info(f"Resuming from checkpoint. Skipping {len(self.completed_drivers)} completed drivers.")
        else:
            # 仅在全新运行时清除merge_report
            merge_report_path = f"{self.report_dir}merge_report"
            if os.path.exists(merge_report_path):
                logger.info(f"Removing existing merge_report directory: {merge_report_path}")
                shutil.rmtree(merge_report_path)
        
        # build_fuzzer_file
        all_drivers = os.listdir(fix_fuzz_driver_dir)
        logger.info(f"Total drivers: {len(all_drivers)}, Already completed: {len(self.completed_drivers)}, Already failed: {len(self.failed_builds)}")
        
        for fuzz_driver_file in all_drivers:
            # 跳过已完成或已失败的驱动
            if fuzz_driver_file in self.completed_drivers:
                logger.info(f"Skipping already completed driver: {fuzz_driver_file}")
                continue
            if fuzz_driver_file in self.failed_builds:
                logger.info(f"Skipping already failed driver: {fuzz_driver_file}")
                continue
                
            logger.info(f"Fuzz Driver File {fuzz_driver_file}")
            self.save_checkpoint(fuzz_driver_file, "in_progress")
            try:
                self.build_and_fuzz_one_file(fuzz_driver_file, fix_fuzz_driver_dir=fix_fuzz_driver_dir)
            except KeyboardInterrupt:
                logger.info(f"User interrupted (Ctrl+C). Saving checkpoint and exiting...")
                self.save_checkpoint(fuzz_driver_file, "interrupted")
                raise
            except Exception as e:
                logger.error(f"Unexpected error processing {fuzz_driver_file}: {type(e).__name__}: {e}")
                if fuzz_driver_file not in self.failed_builds:
                    self.failed_builds.append(fuzz_driver_file)
                self.save_checkpoint(fuzz_driver_file, "failed")
                continue
             
        #logger.info(f"Failed builds: {self.failed_builds}")
        # ← 添加这部分：检查成功数
        total_files = len(os.listdir(fix_fuzz_driver_dir))
        successful_builds = total_files - len(self.failed_builds)
    
        logger.info(f"Build Summary:")
        logger.info(f"  Total drivers: {total_files}")
        logger.info(f"  Successful: {successful_builds}")
        logger.info(f"  Failed: {len(self.failed_builds)}")
        logger.info(f"  Failed builds: {self.failed_builds}")
    
        # 关键检查：如果没有成功编译的驱动，直接退出
        if successful_builds == 0:
            logger.error(f"CRITICAL: No fuzzer was successfully built! All {total_files} drivers failed.")
            logger.error(f"Please check the compilation errors above.")
            logger.error(f"Failed drivers: {self.failed_builds}")
            self.save_checkpoint(status="failed")
            return  # 或者 sys.exit(1)
        
        # 保存最终checkpoint
        self.save_checkpoint(status="completed")
        logger.info(f"All fuzzing completed. Checkpoint saved.")
        