import os,sys

from sympy import Plane
# from configs.log import setup_logger
from loguru import logger
# Get the current working directory
current_work_dir = os.getcwd()
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
logger.info(f"Current workding dir: {current_work_dir}")
logger.info(f"Project Root and Append to the system path: {project_root}")
sys.path.append(project_root)
from llama_index.core import Settings
import shutil
import yaml
import subprocess
import shlex
from roles import input_gen_agent
from roles import planner
from roles import fuzz_generator
from roles import run_fuzzer
from roles import crash_analyzer
from roles import compilation_fix_agent
from models.get_model import get_model
from models.get_model import get_embedding_model
import json
from rag.query_engine_factory import build_test_query, build_cwe_query,build_kg_query
from rag.hybrid_retriever import CodeGraphRetriever


def is_docker_container_running(project_name):
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'name={project_name}_check', '--format', '{{.Names}}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if project_name+"_check" in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error checking Docker container status: {e}")
        return False
    
def extract_api_list(api_code_file):
    try:
        with open(api_code_file, 'r', encoding='utf-8') as f:
            src_api_code = json.load(f)
        
        api_list = list(src_api_code.keys())
        return api_list
    except Exception as e:
        logger.error(f"Error extracting API list from source code: {str(e)}")
        return []

def initialize_api_usage_count(api_list):
    api_usage_count = {api: 0 for api in api_list}
    return api_usage_count


def _filter_driver_names(
    driver_names: list[str],
    driver_filter: str | None,
) -> list[str]:
    """Filter crash-directory names by a dynamic driver filename."""
    if not driver_filter:
        return driver_names
    target = os.path.basename(driver_filter.strip())
    if target.endswith(".cc"):
        target = os.path.splitext(target)[0]
    return [name for name in driver_names if name == target]


import argparse
def args_parser():
    parser = argparse.ArgumentParser(description='Description of fuzzing settings')
    parser.add_argument('--yaml', type=str, default="")
    parser.add_argument("--gen_driver", action='store_true', default=True, help="Fuzz Driver Generation")
    parser.add_argument("--skip_gen_driver", dest='gen_driver', action='store_false', help="Skip Fuzz Driver Generation")
    parser.add_argument("--summary_api", action='store_true', default=True, help="Summary API")
    parser.add_argument("--skip_summary_api", dest="summary_api", action="store_false", help="Skip Summary API")
    parser.add_argument("--check_compilation", action='store_true', default=True, help="Check Compilation")
    parser.add_argument("--skip_check_compilation", dest='check_compilation',action='store_false', help='Skip Check Compilation')
    parser.add_argument("--gen_input", action='store_true', default=True, help="Generate Input")
    parser.add_argument("--skip_gen_input", dest='gen_input',action='store_false', help='Skip Generate Input')
    parser.add_argument("--coverage_timeout", type=str, default=None,
                        help="Maximum time for each driver's coverage collection, e.g. 10m")
    parser.add_argument("--driver-file", default=None,
                        help="Only process one fuzz driver. Accepts a .cc filename "
                             "or the crash-directory basename.")
    parser.add_argument("--reanalyze", action='store_true', default=False,
                        help="Re-analyze existing crashes without re-fuzzing. "
                             "Reads crash data from YAML, re-runs crash analysis pipeline "
                             "with current ABLATION_MODE / ABLATION_BASELINE settings.")
    parser.add_argument("--reanalyze_ablation", action='store_true', default=False,
                        help="Run REAL ablation study on existing crashes. "
                             "Saves paper variants V0/V1/V2/V3/V4. "
                             "This is the command for producing paper RQ5 data.")
    args = parser.parse_args()
    return args
        

def start_docker_for_check_compilation(project_dir, project_name):
    if is_docker_container_running(project_name):
        logger.info(f"Docker container '{project_name}_check' is already running. Continuing...")
        return True
    else:
        logger.info(f"Docker container '{project_name}_check' is not running. Starting...")
        try:
            docker_start_command = f"python  {project_dir}fuzzing_llm_engine/utils/check_gen_fuzzer.py start_docker_check_compilation {project_name} --fuzzing_llm_dir {project_dir}docker_shared/"
            subprocess.run(shlex.split(docker_start_command), check=True)
            logger.info("Docker for check compilation started successfully.")
            return True
        except subprocess.CalledProcessError as e:
            logger.info(f"Error starting Docker for check compilation: {e}")
            return False


def _resolve_binary_path_for_entry(project_name: str, fuzzer_name: str, entry: dict):
    """Prefer per-crash binary snapshot; fallback to current /build/out binary."""
    snap = (entry.get("binary_snapshot") or {}).get("snapshot_path")
    if snap and os.path.isfile(snap):
        return snap, "snapshot"

    legacy = entry.get("binary_path_for_repro")
    if legacy and os.path.isfile(legacy):
        return legacy, "snapshot_legacy"

    live = run_fuzzer._get_binary_path(project_name, fuzzer_name)
    if live and os.path.isfile(live):
        return live, "build_out"
    return None, "missing"


def reanalyze_existing_crashes(
    fuzz_projects_dir: str,
    project_name: str,
    crash_analyzer,
    api_combine_all: list,
    shared_dir: str,
    corpus_dir: str,
    fuzzing_llm_dir: str,
    driver_filter: str | None = None,
):
    """Re-analyze existing crashes without re-running fuzzing.

    Reads crash_analysis.yaml files, re-runs the crash analysis pipeline
    on each saved crash with current ABLATION_MODE / ABLATION_BASELINE settings.
    Useful for:
      - Running ablation experiments (V0-V4) on existing crash data
      - Collecting baseline LLM judgments (ABLATION_BASELINE=1)
      - Re-analyzing after code changes without expensive re-fuzzing
    """
    import re as _re
    crash_root = os.path.join(fuzz_projects_dir, "crash")
    if not os.path.isdir(crash_root):
        logger.error(f"[Reanalyze] No crash directory found: {crash_root}")
        return

    fix_fuzz_driver_dir = os.path.join(shared_dir, f"fuzz_driver/{project_name}/compilation_pass_rag/")
    ablation_mode = os.environ.get("ABLATION_MODE", "V4")
    run_baseline = os.environ.get("ABLATION_BASELINE", "") == "1"
    logger.info(f"[Reanalyze] Starting re-analysis: project={project_name}, "
                f"ablation_mode={ablation_mode}, run_baseline={run_baseline}")
    logger.info(f"[Reanalyze] Crash root: {crash_root}")

    driver_dirs = sorted(
        d for d in os.listdir(crash_root)
        if os.path.isdir(os.path.join(crash_root, d))
    )
    driver_dirs = _filter_driver_names(driver_dirs, driver_filter)
    if not driver_dirs:
        logger.error(f"[Reanalyze] No driver matched {driver_filter!r}")
        return
    total_reanalyzed = 0

    for dname in driver_dirs:
        yaml_path = os.path.join(crash_root, dname, "crash_analysis.yaml")
        if not os.path.isfile(yaml_path):
            continue

        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, list):
            continue

        # Find the fuzz driver source
        fuzz_driver_file = dname + ".cc"
        fuzz_driver_path = os.path.join(fix_fuzz_driver_dir, fuzz_driver_file)
        if not os.path.isfile(fuzz_driver_path):
            saved_drivers = [
                fn for fn in os.listdir(os.path.join(crash_root, dname))
                if fn.endswith(".cc")
            ]
            if saved_drivers:
                fuzz_driver_path = os.path.join(crash_root, dname, saved_drivers[0])
            else:
                logger.warning(f"[Reanalyze] No driver source found for {dname}, skipping")
                continue

        # Determine fuzzer_name and api_combine
        fuzzer_name = dname
        m = _re.search(r"_(\d+)$", dname)
        fuzzer_number = int(m.group(1)) if m else None
        if fuzzer_number and fuzzer_number <= len(api_combine_all):
            api_combine = api_combine_all[fuzzer_number - 1]
        else:
            api_combine = []

        logger.info(f"[Reanalyze] Processing {dname}: {len(data)} crash(es), "
                    f"driver={os.path.basename(fuzz_driver_path)}")

        for item in data:
            if not isinstance(item, dict):
                continue
            for cid, entry in item.items():
                if not isinstance(entry, dict):
                    continue

                crash_info_raw = entry.get("crash_info", "")
                if not crash_info_raw or not crash_info_raw.strip():
                    continue

                # Clean YAML literal markers
                crash_info = str(crash_info_raw)
                if crash_info.startswith("|"):
                    crash_info = crash_info[1:].lstrip("\n")

                binary_path, binary_source = _resolve_binary_path_for_entry(project_name, fuzzer_name, entry)
                driver_corpus = os.path.join(corpus_dir, f"{fuzzer_name}_corpus")

                logger.info(f"[Reanalyze] Re-analyzing {dname}/{cid}...")
                logger.info(f"[Reanalyze] Binary source={binary_source}, path={binary_path}")
                try:
                    pipeline_result = run_fuzzer.run_enhanced_crash_pipeline(
                        crash_info,
                        fuzz_driver_path,
                        api_combine,
                        crash_analyzer,
                        project_name=project_name,
                        fuzzer_name=fuzzer_name,
                        corpus_dir=driver_corpus if os.path.isdir(driver_corpus) else None,
                        fuzzing_llm_dir=fuzzing_llm_dir,
                        binary_path=binary_path,
                        fuzz_project_dir=fuzz_projects_dir,
                        run_baseline=run_baseline,
                        ablation_mode=ablation_mode,
                    )

                    # Update the entry with new analysis results
                    entry["is_api_bug"] = pipeline_result.get("is_api_bug", entry.get("is_api_bug"))
                    entry["crash_category"] = pipeline_result.get("crash_category", entry.get("crash_category"))
                    if pipeline_result.get("enhanced_result"):
                        entry["enhanced_analysis"] = pipeline_result["enhanced_result"]
                    if pipeline_result.get("triage"):
                        entry["triage"] = pipeline_result["triage"]
                    if pipeline_result.get("timings"):
                        entry["timings"] = pipeline_result["timings"]
                        entry["ablation_mode"] = pipeline_result["timings"].get("ablation_mode", ablation_mode)
                    if pipeline_result.get("dedup_info"):
                        entry["dedup"] = pipeline_result["dedup_info"]
                    if pipeline_result.get("runtime_context"):
                        entry["gdb_runtime_context"] = pipeline_result["runtime_context"]
                    if pipeline_result.get("repro"):
                        entry["repro"] = pipeline_result["repro"]
                    if pipeline_result.get("poc_paths"):
                        entry["poc_paths"] = pipeline_result["poc_paths"]
                    if pipeline_result.get("poc_locate"):
                        entry["poc_locate"] = pipeline_result["poc_locate"]
                    if pipeline_result.get("poc_copy"):
                        entry["poc_copy"] = pipeline_result["poc_copy"]
                    if pipeline_result.get("location"):
                        entry["location"] = {
                            "crash_file": pipeline_result["location"].get("crash_file"),
                            "crash_line": pipeline_result["location"].get("crash_line"),
                            "crash_function": pipeline_result["location"].get("crash_function"),
                        }
                    bl = pipeline_result.get("baseline", {})
                    if bl.get("enabled"):
                        entry["baseline_llm"] = {
                            "is_api_bug": bl.get("is_api_bug"),
                            "crash_category": bl.get("crash_category"),
                        }
                    if pipeline_result.get("report", {}).get("verdict"):
                        entry["verdict"] = pipeline_result["report"]["verdict"]

                    total_reanalyzed += 1
                except Exception as e:
                    logger.error(f"[Reanalyze] Failed on {dname}/{cid}: {e}")
                    import traceback; traceback.print_exc()

        # Save updated YAML
        with open(yaml_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        logger.info(f"[Reanalyze] Updated: {yaml_path}")

    logger.info(f"[Reanalyze] Done. Total crashes re-analyzed: {total_reanalyzed}")


def reanalyze_ablation_all_variants(
    fuzz_projects_dir: str,
    project_name: str,
    crash_analyzer,
    api_combine_all: list,
    shared_dir: str,
    corpus_dir: str,
    fuzzing_llm_dir: str,
    driver_filter: str | None = None,
):
    """Run the paper-aligned V0-V4 crash-attribution ablation.

    The determinant of each variant is fixed:
      V0: no filtering, no representatives, no context, clean direct prompt
      V1: filtering, no representatives, no context, clean direct prompt
      V2: filtering, representatives, no context, clean direct prompt
      V3: filtering, representatives, static+runtime context, clean direct prompt
      V4: filtering, representatives, static+runtime context, differential prompt

    V4 reuses the full CrashSage result already stored in crash_analysis.yaml.
    V2 reuses V1's LLM result for representatives because their evidence
    configurations are identical; it still records the representative as sent
    to the LLM for ablation accounting.
    """
    import hashlib as _hashlib
    import re as _re
    import time as _time
    import threading as _threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from crash.sanitizer_parser import parse_sanitizer_output
    from crash.triage import compute_signatures, triage_crash
    from crash.locator import locate_crash_site
    from crash.debugger import reproduce_with_gdb
    from crash.dedup import DeduplicationEngine

    crash_root = os.path.join(fuzz_projects_dir, "crash")
    if not os.path.isdir(crash_root):
        logger.error(f"[Ablation] No crash directory found: {crash_root}")
        return

    fix_fuzz_driver_dir = os.path.join(shared_dir, f"fuzz_driver/{project_name}/compilation_pass_rag/")

    CACHE_PROMPT_VERSION = "paper_v0_v4_clean_direct_2026_10"
    ABLATION_FLOW_VERSION = "paper_v0_v4_2026_10"

    def _first_present_attr(obj, names):
        for name in names:
            if isinstance(obj, dict) and obj.get(name) is not None:
                return obj.get(name)
            if hasattr(obj, name):
                value = getattr(obj, name)
                if value is not None:
                    return value
        return None

    llm_obj = getattr(crash_analyzer, "llm", None)
    llm_config = getattr(llm_obj, "llm_config", None)
    CACHE_MODEL_ID = str(
        _first_present_attr(llm_obj, ("model", "model_name"))
        or _first_present_attr(llm_config, ("model", "model_name"))
        or type(llm_obj).__name__
    )
    CACHE_TEMPERATURE = str(
        _first_present_attr(llm_obj, ("temperature",))
        or _first_present_attr(llm_config, ("temperature",))
        or "unknown"
    )
    cache_path = os.path.join(fuzz_projects_dir, "ablation_llm_cache.json")
    cache_lock = _threading.Lock()
    cache_dirty = False

    def _stable_json(obj):
        return json.dumps(obj, sort_keys=True, ensure_ascii=True, default=str)

    def _hash_text(text):
        return _hashlib.sha256(str(text).encode("utf-8", errors="replace")).hexdigest()

    def _load_cache():
        if not os.path.isfile(cache_path):
            return {}
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                logger.info(f"[Ablation] Loaded LLM cache: {cache_path} ({len(loaded)} entries)")
                return loaded
            logger.warning(f"[Ablation] Ignoring non-dict LLM cache: {cache_path}")
        except Exception as e:
            logger.warning(f"[Ablation] Failed to load LLM cache {cache_path}: {e}")
        return {}

    def _save_cache(cache):
        tmp_path = cache_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, sort_keys=True, indent=2)
        os.replace(tmp_path, cache_path)

    def _copy_llm_result(result):
        allowed_keys = (
            "crash_id",
            "is_api_bug",
            "crash_category",
            "sent_to_llm",
            "skip_reason",
            "llm_ms",
            "prompt_variant",
            "enhanced_result",
        )
        return {k: result[k] for k in allowed_keys if k in result}

    def _is_cacheable_llm_result(result):
        return (
            isinstance(result, dict)
            and result.get("sent_to_llm") is True
            and "error" not in result
            and "is_api_bug" in result
            and "crash_category" in result
        )

    def _has_cached_judgment(result):
        return (
            isinstance(result, dict)
            and "error" not in result
            and "is_api_bug" in result
        )

    def _make_cache_key(vname, crash_info, driver_source_hash, api_combine, inc_triage, inc_context, triage):
        payload = {
            "variant": vname,
            "crash_info_hash": _hash_text(crash_info),
            "driver_source_hash": driver_source_hash,
            "api_combine": api_combine,
            "include_triage": inc_triage,
            "include_context": inc_context,
            "triage_result": triage if inc_triage else None,
            "prompt_version": CACHE_PROMPT_VERSION,
            "model_id": CACHE_MODEL_ID,
            "temperature": CACHE_TEMPERATURE,
        }
        return _hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()

    llm_cache = _load_cache()

    logger.info(f"[Ablation] ═══ REAL ABLATION STUDY: project={project_name} ═══")
    logger.info(
        "[Ablation] Will save paper V0/V1/V2/V3/V4 with the paper-aligned flow"
    )

    def _driver_number(name):
        match = _re.search(r"_(\d+)$", name)
        return int(match.group(1)) if match else 10**9

    driver_dirs = sorted(
        (
            d for d in os.listdir(crash_root)
            if os.path.isdir(os.path.join(crash_root, d))
        ),
        key=_driver_number,
    )
    driver_dirs = _filter_driver_names(driver_dirs, driver_filter)
    if not driver_dirs:
        logger.error(f"[Ablation] No driver matched {driver_filter!r}")
        return

    records = []
    data_by_driver = {}
    for dname in driver_dirs:
        yaml_path = os.path.join(crash_root, dname, "crash_analysis.yaml")
        if not os.path.isfile(yaml_path):
            continue
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, list):
            continue
        data_by_driver[dname] = {"path": yaml_path, "data": data, "records": []}

        fuzz_driver_file = dname + ".cc"
        fuzz_driver_path = os.path.join(fix_fuzz_driver_dir, fuzz_driver_file)
        if not os.path.isfile(fuzz_driver_path):
            saved_drivers = [
                fn for fn in os.listdir(os.path.join(crash_root, dname))
                if fn.endswith(".cc")
            ]
            fuzz_driver_path = (
                os.path.join(crash_root, dname, saved_drivers[0])
                if saved_drivers else None
            )
        if fuzz_driver_path and os.path.isfile(fuzz_driver_path):
            with open(fuzz_driver_path, "rb") as f:
                driver_source_hash = _hashlib.sha256(f.read()).hexdigest()
        else:
            driver_source_hash = "missing-driver-source"

        fuzzer_number = _driver_number(dname)
        api_combine = (
            api_combine_all[fuzzer_number - 1]
            if fuzzer_number <= len(api_combine_all) else []
        )
        fuzz_driver_basename = (
            os.path.basename(fuzz_driver_path) if fuzz_driver_path else fuzz_driver_file
        )

        for item in data:
            if not isinstance(item, dict):
                continue
            for cid, entry in item.items():
                if not isinstance(entry, dict):
                    continue
                raw_crash = entry.get("crash_info", "")
                if not raw_crash or not str(raw_crash).strip():
                    continue
                crash_info = str(raw_crash)
                if crash_info.startswith("|"):
                    crash_info = crash_info[1:].lstrip("\n")

                parsed = entry.get("sanitizer_parsed")
                if not isinstance(parsed, dict):
                    parsed = parse_sanitizer_output(crash_info)
                saved_triage = entry.get("triage")
                triage = (
                    dict(saved_triage)
                    if isinstance(saved_triage, dict) and saved_triage.get("label")
                    else triage_crash(parsed, fuzz_driver_basename=fuzz_driver_basename)
                )
                exact_sig, exact_basis, stack_sig, fuzzy_sig = compute_signatures(parsed)
                triage.update(
                    {
                        "signature": exact_sig,
                        "signature_source": exact_basis,
                        "stack_signature": stack_sig,
                        "fuzzy_signature": fuzzy_sig,
                    }
                )
                triage_filtered = triage.get("label") in {
                    "noise", "likely_driver_bug",
                }
                location = entry.get("location")
                if not isinstance(location, dict) or not location.get("call_chain_context"):
                    location = locate_crash_site(
                        parsed,
                        driver_basename=fuzz_driver_basename,
                    )

                record = {
                    "project": project_name,
                    "driver": dname,
                    "driver_file": fuzz_driver_file,
                    "driver_path": fuzz_driver_path,
                    "driver_basename": fuzz_driver_basename,
                    "driver_source_hash": driver_source_hash,
                    "api_combine": api_combine,
                    "item": item,
                    "crash_key": cid,
                    "crash_id": f"{dname}_{cid}",
                    "entry": entry,
                    "crash_info": crash_info,
                    "parsed": parsed,
                    "triage": triage,
                    "triage_filtered": triage_filtered,
                    "location": location,
                    "dedup": None,
                    "representative_id": None,
                    "results": {},
                    "_runtime_lock": _threading.Lock(),
                    "_runtime_checked": False,
                    "_runtime_ctx": entry.get("gdb_runtime_context") or {},
                }
                records.append(record)
                data_by_driver[dname]["records"].append(record)

    # Representative selection happens before V2/V3 LLM analysis.
    dedup_engine = DeduplicationEngine()
    records_by_id = {record["crash_id"]: record for record in records}
    representative_ids = []
    duplicates = 0
    filtered = 0
    def _discovery_order_key(item):
        original_index, record = item
        timestamp = record["entry"].get("timestamp")
        text = str(timestamp or "").strip()
        if not text:
            return 2, 0.0, "", original_index
        try:
            parsed_timestamp = datetime.fromisoformat(
                text.replace("Z", "+00:00")
            ).timestamp()
            return 0, parsed_timestamp, text, original_index
        except (TypeError, ValueError):
            return 1, 0.0, text, original_index

    indexed_records = list(enumerate(records))
    indexed_records.sort(
        key=_discovery_order_key
    )
    for discovery_index, (_, record) in enumerate(indexed_records):
        if record["triage_filtered"]:
            filtered += 1
            continue
        info = dedup_engine.add_crash(
            record["crash_id"],
            record["triage"],
            record["parsed"],
            timestamp=record["entry"].get("timestamp"),
            discovery_index=discovery_index,
        )
        record["dedup"] = info
        representative = info.get("duplicate_of") or record["crash_id"]
        record["representative_id"] = representative
        if info.get("is_duplicate"):
            duplicates += 1
        else:
            representative_ids.append(record["crash_id"])
    representatives = [records_by_id[cid] for cid in representative_ids]

    def _make_cache_key(
        vname, record, include_triage, include_static, include_runtime, prompt_variant
    ):
        payload = {
            "variant": vname,
            "crash_id": record["crash_id"],
            "crash_info_hash": _hash_text(record["crash_info"]),
            "driver_source_hash": record["driver_source_hash"],
            "api_combine": record["api_combine"],
            "include_triage": include_triage,
            "include_static_context": include_static,
            "include_runtime_context": include_runtime,
            "prompt_variant": prompt_variant,
            "triage_result": record["triage"] if include_triage else None,
            "prompt_version": CACHE_PROMPT_VERSION,
            "model_id": CACHE_MODEL_ID,
            "temperature": CACHE_TEMPERATURE,
        }
        return _hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()

    def _prepare_runtime(record):
        with record["_runtime_lock"]:
            if record["_runtime_checked"]:
                return record["_runtime_ctx"]
            record["_runtime_checked"] = True
            ctx = record["_runtime_ctx"]
            if isinstance(ctx, dict) and ctx.get("reproduced"):
                return ctx
            poc = (record["entry"].get("poc_paths") or {}).get("poc")
            if record["driver_path"] and poc:
                binary_path, _ = _resolve_binary_path_for_entry(
                    project_name, record["driver"], record["entry"]
                )
                if binary_path and os.path.isfile(binary_path) and os.path.isfile(poc):
                    try:
                        record["_runtime_ctx"] = reproduce_with_gdb(
                            binary_path, poc, timeout=15
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[Ablation] GDB failed for {record['crash_id']}: {exc}"
                        )
            return record["_runtime_ctx"] or {}

    def _run_llm(
        vname, record, include_triage, include_static, include_runtime,
        prompt_variant,
    ):
        nonlocal cache_dirty, actual_llm_calls, cache_hits, errors
        if include_triage and record["triage_filtered"]:
            return {
                "is_api_bug": False,
                "crash_category": record["parsed"].get("bug_type", "Unknown"),
                "sent_to_llm": False,
                "skip_reason": f"triage:{record['triage'].get('label')}",
            }
        if not record["driver_path"] or not os.path.isfile(record["driver_path"]):
            errors += 1
            return {
                "is_api_bug": None,
                "crash_category": record["parsed"].get("bug_type", "Unknown"),
                "sent_to_llm": False,
                "skip_reason": "driver_source_missing",
                "error": "driver source missing",
            }

        cache_key = _make_cache_key(
            vname, record, include_triage, include_static, include_runtime,
            prompt_variant,
        )
        with cache_lock:
            cached = llm_cache.get(cache_key)
        if _is_cacheable_llm_result(cached):
            cache_hits += 1
            result = _copy_llm_result(cached)
            result["cache_hit"] = True
            return result

        runtime_ctx = _prepare_runtime(record) if include_runtime else None
        started = _time.monotonic()
        try:
            is_api_bug, category, _text, enhanced = (
                crash_analyzer.analyze_crash_enhanced(
                    record["crash_info"],
                    record["driver_path"],
                    record["api_combine"],
                    triage_result=record["triage"] if include_triage else None,
                    location_result=record["location"] if include_static else None,
                    runtime_context=runtime_ctx if include_runtime else None,
                    include_triage=include_triage,
                    include_static_context=include_static,
                    include_runtime_context=include_runtime,
                    prompt_variant=prompt_variant,
                )
            )
            elapsed = round((_time.monotonic() - started) * 1000, 1)
            result = {
                "is_api_bug": is_api_bug,
                "crash_category": category,
                "sent_to_llm": True,
                "skip_reason": "none",
                "llm_ms": elapsed,
                "prompt_variant": prompt_variant,
                "enhanced_result": enhanced,
            }
            actual_llm_calls += 1
            with cache_lock:
                llm_cache[cache_key] = _copy_llm_result(result)
                cache_dirty = True
            logger.info(
                f"[Ablation] {record['crash_id']} {vname}: "
                f"is_api_bug={is_api_bug} ({elapsed}ms)"
            )
            return result
        except Exception as exc:
            errors += 1
            logger.error(f"[Ablation] {record['crash_id']} {vname}: {exc}")
            return {
                "is_api_bug": None,
                "crash_category": record["parsed"].get("bug_type", "Unknown"),
                "sent_to_llm": True,
                "skip_reason": "none",
                "prompt_variant": prompt_variant,
                "error": str(exc),
            }

    def _existing_v4(record):
        entry = record["entry"]
        existing = entry.get("ablation_results")
        source = None
        if isinstance(existing, dict):
            source = existing.get("V4")
            # Compatibility migration: the old controller called paper V4 "V3".
            if not _has_cached_judgment(source):
                source = existing.get("V3")
        if _has_cached_judgment(source):
            result = _copy_llm_result(source)
            result["reused_existing"] = True
            result["prompt_variant"] = "differential"
            return result
        timings = entry.get("timings") or {}
        skip_reason = timings.get("llm_skip_reason")
        sent = not bool(timings.get("llm_skipped")) and skip_reason in (None, "none")
        return {
            "is_api_bug": entry.get("is_api_bug"),
            "crash_category": entry.get(
                "crash_category", record["parsed"].get("bug_type", "Unknown")
            ),
            "sent_to_llm": sent,
            "skip_reason": skip_reason or ("skipped" if not sent else "none"),
            "prompt_variant": "differential",
            "reused_existing": True,
            "enhanced_result": entry.get("enhanced_analysis"),
        }

    actual_llm_calls = 0
    cache_hits = 0
    errors = 0
    tasks = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for record in records:
            tasks.append((
                record, "V0",
                executor.submit(
                    _run_llm, "V0", record, False, False, False, "direct_v1"
                ),
            ))
        for record in records:
            if not record["triage_filtered"]:
                tasks.append((
                    record, "V1",
                    executor.submit(
                        _run_llm, "V1", record, True, False, False, "direct_v1"
                    ),
                ))
        for record in representatives:
            tasks.append((
                record, "V3",
                executor.submit(
                    _run_llm, "V3", record, True, True, True, "direct_v1"
                ),
            ))
        for record, vname, future in tasks:
            record["results"][vname] = future.result()

    # V2 has the same evidence as V1 but only representatives are analyzed.
    for record in records:
        if record["triage_filtered"]:
            triage_skip = {
                "is_api_bug": False,
                "crash_category": record["parsed"].get("bug_type", "Unknown"),
                "sent_to_llm": False,
                "skip_reason": f"triage:{record['triage'].get('label')}",
            }
            for vname in ("V1", "V2", "V3"):
                record["results"][vname] = dict(triage_skip)
        elif record["dedup"] and record["dedup"].get("is_duplicate"):
            representative = records_by_id[record["representative_id"]]
            for vname in ("V2", "V3"):
                inherited = dict(representative["results"].get(vname) or {})
                inherited["sent_to_llm"] = False
                inherited["skip_reason"] = "duplicate"
                inherited["duplicate_of"] = record["representative_id"]
                record["results"][vname] = inherited
        else:
            v1_result = record["results"].get("V1", {})
            record["results"]["V2"] = {
                **dict(v1_result),
                "sent_to_llm": bool(v1_result.get("is_api_bug") is not None),
                "skip_reason": v1_result.get("skip_reason", "none"),
                "reused_from": "V1",
                "prompt_variant": "direct_v1",
            }

    # V4 is the already-produced full CrashSage result, inherited by duplicates.
    for record in representatives:
        record["results"]["V4"] = _existing_v4(record)
    for record in records:
        if record["triage_filtered"]:
            record["results"]["V4"] = {
                "is_api_bug": False,
                "crash_category": record["entry"].get(
                    "crash_category", record["parsed"].get("bug_type", "Unknown")
                ),
                "sent_to_llm": False,
                "skip_reason": f"triage:{record['triage'].get('label')}",
                "prompt_variant": "differential",
                "reused_existing": True,
            }
        elif record["dedup"] and record["dedup"].get("is_duplicate"):
            representative = records_by_id[record["representative_id"]]
            inherited = dict(representative["results"].get("V4") or {})
            inherited["sent_to_llm"] = False
            inherited["skip_reason"] = "duplicate"
            inherited["duplicate_of"] = record["representative_id"]
            record["results"]["V4"] = inherited

    total_crashes = len(records)
    for driver, driver_data in data_by_driver.items():
        for record in driver_data["records"]:
            entry = record["entry"]
            entry["triage"] = record["triage"]
            if record["dedup"] is not None:
                entry["dedup"] = record["dedup"]
            if record["location"].get("crash_file"):
                entry["location"] = {
                    "crash_file": record["location"].get("crash_file"),
                    "crash_line": record["location"].get("crash_line"),
                    "crash_function": record["location"].get("crash_function"),
                    "call_chain_context": record["location"].get("call_chain_context"),
                }
            entry["ablation_results"] = {
                vname: record["results"].get(vname, {})
                for vname in ("V0", "V1", "V2", "V3", "V4")
            }
            entry["ablation_flow_version"] = ABLATION_FLOW_VERSION
        with open(driver_data["path"], "w") as f:
            yaml.dump(
                driver_data["data"], f, default_flow_style=False,
                sort_keys=False, allow_unicode=True,
            )
        logger.info(f"[Ablation] Saved: {driver_data['path']}")

    if cache_dirty:
        with cache_lock:
            _save_cache(llm_cache)
        logger.info(f"[Ablation] Saved LLM cache: {cache_path}")

    sent_by_variant = {
        vname: sum(
            1 for record in records
            if (record["results"].get(vname) or {}).get("sent_to_llm")
        )
        for vname in ("V0", "V1", "V2", "V3", "V4")
    }
    logger.info(f"[Ablation] ═══ DONE ═══")
    logger.info(
        f"[Ablation] Crashes={total_crashes}, filtered={filtered}, "
        f"representatives={len(representatives)}, duplicates={duplicates}"
    )
    logger.info(f"[Ablation] LLM submissions by variant: {sent_by_variant}")
    logger.info(
        f"[Ablation] Actual new LLM calls={actual_llm_calls}, "
        f"cache hits={cache_hits}, errors={errors}"
    )


if __name__ == '__main__':

    args = args_parser()

    if args.yaml is not None and os.path.isfile(args.yaml):
        with open(os.path.join(args.yaml), 'r') as file:
             config = yaml.safe_load(file)

    project_config = config['config']
    project_name = project_config['project_name']
    program_language = project_config['program_language']
    fuzz_projects_dir = project_config['fuzz_projects_dir']
    work_dir = project_config['work_dir']
    shared_dir = project_config['shared_dir']
    time_budget = project_config['time_budget']
    report_target_dir = project_config['report_target_dir']
    
    api_summary_file = os.path.join(fuzz_projects_dir, "api_summary/api_with_summary.json")
    api_code_file = os.path.join(fuzz_projects_dir, "src/src_api_code.json")
    api_call_graph_file = os.path.join(fuzz_projects_dir, "api_combine/combined_call_graph.csv")
    agents_result_dir = os.path.join(fuzz_projects_dir, "agents_results")
    fuzz_dir=os.path.join(work_dir, "fuzzing_llm_engine/")

    # parameters for construting graph knowledge
    chromadb_dir = os.path.join(fuzz_projects_dir, "chromadb/")
    call_graph_csv = api_call_graph_file
    all_src_api_file = os.path.join(fuzz_projects_dir, "codebase/api/src_api.json")
    kg_saved_folder = fuzz_projects_dir
    exclude_folder_list=[]


    headers= project_config['headers'] 
    

    logger.info(f"Init LLM Models, config {config}")
    # code model for generation and fix
    assert "llm_coder" in config or "llm_analyzer" in config, "your config file has to contain at least the llm_coder config or llm_analyzer config"
    llm_coder = get_model(config["llm_coder"] if "llm_coder" in config else config["llm_analyzer"])
    # code model for combination，summary
    llm_analyzer = get_model(config["llm_analyzer"] if "llm_analyzer" in config else config["llm_coder"] )
    
    assert "llm_embedding" in config or "llm_code_embedding" in config, "your config file has to contain at least the llm_embedding config or llm_code_embedding config"
    # common text embedding model
    llm_embedding= get_embedding_model(config["llm_embedding"]  if "llm_embedding" in config else config["llm_code_embedding"] ) 
    # code embedding model
    llm_embedding_coding = get_embedding_model(config["llm_code_embedding"] if "llm_code_embedding" in config else config["llm_embedding"])

    # set default LLM settings
    Settings.llm = get_model(None)
    Settings.embed_model = get_embedding_model(None, device='cpu')
    logger.info(f"Init Default LLM Model and Embedding Model, LLM config: { Settings.llm.metadata } \n Embed config: {Settings.embed_model}")

        
    logger.info(f"Init API Combine Query and Test Query Engine")

    test_case_index = build_test_query(fuzz_projects_dir, llm=llm_analyzer, embed_model=llm_embedding)
    cwe_index = build_cwe_query(fuzz_dir, llm=llm_analyzer, embed_model=llm_embedding)

    query_tools = {}
    query_tools["test_case_index"] = test_case_index
    query_tools["cwe_index"] = cwe_index

    api_list = extract_api_list(api_code_file)
    api_usage_count = initialize_api_usage_count(api_list)

    logger.info("Init FuzzingPlanner")
    plan_agent = planner.FuzzingPlanner(
        llm = llm_analyzer,
        llm_embedding = llm_embedding,
        project_name = project_name,
        api_info_file = api_summary_file,
        api_code_file = api_code_file,
        api_call_graph_file = api_call_graph_file,
        query_tools = query_tools,
        api_usage_count = api_usage_count
    )


    if args.summary_api:
        logger.info("Generate API Summary")
        plan_agent.summarize_code()
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        api_list = plan_agent.extract_api_list()
    else:
        logger.info("Skip Generate API Summary")
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        api_list = plan_agent.extract_api_list()

    src_api_code = json.load(open(api_code_file))
    api_summary = json.load(open(api_summary_file))

    logger.info(f"Init KG Model")
    #index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary, summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base
    pg_all_code_index, pg_api_summary_index, pg_api_code_index, pg_file_summary_index, summary_text_vector_index, all_src_code_vector_index,api_src_vector_index, code_base = \
                        build_kg_query(chromadb_dir, \
                        call_graph_csv, all_src_api_file, api_summary_file,\
                        project_name, kg_saved_folder, \
                        initGraphKG = True, exclude_folder_list=exclude_folder_list,  llm=llm_analyzer, embed_model=llm_embedding)
    pg_index_all_code_retriever = pg_all_code_index.as_retriever(similarity_top_k=3)
    pg_index_api_summary_retriever = pg_api_summary_index.as_retriever(similarity_top_k=3)
    pg_index_api_code_retriever = pg_api_code_index.as_retriever(similarity_top_k=3)
    pg_index_file_summary_retriever = pg_file_summary_index.as_retriever(similarity_top_k=3)

    code_graph_retriever = CodeGraphRetriever(pg_index_all_code_retriever, pg_index_api_summary_retriever, pg_index_api_code_retriever, pg_index_file_summary_retriever, mode="HYBRID")
    
    plan_agent.set_code_graph_retriever(code_graph_retriever)

    logger.info("Init FuzzingGenerationAgent")
    gen_agent = fuzz_generator.FuzzingGenerationAgent(
        llm_coder = llm_coder,
        llm_analyzer = llm_analyzer,
        llm_embedding = llm_embedding,
        database_dir = fuzz_projects_dir,
        headers = headers,
        query_tools = query_tools,
        language = program_language
    )
    
    logger.info(f"Init CompilationFixAgent")
    test_case_index_dir = os.path.join(fuzz_projects_dir, "test_case_index/")
    fix_agent = compilation_fix_agent.CompilationFixAgent(
        llm_coder=llm_coder, 
        llm_analyzer=llm_analyzer, 
        llm_embedding=llm_embedding, 
        query_tools=query_tools, 
        max_fix_itrs=5
        )

    logger.info(f"Init InputGenerationAgent")
    input_dir = os.path.join(work_dir, f"docker_shared/fuzz_driver/{project_name}/syntax_pass_rag/" )
    output_dir = os.path.join(work_dir, f"fuzzing_llm_engine/build/work/{project_name}/" ) 
    input_agent = input_gen_agent.InputGenerationAgent(
        input_dir = input_dir,
        output_dir = output_dir,
        llm = llm_analyzer, 
        llm_embedding=llm_embedding,
        api_src=src_api_code
        )
    
    logger.info(f"Init CrashAnalyzer")
    crash_analyze_agent = crash_analyzer.CrashAnalyzer(
        llm = llm_analyzer,
        llm_embedding=llm_embedding,
        query_tools=query_tools,
        api_src=src_api_code,
        use_memory=False
    )
    
    
    logger.info(f"Then generation agents starts combining API")

    os.makedirs(agents_result_dir, exist_ok=True)

    if args.gen_driver:
        api_combine_file = os.path.join(agents_result_dir, "api_combine.json")
        if os.path.exists(api_combine_file):
            logger.info("Loading existing API combination from api_combine.json")
            with open(api_combine_file, 'r') as f:
                api_combine = json.load(f)
            
        else:
            logger.info("Generating new API combination")
            api_combine = plan_agent.api_combination(api_list)
            with open(api_combine_file, 'w') as f:
                json.dump(api_combine, f)

        logger.info("The generation agents starts generating fuzzing driver")
        fuzz_gen_code_output_dir = os.path.join(fuzz_projects_dir, "fuzz_driver")
        os.makedirs(fuzz_gen_code_output_dir, exist_ok=True)
        gen_agent.use_memory = False
        gen_agent.driver_gen(api_combine, src_api_code, api_summary, fuzz_gen_code_output_dir,project_name)
    else:
        logger.info("Skip Generating Fuzz Driver")
        api_combine = json.load(open(os.path.join(agents_result_dir, "api_combine.json")))

    input_agent.set_api_combination(api_combine)

    os.makedirs(os.path.dirname(work_dir+f"docker_shared/fuzz_driver/{project_name}/"), exist_ok=True)
    try:
        shutil.copytree(fuzz_projects_dir+"/fuzz_driver", work_dir+f"docker_shared/fuzz_driver/{project_name}/", dirs_exist_ok=True)
        logger.info(f"Copied fuzz drivers successfully.")
    except Exception as e:
        logger.error(f"Error copying fuzz drivers: {e}")
        exit()


    if not start_docker_for_check_compilation(work_dir, project_name):
        logger.info("Failed to start docker for check compilation")
        exit()
    
    if args.check_compilation:
        logger.info("Check Compilation")
        fix_agent.check_compilation(shared_dir, project_name, file_suffix=["c","cc"])
    else:
        logger.info("Skip Check Compilation")

    
    if args.gen_input:
        logger.info("Generate Input")
        for root, dirs, files in os.walk(os.path.join(shared_dir, f"fuzz_driver/{project_name}/compilation_pass_rag/")):
            logger.info(files)
            for file in files:
                input_agent.generate_input_fuzz_driver(os.path.join(shared_dir+f"fuzz_driver/{project_name}/compilation_pass_rag/",file))
    else:
        logger.info("Skip Generate Input")  


    corpus_dir=os.path.join(work_dir, f"fuzzing_llm_engine/build/work/{project_name}/" )    
    coverage_dir = os.path.join(work_dir, f"fuzzing_llm_engine/build/out/{project_name}/report_target/")
    report_dir = os.path.join(fuzz_projects_dir, "coverage_report/")

    fuzzer= run_fuzzer.Fuzzer(
        directory=shared_dir, 
        project=project_name, 
        fuzz_project_dir=fuzz_projects_dir,
        corpus_dir=corpus_dir, 
        coverage_dir=coverage_dir,
        report_dir=report_dir,
        planner=plan_agent,
        compilation_fix_agent=fix_agent,
        fuzz_gen=gen_agent,
        input_gen_agent=input_agent,
        crash_analyzer=crash_analyze_agent,
        api_usage_count=api_usage_count,
        time_budget=time_budget,
        coverage_timeout=args.coverage_timeout,
        report_target_dir=report_target_dir
        )
    
    fuzzer.set_api_combination(api_combine)
    fuzzer.set_api_code(src_api_code)
    fuzzer.set_api_summary(api_summary)
    fuzzer.set_fuzz_gen_code_output_dir(os.path.join(work_dir, f"docker_shared/fuzz_driver/{project_name}/"))
    fuzzer.set_driver_filter(args.driver_file)

    if args.reanalyze_ablation:
        reanalyze_ablation_all_variants(
            fuzz_projects_dir=fuzz_projects_dir,
            project_name=project_name,
            crash_analyzer=crash_analyze_agent,
            api_combine_all=api_combine,
            shared_dir=shared_dir,
            corpus_dir=corpus_dir,
            fuzzing_llm_dir=shared_dir,
            driver_filter=args.driver_file,
        )
    elif args.reanalyze:
        reanalyze_existing_crashes(
            fuzz_projects_dir=fuzz_projects_dir,
            project_name=project_name,
            crash_analyzer=crash_analyze_agent,
            api_combine_all=api_combine,
            shared_dir=shared_dir,
            corpus_dir=corpus_dir,
            fuzzing_llm_dir=shared_dir,
            driver_filter=args.driver_file,
        )
    else:
        fuzzer.build_and_fuzz()




    
    
        
