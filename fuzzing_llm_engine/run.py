import os
import re
import csv
import hashlib
import json
import traceback
import yaml
import time
from pathlib import Path

from crash.run_variant_config import (
    experiment_fingerprint,
    get_variant_config,
    validate_run_prompt_variant,
)

DB_ROOT = Path("external_database")
RUN_VARIANT = os.environ.get("RUN_VARIANT", "V3").strip().upper()
VARIANT_CONFIG = get_variant_config(RUN_VARIANT)
BASELINE_MANIFEST = Path("results/all_crashes_v0_v4_groundtruth.csv")
REPRESENTATIVE_MANIFEST = Path(
    "results/dedup_schema2_14projects_20261027/"
    "representatives_all_14projects.csv"
)
DEFAULT_MANIFEST = (
    BASELINE_MANIFEST
    if RUN_VARIANT in {"V0", "V1"}
    else REPRESENTATIVE_MANIFEST
)
MANIFEST = Path(os.environ.get("MANIFEST", str(DEFAULT_MANIFEST)))
CUSTOM_MANIFEST = "MANIFEST" in os.environ
INPUT_FILES = (
    MANIFEST,
    BASELINE_MANIFEST,
    REPRESENTATIVE_MANIFEST,
    Path("results/dedup_schema2_14projects_20261027/dedup_mapping_14projects.csv"),
)
PROMPT_VARIANT = os.environ.get(
    "PROMPT_VARIANT",
    VARIANT_CONFIG.prompt_variant,
).strip().lower()
INCLUDE_TRIAGE = VARIANT_CONFIG.use_triage
INCLUDE_STATIC_CONTEXT = VARIANT_CONFIG.include_static_context
INCLUDE_RUNTIME_CONTEXT = VARIANT_CONFIG.include_runtime_context
INCLUDE_RECONSTRUCTION_CONTEXT = VARIANT_CONFIG.include_reconstruction_context
EVIDENCE_VARIANT = VARIANT_CONFIG.evidence_variant
DEFAULT_OUT_DIR = f"results/revision_20260725/llm_{RUN_VARIANT.lower()}_{EVIDENCE_VARIANT}_{PROMPT_VARIANT}"
OUT_DIR = Path(os.environ.get("OUT_DIR", DEFAULT_OUT_DIR))
OUT_CSV = OUT_DIR / "llm_bool_results.csv"
OUT_JSONL = OUT_DIR / "llm_bool_results.jsonl"
PROJECT_FILTER = os.environ.get("PROJECT_FILTER", "").strip()
CRASH_ID_FILTER = os.environ.get("CRASH_ID_FILTER", "").strip()
PRIOR_RESULTS = [
    Path(path)
    for path in os.environ.get("PRIOR_RESULTS", "").split(os.pathsep)
    if path.strip()
]
FAST_MODE = os.environ.get(
    f"{RUN_VARIANT}_FAST",
    "0",
).strip().lower() not in {"0", "false", "no"}
RERUN_GDB = os.environ.get(f"{RUN_VARIANT}_RERUN_GDB", "0").strip().lower() in {"1", "true", "yes"}
ANALYZER_TEMPERATURE = float(os.environ.get(f"{RUN_VARIANT}_TEMPERATURE", "0"))
CAPTURE_ARTIFACTS = os.environ.get(f"{RUN_VARIANT}_CAPTURE_ARTIFACTS", "1").strip().lower() not in {"0", "false", "no"}


EXPERIMENT_FINGERPRINT = experiment_fingerprint()


def input_fingerprint() -> str:
    digest = hashlib.sha256()
    # V0/V1 and V2-V4 use different default manifests. Hash the canonical set
    # of unique input files so all variants receive the same fingerprint.
    for path in sorted(set(INPUT_FILES), key=lambda item: str(item)):
        if not path.is_file():
            raise RuntimeError(f"required experiment input is missing: {path}")
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


INPUT_FINGERPRINT = input_fingerprint()

validate_run_prompt_variant(RUN_VARIANT, PROMPT_VARIANT)
if ANALYZER_TEMPERATURE != 0:
    raise RuntimeError("paper ablation requires temperature=0")
if FAST_MODE:
    raise RuntimeError("fast mode changes the CKGFuzzer baseline and is disabled")
if RUN_VARIANT in {"V0", "V1"}:
    raise RuntimeError(
        f"{RUN_VARIANT} predictions are frozen in "
        "results/frozen_baseline_1217; do not rerun this variant"
    )
if RUN_VARIANT == "V2":
    raise RuntimeError(
        "V2 is derived from the V1 result by "
        "crash.assemble_final_1217_metrics; do not run it as an independent LLM variant"
    )
if RUN_VARIANT in {"V3", "V4"} and not PRIOR_RESULTS:
    raise RuntimeError(
        f"{RUN_VARIANT} requires PRIOR_RESULTS pointing to the frozen "
        f"{'V1' if RUN_VARIANT == 'V3' else 'V3'} predictions"
    )

from llama_index.core import Settings
from models.get_model import get_model, get_embedding_model
from roles.crash_analyzer import CrashAnalyzer
from crash.sanitizer_parser import parse_sanitizer_output
from crash.triage import historical_runtime_context_is_compatible, triage_crash
from crash.locator import locate_crash_site
from crash.debugger import collect_runtime_context, gdb_runtime_image
from crash.context_sources import filter_api_names, find_driver_source
from crash.context_validation import (
    runtime_context_matches_parsed,
    runtime_context_summary,
    static_context_is_complete,
    static_context_summary,
)
from crash.pipeline_gate import replay_consistency_passed

OUT_DIR.mkdir(parents=True, exist_ok=True)

def truth(v):
    return str(v).strip().lower() in {"true", "1", "yes"}

def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_prior_predictions(paths):
    predictions = {}
    for path in paths:
        for row in read_csv(path):
            result = row.get("Result", row.get("Prediction", ""))
            if result:
                predictions[(row["Project"], row["CrashID"])] = truth(result)
    return predictions


def load_yaml_entry(project, driver, crash_id):
    yaml_path = DB_ROOT / project / "crash" / driver / "crash_analysis.yaml"
    cache_key = (project, driver)
    if cache_key not in yaml_cache:
        with yaml_path.open("r", encoding="utf-8") as f:
            yaml_cache[cache_key] = yaml.safe_load(f)
    data = yaml_cache[cache_key]
    short_id = crash_id.replace(driver + "_", "", 1)
    for item in data:
        if isinstance(item, dict) and short_id in item:
            return item[short_id]
    raise RuntimeError(f"Missing crash entry: {project}/{driver}/{short_id}")

def load_project_config(project):
    path = DB_ROOT / project / "config.yaml"
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def configured_model(project):
    config = load_project_config(project)
    analyzer_config = config.get("llm_analyzer") or {}
    return str(
        os.environ.get("LLM_MODEL_OVERRIDE", "").strip()
        or analyzer_config.get("model", "")
    )

def load_api_combine(project, driver, driver_path=None, crash_functions=()):
    p = DB_ROOT / project / "agents_results" / "api_combine.json"
    if not p.exists():
        return []
    api_all = json.load(open(p, "r", encoding="utf-8"))
    m = re.search(r"_(\d+)$", driver)
    n = int(m.group(1)) if m else None
    selected = api_all[n - 1] if n and n <= len(api_all) else []
    if driver_path and Path(driver_path).is_file():
        api_src = load_api_src(project)
        candidates = [*selected, *api_src.keys()]
        return filter_api_names(
            Path(driver_path).read_text(encoding="utf-8", errors="replace"),
            candidates,
            required_apis=crash_functions,
        )
    return selected

def load_api_src(project):
    p1 = DB_ROOT / project / "src" / "src_api_code.json"
    p2 = DB_ROOT / project / "api_combine" / "src_api_code.json"
    p = p1 if p1.exists() else p2
    return json.load(open(p, "r", encoding="utf-8"))

def find_driver_path(project, driver, entry=None):
    path = find_driver_source(DB_ROOT, project, driver, entry)
    if path:
        return path
    raise RuntimeError(f"Missing fuzz driver source: {project}/{driver}")

def resolve_binary(project, driver, entry):
    snap = (entry.get("binary_snapshot") or {}).get("snapshot_path")
    if snap:
        p = Path(snap)
        if not p.is_absolute():
            p = Path(__file__).resolve().parent / p
        if p.exists():
            return str(p)
    legacy = entry.get("binary_path_for_repro")
    if legacy and not Path(legacy).is_absolute():
        legacy = str(Path(__file__).resolve().parent / legacy)
    if legacy and Path(legacy).exists():
        return legacy
    live = Path(__file__).resolve().parent / "build" / "out" / project / driver
    if live.exists():
        return str(live)
    return None

def get_runtime_context(project, driver, entry):
    ctx = entry.get("gdb_runtime_context") or {}
    parsed = entry.get("sanitizer_parsed") or {}
    driver_basename = entry.get("fuzz_driver_file") or f"{driver}.cc"
    matched, match_reason = runtime_context_matches_parsed(
        ctx,
        parsed,
        driver_basename,
    )
    replay_ok = replay_consistency_passed(entry.get("repro"))
    legacy_context = bool(ctx) and "stable" not in ctx
    if matched and (
        ctx.get("stable") is True
        or replay_ok
        or (
            legacy_context
            and historical_runtime_context_is_compatible(
                ctx,
                parsed,
                driver_basename,
            )
        )
    ):
        return ctx
    if not RERUN_GDB:
        return {
            "reproduced": False,
            "error_message": (
                "stored runtime context unavailable or incompatible: "
                f"{match_reason}; set {RUN_VARIANT}_RERUN_GDB=1 to recollect"
            ),
            "collection_method": "stored",
            "validation_reason": match_reason,
        }
    binary = resolve_binary(project, driver, entry)
    poc = (entry.get("poc_paths") or {}).get("poc")
    if poc and not Path(poc).is_absolute():
        poc = str(Path(__file__).resolve().parent / poc)
    if binary and poc and Path(poc).exists():
        try:
            # Host replay is only supporting evidence. The OSS-Fuzz runtime
            # may have different libraries from the host, so Docker/GDB must
            # still be attempted and validate the reconstructed crash against
            # the retained sanitizer report.
            return collect_runtime_context(
                binary,
                poc,
                attempts=3,
                timeout=15,
                prefer_docker=True,
                expected_crash=parsed,
                driver_basename=driver_basename,
                docker_image=gdb_runtime_image(project),
            )
        except Exception as exc:
            return {
                "reproduced": False,
                "error_message": f"runtime recollection failed: {exc}",
                "collection_method": "error",
            }
    return {
        "reproduced": False,
        "error_message": "runtime recollection skipped: binary or PoC missing",
        "collection_method": "not_attempted",
    }


def save_analysis_artifact(
    project,
    crash_id,
    driver,
    analysis_text,
    enhanced,
    context_evidence=None,
):
    """Persist the exact evidence and decision used by one experimental run."""
    if not CAPTURE_ARTIFACTS:
        return
    metadata = (enhanced or {}).get("_experiment_metadata") or {}
    artifact_dir = OUT_DIR / "analysis_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", crash_id)
    decision = {key: value for key, value in (enhanced or {}).items() if key != "_experiment_metadata"}
    artifact = {
        "project": project,
        "crash_id": crash_id,
        "driver": driver,
        "prompt": metadata.get("prompt", ""),
        "prompt_sha256": metadata.get("prompt_sha256", ""),
        "raw_model_response": analysis_text,
        "structured_decision": decision,
        "context_evidence": context_evidence or {},
        "decision_parse_mode": metadata.get("decision_parse_mode", ""),
        "decision_parse_error": metadata.get("decision_parse_error", ""),
        "experiment_metadata": {
            key: value for key, value in metadata.items() if key != "prompt"
        },
    }
    with (artifact_dir / f"{safe_name}.json").open("w", encoding="utf-8") as f:
        json.dump(artifact, f, ensure_ascii=False, indent=2)

def row_has_matching_artifact(row):
    if row.get("Status") != "ok":
        return False
    expected_fields = {
        "EvidenceVariant": EVIDENCE_VARIANT,
        "PromptVariant": PROMPT_VARIANT,
        "RunVariant": RUN_VARIANT,
        "AnalysisEngine": VARIANT_CONFIG.analysis_engine,
        "InputFingerprint": INPUT_FINGERPRINT,
    }
    if any(row.get(key) != value for key, value in expected_fields.items()):
        return False
    try:
        if row.get("LLMModel") != configured_model(row["Project"]):
            return False
    except Exception:
        return False

    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", row["CrashID"])
    artifact_path = OUT_DIR / "analysis_artifacts" / f"{safe_name}.json"
    if not artifact_path.is_file():
        return False
    try:
        metadata = (
            json.loads(artifact_path.read_text(encoding="utf-8")).get(
                "experiment_metadata"
            )
            or {}
        )
    except (OSError, json.JSONDecodeError):
        return False
    return (
        metadata.get("run_variant") == RUN_VARIANT
        and metadata.get("analysis_engine") == VARIANT_CONFIG.analysis_engine
        and metadata.get("prompt_variant") == PROMPT_VARIANT
        and metadata.get("experiment_fingerprint") == EXPERIMENT_FINGERPRINT
        and metadata.get("input_fingerprint") == INPUT_FINGERPRINT
    )


done = set()
if OUT_CSV.exists():
    for r in read_csv(OUT_CSV):
        if row_has_matching_artifact(r):
            done.add((r["Project"], r["CrashID"]))

rows = read_csv(MANIFEST)
if not CUSTOM_MANIFEST:
    if RUN_VARIANT == "V1":
        rows = [
            row
            for row in rows
            if row.get("TriageLabel") not in {"noise", "likely_driver_bug"}
        ]
for row in rows:
    if not row.get("Driver") and row.get("CrashID"):
        row["Driver"] = re.sub(r"_crash_\d+$", "", row["CrashID"])
if PROJECT_FILTER:
    rows = [r for r in rows if r.get("Project") == PROJECT_FILTER]
if CRASH_ID_FILTER:
    crash_id_filters = {item.strip() for item in CRASH_ID_FILTER.split(",") if item.strip()}
    rows = [r for r in rows if r.get("CrashID") in crash_id_filters]
if (PROJECT_FILTER or CRASH_ID_FILTER) and not rows:
    raise RuntimeError(
        f"No manifest rows matched PROJECT_FILTER={PROJECT_FILTER!r} "
        f"CRASH_ID_FILTER={CRASH_ID_FILTER!r}"
    )

prior_predictions = load_prior_predictions(PRIOR_RESULTS)

fieldnames = [
    "Project", "CrashID", "Driver", "LLMName", "LLMModel", "Result", "Reason",
    "Status", "LatencyMs", "PromptChars", "PromptSHA256", "EvidenceVariant",
    "PromptVariant", "RunVariant", "AnalysisEngine", "ExperimentFingerprint",
    "InputFingerprint",
]

write_header = not OUT_CSV.exists()
if OUT_CSV.exists():
    with OUT_CSV.open("r", encoding="utf-8-sig", newline="") as existing_file:
        existing_fields = next(csv.reader(existing_file), [])
    if existing_fields != fieldnames:
        raise RuntimeError(
            f"{OUT_CSV} uses an obsolete result schema; choose a fresh OUT_DIR"
        )
csv_f = OUT_CSV.open("a", encoding="utf-8", newline="")
writer = csv.DictWriter(csv_f, fieldnames=fieldnames)
if write_header:
    writer.writeheader()

analyzers = {}
analyzer_models = {}
yaml_cache = {}

def patch_fast_analyzer(analyzer):
    if not FAST_MODE:
        return analyzer
    analyzer.extract_potential_error_patterns = lambda code: []
    analyzer.query_cwe_vulnerabilities = lambda crash_info: "[CWE] Skipped in fast prompt-ablation rerun."
    return analyzer

def analyze_for_current_variant(analyzer, *args, **kwargs):
    return analyzer.analyze_crash_enhanced(*args, **kwargs)

for i, row in enumerate(rows, 1):
    project = row["Project"]
    crash_id = row["CrashID"]
    driver = row["Driver"]

    if (project, crash_id) in done:
        print(f"[{i}/{len(rows)}] skip ok {crash_id}")
        continue

    print(f"[{i}/{len(rows)}] run {project} {crash_id}")

    current_model = analyzer_models.get(project, "")
    try:
        if project not in analyzers:
            config = load_project_config(project)
            analyzer_config = dict(config["llm_analyzer"])
            analyzer_config["temperature"] = ANALYZER_TEMPERATURE
            model_override = os.environ.get("LLM_MODEL_OVERRIDE", "").strip()
            if model_override:
                analyzer_config["model"] = model_override
            current_model = str(analyzer_config.get("model", ""))
            llm = get_model(analyzer_config)
            emb = get_embedding_model(config.get("llm_embedding"), device="cpu")
            Settings.llm = llm
            Settings.embed_model = emb

            from rag.query_engine_factory import build_cwe_query
            cwe_index = build_cwe_query(str(Path.cwd()), llm=llm, embed_model=emb)

            analyzers[project] = CrashAnalyzer(
                llm=llm,
                llm_embedding=emb,
                query_tools={"cwe_index": cwe_index},
                api_src=load_api_src(project),
                use_memory=False,
            )
            patch_fast_analyzer(analyzers[project])
            analyzer_models[project] = current_model
        else:
            current_model = analyzer_models.get(project, "")

        entry = load_yaml_entry(project, driver, crash_id)
        crash_info = str(entry.get("crash_info") or "")
        if crash_info.startswith("|"):
            crash_info = crash_info[1:].lstrip("\n")
        driver_basename = entry.get("fuzz_driver_file") or f"{driver}.cc"

        # Sanitizer parsing is also needed to filter the target API evidence
        # for V0, which does not otherwise enable triage or context.
        parsed = entry.get("sanitizer_parsed") or parse_sanitizer_output(crash_info)
        triage = None
        if INCLUDE_TRIAGE:
            triage = entry.get("triage") or triage_crash(
                parsed,
                fuzz_driver_basename=driver_basename,
            )
        if INCLUDE_STATIC_CONTEXT:
            stored_location = entry.get("location") or {}
            location = (
                stored_location
                if static_context_is_complete(stored_location)
                else locate_crash_site(
                    parsed,
                    driver_basename=driver_basename,
                )
            )
        else:
            location = None
        runtime_ctx = get_runtime_context(project, driver, entry) if INCLUDE_RUNTIME_CONTEXT else {}
        runtime_status = runtime_context_summary(
            runtime_ctx,
            parsed if INCLUDE_RUNTIME_CONTEXT else None,
            entry.get("fuzz_driver_file") or f"{driver}.cc",
        )
        static_status = static_context_summary(location)
        fuzz_driver_path = find_driver_path(project, driver, entry)
        crash_functions = [parsed.get("first_in_project_function") or ""]
        crash_functions.extend(
            frame.get("func") or ""
            for frame in (parsed.get("frames") or [])
        )
        api_combine = load_api_combine(
            project,
            driver,
            fuzz_driver_path,
            crash_functions=crash_functions,
        )

        t0 = time.time()
        if VARIANT_CONFIG.analysis_engine == "ckgfuzzer":
            is_api_bug, category, analysis_text, enhanced = (
                analyzers[project].analyze_crash_ckgfuzzer(
                    crash_info,
                    fuzz_driver_path,
                    api_combine,
                    capture_prompt=CAPTURE_ARTIFACTS,
                )
            )
        else:
            is_api_bug, category, analysis_text, enhanced = analyze_for_current_variant(
                analyzers[project],
                crash_info,
                fuzz_driver_path,
                api_combine,
                triage_result=triage,
                location_result=location,
                runtime_context=runtime_ctx,
                include_triage=INCLUDE_TRIAGE,
                include_static_context=INCLUDE_STATIC_CONTEXT,
                include_runtime_context=INCLUDE_RUNTIME_CONTEXT,
                include_reconstruction_context=INCLUDE_RECONSTRUCTION_CONTEXT,
                prompt_variant=PROMPT_VARIANT,
                capture_prompt=CAPTURE_ARTIFACTS,
                run_decision_repairs=False,
                prior_prediction=prior_predictions.get((project, crash_id)),
            )
        experiment_metadata = (enhanced or {}).get("_experiment_metadata")
        if experiment_metadata is not None:
            experiment_metadata.update({
                "runner_temperature": ANALYZER_TEMPERATURE,
                "fast_mode": FAST_MODE,
                "rerun_gdb": RERUN_GDB,
                "run_variant": RUN_VARIANT,
                "analysis_engine": VARIANT_CONFIG.analysis_engine,
                "experiment_fingerprint": EXPERIMENT_FINGERPRINT,
                "input_fingerprint": INPUT_FINGERPRINT,
                "include_triage": INCLUDE_TRIAGE,
                "include_static_context": INCLUDE_STATIC_CONTEXT,
                "include_runtime_context": INCLUDE_RUNTIME_CONTEXT,
                "include_reconstruction_context": INCLUDE_RECONSTRUCTION_CONTEXT,
                "static_context_status": static_status,
                "runtime_context_status": runtime_status,
                "prior_results": [str(path) for path in PRIOR_RESULTS],
            })
        save_analysis_artifact(
            project,
            crash_id,
            driver,
            analysis_text,
            enhanced,
            context_evidence={
                "static": location if INCLUDE_STATIC_CONTEXT else None,
                "runtime": runtime_ctx if INCLUDE_RUNTIME_CONTEXT else None,
                "static_status": static_status,
                "runtime_status": runtime_status,
            },
        )
        latency_ms = int((time.time() - t0) * 1000)
        prompt_chars = ((enhanced or {}).get("_experiment_metadata") or {}).get("prompt_chars", "")

        out = {
            "Project": project,
            "CrashID": crash_id,
            "Driver": driver,
            "LLMName": "enhanced-crash-analyzer",
            "LLMModel": current_model,
            "Result": str(bool(is_api_bug)).lower(),
            "Reason": str(category),
            "Status": "ok",
            "LatencyMs": latency_ms,
            "PromptChars": prompt_chars,
            "PromptSHA256": ((enhanced or {}).get("_experiment_metadata") or {}).get(
                "prompt_sha256", ""
            ),
            "EvidenceVariant": EVIDENCE_VARIANT,
            "PromptVariant": PROMPT_VARIANT,
            "RunVariant": RUN_VARIANT,
            "AnalysisEngine": VARIANT_CONFIG.analysis_engine,
            "ExperimentFingerprint": EXPERIMENT_FINGERPRINT,
            "InputFingerprint": INPUT_FINGERPRINT,
        }

    except Exception as e:
        traceback.print_exc()
        out = {
            "Project": project,
            "CrashID": crash_id,
            "Driver": driver,
            "LLMName": "enhanced-crash-analyzer",
            "LLMModel": current_model,
            "Result": "",
            "Reason": str(e),
            "Status": "error",
            "LatencyMs": "",
            "PromptChars": "",
            "PromptSHA256": "",
            "EvidenceVariant": EVIDENCE_VARIANT,
            "PromptVariant": PROMPT_VARIANT,
            "RunVariant": RUN_VARIANT,
            "AnalysisEngine": VARIANT_CONFIG.analysis_engine,
            "ExperimentFingerprint": EXPERIMENT_FINGERPRINT,
            "InputFingerprint": INPUT_FINGERPRINT,
        }

    writer.writerow(out)
    csv_f.flush()

    with OUT_JSONL.open("a", encoding="utf-8") as jf:
        jf.write(json.dumps(out, ensure_ascii=False) + "\n")

csv_f.close()
print(f"done: {OUT_CSV}")
