import os
import re
import csv
import json
import yaml
import time
from pathlib import Path

from crash.run_variant_config import validate_run_prompt_variant

DEFAULT_MANIFEST = Path("results/revision_20260722/representatives_v1.csv")
MANIFEST = Path(os.environ.get("MANIFEST", str(DEFAULT_MANIFEST)))
CUSTOM_MANIFEST = "MANIFEST" in os.environ
DB_ROOT = Path("external_database")
RUN_VARIANT = os.environ.get("RUN_VARIANT", "V3").strip().upper()
PROMPT_VARIANT = os.environ.get(
    "PROMPT_VARIANT",
    "direct_v1" if RUN_VARIANT in {"V0", "V4"} else "differential",
).strip().lower()
INCLUDE_TRIAGE = RUN_VARIANT != "V0"
INCLUDE_STATIC_CONTEXT = RUN_VARIANT in {"V3", "V4"}
INCLUDE_RUNTIME_CONTEXT = RUN_VARIANT in {"V3", "V4"}
STRICT_NO_CONTEXT_ABLATION = RUN_VARIANT == "V1" and os.environ.get(
    "STRICT_NO_CONTEXT_ABLATION",
    "1",
).strip().lower() in {"1", "true", "yes"}
EVIDENCE_VARIANT = {
    "V0": "raw_no_context",
    "V1": "triage_no_context",
    "V2": "triage_dedup_no_context",
    "V3": "full",
    "V4": "full",
}[RUN_VARIANT]
DEFAULT_OUT_DIR = f"results/revision_20260725/llm_{RUN_VARIANT.lower()}_{EVIDENCE_VARIANT}_{PROMPT_VARIANT}"
OUT_DIR = Path(os.environ.get("OUT_DIR", DEFAULT_OUT_DIR))
OUT_CSV = OUT_DIR / "llm_bool_results.csv"
OUT_JSONL = OUT_DIR / "llm_bool_results.jsonl"
PROJECT_FILTER = os.environ.get("PROJECT_FILTER", "").strip()
CRASH_ID_FILTER = os.environ.get("CRASH_ID_FILTER", "").strip()
FAST_MODE = os.environ.get(
    f"{RUN_VARIANT}_FAST",
    "0",
).strip().lower() not in {"0", "false", "no"}
RERUN_GDB = os.environ.get(f"{RUN_VARIANT}_RERUN_GDB", "0").strip().lower() in {"1", "true", "yes"}
ANALYZER_TEMPERATURE = float(os.environ.get(f"{RUN_VARIANT}_TEMPERATURE", "0"))
CAPTURE_ARTIFACTS = os.environ.get(f"{RUN_VARIANT}_CAPTURE_ARTIFACTS", "1").strip().lower() not in {"0", "false", "no"}

validate_run_prompt_variant(RUN_VARIANT, PROMPT_VARIANT)

from llama_index.core import Settings
from models.get_model import get_model, get_embedding_model
import roles.crash_analyzer as crash_analyzer_module
from roles.crash_analyzer import CrashAnalyzer
from crash.sanitizer_parser import parse_sanitizer_output
from crash.triage import triage_crash
from crash.locator import locate_crash_site
from crash.debugger import reproduce_with_gdb

OUT_DIR.mkdir(parents=True, exist_ok=True)

def truth(v):
    return str(v).strip().lower() in {"true", "1", "yes"}

def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

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

def load_api_combine(project, driver):
    p = DB_ROOT / project / "agents_results" / "api_combine.json"
    if not p.exists():
        return []
    api_all = json.load(open(p, "r", encoding="utf-8"))
    m = re.search(r"_(\d+)$", driver)
    n = int(m.group(1)) if m else None
    if n and n <= len(api_all):
        return api_all[n - 1]
    return []

def load_api_src(project):
    p1 = DB_ROOT / project / "src" / "src_api_code.json"
    p2 = DB_ROOT / project / "api_combine" / "src_api_code.json"
    p = p1 if p1.exists() else p2
    return json.load(open(p, "r", encoding="utf-8"))

def find_driver_path(project, driver):
    candidates = [
        DB_ROOT / project / "fuzz_driver" / f"{driver}.cc",
        DB_ROOT / project / "crash" / driver / f"{driver}.cc",
        Path("/home/cc/CKGFuzzer-1/docker_shared/fuzz_driver") / project / "compilation_pass_rag" / f"{driver}.cc",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    raise RuntimeError(f"Missing fuzz driver source: {project}/{driver}")

def resolve_binary(project, driver, entry):
    snap = (entry.get("binary_snapshot") or {}).get("snapshot_path")
    if snap:
        p = Path(snap)
        if not p.is_absolute():
            p = Path.cwd() / p
        if p.exists():
            return str(p)
    legacy = entry.get("binary_path_for_repro")
    if legacy and Path(legacy).exists():
        return legacy
    live = Path("build/out") / project / driver
    if live.exists():
        return str(live)
    return None

def get_runtime_context(project, driver, entry):
    ctx = entry.get("gdb_runtime_context")
    if ctx and ctx.get("reproduced"):
        return ctx
    if not RERUN_GDB:
        return ctx or {}
    binary = resolve_binary(project, driver, entry)
    poc = (entry.get("poc_paths") or {}).get("poc")
    if binary and poc and Path(poc).exists():
        try:
            return reproduce_with_gdb(binary, poc, timeout=15)
        except Exception:
            return ctx or {}
    return ctx or {}


def save_analysis_artifact(project, crash_id, driver, analysis_text, enhanced):
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
        "decision_parse_mode": metadata.get("decision_parse_mode", ""),
        "decision_parse_error": metadata.get("decision_parse_error", ""),
        "experiment_metadata": {
            key: value for key, value in metadata.items() if key != "prompt"
        },
    }
    with (artifact_dir / f"{safe_name}.json").open("w", encoding="utf-8") as f:
        json.dump(artifact, f, ensure_ascii=False, indent=2)

done = set()
if OUT_CSV.exists():
    for r in read_csv(OUT_CSV):
        if r.get("Status") == "ok":
            done.add((r["Project"], r["CrashID"]))

rows = read_csv(MANIFEST)
if not CUSTOM_MANIFEST:
    sent_to_llm_field = "V2_SentToLLM" if RUN_VARIANT in {"V2", "V3", "V4"} else f"{RUN_VARIANT}_SentToLLM"
    rows = [r for r in rows if truth(r.get(sent_to_llm_field))]
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

fieldnames = [
    "Project", "CrashID", "Driver", "LLMName", "LLMModel", "Result", "Reason",
    "Status", "LatencyMs", "PromptChars", "EvidenceVariant", "PromptVariant"
]

write_header = not OUT_CSV.exists()
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
    if not STRICT_NO_CONTEXT_ABLATION:
        return analyzer.analyze_crash_enhanced(*args, **kwargs)

    saved_extract_patterns = analyzer.extract_potential_error_patterns
    saved_helpers = {
        "_extract_driver_oracle_context": crash_analyzer_module._extract_driver_oracle_context,
        "_extract_precondition_risk_context": crash_analyzer_module._extract_precondition_risk_context,
        "_extract_decisive_evidence_context": crash_analyzer_module._extract_decisive_evidence_context,
    }
    try:
        analyzer.extract_potential_error_patterns = lambda code: []
        crash_analyzer_module._extract_driver_oracle_context = (
            lambda *a, **k: "[ORACLE] Disabled by strict V1 no-context ablation."
        )
        crash_analyzer_module._extract_precondition_risk_context = (
            lambda *a, **k: "[PRECONDITION] Disabled by strict V1 no-context ablation."
        )
        crash_analyzer_module._extract_decisive_evidence_context = (
            lambda *a, **k: "[DECISIVE-EVIDENCE] Disabled by strict V1 no-context ablation."
        )
        return analyzer.analyze_crash_enhanced(*args, **kwargs)
    finally:
        analyzer.extract_potential_error_patterns = saved_extract_patterns
        for name, func in saved_helpers.items():
            setattr(crash_analyzer_module, name, func)

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

        parsed = None
        triage = None
        if INCLUDE_TRIAGE or INCLUDE_STATIC_CONTEXT:
            parsed = entry.get("sanitizer_parsed") or parse_sanitizer_output(crash_info)
        if INCLUDE_TRIAGE:
            triage = entry.get("triage") or triage_crash(parsed, fuzz_driver_basename=f"{driver}.cc")
        location = (
            entry.get("location") or locate_crash_site(parsed, driver_basename=f"{driver}.cc")
            if INCLUDE_STATIC_CONTEXT
            else None
        )
        runtime_ctx = get_runtime_context(project, driver, entry) if INCLUDE_RUNTIME_CONTEXT else {}
        fuzz_driver_path = find_driver_path(project, driver)
        api_combine = load_api_combine(project, driver)

        t0 = time.time()
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
            prompt_variant=PROMPT_VARIANT,
            capture_prompt=CAPTURE_ARTIFACTS,
        )
        experiment_metadata = (enhanced or {}).get("_experiment_metadata")
        if experiment_metadata is not None:
            experiment_metadata.update({
                "runner_temperature": ANALYZER_TEMPERATURE,
                "fast_mode": FAST_MODE,
                "rerun_gdb": RERUN_GDB,
                "run_variant": RUN_VARIANT,
                "include_triage": INCLUDE_TRIAGE,
                "include_static_context": INCLUDE_STATIC_CONTEXT,
                "include_runtime_context": INCLUDE_RUNTIME_CONTEXT,
                "strict_no_context_ablation": STRICT_NO_CONTEXT_ABLATION,
            })
        save_analysis_artifact(project, crash_id, driver, analysis_text, enhanced)
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
            "EvidenceVariant": EVIDENCE_VARIANT,
            "PromptVariant": PROMPT_VARIANT,
        }

    except Exception as e:
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
            "EvidenceVariant": EVIDENCE_VARIANT,
            "PromptVariant": PROMPT_VARIANT,
        }

    writer.writerow(out)
    csv_f.flush()

    with OUT_JSONL.open("a", encoding="utf-8") as jf:
        jf.write(json.dumps(out, ensure_ascii=False) + "\n")

csv_f.close()
print(f"done: {OUT_CSV}")
