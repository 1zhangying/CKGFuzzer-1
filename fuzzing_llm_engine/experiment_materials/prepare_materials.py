#!/usr/bin/env python3
"""Prepare CKGFuzzer + CrashSage experiment materials.

This script intentionally does not run fuzzing, run_fuzzer, coverage, or any
experiment execution entrypoint. It only organizes files, archives superseded
material, creates manifests, and verifies the prepared layout.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
TODAY = "2026-06-26"
MATERIALS = ROOT / "fuzzing_llm_engine" / "experiment_materials"
ARCHIVES = MATERIALS / "archives"
MANIFESTS = MATERIALS / "manifests"
CLEANUP_RESIDUALS: list[dict[str, str]] = []


@dataclass(frozen=True)
class KnownVuln:
    project: str
    cve: str
    apis: list[str]
    src_driver: Path
    src_poc: Path
    dst_driver_name: str

    @property
    def fuzzer_name(self) -> str:
        return self.dst_driver_name.rsplit(".", 1)[0]

    @property
    def index(self) -> int:
        return int(self.fuzzer_name.rsplit("_", 1)[-1])


KNOWN = {
    "c-ares": KnownVuln(
        project="c-ares",
        cve="CVE-2024-25629",
        apis=["ares_init", "ares_gethostbyname"],
        src_driver=ROOT / "crashsage" / "drivers" / "c-ares" / "CVE-2024-25629" / "driver.cc",
        src_poc=ROOT / "crashsage" / "pocs" / "c-ares" / "CVE-2024-25629" / "poc",
        dst_driver_name="c-ares_fuzz_driver_False_qwen3-coder-plus_26.cc",
    ),
    "cjson": KnownVuln(
        project="cjson",
        cve="CVE-2025-57052",
        apis=["cJSON_ParseWithLength", "cJSONUtils_GetPointer"],
        src_driver=ROOT / "crashsage" / "drivers" / "cjson" / "CVE-2025-57052" / "driver.cc",
        src_poc=ROOT / "crashsage" / "pocs" / "cjson" / "CVE-2025-57052" / "poc",
        dst_driver_name="cjson_fuzz_driver_False_qwen3-coder-plus_60.cc",
    ),
    "libpcap": KnownVuln(
        project="libpcap",
        cve="CVE-2024-8006",
        apis=["pcap_findalldevs_ex"],
        src_driver=ROOT / "crashsage" / "drivers" / "libpcap" / "CVE-2024-8006" / "driver.cc",
        src_poc=ROOT / "crashsage" / "pocs" / "libpcap" / "CVE-2024-8006" / "poc",
        dst_driver_name="libpcap_fuzz_driver_False_qwen3-coder-plus_30.cc",
    ),
    "zlib": KnownVuln(
        project="zlib",
        cve="CVE-2023-45853",
        apis=["zipOpenNewFileInZip4_64"],
        src_driver=ROOT / "crashsage" / "drivers" / "zlib" / "CVE-2023-45853" / "driver.cc",
        src_poc=ROOT / "crashsage" / "pocs" / "zlib" / "CVE-2023-45853" / "poc",
        dst_driver_name="zlib_fuzz_driver_False_qwen3-coder-plus_20.cc",
    ),
}


EXISTING_CRASH_DRIVERS = {
    "c-ares": [
        "c-ares_fuzz_driver_False_qwen3-coder-plus_2",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_9",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_12",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_13",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_16",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_17",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_18",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_23",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_24",
        "c-ares_fuzz_driver_False_qwen3-coder-plus_25",
    ],
    "cjson": [
        "cjson_fuzz_driver_False_qwen3-coder-plus_2",
        "cjson_fuzz_driver_False_qwen3-coder-plus_4",
        "cjson_fuzz_driver_False_qwen3-coder-plus_6",
        "cjson_fuzz_driver_False_qwen3-coder-plus_7",
        "cjson_fuzz_driver_False_qwen3-coder-plus_9",
        "cjson_fuzz_driver_False_qwen3-coder-plus_12",
        "cjson_fuzz_driver_False_qwen3-coder-plus_14",
        "cjson_fuzz_driver_False_qwen3-coder-plus_18",
        "cjson_fuzz_driver_False_qwen3-coder-plus_22",
        "cjson_fuzz_driver_False_qwen3-coder-plus_23",
        "cjson_fuzz_driver_False_qwen3-coder-plus_25",
        "cjson_fuzz_driver_False_qwen3-coder-plus_28",
        "cjson_fuzz_driver_False_qwen3-coder-plus_29",
        "cjson_fuzz_driver_False_qwen3-coder-plus_30",
        "cjson_fuzz_driver_False_qwen3-coder-plus_32",
        "cjson_fuzz_driver_False_qwen3-coder-plus_33",
        "cjson_fuzz_driver_False_qwen3-coder-plus_36",
        "cjson_fuzz_driver_False_qwen3-coder-plus_42",
        "cjson_fuzz_driver_False_qwen3-coder-plus_49",
    ],
    "libpcap": [
        "libpcap_fuzz_driver_False_qwen3-coder-plus_8",
        "libpcap_fuzz_driver_False_qwen3-coder-plus_9",
        "libpcap_fuzz_driver_False_qwen3-coder-plus_15",
        "libpcap_fuzz_driver_False_qwen3-coder-plus_18",
        "libpcap_fuzz_driver_False_qwen3-coder-plus_27",
        "libpcap_fuzz_driver_False_qwen3-coder-plus_29",
    ],
    "zlib": [
        "zlib_fuzz_driver_False_qwen3-coder-plus_3",
        "zlib_fuzz_driver_False_qwen3-coder-plus_4",
        "zlib_fuzz_driver_False_qwen3-coder-plus_7",
        "zlib_fuzz_driver_False_qwen3-coder-plus_10",
        "zlib_fuzz_driver_False_qwen3-coder-plus_12",
        "zlib_fuzz_driver_False_qwen3-coder-plus_17",
        "zlib_fuzz_driver_False_qwen3-coder-plus_22",
    ],
}


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def ensure_dirs() -> None:
    MATERIALS.mkdir(parents=True, exist_ok=True)
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    MANIFESTS.mkdir(parents=True, exist_ok=True)


def archive_paths(archive_name: str, paths: Iterable[Path]) -> Path | None:
    archive = ARCHIVES / archive_name
    if archive.exists():
        with tarfile.open(archive, "r:gz") as tf:
            names = tf.getnames()
            if not names:
                raise RuntimeError(f"Existing archive verification failed: {archive} is empty")
        return archive

    existing = []
    seen = set()
    for path in paths:
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        existing.append(path)
    if not existing:
        return None

    with tarfile.open(archive, "w:gz") as tf:
        for path in existing:
            tf.add(path, arcname=rel(path))

    with tarfile.open(archive, "r:gz") as tf:
        names = tf.getnames()
        if not names:
            raise RuntimeError(f"Archive verification failed: {archive} is empty")
    return archive


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    except PermissionError as exc:
        CLEANUP_RESIDUALS.append({
            "path": rel(path),
            "reason": f"permission_denied:{exc}",
        })


def list_known_sanity_paths() -> list[Path]:
    external = ROOT / "fuzzing_llm_engine" / "external_database"
    return sorted(p for p in external.glob("*/crash/known_cve_sanity_*"))


def project_api_names(project: str) -> set[str]:
    candidates = [
        ROOT / "fuzzing_llm_engine" / "external_database" / project / "api_list.json",
        ROOT / "code" / project / "api_list.json",
    ]
    if project == "cjson":
        candidates.append(ROOT / "code" / "cJSON" / "api_list.json")
    names: set[str] = set()
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(errors="ignore"))
        except Exception:
            continue
        names.update(extract_names_from_json(data))
    return names


def extract_names_from_json(data) -> set[str]:
    names: set[str] = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                names.add(key)
            names.update(extract_names_from_json(value))
    elif isinstance(data, list):
        for item in data:
            names.update(extract_names_from_json(item))
    elif isinstance(data, str):
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", data):
            names.add(token)
    return names


def find_driver_file(project: str, driver: str) -> Path | None:
    search_dirs = [
        ROOT / "docker_shared" / "fuzz_driver" / project / "compilation_pass_rag",
        ROOT / "docker_shared" / "fuzz_driver" / project,
        ROOT / "fuzzing_llm_engine" / "external_database" / project / "fuzz_driver",
        ROOT / "fuzzing_llm_engine" / "external_database" / project / "crash" / driver,
    ]
    for base in search_dirs:
        for ext in (".cc", ".c"):
            path = base / f"{driver}{ext}"
            if path.exists():
                return path
        if base.exists():
            for path in sorted(base.glob(f"{driver}_crash_*.cc")) + sorted(base.glob(f"{driver}_crash_*.c")):
                return path
    return None


def copy_existing_drivers_to_external() -> dict[str, dict[str, str | None]]:
    copied: dict[str, dict[str, str | None]] = {}
    for project, drivers in EXISTING_CRASH_DRIVERS.items():
        dst_dir = ROOT / "fuzzing_llm_engine" / "external_database" / project / "fuzz_driver"
        dst_dir.mkdir(parents=True, exist_ok=True)
        copied[project] = {}
        for driver in drivers:
            src = find_driver_file(project, driver)
            if not src:
                copied[project][driver] = None
                continue
            dst = dst_dir / f"{driver}{src.suffix if src.suffix in {'.c', '.cc'} else '.cc'}"
            shutil.copy2(src, dst)
            copied[project][driver] = rel(dst)
    return copied


def copy_known_materials() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for project, known in KNOWN.items():
        dst_driver_dir = ROOT / "fuzzing_llm_engine" / "external_database" / project / "fuzz_driver"
        dst_driver_dir.mkdir(parents=True, exist_ok=True)
        dst_driver = dst_driver_dir / known.dst_driver_name
        shutil.copy2(known.src_driver, dst_driver)

        corpus_dir = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{known.fuzzer_name}_corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        dst_poc = corpus_dir / f"crashsage_known_{known.cve}_poc"
        shutil.copy2(known.src_poc, dst_poc)

        result[project] = {
            "driver": rel(dst_driver),
            "corpus": rel(corpus_dir),
            "poc": rel(dst_poc),
        }
    return result


def infer_api_combine(project: str, driver: str, api_names: set[str]) -> list[str]:
    path = find_driver_file(project, driver)
    if not path or not path.exists():
        return []
    text = path.read_text(errors="ignore")
    called: list[str] = []
    for name in sorted(api_names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(name)}\s*\(", text):
            called.append(name)
    seen = set()
    ordered = []
    for name in called:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def prepare_api_combine() -> dict[str, dict[str, object]]:
    status: dict[str, dict[str, object]] = {}
    for project, known in KNOWN.items():
        agents_dir = ROOT / "fuzzing_llm_engine" / "external_database" / project / "agents_results"
        agents_dir.mkdir(parents=True, exist_ok=True)
        path = agents_dir / "api_combine.json"
        if path.exists():
            data = json.loads(path.read_text())
        else:
            data = []
        if not isinstance(data, list):
            data = []

        data = list(data)
        while len(data) < known.index:
            data.append([])

        data[known.index - 1] = known.apis
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        status[project] = {
            "path": rel(path),
            "length": len(data),
            "known_index": known.index,
            "known_apis": data[known.index - 1],
        }
    return status


def archive_and_clean_known_sanity() -> tuple[Path | None, list[str]]:
    paths = list_known_sanity_paths()
    archive = archive_paths(f"known_cve_sanity_archive_{TODAY}.tar.gz", paths)
    if archive:
        for path in paths:
            remove_path(path)
    removed = [rel(p) for p in paths]
    if archive and not removed:
        removed = known_sanity_paths_from_archive(archive)
    return archive, removed


def known_sanity_paths_from_archive(archive: Path) -> list[str]:
    paths = set()
    pattern = re.compile(r"^(.*?/crash/known_cve_sanity_[^/]+)")
    with tarfile.open(archive, "r:gz") as tf:
        for name in tf.getnames():
            match = pattern.match(name)
            if match:
                paths.add(match.group(1))
    return sorted(paths)


def archive_results() -> Path | None:
    results = ROOT / "fuzzing_llm_engine" / "results"
    archive = archive_paths(f"results_archive_{TODAY}.tar.gz", [results])
    if archive and results.exists():
        for child in list(results.iterdir()):
            remove_path(child)
    return archive


def selected_driver_names(project: str) -> set[str]:
    return set(EXISTING_CRASH_DRIVERS[project]) | {KNOWN[project].fuzzer_name}


def is_driver_source(path: Path) -> bool:
    return path.suffix in {".c", ".cc"} and path.is_file()


def archive_unselected_drivers() -> Path | None:
    paths: list[Path] = []
    for project in KNOWN:
        keep = selected_driver_names(project)
        for base in [
            ROOT / "docker_shared" / "fuzz_driver" / project,
            ROOT / "docker_shared" / "fuzz_driver" / project / "compilation_pass_rag",
            ROOT / "fuzzing_llm_engine" / "external_database" / project / "fuzz_driver",
        ]:
            if not base.exists():
                continue
            for path in base.iterdir():
                if is_driver_source(path) and path.stem not in keep:
                    paths.append(path)
    archive = archive_paths(f"unselected_drivers_archive_{TODAY}.tar.gz", paths)
    if archive:
        for path in paths:
            remove_path(path)
    return archive


def archive_unselected_corpus() -> Path | None:
    paths: list[Path] = []
    for project in KNOWN:
        keep = {f"{name}_corpus" for name in selected_driver_names(project)}
        base = ROOT / "fuzzing_llm_engine" / "build" / "work" / project
        if not base.exists():
            continue
        for path in base.iterdir():
            if path.is_dir() and path.name not in keep:
                paths.append(path)
    archive = archive_paths(f"unselected_corpus_archive_{TODAY}.tar.gz", paths)
    if archive:
        for path in paths:
            remove_path(path)
    return archive


def archive_extra_corpus_seeds() -> Path | None:
    paths: list[Path] = []
    for project, drivers in EXISTING_CRASH_DRIVERS.items():
        for driver in drivers:
            corpus = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{driver}_corpus"
            if not corpus.exists():
                continue
            files = sorted(p for p in corpus.iterdir() if p.is_file() and p.stat().st_size > 0)
            for path in files[3:]:
                paths.append(path)
            for path in sorted(p for p in corpus.iterdir() if p.is_dir()):
                paths.append(path)
    archive = archive_paths(f"extra_corpus_seeds_archive_{TODAY}.tar.gz", paths)
    if archive:
        for path in paths:
            remove_path(path)
    return archive


def archive_unselected_build_outputs() -> Path | None:
    paths: list[Path] = []
    for project in KNOWN:
        keep = selected_driver_names(project)
        base = ROOT / "fuzzing_llm_engine" / "build" / "out" / project
        if not base.exists():
            continue
        for path in base.iterdir():
            name = path.name
            driver_name = name.removesuffix("_libfuzzer_address_out")
            if name.endswith("_libfuzzer_address_out") and driver_name not in keep:
                paths.append(path)
        report_target = base / "report_target"
        if report_target.exists():
            for path in report_target.iterdir():
                if path.is_dir() and path.name not in keep:
                    paths.append(path)
    archive = archive_paths(f"unselected_build_outputs_archive_{TODAY}.tar.gz", paths)
    if archive:
        for path in paths:
            remove_path(path)
    return archive


def driver_path_in_external(project: str, driver: str) -> Path | None:
    base = ROOT / "fuzzing_llm_engine" / "external_database" / project / "fuzz_driver"
    for ext in (".cc", ".c"):
        path = base / f"{driver}{ext}"
        if path.exists():
            return path
    return None


def corpus_seed_count(project: str, driver: str) -> int:
    corpus = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{driver}_corpus"
    if not corpus.exists():
        return 0
    return len([p for p in corpus.iterdir() if p.is_file() and p.stat().st_size > 0])


def create_existing_manifest() -> list[dict[str, object]]:
    rows = []
    for project, drivers in EXISTING_CRASH_DRIVERS.items():
        for driver in drivers:
            crash_dir = ROOT / "fuzzing_llm_engine" / "external_database" / project / "crash" / driver
            pocs_dir = crash_dir / "pocs"
            aggregate_poc = ROOT / "fuzzing_llm_engine" / "external_database" / project / "crash" / "pocs" / f"poc_{driver}"
            corpus = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{driver}_corpus"
            docker_driver = find_path_with_ext(ROOT / "docker_shared" / "fuzz_driver" / project, driver)
            pass_driver = find_path_with_ext(ROOT / "docker_shared" / "fuzz_driver" / project / "compilation_pass_rag", driver)
            out_binary = ROOT / "fuzzing_llm_engine" / "build" / "out" / project / f"{driver}_libfuzzer_address_out"
            report_target = ROOT / "fuzzing_llm_engine" / "build" / "out" / project / "report_target" / driver
            rows.append({
                "project": project,
                "driver_name": driver,
                "crash_dir": rel(crash_dir) if crash_dir.exists() else None,
                "driver_crash_pocs": rel(pocs_dir) if pocs_dir.exists() else None,
                "aggregate_crash_poc": rel(aggregate_poc) if aggregate_poc.exists() else None,
                "build_work_corpus": rel(corpus) if corpus.exists() else None,
                "build_work_seed_count": corpus_seed_count(project, driver),
                "docker_shared_driver": rel(docker_driver) if docker_driver else None,
                "compilation_pass_driver": rel(pass_driver) if pass_driver else None,
                "external_driver": rel(driver_path_in_external(project, driver)) if driver_path_in_external(project, driver) else None,
                "build_out_binary": rel(out_binary) if out_binary.exists() else None,
                "build_out_report_target": rel(report_target) if report_target.exists() else None,
            })
    (MANIFESTS / "existing_crash_drivers.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    return rows


def find_path_with_ext(base: Path, stem: str) -> Path | None:
    for ext in (".cc", ".c"):
        path = base / f"{stem}{ext}"
        if path.exists():
            return path
    return None


def create_experiment_index() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for project, drivers in EXISTING_CRASH_DRIVERS.items():
        api_path = ROOT / "fuzzing_llm_engine" / "external_database" / project / "agents_results" / "api_combine.json"
        api_data = json.loads(api_path.read_text()) if api_path.exists() else []
        for driver in drivers:
            index = int(driver.rsplit("_", 1)[-1])
            api = api_data[index - 1] if index <= len(api_data) else []
            driver_path = driver_path_in_external(project, driver)
            corpus = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{driver}_corpus"
            crash_dir = ROOT / "fuzzing_llm_engine" / "external_database" / project / "crash" / driver
            poc_dir = crash_dir / "pocs"
            status = material_status(driver_path, corpus, api)
            rows.append({
                "Project": project,
                "DriverName": driver,
                "DriverPath": rel(driver_path) if driver_path else "",
                "DriverSource": "existing_ckgfuzzer_crash",
                "LabelPlanned": "existing_crash_candidate",
                "KnownVulnID": "",
                "TriggerAPI": ";".join(api),
                "InitialSeedCorpus": rel(corpus) if corpus.exists() else "",
                "CrashPocPath": rel(poc_dir) if poc_dir.exists() else "",
                "CrashDir": rel(crash_dir) if crash_dir.exists() else "",
                "ApiCombineIndex": str(index),
                "RepeatTimes": "10",
                "MaterialStatus": status,
                "Notes": "Existing CKGFuzzer crash material retained; final non-api label deferred.",
            })

        known = KNOWN[project]
        api = known.apis
        driver_path = driver_path_in_external(project, known.fuzzer_name)
        corpus = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{known.fuzzer_name}_corpus"
        poc = corpus / f"crashsage_known_{known.cve}_poc"
        status = material_status(driver_path, corpus, api, required_poc=poc)
        rows.append({
            "Project": project,
            "DriverName": known.fuzzer_name,
            "DriverPath": rel(driver_path) if driver_path else "",
            "DriverSource": "crashsage_known_vuln",
            "LabelPlanned": "real_api_vulnerability",
            "KnownVulnID": known.cve,
            "TriggerAPI": ";".join(api),
            "InitialSeedCorpus": rel(corpus) if corpus.exists() else "",
            "CrashPocPath": rel(poc) if poc.exists() else "",
            "CrashDir": rel(ROOT / "crashsage" / "results" / project / known.cve),
            "ApiCombineIndex": str(known.index),
            "RepeatTimes": "10",
            "MaterialStatus": status,
            "Notes": "CrashSage driver and PoC prepared; experiment execution not run.",
        })

    index_path = MATERIALS / "four_project_experiment_index.csv"
    with index_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Project",
            "DriverName",
            "DriverPath",
            "DriverSource",
            "LabelPlanned",
            "KnownVulnID",
            "TriggerAPI",
            "InitialSeedCorpus",
            "CrashPocPath",
            "CrashDir",
            "ApiCombineIndex",
            "RepeatTimes",
            "MaterialStatus",
            "Notes",
        ])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def material_status(driver_path: Path | None, corpus: Path, api: list[str], required_poc: Path | None = None) -> str:
    missing = []
    if not driver_path or not driver_path.exists():
        missing.append("missing_driver")
    if not corpus.exists() or not any(p.is_file() for p in corpus.iterdir()):
        missing.append("missing_seed")
    if not api:
        missing.append("missing_api_combine")
    if required_poc is not None and not required_poc.exists():
        missing.append("missing_known_poc")
    return "prepared" if not missing else ";".join(missing)


def verify_archives(paths: Iterable[Path | None]) -> list[str]:
    verified = []
    for path in paths:
        if not path:
            continue
        with tarfile.open(path, "r:gz") as tf:
            names = tf.getnames()
            if not names:
                raise RuntimeError(f"Archive has no entries: {path}")
        verified.append(rel(path))
    return verified


def verify_no_known_sanity() -> bool:
    return not list_known_sanity_paths()


def write_report(
    existing_manifest: list[dict[str, object]],
    index_rows: list[dict[str, str]],
    known_archive: Path | None,
    known_sanity_paths: list[str],
    archives: list[str],
    api_status: dict[str, dict[str, object]],
) -> None:
    missing = [row for row in index_rows if row["MaterialStatus"] != "prepared"]
    lines = [
        "# CKGFuzzer + CrashSage Materials Preparation Report",
        "",
        f"Date: {TODAY}",
        "",
        "This preparation step did not run `python fuzzing.py`, `run_fuzzer`, coverage, or repeated experiments.",
        "",
        "## Project Summary",
        "",
    ]
    for project in KNOWN:
        existing_count = len(EXISTING_CRASH_DRIVERS[project])
        known = KNOWN[project]
        lines.extend([
            f"- {project}: retained {existing_count} existing crash driver(s); added known-vuln driver `{known.fuzzer_name}` for {known.cve}.",
        ])

    lines.extend([
        "",
        "## Known-Vuln PoC Placement",
        "",
    ])
    for project, known in KNOWN.items():
        poc_path = ROOT / "fuzzing_llm_engine" / "build" / "work" / project / f"{known.fuzzer_name}_corpus" / f"crashsage_known_{known.cve}_poc"
        lines.append(f"- {project}: `{rel(poc_path)}`")

    lines.extend([
        "",
        "## API Combine Status",
        "",
    ])
    for project, status in api_status.items():
        lines.append(f"- {project}: `{status['path']}`, length={status['length']}, known_index={status['known_index']}")

    lines.extend([
        "",
        "## Archives",
        "",
    ])
    for archive in archives:
        lines.append(f"- `{archive}`")

    lines.extend([
        "",
        "## Removed Known-CVE Sanity Paths",
        "",
    ])
    if known_archive:
        lines.append(f"Archive: `{rel(known_archive)}`")
    for path in known_sanity_paths:
        lines.append(f"- `{path}`")

    lines.extend([
        "",
        "## Missing Or Needs Check",
        "",
    ])
    if missing:
        for row in missing:
            lines.append(f"- {row['Project']} / {row['DriverName']}: {row['MaterialStatus']}")
    else:
        lines.append("- None.")

    lines.extend([
        "",
        "## Cleanup Residuals",
        "",
    ])
    if CLEANUP_RESIDUALS:
        lines.append("These paths were archived but could not be deleted due to filesystem ownership/permissions:")
        for item in CLEANUP_RESIDUALS:
            lines.append(f"- `{item['path']}`: {item['reason']}")
    else:
        lines.append("- None.")

    lines.extend([
        "",
        "## Manifest Files",
        "",
        "- `fuzzing_llm_engine/experiment_materials/manifests/existing_crash_drivers.json`",
        "- `fuzzing_llm_engine/experiment_materials/four_project_experiment_index.csv`",
        "",
    ])

    (MATERIALS / "materials_preparation_report.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    ensure_dirs()
    copied_existing = copy_existing_drivers_to_external()
    copied_known = copy_known_materials()
    api_status = prepare_api_combine()
    pre_cleanup_existing_manifest = create_existing_manifest()

    known_archive, known_sanity_paths = archive_and_clean_known_sanity()
    results_archive = archive_results()
    unselected_drivers_archive = archive_unselected_drivers()
    unselected_corpus_archive = archive_unselected_corpus()
    extra_seeds_archive = archive_extra_corpus_seeds()
    unselected_outputs_archive = archive_unselected_build_outputs()
    archives = verify_archives([
        known_archive,
        results_archive,
        unselected_drivers_archive,
        unselected_corpus_archive,
        extra_seeds_archive,
        unselected_outputs_archive,
    ])

    existing_manifest = create_existing_manifest()
    index_rows = create_experiment_index()

    summary = {
        "date": TODAY,
        "did_not_execute": ["fuzzing.py", "run_fuzzer", "coverage", "repeated_experiments"],
        "copied_existing_drivers": copied_existing,
        "copied_known_materials": copied_known,
        "api_combine": api_status,
        "known_sanity_archive": rel(known_archive) if known_archive else None,
        "known_sanity_paths_removed": known_sanity_paths,
        "archives_verified": archives,
        "cleanup_residuals": CLEANUP_RESIDUALS,
        "known_sanity_clean": verify_no_known_sanity(),
        "index_rows": len(index_rows),
        "pre_cleanup_manifest_rows": len(pre_cleanup_existing_manifest),
        "manifest_rows": len(existing_manifest),
    }
    (MANIFESTS / "preparation_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    write_report(existing_manifest, index_rows, known_archive, known_sanity_paths, archives, api_status)

    if not verify_no_known_sanity():
        raise RuntimeError("known_cve_sanity paths still exist after cleanup")


if __name__ == "__main__":
    main()
