# CKGFuzzer + CrashSage Materials Preparation Report

Date: 2026-06-26

This preparation step did not run `python fuzzing.py`, `run_fuzzer`, coverage, or repeated experiments.

## Project Summary

- c-ares: retained 10 existing crash driver(s); added known-vuln driver `c-ares_fuzz_driver_False_qwen3-coder-plus_26` for CVE-2024-25629.
- cjson: retained 19 existing crash driver(s); added known-vuln driver `cjson_fuzz_driver_False_qwen3-coder-plus_60` for CVE-2025-57052.
- libpcap: retained 6 existing crash driver(s); added known-vuln driver `libpcap_fuzz_driver_False_qwen3-coder-plus_30` for CVE-2024-8006.
- zlib: retained 7 existing crash driver(s); added known-vuln driver `zlib_fuzz_driver_False_qwen3-coder-plus_20` for CVE-2023-45853.

## Known-Vuln PoC Placement

- c-ares: `fuzzing_llm_engine/build/work/c-ares/c-ares_fuzz_driver_False_qwen3-coder-plus_26_corpus/crashsage_known_CVE-2024-25629_poc`
- cjson: `fuzzing_llm_engine/build/work/cjson/cjson_fuzz_driver_False_qwen3-coder-plus_60_corpus/crashsage_known_CVE-2025-57052_poc`
- libpcap: `fuzzing_llm_engine/build/work/libpcap/libpcap_fuzz_driver_False_qwen3-coder-plus_30_corpus/crashsage_known_CVE-2024-8006_poc`
- zlib: `fuzzing_llm_engine/build/work/zlib/zlib_fuzz_driver_False_qwen3-coder-plus_20_corpus/crashsage_known_CVE-2023-45853_poc`

## API Combine Status

- c-ares: `fuzzing_llm_engine/external_database/c-ares/agents_results/api_combine.json`, length=26, known_index=26
- cjson: `fuzzing_llm_engine/external_database/cjson/agents_results/api_combine.json`, length=60, known_index=60
- libpcap: `fuzzing_llm_engine/external_database/libpcap/agents_results/api_combine.json`, length=30, known_index=30
- zlib: `fuzzing_llm_engine/external_database/zlib/agents_results/api_combine.json`, length=20, known_index=20

## Archives

- `fuzzing_llm_engine/experiment_materials/archives/known_cve_sanity_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/experiment_materials/archives/results_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/experiment_materials/archives/unselected_drivers_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/experiment_materials/archives/unselected_corpus_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/experiment_materials/archives/extra_corpus_seeds_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/experiment_materials/archives/unselected_build_outputs_archive_2026-06-26.tar.gz`

## Removed Known-CVE Sanity Paths

Archive: `fuzzing_llm_engine/experiment_materials/archives/known_cve_sanity_archive_2026-06-26.tar.gz`
- `fuzzing_llm_engine/external_database/c-ares/crash/known_cve_sanity_cares_cve_2016_5180`
- `fuzzing_llm_engine/external_database/cjson/crash/known_cve_sanity_cjson_cve_2025_57052`
- `fuzzing_llm_engine/external_database/zlib/crash/known_cve_sanity_zlib_cve_2026_27171`

## Missing Or Needs Check

- zlib / zlib_fuzz_driver_False_qwen3-coder-plus_22: missing_api_combine

## Cleanup Residuals

- None.

## Manifest Files

- `fuzzing_llm_engine/experiment_materials/manifests/existing_crash_drivers.json`
- `fuzzing_llm_engine/experiment_materials/four_project_experiment_index.csv`

