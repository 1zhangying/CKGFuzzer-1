# CrashSage Runtime Measurement Record

Date: 2026-10-30  
Population: 1,217 expanded crash reports and 96 representatives from 14 projects  
Model latency source: existing `qwen3-coder-flash` V4 representative results  
LLM calls made by this timing experiment: 0

## Measurement Protocol

- Sanitizer parsing, rule-guided attribution, and representative selection were
  measured independently over the complete report population.
- All 96 representatives were processed once for context reconstruction, in a
  single serial run. Context measurements were not collected concurrently.
- Direct replay and Docker/GDB collection used three attempts, a 15-second
  per-attempt timeout, and Docker-first execution with local-GDB fallback.
- Prompt construction was measured separately without an LLM call.
- LLM latency was joined from the existing V4 `qwen3-coder-flash` results by
  `(Project, CrashID)`.
- Timings use `time.perf_counter_ns()`. Failed and timed-out attempts are
  included in the latency distributions.

## Stage Results

| Stage | Scope | N | Succeeded | Failed | P50 | P95 | Total |
|---|---|---:|---:|---:|---:|---:|---:|
| Sanitizer parsing | Reports | 1,217 | 1,214 | 3 | 0.643 ms | 0.985 ms | 0.810 s |
| Rule-guided attribution | Reports | 1,217 | 1,217 | 0 | 0.074 ms | 0.103 ms | 0.119 s |
| Representative selection | Retained reports | 534 | 534 | 0 | 0.008 ms | 0.015 ms | 0.005 s |
| Seed/binary resolution | Representatives | 96 | 95 | 1 | 0.166 ms | 0.288 ms | 0.017 s |
| Static context | Representatives | 96 | 93 | 3 | 0.970 ms | 3.838 ms | 0.113 s |
| Direct replay | Representatives | 96 | 34 | 62 | 58.166 ms | 5,653.748 ms | 234.222 s |
| Docker/GDB collection | Representatives | 96 | 40 | 56 | 11,061.354 ms | 31,519.981 ms | 1,819.685 s |
| Runtime validation | Representatives | 96 | 49 | 47 | 0.098 ms | 0.271 ms | 0.011 s |
| Evidence package construction | Representatives | 96 | 96 | 0 | 239.986 ms | 537.209 ms | 30.583 s |
| Prompt serialization | Representatives | 96 | 96 | 0 | 15.881 ms | 22.135 ms | 1.842 s |
| LLM analysis | Representatives | 96 | 96 | 0 | 6,599.500 ms | 8,431.000 ms | 636.496 s |
| Total context reconstruction | Representatives | 96 | 96 | 0 | 11,732.614 ms | 37,226.020 ms | 2,085.158 s |

`Total context reconstruction` means that all 96 records completed the
measurement procedure; it does not mean that runtime context was available.

## Runtime Availability

| Outcome | Count |
|---|---:|
| Static context available | 93 / 96 |
| Runtime context available | 49 / 96 |
| Freshly reconstructed runtime context | 40 / 96 |
| Historical runtime context reused after fresh reconstruction failed | 9 / 96 |
| Runtime context unavailable | 47 / 96 |

Direct replay outcomes were `3/3` consistent for 34 representatives, `0/3` for
61, and `0/0` for one representative with no binary replay attempt. Of the 47
unavailable runtime contexts, 45 failed to reproduce and 2 reproduced a
different crash identity.

Failure-aware latency is reported separately because successful reconstruction
is slower than a failed attempt:

| Runtime result | N | Context P50 | Context P95 |
|---|---:|---:|---:|
| Fresh runtime context | 40 | 32.536 s | 56.473 s |
| Historical runtime context | 9 | 11.545 s | 12.236 s |
| Runtime context unavailable | 47 | 11.274 s | 11.948 s |

For the GDB collection stage itself, successful runs have a 31.355-second
median and failed runs have a 10.986-second median. Reporting only the pooled
11.061-second median would obscure the dominant cost of successful evidence
collection.

## Representative End-to-End Timing

| Component | P50 | P95 | Maximum | Total |
|---|---:|---:|---:|---:|
| Context reconstruction | 11.733 s | 37.226 s | 78.600 s | 2,085.158 s |
| LLM analysis | 6.600 s | 8.431 s | 9.370 s | 636.496 s |
| Context + LLM | 18.979 s | 44.297 s | 82.647 s | 2,721.654 s |
| Context + prompt + LLM | 19.958 s | 44.634 s | 84.987 s | 2,754.080 s |

The last row is a component-wise end-to-end estimate: it combines separately
measured context and prompt construction with the archived LLM latency for the
same representative. It does not represent one continuously executed process.

## Main Findings

1. The lightweight report-level stages are negligible. Parsing, rule-guided
   attribution, and representative selection together required less than one
   second across 1,217 reports.
2. Docker/GDB collection dominates context reconstruction: 1,819.685 seconds
   out of 2,085.158 seconds (87.27%).
3. LLM analysis remains a major cost. The measured median is 6.600 seconds and
   the total for 96 calls is 636.496 seconds.
4. Representative selection reduces the number of LLM submissions from 1,217
   to 96, a 92.11% reduction, but it does not eliminate the cost of replay and
   GDB inspection for each retained representative.
5. Runtime success is project-dependent. For example, all 17 isotp-c
   representatives and all 5 dlt-daemon representatives produced fresh runtime
   context, while all 8 c-ares and all 4 libmad representatives were
   unavailable in this environment.

## Result Files

- Raw stage rows: `runtime_timing.csv`
- Stage summary: `runtime_stage_summary.csv`
- Success/failure-aware stage summary: `runtime_status_breakdown.csv`
- Per-representative end-to-end results: `runtime_end_to_end.csv`
- Per-project summary: `runtime_project_summary.csv`
- Context availability: `runtime_outcome_summary.csv`
- Report-level measurements: `base_stage_measurements.csv`
- Prompt-construction measurements: `prompt_stage_measurements.csv`
- Individual context records: `context_96/*.json`
