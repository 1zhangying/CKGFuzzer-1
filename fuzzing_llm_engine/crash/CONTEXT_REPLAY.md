# Context replay

`context_replay` validates or regenerates the static and runtime evidence used
by V3/V4 without calling an LLM.

The replay gate follows the paper-defined crash identity:

1. Direct PoC replay is supporting evidence: when it runs, it should retain the
   same sanitizer bug type and target crash site/call stack. Consecutive
   duplicate frames created by optimization are normalized.
2. The static locator must resolve the crash source line and at least one
   source snippet.
3. Docker/GDB collection must still be attempted when direct host replay fails,
   because the host may lack the OSS-Fuzz runtime libraries. GDB must stop at
   the sanitizer report entry or a fatal signal.
4. The original target frame must match a leading target-library GDB frame
   (allowing compiler-inserted inline/callee frames) and its source location.
5. Runtime context is stable only when at least two GDB attempts produce the
   same validated crash-frame key.

For rebuilt binaries, sanitizer stacks can move a crash site across compiler
inline frames. The replay gate therefore first tries the exact paper replay key
and then requires the original target frame/location to occur, in order, inside
the reconstructed target stack. It never falls back to arbitrary stack-frame
membership.

Run from `fuzzing_llm_engine`:

```bash
PYTHONPATH=. python -m crash.context_replay \
  --project dlt-daemon \
  --driver dlt-daemon_fuzz_driver_False_qwen3-coder-flash_12 \
  --crash-id crash_1 \
  --prefer-docker
```

Multiple IDs are accepted:

```bash
PYTHONPATH=. python -m crash.context_replay \
  --project faad2 \
  --driver faad2_fuzz_driver_False_qwen3-coder-plus_2 \
  --crash-id crash_1,crash_2 \
  --crash-id crash_8 \
  --prefer-docker
```

To audit a representative manifest with the OSS-Fuzz runtime environment:

```bash
PYTHONPATH=. python -m crash.context_replay \
  --manifest results/dedup_schema2_14projects_20261027/representatives_all_14projects.csv \
  --prefer-docker \
  --output-dir results/context_replay_20261028_fixed
```

Results are written to `results/context_replay/` by default. Use `--update-db`
to persist a validated static context and a reproduced runtime context back to
the selected `crash_analysis.yaml`. Failed runtime attempts are recorded under
`context_replay.runtime_context_attempt` and do not overwrite an existing valid
runtime snapshot. Pass `--prefer-docker` to try the official
`gcr.io/oss-fuzz-base/base-runner-debug` image before the host GDB. This image
includes GDB and the OSS-Fuzz-era runtime libraries. If fresh
collection fails, a previously stored context is retained only when it passes
the same crash-identity validation; the result records its provenance as
`runtime_source=historical`.
