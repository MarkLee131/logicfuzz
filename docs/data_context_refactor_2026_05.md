# data_context refactor — 2026-05

Eighth in the 2026-05 refactor series. Full audit of
`src/context/data_context.py` — the 12-step `FuzzingContext.prepare()`
orchestrator that owns every static-analysis-time fact the LLM agents
later consume.

Six findings (F1–F6) surfaced. User confirmed scope: fix F1 (resurrect
the stubbed extractors via `data_prep`), F4 (drop dead first call in
Step 7), F5 (normalise step-numbering log strings). Defer F2, F3, F6
with rationale below.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### F1 — Resurrect `_extract_existing_fuzzer_headers` and `_extract_existing_driver_knowledge`

**Symptom.** Both functions had been replaced with unconditional
empty-dict stubs after FuzzIntrospector was removed. Three call sites
(Step 7 line 908, Step 8 line 956, Step 12 line 1175, plus the cache-hit
path at line 195 + line 310) flowed empty data into the
`FuzzingContext.existing_fuzzer_headers` and `existing_driver_knowledge`
fields. Five downstream consumers — `prototyper.py:245-246,349-351`,
`fixer.py:240-250`, `workflow.py:39`, `context_prefetcher.py:74,88`,
`prototyper._format_driver_knowledge` and `_format_include_path_context`
— invariably saw empty data. The `<existing_driver_knowledge>` /
`<reference_drivers>` / "Reference includes from existing fuzzers"
blocks promised by CLAUDE.md (and by the docstring of those formatters)
were silently absent from every prompt.

**Fix.** Disk-backed resurrection. Both extractors now read from the
corpus produced by `data_prep/extract_all_fuzz_drivers.py` (which pulls
`oss-fuzz-llm-public/human_written_targets/{project}/` from GCS):

  - `_resolve_drivers_root(project_name)` — shared lookup helper.
    Probes `$LOGICFUZZ_DRIVERS_ROOT/{project}/`,
    `./extracted_fuzz_drivers/{project}/`, and the repo-root form. First
    hit wins. Returns `None` if no corpus is present; both callers
    degrade to empty (matching the pre-fix shape, so no caller breaks
    when the operator hasn't run the download yet).
  - `_iter_driver_source_files(root)` — filters by file extension
    (`.c .cc .cpp .cxx .c++`) AND content (must match
    `LLVMFuzzerTestOneInput`). Name-pattern matching alone is unreliable
    — OSS-Fuzz drivers use `*_fuzzer.*`, `fuzz_*.*`, `*_harness.*`,
    plain `main.cc`, etc.
  - `_extract_existing_fuzzer_headers` — parses `#include` directives
    from those driver files, partitions into `<...>` (`standard_headers`)
    vs `"..."` (`project_headers`), dedups + sorts. Matches the shape
    the Prototyper's `_format_include_path_context` expects.
  - `_extract_existing_driver_knowledge` — loads up to `max_drivers`
    driver sources and, when `llm_client` is supplied, calls the
    pre-existing `_analyze_driver_patterns` (still reachable — was just
    starved by the stub). Returns
    `{'driver_sources': [{path, source}, ...], 'analysis': {...}}`.
    Matches the Prototyper's `_format_driver_knowledge` expectations.
  - Cache-hit branch at line 195 was hardcoded to empty
    `existing_fuzzer_headers`; now also routes through
    `_extract_existing_fuzzer_headers` so cache hits benefit from the
    feature too.

The chosen design avoids LLM costs on baseline comparisons: when no
corpus is on disk the extractors log a debug hint pointing at the
download script and return empty. Operators flip the feature on by
running `python3 data_prep/extract_all_fuzz_drivers.py -p <project>`
once (or setting `LOGICFUZZ_DRIVERS_ROOT` to point at an existing
corpus).

**Files.** `src/context/data_context.py`:
  - `_resolve_drivers_root` (new, near the top of the helper block)
  - `_iter_driver_source_files` (new)
  - `_DRIVER_SIGNATURE_RE`, `_DRIVER_INCLUDE_RE`, `_DRIVER_FILE_EXTS`
    (module-level regexes/constants)
  - `_extract_existing_fuzzer_headers` (rewritten)
  - `_extract_existing_driver_knowledge` (rewritten)
  - `prepare()` cache branch line ~195 (call site updated)

### F4 — Drop dead `_extract_existing_fuzzer_headers` call in Step 7

**Symptom.** Step 7 opened with:

```python
header_info = _extract_existing_fuzzer_headers(project_name, log)
if not header_info or (...empty...):
    log.warning("No existing fuzzer headers found, using minimal header set")
    header_info = {'standard_headers': [...libc...], 'project_headers': []}
if not header_info.get('project_headers'):
    # ...real work: load public_headers.txt from generator.extract_metadata...
```

Pre-F1 the first call returned an empty stub unconditionally — so every
run hit the warning, fell back to minimal, then did the real work
(loading the project's `public_headers.txt`). Post-F1 the first call
would return existing-fuzzer `#include`s, conflating Step 7's purpose
(the target project's compile headers) with Step 8's purpose (reference
drivers' includes).

**Fix.** Removed the dead/conflated first call and its associated
warning branch. Step 7 now opens directly with the minimal-libc baseline
and augments with `public_headers.txt`. Step 7 and Step 8 are now
cleanly separated:

  - Step 7: project compile headers (what the driver `#include`s to see
    target APIs)
  - Step 8: existing-fuzzer reference headers (what real OSS-Fuzz
    drivers `#include`, used as include-path hints)

Header `try/except` retained for the public_headers.txt I/O path so a
disk error doesn't kill prepare().

**File.** `src/context/data_context.py` Step 7 block (~line 903-945).

### F5 — Normalise step-numbering log strings to /12

**Symptom.** Log lines variously said `1/10` through `10/10`, then
`11/11`, then `12/12`. Three different denominators for a 12-step
pipeline. Cosmetic, but a reader scanning logs couldn't tell at a
glance how far along they were.

**Fix.** All `N/M` strings in `prepare()` now use `/12`:

  - `1/12 … 6b/12` (and the `5b 5c 5d 5e 5f 5e2 6b` sub-numbered ones)
  - `7/12, 8/12, 9/12, 10/12, 11/12, 12/12`

**File.** `src/context/data_context.py` log strings at the head of each
Step block.

---

## §2. Deferred — with rationale

### F2 — Step 4 grammar generation mostly wasted

**Observation.** Step 5c replaces `api_sequences` wholesale with the
output of `_generate_entry_point_sequences` (which is built from L1
entry-point names + L2 lifecycle pairs only — never consults grammar).
The grammar work survives only as a Plan B fallback when EP-gen returns
empty (very rare; only projects whose L1 finds no entry points).

**Why not fix now.** EP-gen reads `entry_point_names` produced by Step
5c, which itself runs after grammar (Step 4). Skipping Step 4 means
re-ordering 4 → 5c, then conditionally running 4 only on the EP-gen
empty path. This is a real ordering rewrite (the cross-module review
already caught one such regression with `build_data_layout` —
[cross_module_review_2026_05.md](cross_module_review_2026_05.md)). Out
of scope for a single commit; needs its own ordering analysis.

### F3 — Step 5e2 / Step 5f doc-vs-code mismatch

**Observation.** CLAUDE.md says "5e2 runs after 5f," but the code
visually interleaves 5e2 within Step 5f. Both still execute correctly;
only the doc claim is wrong.

**Why not fix now.** Either fix is low value. Updating CLAUDE.md drops
the audit trail of why the numbering looks weird; moving the code
touches a working block for cosmetic gain. Mark for revisit alongside a
future Step renumbering pass.

### F6 — `_dedup_sequences` filter quirk

**Observation.** Line 1642's filter `if key and key not in seen` is
truthy-check on the tuple, so the empty tuple `()` is filtered, but a
sequence containing an empty string slot (e.g. `('foo', '', 'bar')`)
would survive.

**Why not fix now.** Not reachable from current callers — `seq` entries
always come from `api.function_name` (non-empty by construction). Pure
defensive hardening; flag only if a regression test exposes it.

---

## §3. Empirical validation — to be filled in

After the 17-benchmark dynamic run:

### F1: corpus-driven prompt augmentation

  - **Without corpus** (default): confirm `existing_fuzzer_headers` and
    `existing_driver_knowledge` are still empty in
    `results/{project}/static_analysis/`. Confirm the Prototyper prompt
    contains no `<existing_driver_knowledge>` block.
  - **With corpus**: run
    `python3 data_prep/extract_all_fuzz_drivers.py -p <project>` once,
    re-run logicfuzz, confirm:
    - Step 8 log line `📚 Loaded N existing fuzzer driver(s) for header
      reference`
    - Step 12 log line `📚 Loaded N existing driver(s) for knowledge
      extraction`
    - Prototyper prompts now contain `<existing_driver_knowledge>` and
      "Reference includes from existing fuzzers" blocks.
  - **A/B win condition**: with-corpus run produces ≥1 trial that
    compiles on first attempt thanks to copying an `#include` line from
    the reference set (vs hallucinating a header that doesn't exist).
    Coverage uplift secondary signal.

### F4: Step 7 cleanup

Confirm Step 7 log no longer contains "No existing fuzzer headers
found, using minimal header set" on any run (the warning was a
false-positive driven by the stubbed first call). Step 7 should
quietly skip straight to `Loaded N project headers from <path>` or
silently use the libc minimal set.

### F5: log denominator consistency

Spot-check any run log — every step line should read `N/12`. No `N/10`
or `11/11` should remain.

---

## §4. Rollback recipe

If F1 needs to be rolled back (e.g. corpus-loading turns out to break a
fragile prompt template):

  - In `src/context/data_context.py`, restore both extractors to their
    pre-fix one-liner stubs:
    ```python
    def _extract_existing_fuzzer_headers(project_name, log):
        return {'standard_headers': [], 'project_headers': []}

    def _extract_existing_driver_knowledge(project_name, log,
                                           llm_client=None, max_drivers=3):
        return {'driver_sources': [], 'analysis': None}
    ```
  - Delete the three new helpers (`_resolve_drivers_root`,
    `_iter_driver_source_files`, the module-level regex constants).
  - Revert the cache-hit branch at the top of `prepare()` to hardcoded
    empty `existing_fuzzer_headers`.

If F4 needs to be rolled back: restore the dead first call to
`_extract_existing_fuzzer_headers` at the top of Step 7's `try` block
and the associated minimal-set warning branch.

If F5 needs to be rolled back: revert log strings back to `/10` and
`11/11` (use the `git log -p` for this commit to find every line).
