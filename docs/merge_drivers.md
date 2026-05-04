# Harness Merging — `tools/merge_drivers/`

> **Status**: shipped. `python -m tools.merge_drivers pipeline ...`
> runs the full O1 → O2 → O3 → O4 chain end-to-end. Integrated into
> `scripts/batch_extended_fuzzing.sh` via `--fuzz-target-dir`.
>
> **Scope**: a *coverage-aware multi-task fuzzing harness compiler*.
> Takes N independent LogicFuzz-generated drivers, picks a Top-K
> non-redundant subset, fuses them into one OSS-Fuzz binary with a
> weighted dispatcher, and rewrites their existing seed corpora so the
> shared corpus is immediately usable.

This is the multi-driver counterpart of `run_extended_fuzzing.py`.
Each individual driver still runs as its own evaluation row; the
merged binary runs in parallel as an additional row.

---

## 1. Why merge — and why not just run N drivers?

Per-driver evaluation gives N independent 24h runs with N independent
corpora. Pros: per-driver coverage attribution is clean. Cons:
exec-budget fragmentation — N drivers × 1 core ≠ 1 driver × N cores
in throughput, and there's no cross-driver learning (an interesting
input for driver A doesn't seed driver B).

Multi-task fuzzing folds the N drivers into one binary that dispatches
on a discriminator word. The fuzzer's mutator implicitly schedules
across sub-harnesses — improving an input for harness A transfers to
B with a single-byte mutation of the discriminator. PromeFuzz (CCS'25)
showed this can outperform per-driver runs on coverage and time-to-bug.

We adopt the multi-TU + entry dispatcher *structural* approach from
PromeFuzz, then add four optimisations beyond it.

## 2. Architecture (O1 → O2 → O3 → O4)

```
N candidate drivers + N built libFuzzer binaries
        │
        ▼  O1  preflight.py
   smoke-fuzz each binary 15s, drop:
     - crash_on_empty
     - no_progress (edges < 1 in 15s)
     - binary_broken (non-zero exit, no crash artifact)
        │
        ▼  O2  select.py
   max-coverage greedy (Khuller 1−1/e) on per-driver
   reached-functions read from existing OSS-Fuzz coverage
   reports — drops subsumed drivers naturally
        │
        ▼  O3  merge.py (DispatchMode.CDF, SelectorPosition.TAIL)
   - each surviving driver becomes its own TU
   - LLVMFuzzerTestOneInput renamed to LLVMFuzzerTestOneInput_<id>
   - entry.{c,cpp} dispatches on a 16-bit selector
   - selector lives at input *tail* (decouples libFuzzer's
     prefix-biased mutators from sub-harness routing)
   - bucket widths ∝ marginal coverage (heavier drivers get
     more selector space → more fuzz budget)
        │
        ▼  O4  corpus.py
   - each surviving driver's existing corpus
     (results/output-{proj}-project/corpora/<id>/) is copied
   - each seed gets selector bytes appended that route it
     back to its origin sub-driver
   - optional dictionary union (cross-sub-driver token
     noise accepted)
        │
        ▼
   results/output-{proj}-project/merged/
     synthesized/
       entry.{c,cpp}
       <id>.{c,cpp} per surviving sub-driver
     corpus_merged/
       <sub-driver-id>_<seq>_<orig-name>  (selector-tagged seeds)
     oss_fuzz_build_snippet.sh           (compile + link recipe)
     preflight.json                      (O1 telemetry)
     selection.json                      (O2 marginal coverage trace)
```

Run it:

```bash
python -m tools.merge_drivers pipeline \
    --project libucl \
    --project-root results/output-libucl-project \
    --pair fuzz_targets/01.fuzz_target=oss-fuzz/build/out/.../01_fuzzer \
    --pair fuzz_targets/02.fuzz_target=oss-fuzz/build/out/.../02_fuzzer \
    ... \
    --output results/output-libucl-project/merged \
    --top-k 12 --mode cdf --position tail --smoke-duration 15
```

Then evaluate the merged binary alongside the per-driver rows:

```bash
# scripts/batch_extended_fuzzing.sh discovers
# results/output-{proj}-project/merged/synthesized/ automatically
# and adds a "{proj}_merged" row in parallel with per-driver rows.
MERGED_PROJECTS="libucl c-ares sqlite3" \
    bash scripts/batch_extended_fuzzing.sh 24
```

## 3. Best-practice deviations from PromeFuzz

### 3.1 Multi-TU instead of single-file flattening

PromeFuzz's `synthesize_into_one` keeps each driver as its own
translation unit. We do the same. Single-file flattening is fragile —
two drivers each declaring `static int compare(...)` or including
the same header that defines macros either link-fails or requires
heroic identifier rewriting. Independent TUs let the linker do that
work for us. Only the public symbol (`LLVMFuzzerTestOneInput`) needs
to be unique, so we rename it to `LLVMFuzzerTestOneInput_<id>`.

### 3.2 Selector at *tail*, not head

PromeFuzz puts the selector at offset 0. Issue: libFuzzer / AFL++
mutators are strongly prefix-biased — front bytes are flipped most
often. A selector at offset 0 mutates with every prefix-biased op,
so the body bytes shift sub-harness meaning whenever the selector
flips. The fuzzer's body-discovery effort gets diluted by selector
churn.

We default to `SelectorPosition.TAIL`. Tail bytes are mutated less
often, so the body is *locally stable* for intra-sub-harness
exploration. Cross-sub-harness migration still happens via tail
mutation but at lower frequency. Empirically, this biases the
implicit scheduler toward "deep-fuzz one sub-harness at a time"
rather than "round-robin every fuzz step".

`--position head` is available for A/B comparison.

### 3.3 Coverage-aware subset selection (O2)

PromeFuzz throws all built drivers in. We pre-prune with a classical
max-coverage greedy on each driver's reached-function set (Khuller
1−1/e). A driver whose reached functions are a subset of another's
contributes no marginal coverage and is dropped. On a 5-driver
example with one subset driver, O2 cleanly drops it; the merged
binary fuzzes 4 sub-harnesses instead of 5, with no coverage loss.

### 3.4 Weighted CDF dispatch (O3)

PromeFuzz uses uniform `idx = selector % N`. Each sub-driver gets
≈1/N of the fuzz budget regardless of marginal coverage. Sub-driver
marginal coverage often spreads over a 10× range, so uniform
allocation wastes budget on high-overlap drivers.

CDF mode emits a uint16 threshold table where `width(bucket_i) ∝
weight_i`. Weights default to O2 marginal coverage. A 16-bit
selector indexes the table by linear scan (K ≤ 12 in practice — cache-
friendly, no branch misprediction).

The behaviour is empirically untested vs. uniform on real 24h
campaigns. Both modes are exposed (`--mode uniform` / `--mode cdf`)
so we can A/B and decide whether the complexity earns its keep.

### 3.5 Corpus union with selector pre-tagging (O4)

PromeFuzz doesn't carry over per-driver seed corpora. We do — each
sub-driver's `corpora/<id>/` seeds get the matching selector bytes
appended (or prepended, for `--position head`) and are written to
`corpus_merged/`. The merged binary starts with a corpus that
already exercises every sub-harness, instead of having to discover
the selector + body joint structure from `""`.

For CDF mode, we use the bucket *midpoint* for the selector — most
stable under bit-flip / arithmetic mutators (a 1-bit flip is least
likely to cross either neighbouring threshold).

## 4. FAQ — coverage data source

> **Q**: O2 reads per-driver reached functions from
> `code-coverage-reports/<id>.fuzz_target/linux/summary.json`.
> Where does that file come from? Do I need to run a coverage build
> myself?

**A**: No. LogicFuzz's main pipeline (`run_logicfuzz.py`) already
runs an OSS-Fuzz coverage build for every driver as part of its
per-driver evaluation. The summary JSONs are written to
`results/output-{project}-project/code-coverage-reports/<id>.fuzz_target/linux/summary.json`
and are persistent across runs. The merge pipeline reads this
existing data — no separate coverage build is triggered.

### What if a driver has no `summary.json`?

`DriverCoverage.from_oss_fuzz_report` returns a fallback singleton
with `has_real_data=False`. By default,
`select_top_k(require_coverage_data=True)` *skips* such drivers
rather than letting them appear "novel" with their unique singleton.
The CLI prints `[skipped N without coverage data]` and the
`selection.json` records them under `skipped_no_data`.

To produce the missing reports: re-run the corresponding LogicFuzz
evaluation (`python3 run_logicfuzz.py -y comparison/<proj>.yaml ...`)
on the affected drivers. This is by design — we *don't* shell out to
`infra/helper.py build_fuzzers --sanitizer coverage` from inside the
merge pipeline because:

1. **Cost**: each coverage build is ~2–5 min in docker; N drivers ×
   that is wasted on data already on disk.
2. **Concerns**: `tools/merge_drivers` is a *merging* tool, not a
   *building* tool. Coupling OSS-Fuzz docker to it makes the
   pipeline unusable in isolation.
3. **UX**: synchronous shell-out blocks the CLI for tens of minutes;
   async forking creates wait/error-handling complexity.

The fallback singleton + skip-and-warn behaviour is the safe default.

### Why not use static reachability instead?

`FuzzingContext.l0_dependency_graph.get_reachable_funcs(api)` predicts
reachable functions during driver synthesis. It's available without a
coverage build. Why don't we use it?

Static reachability over-approximates: it assumes every callable
function is callable in this driver's actual execution. The runtime
coverage report is *grounded* — it's the set of functions the driver
*actually executed* on its OSS-Fuzz coverage corpus. For O2's
max-coverage greedy, ground truth wins.

If you really want a no-coverage-build path, pass
`--top-k <small-k>` to cap selection and rely on preflight edges
(O1 by-product) for tie-breaking. The CDF weights then default to
uniform within the selected set.

## 5. Implementation notes

### 5.1 CDF threshold sentinel

The 16-bit threshold table uses `unsigned short`. A naive "force last
threshold to 65536" wraps to 0 with `-Woverflow`. We cap at 65535;
the lookup loop exits via `idx + 1 < N` *before* reading
`threshold[N-1]`, so the last value is sentinel-only. See
`merge.py:_compute_cdf_thresholds`.

### 5.2 Language detection

Mixed C/C++ is common in OSS-Fuzz projects. We look at:
1. Real file extension (`.c` / `.cpp` / `.cc` / `.cxx`) — first
   priority.
2. Comment-stripped content scan for high-specificity C++ markers:
   `std::`, `template<`, `nullptr`, `class Name {`, `namespace Name {`.
3. Default C.

We **don't** treat `extern "C"` as a C++ marker — it's standard
C/C++ portability boilerplate when guarded by `#ifdef __cplusplus`,
and bare C drivers from LogicFuzz commonly include it. (We hit a
specific false positive on c-ares whose drivers have `// Internet
class` in comments; the comment-stripping pass handles that.)

### 5.3 Why no minset / corpus dedup

`libFuzzer -merge=1` already does this. It's the fuzzer's job, not
the merge tool's. If you want a deduplicated `corpus_merged/`, run
`libFuzzer -merge=1` on it before kicking off 24h fuzzing.

## 6. Future work (not yet)

- **A/B uniform vs CDF on real 24h campaigns** — collect the data
  before deciding whether to keep the CDF complexity.
- **Pre-flight integration in the LogicFuzz main pipeline** — today
  pre-flight expects pre-built libFuzzer binaries; the main pipeline
  could optionally feed them directly.
- **OSS-Fuzz corpus from `*_seed_corpus.zip`** — we currently read
  `results/output-{proj}-project/corpora/<id>/` (LogicFuzz output),
  not `oss-fuzz/build/out/{proj}/<target>_seed_corpus.zip` (OSS-Fuzz
  upstream). Adding the OSS-Fuzz path would give merged binaries
  access to professionally-curated seeds.
- **`merge_drivers` as a `run_logicfuzz.py` post-step** — auto-fire
  after every full LogicFuzz run, with the resulting merged harness
  joining the per-driver evaluation matrix automatically.

## References

- PromeFuzz (Wang et al., CCS 2025) — `synthesize_into_one` design,
  multi-task fuzzing structural approach.
- Khuller, Moss, Naor, "The budgeted maximum coverage problem", 1999
  — (1−1/e) approximation for O2's greedy.
