# Harness Merging — `tools/merge_drivers/`

> **Status**: shipped. `python -m tools.merge_drivers pipeline ...` runs the
> full O1 → O2 → O3 → O4 chain; integrated into
> `scripts/batch_extended_fuzzing.sh` via `--fuzz-target-dir`.

A *coverage-aware multi-task fuzzing harness compiler*: takes N independent
LogicFuzz drivers, picks a Top-K non-redundant subset, fuses them into one
OSS-Fuzz binary with a weighted dispatcher, and rewrites their seed corpora so
the shared corpus is immediately usable. The merged binary runs as an extra
evaluation row alongside the per-driver rows.

**Why merge:** per-driver runs fragment the exec budget (N drivers × 1 core ≠
1 driver × N cores) and share nothing across drivers. Folding them into one
binary that dispatches on a discriminator word lets the fuzzer's mutator
implicitly schedule across sub-harnesses — an interesting input for harness A
transfers to B with a single-byte mutation. We adopt PromeFuzz's (CCS'25)
multi-TU + entry-dispatcher structure, then add four optimisations.

---

## Architecture (O1 → O2 → O3 → O4)

```
N candidate drivers + N built libFuzzer binaries
   │
   ▼  O1  preflight.py — smoke-fuzz each 15s, drop crash_on_empty / no_progress / binary_broken
   │
   ▼  O2  select.py — max-coverage greedy (Khuller 1−1/e) on per-driver reached-functions
   │       (read from existing OSS-Fuzz coverage reports; subsumed drivers dropped)
   │
   ▼  O3  merge.py (DispatchMode.CDF, SelectorPosition.TAIL)
   │       · each driver → its own TU; LLVMFuzzerTestOneInput renamed to …_<id>
   │       · entry.{c,cpp} dispatches on a 16-bit selector at the input *tail*
   │       · bucket widths ∝ marginal coverage (heavier drivers get more fuzz budget)
   │
   ▼  O4  corpus.py — copy each surviving driver's corpus, append selector bytes routing
   │       each seed back to its origin sub-driver; optional dictionary union
   ▼
results/output-{proj}-project/merged/
  synthesized/{entry.{c,cpp}, <id>.{c,cpp}}   corpus_merged/<id>_<seq>_<name>
  oss_fuzz_build_snippet.sh   preflight.json   selection.json
```

Run it:

```bash
python -m tools.merge_drivers pipeline \
    --project libucl --project-root results/output-libucl-project \
    --pair fuzz_targets/01.fuzz_target=oss-fuzz/build/out/.../01_fuzzer \
    --pair fuzz_targets/02.fuzz_target=oss-fuzz/build/out/.../02_fuzzer \
    --output results/output-libucl-project/merged \
    --top-k 12 --mode cdf --position tail --smoke-duration 15

# Evaluate alongside per-driver rows (auto-discovers merged/synthesized/):
MERGED_PROJECTS="libucl c-ares sqlite3" bash scripts/batch_extended_fuzzing.sh 24
```

## Four deviations from PromeFuzz

1. **Multi-TU, not single-file flattening.** Each driver stays its own
   translation unit; only the public symbol is renamed
   (`LLVMFuzzerTestOneInput_<id>`). Flattening link-fails on duplicate
   `static` symbols / macro clashes; independent TUs let the linker resolve it.
2. **Selector at *tail*, not head.** libFuzzer/AFL++ mutators are prefix-biased;
   a head selector churns sub-harness routing on every front-byte flip. Tail
   bytes mutate less, so the body is locally stable for intra-sub-harness
   exploration — biasing the implicit scheduler toward "deep-fuzz one
   sub-harness at a time". `--position head` available for A/B.
3. **Coverage-aware subset selection (O2).** PromeFuzz includes all drivers;
   we pre-prune with max-coverage greedy on each driver's reached-function set,
   dropping drivers whose coverage is subsumed.
4. **Weighted CDF dispatch (O3).** PromeFuzz uses uniform `selector % N`; we
   emit a uint16 threshold table with `width(bucket_i) ∝ marginal_coverage_i`
   so high-overlap drivers don't waste budget. `--mode uniform` available.

CDF-vs-uniform on real 24h campaigns is **empirically untested** — both modes
are exposed so the complexity can be A/B'd before being kept.

## Notes

- **O2 coverage source.** Reads
  `code-coverage-reports/<id>.fuzz_target/linux/summary.json`, already written
  by `run_logicfuzz.py`'s per-driver evaluation — the merge pipeline triggers
  no new coverage build. A driver missing `summary.json` is *skipped* by
  default (`require_coverage_data=True`) rather than appearing falsely novel;
  re-run its LogicFuzz evaluation to produce the report. We deliberately don't
  use static reachability here — it over-approximates; runtime coverage is
  ground truth for the greedy.
- **No minset / corpus dedup** — that's `libFuzzer -merge=1`'s job; run it on
  `corpus_merged/` before a 24h campaign if you want it.
- **CDF selector for seeds** uses the bucket *midpoint* (most stable under
  bit-flip / arithmetic mutators).
- **Language detection** prefers the real file extension, then a
  comment-stripped scan for high-specificity C++ markers (`std::`, `template<`,
  `nullptr`, `class N {`); `extern "C"` is *not* treated as a C++ marker.

## References

- PromeFuzz (Wang et al., CCS 2025) — `synthesize_into_one`, multi-task structure
- Khuller/Moss/Naor, "The budgeted maximum coverage problem", 1999 — O2 greedy
