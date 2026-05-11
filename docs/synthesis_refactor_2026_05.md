# Synthesis-pipeline refactor — 2026-05

This doc records the adapter-side refactor that followed the
program-synthesis review of 2026-05. Six clusters of related bugs were
fixed atomically; ~1200 LOC of dead/duplicate infrastructure was
removed; the LLM refinement boundary was tightened to keep
deterministic work out of the LLM.

The empirical study that drove the cluster-2 (HoleFiller) and
cluster-4 (skeleton path) decisions used 70 OSS-Fuzz drivers across
17 projects. Methodology and per-project numbers live in
`/tmp/hole_analysis.py` (development tool, not checked in).

The "actual effects after running" section at the bottom is
**intentionally left blank** — it should be filled in after running
an A/B comparison on the 17-benchmark suite once the refactor lands.

---

## §1. What changed (per cluster)

### Cluster 1 — Z3 layer correctness

| Bug | Location | Fix |
|---|---|---|
| Type-match contradiction | `z3_solver.py:add_type_match_constraint` | Was asserting `Not(expr) ∧ expr` for incompatible types — unconditional UNSAT. Now incompatible types assert `¬(src_called ∧ tgt_called)`, compatible types assert type-var equality. |
| Lifecycle missed CREATE-before-USE | `z3_solver.py:_add_lifecycle_constraints` | Tracked only CREATE/DELETE; USE access was ignored. Now extracts `READ`/`WRITE` per-type and emits CREATE→USE, USE→DELETE, CREATE→DELETE order constraints. |
| Unsat-core diagnostic mis-parsed API names | `z3_guided_synthesis.py:_extract_missing_resources` | Old code split constraint name on `_`, breaking on `cJSON_Print`/`archive_read_*`. Now round-trips through the live `solver.api_vars` keyset, longest-first, to peel off the API prefix exactly. |
| `solver.check()` exception → `TIMEOUT` | `z3_guided_synthesis.py:IncrementalZ3Solver.check` | Distinguishes Python exceptions (now `UNKNOWN` with a tag in `unsat_core`) from Z3-reported `unknown` (reads `reason_unknown()` to tell timeout from genuinely-undecidable). |

### Cluster 2 — HoleFiller infrastructure deleted

`liberator_adapter/driver/synthesis/hole_filler.py`,
`constraint_collector.py`, and `test_synthesis.py` (~1200 LOC) were
removed. Empirical evidence: a 70-driver corpus study showed only
~3–5% of the LLM API bill could have been saved by pre-filling simple
holes deterministically, and 15% of those fills were "expert tricks"
the rule layer would have missed (zlib's `data[0]`-as-size,
cjson's `prebuffer=1`, ...).

In place of the removed strategy framework, `SkeletonGenerator` now
inlines the only two pre-fills that *are* unambiguously deterministic:

* **`RESOURCE_CLEANUP`**: `_infer_paired_destroy(producer_api, var)`
  emits `if (var) destroy(var);` based on canonical name pairs
  (`_create`/`_destroy`, `_new`/`_free`, `_open`/`_close`,
  `_init`/`_deinit`, `Parse`/`Delete`, ...). 100% rule-equivalent in
  the corpus study.
* **`LOOP_BOUND`**: numeric literal substituted directly into the
  `while` predicate. Was a hole; is now an integer.

Six bugs from the review (B5/B6/M4/M5/M6/M7) were inside the deleted
code and disappear with the deletion.

### Cluster 3 — `_is_input_param` entry-point safety net (B4)

`SkeletonGenerator._is_input_param` returned `False` for non-const
pointer arguments, mis-classifying the classic
`parse(uint8_t* data, size_t)` shape as "output" and emitting a
stack array instead of a fuzz-input pointer. The fix is an
entry-point-only safety net in `_create_variable_for_param`: when

  - the API is the first in the sequence, AND
  - the arg is a non-callback pointer that isn't `char*` (the C_STRING
    wrapper handles that), AND
  - the const-check classified it as not-input

force the FUZZ_INPUT branch with `(void*)data`. The 2026-05 corpus
study showed B4 affects ~5–10% of entry-point APIs; the fix is
narrowly scoped and bandages the most-affected call site without
touching the const heuristic for non-entry positions.

### Cluster 4 — Skeleton-path duality preserved

`create_skeleton_for_sequence` (L4-validated path, feeds the LLM) and
`create_random_driver_skeleton` (random walk, feeds Phase G
closed-loop's evidence regenerator) are intentionally *both* kept.
The two have different roles:

  - The L4 path produces skeleton CODE that drives prototyper-level
    refinement.
  - The random-walk path produces skeleton API_SEQUENCE that drives
    automaton learning (`update_with_traces`).

Removing the random-walk path would force closed-loop to call the L4
re-rank → skeleton-for-sequence chain on every iteration, which is
~10× the work. We instead let cluster 3's safety net cover B4 in both
paths simultaneously.

### Cluster 5 — Silent fallbacks removed

These all violated CLAUDE.md's "No fallbacks — explicit failures".

* `CBFactory.validate_sequence_with_z3` no longer swallows Z3
  exceptions as `(True, [])` (the old "conservatively assume valid"
  behaviour that was masking cluster 1's contradiction). It now
  re-raises under `z3_strict_mode` and reports
  `(False, ["z3_error: ..."])` otherwise.
* `Conditions.py` and `ConditionManager.py` no longer carry the
  `try: from ... import Variable / ApiCall, Buffer except ImportError:
  ... = None` guards that were stale dead code (the imports always
  succeed; the guards would have silently degraded type annotations to
  `None`).
* `Factory.normalize_type` no longer wraps `DataLayout.instance()`
  calls in `try/except → 0/False/PRIMITIVE`. The production
  pipeline (`data_context.py` Step 3.5 — see the cross-module
  review note below) initialises DataLayout before any
  `normalize_type` call; the fallback was masking a contract bug
  rather than serving a real scenario.

  **Cross-module follow-up (2026-05 review-of-review):** the
  original change here exposed a latent ordering bug — Step 4
  (grammar gen) called `Factory.normalize_type` BEFORE Step 5
  initialised DataLayout, and the old `try/except` masked it.
  After removing the mask, Step 4 started crashing on every
  non-primitive type. Fix: `build_data_layout` was moved up to
  Step 3.5 (before Step 4), so the SSOT-strict normalize_type
  now has a properly initialised DataLayout when it runs.

### Cluster 6 — Cleanups

* Dead caching scaffolding (`_feasibility_cache`, `_cache_hits`,
  `_cache_misses`, `get_cache_stats`) removed from
  `Z3GuidedSynthesisController`.
* `is_cpp_target` parameter removed from
  `SkeletonRenderer.render`/`render_with_holes_marked` (was already
  marked deprecated and threaded through but never actually changed
  behaviour — the `extern "C"` block uses `#ifdef __cplusplus`
  unconditionally).
* `ParamConstraintHole` and the unused `HoleKind` values
  (`NULL_CHECK`, `TYPE_CAST`, `API_SEQUENCE`, `PARAM_CONSTRAINT`)
  removed from `hole.py`.

---

## §2. Open / deferred items

These were noted during review but **not** addressed in this refactor:

* `_get_loop_apis` / `_apply_loop_patterns` /
  `_sample_sequence_from_grammar` were removed from
  `project_driver_generator.py` because they had no callers after
  `generate_skeleton_drivers` was deleted. If grammar-based sequence
  generation ever revives, it should reuse the L4 ranker pipeline
  rather than re-implementing.
* The `_compute_arg_bindings_via_running_context` re-runs
  `try_to_instantiate_api_call` over a sequence that
  `validate_sequence_with_z3` already approved (double-validation).
  The Z3 path and the upstream binding semantics can disagree; that
  divergence is real signal worth keeping for now, but should be
  reconciled later.
* The L4 random-walk skeleton path has its own
  `_create_skeleton_from_sequence` flow that bypasses
  `create_skeleton_for_sequence`'s Z3 re-validation. Worth auditing
  whether closed-loop should always pass through the validator.

---

## §3. Empirical validation

**cjson run4 (2026-05-11) — synthesis cluster fixes mostly unreachable.**

### Skeleton synthesis attrition (the load-bearing telemetry)

```
⚠️ Skeleton synthesis attrition on 10 sequences:
  automaton_pruned=10 (acceptance_score < 0.6),
  z3_rejected=0,
  emitted=0
```

This is the new telemetry surface that the synthesis refactor added
(splitting Phase H pre-prune from Z3 rejection). On cjson the
breakdown is unambiguous: **automaton is the bottleneck, not Z3**.
Pre-refactor (single counter), we wouldn't have known.

### Cluster B1 (HoleFiller deletion + silent-fallback removal)

HoleFiller path is gone; CBFactory uses `create_skeleton_for_sequence`
directly. No `HoleFiller` import errors in run4.

### Cluster B4 (entry-point safety net)

Not triggered. The safety net fires when L1 admits zero entry points;
on cjson L1 found 5 and L4 produced 10.

### Cluster C (Z3 correctness fixes)

Z3 ran zero rejections (`z3_rejected=0`) — not because the fixes are
broken, but because the candidates were pruned upstream by the
automaton guard before reaching Z3. Z3 correctness on cjson:
unobservable until automaton threshold is loosened or a richer
benchmark exercises it.

### Cluster A (silent-fallback removal)

Equivalent: no candidates reached Z3. Untested on cjson.

### Next benchmark for synthesis validation

Need a benchmark where ≥1 skeleton survives Phase H. Candidates:
c-ares (richer tests/, larger automaton) or libxml2 (heavyweight,
many init/destroy pairs).

### c-ares run1 (2026-05-11) addendum — synthesis cluster still unreachable

c-ares ran with 24-state automaton (vs cjson 2), confirmed via the
new attrition telemetry:
```
⚠️ Skeleton synthesis attrition on 10 sequences:
  automaton_pruned=10 (acceptance_score < 0.6), z3_rejected=0, emitted=0
```

**Same 10/10 pruned outcome as cjson — Z3 correctness fixes still
not validated empirically.** The richer automaton didn't help Phase H
admit any candidates. See `docs/automaton_refactor_2026_05.md` §3 for
the calibration analysis.

Action needed before synthesis cluster A/C can be empirically
validated: either drop the Phase H default threshold, or pick a
benchmark with an unusually rich test suite where 0.6 is achievable.
libxml2 might do; libucl probably won't.


This section is the placeholder for post-refactor measurements. After
running the 17-benchmark suite end-to-end with the refactor in place,
populate the table below and note any per-project regressions.

### Compile-rate effect (B4 cluster-3 fix)

Hypothesis: the entry-point safety net should improve first-trial
driver compile rate on projects whose entry-point APIs take non-const
pointer + non-char input. From the corpus study these are ~5–10% of
entry-point APIs.

| Project | Compile-rate before | Compile-rate after | Δ |
|---|---|---|---|
| c-ares | _TBD_ | _TBD_ | _TBD_ |
| cjson | _TBD_ | _TBD_ | _TBD_ |
| curl | _TBD_ | _TBD_ | _TBD_ |
| lcms | _TBD_ | _TBD_ | _TBD_ |
| libaom | _TBD_ | _TBD_ | _TBD_ |
| libjpeg-turbo | _TBD_ | _TBD_ | _TBD_ |
| libpcap | _TBD_ | _TBD_ | _TBD_ |
| libpng | _TBD_ | _TBD_ | _TBD_ |
| libsndfile | _TBD_ | _TBD_ | _TBD_ |
| libtiff | _TBD_ | _TBD_ | _TBD_ |
| libucl | _TBD_ | _TBD_ | _TBD_ |
| libvpx | _TBD_ | _TBD_ | _TBD_ |
| mbedtls | _TBD_ | _TBD_ | _TBD_ |
| nghttp2 | _TBD_ | _TBD_ | _TBD_ |
| re2 | _TBD_ | _TBD_ | _TBD_ |
| sqlite3 | _TBD_ | _TBD_ | _TBD_ |
| zlib | _TBD_ | _TBD_ | _TBD_ |

### Coverage delta (cluster-2 + cluster-3 combined)

Hypothesis: cluster-2 (kill HoleFiller) is coverage-neutral or
slightly positive (LLM stochasticity preserves expert-trick
diversity). Cluster-3 (B4 fix) adds 5-10% compile-rate which should
translate to coverage gains on those projects.

| Project | Coverage% before | Coverage% after | Δ |
|---|---|---|---|
| _per project, run 24h fuzz_ | _TBD_ | _TBD_ | _TBD_ |

### Z3 telemetry (cluster-1)

Z3 strict-mode flags previously-hidden bugs in the constraint
encoding. Track:

  - How many sequences NOW go UNSAT that previously SAT-passed?
    (cluster 1 is correct only if some increase is observed.)
  - How many `validate_sequence_with_z3` calls now raise / return
    `(False, ["z3_error:..."])`? (Should be 0 in steady state if the
    encoding is bug-free.)

| Run | UNSAT count (Z3-strict) | z3_error count |
|---|---|---|
| _TBD_ | _TBD_ | _TBD_ |

### Token / API-bill delta (cluster-2)

Hypothesis: deleting HoleFiller should be ~neutral in API spend
(prompt cost dominates). Track per-trial output-token counts to
confirm.

| Run | Avg prompt tokens | Avg response tokens | Δ vs baseline |
|---|---|---|---|
| _TBD_ | _TBD_ | _TBD_ | _TBD_ |

---

## §4. Rollback recipe

If any of the cluster fixes break a benchmark:

  - Per-cluster commits are tagged in commit messages with the
    `[cluster-N]` prefix; revert any single cluster individually.
  - Cluster 2's deletion can be partially reverted by restoring
    `hole_filler.py` from `git show HEAD~1`. The re-add in
    `synthesis/__init__.py` would also need restoring. Note: B5/B6/
    M4/M5/M6/M7 inside the restored code remain unfixed.
  - Cluster 3's safety net is a single conditional in
    `_create_variable_for_param`; revert the
    `if (is_entry_api and is_pointer and not is_char_star ...)` block
    to disable.
  - Cluster 5's three changes are independent; revert one at a time
    if a particular fallback turns out to be load-bearing for a real
    use case.
