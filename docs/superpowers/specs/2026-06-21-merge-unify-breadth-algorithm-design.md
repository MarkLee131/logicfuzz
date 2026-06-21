# Merge Unification + Systematic Breadth Algorithm — Design

**Date:** 2026-06-21
**Status:** approved (dominance-filter + direct integration) → writing-plans
**Origin:** 4-agent parallel review `wf_bcd8c0e7-b16`; root causes in
[memory] `project_merge_unify_breadth_algorithm`.

## Goal

Eliminate two structural inconsistencies the user flagged:
1. **Two merge code paths** (production in-workflow vs. standalone CLI) that share only leaf
   primitives, with divergent filters/selection/defaults.
2. **No single breadth algorithm** — breadth is an emergent product of stacked, partly-duplicated
   name-set heuristics with a *min-cardinality* objective; the one real measured max-coverage greedy
   is dead CLI-only code.

Replace both with: **ONE shared merge pipeline** that both entry points call, containing **ONE
explicit, measured DOMINANCE-FILTER selector** (keep-all-non-dominated) run at merge time.

## Decisions (user-confirmed 2026-06-21)

- **Algorithm = measured dominance-filter, NOT greedy max-coverage.** Analysis showed greedy
  max-coverage (even uncapped) collapses to a near-minimal cover and KILLS the per-API redundancy the
  user wants; it is also tie-break/noise-sensitive. The dominance-filter (drop a driver only if its
  measured reached-function set is fully contained in a single other kept driver) keeps maximum
  breadth + redundancy, is EXACT + deterministic + order-independent, and generalizes the existing
  `SUBSET_ELIM` (name-set@construction → measured-coverage@merge). Greedy/Z3-exact max-cover are kept
  in reserve ONLY for a future hard cap N. (Empirical backing: breadth-dominates-depth; CDF dispatch
  lost 1708→416 br to uniform; "27 shallow drivers beat 16 deep".)
- **Dilution cap:** none (uncapped). The dominance-filter has no cap; it drops only fully-redundant
  drivers. An explicit finite cap (then via Z3-exact max-cover) is a future opt-in, not in scope.
- **Rollout = direct integration, NO switch.** The dominance-filter becomes the default merge
  selection, replacing keep-all. This is safe WITHOUT a flag because it provably cannot drop any
  distinct API (it only removes drivers whose coverage is a strict subset of another kept driver), so
  there is nothing to A/B-guard. The only fallback is a CORRECTNESS one (no measured coverage ⇒ keep
  all), not a runtime switch. The golden test still locks the mechanical merge-unification refactor,
  and the lcms/cjson/c-ares/libpng regression still runs to confirm distinct-API counts hold.

## Part A — Merge Unification

**Current state.** PATH A = `run_single_fuzz._maybe_merge_drivers` (run_single_fuzz.py:890-1087),
used by both `--eval` and `--merge-drivers`; full gate stack (quarantine → preflight → orphan →
compile-validate A≡B → UNIFORM dispatch) but **no coverage-aware selection**. PATH B = manual CLI
`python -m tools.merge_drivers` (tools/merge_drivers/__main__.py), never invoked by production; has
the only measured max-coverage greedy `select.select_top_k` + corpus-union but **weak/missing gates**
(static `HOLE[` scan instead of real compile; can ship A≢B). They share only the leaf primitives in
`tools/merge_drivers/{merge,preflight,select,corpus,compile_validate,orphan_filter,crash_frame}.py`.

**Design.**
- New module `tools/merge_drivers/pipeline.py:run_merge_pipeline(candidates, *, project, stock_lang,
  iquote_dirs, trial_verdicts=None, model_name=None, drop_no_progress=None, cdf=False,
  coverage_reports_dir=None, corpus_root=None) -> MergeResult`. The dominance-filter runs whenever
  `coverage_reports_dir` resolves ≥2 per-driver reports (no flag); otherwise it is a no-op (keep all).
  Body = PATH A's orchestration (run_single_fuzz.py:924-1082), parameterized so it depends on no
  `Benchmark`/`WorkDirs` types. The merge-only helpers (run_single_fuzz.py:512-887:
  `_is_immediate_crash_fp`, `_should_quarantine_from_merge`, `_trial_confirms_real_bug`,
  `_preflight_rejection_set`, `_preflight_filter_candidates`, `_compile_validate_candidates`,
  `_edges_weights_for`, `_stock_target_lang`, `_iquote_dirs_for_target`, `_is_degenerate_binary_set`,
  `_resolve_candidate_binary`) move into the module and are shared once.
- `run_single_fuzz._maybe_merge_drivers` becomes a ~15-line adapter: build candidates (br.compiles +
  source-on-disk), map each trial to `(crashes, real_bug)` via `_trial_confirms_real_bug`, call
  `run_merge_pipeline(...)`. Returns the out dir.
- `__main__._cmd_merge` / `_cmd_pipeline` become thin adapters onto `run_merge_pipeline`. **Delete**
  `_cmd_merge`'s static-`HOLE[`/status heuristic (__main__.py:92-99); require `--project` so the real
  compile gate runs (fail-open when absent — never block). `_cmd_pipeline` passes
  `coverage_reports_dir` + `corpus_root` to enable the optional selector + corpus union.
- Quarantine takes an injected per-candidate verdict callback; the CLI (no trial verdicts) passes None
  and that stage is skipped. The dominance-filter and corpus stages key on data availability
  (`coverage_reports_dir` / `corpus_root`); CDF stays per-caller (UNIFORM default). The golden test
  locks the GATE STACK + dispatch byte-identical; the dominance-filter is an intentional, additive
  behavior change (drops only fully-dominated drivers — provably no distinct-API loss).

## Part B — Systematic Breadth Algorithm

**Selection rule (explicit — dominance filter).**
> Ship `D = { d ∈ Pool : ¬∃ d' ∈ Pool, d'≠d, APIs(d) ⊆ APIs(d') }`, i.e. keep every driver EXCEPT
> those whose measured reached-function set is fully contained in another kept driver. `Pool` =
> candidates that (1) COMPILE under OSS-Fuzz coverage-build flags (existing `compile_validate` gate ⇒
> A≡B), (2) are LIVE (preflight `edges_seen > 0`, not `dead_on_empty`), (3) are non-crashing-FP /
> non-orphan. This keeps maximum breadth AND redundancy (partial-overlap drivers are kept; only
> fully-dominated ones drop), so it **provably cannot remove any distinct API**.
> `APIs(d)` = measured reached-functions from `code-coverage-reports/<id>/linux/summary.json`
> (`DriverCoverage.from_oss_fuzz_report`, `has_real_data`); a driver with no measurement is treated as
> NON-dominated (kept) — never compared on a fallback singleton, never double-counted.
> **Dominance tie-handling:** if `APIs(d) == APIs(d')` (mutual containment / exact duplicates), keep
> the one with higher preflight `edges_15s`, then lexicographic name (deterministic); drop the other.
> **Subsystem floor:** never drop the sole kept driver of a subsystem cluster even if dominated
> (preserves the parser-entry-bias fix). Exactness is unaffected (floor only ADDS back).

**The algorithm.** A single O(n²) pairwise dominance pass over the Pool's measured API sets (n is small
— tens to low-hundreds of drivers). Deterministic, order-independent. NOT greedy `select.select_top_k`
(kept in the module, unused by production, reserved for a future hard-cap path via Z3-exact max-cover).
Generalizes `SUBSET_ELIM` from name-set@construction to measured-coverage@merge — same concept, one home.

**Where it runs.** ONE merge-time stage, strictly AFTER `compile_validate` (so shipped ⊆ A≡B set),
inside `run_merge_pipeline`, **directly integrated (no flag)**. **Correctness fallback:** when <2
per-driver coverage reports resolve, it is a no-op (keep all survivors — today's behavior); never
empties the merge.

**Generator vs selector split.** Construction + `_densify` + RESIDUAL_ALLCOVER + repair_validity stay
GENERATOR-only (produce the candidate pool toward the extraction ceiling); they no longer treat
name-set coverage as a *selection* objective. `coverage_ranker` selection + the data_context PORTFOLIO
selection demote to candidate RANKING / tie-break.

**De-duplication (DEFERRED — review counts were overstated; corrected by direct verification 2026-06-21).**
The review's "3 RESIDUAL_ALLCOVER / 2 portfolio / 6 marginal loops" did NOT survive verification:
- **RESIDUAL_ALLCOVER is implemented ONCE** (data_context.py:1966, construction all-cover). The two
  other cited sites (data_context.py:2117-2140, coverage_ranker.py:548-569) are **API_FLOOR** — a
  *different* mechanism ("smallest driver covering each still-uncovered API"), genuinely duplicated
  TWICE. The review conflated API_FLOOR with RESIDUAL_ALLCOVER.
- **Marginal loops:** ~2 real (`select_marginal` primitive + 1 inline at coverage_ranker.py:474); the
  CBFactory matches are Z3 chain-backtracking (`new_api` var), unrelated — false matches.
- **Portfolio:** 1 confirmed (`coverage_ranker._coverage_complete_select`); the data_context.py:2142 hit
  is a log line — needs a closer look before claiming a true duplicate.
The only VERIFIED duplication is **API_FLOOR ×2**. The min-cardinality early-stop (`if not new: break`,
coverage_ranker.py:64-65, 404) is real but lives in the LIVE construction-time selection lcms depends on.
⇒ **De-dup is a code-cleanliness follow-up, NOT part of this increment.** Each target gets per-item
verification + its own TDD before any collapse; nothing here is built on the unverified counts.

**REFRAME (critical, verified).** A merge-time max-coverage SELECTOR does NOT expand breadth: production
already ships ALL compiled+live survivors = maximum breadth; a selector can only pick a subset (uncapped
⇒ drop only pure-redundant drivers adding 0 new measured APIs). So this part is **dilution/redundancy
control + an explicit, consistent, measured objective — not breadth expansion.** Breadth EXPANSION lives
in the GENERATOR (construction all-cover + API_FLOOR + validity-prepend), exactly where #19/#20/#21 made
their gains. The "systematic breadth algorithm" is therefore TWO layers with distinct jobs:
- **Generator** (construction): maximize the candidate POOL toward the extraction ceiling — RESIDUAL_ALLCOVER
  (all-cover) + API_FLOOR + validity-prepend. *This is where more distinct APIs come from.*
- **Selector** (merge, this increment): the explicit measured greedy decides which of the pool to ship,
  uncapped-while-marginal>0 by default (= keep max breadth, drop pure dups), with the dilution cap as a knob.

## Regression guards

- **Golden test FIRST:** capture current production `--eval` merge output (surviving set + UNIFORM
  dispatch) for fixed candidates+verdicts; the mechanical extraction must keep it byte-identical.
- **A≡B:** selector runs downstream of compile_validate; assert `merged/compile_validation.json` shows
  shipped == compiled.
- **Distinct-API invariant (the dominance guarantee):** the merged distinct-API union AFTER the
  dominance-filter must EQUAL the union over the full Pool (the filter only drops fully-dominated
  drivers). Assert this in a test — it is the formal safety net replacing a flag.
- **lcms non-regression:** static A/B — merged distinct APIs hold (≥69 merged / pool toward 297); the
  dominance-filter cannot drop a sole carrier of any API (by construction) and the subsystem floor
  protects sole cluster carriers.
- **Empty-merge guard:** no-op (keep-all) when <2 measured reports resolve; never empty the merge.
- **Dispatch invariant:** UNIFORM default (CDF measured 1708→416 br collapse); golden test asserts mode.
- **Determinism:** exact-duplicate tie broken by edges_15s then lexicographic name; order-independent
  (no greedy ordering) — robust against edge-count noise + PYTHONHASHSEED drift.
- **Multi-project:** validate on cjson/c-ares/zlib/libpng, not just lcms (over-fit guard).

## Out of scope

- Corpus-union (O4) wiring into production `--eval` (kept optional, CLI-only for now).
- CDF dispatch default change (stays UNIFORM/opt-in).
- The deeper measured-coverage signal for ALL pool candidates (eval currently writes per-driver reports
  for a subset; keep-all fallback covers the gap).

## Open questions (resolved)

- Algorithm: measured dominance-filter, not greedy (decided after analysis). Cap: none. Rollout:
  direct integration, no flag. Cluster floor: soft (only adds back a sole carrier). SUBSET_ELIM: the
  merge-time dominance-filter IS its measured generalization; the construction-time name-set SUBSET_ELIM
  stays for now (its consolidation is part of the deferred de-dup follow-up).
