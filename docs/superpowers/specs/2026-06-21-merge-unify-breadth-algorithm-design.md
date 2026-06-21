# Merge Unification + Systematic Breadth Algorithm — Design

**Date:** 2026-06-21
**Status:** design (awaiting user review → writing-plans)
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
explicit coverage-aware greedy max-coverage selector** run at merge time.

## Decisions (user-confirmed 2026-06-21)

- **Dilution cap:** uncapped while marginal coverage > 0 (keep every driver that adds ≥1 distinct
  API). Maximizes breadth + per-API redundancy/robustness. An explicit finite cap is opt-in only.
- **Rollout:** flag-gated A/B first (`LOGICFUZZ_MERGE_SELECT`, default-OFF). Production behavior stays
  byte-identical, locked by a golden test, until static multi-project A/B proves no regression; then
  graduate to default-ON. (Systematic-debugging / gate-then-graduate discipline.)

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
  coverage_reports_dir=None, corpus_root=None, select=False, select_cap=None) -> MergeResult`.
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
  and that stage is skipped. `select`/`corpus`/`cdf` stages are OPTIONAL, keyed on data availability,
  DEFAULT-OFF → production byte-identical.

## Part B — Systematic Breadth Algorithm

**Objective function (explicit).**
> Select `D ⊆ Pool` maximizing `|⋃_{d∈D} APIs_executed(d)|`, where `Pool` = candidates that
> (1) COMPILE under OSS-Fuzz coverage-build flags (existing `compile_validate` gate ⇒ A≡B),
> (2) are LIVE (preflight `edges_seen > 0`, not `dead_on_empty`),
> (3) are non-crashing-FP / non-orphan.
> **Keep every driver that adds ≥1 distinct API** (no min-cardinality early-stop); cap only by an
> explicit opt-in `select_cap`. Tie-breaks, lexicographic: (a) minimize mean pairwise API Jaccard
> redundancy (redundancy_telemetry oracle), (b) prefer higher preflight `edges_15s`, (c) driver name.
> Floor: ≥1 driver per subsystem cluster (preserves the parser-entry-bias fix) — as a soft floor.
> `APIs_executed(d)` = measured reached-functions from `code-coverage-reports/<id>/linux/summary.json`
> (`DriverCoverage.from_oss_fuzz_report`, `has_real_data`); falls back to the constructed api_sequence
> NAME set per-driver only when no measurement exists (never double-counted).

**The one greedy.** Promote `select.select_top_k` (select.py:133-206 — classical (1−1/e) max-coverage
greedy, already reads summary.json, edges_15s + name tie-breaks, self-terminates at 0 marginal gain)
to the authoritative merge selector. Add the Jaccard-redundancy tie-break + the subsystem-cluster
soft-floor to its comparator.

**Where it runs.** ONE merge-time stage, strictly AFTER `compile_validate` (so shipped ⊆ A≡B set),
inside `run_merge_pipeline` as optional stage O2. Gated by `LOGICFUZZ_MERGE_SELECT` (default-OFF
initially). **Empty-merge guard:** when <2 per-driver coverage reports resolve, fall back to keep-all
survivors (today's behavior) — never empty the merge.

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
- **lcms non-regression:** static A/B preserves merged distinct APIs (≥69 merged / pool toward 297);
  never drop sole-carrier residual single-API drivers (uncapped default ensures this).
- **Empty-merge guard:** keep-all fallback when no measured coverage; never empty the merge.
- **Dispatch invariant:** UNIFORM default (CDF measured 1708→416 br collapse); golden test asserts mode.
- **Subsystem balance:** retain the ≥1-driver-per-cluster soft floor.
- **Determinism:** lexicographic name tie-break (select_top_k already does) against edge-count noise +
  PYTHONHASHSEED drift.
- **Multi-project:** validate on cjson/c-ares/zlib/libpng, not just lcms (over-fit guard).

## Out of scope

- Corpus-union (O4) wiring into production `--eval` (kept optional, CLI-only for now).
- CDF dispatch default change (stays UNIFORM/opt-in).
- The deeper measured-coverage signal for ALL pool candidates (eval currently writes per-driver reports
  for a subset; keep-all fallback covers the gap).

## Open questions (resolved → defaults)

- Dilution cap: uncapped (decided). Cluster floor: soft floor (tie-break + guarantee), not hard
  constraint. SUBSET_ELIM: fold into selector keep-rule.
