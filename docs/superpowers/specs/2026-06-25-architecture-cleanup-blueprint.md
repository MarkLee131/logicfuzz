# LogicFuzz Architecture Cleanup — Blueprint (2026-06-25)

Evidence-grounded 12-agent audit (workflow wh5s1tkea) + adversarial critic. Goal: remove
valueless designs, replace always-failing components, reduce complexity toward simple-but-efficient.

## Target architecture — 4 honest layers
**symbolic PLAN → symbolic VALIDATE → LLM RENDER → reliable MEASURE**
- **PLAN** (symbolic, cheap, the differentiator): use-def/typestate substrate → APISemanticModel.reconcile (roles) → Sequence Constructor (lifecycle-complete deep chains) → hole_semantics promoted to a full structured *spec* (API order, arg roles, runtime-buffer relations, lifecycle, ret-contracts).
- **VALIDATE** (symbolic): position-indexed lifecycle walk + length-dependency Z3 SAT (the only checks that reject anything).
- **RENDER** (LLM): Prototyper authors the COMPLETE driver FROM the spec (buffer sizing, guards, setjmp) + a plan-conformance check (reject API-set/order drift → regenerate). Deterministic hole-fill kept ONLY as SVF-failed fallback.
- **MEASURE** (profdata-first): per-input replay w/ timeout → llvm-profdata merge → llvm-cov export → totals; n_files<2 sanity gate; fail-open to live edge count.

## REMOVE (dead weight, ~2000 LOC, zero behavior change)
AutomatonAcceptanceGuard.admits (hardwired True, prunes nothing) · IncrementalZ3Solver push/pop controller (soft mode falls through) · EDSM merge + acceptance_score + PTA quotient (re-sorted away; accept-all) · run_closed_loop + --closed-loop/--eval wiring (output discarded, saturates 1 iter, paper liability) · dead llm_tiebreak hook · 5 inert levers (_exercise_object, _recover_init_handles, _drop_unrunnable, ERROR_VARIANTS, _dense_repeat) · dominance gate from DEFAULT merge path (0 drops; keep select.py import for CLI) · LLM_REPAIR branch (subsumed by 92d17830) · ~20 dead/graduated LOGICFUZZ_* flag reads+docs. KEEP LOGICFUZZ_PORTFOLIO read (PORTFOLIO=off A/B control).

## REPLACE (always-failing → appropriate tool)
- **#0 Coverage measurement** (run_extended_fuzzing._measure_coverage; replay→0.0, accepts 1-file garbage) → **profdata-first**: per-input `<cov_bin> -timeout=10 -runs=0 <corpus>` → `llvm-profdata merge -sparse` → `llvm-cov export -summary-only` (data[0].totals); n_files<2 gate; fail-open to live `cov:` edges; on fail export the surviving merged.profdata. **P0 — every A/B is unfalsifiable until this lands.**
- **#4 Deterministic RENDER** (skeleton_generator body, 24 branches, no HEAP mode → libpng 19,946 stack-overflows) → **LLM authoring from the structured spec** (validated: LLM one-shot a correct deep libpng driver w/ runtime-heap rows + setjmp).
- **#9 Prototyper hole-fill** → spec-guided FULL render + plan-conformance check; demote Fixer to source-errors-only; route build-config (-I/-l/link) to the deterministic build layer.
- **#1 (partial)** drop default-path function_conditions Z3 binding; keep Z3 behind REQUIRE_Z3.

## KEEP (load-bearing moat — off-limits)
use-def + typestate substrate (usedef.py, 16 consumers) · light SVF signal (_svf_writes write/read/is_array/set_by — only in-out-handle vs written-array disambiguation) · G2 Sequence Constructor planner core (_build_prefix/_densify/repair_sequence_validity/Typestate self-filter/cross_source — the validated depth moat) · hole_semantics PLAN · handle-aware role classifier (003cd672) · position-indexed lifecycle walk + length-dep Z3 SAT · A≡B compile-validate + orphan filter · traces.json + graft_creator_prefix · ablation switches (DISABLE_*, REQUIRE_Z3, Z3_MODE — paper controls).

## Migration order (dependency-correct, each independently testable)
- **#0 Coverage measurement** (BLOCKING). profdata-first + n_files<2 gate + fail-open. Test: re-measure surviving merged.profdata → non-zero; 1-file garbage → rejected. *Nothing render-related ships first.*
- **#1 Flag registry (warn-only)** src/config/flags.py — kills silent-dark-default class.
- **#2 Pure deletes** (parallel-safe): automaton guard · EDSM/closed-loop · dead llm_tiebreak · 5 inert levers · dominance-from-default · LLM_REPAIR · dead flag docs. Test: suite green + merge counts unchanged on cjson/c-ares.
- **#3 Merge collapse to 3 gates** (crash-poison → compile-validate A≡B → synthesize); migrate dead_on_empty into the fused stage first.
- **#4 Spec-guided LLM render + author** (gated LOGICFUZZ_LLM_REWRITE; A/B breadth-matched on cjson+lcms+libpng using the now-trustworthy #0 metric before default). MANDATORY plan-conformance check (blocks the discredited A-design revert).
- **#5 Deferred research** (NOT this cleanup): SVF→MemorySSA/store-to-arg light pass; role-lattice collapse. Each behind its own A/B.

## Risk
#0 is the linchpin (fallback: `-merge=1` into control dir; surviving-profdata export is the safety net). #4/#9 is highest-risk (A-design revert) — the plan-conformance check is mandatory + gated + A/B'd before default; if drift can't be caught, keep deterministic render shipping + LLM-render opt-in. Off-limits: G2 planner core, use-def substrate, A≡B gate, validate_sequence signature (L2/L3). Re-measure cjson+c-ares before/after #2/#3.
