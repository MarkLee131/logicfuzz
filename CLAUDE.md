# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Knowledge-Driven Neuro-Symbolic Fuzz Driver Generation over Structured API Program Spaces.

**Generation stage**: see `docs/generation.md` (SSOT). The pipeline is
reconcile-then-construct — build an `APISemanticModel` first (IR ⊕ doc ⊕ usage),
then *construct* lifecycle-complete sequences from it, so candidates are valid by
construction (no repair stage). The old "classify-then-repair" flow (Phase A
repair + Tier-1 F1–F4) was deleted.

## Commands

```bash
# Run on a benchmark
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
# Extract APIs only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only
# Generate drivers with CBFactory only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10
# Phase G closed-loop CBFactory feedback (re-synthesise with grown automaton)
python3 run_logicfuzz.py -y comparison/cjson.yaml --closed-loop --closed-loop-iters 3 --closed-loop-early-stop 0
# A/B: disable G2 model-driven construction, fall back to random-walk grammar
LOGICFUZZ_DISABLE_G2_CONSTRUCT=1 python3 run_logicfuzz.py -y comparison/cjson.yaml
# Merge: synthesize a multi-task harness from successful trials
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_TOP_K=56 python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers
# Evaluation profile: bundles --closed-loop + --merge-drivers
python3 run_logicfuzz.py -y comparison/cjson.yaml --eval
# Multi-hop reasoning Mode A (Prototyper); opt-in
python3 run_logicfuzz.py -y comparison/cjson.yaml --multihop-prototyper
# Control parallelism
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml
# Code quality + tests
pylint src/ && pyright src/ && pytest tests/
# Extended fuzzing evaluation (24h)
python scripts/run_extended_fuzzing.py -p re2 -f results/output-re2-project/fuzz_targets/02.fuzz_target -d 86400
```

`--num-samples` auto-resolves to `len(skeleton_drivers)` (one trial per
Z3-validated skeleton); see `run_single_fuzz.py:_fuzzing_pipelines`. Knowledge-layer
priors (Phase B / T1) are DEFAULT-ON (`--use-doxygen-priors`/`--use-readme-purpose`
removed; live in `FuzzingContext.prepare()` defaults).

## Flag / Gate Reference (`LOGICFUZZ_*` / `LIBERATOR_*`)

Format: `FLAG=val — purpose (default)`. Full rationale/measurements live in git history.

### Tuning values + always-on A/B kill-switches
- `LOGICFUZZ_TOP_K=N` — skeleton/driver count, the union-breadth lever (default 10; needs `NO_CACHE=1` to regen). Under PORTFOLIO=complete (default) SUPERSEDED by coverage-complete selection; only bounds PORTFOLIO=off.
- `LOGICFUZZ_PORTFOLIO=complete|minimal|off` — coverage-COMPLETE portfolio selection (DEFAULT complete): ≥1 lifecycle-valid driver per subsystem cluster (cover) + bounded depth pass; fixes parser-entry-bias. (minimal=cover only; off=legacy fixed top_k round-robin = A/B control.)
- `LOGICFUZZ_PORTFOLIO_DEPTH=F` — depth multiplier for PORTFOLIO Phase 2 (default 0.5).
- `LOGICFUZZ_DENSE_MAX_EXTRA=N` — cap extra APIs appended per chain (default 8 → ~7.7 APIs/seq lcms = PromeFuzz parity).
- `LOGICFUZZ_DENSE_COOCCUR=0` — density extends ONLY handle-sharing, dropping automaton co-occurrence (default on).
- `LOGICFUZZ_DENSE_REPEAT_CONSUMER=1` — density also repeats a handle's consumer (default off).
- `LOGICFUZZ_STRICT_ORDERING=1` — revert B graceful degradation (drop orphan USE_BEFORE_INIT instead of keeping as a hole).
- `LOGICFUZZ_DISABLE_{G2_CONSTRUCT,DRIVER_TRACES,SEQFACTS,LLM_ROLES}=1` — A/B kill-switch for that default-on stage.

### Graduated to default (gates removed — now unconditional)
Design-confirmed / A-B-validated levers that are now DEFAULT behavior; the
`LOGICFUZZ_*` switch was deleted (rationale + per-lever measurements in git
history). Net effect on the construct+select default: fewer selected drivers
covering MORE APIs at far lower redundancy (cjson 33→19 drivers / 58→77 APIs /
Jaccard 0.43→0.05; lcms 60→45 / 154→212 / 0.15→0.06).
- **DENSE_PARTITION** (A-2a) — sibling chains take DISJOINT densifier slices (`sequence_constructor._densify`).
- **DIVERSIFY_PRODUCERS** (A-1/A-3) — rotate among >1 valid producers/destroyers per sibling (`_build_prefix`/`_closing_destroyers`).
- **MARGINAL_DEPTH** (B-1) — Step-10 depth picks by MAX marginal new-API coverage (`coverage_ranker.select_marginal`), not round-robin.
- **SUBSET_ELIM + semantic guard** (B-3) — drop strict same-value-domain fingerprint subsets; never drop a Comprehender-VALID sequence (`driver_dedup`).
- **SCOPED_GUARDS** (B+D) — per-dependency-component nested NULL-guards so an independent API runs when the parser returns NULL (`sequence_constructor._dependency_components` + `skeleton_generator`); construct reorders components contiguous.
- **CROSS_SOURCE_BIND** — cross-profile transform binding (CREATOR-scoped + name-deny; byte-identical off-lcms; +134% lcms edges) (`sequence_constructor._inject_cross_source` + `CBFactory._distribute_cross_source`).
- **QUARANTINE_FP_CRASHERS** — drop driver-FP crashers from the merge regardless of coverage; confirmed real library bugs never dropped (`run_single_fuzz._should_quarantine_from_merge`).
- **VALUE_DOMAINS** — knowledge dictates leaf values: 4cc signature #defines + forbid `(Enum)(data%N)` arithmetic + carry @param ranges; compatible with FUZZABLE_HOLES enum-sweep (`hole_semantics`/`named_constants`).

### Pruned (removed — redundant / over-fit / niche)
TAG_ROUNDTRIP + EXERCISE_DEEP_BUFFER (lcms over-fit single-idiom); CROSS_PROJECT / XPROJ_CORPUS (unvalidated resource-thin fallback); DEDUP_WORKFLOW_PARTITION (⊂ DENSE_PARTITION); PAIRWISE_DEDUP / PAIRWISE_TAU (⊂ SUBSET_ELIM + construction decoupling); ORDERSETS (⊂ coverage-complete selection).

### Construction / depth / dedup levers
- `LOGICFUZZ_ERROR_VARIANTS=1` / `_MAX=N` — T11: emit error-shape skeleton variants (double-free / use-after-destroy / skip-init) so library error branches become reachable (gated, A/B pending).
- `LOGICFUZZ_VALUE_FEEDBACK` — T12: capture filled hole values → coverage_memory, pin deepest-coverage into the same skeleton next run (cross-run). DEFAULT-ON (opt-out =0); no-op on a fresh project.
- `LOGICFUZZ_FORMAT_INFER=1` — T10: synthesize front-gate-passing seed(s) from inferred magic when no real seed matches (opt-in; emits a diverse k≥3 corpus).
- `LOGICFUZZ_FUZZABLE_HOLES=1` — Tier 1: render tunable CONFIG holes (enum/scalar/float) as FUZZ_DERIVE directives so the fuzzer sweeps the param. DEFAULT-ON (opt-out =0).
- `LOGICFUZZ_OBJCONSTRUCT_FIRST=1` — L1: prefer object-construction chain roots over parser-entry (top coverage lever; keeps ≥1 parser-rooted per parser-only cluster). (gated, A/B pending)
- `LOGICFUZZ_API_FLOOR=1` — L7: greedy set-cover guarantees every constructable API appears in ≥1 selected sequence. (gated)
- `LOGICFUZZ_RESIDUAL_ALLCOVER=1` — breadth lever: append a single-API sequence for every public API the symbolic constructor can't chain (validity-repair prepends its handle creators), lifting API breadth toward the extraction ceiling (cjson 75→78, lcms 149→297). (gated, A/B pending)
- `LOGICFUZZ_VALIDITY_CONTRACT=1` — valid-by-construction contract: every `nullable=False` opaque-handle arg gets a type-matching producer in producer-before-consumer order with type-correct binding (I1/I2a/I2b/I3), driven by the model's per-arg nullable. Oracle `analysis/validity_contract.py`. (gated default-OFF)
- `LOGICFUZZ_SKIP_COMPILE_VALIDATE=1` — opt OUT of the merge compile-validation gate (default-on, fail-open: ships only drivers that compile under real cov-build flags).

### Driver DECOUPLING / DE-DUP levers
DENSE_PARTITION, DIVERSIFY_PRODUCERS, SUBSET_ELIM graduated to default (see Graduated block). Always-on Layer-E redundancy telemetry → `results/<project>/static_analysis/redundancy_telemetry.json` (mean pairwise API Jaccard + disjointness; the A/B oracle).

### Driver DEPTH levers
CROSS_SOURCE_BIND graduated to default; EXERCISE_DEEP_BUFFER removed (lcms over-fit).
- `LOGICFUZZ_EXERCISE_OBJECT=1` — after the prefix builds a handle, append ONE consumer that RUNS it (prefers an INPUT_BUFFER fuzz-data consumer). (gated, A/B pending)

### LLM / debug / SVF config
- `LOGICFUZZ_LLM_REWRITE=1` — opt OUT of B-design (hole-filling) back to A-design (LLM free-rewrite). DEFAULT B-design preserves constructed skeletons (A-design = A/B control, measured inert).
- `LIBERATOR_SVF_TIMEOUT_SECS=N` — SVF pointer-analysis wall-time cap (default 1800; libtiff/libvpx are TIME-bound, set =14400).
- `LIBERATOR_SVF_MEM_GB=N` — SVF memory cap (RLIMIT_AS, GB; default 0=off); over-cap → clang-only fallback instead of host OOM.
- `LOGICFUZZ_REUSE_SKELETONS=1` — DEBUG: load saved `skeleton_drivers.json`, SKIP Z3 synthesis to iterate on LLM/prompt side. Do NOT set when you changed a construction lever.
- `LOGICFUZZ_DROP_NO_PROGRESS=1` — opt IN to dropping no-progress drivers from the merge (default KEPT — the solo edge-growth gate is wrong for a merged harness; only crashers dropped).
- `LOGICFUZZ_{Z3_MODE,CONSTRUCT_MODE,NO_CACHE,TRIAGE_INCONCLUSIVE,TRIAGE_PREFIX_LEN,DRIVERS_ROOT,FI_ENDPOINT,BINDING_TELEMETRY}` — config values.

## Docs

5 docs, each the SSOT for its topic; everything else cross-references.

| Doc | SSOT for (owns) |
|-----|-----------------|
| `README.md` | User entry: what it is, install, quick-start, commands, supported projects, output. |
| `CLAUDE.md` (this file) | Agent operational guide: the `LOGICFUZZ_*`/`LIBERATOR_*` **flag/gate reference**, **file/component map**, **design principles**, the **Implementation-Flow Step list**, **Open TODOs**, **Failed Attempts/Lessons**, **architecture map**. |
| `docs/generation.md` | **Driver-generation pipeline.** G1–G5, the two handle-recovery passes, sequence construction, hole semantics, merge + coverage measurement, build-cache, honest verdicts, roadmap. Start generation work here. |
| `docs/knowledge_layer.md` | **Comprehender + project-adaptive automaton.** Two-stage deterministic-first knowledge layer; automaton mechanics (state vector, EDSM merge, `AutomatonArtifact`, persistence, Phase G closed loop); preflight-as-Liberator-seed-oracle. |
| `docs/contributions_and_related_work.md` | **Innovations pitch + baseline comparison.** 3 innovations, comparison vs PromeFuzz (neural) + Liberator (symbolic), attribute matrix, per-LLM-call-site rationale. |

Historical proposals + refactor logs live in git history (`git log --grep`).

## Architecture

```
run_logicfuzz.py → FuzzingContext (SSOT) → FuzzingWorkflow (LangGraph) → Evaluation
                         ↑                        ↓
              Static Analysis (Liberator)    Agent System
                         │
            ┌────────────┴────────────┐
   Project-Adaptive Automaton   Knowledge Layer
   (analysis/ static traces →   (knowledge/ comprehender +
    PTA → EDSM → Artifact)       Phase B idiom distiller)
            │                         │
            ▼                         ▼
   APISemanticModel (G1) ◀── reconcile IR⊕doc/naming⊕usage
            ▼
   Sequence Constructor (G2)   ── creator→mutator*→consumer→destroyer
   (gap-directed targets, G5;      lifecycle-complete by construction
    prepend to grammar floor)      ranked by gap-hits then reachability (G3+G5)
            ▼
   Z3 confirm (type/var only — lifecycle correct by construction)
            ▼
   skeleton_drivers + value-intents (G4) → trials × N → merge_drivers
            ▼
   Phase C IterationSnapshot → coverage_memory.json
```

### Workflow State Machine

```
COMPILATION:  prototyper → build → [fail] → fixer (×3) → END
                                 → [ok]  → OPTIMIZATION
OPTIMIZATION: execution → [crash] → crash_analyzer → feasibility → END/fixer
                        → [ok]    → END
```

No per-driver coverage-optimize loop: the `coverage_analyzer` → `improver` + §10B
`baseline_diff_analyzer` subsystem was **removed** — breadth comes from
many-drivers + merge + gap-direction. A clean build+run ends the trial; the
*crash* LLM path is unaffected. Per-trial caps are module constants atop
`src/workflow/nodes/supervisor.py` (read them there).

### Agent System (`src/agents/`)

| Agent | Tools | Purpose |
|-------|-------|---------|
| Prototyper | - (context pre-fetched) | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants`, `skeleton_drivers[(N-1) % K]`, Phase B idioms |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CrashAnalyzer | BashExecuteTool, GDBExecuteTool | Determine if crash is driver bug or real bug |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| Comprehender (non-LangGraph) | LLM batched | A: per-API usage + library purpose. B: per-sequence semantic verdict |

(The per-driver optimize agents — CoverageAnalyzer / Improver / BaselineDiffAnalyzer
— were removed; see Failed Attempts.) **Tool Consolidation**: all
introspector-derived context (signatures, cross-refs, type defs, headers, tests,
debug types) is pre-fetched into `FuzzingContext` before agent turns. Remaining
LangGraph tools: `BashExecuteTool` + `GDBExecuteTool` (`src/tools/execution.py`,
8KB output truncation).

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT |
| Supervisor | `src/workflow/nodes/supervisor.py` | Agent routing, phase management |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop |
| UnifiedCodeValidator | `src/utils/unified_validator.py` | Single-pass validator (fake-defs, internal APIs, language mismatch, hallucination) |
| Closed-loop (Phase G) | `src/closed_loop.py` | Re-runs L4+CBFactory with `update_with_traces` evidence |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate`; caller-alloc INIT producer channel recovers in-place initializers (`deflateInit_`) as creators, SVF-write-gated. Detail: `docs/generation.md` G1. |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | `AutomatonArtifact` |
| **APISemanticModel** (G1) | `liberator_adapter/analysis/api_semantic_model.py` | `reconcile()` → per-API role+arg semantics+evidence; role authority (demotes ConditionManager); 0 LLM; Step 5g. |
| **Sequence Constructor** (G2) | `liberator_adapter/analysis/sequence_constructor.py` | `construct_sequences()` builds lifecycle-complete chains, merged with grammar floor at Step 5h. `_densify()` thickens chains (default-on); factory-chain opaque-producer recovery (default-on). |
| **Hole Semantics** (G4) | `liberator_adapter/analysis/hole_semantics.py` | `annotate_skeletons()` attaches per-arg value intents at Step 10b. `_hard_nullguard()` (default-on) escalates ret-contract to MUST-GUARD. |
| **Validity Contract** | `liberator_adapter/analysis/validity_contract.py` | Oracle for `LOGICFUZZ_VALIDITY_CONTRACT` — checks I1/I2a/I2b/I3 over a constructed sequence using the model's per-arg nullable. |
| **Crash-frame classifier** | `tools/merge_drivers/crash_frame.py` | `classify_crash_frame()` → driver/library/unknown (deterministic ASan frame attribution). |
| **Pre-ship quarantine** | `run_single_fuzz.py:_is_immediate_crash_fp` + `_maybe_merge_drivers` | drops immediate-crash 0-coverage FP drivers from the merge; uses the trial's own verdict. + dead-filter bugfix (`dead_on_empty`). |
| **Compile-validation merge gate** | `tools/merge_drivers/compile_validate.py:validate_compilable` + `run_single_fuzz.py:_compile_validate_candidates` | merge includes ONLY drivers that COMPILE under real OSS-Fuzz cov-build flags (per-TU C/C++, `-Werror=implicit-function-declaration` re-promoted) so address-build and cov-build compile the IDENTICAL set (A≡B). Fail-open; opt-out `LOGICFUZZ_SKIP_COMPILE_VALIDATE=1`; writes `merged/compile_validation.json`. |
| **Edge-weighted CDF dispatch** | `run_single_fuzz.py:_edges_weights_for` + `SynthesizedDriver.from_paths(mode=CDF, weights=…)` | preflight `edges_15s` weights the merged-harness CDF dispatch so high-interaction sub-drivers get a larger per-input share (was uniform). Missing ⇒ median, none ⇒ uniform. |
| **Keep-best + file-restore** | `src/workflow/nodes/execution.py:_keep_best` | never ship a driver worse than the trial's peak; restores the kept source to disk on rollback. |
| **Coverage Gap** (G5) | `liberator_adapter/analysis/coverage_gap.py` | `compute_gap_apis()` → baseline-uncovered APIs; directs Step 5h toward the gap. |
| Comprehender | `src/knowledge/comprehender.py` | Two-stage knowledge extraction. Detail: `docs/knowledge_layer.md`. |
| **Phase B Idiom Distiller** | `src/knowledge/idiom_distiller.py` | 10 L1 deterministic patterns; writes `state/idioms.json` |
| **Phase C Coverage Memory** | `src/state/coverage_memory.py` | `CoverageMemory` + `IterationSnapshot`; writes `state/coverage_memory.json` |
| **Phase D Path Planner** | `src/state/path_planner.py` | Idiom-align rerank + synthesize_missing; writes `state/plan_ledger.json` |

### Progressive Filter Pipeline (`liberator_adapter/constraints/`)

Multi-layer filtering: **Type compatibility ≠ Semantic validity ≠ High coverage**.

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Reachability Ranking → Top-K
              (~1000)    (~100)      (~30)          (~10)            (acceptance_score-first)   (K=12)
                                                          ↑ Project-adaptive automaton signal
```

This L0–L4 path produces the **grammar floor** (a guaranteed
CBFactory-synthesizability safety net); the lead candidates are Step 5h
model-driven construction, merged onto that floor. (L5 deleted in G3 — see Failed
Attempts.)

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct buffer + indirect `IndirectEntryPoint(creator, consumer)` pairs |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L4 | `coverage_ranker.py` | Reachability-first (G3): `acceptance_score` primary sort, diversity tiebreak, greedy Top-K |

**Use-def + typestate substrate** (`usedef.py`): `APIEffect` per API feeds L4,
Prototyper (via automaton), and Comprehender. L1 (handle classification) + L2/L3
(per-sequence validation) delegate here; L2/L3 build a per-analysis `UseDefGraph`
and call `Typestate.check`. Domain *discovery* lives in each Lx file; the *walker*
is shared.

### Z3-Guided Synthesis (`liberator_adapter/constraints/`)

| Component | File | Purpose |
|-----------|------|---------|
| `IncrementalZ3Solver` | `z3_guided_synthesis.py` | push/pop for decision guidance |
| `Z3GuidedSynthesisController` | `z3_guided_synthesis.py` | TYPE_MATCH, PROVENANCE, RESOURCE_LIFECYCLE, VARIABLE_AVAILABILITY |
| `AutomatonAcceptanceGuard` | `z3_guided_synthesis.py` | Phase H hard-pruning gate (positive-only) |
| `Z3SequenceValidator` | `z3_solver.py` | Position-indexed lifecycle validation (#4) + LLVM-IR byte-buffer exemption (#73) |
| UnsatCoreDiagnoser | `z3_guided_synthesis.py` | Failure diagnosis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | L2 `lifecycle_analyzer.py` + shared `usedef.py` `Typestate` walker (former `sequence_filter.py`/`LLMLifecycleValidator` removed) |
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY). Demoted by G1 to one IR-evidence source feeding `APISemanticModel.reconcile`. |

## Project-Adaptive Automaton + Closed-Loop

Per-project typestate automaton learned from the library's own tests/examples
(`project_automaton.py`); the Phase G closed loop (`src/closed_loop.py`, Step 11,
`--closed-loop`/`--closed-loop-iters N`/`--closed-loop-early-stop K`) grows it from
Z3-viable sequences each round. Mechanics are SSOT in `docs/knowledge_layer.md`.
Persistence: `results/{project}/{automaton,comprehension,state}/`.

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks — explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: categorize build errors (link/header/type) for targeted fixing.
- **Token Efficiency**: context prefetching, 8KB truncation, deterministic-first Comprehender + automaton prefilter. Per-run cost metered (`src/utils/token_meter.py`) → `results/<project>/token_summary.json`.
- **Signal vs Filter**: the automaton produces *signals* (acceptance, sampled paths, grafting) that bias the candidate pool/ranking; greedy max-coverage selection is unchanged.
- **Reuse upstream Liberator over reimplementation**: check `reference/liberator` first; adapt at the boundary, don't fork.
- **Coverage measurement (A≡B / valid-harness)**: address-build and cov-build must compile the IDENTICAL harness, else replayed coverage is spurious (enforced by the compile-validation gate; `docs/generation.md` §6).

## Validation Pipeline

`UnifiedCodeValidator` (`src/utils/unified_validator.py`) replaces the former 4
validators. Build errors are triaged by `src/utils/compilation_error_triage.py`
into link/header/type buckets for the Fixer. Hallucinated defs + internal API
calls are fatal; other issues pass to the Fixer.

## Implementation Flow

```python
# In FuzzingContext.prepare()  (src/context/data_context.py)
Step 1    ProjectDriverGenerator init
Step 2    Extract APIs
Step 3    Build dependency graph                 # L0: type compatibility
Step 3.5  Build data layout                       # must precede grammar gen
Step 4    Generate sequences (grammar)
Step 5b   Build ConditionManager
Step 5c   L1 Entry-point filter
Step 5d   L2 Lifecycle filter
Step 5e   L3 State-machine filter
Step 5f   L4 reachability ranker (grammar floor)
Step 5e2  learn_project_automaton                (after 5f)
Step 5g   Build APISemanticModel                 (G1)
Step 5h   Construct sequences from model + merge onto floor  (G2+G5)
Step 6b   Comprehender A+B
Step 7    Header extraction
Step 8    Existing-fuzzer header extraction
Step 9    DriverEnhancer pattern analysis
Step 10   Phase D Planner + Z3-validated skeleton drivers
Step 10b  Semantic value-intent on holes         (G4)
Step 11   Closed-loop iterations                 (Phase G, opt-in)
Step 12   Existing-driver knowledge extraction + Phase B idiom distillation
# Post-merge: Phase C IterationSnapshot persisted by run_single_fuzz.py
```

## Recent Keystone Fixes

- **Stock-binary build bug** — cached builds compiled the STOCK fuzzer, not the generated driver (`oss_fuzz_checkout._invalidate_stale_cache_dockerfiles`).
- **no_progress gate KEPT** for the merged harness; only `dead_on_empty` crashers dropped (`LOGICFUZZ_DROP_NO_PROGRESS=1` to drop).
- **Crash-path merge exclusion** — `StateAdapter` now propagates `compiles` so compiled-but-crashed drivers aren't lost from the merge.
- **Valid-by-construction binding** (gated `VALIDITY_CONTRACT`) — Z3-path opaque-handle binding made drivers dead→live (lcms merged ~0→21%; one driver covers ~1000 liblcms2 br, was 0).
- **Breadth to the extraction ceiling** — `RESIDUAL_ALLCOVER` + portfolio API-floor (cjson 78/78 = PromeFuzz count, c-ares 138≥136, lcms 149→297).
- **Merge-include root-fix** — pass the stock fuzzer's dir as `-iquote dirname(target_path)` so a relocated driver's `#include "../cJSON.h"` resolves identically in compile-validation + merged build (cjson harness 0→53 drivers).
- **Merged-coverage measurement** — recover the number via `llvm-cov` on the surviving `dumps/merged.profdata` (the live replay hangs).

## Open TODOs

- 2026-06-19: 实现deepseek的思考模式支持： https://api-docs.deepseek.com/guides/thinking_mode

Live frontier = **coverage vs PromeFuzz** on unsaturated, breadth-matched libs
(c-ares/libpng/sqlite3); lead the eval on quality/efficiency/complementarity, NOT
raw 24h (PromeFuzz saturates small libs). Start from `docs/generation.md`.

- **The headline test**: a 24h `--merge` run on a breadth-matched config (`VALIDITY_CONTRACT + RESIDUAL_ALLCOVER + API_FLOOR + PORTFOLIO_DEPTH=2`) vs PromeFuzz Table 2 — on the breadth-matched libs only.
- Verify residual single-API drivers compile+run end-to-end (a `nullable=True`-handle residual driver may be shallow; lcms-style `nullable=False` gets a creator prepended).
- F6 Phase C CEGAR loop (post-merge, gap-directed, cross-round; prereq WorkingMemory) + F7 L2 LLM idioms.
- Synthetic/structural (TLV) seed gen — real-seed routing + T10 front-gate seed landed; a valid DEEP file still TODO.
- libaom path resolution; batch eval aggregator → Table 2; SVF ≥4h re-run for libtiff/libvpx `conditions.json`.

(Resolved/landed — orphaned optimize-loop removed, build-cache×llvm14 `ensure_llvm14_base_builder`, SVF caps `LIBERATOR_SVF_{TIMEOUT_SECS,MEM_GB}`, skeleton-rendering validity, real-seed routing — are in git history / `generation.md`.)

## Failed Attempts / Lessons

Guardrails — read before re-litigating. Full detail in git history.

- **Don't reintroduce a novelty pre-filter as a hard gate** (deleted L5
  `coverage_aware_filter.py`). Novelty-vs-baseline suppresses total coverage and
  doesn't predict reachability. Rank by reachability (`acceptance_score`, G3); target
  the gap positively via G5.
- **Lifecycle order constraints are position-indexed, not over the API-name set**
  (`Z3SequenceValidator._check_lifecycle_position_indexed`, 2026-05-22). All-pairs
  name-set quantification made chained-builder APIs (cjson `cJSON_Add*`) self-cyclic
  → all-UNSAT. Don't revert to set-based.
- **§10B baseline-regression recovery belonged post-merge, not per-trial**
  (`BaselineDiffAnalyzer`, REMOVED). Per-trial granularity wasted LLM calls; if
  revived, it belongs in the Phase C CEGAR loop (`generation.md` F6) — post-merge,
  cross-round, NOT a per-trial node.
- **Don't chase raw 24h coverage vs PromeFuzz on SATURATED libs** (2026-06-17
  systematic-debug). PromeFuzz Table 2 = 24h-AFL++/GCOV, ~98% on small libs;
  exceeding a saturated baseline needs comparable fuzz time (arithmetic). Our
  metric (llvm-cov) AGREES with gcov (cjson 48.7%≈49.9%) — no measurement win to
  find. Compete on quality/efficiency/complementarity, and on raw coverage only
  where PromeFuzz is unsaturated AND our breadth ≥ theirs. Don't burn a 24h run on
  a 149-API config — it hits a link-time reachability wall (lcms 443 fns); run it
  only breadth-matched.
- **Merged-coverage llvm-cov replay HANGS on the dispatcher binary** (slow/looping
  input, no per-input timeout → 1800-2400s timeout → 0%). Don't trust a 0%/stale
  snapshot as final. Measure from the surviving `dumps/merged.profdata` via
  `llvm-cov export`, or sample the corpus (`run_extended_fuzzing._measure_coverage`).
