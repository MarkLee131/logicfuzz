# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Knowledge-Driven Neuro-Symbolic Fuzz Driver Generation over Structured API Program Spaces.

**Generation stage**: see `docs/generation.md` (source of truth for driver
generation). The pipeline is reconcile-then-construct — build an
`APISemanticModel` first (IR ⊕ doc ⊕ usage), then *construct* lifecycle-
complete sequences from it, so candidates are valid by construction and there
is no repair stage. (The old "classify-then-repair" flow — Phase A repair +
Tier-1 F1–F4 — was deleted; it band-aided the missing model downstream.)

## Commands

```bash
# Run on a benchmark
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Extract APIs only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Generate drivers with CBFactory only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Phase G (existing): closed-loop CBFactory feedback (re-synthesise with grown automaton)
python3 run_logicfuzz.py -y comparison/cjson.yaml --closed-loop --closed-loop-iters 3 \
                        --closed-loop-early-stop 0

# A/B: disable G2 model-driven construction, fall back to random-walk grammar
LOGICFUZZ_DISABLE_G2_CONSTRUCT=1 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Generation features now DEFAULT-ON (gates removed 2026-06 — flag cleanup):
# factory chain (opaque void*-return producer recovery), density + hard NULL-guard
# (coupled; density-only is ablation-proven harmful), max-coverage diversity
# selection, real seed-corpus routing (*.icc/*.it8/… by parser-entry API + magic),
# deterministic lean crash triage + skip per-driver optimize, typedef-handle
# recovery. Measured lcms 30s (density+guard, now default): 66→206 br, FP 1→0.
#
# Remaining knobs — tuning values + A/B kill-switches (the only LOGICFUZZ_* left):
#   LOGICFUZZ_TOP_K=N             skeleton/driver count = the UNION-breadth lever
#                                 (default filter_top_k=10; needs NO_CACHE=1 to
#                                 regen skeletons). Target ≈ PromeFuzz drivers/2.5.
#   LOGICFUZZ_DENSE_MAX_EXTRA=N   cap extra APIs appended per chain (default 8 →
#                                 ~7.7 APIs/seq lcms = PromeFuzz parity).
#   LOGICFUZZ_DENSE_COOCCUR=0     density extends ONLY handle-sharing (drop the
#                                 automaton-co-occurrence source; default on).
#   LOGICFUZZ_STRICT_ORDERING=1   revert B graceful degradation (drop orphan
#                                 USE_BEFORE_INIT instead of keeping as a hole).
#   LOGICFUZZ_DISABLE_{G2_CONSTRUCT,DRIVER_TRACES,SEQFACTS,LLM_ROLES,
#                       BASELINE_RECOVERY}=1   A/B kill-switch for that default-on stage.
#   LOGICFUZZ_{Z3_MODE,CONSTRUCT_MODE,NO_CACHE,TRIAGE_INCONCLUSIVE,
#              TRIAGE_PREFIX_LEN,DRIVERS_ROOT,FI_ENDPOINT,BINDING_TELEMETRY}   config values.
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_TOP_K=56 \
  python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers

# Synthesize a multi-task harness from successful trials at the eval tail
python3 run_logicfuzz.py -y comparison/cjson.yaml --merge-drivers

# Evaluation profile: bundles --closed-loop + --merge-drivers
python3 run_logicfuzz.py -y comparison/cjson.yaml --eval

# Multi-hop reasoning Mode A (Prototyper); opt-in
python3 run_logicfuzz.py -y comparison/cjson.yaml --multihop-prototyper

# Knowledge-layer priors (Phase B / T1)
python3 run_logicfuzz.py -y comparison/cjson.yaml --use-doxygen-priors --use-readme-purpose

# Control parallelism
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Code quality
pylint src/ && pyright src/
pytest tests/   # 121 P0/P1 regression tests as of 2026-05-23

# Extended fuzzing evaluation (24h)
python scripts/run_extended_fuzzing.py -p re2 -f results/output-re2-project/fuzz_targets/02.fuzz_target -d 86400
```

`--num-samples` is auto-resolved at runtime to `len(skeleton_drivers)`
(one trial per Z3-validated skeleton). See `run_single_fuzz.py:_fuzzing_pipelines`.

## Docs

| Doc | Subsystem |
|-----|-----------|
| `docs/generation.md` | **SoT for driver generation.** The built G1–G5 pipeline (APISemanticModel → construct → gap-direct → rank → semantic holes), the three load-bearing lessons, the open binding-layer bottleneck, and surrounding-phase status + roadmap (B/C/D landed, E/F5–F7 open). Start generation work here. |
| `docs/knowledge_layer.md` | PromeFuzz-derived comprehender (two-stage, deterministic-first, ~70× cheaper). Automaton mechanics live in the `Project-Adaptive Automaton` section below. |
| `docs/contributions_and_related_work.md` | **Contributions pitch (3 innovations vs prior work) + objective comparison vs PromeFuzz (neural baseline) and Liberator (symbolic baseline).** |
| `docs/llm_vs_traditional_choices.md` | Per-LLM-call-site rationale: symbolic alternative considered, why LLM won, falsifiable measurement to revisit. |

Historical proposals and refactor logs live in git history (`git log --grep`).

## Architecture

```
run_logicfuzz.py → FuzzingContext (SSOT) → FuzzingWorkflow (LangGraph) → Evaluation
                         ↑                        ↓
              Static Analysis (Liberator)    Agent System
                         │
            ┌────────────┴────────────┐
            │                         │
   Project-Adaptive Automaton   Knowledge Layer
   (analysis/ static traces →   (knowledge/ comprehender +
    PTA → EDSM → Artifact)       Phase B idiom distiller)
            │                         │
            ▼                         ▼
   APISemanticModel (G1) ◀── reconcile IR⊕doc/naming⊕usage
            │
            ▼
   Sequence Constructor (G2)   ── creator→mutator*→consumer→destroyer
   (gap-directed targets, G5;      lifecycle-complete by construction
    prepend to grammar floor;      ranked by gap-hits then reachability
    Typestate self-filter)         (G3+G5)
            │
            ▼
       Z3 confirm (type/var only — lifecycle correct by construction)
            │
            ▼
       skeleton_drivers + value-intents (G4) → trials × N → merge_drivers
            │
            ▼
       Phase C IterationSnapshot → coverage_memory.json
```

### Workflow State Machine

```
COMPILATION:  prototyper → build → [fail] → fixer (×3) → END
                                 → [ok]  → OPTIMIZATION

OPTIMIZATION: execution → [crash] → crash_analyzer → feasibility → END/fixer
                        → [ok]    → coverage_analyzer → improver → END
```

Per-trial caps live as module constants at the top of
`src/workflow/nodes/supervisor.py` (compilation retries, fixer cap,
total build failures, node-visit loop detection). Read them there;
duplicating here just rots.

### Agent System (`src/agents/`)

| Agent | Tools | Purpose |
|-------|-------|---------|
| Prototyper | - (context pre-fetched) | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants`, `skeleton_drivers[(N-1) % K]`, **Phase B idioms** |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CoverageAnalyzer | BashExecuteTool | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | BashExecuteTool, GDBExecuteTool | Determine if crash is driver bug or real bug |
| Improver | - (context pre-fetched) | Improve coverage based on analyzer suggestions |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| BaselineDiffAnalyzer (§10B) | - | Triggered on baseline-regression alert. Granularity under reconsideration — see Failed Attempts / `generation.md` F6 |
| Comprehender (non-LangGraph stage) | LLM batched | A: per-API usage + library purpose. B: per-sequence semantic verdict |

**Tool Consolidation**: All introspector-derived context (signatures,
cross-refs, type defs, headers, tests, debug types) is pre-fetched
into `FuzzingContext` before agent turns. Remaining LangGraph tools:
- `BashExecuteTool` (`src/tools/execution.py`): unified bash, 8KB output truncation
- `GDBExecuteTool` (`src/tools/execution.py`): scripted GDB session for crash triage

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT |
| Supervisor | `src/workflow/nodes/supervisor.py` | Agent routing, phase management |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop |
| UnifiedCodeValidator | `src/utils/unified_validator.py` | Single-pass validator (fake-defs, internal APIs, language mismatch, hallucination) |
| Closed-loop (Phase G existing) | `src/closed_loop.py` | Re-runs L4+CBFactory with `update_with_traces` evidence |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate` interpreter; **caller-alloc INIT producer channel** (`annotate_svf_writes` + `extract_produced_handles`) recovers in-place initializers (`deflateInit_(z_stream*)`) as creators, SVF-write-gated via `conditions.json`. Detail: `docs/generation.md` G1. |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | `AutomatonArtifact` |
| **APISemanticModel** (G1) | `liberator_adapter/analysis/api_semantic_model.py` | `reconcile()` → per-API role+arg semantics+evidence; role authority (demotes ConditionManager); 0 LLM; Step 5g. Detail: `docs/generation.md`. |
| **Sequence Constructor** (G2) | `liberator_adapter/analysis/sequence_constructor.py` | `construct_sequences()` builds lifecycle-complete chains, **merged with** the grammar floor at Step 5h. A/B: `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1`. B graceful degradation keeps orphan-handle sequences (kill-switch `LOGICFUZZ_STRICT_ORDERING`); `_densify()` thickens chains (**default-on**; tune via `LOGICFUZZ_DENSE_MAX_EXTRA`/`_COOCCUR`); factory-chain opaque-producer recovery (**default-on**). |
| **Hole Semantics** (G4) | `liberator_adapter/analysis/hole_semantics.py` | `annotate_skeletons()` attaches per-arg value intents at Step 10b (rendered into the hole prompt). `_hard_nullguard()` (**default-on**) escalates ret-contract to `MUST-GUARD` + opaque factory-chain hint. |
| **Crash-frame classifier** | `tools/merge_drivers/crash_frame.py` | `classify_crash_frame(asan_log, driver_basename)` → driver/library/unknown (deterministic ASan frame attribution; driver-bug FP vs real library bug). |
| **Pre-ship quarantine** | `run_single_fuzz.py:_is_immediate_crash_fp` + `_maybe_merge_drivers` | drops immediate-crash 0-coverage FP drivers from the merge (poison the fused harness); binary-free, uses the trial's own verdict. + dead-filter bugfix (`dead_on_empty`). |
| **Keep-best + file-restore** | `src/workflow/nodes/execution.py:_keep_best` | never ship a driver worse than the trial's peak (all paths); restores the kept source **to disk** on rollback (else merge ships the regressed file). |
| **Coverage Gap** (G5) | `liberator_adapter/analysis/coverage_gap.py` | `compute_gap_apis()` → baseline-uncovered APIs; directs Step 5h construction+ranking toward the gap. |
| Comprehender | `src/knowledge/comprehender.py` | Two-stage knowledge extraction. Detail: `docs/knowledge_layer.md`. |
| **Phase B Idiom Distiller** | `src/knowledge/idiom_distiller.py` | 10 L1 deterministic patterns; writes `state/idioms.json` |
| **Phase C Coverage Memory** | `src/state/coverage_memory.py` | `CoverageMemory` + `IterationSnapshot`; writes `state/coverage_memory.json` |
| **Phase D Path Planner** | `src/state/path_planner.py` | Idiom-align rerank + synthesize_missing; writes `state/plan_ledger.json` |

### Progressive Filter Pipeline (`liberator_adapter/constraints/`)

Multi-layer filtering: **Type compatibility ≠ Semantic validity ≠ High coverage**

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Reachability Ranking → Top-K
              (~1000)    (~100)      (~30)          (~10)            (acceptance_score-first)   (K=12)
                                                                                ↑
                                                          Project-adaptive automaton signal
```

This L0–L4 path now produces the **grammar floor** (a guaranteed
CBFactory-synthesizability safety net); the lead candidates are Step 5h
model-driven construction, merged onto that floor. (L5 was deleted in G3 — see
Failed Attempts.)

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct buffer + indirect `IndirectEntryPoint(creator, consumer)` pairs |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L4 | `coverage_ranker.py` | **Reachability-first** (G3): `acceptance_score` primary sort, diversity tiebreak, greedy Top-K |

**Use-def + typestate substrate** (`liberator_adapter/analysis/usedef.py`):
`APIEffect` (USE/DEF/KILL) per API feeds L4, Prototyper (via automaton), and Comprehender.
L1 (handle classification) and L2/L3 (per-sequence validation) both delegate here.
L2/L3 build a per-analysis `UseDefGraph` from their domain model (lifecycle pairs / state constraints) and call `Typestate.check`. Domain-specific *discovery* still lives in each Lx file; the *walker* is shared.

### Z3-Guided Synthesis (`liberator_adapter/driver/factory/constraint_based/`)

| Component | File | Purpose |
|-----------|------|---------|
| IncrementalZ3Solver | `z3_solver.py` | push/pop for decision guidance |
| Z3-guided controller | `z3_guided_synthesis.py` | TYPE_MATCH, PROVENANCE, RESOURCE_LIFECYCLE, VARIABLE_AVAILABILITY |
| `AutomatonAcceptanceGuard` | `z3_guided_synthesis.py` | Phase H hard-pruning gate (currently positive-only) |
| `Z3SequenceValidator` | `z3_solver.py` | **Position-indexed** lifecycle validation (#4 fix, 2026-05-22) + LLVM-IR byte-buffer exemption (#73) |
| UnsatCoreDiagnoser | `z3_guided_synthesis.py` | Failure diagnosis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | `LLMLifecycleValidator` in `sequence_filter.py` |
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY). **Demoted by G1** to one IR-evidence source feeding `APISemanticModel.reconcile`; no longer the role authority. |

## Project-Adaptive Automaton

Per-project typestate automaton learned from the library's own tests/examples. The comprehender that consumes it: `docs/knowledge_layer.md`.

Pipeline (all in `liberator_adapter/analysis/`):
`extract_project_traces` → `extract_api_effects` → `build_pta` →
`edsm.merge` → `learn_project_automaton() → AutomatonArtifact`.
State vector = `frozenset[(handle_type, lifecycle_state)]`. EDSM merging is
*constructive*: every input trace stays accepted after every merge; an
oracle-vetoed merge is skipped, never weakened. Selection over the
automaton-augmented pool is budgeted max-coverage ((1−1/e) greedy).

`AutomatonArtifact` surface (consumers in parens):
- `acceptance_score(seq)` — L4 **primary** sort axis (G3; diversity demoted to tiebreak when an automaton is present), Comprehender-B positive-only prefilter, Phase H guard
- `sample_accepting_paths(n)` — L4 pool augmentation, Prototyper `<protocol_templates>`
- `graft_creator_prefix(seq)` — L4 candidate variants (Phase A repair, its other consumer, was deleted in G2)
- `post_parse_extensions(seq)` — extends `parse → get_object` prefixes via `extend_post_def`
- `update_with_traces(traces)` — Phase G incremental EDSM merge

Persistence: `results/{project}/automaton/`. Comprehender output: `results/{project}/comprehension/`. Phase A/B/C/D state: `results/{project}/state/`.

## Closed-Loop Synthesis (Phase G, existing)

Distinct from the proposed Phase C CEGAR loop (which is for cross-iteration coverage feedback; see `generation.md` F6).

Phase G grows the automaton each round using current viable Z3 skeletons' API sequences as evidence (incremental EDSM merge). Skeletons drive the LLM; closed-loop's value is the in-place mutation of `automaton_artifact` preserved through `persist_dir`.

Entry: `src/closed_loop.py:run_closed_loop`. Wired into `data_context.py` Step 11.

CLI: `--closed-loop`, `--closed-loop-iters N`, `--closed-loop-early-stop K`.

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks — explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Token Efficiency**: Context prefetching, 8KB output truncation. Comprehender uses deterministic-first layering and automaton acceptance prefilter.
- **Signal vs Filter**: The automaton produces *signals* (acceptance, sampled paths, grafting) that augment the candidate pool and bias ranking; the greedy max-coverage selection is unchanged.
- **Reuse upstream Liberator over reimplementation**: When fixing a synthesis-layer problem, first check whether `reference/liberator` already solves it. Adapt at the boundary; don't fork.

## Validation Pipeline

`UnifiedCodeValidator` (`src/utils/unified_validator.py`) replaces the former 4 validators (fake-defs, language mismatch, internal APIs, API hallucination). Build errors are then triaged by `src/utils/compilation_error_triage.py` into link/header/type buckets for the Fixer. Hallucinated defs and internal API calls are fatal; other issues pass to the Fixer.

## Implementation Flow

```python
# In FuzzingContext.prepare()  (src/context/data_context.py)
Step 1   ProjectDriverGenerator init
Step 2   Extract APIs
Step 3   Build dependency graph                  # L0: type compatibility
Step 4   Generate sequences (grammar)
Step 5   Build data layout
Step 5b  Build ConditionManager
Step 5c  L1 Entry-point filter
Step 5d  L2 Lifecycle filter
Step 5e  L3 State-machine filter
Step 5f  L4 reachability ranker (grammar floor)
Step 5e2 learn_project_automaton                 (runs after 5f)
Step 5g  Build APISemanticModel                  (G1)
Step 5h  Construct sequences from model + merge onto floor   (G2+G5)
Step 6b  Comprehender A+B
Step 7   Header extraction
Step 8   Existing-fuzzer header extraction
Step 9   DriverEnhancer pattern analysis
Step 10  Phase D Planner + Z3-validated skeleton drivers
Step 10b Semantic value-intent on holes          (G4)
Step 11  Closed-loop iterations                  (Phase G, opt-in)
Step 12  Existing-driver knowledge extraction + Phase B idiom distillation
# Post-merge: Phase C IterationSnapshot persisted by run_single_fuzz.py
```

## Open TODOs

Generation (G1–G5) has landed; the live frontier is now **below** it. Start
new work from `docs/generation.md` (open bottleneck + roadmap):

- **⚠ DECISION NEEDED — orphaned optimize subsystem: keep-redesigned, or remove?**
  Lean crash-triage + skip-per-driver-optimize is now the **default** (gate
  removed). So the per-driver coverage-optimize loop is **unreachable**: a clean
  build+run returns END directly. Dead-but-still-present: graph nodes
  `coverage_analyzer` → `improver` and `baseline_diff_analyzer` (§10B regression
  recovery) (`src/workflow/workflow.py`), their agents
  (`CoverageAnalyzer`/`Improver`/`BaselineDiffAnalyzer`), and
  `supervisor._handle_coverage_improvement`. (The *crash* LLM nodes are NOT
  orphaned — they keep the unknown-frame fallback; only the *optimize* path lost
  its route.) **Two options:**
  - **Remove** — delete those 3 nodes + agents + `_handle_coverage_improvement` +
    their graph edges. Cleanest if "breadth from many-drivers + merge + diversity
    + gap-direction" is the final stance (per-driver LLM refinement is then dead
    weight).
  - **Keep, redesigned to FIT the current tool** — the old loop was *per-driver*
    LLM refinement (N× cost), mismatched with the breadth-via-merge design. A
    fitted version is **portfolio/union-level + gap-directed + cross-round**, not
    per-trial: after merge, compute the *union* coverage gap (reuse G5
    `coverage_gap`), then run ONE targeted optimize/re-gen pass on the
    under-covered gap APIs — i.e. fold it into the proposed **Phase C CEGAR loop**
    (`generation.md` F6, prereq WorkingMemory). §10B baseline-diff belongs there
    too (post-merge, cross-round — see Failed Attempts, "belongs post-merge, not
    per-trial"). Cost: ~1 pass/round vs N drivers.
  Until decided the subsystem is **dead code kept in place** — don't rely on it.

- **Input/seed layer (NEW #1 below binding) — real-seed routing landed (gated).**
  Factory chain made `cmsDoTransform` constructable + compilable (lcms opaque args
  0→77/128), but a degraded-30s probe covered **0/799 of `cmsxform.c`**: random
  bytes never form a valid ICC profile → `cmsCreateTransform` NULL → guard →
  `cmsDoTransform` never runs. Real-seed routing (**default-on**, gate removed)
  routes the project's REAL format-matching seeds (`*.icc`/`*.it8`/…, by
  parser-entry API + file magic) into each driver's generation-phase corpus +
  the merged harness (`scripts/seed_discovery.py` `seed_corpus_for_driver` →
  `builder_runner._seed_corpus_dir`). Remaining: **measure** the cmsxform.c gain
  end-to-end, and synthetic seed generation from format analysis (still TODO).
  See `docs/generation.md` §6.
- **build-cache × llvm14 — RESOLVED by A1 (additive canonical base).** Cached runs
  used to silently degrade to Z3-OFF (reused non-clang-14 image → clang-only →
  empty `function_conditions`). Fix: `ensure_llvm14_base_builder()` builds the
  *additive* llvm14 image (clang-14 at /usr/lib/llvm-14; default `/usr/local` clang
  + libc++ untouched → fuzzers still link) and retags it onto
  `gcr.io/oss-fuzz-base/base-builder`, so every project + cache image inherits
  clang-14 — one image serves extraction + trials (no patch, no isolation, no
  bypass). Called before `prepare_cached_images`. **One-time deploy step:** OFG
  cache images are registry-hosted (pull-first) — rebuild + re-push the
  `*-ofg-cached-*` images on the additive base (or `OFG_USE_CACHING=0`) so cached
  eval is Z3-on. Memory `project_buildcache_llvm14_conflict`; `docs/generation.md` §4.
- **Binding layer (#14) — construction lifted, tail remains.** Factory chain
  recovers `cmsCreate*`-named opaque producers; remaining: residual
  non-`Create*`-named / no-in-project-producer tail + caller-alloc-init args beyond
  the SVF-INIT channel. See `docs/generation.md` §5/§6.
- **Feedback layers** — F5 adaptive shape (error-injection skeletons), F6 Phase C
  CEGAR loop (prereq: WorkingMemory), F7 L2 LLM idioms. See `docs/generation.md`.
- LLM equivalence oracle production throttling (`enable_llm_oracle=False` in `data_context.py:Step 5e2` until cost-aware pacing lands).
- libaom path resolution — `src_ossfuzz/libaom/` layout doesn't match the consumer-paths probe.
- Batch evaluation aggregator — auto-aggregate `scripts/batch_extended_fuzzing.sh` output into PromeFuzz Table 2 format.
- TLV-aware seed generation based on format analysis. (Partial: `scripts/seed_discovery.py` now feeds the project's REAL on-disk seeds — `*.icc`/`*.it8`/OSS-Fuzz `*_seed_corpus.zip` — into continuous/extended fuzzing so parser-entry drivers reach deep code; synthetic generation from format analysis is still TODO.)
- Cross-phase information flow (write-only JSON state, WorkingMemory prereq for F6) — see `generation.md`.

## Failed Attempts / Lessons

Guardrails — read before re-litigating. Full detail in git history.

- **Don't reintroduce a novelty pre-filter as a hard gate** (the deleted L5
  `coverage_aware_filter.py`). Novelty-vs-baseline is a proxy that suppresses
  total coverage and doesn't predict reachability. Rank by reachability
  (`acceptance_score` primary, G3); target the gap positively via G5.
- **Lifecycle order constraints are position-indexed, not over the API-name
  set** (`Z3SequenceValidator._check_lifecycle_position_indexed`, resolved
  2026-05-22). All-pairs name-set quantification made chained-builder APIs
  (cjson `cJSON_Add*`) self-cyclic → all-UNSAT. Don't revert to set-based.
- **§10B baseline-regression recovery belongs post-merge, not per-trial**
  (`BaselineDiffAnalyzer`, under reconsideration). Per-trial granularity wastes
  LLM calls; to be folded into the Phase C CEGAR loop (`generation.md` F6).
