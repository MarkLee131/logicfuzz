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
# (--no-coverage-filter is now a no-op: L5 was deleted in G3)

# Synthesize a multi-task harness from successful trials at the eval tail
python3 run_logicfuzz.py -y comparison/cjson.yaml --merge-drivers

# Evaluation profile: bundles --closed-loop + --merge-drivers (+ legacy --no-coverage-filter no-op)
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
| `docs/merge_drivers.md` | Multi-driver harness merger (`tools/merge_drivers`). |
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
| ProjectAnalyzer (pre-prototyper) | - | Derives `project_understanding` before driver synthesis |
| Prototyper | - (context pre-fetched) | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants`, `project_understanding`, `skeleton_drivers[(N-1) % K]`, **Phase B idioms** |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CoverageAnalyzer | BashExecuteTool | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | BashExecuteTool, GDBExecuteTool | Determine if crash is driver bug or real bug |
| Improver | - (context pre-fetched) | Improve coverage based on analyzer suggestions |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| BaselineDiffAnalyzer (§10B v2) | - | Triggered on baseline-regression alert. **Layer being reconsidered** — single-trial granularity wrong; should move to post-merge in CEGAR loop (see `generation.md` F6) |
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
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate` interpreter |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | `AutomatonArtifact` |
| **APISemanticModel** (redesign G1) | `liberator_adapter/analysis/api_semantic_model.py` | `reconcile()` fuses IR ⊕ doc/naming ⊕ usage → per-API `APISemantics` (role + arg semantics + evidence log). **New role authority** (demotes ConditionManager). Deterministic-only (0 LLM). Built at Step 5g; writes `state/api_semantic_model.json`. Structured doc signals via `project_docs.extract_doc_signals`. |
| **Sequence Constructor** (redesign G2) | `liberator_adapter/analysis/sequence_constructor.py` | `construct_sequences(model)` grows dependency-resolved creator→mutator*→consumer→destroyer chains. Step 5h **prepends** them to the grammar candidates (grammar kept as a guaranteed CBFactory-synthesizability floor), reachability-ranked, enlarged Z3 budget. Lifecycle-complete by construction, but NOT necessarily CBFactory-bindable (live lesson: lcms `void*` args) — hence merge, not replace. A/B via `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1`. Don't seed raw `sample_accepting_paths` as candidates (fragments). |
| **Hole Semantics** (redesign G4) | `liberator_adapter/analysis/hole_semantics.py` | `annotate_skeletons(skeletons, model)` attaches per-arg **value intents** (scalar→in/out-of-range, parser buffer→structured-input, length-pairing, output, live-handle) at Step 10b; the Prototyper renders them into the hole-filling prompt. Deterministic. |
| **Coverage Gap** (redesign G5) | `liberator_adapter/analysis/coverage_gap.py` | `compute_gap_apis(...)` reads the OSS-Fuzz **baseline textcov** → APIs the baseline never covers (lcms: 292/297). Step 5h directs construction (gap APIs as targets) + ranking (gap-hits primary) **toward** the gap, so drivers add NEW lines instead of re-covering baseline (the §10B `line_diff=0` problem). Positive successor to deleted L5. |
| Comprehender | `src/knowledge/comprehender.py` | Two-stage knowledge extraction |
| ~~Phase A Repair Engine~~ **DELETED (G2, 2026-05-25)** | — | `candidate_repair.py` + F1/F2/F4 removed. Construction is lifecycle-complete by construction, so repair was dead code. (`graft_creator_prefix` survives on `AutomatonArtifact` — still an L4 ranking signal.) |
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

**Post-G2/G3, this L0–L4 path produces the grammar candidates that Step 5h
keeps as a synthesizability *floor*.** The lead candidates are Step 5h
*model-driven construction* (`sequence_constructor.py`), prepended to that
floor and reachability-ranked. L5 (`coverage_aware_filter.py`, novelty
pre-filter) was **deleted in G3**; L4 ranking is now reachability-first
(`acceptance_score` primary, diversity
tiebreak).

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct buffer + indirect `IndirectEntryPoint(creator, consumer)` pairs |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L4 | `coverage_ranker.py` | **Reachability-first** (G3): `acceptance_score` primary sort, diversity tiebreak, greedy Top-K |
| ~~L5~~ | ~~`coverage_aware_filter.py`~~ | **DELETED (G3)** — novelty pre-filter was a proxy that suppressed total coverage |

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
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY). **Demoted by G1** — now one IR-evidence source feeding `APISemanticModel.reconcile`, no longer the role authority (still authoritative inside CBFactory/RunningContext until G2). |

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
Step 5f  L4 reachability ranker (fallback path)  (acceptance_score-first; L5 deleted in G3)
Step 5e2 learn_project_automaton                 (runs after 5f)
Step 5g  Build APISemanticModel                  (reconcile IR⊕doc/naming⊕usage; G1)
Step 5h  Construct sequences from model           (gap-directed targets + prepend to grammar floor; gap+reachability-ranked; G2+G5)
Step 6b  Comprehender A+B                        (uses acceptance_score + 5g role authority)
Step 7   Header extraction
Step 8   Existing-fuzzer header extraction
Step 9   DriverEnhancer pattern analysis
Step 10  Phase D Planner + Z3-validated skeleton drivers   (Phase A repair DELETED in G2)
Step 10b Semantic value-intent on holes          (per-arg intent from model; G4)
Step 11  Closed-loop iterations                  (Phase G, opt-in)
Step 12  Existing-driver knowledge extraction + Phase B idiom distillation
# Post-merge: Phase C IterationSnapshot persisted by run_single_fuzz.py
```

## Open TODOs

- LLM equivalence oracle production throttling (`enable_llm_oracle=False` in `data_context.py:Step 5e2` until cost-aware pacing lands).
- libaom path resolution — `src_ossfuzz/libaom/` layout doesn't match the consumer-paths probe.
- Batch evaluation aggregator — auto-aggregate `scripts/batch_extended_fuzzing.sh` output into PromeFuzz Table 2 format.
- TLV-aware seed generation based on format analysis. (Partial: `scripts/seed_discovery.py` now feeds the project's REAL on-disk seeds — `*.icc`/`*.it8`/OSS-Fuzz `*_seed_corpus.zip` — into continuous/extended fuzzing so parser-entry drivers reach deep code; synthetic generation from format analysis is still TODO.)
- Cross-phase information flow (write-only JSON state, WorkingMemory prereq for F6) — see `generation.md`.

## Failed Attempts / Lessons

Approaches we tried earlier and have since reworked. Read before re-litigating.

### L5 `CoverageAwareFilter` novelty pre-filter — DELETED (G3, 2026-05-25)

L5 dropped sequences with novelty < 0.2 vs existing OSS-Fuzz coverage. It is a
*proxy* that suppresses TOTAL coverage and does not predict reachability. The
redesign (G3) replaced it with reachability-first ranking (`acceptance_score`
primary in `coverage_ranker.py`) and **deleted the module**. The
`--no-coverage-filter` / `LOGICFUZZ_DISABLE_COVERAGE_FILTER` escape hatch is no
longer needed (there is nothing to disable). Don't reintroduce a novelty
pre-filter as a hard gate — rank by reachability instead.

### Z3 cyclic order constraints (resolved 2026-05-22)

Legacy `Z3SequenceValidator` quantified lifecycle order constraints over the **API-name set** ("∀c ∈ creates[T], u ∈ uses[T]: order_c < order_u"). For chained-builder APIs that are both creator and user (cjson's `cJSON_Add*` family), all-pairs expansion generated cyclic constraints → 10/10 sequences UNSAT.

**Fix landed `f7001cf7` + `7a140f80`**: position-indexed lifecycle validation in `Z3SequenceValidator._check_lifecycle_position_indexed`; LLVM-IR byte-buffer types exempt. cjson 0/10 → 7/10 SAT. Full root-cause analysis in commit message.

### §10B v1/v2 baseline-regression alert at per-trial granularity (under reconsideration)

`§10B` landed (commits `9b2cf883`, `f6dd60b6`) but operates at single-trial level. The proper unit is post-merge (multi-trial harness vs baseline). Per-trial recovery in `BaselineDiffAnalyzer` wastes LLM calls on the wrong granularity. To be folded into Phase C CEGAR loop (`generation.md` F6).
