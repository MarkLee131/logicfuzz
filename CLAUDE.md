# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Knowledge-Driven Neuro-Symbolic Fuzz Driver Generation over Structured API Program Spaces

## Commands

```bash
# Run on a benchmark
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Extract APIs only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Generate drivers with CBFactory only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Phase G: closed-loop CBFactory feedback (re-synthesise with grown automaton)
python3 run_logicfuzz.py -y comparison/cjson.yaml --closed-loop --closed-loop-iters 3 \
                        --closed-loop-early-stop 0

# Evaluation mode: disable L5 novelty filter (max total coverage vs baseline)
python3 run_logicfuzz.py -y comparison/cjson.yaml --no-coverage-filter

# Synthesize a multi-task harness from successful trials at the eval tail
python3 run_logicfuzz.py -y comparison/cjson.yaml --merge-drivers

# Evaluation profile: bundles --no-coverage-filter + --closed-loop + --merge-drivers
python3 run_logicfuzz.py -y comparison/cjson.yaml --eval

# Control parallelism
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Code quality
pylint src/ && pyright src/
pytest tests/ -v   # P0/P1 regression + telemetry tests

# Aggregate per-trial telemetry into per-error-class fix-success curves
python3 scripts/aggregate_build_attempts.py results/

# Extended fuzzing evaluation (24h)
python scripts/run_extended_fuzzing.py -p re2 -f results/output-re2-project/fuzz_targets/02.fuzz_target -d 86400
```

`--num-samples` is auto-resolved at runtime to `len(skeleton_drivers)`
(one trial per Z3-validated skeleton). See `src/runner.py:_fuzzing_pipelines`.

## Subsystem deep-dives

For non-obvious subsystems, the design + theory + empirical
justification + future-work plan lives in `docs/`:

| Doc | Subsystem | Status |
|-----|-----------|--------|
| `docs/automaton.md` | Project-adaptive automaton (PTA + EDSM) **and** the PromeFuzz-derived knowledge layer (comprehender shipped, ConstraintLearner design-only). Includes empirical justification across 25 benchmarks, A/B outcomes, future work. | shipped + forward-looking |
| `docs/merge_drivers.md` | Multi-driver harness merger (`tools/merge_drivers`); preflight + coverage-aware selection + weighted CDF dispatch + tail selector + corpus union. | shipped |
| `docs/upstream_liberator_diffs.md` | Upstream `reference/liberator` issues that the adapter has already fixed (or has a clear path to fix). Adapter-side bugs are NOT recorded here — they are work-in-progress fix items. | living |
| `docs/archived_2026_05_validated/synthesis_refactor_2026_05.md` | Per-cluster record of the 2026-05 synthesis-pipeline refactor: HoleFiller deletion, Z3 correctness fixes, B4 entry-point safety net, silent-fallback removal. Includes empty placeholder for post-run A/B coverage data. | living |
| `docs/llm_vs_traditional_choices.md` | For every place LogicFuzz invokes an LLM (Prototyper, Fixer, Crash{,Feasibility}Analyzer, Coverage{Analyzer,Improver}, Comprehender, ProjectAnalyzer): what symbolic alternative was considered, why LLM won, what we'd lose by reverting, and the falsifiable measurement that would prove the LLM choice wrong. | living |
| `docs/archived_2026_05_validated/filter_pipeline_refactor_2026_05.md` | Sequel to the synthesis refactor: 2026-05 review of L1–L5 filter pipeline. 4 high-priority cluster fixes (L1 const-buffer admit, L2 auto_complete strictness, L3 dead method removal, L1 dead-helper removal); 4 deferred items with rationale. Includes placeholder for post-run A/B data. | living |
| `docs/review_and_fix_log_2026_05.md` | **Canonical hand-off from static review → dynamic-run validation.** Per-fix table with file:symbol, what changed, expected dynamic-run observable. Combined run script template. List of components NOT YET reviewed with priority rationale. Update this when reviews land; fill post-run results into the per-cluster docs (synthesis_refactor / filter_pipeline_refactor / automaton_refactor), not here. | living |
| `docs/archived_2026_05_validated/automaton_refactor_2026_05.md` | Third in the refactor series: 2826-LOC automaton subsystem review (pta/edsm/project_automaton/usedef/static_trace/llm_oracle). 4 cluster fixes (A: EDSM oracle log visibility, B: acceptance adjacency caching, C2: multi-handle graft, E: default policy alignment). Includes deferred-with-rationale list and empty placeholder for post-run validation. | living |
| `docs/archived_2026_05_validated/cross_module_review_2026_05.md` | Global consistency audit of the three refactor commits. 10 cross-module invariants checked; 1 real regression caught (Factory.normalize_type ↔ Step 4 grammar gen ordering) and fixed by moving `build_data_layout` to Step 3.5. Documents the regression mechanism in detail so future cross-module audits can mimic the format. | living |
| `docs/agent_refactor_2026_05.md` | Fourth in the refactor series: 4316-LOC Agent subsystem review (base/tool_calling_mixin/utils/prototyper/fixer/crash_analyzer/crash_feasibility_analyzer/coverage_analyzer/improver/project_analyzer). 4 cluster fixes (B: Prototyper validator dead code + silent fallback, C: Improver hallucination-validation gate, A: 8KB truncate alignment, F: LLM transient-network retry). Includes deferred-with-rationale list and empty placeholder for post-run validation. | living |
| `docs/driverenhancer_refactor_2026_05.md` | Fifth in the refactor series: 430-LOC DriverEnhancer review. After synthesis cluster-2 deleted CallbackStubLibrary, DriverEnhancer is the sole callback-stub source. 3 fixes (issue #1: empty-stub had wrong signature, replaced with signature-aware default fallback; issue #2: READER template required driver-side context nobody emitted, now signature-safe no-op; issue #3: dead `enhance_context_get_function_pointer` decorator removed). Includes empty placeholder for post-run validation. | living |
| `docs/archived_2026_05_validated/supervisor_validator_refactor_2026_05.md` | Sixth in the refactor series: paired review of Supervisor (386 LOC) and UnifiedCodeValidator (771 LOC). Final fix: V1 replaces external CGProcessor binary with libclang-Python FunctionBodyWalker (no duplicate AST front-end; −1 external binary dep). V4: FUNCTION_WHITELIST extended to `__builtin_*` etc. V5: IGNORE_FUNCTIONS extended to common libc surface. Six other observations deferred with explicit downside analysis. | living |
| `docs/archived_2026_05_validated/comprehender_closedloop_refactor_2026_05.md` | Seventh in the refactor series: paired defect-hunt of Comprehender (489 LOC) and closed_loop.py (312 LOC). Q1: closed-loop docstring overpromised L4 re-rank — kept impl, fixed docs (alternative would saturate automaton in 1 iter). Q2: Comprehender-B's automaton prefilter now strength-gated. Q3: patched_sequence stays advisory (apply would need re-validation). Plus 5 secondary defects (CL2 dead metrics, CL5 per-iter persist, C2 greedy JSON regex → balanced scanner, C4 cache-poison fallback, C5 batch-fail dropped APIs → signature fallback). | living |

## Architecture

```
run_logicfuzz.py → FuzzingContext (SSOT) → FuzzingWorkflow (LangGraph) → Evaluation
                         ↑                        ↓
              Static Analysis (Liberator)    Agent System
                         │
            ┌────────────┴────────────┐
            │                         │
   Project-Adaptive Automaton   Knowledge Layer
   (analysis/ static traces →   (knowledge/ comprehender:
    PTA → EDSM → Artifact)       per-API usage + sequence
            │                    semantics)
            ▼                         ▼
     L4 Coverage Ranker       Prototyper protocol templates
     (acceptance_score,        + library_purpose +
      sample_paths,             sequence_invariants
      graft_creator_prefix)
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
| ProjectAnalyzer (pre-prototyper) | - | Derives `project_understanding` (library purpose, build conventions, invariants) before driver synthesis. Output consumed by Prototyper |
| Prototyper | - (context pre-fetched) | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants`, `project_understanding`, `skeleton_drivers[(N-1) % K]` from FuzzingContext |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CoverageAnalyzer | BashExecuteTool | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | BashExecuteTool, GDBExecuteTool | Determine if crash is driver bug or real bug |
| Improver | - (context pre-fetched) | Improve coverage based on analyzer suggestions |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| Comprehender (non-LangGraph stage) | LLM batched | A: per-API usage notes + library purpose. B: per-sequence semantic verdict, optional repair, prototyper invariants. Stored in `FuzzingContext.comprehension` and `sequence_semantics`. |

**Tool Consolidation**: All introspector-derived context (signatures,
cross-refs, type defs, headers, tests, debug types) is **pre-fetched**
into `FuzzingContext` before agent turns. The remaining LangGraph tools:
- `BashExecuteTool` (`src/tools/execution.py`): unified bash, 8KB output truncation
- `GDBExecuteTool` (`src/tools/execution.py`): scripted GDB session for crash triage

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT. Carries L0-L4 results plus `comprehension`, `sequence_semantics`, `automaton`, `skeleton_drivers`, `existing_driver_knowledge` |
| Supervisor | `src/workflow/nodes/supervisor.py` | Route between agents, manage phases |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop for agent tool use |
| ProjectAnalyzer | `src/agents/project_analyzer.py` | Pre-prototyper context-understanding pass (`project_understanding`) |
| UnifiedCodeValidator | `src/utils/unified_validator.py` | Single-pass validator (fake-defs, internal APIs, language mismatch). Replaces former 4-validator pipeline |
| Closed-loop orchestrator | `src/closed_loop.py` | Phase G: `run_closed_loop` re-runs L4+CBFactory with `update_with_traces` evidence each iteration |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis (Phase H gate: `AutomatonAcceptanceGuard`) |
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate` interpreter, Phase E `extend_post_def` |
| Static traces | `liberator_adapter/analysis/static_trace.py` | libclang AST walker → `StaticTrace` with intra-function value-flow bindings |
| PTA / EDSM | `liberator_adapter/analysis/pta.py`, `edsm.py` | Value-flow Prefix Tree Acceptor + evidence-driven state merging; `incremental_merge` for closed-loop |
| LLM oracle | `liberator_adapter/analysis/llm_oracle.py` | Per-merge equivalence oracle, disk-cached. Off in production |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | Orchestrator + `AutomatonArtifact` (acceptance_score, sample_accepting_paths, graft_creator_prefix, observed_apis, post_parse_extensions, update_with_traces) |
| Knowledge cache | `src/knowledge/cache.py` | Disk cache for purpose / api_usage / sequence semantics |
| Comprehender | `src/knowledge/comprehender.py` | Two-stage comprehender (A: per-API, B: per-sequence) with deterministic-then-LLM fallback |

### Progressive Filter Pipeline (`liberator_adapter/constraints/`)

Multi-layer filtering: **Type compatibility ≠ Semantic validity ≠ High coverage**

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L5 Coverage-Aware → L4 Ranking → Top-K
              (~1000)    (~100)      (~30)          (~10)            (filter by novelty)  (K=12)
                                                                                              ↑
                                                              Project-adaptive automaton signal
                                                              (acceptance_score, sample_paths,
                                                               creator-grafted candidates)
```

L5 runs **before** L4 (see `coverage_ranker.py::select_top_k_sequences`):
`CoverageAwareFilter` runs first when OSS-Fuzz coverage is available,
then L4 ranks the survivors. L4's numbering predates L5; not applied
in numerical order.

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct: API consumes `(uint8_t* data, size_t size)`. Indirect: `IndirectEntryPoint(creator, consumer)` pair |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L5 | `coverage_aware_filter.py` | Pre-filter by novelty vs existing OSS-Fuzz coverage. Skipped without coverage data, or with `--no-coverage-filter` / `LOGICFUZZ_DISABLE_COVERAGE_FILTER=1` |
| L4 | `coverage_ranker.py` | Diversity-sorted greedy Top-K. With `automaton_artifact`, pool is augmented by `sample_accepting_paths(8)`, `graft_creator_prefix(...)`, `post_parse_extensions(...)`; `acceptance_score` is the secondary sort axis |

**Use-def + typestate substrate** (`liberator_adapter/analysis/usedef.py`):
single USE/DEF/KILL summary per API (`APIEffect`) feeds the L4 ranker,
the prototyper (via the automaton), and the comprehender. **Not its own
filter** — consolidates the model formerly re-implemented inside each Lx.
L1/L2/L3 still carry their own matchers (open TODO).

**Entry Point Categories** (L1):
- `C_BUFFER_WITH_SIZE`: (const uint8_t* data, size_t size)
- `CPP_VIEW`: string_view, span<>, StringRef
- `CPP_CONTAINER_REF`: std::string&, std::vector&
- `C_STRING`: (const char*) null-terminated
- Indirect: `IndirectEntryPoint` pairs (e.g. `ucl_parser_new()` → `ucl_parser_add_chunk(p, data, size)`); creator names captured in `indirect_creator_names`

**Lifecycle Discovery** (L2): NAME_PATTERN (xxx_init↔xxx_destroy), TYPE_PATTERN, SEMANTIC_PATTERN (library-specific)

**State Machine Violations** (L3): USE_BEFORE_INIT, DESTROY_BEFORE_INIT, DOUBLE_DESTROY, USE_AFTER_DESTROY, REINIT_WITHOUT_DESTROY (also UNCLOSED_RESOURCE / UNOPENED_CLOSE in the typestate interpreter)

### Z3-Guided Synthesis (`liberator_adapter/driver/factory/constraint_based/`)

| Component | File | Purpose |
|-----------|------|---------|
| IncrementalZ3Solver | `z3_solver.py` | push/pop for decision guidance |
| Z3-guided controller | `z3_guided_synthesis.py` | TYPE_MATCH, PROVENANCE, RESOURCE_LIFECYCLE, VARIABLE_AVAILABILITY |
| `AutomatonAcceptanceGuard` | `z3_guided_synthesis.py` (class) | Phase H hard-pruning gate: rejects candidates whose `acceptance_score` is below `automaton_threshold` **before** Z3 is consulted. Wired in via `CBFactory(automaton_artifact=...)`. Telemetry via `get_automaton_stats()` |
| UnsatCoreDiagnoser | `z3_guided_synthesis.py` | Failure diagnosis with unsat-core analysis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | `LLMLifecycleValidator` in `sequence_filter.py` |
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY) |

## Project-Adaptive Automaton

Per-project typestate automaton learned from the library's own tests/examples.
**Full design + empirical justification + future work: `docs/automaton.md`.**

Pipeline (all in `liberator_adapter/analysis/`):
`extract_project_traces` → `extract_api_effects` → `build_pta` →
`edsm.merge` → `learn_project_automaton() → AutomatonArtifact`.

`AutomatonArtifact` surface (consumers in parens):
- `acceptance_score(seq)` — L4 secondary sort, comprehender-B prefilter, Phase H guard
- `sample_accepting_paths(n)` — L4 pool augmentation, prototyper `<protocol_templates>`
- `graft_creator_prefix(seq)` — L4 turns unaccepted candidates into L_A-grounded variants
- `post_parse_extensions(seq)` — Phase E: extends `parse → get_object` prefixes via `extend_post_def`
- `update_with_traces(traces)` — Phase G incremental EDSM merge
- `observed_apis()` — telemetry

Persistence: `results/{project}/automaton/{traces.json, pta.json, merged.json,
metadata.json, oracle_cache.json}`. Comprehender output:
`results/{project}/comprehension/{purpose.txt, api_usage.json, sequences.json}`.

## Closed-Loop Synthesis (Phase G)

Grows the automaton each round using the current viable Z3 skeletons'
API sequences as evidence (incremental EDSM merge). Skeletons drive the
LLM; closed-loop's value here is the in-place mutation of
`automaton_artifact` it preserves through `persist_dir`.

Entry: `src/closed_loop.py:run_closed_loop`. Wired into `data_context.py`
Step 11 (right after Step 10 skeleton synthesis).

CLI: `--closed-loop`, `--closed-loop-iters N` (default 3),
`--closed-loop-early-stop K` (default 0).

Loop: extract `api_sequence` from skeletons → `update_with_traces` →
`edsm.incremental_merge` → re-rank → re-synthesise random drivers under
updated automaton (evidence for next iter, NOT fed to LLM).
Stops when Δmerged_states ≤ K for 2 consecutive rounds.

## Working method — post-run validation pass (2026-05-12)

After every actual end-to-end run, **read the intermediate logs
carefully** and confirm whether each remaining refactor / optimization
is behaving as designed. Specifically:

  1. Cross-check the run log against each ``docs/*_refactor_2026_05.md``
     §3 "Empirical validation" section. The §3 lists what should
     happen on a real run; verify presence (positive signals) and
     absence (negative signals).
  2. When the generated driver coverage drops vs the existing OSS-Fuzz
     baseline driver (the "gold standard" hand-written by library
     experts), **trigger emergency-mode analysis** — we likely dropped
     critical context. See ``docs/knowledge_layer_design_proposal_2026_05.md``
     §10B.
  3. Archive validated refactor docs to ``docs/archived_2026_05_validated/``;
     keep unvalidated ones in ``docs/`` so they remain visible for
     follow-up runs.

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks — explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Driver Knowledge**: Extract patterns from existing OSS-Fuzz drivers as reference.
- **Token Efficiency**: Consolidated tools, context prefetching, 8KB output truncation. Comprehender uses deterministic-first layering and the automaton acceptance prefilter to cut LLM calls.
- **Signal vs Filter**: The automaton produces three *signals* (acceptance, sampled paths, grafting) that augment the candidate pool and bias ranking; the underlying greedy max-coverage selection is unchanged.
- **Reuse upstream Liberator over reimplementation.** When fixing a synthesis-layer problem, first check whether upstream Liberator (`reference/liberator` branch, tracking `https://github.com/HexHive/liberator` main) already solves it. If yes, route through the existing port in `liberator_adapter/` (e.g. `RunningContext.try_to_get_var`, `try_to_instantiate_api_call`, `LFBackendDriver`) rather than writing a simplified parallel implementation. Adapt at the boundary; don't fork.

## Validation Pipeline

Single-pass `UnifiedCodeValidator` (`src/utils/unified_validator.py`)
replaces the former 4 validators (fake-defs, language mismatch, internal
APIs, API hallucination). Build errors are then triaged by
`src/utils/compilation_error_triage.py` into link/header/type buckets for
the Fixer. Hallucinated defs and internal API calls are fatal; other
issues pass to the Fixer.

## Open TODOs

- Migrate L1/L2/L3 onto shared `UseDefGraph + Typestate`. Today only the automaton consumes the new analysis module; each Lx still carries its own matcher.
- LLM equivalence oracle production throttling (`enable_llm_oracle=False` in `data_context.py:Step 5e2` until cost-aware pacing lands).
- libaom path resolution — `src_ossfuzz/libaom/` layout doesn't match the consumer-paths probe.
- Batch evaluation aggregator — auto-aggregate `scripts/batch_extended_fuzzing.sh` output into PromeFuzz Table 2 format.
- TLV-aware seed generation based on format analysis.
- Index `order_var` by sequence position in CBFactory's Z3 model (currently keyed by API name; repeated APIs deduped at the boundary instead — see Failed Attempts below).

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
Step 5f  L5 pre-filter + L4 coverage ranker      (uses automaton signal)
Step 5e2 learn_project_automaton                 (runs after 5f)
Step 6b  Comprehender A+B                        (uses acceptance_score)
Step 7   Header extraction
Step 8   Existing-fuzzer header extraction
Step 9   DriverEnhancer pattern analysis
Step 10  Z3-validated skeleton drivers           (CBFactory + Phase H guard)
Step 11  Closed-loop iterations                  (Phase G, opt-in)
Step 12  Existing-driver knowledge extraction    (optional)
# Exposes on FuzzingContext: comprehension, sequence_semantics, automaton,
#                            skeleton_drivers, existing_driver_knowledge
```

---

## Failed Attempts / Lessons

Approaches we tried earlier and have since reworked. Why the current
design looks the way it does — read before re-litigating.

### L5 `CoverageAwareFilter` as default-on hard filter

L5 drops sequences with novelty < 0.2 vs existing OSS-Fuzz coverage to
focus on uncovered code. Useful for production "extend baseline" runs,
but **suppresses TOTAL coverage** in baseline comparisons (we deliberately
avoid touching what the baseline already covers).

**Now:** still default-on for production. Disabled via `--no-coverage-filter`
or `LOGICFUZZ_DISABLE_COVERAGE_FILTER=1` for paper comparisons where
total coverage is the metric.

### CBFactory's "one position per API" Z3 model (papered over)

`api_vars` and `order_vars` are keyed by API name (`Bool("api_called_X")`,
`Int("order_X")`). Synthesis genuinely produces sequences with repeated
APIs (e.g. `cJSON_Print` called multiple times) and `_try_find_init_chain`
routes through the same API as a producer for several types — both
legitimate but incompatible with one-var-per-name. Z3 raised
`b'named assertion defined twice'` in three places.

**Mitigation (applied):**
- Per-checkpoint dedup of `(api, type)` and `(api, position)` pairs in
  `IncrementalZ3Solver` (`add_resource_required` / `add_resource_produced`
  / `add_api_called`).
- Idempotent guard in `CBFactory._track_api_in_z3` so the init-chain
  recursion can revisit an already-tracked API without re-asserting.
- Dedup of repeated names in post-hoc `Z3SequenceValidator.add_api_sequence_constraint`.

**Proper fix (open TODO):** index `order_var` by sequence position rather than API name.

### libucl indirect entry point (added to L1)

Original L1 only admitted APIs that directly consume `(const uint8_t*, size_t)`.
libucl's parser API is `ucl_parser_new()` → `ucl_parser_add_chunk(p, data, size)`,
so most sequences were filtered out, capping coverage at ~20% of the 70%
reachable surface.

**Now:** L1 emits `IndirectEntryPoint(creator, consumer)` pairs;
`indirect_creator_names` captured for downstream sequence grounding.

### Post-parse sequence cliff (Phase E)

Sequences stopped at `parse → get_object`. High-value APIs like
`emit/merge/compare` that operate on a parsed object were unreachable
even when the object was in scope.

**Now:** `AutomatonArtifact.post_parse_extensions` invokes
`extend_post_def` over `UseDefGraph` to extend `parse → get_object`
prefixes with witness-grounded post-parse uses. Consumed by L4
candidate augmentation.

---

## Upstream Liberator issues fixed in the adapter

Bugs / limitations that exist in upstream `reference/liberator`
that the adapter has fixed (or has a clear path to fix). See
`docs/upstream_liberator_diffs.md` for the per-item detail.
