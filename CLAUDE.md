# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

LogicFuzz: LLM-powered agentic fuzz driver generation for C/C++ libraries using LangGraph.

## Commands

```bash
# Run on a benchmark
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Extract APIs only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Generate drivers with CBFactory (Z3-guided)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Control parallelism
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Code quality
pylint src/ && pyright src/

# Extended fuzzing evaluation (24h)
python scripts/run_extended_fuzzing.py -p re2 -f results/output-re2-project/fuzz_targets/02.fuzz_target -d 86400
```

## Subsystem deep-dives

For non-obvious subsystems, the design + theory + empirical
justification + future-work plan lives in `docs/`:

| Doc | Subsystem | Status |
|-----|-----------|--------|
| `docs/automaton.md` | Project-adaptive automaton (PTA + EDSM) **and** the PromeFuzz-derived knowledge layer (comprehender shipped, ConstraintLearner design-only). Includes empirical justification across 25 benchmarks, A/B outcomes, future work (Z3 hard pruning, closed-loop refinement, A2DG, oracle throttling). | shipped + forward-looking |
| `docs/merge_drivers.md` | Multi-driver harness merger (`tools/merge_drivers`); preflight + coverage-aware selection + weighted CDF dispatch + tail selector + corpus union; coverage-data-source FAQ | shipped |

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

### Agent System (`src/agents/`)

| Agent | Tools | Purpose |
|-------|-------|---------|
| Prototyper | FuzzIntrospectorQueryTool | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants` from FuzzingContext (rendered via `_format_library_purpose`, `_format_protocol_templates`, `_format_sequence_invariants`) |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CoverageAnalyzer | BashExecuteTool | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | BashExecuteTool | Determine if crash is driver bug or real bug |
| Improver | FuzzIntrospectorQueryTool | Improve coverage based on analyzer suggestions |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| Comprehender (non-LangGraph stage) | LLM batched | Comprehender-A: per-API usage notes + library purpose. Comprehender-B: per-sequence semantic verdict, optional repair, prototyper invariants. Output stored in `FuzzingContext.comprehension` and `sequence_semantics`. |

**Tool Consolidation**: Tools are consolidated for token efficiency:
- `FuzzIntrospectorQueryTool`: Unified tool for function impl, signatures, cross-refs, type defs, headers, tests, debug types
- `BashExecuteTool`: Unified bash execution with 8KB output truncation

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT. Carries L0-L4 results plus new fields `comprehension`, `sequence_semantics`, `automaton` |
| Supervisor | `src/workflow/nodes/supervisor.py` | Route between agents, manage phases |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop for agent tool use |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |
| FuzzIntrospectorQueryTool | `src/tools/introspector.py` | Unified FuzzIntrospector query interface |
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate` interpreter |
| Static traces | `liberator_adapter/analysis/static_trace.py` | libclang AST walker → `StaticTrace` with intra-function value-flow bindings |
| PTA / EDSM | `liberator_adapter/analysis/pta.py`, `edsm.py` | Value-flow Prefix Tree Acceptor + evidence-driven state merging |
| LLM oracle | `liberator_adapter/analysis/llm_oracle.py` | Per-merge equivalence oracle, disk-cached. Off in production for now |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | Orchestrator + `AutomatonArtifact` (acceptance_score, sample_accepting_paths, graft_creator_prefix, observed_apis) |
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

Note: L5 runs **before** L4 (see `coverage_ranker.py:select_top_k_sequences`,
which invokes `CoverageAwareFilter` first when OSS-Fuzz coverage is available,
then ranks the survivors). L4's numbering predates L5; the layers are *not*
applied in numerical order.

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct entry: API consumes `(uint8_t* data, size_t size)`. Indirect entry: `IndirectEntryPoint(creator, consumer)` pair where creator produces a handle the consumer needs |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L5 | `coverage_aware_filter.py` | Pre-filter by novelty vs existing OSS-Fuzz coverage (skipped if no coverage data) |
| L4 | `coverage_ranker.py` | Diversity-sorted greedy Top-K. When `automaton_artifact` is supplied, pool augmented with `sample_accepting_paths(8)` and `graft_creator_prefix(...)` of unaccepted L0-L4 candidates; `acceptance_score` becomes the secondary sort axis |

**Use-def + typestate substrate** (`liberator_adapter/analysis/`): a single
USE/DEF/KILL summary per API (`APIEffect`) feeds the L4 ranker, the
prototyper (via the automaton), and the comprehender. **Not its own
filter** — it consolidates the model previously re-implemented inside
each Lx file. Full migration of L1/L2/L3 onto `UseDefGraph + Typestate`
is a future work item; today the analysis module is consumed by the
project-adaptive automaton (see below).

**Entry Point Categories** (L1):
- `C_BUFFER_WITH_SIZE`: (const uint8_t* data, size_t size)
- `CPP_VIEW`: string_view, span<>, StringRef
- `CPP_CONTAINER_REF`: std::string&, std::vector&
- `C_STRING`: (const char*) null-terminated
- Indirect: `IndirectEntryPoint` pairs (e.g. `ucl_parser_new()` → `ucl_parser_add_chunk(p, data, size)`); creator names captured in `indirect_creator_names` for downstream sequence grounding

**Lifecycle Discovery** (L2):
- NAME_PATTERN: xxx_init ↔ xxx_destroy, xxx_create ↔ xxx_delete
- TYPE_PATTERN: Type-based matching on return/parameter types
- SEMANTIC_PATTERN: Library-specific (e.g., all ares parsers → ares_free_data)

**State Machine Violations** (L3): USE_BEFORE_INIT, DESTROY_BEFORE_INIT, DOUBLE_DESTROY, USE_AFTER_DESTROY, REINIT_WITHOUT_DESTROY (also UNCLOSED_RESOURCE / UNOPENED_CLOSE in the typestate interpreter)

### Z3-Guided Synthesis (`liberator_adapter/driver/factory/constraint_based/`)

| Component | Purpose |
|-----------|---------|
| `z3_solver.py` | IncrementalZ3Solver with push/pop for decision guidance |
| `z3_guided_synthesis.py` | Extended constraints: TYPE_MATCH, PROVENANCE, RESOURCE_LIFECYCLE, VARIABLE_AVAILABILITY |
| UnsatCoreDiagnoser | Intelligent failure diagnosis with unsat core analysis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | `LLMLifecycleValidator` in `sequence_filter.py` |
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY) |

## Project-Adaptive Automaton

> Full design + empirical justification + future work: **`docs/automaton.md`**.

Per-project typestate automaton learned from the library's own tests/examples,
used as a soft signal in L4 ranking, comprehender-B, and the prototyper prompt.
Pipeline lives entirely in `liberator_adapter/analysis/`:

```
extract_project_traces()        # libclang walker → ordered CallSite list with
                                #   value-flow bindings (var_to_call, &var DEFs,
                                #   parameter implicit DEFs, struct fields, TU globals)
  → extract_api_effects()       # USE/DEF/KILL summary per API; lifecycle pairs
                                #   from L2 piped in as KILL edges
  → build_pta()                 # value-flow Prefix Tree Acceptor; node state =
                                #   frozenset[(handle_type, ResourceLifecycleState)]
  → edsm.merge()                # evidence-driven state merging on the typestate
                                #   bucketing; oracle calls deferred when uncertain
  → AutomatonArtifact           # learn_project_automaton() entry point
```

`AutomatonArtifact` API surface (consumed by L4 / comprehender / prototyper):

| method | use site |
|--------|----------|
| `acceptance_score(seq) → [0.0, 1.0]` | L4 secondary sort axis; comprehender-B positive-only prefilter (acc=1.0 ⇒ skip LLM) |
| `sample_accepting_paths(n=8)` | L4 candidate-pool augmentation; prototyper renders as `<protocol_templates>` |
| `graft_creator_prefix(seq)` | L4 transforms unaccepted L0-L4 candidates into L_A-grounded versions by prepending the top depth-ranked root producer |
| `observed_apis()` | L4 telemetry; identifies candidates outside the project's witnessed protocol surface |

References: Strom & Yemini, "Typestate", IEEE TSE 1986; Lang/Pearlmutter/Price,
"Results of the Abbadingo One DFA learning competition and a new evidence-driven
state merging algorithm", 1998; Khuller/Moss/Naor, "The budgeted maximum coverage
problem", 1999 (justifies the (1−1/e)-greedy in `_greedy_select`).

Persistence: `results/{project}/automaton/{traces.json, pta.json, merged.json,
metadata.json, oracle_cache.json}`. Comprehender output:
`results/{project}/comprehension/{purpose.txt, api_usage.json, sequences.json}`.

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks - explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Driver Knowledge**: Extract patterns from existing OSS-Fuzz drivers as reference.
- **Token Efficiency**: Consolidated tools, context prefetching, 8KB output truncation. Comprehender uses deterministic-first layering and the automaton acceptance prefilter to cut LLM calls roughly proportional to the fraction of candidate sequences that hit canonical project protocols.
- **Signal vs Filter**: The automaton produces three *signals* (acceptance, sampled paths, grafting) that augment the candidate pool and bias ranking; the underlying greedy max-coverage selection is unchanged.

## Validation Pipeline

Build errors pass through multiple validators before reaching Fixer:

1. **FakeDefinitionValidator** - Detect LLM-hallucinated functions → terminate if found
2. **CompilationErrorTriage** - Categorize errors → provide targeted fix guidance
3. **LanguageMismatchValidator** - Detect C++ in C code
4. **APIValidator** - Detect internal/private API usage

## Supervisor Configuration

```python
MAX_COMPILATION_RETRIES = 2
MAX_CRASH_FIX_RETRIES = 2
MAX_TOTAL_BUILD_FAILURES = 10
MAX_NODE_VISITS = 10  # Loop detection
MAX_COVERAGE_IMPROVE_ITERATIONS = 1
```

## TODO

### Analysis Consolidation

- [ ] **Migrate L1/L2/L3 onto `UseDefGraph + Typestate`**
  - Today the new `liberator_adapter/analysis/` module is only consumed by
    the project-adaptive automaton; L1/L2/L3 still carry their own matchers.
  - Target: each Lx becomes a thin typestate query against the shared
    `APIEffect` summaries.

- [ ] **LLM oracle production throttling**
  - `LLMEquivalenceOracle` is wired but `enable_llm_oracle=False` in
    `data_context.py:Step 5e2` — needs cost-aware pacing (pair-budget,
    per-bucket sampling) before turning on at scale.

- [ ] **libaom path resolution**
  - P0 trace survey skipped libaom because the `src_ossfuzz/libaom/` layout
    didn't match the consumer-paths probe; fix the layout or add a
    project-specific override.

### Evaluation Workflow

- [ ] **Batch Evaluation Aggregator**
  - Scan `results/output-*-project/fuzz_targets/` for successful builds
  - Run 24h fuzzing via `scripts/batch_24h_fuzzing.sh` /
    `scripts/batch_extended_fuzzing.sh`, aggregate metrics into PromeFuzz
    Table 2 format

- [x] **Harness Merging** (PromeFuzz-style multi-TU + entry dispatcher,
  with O1–O4 optimizations beyond PromeFuzz). Full design +
  coverage-data-source FAQ: **`docs/merge_drivers.md`**.
  - `tools/merge_drivers/` package — `merge.py`, `preflight.py`,
    `select.py`, `corpus.py`, `__main__.py`. Each sub-driver is its
    own TU (linker-isolated collisions), `LLVMFuzzerTestOneInput`
    renamed to `LLVMFuzzerTestOneInput_<id>`, C/C++ auto-detected.
  - **O1** Pre-flight (`preflight.py`): 15 s libFuzzer smoke per
    candidate; rejects crash-on-empty / no edge gain / broken binary.
  - **O2** Coverage-aware Top-K selection (`select.py`): classical
    max-coverage greedy (Khuller/Moss/Naor 1999, ratio 1−1/e) on
    per-driver reached-functions read from existing OSS-Fuzz
    coverage reports (`code-coverage-reports/<id>.fuzz_target/
    linux/summary.json`). No coverage rebuild. Subsumed drivers
    drop out naturally; tie-break by preflight edges then path.
  - **O3** Weighted CDF dispatch (`merge.py:DispatchMode.CDF`): a
    16-bit selector indexes a precomputed uint16 threshold table;
    each sub-driver's slot ∝ its O2 marginal coverage. Plus
    `SelectorPosition.TAIL` (default — selector at end of input,
    decouples libFuzzer's prefix-biased mutators from
    sub-harness routing) vs `HEAD` (PromeFuzz default).
  - **O4** Corpus union (`corpus.py`): each sub-driver's
    pre-existing corpus (`corpora/<id>.fuzz_target/`) is scanned
    and seeds are tagged with selector bytes routing back to
    their origin sub-driver, written to `corpus_merged/`. Optional
    dictionary union (cross-sub-harness token noise accepted).
  - **Pipeline CLI**: `python -m tools.merge_drivers pipeline
    --pair SRC=BIN ... --project-root <out-dir> --output ...`
    runs O1→O2→O3→O4 end-to-end.
  - **Batch integration**: `scripts/batch_extended_fuzzing.sh` runs
    one merged-harness target per project (`MERGED_PROJECTS` env var)
    in parallel with the per-driver runs;
    `scripts/run_extended_fuzzing.py --fuzz-target-dir SYNTH_DIR`
    accepts merged synthesized/ as the fuzz target and copies any
    `--seed-corpus-dir` (e.g. `corpus_merged/`) into the runtime
    corpus. Caller must run the pipeline beforehand to produce
    `<project>/merged/synthesized/`; not auto-run because the
    pipeline itself needs the per-driver fuzzer binaries built.

### Future Enhancements

- [ ] **Post-Parse Sequence Extension**
  - Auto-extend: `parse → get_object → emit/compare/merge`
  - Cover high-value APIs requiring parsed objects

- [x] Early crash detection (15s fuzzing to filter bad drivers) —
  shipped as `tools/merge_drivers/preflight.py`. Standalone usable
  outside of the merge pipeline as well.
- [ ] TLV-aware seed generation based on format analysis
- [ ] Coverage feedback loop from execution phase (closed-loop CBFactory feedback)

## Implementation Flow

```python
# In FuzzingContext.prepare():
Step 1-4:  _build_dependency_graph() → _generate_sequences()  # L0: Type compatibility
Step 5c:   analyze_entry_points() → filter_sequences_by_entry_point()  # L1: Entry Point (direct + indirect)
Step 5d:   analyze_lifecycle() → filter_sequences_by_lifecycle()  # L2: Lifecycle
Step 5e:   analyze_state_machine() → filter_sequences_by_state_machine()  # L3: State Machine
Step 5e2:  learn_project_automaton(project, src_root, consumer_paths)  # P3: AutomatonArtifact
Step 5f:   select_top_k_sequences(..., automaton_artifact=art)  # L5 pre-filter (if cov data)
                                                                # → L4 ranking with automaton signal
Step 6b:   comprehender.comprehend_purpose() / comprehend_apis() / comprehend_sequences(
              automaton_acceptance_fn=art.acceptance_score)  # comprehender-A + B
# FuzzingContext exposes: comprehension, sequence_semantics, automaton (summary + sample_paths)
```

---

## Coverage Analysis Cases

记录各项目的 coverage diff 分析，识别跨项目共性问题，避免局部最优设计。

### Case 1: libucl (完整分析)

**OSS-Fuzz Baseline**: Line 14.35% (1,117/7,785), Function 5.67% (17/300), Reachability 70.1%

**LogicFuzz Result**: Coverage Diff **~9.7%**, Final ~20.76%, Sequences **5** (from 134 APIs)

**高价值未覆盖 APIs**:

| API | 潜在复杂度 | 未覆盖原因 |
|-----|-----------|-----------|
| `ucl_emit_yaml_start_array` | +109 | 需要 `ucl_object_t*` 输入 |
| `ucl_hash_sort` | +81 | 需要 hash 对象 |
| `ucl_object_merge` | +55 | 需要两个 `ucl_object_t*` |
| `ucl_object_compare` | +44 | 需要两个 `ucl_object_t*` |

**瓶颈识别**:

| 瓶颈 | 影响 | 说明 |
|------|-----|------|
| **L1 Entry Point 过严** | 高 | 不支持间接入口点模式 |
| **Post-parse 操作缺失** | 高 | Sequences 止步于 `get_object`，未延伸到 emit/compare/merge |
| **Sequence 数量受限** | 中 | Top-K 选择后仅 5 个 |

**理论 vs 实际 Gap**: 可达覆盖率 70.1% vs 实际 20.76% = **49.3% gap**

**根因**: libucl 使用间接入口点模式：
```c
ucl_parser *parser = ucl_parser_new(0);      // 先创建 handle
ucl_parser_add_chunk(parser, data, size);    // 再消费 fuzzer data
```
当前 L1 filter 要求直接消费 `(uint8_t* data, size_t)`，导致大量 sequences 被过滤。

### Case 2: re2 (待完成)

**OSS-Fuzz Baseline**: Line 30.77% (10,071/32,725), Function ~0.78% (36/4,615), Reachability 52.99%

**特点**: 函数覆盖率极低，潜力大

**高复杂度未覆盖**: `Compiler::PostVisit()` (4,997), `Prefilter::DebugString()` (4,046)

### Case 3: sqlite3 (待完成)

**OSS-Fuzz Baseline**: Line 79.27% (66,467/83,850), Function ~79%

**特点**: 覆盖率已高，提升空间有限

**高复杂度未覆盖**: `jsonExtractFunc` (838), `resolveExprStep` (501), `strftimeFunc` (245)

### Case 4: libaom (待完成)

**OSS-Fuzz Baseline**: Line 61.36% (48,101/78,392)

### 项目特征分类

| 类型 | 特征 | 代表项目 | 优化策略 |
|------|------|---------|---------|
| 间接入口点 | 需先创建 handle | libucl | 支持 init→consume 模式 |
| 低基线高潜力 | 覆盖率<30%，可达性>50% | re2 | 待分析 |
| 高基线低潜力 | 覆盖率>70% | sqlite3 | 待分析 |

### 跨项目共性问题 (待验证)

1. **L1 过滤过严**: 间接入口点模式被错误过滤
2. **Post-parse 缺失**: 高价值 API (emit/merge/compare) 需要 parsed object
3. **Sequence 多样性不足**: Top-K 选择可能丢失重要功能模块覆盖
