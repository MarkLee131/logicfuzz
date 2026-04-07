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

## Architecture

```
run_logicfuzz.py → FuzzingContext (SSOT) → FuzzingWorkflow (LangGraph) → Evaluation
                         ↑                        ↓
              Static Analysis (Liberator)    Agent System
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
| Prototyper | FuzzIntrospectorQueryTool | Generate initial driver from API sequence |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CoverageAnalyzer | BashExecuteTool | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | BashExecuteTool | Determine if crash is driver bug or real bug |
| Improver | FuzzIntrospectorQueryTool | Improve coverage based on analyzer suggestions |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |

**Tool Consolidation**: Tools are consolidated for token efficiency:
- `FuzzIntrospectorQueryTool`: Unified tool for function impl, signatures, cross-refs, type defs, headers, tests, debug types
- `BashExecuteTool`: Unified bash execution with 8KB output truncation

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT for all static analysis |
| Supervisor | `src/workflow/nodes/supervisor.py` | Route between agents, manage phases |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop for agent tool use |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |
| FuzzIntrospectorQueryTool | `src/tools/introspector.py` | Unified FuzzIntrospector query interface |

### Progressive Filter Pipeline (`liberator_adapter/constraints/`)

Multi-layer filtering: **Type compatibility ≠ Semantic validity ≠ High coverage**

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Ranking → L5 Coverage-Aware → Top-K
              (~1000)    (~100)      (~30)          (~10)            (K=12)       (prioritize uncovered)
```

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Contains API consuming `(uint8_t* data, size_t size)` |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L4 | `coverage_ranker.py` | Prioritize by diversity, greedy selection |
| L5 | `coverage_aware_filter.py` | Deprioritize APIs already well-covered |

**Entry Point Categories** (L1):
- `C_BUFFER_WITH_SIZE`: (const uint8_t* data, size_t size)
- `CPP_VIEW`: string_view, span<>, StringRef
- `CPP_CONTAINER_REF`: std::string&, std::vector&
- `C_STRING`: (const char*) null-terminated

**Lifecycle Discovery** (L2):
- NAME_PATTERN: xxx_init ↔ xxx_destroy, xxx_create ↔ xxx_delete
- TYPE_PATTERN: Type-based matching on return/parameter types
- SEMANTIC_PATTERN: Library-specific (e.g., all ares parsers → ares_free_data)

**State Machine Violations** (L3): USE_BEFORE_INIT, DESTROY_BEFORE_INIT, DOUBLE_DESTROY, USE_AFTER_DESTROY, REINIT_WITHOUT_DESTROY

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

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks - explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Driver Knowledge**: Extract patterns from existing OSS-Fuzz drivers as reference.
- **Token Efficiency**: Consolidated tools, context prefetching, 8KB output truncation.

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

### Evaluation Workflow (High Priority)

- [ ] **24-Hour Fuzzing Evaluation**
  - Script: `scripts/run_extended_fuzzing.py`
  - Outputs: `results.json`, `coverage_timeline.csv`

- [ ] **Batch Evaluation Script**
  - Scan `results/output-*-project/fuzz_targets/` for successful builds
  - Run 24h fuzzing, aggregate metrics into PromeFuzz Table 2 format

- [ ] **Harness Merging**
  - Merge multiple `fuzz_targets/*.fuzz_target` into single harness
  - Approach: Combine LLVMFuzzerTestOneInput with switch-case on first byte

### Future Enhancements

- [ ] **Indirect Entry Point Support**
  - Support `init() → consume_data()` pattern (e.g., ucl_parser_new() → ucl_parser_add_chunk())
  - Current L1 only supports direct `(uint8_t*, size_t)` consumption

- [ ] **Post-Parse Sequence Extension**
  - Auto-extend: `parse → get_object → emit/compare/merge`
  - Cover high-value APIs requiring parsed objects

- [ ] Early crash detection (15s fuzzing to filter bad drivers)
- [ ] TLV-aware seed generation based on format analysis
- [ ] Coverage feedback loop from execution phase

## Implementation Flow

```python
# In FuzzingContext.prepare():
Step 1-4: _build_dependency_graph() → _generate_sequences()  # L0: Type compatibility
Step 5c:  analyze_entry_points() → filter_sequences_by_entry_point()  # L1: Entry Point
Step 5d:  analyze_lifecycle() → filter_sequences_by_lifecycle()  # L2: Lifecycle
Step 5e:  analyze_state_machine() → filter_sequences_by_state_machine()  # L3: State Machine
Step 5f:  select_top_k_sequences()  # L4: Coverage Ranking
# L5: Coverage-Aware applied during ranking
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
