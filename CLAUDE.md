# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

LogicFuzz: Agentic fuzz driver generation for C/C++ libraries.

## Commands

```bash
# Setup
source .venv/bin/activate
pip install -r requirements.txt

# Run on a benchmark
python3 run_logicfuzz.py --benchmark-yaml comparison/cjson.yaml

# Run with specific model
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Extract APIs only (no LLM calls)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Generate drivers with CBFactory
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Control parallelism (default: 10 experiments, 6 evaluations each)
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Disable session memory (cross-agent consensus sharing)
python3 run_logicfuzz.py -y comparison/cjson.yaml --no-session-memory

# Code quality
pylint src/
pyright src/
yapf -i src/**/*.py  # Format code
```

## Environment Variables

Configure in `logicfuzz.env`:
- `OPENAI_API_KEY` - For GPT models (gpt-4o, gpt-4o-mini, gpt-4-turbo)
- `DEEPSEEK_API_KEY` - For DeepSeek models
- `ANTHROPIC_API_KEY` - For Claude models (claude-3-5-sonnet, claude-3-opus)
- `LLM_NUM_EXP` - Parallel experiment count (default: 10)

## Supported Models

All models in `src/llm/models.py` support tool calling:
- OpenAI: `gpt-4o` (recommended), `gpt-4o-mini`, `gpt-4-turbo`, `gpt-4`
- DeepSeek: `deepseek-chat`
- Anthropic: `claude-3-5-sonnet`, `claude-3-opus`, `claude-3-haiku`

## Benchmark YAML Format

```yaml
"language": "c"
"project": "cjson"
"url": "https://github.com/DaveGamble/cJSON.git"
"target_name": "cjson_read_fuzzer"
"target_path": "/src/cjson/fuzzing/cjson_read_fuzzer.c"
```

## Architecture

### Data Flow

```
run_logicfuzz.py
    ↓
_prepare_shared_data_for_benchmark()  # Once per benchmark
    ├── ProjectDriverGenerator (Liberator static analysis)
    ├── Extract all APIs via Clang/LLVM
    ├── Build type dependency graph
    └── Generate API sequences
    ↓
FuzzingContext (immutable, SSOT)
    ↓
FuzzingWorkflow (LangGraph)
    ├── Prototyper → generates driver
    ├── Fixer → fixes compilation errors
    ├── CoverageAnalyzer → analyzes coverage gaps
    ├── CrashAnalyzer → diagnoses crashes
    └── Supervisor → routes between agents
    ↓
Evaluation (build, coverage, crash detection)
```

### Workflow State Machine (`src/workflow/nodes/supervisor.py`)

```
COMPILATION PHASE:
prototyper ──► build ──► [success] ──► OPTIMIZATION PHASE
                  │
                  └──► [fail] ──► fixer (max 3 retries) ──► build
                                        └──► [max retries] ──► END

OPTIMIZATION PHASE:
build ──► execution ──┬──► [crash] ──► crash_analyzer ──► crash_feasibility_analyzer
                      │                                          │
                      │                          ┌───────────────┴──────────┐
                      │                          ▼                          ▼
                      │                    END (true bug)               fixer ──► build
                      │
                      └──► [success] ──► coverage_analyzer (×1) ──► improver (×1) ──► END
```

### Agent System

All agents inherit from `LangGraphAgent` + `ToolCallingMixin` (ReAct-style tool calling):

| Agent | File | Tools | Purpose |
|-------|------|-------|---------|
| Prototyper | `src/agents/prototyper.py` | FI (source, xrefs, signature, tests) | Generate initial driver |
| Improver | `src/agents/improver.py` | FI tools | Improve driver quality |
| Fixer | `src/agents/fixer.py` | Bash | Fix compilation errors |
| CoverageAnalyzer | `src/agents/coverage_analyzer.py` | Bash | Analyze coverage gaps |
| CrashAnalyzer | `src/agents/crash_analyzer.py` | GDB, Bash | Diagnose root causes |
| CrashFeasibilityAnalyzer | `src/agents/crash_feasibility_analyzer.py` | FI + Bash | Assess crash severity |

### Key Components

- **FuzzingContext** (`src/context/data_context.py`): Immutable dataclass with all static analysis results. No fallbacks - missing data raises ValueError. Supports caching via `load_from_cache()`.
- **FuzzingWorkflowState** (`src/workflow/state.py`): LangGraph TypedDict with build results, coverage, crashes, node visit counts, session memory for cross-agent consensus.
- **ToolCallingMixin** (`src/agents/tool_calling_mixin.py`): ReAct loop - LLM generates tool calls → tools execute (parallel via ThreadPoolExecutor) → results returned → repeat until done.
- **Supervisor** (`src/workflow/nodes/supervisor.py`): Routes between agents based on state, manages phases (compilation vs optimization). Constants: `MAX_COMPILATION_RETRIES=3`, `MAX_NODE_VISITS=10`.

### Liberator Integration (`liberator_adapter/`)

- **Extractors** (`extractors/`): `ClangAPIExtractor` (headers), `LLVMAPIExtractor` (bitcode flags/sizes)
- **CBFactory** (`driver/factory/constraint_based/`): Z3-guided synthesis with `IncrementalZ3Solver`, `UnsatCoreDiagnoser`
- **ConditionManager** (`constraints/`): Source/sink/init API classification
- **Grammar** (`grammar/`): CFG-based API sequence generation

## Static Analysis Bottlenecks (Liberator)

| ID | Problem | Solution | File |
|----|---------|----------|------|
| L1 | Type over-connection | ProvenanceChecker + LLM filter | `provenance_checker.py`, `sequence_filter.py` |
| L2 | Var-len hardcoded | VarLenAnalyzer | `special_patterns.py` |
| L3 | Callbacks | CallbackAnalyzer + 8 stub templates | `special_patterns.py` |
| L4 | Loop APIs | LoopPatternAnalyzer | `special_patterns.py` |
| L5 | API roles | LLMLifecycleValidator | `sequence_filter.py` |
| L6 | Lifecycle | LLM validation | `sequence_filter.py` |
| L7 | Guard conditions | Deferred | - |

## CBFactory (Z3-Guided Synthesis)

**Location**: `liberator_adapter/driver/factory/constraint_based/CBFactory.py`

Z3 as **core decision participant** (not post-hoc validator):
1. Z3 evaluates source API feasibility → sorted candidates
2. Z3 guides producer selection → only try SAT options
3. Incremental validation per API → early conflict detection
4. UNSAT core analysis → intelligent backtrack

## Key Design Decisions

- **LLM Active Query**: Hard constraints (symbolic via Z3) vs soft constraints (LLM reference). Avoid blurring symbolic/neural responsibilities.
- **SSOT (Single Source of Truth)**: FuzzingContext prepared once, immutable. No fallbacks - explicit failures prevent hidden bugs.
- **Lazy Initialization**: Agents lazy-load `_chat_model` and `fi_tool` on first use to reduce memory in parallel execution.
- **Session Memory**: Optional cross-agent consensus sharing via `session_memory` field (enabled by default). Stores API constraints, known fixes, coverage strategies.
- **Token Tracking**: All LLM calls tracked via `update_token_usage()` in state, aggregated in final `report.json`.

## Output Structure

Results saved to `results/output-{benchmark_id}/`:
- `status/{trial}/result.json` - Per-trial results with token usage
- `code-coverage-reports/` - Coverage data
- `benchmark.yaml` - Benchmark configuration used
- `report.json` - Aggregated statistics

## TODO

### Existing
- [ ] Extract state machine knowledge from OSS-Fuzz drivers
- [ ] Public headers via FuzzIntrospector
- [ ] Guard condition extraction (L7)

### Seed Generation (from DriverEnhancer analysis)
- [ ] TLV-aware seed generation: use `TLVAnalysisResult.format_type` (JSON/XML/TLV/ASN1) to generate structured initial corpus
- [ ] VarLen boundary seeds: generate edge-case seeds based on buffer-size relations (size=0, size=1, size=boundary)
- [ ] Loop iteration seeds: leverage `LoopPatternInfo.max_iterations` for iteration-boundary testing

### Scheduzz-inspired Improvements
- [ ] **P0: Fake Definition Check** - Detect LLM-generated fake function definitions in validation phase
- [ ] **P1: Imply/Conflict Constraints** - Extract explicit `imply(api1, api2)` and `conflict(api1, api2)` relations via LLM, integrate with Z3
- [ ] **P1: Structure Init/Destroy Discovery** - Auto-discover struct initialization/destruction functions
- [ ] **P1: Compilation Error Triage** - Distinguish link error / inclusion error / missing header, handle separately
- [ ] **P2: Early Crash Detection** - 15s short-term fuzzing to filter irrational drivers before full execution
- [ ] **P2: Driver Example Feedback** - Provide project's existing drivers as reference context in fixing phase
- [ ] **P3: Group Entropy** - Ensure API coverage diversity, avoid always selecting same high-coverage APIs
