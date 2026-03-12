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
| Prototyper | FuzzIntrospector | Generate initial driver from API sequence |
| Fixer | Bash | Fix compilation errors with error triage |
| CoverageAnalyzer | Bash | Diagnose low coverage, suggest improvements |
| CrashAnalyzer | GDB, Bash | Determine if crash is driver bug or real bug |

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT for all static analysis |
| Supervisor | `src/workflow/nodes/supervisor.py` | Route between agents, manage phases |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop for agent tool use |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | `LLMLifecycleValidator` in `sequence_filter.py` |

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks - explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Driver Knowledge**: Extract patterns from existing OSS-Fuzz drivers as reference.

## Validation Pipeline

Build errors pass through multiple validators before reaching Fixer:

1. **FakeDefinitionValidator** - Detect LLM-hallucinated functions → terminate if found
2. **CompilationErrorTriage** - Categorize errors → provide targeted fix guidance
3. **LanguageMismatchValidator** - Detect C++ in C code
4. **APIValidator** - Detect internal/private API usage

## TODO

### In Progress
- [ ] **Imply/Conflict Constraints** - Extract API relations via LLM, integrate with Z3
- [ ] **Structure Init/Destroy Discovery** - Auto-discover struct lifecycle functions

### Planned
- [ ] Guard condition extraction (L7)
- [ ] Early crash detection (15s fuzzing to filter bad drivers)
- [ ] TLV-aware seed generation based on format analysis
