# CLAUDE.md

LogicFuzz: LLM-powered fuzz driver generation using LangGraph agents for C/C++ libraries.

## Quick Start

```bash
source .venv/bin/activate
pip install -r requirements.txt

# Run
python3 run_logicfuzz.py --benchmark-yaml comparison/cjson.yaml
```

Environment: `DASHSCOPE_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY` in `logicfuzz.env`

---

## Architecture

### Agents (all use ToolCallingMixin for ReAct-style tool calling)

| Agent | File | Tools |
|-------|------|-------|
| Prototyper | `src/agents/prototyper.py` | FI tools (source, xrefs, signature, tests) |
| Improver | `src/agents/improver.py` | FI tools |
| CoverageAnalyzer | `src/agents/coverage_analyzer.py` | Bash |
| CrashAnalyzer | `src/agents/crash_analyzer.py` | GDB, Bash |
| CrashFeasibilityAnalyzer | `src/agents/crash_feasibility_analyzer.py` | FI + Bash |
| Fixer | `src/agents/fixer.py` | Bash |

### Data Flow

```
ProjectDriverGenerator → FuzzingContext → CBFactory (Z3-guided) → Prototyper → FuzzTarget
```

### Key Design: LLM Active Query

Prototyper/Improver **actively query** FuzzIntrospector instead of receiving static analysis conclusions:
- `get_function_implementation` - understand buffer/var-len logic
- `get_sample_cross_references` - learn API patterns
- Tool calls are **optional** - LLM decides when needed

---

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

---

## CBFactory (Z3-Guided Synthesis)

**Location**: `liberator_adapter/driver/factory/constraint_based/CBFactory.py`

Z3 as **core decision participant** (not post-hoc validator):
1. Z3 evaluates source API feasibility → sorted candidates
2. Z3 guides producer selection → only try SAT options
3. Incremental validation per API → early conflict detection
4. UNSAT core analysis → intelligent backtrack

**Components**: `IncrementalZ3Solver`, `Z3GuidedSynthesisController`, `UnsatCoreDiagnoser` in `z3_guided_synthesis.py`

---

## Out of Scope

- Cross-thread/global state protocols
- Complex ownership (refcount, borrowed pointers)
- Async/reentrant callbacks
- Macro expansion
- Deep alias precision

---

## TODO

### Existing
- [ ] Extract state machine knowledge from OSS-Fuzz drivers
- [ ] Public headers via FuzzIntrospector
- [ ] Guard condition extraction (L7)

### Seed Generation (from DriverEnhancer analysis)
- [ ] TLV-aware seed generation: use `TLVAnalysisResult.format_type` (JSON/XML/TLV/ASN1) to generate structured initial corpus
- [ ] VarLen boundary seeds: generate edge-case seeds based on buffer-size relations (size=0, size=1, size=boundary)
- [ ] Loop iteration seeds: leverage `LoopPatternInfo.max_iterations` for iteration-boundary testing

### Scheduzz-inspired Improvements (from ScheDuzz)
- [ ] **P0: Dual Scheduling Framework** - Group Scheduler (similarity, coverage, group length, entropy) + Driver Scheduler (energy, cov/time score)
- [ ] **P1: Imply/Conflict Constraints** - Extract explicit `imply(api1, api2)` and `conflict(api1, api2)` relations via LLM, integrate with Z3
- [ ] **P2: Early Crash Detection** - 15s short-term fuzzing to filter irrational drivers before full execution
- [ ] **P3: Group Entropy** - Ensure API coverage diversity, avoid always selecting same high-coverage APIs
