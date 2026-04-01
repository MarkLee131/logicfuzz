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

### Progressive Filter Pipeline (Core Enhancement)

The key insight: **Type compatibility ≠ Semantic validity ≠ High coverage**.
Current grammar-based sequence generation produces syntactically valid but semantically meaningless sequences.

**Solution**: Multi-layer progressive filtering that incrementally tightens constraints.

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Ranking → L5 Coverage-Aware → Top-K
              (~1000)    (~100)      (~30)          (~10)            (K=12)       (prioritize uncovered)
```

| Layer | Filter | Constraint | Status |
|-------|--------|------------|--------|
| L0 | Type Compatibility | `API_A.arg.type == API_B.return_type` | ✅ Done |
| L1 | Entry Point | Sequence contains API that directly consumes `(uint8_t* data, size_t size)` | ✅ Done |
| L2 | Lifecycle | Resources have matching init/destroy pairs | ✅ Done |
| L3 | State Machine | API calls satisfy precondition/postcondition constraints | ✅ Done |
| L4 | Coverage Ranking | Prioritize by coverage potential (diversity, greedy selection) | ✅ Done |
| L5 | Coverage-Aware | Deprioritize APIs already well-covered by existing fuzzers | ✅ Done |

### Completed

- [x] **L1: Entry Point Analyzer** (`liberator_adapter/constraints/entry_point_analyzer.py`)
  - Pattern match: `(const unsigned char*, int/size_t)` as first two args
  - Strategies: ANY_POSITION, MUST_BE_FIRST, WITHIN_FIRST_N

- [x] **L2: Lifecycle Discovery** (`liberator_adapter/constraints/lifecycle_analyzer.py`)
  - Name matching: `xxx_init` ↔ `xxx_destroy`, `xxx_create` ↔ `xxx_delete`
  - Semantic patterns: `ares_parse_*_reply` -> `ares_free_data`
  - Auto-complete sequences with missing cleanup APIs

- [x] **L3: State Machine Extraction** (`liberator_adapter/constraints/state_machine_analyzer.py`)
  - Derive from lifecycle: init produces INITIALIZED, destroy requires INITIALIZED
  - Detect violations: use-before-init, use-after-free, double-free
  - Filter strategies: strict, fixable, permissive

- [x] **L4: Coverage Ranking** (`liberator_adapter/constraints/coverage_ranker.py`)
  - Hierarchical sorting: diversity -> entry point position -> length
  - Greedy selection: maximize marginal API coverage
  - No empirical weights - all rules deterministic and explainable

- [x] **L5: Coverage-Aware Filter** (`liberator_adapter/constraints/coverage_aware_filter.py`)
  - Fetch existing coverage from FuzzIntrospector API
  - Calculate novelty score: +2 uncovered, +1 poorly-covered, -0.5 well-covered
  - Keep "important APIs" (parsers, init/destroy) regardless of coverage
  - Filter sequences with >70% overlap with existing coverage

### Future Work

---

### L1: Entry Point Analyzer - Detailed Design

#### Definition

**Entry Point** = API that directly consumes fuzzer input `(const uint8_t* data, size_t size)` without requiring complex initialization (like channel/handle).

```
Entry Point Types:
├── PARSER   - Parse external data into internal structure (ares_dns_parse, cJSON_Parse)
├── CREATOR  - Create object from external data (ares_create_query)
└── VALIDATOR - Validate external data format (json_validate)
```

#### Identification Rules

```python
# Entry Point signature patterns
ENTRY_POINT_PATTERNS = [
    # Pattern 1: (const unsigned char*, int/size_t) - most common
    {
        "arg0_types": ["unsigned char *", "uint8_t *", "char *", "void *"],
        "arg1_types": ["int", "size_t", "unsigned long", "long"],
        "arg0_must_be_const": True,
    },
    # Pattern 2: (const char*) - string input (no explicit size)
    # Note: requires null-termination of fuzzer data
    {
        "arg0_types": ["char *"],
        "arg0_must_be_const": True,
        "no_size_arg": True,
    },
]

def is_entry_point(api: Api) -> bool:
    if len(api.args) < 2:
        return False
    arg0_type = api.args[0].type.lower()
    arg1_type = api.args[1].type.lower()
    arg0_const = api.args[0].is_const[0]

    is_buffer = any(t in arg0_type for t in ["unsigned char *", "char *", "void *"])
    is_size = any(t in arg1_type for t in ["int", "size_t", "unsigned long"])

    return is_buffer and is_size and arg0_const
```

#### Example: c-ares Project

| Total APIs | Entry Points | Ratio |
|------------|--------------|-------|
| 138 | 15 | 10.9% |

```
Entry Points found:
├── ares_dns_parse          (unsigned char*, unsigned long)  ← Modern unified parser
├── ares_parse_mx_reply     (unsigned char*, int)            ← Legacy parsers
├── ares_parse_txt_reply    (unsigned char*, int)
├── ares_parse_srv_reply    (unsigned char*, int)
├── ares_parse_soa_reply    (unsigned char*, int)
├── ares_parse_a_reply      (unsigned char*, int)
├── ares_parse_aaaa_reply   (unsigned char*, int)
├── ares_parse_ptr_reply    (unsigned char*, int)
├── ares_parse_ns_reply     (unsigned char*, int)
├── ares_parse_uri_reply    (unsigned char*, int)
├── ares_parse_caa_reply    (unsigned char*, int)
├── ares_parse_naptr_reply  (unsigned char*, int)
├── ares_parse_txt_reply_ext(unsigned char*, int)
├── ares_create_query       (char*, int)                     ← Query creators
└── ares_mkquery            (char*, int)
```

#### Filter Strategies

```python
class EntryPointFilterStrategy(Enum):
    ANY_POSITION = "any"       # At least one Entry Point anywhere in sequence
    MUST_BE_FIRST = "first"    # Entry Point must be first API in sequence
    WITHIN_FIRST_N = "within"  # Entry Point within first N positions (default: N=3)
```

**Recommended**: `WITHIN_FIRST_N` with N=3 (balanced between strictness and flexibility)

#### Sequence Filter Logic

```python
def filter_sequences_by_entry_point(sequences, entry_point_names, strategy="within", n=3):
    filtered = []
    for seq in sequences:
        if strategy == "any":
            ok = any(api in entry_point_names for api in seq)
        elif strategy == "first":
            ok = seq[0] in entry_point_names if seq else False
        elif strategy == "within":
            ok = any(api in entry_point_names for api in seq[:n])

        if ok:
            filtered.append(seq)
    return filtered
```

#### Output Data Structure

```python
@dataclass
class EntryPointAnalysis:
    entry_points: List[EntryPointInfo]    # List of Entry Point APIs with metadata
    entry_point_names: Set[str]           # Set of Entry Point function names
    non_entry_points: List[Api]           # APIs that are not Entry Points

@dataclass
class EntryPointInfo:
    api: Api                    # Original API info
    entry_type: str             # "parser" | "creator" | "validator"
    buffer_arg_index: int       # Index of buffer argument (usually 0)
    size_arg_index: int         # Index of size argument (usually 1, -1 if none)
```

#### Integration Point

```python
# In FuzzingContext.prepare() - after L0, before L2

def _analyze_entry_points(self) -> EntryPointAnalysis:
    """L1: Identify Entry Point APIs"""
    analyzer = EntryPointAnalyzer(patterns=ENTRY_POINT_PATTERNS)
    return analyzer.analyze(self.project_apis)

def _filter_by_entry_point(self, sequences, analysis, strategy="within", n=3):
    """L1: Filter sequences to keep only those with Entry Points"""
    return [
        seq for seq in sequences
        if any(api in analysis.entry_point_names for api in seq[:n])
    ]
```

#### Expected Filtering Effect

| Stage | Sequences | Reduction |
|-------|-----------|-----------|
| L0 output | ~1000 | - |
| L1 filtered | ~100-200 | 80-90% |

**Key value**: Eliminates sequences that only call APIs requiring channel/handle (like `ares_getnameinfo`, `ares_query`) which would need complex initialization and produce low coverage.

#### Open Questions

1. **String-only Entry Points** (e.g., `cJSON_Parse(const char*)`)
   - Requires null-terminating fuzzer data
   - Handle in driver template or filter out?

2. **Entry Point priority within L1**
   - `ares_dns_parse` (modern) vs `ares_parse_*_reply` (legacy)
   - Defer to L4 ranking or pre-sort here?

### Planned

- [ ] Early crash detection (15s fuzzing to filter bad drivers)
- [ ] TLV-aware seed generation based on format analysis
- [ ] Coverage feedback loop from execution phase for adaptive ranking

### Implementation Notes

Integration point: `src/context/data_context.py` in `FuzzingContext.prepare()`

```python
# Current flow (L0-L4 fully implemented):
Step 1-4: _build_dependency_graph() → _generate_sequences()  # L0: Type compatibility
Step 5c:  analyze_entry_points() → filter_sequences_by_entry_point()  # L1: Entry Point
Step 5d:  analyze_lifecycle() → filter_sequences_by_lifecycle()  # L2: Lifecycle
Step 5e:  analyze_state_machine() → filter_sequences_by_state_machine()  # L3: State Machine
Step 5f:  select_top_k_sequences()  # L4: Coverage Ranking (replaces old heuristic filter)
```



