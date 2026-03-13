# Fuzz Driver Generation: Problem Modeling

## 1. Task Decomposition

Fuzz driver generation can be decomposed into **5 distinct sub-problems**, each requiring different capabilities:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FUZZ DRIVER GENERATION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  Sub-problem │    │  Sub-problem │    │  Sub-problem │                   │
│  │      #1      │───▶│      #2      │───▶│      #3      │                   │
│  │              │    │              │    │              │                   │
│  │ API Discovery│    │ Type Mapping │    │ Input Mapping│                   │
│  │ & Selection  │    │ & Resolution │    │ (Fuzz → API) │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  "Which APIs │    │ "How to use  │    │ "How to feed │                   │
│  │   to fuzz?"  │    │  these types │    │  fuzz data   │                   │
│  │              │    │  correctly?" │    │  to params?" │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐                                       │
│  │  Sub-problem │    │  Sub-problem │                                       │
│  │      #4      │───▶│      #5      │                                       │
│  │              │    │              │                                       │
│  │  Lifecycle   │    │   Semantic   │                                       │
│  │  Management  │    │  Correctness │                                       │
│  └──────────────┘    └──────────────┘                                       │
│         │                   │                                               │
│         ▼                   ▼                                               │
│  ┌──────────────┐    ┌──────────────┐                                       │
│  │ "Init/cleanup│    │ "Avoid false │                                       │
│  │  ordering?"  │    │  positives?" │                                       │
│  └──────────────┘    └──────────────┘                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2. Sub-problem Analysis

### Sub-problem #1: API Discovery & Selection

**Question**: Which functions should we fuzz?

**Input**: Library headers, documentation, existing fuzzers
**Output**: Prioritized list of target functions

**Challenges**:
- Not all functions are equally important (core vs utility)
- Some functions are entry points, others are internal
- Coverage potential varies greatly between functions

**Current Approach**: LLM freely chooses based on FuzzIntrospector data
**Problem**: No clear prioritization strategy

**Better Approach**:
```
Priority Score = f(
    is_entry_point,           # Entry points > internal
    reachable_code_volume,    # More reachable code = higher priority
    existing_coverage_gap,    # Uncovered functions > covered
    complexity,               # Complex parsing functions > simple getters
    security_relevance        # Memory ops, parsing > logging
)
```

### Sub-problem #2: Type Mapping & Resolution

**Question**: How to correctly use types in target language?

**Input**: Type definitions from headers (struct, typedef, enum, union)
**Output**: Syntactically correct type usage

**Challenges**:
- C vs C++ differ in `struct` keyword requirement
- Opaque types vs concrete types
- Forward declarations vs full definitions
- Platform-specific types (size_t, int32_t)

**Current Approach**: LLM generates, Fixer repairs
**Problem**:
- Error triage doesn't recognize type errors
- Language mismatch (C++ code for C library)

**Better Approach**:
```
Type Resolution Pipeline:
1. Parse headers → extract all type definitions
2. Classify: typedef'd vs raw struct vs opaque
3. Generate type-correct templates
4. Validate before LLM generation
```

### Sub-problem #3: Input Mapping (Fuzzer → API)

**Question**: How to map random bytes to API parameters?

**Input**: Function signatures with parameter types
**Output**: Code that converts `uint8_t* data, size_t size` to typed params

**Challenges**:
- Simple types: int, char, pointer (relatively easy)
- Complex types: struct with nested pointers (hard)
- Variable-length: strings, buffers with size params
- Structured: JSON, XML, binary protocols

**Current Approach**: LLM generates ad-hoc mapping
**Problem**: No systematic handling of varlen or structured input

**Better Approach**:
```
Input Mapping Strategies:
├── Primitive Types
│   └── Direct cast from fuzz bytes
├── Varlen Types (buffer + size)
│   └── VarLenAnalyzer identifies pairs, maps correctly
├── Structured Types
│   └── Format-aware generators (TLV, JSON, etc.)
└── Complex Structs
    └── Field-by-field initialization or factory functions
```

### Sub-problem #4: Lifecycle Management

**Question**: What's the correct init/use/cleanup order?

**Input**: API documentation, code patterns
**Output**: Correctly ordered API calls

**Challenges**:
- Library init before any calls (ares_library_init)
- Resource allocation → use → deallocation
- Error handling paths
- Nested lifecycles (channel contains sockets)

**Current Approach**: LLM infers from examples
**Problem**: May miss required init or cleanup calls

**Better Approach**:
```
Lifecycle Model:
1. Extract init/cleanup pairs via pattern matching
2. Build dependency graph: init_A → use_B → cleanup_A
3. Generate valid orderings via topological sort
4. Validate against existing drivers
```

### Sub-problem #5: Semantic Correctness

**Question**: Will the generated code trigger false positives?

**Input**: Generated driver code
**Output**: Driver that only crashes on real bugs

**Challenges**:
- Null pointer dereference in driver (not library bug)
- Use-after-free in driver logic
- Invalid parameter combinations
- Timeout due to infinite loops in driver

**Current Approach**: CrashAnalyzer + FeasibilityAnalyzer post-hoc
**Problem**: Reactive, wastes fuzzing time

**Better Approach**:
```
Pre-generation Validation:
1. Static analysis of generated code
2. Symbolic execution for obvious bugs
3. Short fuzzing (15s) to catch immediate issues
4. Pattern-based detection of common driver bugs
```

## 3. Capability Matrix: Symbolic vs Neural

Not all sub-problems should be solved by LLM:

| Sub-problem | Symbolic (Z3/Static) | Neural (LLM) | Hybrid |
|-------------|---------------------|--------------|--------|
| #1 API Selection | Coverage analysis | Prioritization intuition | **Hybrid** |
| #2 Type Resolution | Parse headers | - | **Symbolic** |
| #3 Input Mapping | Varlen detection | Creative mapping | **Hybrid** |
| #4 Lifecycle | Dependency graph | Pattern recognition | **Hybrid** |
| #5 Semantic | Static analysis | - | **Symbolic** |

**Key Insight**:
- **Type resolution (#2) should be 100% symbolic** - no LLM guessing
- **Input mapping (#3) can be templated** - LLM fills in gaps
- **API selection (#1) benefits from LLM** - needs intuition about importance

## 4. Current Architecture vs. Proposed Architecture

### Current (LLM-Centric)

```
                    ┌─────────────────┐
                    │   FuzzIntrospector   │
                    │   (API Discovery)    │
                    └─────────┬───────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         LLM (Prototyper)                    │
│                                                             │
│   Sub-problems #1-#5 ALL handled by LLM generation         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   Compile/Run   │
                    │   (Validation)  │
                    └─────────┬───────┘
                              │
                   ┌──────────┴──────────┐
                   │                     │
                   ▼                     ▼
              [Success]             [Failure]
                   │                     │
                   ▼                     ▼
              Coverage            ┌───────────┐
              Analysis            │   Fixer   │
                                  │   (LLM)   │
                                  └───────────┘
```

**Problem**: LLM handles everything → unpredictable, high variance

### Proposed (Separation of Concerns)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STATIC ANALYSIS LAYER                             │
│                         (Deterministic, Reliable)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ Header Parser   │  │ Type Resolver   │  │ Lifecycle       │              │
│  │                 │  │                 │  │ Extractor       │              │
│  │ - struct defs   │  │ - C vs C++      │  │ - init/cleanup  │              │
│  │ - function sigs │  │ - typedef chain │  │ - dependencies  │              │
│  │ - enum values   │  │ - opaque types  │  │ - ordering      │              │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘              │
│           │                    │                    │                       │
│           └────────────────────┴────────────────────┘                       │
│                                │                                            │
│                                ▼                                            │
│                    ┌───────────────────────┐                                │
│                    │   Driver Skeleton     │                                │
│                    │   (Type-Correct)      │                                │
│                    │                       │                                │
│                    │ - Correct includes    │                                │
│                    │ - Correct struct tags │                                │
│                    │ - Init/cleanup calls  │                                │
│                    └───────────┬───────────┘                                │
│                                │                                            │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LLM LAYER                                      │
│                     (Creative, Intelligent Decisions)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input:  Driver Skeleton + API Candidates + Coverage Goals                  │
│                                                                             │
│  Task:   1. Select which APIs to call (prioritization)                      │
│          2. Design input mapping strategy                                   │
│          3. Add edge case handling                                          │
│                                                                             │
│  Output: Complete fuzz driver (fills in skeleton)                           │
│                                                                             │
│  Key:    LLM CANNOT violate type-correctness (skeleton enforces it)        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VALIDATION LAYER                                   │
│                      (Fast Feedback, Iteration)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Compile Check ──────────────────────────────────────► Syntax OK?        │
│                                                                             │
│  2. Static Analysis ────────────────────────────────────► Obvious bugs?     │
│                                                                             │
│  3. Quick Fuzz (15s) ───────────────────────────────────► Immediate crash?  │
│                                                                             │
│  4. Coverage Measurement ───────────────────────────────► Good coverage?    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5. Existing Infrastructure Analysis

LogicFuzz already has significant static analysis infrastructure. The key question is: **why isn't it being used effectively?**

### What We Have

| Component | Location | Capability | Status |
|-----------|----------|------------|--------|
| `SkeletonGenerator` | `liberator_adapter/driver/synthesis/` | Generates type-correct driver skeleton with holes | ✅ Implemented |
| `ClangAPIExtractor` | `liberator_adapter/extractors/` | Extracts API signatures from headers | ✅ Implemented |
| `CBFactory` | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis | ✅ Implemented |
| `VarLenAnalyzer` | `liberator_adapter/constraints/special_patterns.py` | Detects buffer/size relationships | ✅ Implemented |
| `LLMLifecycleValidator` | `liberator_adapter/constraints/sequence_filter.py` | LLM-based API lifecycle validation | ✅ Implemented |
| `CompilationErrorTriage` | `src/utils/compilation_error_triage.py` | Categorizes build errors | ✅ Implemented |

### The Actual Gap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              THE GAP                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Static Analysis Layer          LLM Layer                                   │
│  ┌───────────────────┐         ┌───────────────────┐                        │
│  │ SkeletonGenerator │ ──────▶ │ Prototyper        │                        │
│  │ (Type-correct)    │         │ (Can ignore it!)  │                        │
│  └───────────────────┘         └───────────────────┘                        │
│           │                             │                                   │
│           │  Skeleton provided as       │  LLM generates                    │
│           │  <skeleton_drivers>         │  completely new code              │
│           │  REFERENCE only             │  ignoring the skeleton            │
│           │                             │                                   │
│           ▼                             ▼                                   │
│  ┌───────────────────┐         ┌───────────────────┐                        │
│  │ Type-correct code │         │ May have type     │                        │
│  │ struct foo *p     │         │ errors: foo *p    │                        │
│  └───────────────────┘         └───────────────────┘                        │
│                                                                             │
│  PROBLEM: Skeleton is "reference material", not enforced template           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Root Cause Chain (c-ares Case Study)

```
1. OSS-Fuzz project.yaml says language: c++ (incorrect for c-ares)
                     │
                     ▼
2. get_project_language() returns "c++" (overrides our yaml)
                     │
                     ▼
3. SkeletonRenderer uses is_cpp_target=True (C++ mode)
                     │
                     ▼
4. Skeleton doesn't require struct keyword
                     │
                     ▼
5. LLM generates: ares_mx_reply *mx (C++ style)
                     │
                     ▼
6. C compiler: "error: must use 'struct' tag"
                     │
                     ▼
7. Error Triage: "OTHER:4" (pattern not recognized)
                     │
                     ▼
8. Fixer fails after 3 attempts
```

### Fixes Applied

| Issue | Fix | Status |
|-------|-----|--------|
| Error Triage missing struct pattern | Added `c_struct_tag_required` pattern | ✅ Done |
| OSS-Fuzz language override | User fixed in yaml | ✅ Done |
| Skeleton as reference vs template | Pending | 🔄 In Progress |

## 6. Implementation Roadmap

### Phase 0: Fix Immediate Issues (Done)

**Completed**:
1. ✅ Added `must use 'struct' tag` error pattern to `CompilationErrorTriage`
2. ✅ Added specific fix guidance for C struct/enum/union tag requirements
3. ✅ User fixed language metadata in yaml

### Phase 1: Enforce Skeleton Template Mode (In Progress)

**Goal**: Make LLM fill in skeleton holes instead of generating from scratch

**Current State**:
- `SkeletonGenerator` already generates type-correct skeletons
- Prototyper provides skeleton as `<skeleton_drivers>` reference
- LLM can (and does) ignore the skeleton entirely

**Tasks**:
1. Change Prototyper prompt to enforce skeleton-based generation:
   - Provide skeleton as mandatory template, not reference
   - Define clear "holes" that LLM must fill
   - Reject outputs that don't follow skeleton structure
2. Add skeleton validation in post-processing:
   - Verify generated code matches skeleton structure
   - Ensure type declarations are preserved

**Expected Impact**:
- Compilation success rate: 60% → 95%
- LLM token usage: Reduced (less fixing needed)

### Phase 2: API Prioritization Strategy (P1)

**Goal**: Focus fuzzing on high-value APIs

**Tasks**:
1. Build API importance scorer:
   - Entry point detection
   - Reachable code volume
   - Coverage gap analysis
2. Provide ranked API list to LLM
3. Add coverage goals to prompt

**Expected Impact**:
- Coverage: 8% → 20%+
- Bug finding potential: Increased

### Phase 3: Structured Input Generation (P2)

**Goal**: Better handle complex input types

**Tasks**:
1. Integrate VarLenAnalyzer results into skeleton
2. Add format-aware generators for JSON/XML/TLV
3. Template-based struct initialization

**Expected Impact**:
- Driver quality: Higher
- Fewer semantic bugs in generated drivers

## 7. Success Metrics

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| Compilation Success | 60% | 95% | Trials that compile on first attempt |
| Coverage (avg) | 8% | 25% | Line coverage over existing OSS-Fuzz |
| Token Efficiency | ~45k/driver | <20k/driver | Avg tokens per successful driver |
| Bug Finding | 0 | >0 | Real bugs found in benchmarks |

## 8. Key Insight

> **The fundamental shift is from "LLM generates everything" to "LLM fills in a type-safe skeleton".**

This separation ensures:
1. **Determinism**: Type correctness is guaranteed by static analysis
2. **Efficiency**: LLM focuses on creative decisions, not syntax
3. **Debuggability**: Failures are easier to diagnose and fix
4. **Scalability**: Static analysis scales better than LLM retries

## 9. Current vs. Ideal Implementation

| Dimension | Current | Ideal | Gap |
|-----------|---------|-------|-----|
| **Skeleton Role** | Reference (`<skeleton_drivers>`) | Mandatory template (`<skeleton_template>`) | LLM can ignore skeleton |
| **LLM Output Format** | Complete fuzz driver code | JSON Hole filling | Output too free-form |
| **Type Correctness** | LLM generates, Fixer repairs | Skeleton guarantees, no repair needed | High compilation failure |
| **CBFactory Integration** | As reference (`synthesis_base_text`) | Generate Skeleton, LLM fills Holes | Loose integration |
| **Error Triage Usage** | Logging + termination | Guide Fixer strategy | Strategy not passed to Fixer |

## 10. Ideal Implementation: Code Architecture

### Core Principle

**From "LLM generates everything" to "LLM fills type-safe skeleton"**

### Implementation Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Phase 1: Static Analysis                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  FuzzingContext.prepare() → Collect all static info once       │
│      ├── ClangExtractor: API signatures, type definitions     │
│      ├── VarLenAnalyzer: buffer/size relationships            │
│      ├── CallbackAnalyzer: callback parameters                │
│      └── LLMLifecycleValidator: init/cleanup pairs            │
│                                                                │
│  SkeletonGenerator.generate() → Type-correct skeleton         │
│      ├── Deterministic: variable decls, API call order, flow  │
│      └── Holes: uncertain parts for LLM to fill               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                    Phase 2: LLM Hole Filling                   │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Input: Skeleton + Hole definitions + API constraints          │
│                                                                │
│  LLM Tasks (ONLY):                                             │
│      1. Fill BufferSizeHole: determine buffer sizes            │
│      2. Fill CallbackImplHole: generate callback code          │
│      3. Fill LoopConditionHole: determine loop termination     │
│      4. Fill InitValueHole: choose appropriate init values     │
│                                                                │
│  Output Format: JSON { hole_name: filled_code }                │
│                                                                │
│  Key Constraint: LLM cannot modify skeleton, only fill Holes   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                    Phase 3: Synthesis                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HoleFiller.fill() → Merge LLM fillings into Skeleton          │
│      ├── Validate filling format                               │
│      ├── Validate type matching                                │
│      └── Generate complete code                                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Hole Type System (Existing in `hole.py`)

```python
class HoleKind(Enum):
    """Types of holes in skeleton"""
    BUFFER_SIZE = auto()      # Buffer allocation size
    ARRAY_LENGTH = auto()     # Array element count
    INIT_VALUE = auto()       # Variable initialization
    LOOP_BOUND = auto()       # Loop iteration limit
    LOOP_CONDITION = auto()   # Loop termination condition
    CALLBACK_IMPL = auto()    # Callback function implementation
    ERROR_HANDLING = auto()   # Error check logic
    RESOURCE_CLEANUP = auto() # Resource deallocation

# Each Hole type has specific interface:
@dataclass
class BufferSizeHole(Hole):
    buffer_idx: int           # Which buffer parameter
    length_idx: int           # Associated length parameter
    relationship: str         # "==", ">=", "size*count"

@dataclass
class CallbackImplHole(Hole):
    signature: str            # Function signature
    callback_type: str        # comparator, reader, writer, etc.
```

### Key Code Changes

#### 1. Modify Prototyper Prompt Structure

```python
# Current: skeleton as reference
<skeleton_drivers>
{skeleton_text}
</skeleton_drivers>

# Ideal: skeleton as mandatory template
<skeleton_template>
{skeleton_code_with_holes_marked}
</skeleton_template>

<holes_to_fill>
- HOLE_1 (BufferSizeHole): Line 15, determine input_buffer size
- HOLE_2 (CallbackImplHole): Implement parse_callback function
</holes_to_fill>

<output_format>
Output ONLY JSON format Hole fillings:
{
  "HOLE_1": "size",
  "HOLE_2": "int parse_callback(...) { ... }"
}
</output_format>
```

#### 2. Progressive Fallback on Failure

```python
def generate_with_fallback(skeleton, llm):
    # Attempt 1: Strict skeleton mode
    result = llm.fill_holes(skeleton.get_holes())
    if validate_fillings(result, skeleton):
        return skeleton.fill(result)

    # Attempt 2: Provide more context
    result = llm.fill_holes_with_context(
        skeleton.get_holes(),
        error_feedback=get_filling_errors(result)
    )
    if validate_fillings(result, skeleton):
        return skeleton.fill(result)

    # Attempt 3: Fallback to current mode (skeleton as reference)
    return llm.generate_full_driver(skeleton_as_reference=True)
```

#### 3. CBFactory + LLM Integration

```python
# Current flow:
CBFactory.create_driver() → synthesized_driver
Prototyper receives synthesized_driver as "Base for Refinement"
LLM can ignore it entirely

# Ideal flow:
CBFactory.create_skeleton() → DriverSkeleton with Holes
Prototyper receives Skeleton + Hole definitions
LLM fills Holes (cannot modify skeleton structure)
HoleFiller.fill() → Complete driver code
```

### Error Triage → Fixer Strategy Passing

```python
# Current (supervisor.py):
triage_result = triage_build_errors(build_errors)
# Only used for logging and FAKE_DEFINITION detection

# Ideal:
triage_result = triage_build_errors(build_errors)
state["fix_strategy"] = triage_result.recommended_strategy
state["fix_guidance"] = get_fix_guidance(triage_result)
# Fixer receives targeted guidance based on error category
```

## 11. Implementation Priority

| Priority | Task | Impact | Effort |
|----------|------|--------|--------|
| P0 | Pass Error Triage strategy to Fixer | Higher fix success rate | Low |
| P1 | Skeleton as mandatory template (not reference) | 60%→95% compilation | Medium |
| P2 | JSON Hole-filling output format | Structured, predictable | Medium |
| P3 | CBFactory generates Skeleton (not full driver) | Tighter integration | High |
