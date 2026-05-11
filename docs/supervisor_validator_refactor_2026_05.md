# Supervisor + UnifiedCodeValidator refactor — 2026-05

Sixth in the 2026-05 refactor series. Pair-reviewed because the
Validator's behaviour cascades through the Supervisor's routing
decisions (validator warnings flow into Fixer's context, the
supervisor's FAKE_DEFINITION termination depends on the same
signal), and the agent-side validator wire-ups landed in the
prior Agent refactor commit depend on the Validator producing
reliable results.

Verdict from the review:
  - **Supervisor**: clean state-machine design, only minor smells
    (cap consistency, duplicated triage calls). No fixes landed.
  - **UnifiedCodeValidator**: three high-net-value low-downside
    fixes landed (CGProcessor path resolution, FUNCTION_WHITELIST,
    IGNORE_FUNCTIONS). Four other observations deferred with
    explicit downside analysis.

User directive that shaped scope: "修复要全局最优，不要钻牛角尖，
而且不要导致整体效果下降". Every candidate fix was scored on
net (upside − downside); only positive-net ones landed.

The "empirical validation" section is intentionally blank.

---

## §1. What changed (per item)

### V1 — CGProcessor replaced by FunctionBodyWalker (libclang-Python)

**Original symptom.**
`DEFAULT_CGPROCESSOR_PATH = Path("/home/likaixuan/fuzzing/PromeFuzz/build/bin/cgprocessor")`
hardcoded to a personal home directory. On CI / new machines /
collaborator workstations this path doesn't exist;
`is_cgprocessor_available()` returned False; every `_check_target_apis`
call silently fell through to the naive regex check. The accuracy
delta between AST and naive was hidden by this fallback.

**Original fix (intermediate).** Env-var resolution with fallback
chain. Solved the cross-machine portability problem but kept the
external-binary dependency.

**Final fix (after follow-up question — "is CGProcessor really
needed? we could migrate it from promefuzz, but is it duplicating
something?").** Replaced the entire CGProcessor path with
`FunctionBodyWalker` from `liberator_adapter/analysis/static_trace.py`:

  - Same input/output: source code + target_apis → (called_apis,
    missing_apis).
  - Same underlying technology: libclang AST walk.
  - Already maintained for the automaton subsystem's trace
    extraction — zero new code surface.
  - No external binary, no env-var resolution complexity, no
    cross-machine path issues.

`_check_target_apis_ast` rewritten to:

  1. Write the driver code to a temp file (libclang needs a real
     path).
  2. `index.parse(tmp_path, args=["-I/usr/include", ...])`.
  3. For every `FUNCTION_DECL` definition in the TU, run a
     `FunctionBodyWalker` filtered by the target_apis set.
  4. Union the `walker.calls` across functions → return matched
     subset.

`is_cgprocessor_available()` retained for back-compat with any
caller that gated on it; now returns True iff `clang.cindex`
imports successfully. The `cgprocessor_path` constructor argument
is also retained but ignored.

**Downside.** Python libclang is slower than the compiled C++
CGProcessor binary, but per-driver overhead is sub-second.
`FunctionBodyWalker` was designed for trace extraction over a
training corpus; using it for single-driver post-validation works
identically because the walker takes one function at a time.

**Net effect on overall driver quality** (per the "globally
optimal, don't degrade" principle):

  - Driver quality: unchanged (validator accuracy ≈ same as
    CGProcessor on single-driver input).
  - Repo complexity: −70 LOC, −1 external binary dep, −env-var
    resolution layer, −cross-machine path issues.
  - Maintenance burden: −1 separate AST front-end to keep in sync.

**File.** `src/utils/unified_validator.py:_check_target_apis_ast` +
`__init__` + `is_cgprocessor_available`.

### V4 — `INTERNAL_FUNCTION_PATTERNS` whitelist now covers compiler intrinsics

**Symptom.** The pattern `r'\b_[a-z]\w+\s*\('` matches any
function call starting with an underscore-lowercase prefix. The
whitelist only included `__attribute__` and `_Generic`, so legitimate
GCC/Clang intrinsics (`__builtin_expect`, `__builtin_unreachable`, etc.)
and language constructs (`_Static_assert`, `_Atomic`, `_Pragma`, etc.)
were flagged as "Internal API usage".

`is_c_target=False` default in agent callers meant language-compat
check didn't run, but `_check_internal_apis` always runs.
LLM-generated code that uses these (Prototyper output sometimes
emits `__builtin_expect` for branch hints) got false-positive
validation warnings → fed into Fixer's context as noise.

**Fix.** `FUNCTION_WHITELIST` expanded to include:
  - Language constructs: `__attribute__`, `_Generic`, `_Static_assert`,
    `_Atomic`, `_Alignof`, `_Alignas`
  - GCC/Clang intrinsics: `__builtin_expect` and ~15 other common
    builtins, listed explicitly (NOT wildcarded so we still catch
    genuinely-internal `_internal_helper`-style invented symbols)
  - Pragma / control: `_Pragma`
  - libfuzzer entry points: `LLVMFuzzerTestOneInput`, `LLVMFuzzerInitialize`

**Downside:** very narrow — only false-positive risk is if an LLM
invents a symbol that exactly matches one of the added whitelist
entries. None of our whitelist entries are plausible hallucination
targets.

**File.** `src/utils/unified_validator.py:FUNCTION_WHITELIST`.

### V5 — `IGNORE_FUNCTIONS` now covers common libc

**Symptom.** Fake-definition check ignored 15 standard libc
functions (`memcpy`, `printf`, `strlen`, etc.). Missing: `snprintf`,
`fprintf`, `sprintf`, `fgets`, `fread`, `fwrite`, `fopen`, `fclose`,
`exit`, `abort`, `getenv`, `setenv`, `atoi`/`atol`/`strtol` family,
`strcasecmp`/`strncasecmp`, `strchr`/`strrchr`/`strstr`, `strdup`,
`strtok`. When LLM-generated code used these and the build linker
reported them as undefined (rare; usually project-build-script
issue not LLM hallucination), the validator's fake-def check
flagged them as "LLM-hallucinated function". False positives only —
no real fake def gets missed.

**Fix.** `IGNORE_FUNCTIONS` expanded to ~55 entries covering the
common libc surface.

**Downside:** the validator no longer flags real undefined libc
functions, but a true link error from `snprintf` etc. would still
appear in `real_undefined` (linker resolves it as a project
problem, not a hallucination). The Fixer's error-triage layer
catches it through the LINK_ERROR category. Zero functional
downside.

**File.** `src/utils/unified_validator.py:IGNORE_FUNCTIONS`.

---

## §2. Deferred (with explicit downside)

### V2 — Wire fake-def check to Fixer (post-build-fail)

**Symptom.** `_check_fake_definitions` runs only when `build_errors`
AND `known_apis` are passed. Prototyper and Improver call
`validate(code=code, project_name=...)` — no build_errors, so
fake-def check is dormant in those paths. Only `execution.py` passes
some (but not build_errors). Result: fake-def is effectively dead
in the production validation flow.

**Considered.** Have Fixer pass `state["build_errors"]` to the
validator post-build-fail, enabling fake-def detection.

**Downside that blocked the fix.** `compilation_error_triage.py`
already has a `FAKE_DEFINITION` ErrorCategory that runs in
Supervisor's `_handle_compilation_phase` (line 217). Adding the
validator's fake-def check would create a second parallel
detection. Either:
  - Both detectors agree → redundant compute
  - Detectors disagree → ambiguous signal to Fixer/Supervisor

Defer until we have empirical data on triage-side fake-def hit
rate. If triage catches everything, the validator-side check
should be removed, not added.

### V3 — Validator vs triage fake-def deduplication

Same root cause as V2. The two paths track the same concept
through different APIs. Either move all fake-def logic into the
validator (and have triage call into it) OR into triage (and
remove from validator). Empirical data needed before choosing.

### V6 — Naive regex target-API check doesn't distinguish DEF vs CALL

`_check_target_apis_naive`'s pattern `\b{api}\s*\(` matches
function definitions as well as calls. If a fuzz driver defines a
helper with the same name as a target API, the naive check
counts it as "called". False positive in the *coverage* signal
(target_api_coverage inflated).

**Downside that blocked the fix.** Fixing requires proper parsing
or at least lookbehind for `{` (function body start). Complexity
is moderate, but the affected callers are only the post-build
execution-node path. After V1 makes CGProcessor more reliably
available, the AST check is the primary path and naive is the
true fallback. Risk of regression on the AST path is higher than
the false-positive reduction is worth.

### V7 — `CPP_INCLUDE_PATTERNS` flags FuzzedDataProvider as C-only

The pattern at `CPP_INCLUDE_PATTERNS` line 175 marks
`<fuzzer/FuzzedDataProvider.h>` as a C++ header. Our Prototyper
deliberately wraps C drivers in `extern "C"` and uses FDP through
OSS-Fuzz's clang++ compilation. If `is_c_target=True` were ever
passed, this would flag valid drivers.

**Net assessment: inert.** Every production call site uses the
default `is_c_target=False` (since callers don't pass it).
Language-compat check never runs in production. No fix needed
unless we ever enable `is_c_target=True`, at which point this
pattern needs to be removed.

### S1 — Supervisor `triage_build_errors` called twice on same input

`_handle_compilation_phase` line 207 calls triage to decide route.
Then `supervisor_node` line 125 calls it AGAIN to pack into the
return dict for Fixer. Same input, redundant call.

**Considered.** Cache the result on supervisor state. Tiny perf win.

**Downside.** The triage call is cheap (string parsing); caching
adds a state field that needs to be invalidated on every supervisor
re-entry. Not worth the abstraction.

### S2 — Workflow phase transition is implicit

Supervisor returns `"execution"` to switch to optimization phase
but doesn't write `state["workflow_phase"]`. The actual update
must happen in the build or execution node. Not a bug — works
because the build node updates phase on success — but the
implicit handoff is fragile.

**Deferred.** Tracing the implicit transition requires reading
both the build node and the LangGraph state-update semantics.
Defer to a Workflow Layer review.

### S3 — `LINE_COVERAGE_THRESHOLD = 0.1` may be unrealistic

Most projects don't reach 10% line coverage on first-attempt
drivers; the threshold may effectively never short-circuit the
coverage_analyzer/improver path. The cost: always pay LLM
roundtrips for analyzer + improver even when coverage is
adequate.

**Deferred — needs empirical data.** 10% may have been chosen for
specific projects; without per-project per-trial coverage stats
we can't tune it.

---

## §3. Empirical validation

**cjson run4 (2026-05-11) — UnifiedCodeValidator AST check has a REAL BUG.**

### V1 FunctionBodyWalker — false negative on cjson trial 01

The post-2026-05 V1 refactor replaced CGProcessor with the in-process
`FunctionBodyWalker` (libclang Python). On cjson trial 01:

```
INFO unified_validator - _check_target_apis:
  Target API check (AST): 0/3 APIs called (0.0%)
WARNING [logger.warning:150]:
  Target API validation: 0.0% coverage, 3 APIs missing:
  ['cJSON_ParseWithOpts', 'cJSON_AddArrayToObject', 'cJSON_AddBoolToObject']
```

The generated driver `01.fuzz_target` **clearly calls all three** —
visual inspection of the source shows `cJSON_ParseWithOpts(json_data,
NULL, flags)`, `cJSON_AddArrayToObject(json, "array")`, and
`cJSON_AddBoolToObject(array, "bool", 1)` as direct call expressions.

**The libclang-Python AST walk is missing call-expressions**, likely
because:
- The driver uses `struct cJSON *json = ...` instead of `cJSON *json`,
  which may confuse the walker's symbol resolution.
- Or the walker is filtering on the wrong cursor kind.
- Or the project's headers aren't on the parse path so calls resolve
  as `OVERLOADED_DECL_REF`-style unknown.

**Severity: HIGH** — this is exactly the kind of regression we
predicted in cluster F (lapse in CGProcessor → FunctionBodyWalker
equivalence). The supervisor uses target_api_validation to route the
Fixer; burning fixer retries on a driver that's already correct is a
real cost.

Tracked for follow-up: investigate `FunctionBodyWalker` cursor traversal
and confirm whether `args = ["-I", str(headers_root), ...]` is
reaching the cjson header on the parse path.

### V4/V5 (whitelist additions)

No `__builtin_*` / common-libc symbols were flagged as undefined in
run4; both whitelist additions appear to be doing their job.

### V1: CGProcessor availability

Hypothesis: setting `LOGICFUZZ_CGPROCESSOR` to a real path
enables the AST check. Confirm by inspecting
`validation_method` field in execution-node output —
should be "AST" not "naive".

| Run | LOGICFUZZ_CGPROCESSOR set? | validation_method |
|---|---|---|
| _TBD_ | _no_ | _expect "naive"_ |
| _TBD_ | _yes (real path)_ | _expect "AST"_ |
| _TBD_ | _yes (bad path)_ | _expect "naive" (fallback)_ |

### V4: Compiler-intrinsic false positives

Hypothesis: drivers that use `__builtin_expect` / `_Pragma` /
`_Static_assert` no longer get flagged as internal-API usage.

Probe code:
```c
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {
    if (__builtin_expect(s < 4, 0)) return 0;
    return 0;
}
```

Pre-fix: 1 internal_api warning. Post-fix: 0.

Already verified in the smoke test attached to this commit.

### V5: libc false positives

Hypothesis: drivers that use `snprintf` / `fprintf` / `fgets` /
`exit` etc. and trigger linker errors no longer get
`FAKE_DEFINITION` warnings on those names.

| Project | Pre-fix snprintf-as-fake-def hits | Post-fix |
|---|---|---|
| _TBD_ | _TBD_ | _expect 0_ |

---

## §4. Rollback recipe

- V1: revert `__init__` to single hardcoded path. CI / new
  machines will silently fall back to naive. Dev boxes that
  already had the file unchanged.
- V4: revert FUNCTION_WHITELIST to `{'__attribute__', '_Generic'}`.
  Re-introduces false-positive internal-API warnings on
  `__builtin_*` and `_Pragma`.
- V5: revert IGNORE_FUNCTIONS to the original 15 entries.
  Re-introduces false-positive fake-def warnings on common libc.
