# C++-Clean Driver Rendering + Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make generated fuzz drivers compile under `$CXX` (OSS-Fuzz compiles C fuzzers as clang++ + `extern "C"`), fixing the cjson-class 0/N compile failures under DeepSeek.

**Architecture:** Three layers — (C1) the skeleton renderer reconstructs const-qualified pointer arg types from the extractor's `is_const` flags; (C2) a post-LLM repair re-balances a dropped `extern "C"` block; (C3) the C++ error triage routes const/`extern "C"` errors to useful fix strategies, and a `$CXX -fsyntax-only` gate (reusing `compile_validate`) catches the tail before the trial build wastes fix attempts.

**Tech Stack:** Python 3.10, pytest, Docker (OSS-Fuzz images), clang++ (`$CXX`).

## Global Constraints

- **Preserve `$CC` correctness:** drivers must remain valid C (the `#ifdef __cplusplus` guards stay; const additions are valid C too).
- **No per-project fork build edits** (no forcing `$CC`); fixes live in generation + validation.
- **Gate-off / no regression:** projects already compiling (GPT runs: c-ares ~91%, lcms ~95%) must not regress; opaque-handle args still render as `void *`.
- **C3 gate fails OPEN** on infra error (mirrors `compile_validate.validate_compilable`): never silently drop a driver on a Docker/toolchain hiccup.
- **Tests:** `python3 -m pytest tests/ -q`. New unit tests must not require Docker.
- Commit after each task; stage only the task's files (`git add <exact paths>`, never `-A`).

---

### Task 1: C1 — const-qualified pointer arg rendering

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` (add helper near the other type helpers ~line 150; apply at the arg-decl site ~line 870 `c_type = target_arg.type`)
- Test: `tests/test_cxx_clean_rendering.py` (create)

**Interfaces:**
- Produces: `const_qualified_type(type_str: str, is_const: list | None) -> str` — reconstructs a const-qualified C type from the bare type string + per-level const flags (`is_const[0]` = const on the base type; `is_const[i>0]` = const on the i-th pointer level).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cxx_clean_rendering.py
from liberator_adapter.driver.synthesis.skeleton_generator import const_qualified_type

def test_const_qualified_double_pointer():
    # cJSON_ParseWithOpts return_parse_end: 'char * *' + [True,False,False] -> const char **
    assert const_qualified_type("char * *", [True, False, False]).replace(" ", "") == "constchar**"

def test_const_qualified_single_pointer():
    assert const_qualified_type("char *", [True, False]).replace(" ", "") == "constchar*"

def test_no_const_unchanged():
    assert const_qualified_type("int", [False]) == "int"
    assert const_qualified_type("cJSON *", [False, False]) == "cJSON *"

def test_missing_is_const_is_noop():
    assert const_qualified_type("char * *", None) == "char * *"
    assert const_qualified_type("char * *", []) == "char * *"

def test_pointer_level_const():
    # 'char *' with const on the pointer (char * const): is_const=[False, True]
    assert const_qualified_type("char *", [False, True]).replace(" ", "") == "char*const"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k const_qualified -q`
Expected: FAIL — `ImportError: cannot import name 'const_qualified_type'`.

- [ ] **Step 3: Implement the helper**

```python
# liberator_adapter/driver/synthesis/skeleton_generator.py  (module scope, near ~line 150)
def const_qualified_type(type_str, is_const):
    """Reconstruct a const-qualified C type from the bare type string + per-level
    const flags. The extractor stores e.g. cJSON_ParseWithOpts return_parse_end as
    type='char * *', is_const=[True, False, False] (= const char **); the bare
    type string drops the const, which is a *warning* under $CC but a hard *error*
    under $CXX. is_const[0] = const on the base type; is_const[i>0] = const on the
    (i-1)-th pointer level. No-op when is_const is empty/falsy."""
    if not is_const or not any(is_const):
        return type_str
    stars = type_str.count('*')
    base = type_str.replace('*', '').strip()
    out = (("const " + base) if is_const[0] else base)
    for i in range(stars):
        out += " *"
        if i + 1 < len(is_const) and is_const[i + 1]:
            out += " const"
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k const_qualified -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Apply at the arg-declaration site**

In `skeleton_generator.py` `_apply_arg_bindings` at the arg Variable creation (`c_type = target_arg.type`, ~line 870), reconstruct const BEFORE the opaque-handle/`void *` mapping is considered (const reconstruction only changes non-opaque pointer types; opaque handles still map to `void *`):

```python
        c_type = const_qualified_type(
            target_arg.type, getattr(target_arg, 'is_const', None))
```
Leave the subsequent opaque→`void *` handling unchanged (it operates on `_is_internal_opaque_type`, which a `const char **` is not).

- [ ] **Step 6: Run the unit suite**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_cxx_clean_rendering.py
git commit -m "fix(render): const-qualified pointer arg types for C++ compile (C1)"
```

---

### Task 2: C2 — `extern "C"` balance repair (post-LLM)

**Files:**
- Modify: `src/agents/prototyper.py` (add helper at module scope; call it in the post-process chain near `_ensure_project_headers`, ~line 997)
- Test: `tests/test_cxx_clean_rendering.py` (append)

**Interfaces:**
- Produces: `balance_extern_c(code: str) -> str` — appends a closing `#ifdef __cplusplus\n}\n#endif` when the code has a guarded `extern "C" {` with no matching guarded close; idempotent otherwise.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cxx_clean_rendering.py  (append)
from src.agents.prototyper import balance_extern_c

_UNBALANCED = '''#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
'''

def test_balance_adds_missing_close():
    out = balance_extern_c(_UNBALANCED)
    assert out.count('extern "C" {') == 1
    assert out.count('#ifdef __cplusplus') == 2  # open guard + close guard
    assert out.rstrip().endswith('#endif')

def test_balance_noop_when_balanced():
    balanced = _UNBALANCED + '\n#ifdef __cplusplus\n}\n#endif\n'
    assert balance_extern_c(balanced) == balanced

def test_balance_noop_without_extern_c():
    plain = 'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s){return 0;}\n'
    assert balance_extern_c(plain) == plain
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k balance -q`
Expected: FAIL — `ImportError: cannot import name 'balance_extern_c'`.

- [ ] **Step 3: Implement the helper**

```python
# src/agents/prototyper.py  (module scope)
def balance_extern_c(code: str) -> str:
    """If `code` opens a guarded `extern "C" {` (under #ifdef __cplusplus) without a
    matching guarded close, append `#ifdef __cplusplus } #endif`. Idempotent; no-op
    when balanced or when no `extern "C"` is present. Robust to an LLM dropping the
    closing block (invisible under $CC, fatal under $CXX)."""
    if 'extern "C" {' not in code:
        return code
    opens = code.count('extern "C" {')
    # a guarded close is a `}` line whose surrounding lines are #ifdef/#endif __cplusplus
    closes = 0
    lines = code.splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() == '}' and i >= 1 and lines[i - 1].strip() == '#ifdef __cplusplus':
            closes += 1
    if closes >= opens:
        return code
    suffix = '\n#ifdef __cplusplus\n}\n#endif\n'
    return code.rstrip('\n') + '\n' + suffix
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k balance -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire into the prototyper post-process**

In `prototyper.py`, where the final driver code is post-processed (the chain that calls `_ensure_project_headers(...)`, ~line 997), add `code = balance_extern_c(code)` immediately AFTER the header-ensuring step so it operates on the final assembled driver.

- [ ] **Step 6: Run the unit suite**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/agents/prototyper.py tests/test_cxx_clean_rendering.py
git commit -m "fix(render): re-balance dropped extern \"C\" block post-LLM (C2)"
```

---

### Task 3: C3a — correct triage routing for C++ errors

**Files:**
- Modify: `src/utils/compilation_error_triage.py` (`TYPE_ERROR_PATTERNS` ~:193, `LANGUAGE_MISMATCH_PATTERNS` ~:219, `_get_recommended_strategy` ~:282)
- Test: `tests/test_cxx_clean_rendering.py` (append)

**Interfaces:**
- Consumes: `CompilationErrorTriager().triage(build_errors: list[str]) -> TriageResult` with `.primary_category: ErrorCategory` and `.recommended_strategy: FixStrategy`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cxx_clean_rendering.py  (append)
from src.utils.compilation_error_triage import (
    CompilationErrorTriager, ErrorCategory, FixStrategy)

def test_no_matching_function_is_type_error_not_include():
    t = CompilationErrorTriager().triage(
        ["error: no matching function for call to 'cJSON_ParseWithOpts'"])
    assert t.primary_category == ErrorCategory.TYPE_ERROR
    assert t.recommended_strategy != FixStrategy.ADD_INCLUDE
    assert t.recommended_strategy != FixStrategy.FIX_INCLUDE_PATH

def test_unterminated_extern_c_is_language_mismatch():
    t = CompilationErrorTriager().triage(
        ["error: expected '}'", "note: to match this '{'  extern \"C\" {"])
    assert t.primary_category in (ErrorCategory.LANGUAGE_MISMATCH, ErrorCategory.TYPE_ERROR)
    assert t.recommended_strategy not in (FixStrategy.ADD_INCLUDE, FixStrategy.FIX_INCLUDE_PATH)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k "type_error or extern_c" -q`
Expected: likely FAIL — `extern "C"` brace error mis-triaged / recommended strategy is an include strategy.

- [ ] **Step 3: Implement**

- Add an `extern "C"` brace pattern to `LANGUAGE_MISMATCH_PATTERNS` (~:219):
  ```python
      (r"to match this '\{'.*extern \"C\"", "unterminated_extern_c"),
  ```
- In `_get_recommended_strategy` (~:282), ensure `ErrorCategory.TYPE_ERROR` and
  `ErrorCategory.LANGUAGE_MISMATCH` map to a regenerate/LLM-fix strategy (e.g. the
  existing `FixStrategy.REGENERATE` or `FIX_ENTRYPOINT` — whichever the enum at
  `:52-57` provides for "hand the real error back to the LLM"), NOT `ADD_INCLUDE`/
  `FIX_INCLUDE_PATH`. Read the `FixStrategy` enum first and pick the existing
  member that means "regenerate with the error context"; do not invent a new one
  unless none fits.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cxx_clean_rendering.py -k "type_error or extern_c" -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/utils/compilation_error_triage.py tests/test_cxx_clean_rendering.py
git commit -m "fix(triage): route C++ const/extern-C errors away from ADD_INCLUDE (C3a)"
```

---

### Task 4: C3b — `$CXX -fsyntax-only` validation gate for the generated driver

**Files:**
- Modify: `run_single_fuzz.py` (add a pre-trial validation call) OR `src/workflow/nodes` build path — locate where the per-trial driver is first built; insert the gate before it.
- Reuse: `tools/merge_drivers/compile_validate.py:validate_compilable` (already compiles a TU with the project's `$CXX` + `extern "C"` + `-iquote` flags; fail-open).
- Test: `tests/test_extraction_integration.py` (append, opt-in/slow)

**Interfaces:**
- Consumes: `validate_compilable(driver_path, benchmark, iquote_dirs) -> (ok: bool, errors: list[str])` (confirm the real signature in `compile_validate.py` before wiring).

- [ ] **Step 1: Read the existing machinery**

Read `tools/merge_drivers/compile_validate.py:validate_compilable` and `run_single_fuzz.py:_compile_validate_candidates` / `_iquote_dirs_for_target` to learn the exact signature + how `-iquote` dirs are derived for a target. Confirm it compiles with `$CXX` for C projects.

- [ ] **Step 2: Write the failing (opt-in) integration test**

```python
# tests/test_extraction_integration.py  (append)
@pytest.mark.skipif(os.environ.get("RUN_EXTRACTION_INTEGRATION") != "1",
                    reason="docker; set RUN_EXTRACTION_INTEGRATION=1")
def test_cjson_generated_driver_compiles_cxx():
    # After C1+C2, a generated cjson driver must compile under the real $CXX build.
    import glob, subprocess, os
    drv = sorted(glob.glob("results/output-cjson-project/fuzz_targets/*.fuzz_target"))
    assert drv, "no generated cjson driver to check"
    # compile the first driver as the trial does ($CXX at target_path); rc==0 expected
    # (this mirrors the manual repro; uses the cjson OSS-Fuzz image)
    # implementation: docker run gcr.io/oss-fuzz/cjson:latest, cp driver to target_path, compile
    ...
```
Replace the `...` with the concrete docker-run repro used in this design's investigation
(driver → `/src/cjson/fuzzing/cjson_read_fuzzer.c`, run `compile`, assert rc==0).

- [ ] **Step 3: Wire the gate**

At the pre-trial build site, call `validate_compilable` on the generated driver; on failure, attach the real `$CXX` errors to the state passed to the triage/Fixer (so Task 3's routing applies) instead of letting the heavy trial build be the first detector. Fail OPEN on infra error (catch + log + proceed), per the global constraint.

- [ ] **Step 4: Verify (opt-in)**

Run: `RUN_EXTRACTION_INTEGRATION=1 python3 -m pytest tests/test_extraction_integration.py -k cjson_generated -q`
Expected: PASS (driver compiles under `$CXX`).

- [ ] **Step 5: Commit**

```bash
git add run_single_fuzz.py tests/test_extraction_integration.py
git commit -m "feat(validate): pre-trial \$CXX syntax gate for generated drivers (C3b)"
```

---

### Task 5: Integration regression — cjson under DeepSeek compiles

**Files:**
- Test: `tests/test_extraction_integration.py` (append, opt-in/slow)

- [ ] **Step 1: Add the opt-in regression test**

```python
# tests/test_extraction_integration.py  (append)
@pytest.mark.skipif(os.environ.get("RUN_CJSON_DEEPSEEK") != "1",
                    reason="full LLM+docker run; set RUN_CJSON_DEEPSEEK=1")
def test_cjson_deepseek_compiles_some():
    import subprocess, glob, json, os
    subprocess.run("LLM_NUM_EXP=4 python3 run_logicfuzz.py -y comparison/cjson.yaml "
                   "-l deepseek-v4-flash", shell=True, timeout=5400, check=False)
    rs = glob.glob("results/output-cjson-project/status/*/result.json")
    comp = sum(1 for f in rs if json.load(open(f)).get("compiles"))
    assert comp > 0, f"still 0 compiled of {len(rs)}"
```

- [ ] **Step 2: Run it once manually**

Run: `RUN_CJSON_DEEPSEEK=1 python3 -m pytest tests/test_extraction_integration.py -k deepseek_compiles -q`
Expected: PASS — `compiled > 0` (target: most of N).

- [ ] **Step 3: Commit**

```bash
git add tests/test_extraction_integration.py
git commit -m "test(cxx): opt-in cjson/deepseek compile regression"
```

---

## Self-Review

- **Spec coverage:** C1 → Task 1; C2 → Task 2; C3 (triage) → Task 3; C3 (`$CXX` gate) → Task 4; regression → Task 5. Blast-radius / non-goals respected (no per-project `$CC`, no detection reframe).
- **Placeholder scan:** Task 4 has two "confirm the real signature / replace `...` with the concrete repro" steps — these are *read-then-wire* against existing code (`validate_compilable`) and the already-proven docker repro, not vague requirements; everything else carries complete code. Task 3 says "pick the existing `FixStrategy` member" — bounded by reading the enum.
- **Type consistency:** `const_qualified_type(type_str, is_const)`, `balance_extern_c(code)`, and the triage `ErrorCategory`/`FixStrategy` names match across tasks and tests.
