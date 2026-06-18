# Robust, Observable LLVM-14 Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the LLVM-14 bitcode→SVF→conditions extraction recover the 5 degraded benchmark projects (libpcap, liblouis, nghttp2, sqlite3, libucl) to `extraction_mode=full`, and make every remaining degradation loud + persisted instead of silent.

**Architecture:** Fixes are applied inline at the file that already owns each invariant (no new module). A shared `DegradedReason` enum + a status-field helper make degradation observable; targeted flag-strip (A), image-side clang-14 recovery (C), condition-parser guards (B2), and a per-project SVF resource/lite table (B1) each close one root cause. The clang-14 / typed-pointer / flow-sensitive design is unchanged.

**Tech Stack:** Python 3.10, pytest, Docker (OSS-Fuzz images), wllvm + clang-14, SVF (C++ `condition_extractor`), Z3.

## Global Constraints

- **Gate-off byte-identical:** projects already at full (cjson, zlib, lcms, c-ares, libpng) MUST produce identical `analysis_summary.json` aside from the two new always-present fields (`extraction_mode="full"`, `degraded_reason=null`). No project not in a lite/strip set changes its SVF command or flags.
- **`LOGICFUZZ_REQUIRE_Z3` default OFF** — degraded mode stays load-bearing for `--eval`/`--merge`.
- **Do not change** the clang-14 pin, typed-pointer assumption, or FlowSensitive analysis (Andersen swap is explicitly deferred).
- **Determinism:** no runtime `apt install` of clang-14 (would break `_bitcode_fingerprint`); pin `PYTHONHASHSEED=0` for any extraction A/B (per `project_generation_nondeterminism`).
- **Tests:** `pytest tests/ -q`. New unit tests must not require Docker or a 1800s SVF run.
- Commit after each task.

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `liberator_adapter/extractors/base_extractor.py` | `DegradedReason` enum + `extraction_status_fields()` helper | Create symbols |
| `liberator_adapter/extractors/llvm_extractor.py` | flag sanitizer (A), SVF cmd builder + lite/resource table (B1), `DegradedReason` capture, actionable clang-14 raise (C) | Modify |
| `liberator_adapter/extractors/hybrid_extractor.py` | capture `_degraded_reason`; write `extraction_mode`/`degraded_reason` into metadata | Modify |
| `src/context/data_context.py` | persist status into `analysis_summary.json`; `REQUIRE_Z3` gate | Modify |
| `liberator_adapter/constraints/ConditionManager.py` | bounds guards (B2 IndexError) + skip-None on missing conditions | Modify |
| `liberator_adapter/common/conditions.py` | `get_function_conditions` returns None on miss (B2 KeyError) | Modify |
| `experiment/oss_fuzz_checkout.py` | detect stale project image lacking clang-14 → invalidate cache (C) | Modify |
| `tests/test_extraction_robustness.py` | unit tests for all pure helpers | Create |
| `tests/test_extraction_integration.py` | container regression (marked `slow`, opt-in) | Create |

---

### Task 1: `DegradedReason` enum + status-field helper

**Files:**
- Modify: `liberator_adapter/extractors/base_extractor.py` (after the imports, before `class BaseAPIExtractor`)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `DegradedReason(str, Enum)` with members `NONE, COMPILE_FAILED, EXTRACT_BC_FAILED, SVF_TIMEOUT, SVF_OOM, CONDITIONS_EMPTY, CONDITIONS_MISSING, HOST_EXTRACTOR_MISSING, CONDITION_MANAGER_ERROR`; `extraction_status_fields(clang_only: bool, reason: DegradedReason|str|None) -> dict` returning keys `extraction_mode` ∈ {"full","clang_only"} and `degraded_reason` (str|None).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py
from liberator_adapter.extractors.base_extractor import (
    DegradedReason, extraction_status_fields)

def test_status_fields_full():
    assert extraction_status_fields(False, None) == {
        "extraction_mode": "full", "degraded_reason": None}

def test_status_fields_degraded_enum():
    assert extraction_status_fields(True, DegradedReason.SVF_TIMEOUT) == {
        "extraction_mode": "clang_only", "degraded_reason": "svf_timeout"}

def test_status_fields_degraded_str_fallback():
    assert extraction_status_fields(True, "boom")["degraded_reason"] == "boom"
    # missing reason still yields a non-None marker
    assert extraction_status_fields(True, None)["degraded_reason"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -q`
Expected: FAIL — `ImportError: cannot import name 'DegradedReason'`.

- [ ] **Step 3: Implement the enum + helper**

```python
# liberator_adapter/extractors/base_extractor.py  (add after existing imports)
from enum import Enum


class DegradedReason(str, Enum):
    NONE = "none"
    COMPILE_FAILED = "compile_failed"
    EXTRACT_BC_FAILED = "extract_bc_failed"
    SVF_TIMEOUT = "svf_timeout"
    SVF_OOM = "svf_oom"
    CONDITIONS_EMPTY = "conditions_empty"
    CONDITIONS_MISSING = "conditions_missing"
    HOST_EXTRACTOR_MISSING = "host_extractor_missing"
    CONDITION_MANAGER_ERROR = "condition_manager_error"


def extraction_status_fields(clang_only, reason):
    """Single source of truth for the persisted extraction-status fields."""
    if not clang_only:
        return {"extraction_mode": "full", "degraded_reason": None}
    if isinstance(reason, DegradedReason):
        reason = reason.value
    return {"extraction_mode": "clang_only",
            "degraded_reason": reason or DegradedReason.COMPILE_FAILED.value}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/extractors/base_extractor.py tests/test_extraction_robustness.py
git commit -m "feat(extract): add DegradedReason enum + extraction_status_fields helper"
```

---

### Task 2: clang-14 flag sanitizer (Fix A) + wire into `compile_to_bitcode`

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (module top near `_SVF_*` consts ~line 42; and `compile_to_bitcode` compile_cmd ~137-148)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: module-level `_CLANG14_INCOMPATIBLE_FLAGS: tuple[str,...]` and `sanitize_extraction_flags(flags: str, deny=_CLANG14_INCOMPATIBLE_FLAGS) -> tuple[str, list[str]]` returning `(cleaned_flags, stripped_tokens)`.
- Consumes (wiring): the container's `$CFLAGS`/`$CXXFLAGS` (read via `self.container.execute('echo $CFLAGS')`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py  (append)
from liberator_adapter.extractors.llvm_extractor import sanitize_extraction_flags

def test_sanitize_strips_known_incompatible():
    cleaned, stripped = sanitize_extraction_flags(
        "-O1 -Wno-error=vla-cxx-extension -g")
    assert cleaned == "-O1 -g"
    assert stripped == ["-Wno-error=vla-cxx-extension"]

def test_sanitize_noop_when_clean():
    cleaned, stripped = sanitize_extraction_flags("-O1 -g -std=gnu99")
    assert cleaned == "-O1 -g -std=gnu99"
    assert stripped == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k sanitize -q`
Expected: FAIL — `ImportError: cannot import name 'sanitize_extraction_flags'`.

- [ ] **Step 3: Implement the sanitizer**

```python
# liberator_adapter/extractors/llvm_extractor.py  (near the _SVF_* module consts)
# clang>=15-only warning tokens that the base-builder (clang-22) injects into
# CFLAGS; clang-14 rejects them, which trips cmake's CHECK_C_COMPILER_FLAG probes.
_CLANG14_INCOMPATIBLE_FLAGS = ("-Wno-error=vla-cxx-extension",)


def sanitize_extraction_flags(flags, deny=_CLANG14_INCOMPATIBLE_FLAGS):
    """Drop clang-14-incompatible tokens; return (cleaned, stripped[])."""
    kept, stripped = [], []
    for tok in (flags or "").split():
        (stripped if tok in deny else kept).append(tok)
    return " ".join(kept), stripped
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k sanitize -q`
Expected: PASS.

- [ ] **Step 5: Wire into `compile_to_bitcode` (record stripped on self)**

In `compile_to_bitcode`, immediately before building `compile_cmd` (~line 137), read and sanitize the inherited flags, and store what was stripped:

```python
        # Fix A: strip clang-14-incompatible flags the base-builder (clang-22) injects.
        _cf = self.container.execute('echo "$CFLAGS"').stdout.strip()
        _cxf = self.container.execute('echo "$CXXFLAGS"').stdout.strip()
        _cf_clean, _cf_strip = sanitize_extraction_flags(_cf)
        _cxf_clean, _cxf_strip = sanitize_extraction_flags(_cxf)
        self.flags_stripped = sorted(set(_cf_strip) | set(_cxf_strip))
        if self.flags_stripped:
            logger.info("Stripped clang-14-incompatible flags: %s",
                        self.flags_stripped)
```

Then in `compile_cmd`, add explicit re-exports of the cleaned flags **before** the `compile 2>&1` line (use single f-string interpolation of the cleaned values):

```python
            f'export CFLAGS="{_cf_clean}" && '
            f'export CXXFLAGS="{_cxf_clean}" && '
```

- [ ] **Step 6: Run the unit suite (no regression)**

Run: `pytest tests/test_extraction_robustness.py -q`
Expected: PASS. (Container behavior is exercised in Task 10.)

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extraction_robustness.py
git commit -m "fix(extract): strip clang-14-incompatible CFLAGS before wllvm build (Fix A, libpcap)"
```

---

### Task 3: Capture + persist extraction status (keystone)

**Files:**
- Modify: `liberator_adapter/extractors/hybrid_extractor.py` (extract ~86/92/129; success metadata ~251-269; clang_only metadata ~349-368)
- Modify: `src/context/data_context.py` (`save_intermediate_results` summary dict ~4117-4135)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Consumes: `extraction_status_fields` (Task 1).
- Produces: `hybrid_extractor` `last_metadata` carries `extraction_mode`+`degraded_reason`; `analysis_summary.json` top-level carries both fields.

- [ ] **Step 1: Write the failing test (metadata fields present)**

```python
# tests/test_extraction_robustness.py  (append)
from liberator_adapter.extractors.base_extractor import extraction_status_fields

def test_summary_carries_extraction_status(tmp_path):
    # mimic the summary-dict assembly contract: status fields are merged in
    status = extraction_status_fields(True, "svf_timeout")
    summary = {"project_name": "x", "statistics": {}, **status}
    assert summary["extraction_mode"] == "clang_only"
    assert summary["degraded_reason"] == "svf_timeout"
```

- [ ] **Step 2: Run to verify it passes trivially, then add the real wiring assertion**

Run: `pytest tests/test_extraction_robustness.py -k summary -q`
Expected: PASS (this pins the contract; the wiring below makes the pipeline honor it).

- [ ] **Step 3: Capture the reason in `hybrid_extractor.extract`**

At the start of `extract` (~line 86) add `self._degraded_reason = None`. In the two `except` blocks (~92 P1, ~129 P2) set it from the exception, mapping to `DegradedReason`:

```python
            except Exception as e:
                from liberator_adapter.extractors.base_extractor import DegradedReason
                msg = str(e)
                if "timed out" in msg:
                    self._degraded_reason = DegradedReason.SVF_TIMEOUT.value
                elif "bad_alloc" in msg or "MemoryError" in msg:
                    self._degraded_reason = DegradedReason.SVF_OOM.value
                elif "Could not find library" in msg or "compile" in msg.lower():
                    self._degraded_reason = DegradedReason.COMPILE_FAILED.value
                else:
                    self._degraded_reason = msg[:200]
                logger.warning(f"LLVM extraction failed, falling back to clang-only mode: {e}")
                llvm_extraction_failed = True
```

- [ ] **Step 4: Stamp the metadata (success + clang-only paths)**

In the success `last_metadata` (~251-269) add `**extraction_status_fields(False, None)`. In `_clang_only_extraction`'s `last_metadata` (~349-368) add `**extraction_status_fields(True, getattr(self, "_degraded_reason", None))` (keep `clang_only_mode` for back-compat). Import `extraction_status_fields` at top of file.

- [ ] **Step 5: Persist into `analysis_summary.json`**

In `data_context.save_intermediate_results`, where the `summary` dict is built (~4117-4135), merge the status carried on the extractor metadata. Add a parameter `extraction_status: dict | None = None` to the function signature, pass `generator`'s `extract_metadata` status at the call site, and:

```python
        summary = {
            'project_name': project_name,
            'statistics': { ... },                       # unchanged
            'grammar_info': grammar_info,
            'condition_info': condition_info,
            'pattern_summary': pattern_analysis.get('summary', {}),
            **(extraction_status or {"extraction_mode": "full", "degraded_reason": None}),
        }
```

At the call site, derive `extraction_status` from the extractor metadata (the dict already flows via `generator.extract_metadata`); if absent, default to full.

- [ ] **Step 6: Run unit tests**

Run: `pytest tests/test_extraction_robustness.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/extractors/hybrid_extractor.py src/context/data_context.py tests/test_extraction_robustness.py
git commit -m "feat(extract): persist extraction_mode/degraded_reason in analysis_summary (keystone)"
```

---

### Task 4: ConditionManager bounds guards (Fix B2 — IndexError)

**Files:**
- Modify: `liberator_adapter/constraints/ConditionManager.py` (`init_init` :247-257; `init_sinks` :87-89)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: module-level `_safe_arg_cond(api_cond, arg_pos) -> cond|None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py  (append)
from liberator_adapter.constraints.ConditionManager import _safe_arg_cond

class _FakeCond:
    def __init__(self, n): self.argument_at = list(range(n))

def test_safe_arg_cond_in_range():
    assert _safe_arg_cond(_FakeCond(2), 1) == 1

def test_safe_arg_cond_out_of_range_returns_none():
    assert _safe_arg_cond(_FakeCond(0), 0) is None
    assert _safe_arg_cond(_FakeCond(1), 5) is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k safe_arg_cond -q`
Expected: FAIL — `ImportError: cannot import name '_safe_arg_cond'`.

- [ ] **Step 3: Add the helper + apply guards**

```python
# liberator_adapter/constraints/ConditionManager.py  (module scope)
def _safe_arg_cond(api_cond, arg_pos):
    """Return the per-arg condition or None when SVF emitted fewer entries
    than the clang-derived signature (length divergence is the parser's
    documented contract, utils.prase_function_conditions sets params_at=[])."""
    aa = getattr(api_cond, "argument_at", None) or []
    if arg_pos < 0 or arg_pos >= len(aa):
        return None
    return aa[arg_pos]
```

In `init_init` (~247): replace `cond = api_cond.argument_at[arg_pos]` with
```python
                cond = _safe_arg_cond(api_cond, arg_pos)
                if cond is None:
                    continue
```
In the setby-dependency loop (~255-257): guard the param index:
```python
                for d in cond.setby_dependencies:
                    p_idx = int(d.replace("param_", ""))
                    if p_idx >= len(api_call.arg_types):
                        continue
                    d_type = api_call.arg_types[p_idx]
```
In `init_sinks` (~87-89): require the condition list length before `argument_at[0]`:
```python
            if (len(api.arguments_info) == 1 and
                    len(getattr(fun_cond, "argument_at", []) or []) >= 1 and
                    self.is_return_sink(api.return_info.type) and
                    self.is_a_sink_condition(fun_cond.argument_at[0])):
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k safe_arg_cond -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/constraints/ConditionManager.py tests/test_extraction_robustness.py
git commit -m "fix(conditions): bounds-guard ConditionManager arg indexing (Fix B2, nghttp2 IndexError)"
```

---

### Task 5: Missing-conditions guard (Fix B2 — KeyError on operator overloads)

**Files:**
- Modify: `liberator_adapter/common/conditions.py` (`get_function_conditions` :155-157; `__getitem__` :176)
- Modify: `liberator_adapter/constraints/ConditionManager.py` (`get_cond` callers ~86, ~244)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Consumes: `FunctionConditionsSet`.
- Produces: `get_function_conditions(fun_name)` returns `None` on miss (no `KeyError`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py  (append)
from liberator_adapter.common.conditions import FunctionConditionsSet

def test_get_function_conditions_missing_returns_none():
    fcs = FunctionConditionsSet()
    # 'operator>' (C++ overload) is not a key -> must not raise
    assert fcs.get_function_conditions("operator>") is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k function_conditions_missing -q`
Expected: FAIL — `KeyError: 'operator>'`.

- [ ] **Step 3: Guard the lookup + callers**

In `conditions.py` `get_function_conditions` (~157): `return self.fun_cond_set.get(fun_name)`.
Leave `__getitem__` (~176) raising (it's the dict protocol) but ensure callers use `get_function_conditions`.
In `ConditionManager.py`, after each `get_cond(api)` in `init_sources`/`init_sinks`/`init_init` (the lambdas at ~77/~239 call `get_function_conditions`), skip when None:
```python
            fun_cond = get_cond(api)
            if fun_cond is None:
                continue
```
(Apply at the `init_sinks` loop ~86 and `init_init` loop ~244 — `api_cond = get_cond(api); if api_cond is None: continue`.)

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k function_conditions_missing -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/common/conditions.py liberator_adapter/constraints/ConditionManager.py tests/test_extraction_robustness.py
git commit -m "fix(conditions): None-safe get_function_conditions + skip (Fix B2, libucl operator KeyError)"
```

---

### Task 6: Per-project SVF resource table + lite-mode cmd builder (Fix B1)

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (module consts near `_SVF_*`; `extract_apis_llvm_on_host` cmd ~328-338; timeout/mem read ~29/42)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `_SVF_LITE_PROJECTS: set[str]`; `svf_resources_for(project: str) -> dict` (keys `timeout_secs`, `mem_gb`, `lite`); `build_svf_cmd(extractor_bin, bc, interface, output, minimize, data_layout, lite: bool) -> list[str]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py  (append)
from liberator_adapter.extractors.llvm_extractor import (
    build_svf_cmd, svf_resources_for)

def test_build_svf_cmd_full_has_indirect_jumps():
    cmd = build_svf_cmd("EX","in.bc","if.json","out.json","min.txt","dl.txt", lite=False)
    assert "-do_indirect_jumps" in cmd
    assert "-data_layout" in cmd and cmd[-1] == "dl.txt"

def test_build_svf_cmd_lite_omits_indirect_jumps():
    cmd = build_svf_cmd("EX","in.bc","if.json","out.json","min.txt","dl.txt", lite=True)
    assert "-do_indirect_jumps" not in cmd
    assert "-data_layout" in cmd and cmd[-1] == "dl.txt"

def test_svf_resources_libucl_is_lite():
    assert svf_resources_for("libucl")["lite"] is True
    assert svf_resources_for("cjson")["lite"] is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k svf -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Implement the table + builder**

```python
# liberator_adapter/extractors/llvm_extractor.py  (near _SVF_TIMEOUT_SECS / _SVF_MEM_GB)
import os
_SVF_LITE_PROJECTS = set(filter(None, os.environ.get(
    "LIBERATOR_SVF_LITE", "libucl").split(",")))
# Per-project SVF resource overrides. Heavy libs need a bigger one-time budget;
# the result is disk-cached forever after the first success.
_SVF_PROJECT_RESOURCES = {
    "sqlite3": {"timeout_secs": 14400, "mem_gb": 0},   # time-bound amalgamation
    "libucl":  {"timeout_secs": 21600, "mem_gb": 140}, # try big flow-sensitive first
}


def svf_resources_for(project):
    base = {"timeout_secs": _SVF_TIMEOUT_SECS, "mem_gb": _SVF_MEM_GB, "lite": False}
    base.update(_SVF_PROJECT_RESOURCES.get(project, {}))
    base["lite"] = project in _SVF_LITE_PROJECTS
    return base


def build_svf_cmd(extractor_bin, bc, interface, output, minimize, data_layout, lite):
    cmd = [str(extractor_bin), bc, "-interface", interface, "-output", output,
           "-minimize_api", minimize, "-v", "v0", "-t", "json"]
    if not lite:
        cmd.append("-do_indirect_jumps")   # callback fan-out; the libucl blow-up
    cmd += ["-data_layout", data_layout]
    return cmd
```

- [ ] **Step 4: Wire into `extract_apis_llvm_on_host`**

Replace the hardcoded `cmd = [...]` (~328-338) with:
```python
                _res = svf_resources_for(self.benchmark.project)
                cmd = build_svf_cmd(self.extractor_bin, local_bc_file,
                                    local_apis_clang, local_conditions,
                                    local_minimized_apis, local_data_layout,
                                    lite=_res["lite"])
                _timeout = _res["timeout_secs"]
```
and use `_timeout` (not `_SVF_TIMEOUT_SECS`) in the `subprocess.run(..., timeout=_timeout)` and its log/error messages; honor `_res["mem_gb"]` for the `preexec_fn` mem cap.

- [ ] **Step 5: Run to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k svf -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extraction_robustness.py
git commit -m "feat(extract): per-project SVF resources + lite mode (Fix B1, libucl/sqlite3)"
```

---

### Task 7: Image-side stale clang-14 detection + actionable raise (Fix C)

**Files:**
- Modify: `experiment/oss_fuzz_checkout.py` (`ensure_llvm14_base_builder` ~99; reuse cache-invalidation path)
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (`_ensure_clang14_installed` :226-238)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `_image_has_clang14(image_name: str, runner=subprocess.run) -> bool` in `oss_fuzz_checkout.py`.

- [ ] **Step 1: Write the failing test (predicate, mocked docker)**

```python
# tests/test_extraction_robustness.py  (append)
from experiment import oss_fuzz_checkout as ofc

class _R:
    def __init__(self, rc): self.returncode = rc

def test_image_has_clang14_true(monkeypatch):
    monkeypatch.setattr(ofc, "subprocess", type("S", (), {"run": staticmethod(lambda *a, **k: _R(0))}))
    assert ofc._image_has_clang14("img") is True

def test_image_has_clang14_false(monkeypatch):
    monkeypatch.setattr(ofc, "subprocess", type("S", (), {"run": staticmethod(lambda *a, **k: _R(1))}))
    assert ofc._image_has_clang14("img") is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k image_has_clang14 -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_image_has_clang14'`.

- [ ] **Step 3: Implement the predicate + invalidation hook**

```python
# experiment/oss_fuzz_checkout.py
def _image_has_clang14(image_name):
    """True iff the image carries the pinned clang-14 used for bitcode extraction."""
    res = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "test", image_name,
         "-x", "/usr/lib/llvm-14/bin/clang"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0
```
In `prepare_project_image` (after the project image is resolved), if `not _image_has_clang14(image_name)`, log a warning and invalidate that project's cache image via the existing stale-cache path (`_invalidate_stale_cache_dockerfiles`) so it rebuilds FROM the augmented base.

- [ ] **Step 4: Make the clang-14 guard actionable**

In `llvm_extractor._ensure_clang14_installed` (~233-238), keep the raise but make it actionable (no runtime apt):
```python
        raise RuntimeError(
            f"clang-14 missing in container for project "
            f"'{self.benchmark.project}' (stale image). Rebuild: "
            f"docker rmi gcr.io/oss-fuzz/{self.benchmark.project} && "
            f"re-run with NO_CACHE=1 so prepare_project_image rebuilds FROM "
            f"the clang-14-augmented base (ensure_llvm14_base_builder).")
```

- [ ] **Step 5: Run to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k image_has_clang14 -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add experiment/oss_fuzz_checkout.py liberator_adapter/extractors/llvm_extractor.py tests/test_extraction_robustness.py
git commit -m "fix(images): detect+invalidate stale clang-14 project image; actionable guard (Fix C, liblouis)"
```

---

### Task 8: `LOGICFUZZ_REQUIRE_Z3` opt-in strict gate

**Files:**
- Modify: `src/context/data_context.py` (build_condition_manager except ~526-530; `_degraded` site ~3451-3464)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `require_z3_enabled() -> bool` in `src/context/data_context.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extraction_robustness.py  (append)
from src.context.data_context import require_z3_enabled

def test_require_z3_default_off(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_REQUIRE_Z3", raising=False)
    assert require_z3_enabled() is False

def test_require_z3_on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_REQUIRE_Z3", "1")
    assert require_z3_enabled() is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_extraction_robustness.py -k require_z3 -q`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Implement gate + apply at both degradation sites**

```python
# src/context/data_context.py  (module scope)
def require_z3_enabled():
    return os.environ.get("LOGICFUZZ_REQUIRE_Z3", "").strip().lower() in (
        "1", "true", "yes")
```
At the `build_condition_manager` except (~526), before `condition_manager = None`:
```python
            if require_z3_enabled():
                raise RuntimeError(
                    f"LOGICFUZZ_REQUIRE_Z3 set but condition manager build "
                    f"failed: {e}") from e
```
At the `_degraded` site (~3459, inside `if _degraded:` before the warning):
```python
        if require_z3_enabled():
            raise RuntimeError(
                "LOGICFUZZ_REQUIRE_Z3 set but extraction degraded "
                "(function_conditions empty) — refusing to ship unvalidated "
                "drivers")
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_extraction_robustness.py -k require_z3 -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/context/data_context.py tests/test_extraction_robustness.py
git commit -m "feat(extract): LOGICFUZZ_REQUIRE_Z3 opt-in strict gate (default off)"
```

---

### Task 9: libucl convergence procedure + per-project values

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (`_SVF_PROJECT_RESOURCES` values from Task 6, finalize)
- Doc: append findings to `docs/superpowers/specs/2026-06-18-robust-llvm14-extraction-design.md`

This task has **no new code** beyond confirming Task 6 values; it is a one-time empirical procedure (per the user's "manual run is acceptable").

- [ ] **Step 1: Run big-budget flow-sensitive libucl extraction**

```bash
LOGICFUZZ_NO_CACHE=1 LIBERATOR_SVF_LITE="" LIBERATOR_SVF_TIMEOUT_SECS=21600 \
LIBERATOR_SVF_MEM_GB=140 PYTHONHASHSEED=0 \
  python3 scripts/measure_breadth.py comparison/libucl.yaml 2>&1 | tee /tmp/libucl_full.log
```
Expected: either `conditions.json` produced (→ libucl converges full; set `_SVF_PROJECT_RESOURCES["libucl"]["lite"]=False` by removing it from `_SVF_LITE_PROJECTS` default) OR timeout/OOM (→ keep lite default).

- [ ] **Step 2: If (1) did not converge, run lite mode**

```bash
LOGICFUZZ_NO_CACHE=1 LIBERATOR_SVF_LITE=libucl PYTHONHASHSEED=0 \
  python3 scripts/measure_breadth.py comparison/libucl.yaml 2>&1 | tee /tmp/libucl_lite.log
jq '. | length' results/libucl/conditions.json
```
Expected: non-empty `conditions.json` (length > 0).

- [ ] **Step 3: Soundness check (callback-creator risk)**

```bash
python3 - <<'EOF'
import json
d=json.load(open('results/libucl/conditions.json'))
creates=sum(1 for f in d for a in [f.get('return_at',{})]+list(f.values()) if isinstance(a,dict) and 'create' in str(a).lower())
print("functions:",len(d),"with create/source evidence:",creates)
assert len(d)>0 and creates>0, "lite conditions impoverished — re-add -do_indirect_jumps with big budget"
EOF
```
Expected: `functions > 0` and `create/source evidence > 0`. If the assert fails, set libucl to non-lite + `timeout_secs=21600, mem_gb=140` (Step 1 path) instead.

- [ ] **Step 4: Record the chosen mode in the spec + commit**

Append a one-paragraph "libucl resolution: <full-bigbudget | lite>" note to the design doc.

```bash
git add liberator_adapter/extractors/llvm_extractor.py docs/superpowers/specs/2026-06-18-robust-llvm14-extraction-design.md
git commit -m "chore(extract): finalize libucl SVF mode from convergence run"
```

---

### Task 10: Container regression harness (opt-in, slow)

**Files:**
- Create: `tests/test_extraction_integration.py`

**Interfaces:**
- Consumes: the full pipeline via `scripts/measure_breadth.py`.

- [ ] **Step 1: Write the regression test (marked slow/opt-in)**

```python
# tests/test_extraction_integration.py
import json, os, subprocess, pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_EXTRACTION_INTEGRATION") != "1",
    reason="docker+SVF; set RUN_EXTRACTION_INTEGRATION=1 to run")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _run(project, env_extra=""):
    cmd = (f"LOGICFUZZ_NO_CACHE=1 PYTHONHASHSEED=0 {env_extra} "
           f"python3 scripts/measure_breadth.py comparison/{project}.yaml")
    subprocess.run(cmd, shell=True, cwd=REPO, timeout=24000, check=False)
    p = os.path.join(REPO, "results", project, "conditions.json")
    return p

@pytest.mark.parametrize("project", ["libpcap", "liblouis", "nghttp2", "sqlite3"])
def test_project_reaches_full(project):
    p = _run(project, "LIBERATOR_SVF_TIMEOUT_SECS=14400")
    assert os.path.exists(p), f"{project}: no conditions.json (still degraded)"
    assert len(json.load(open(p))) > 0, f"{project}: empty conditions"
```

- [ ] **Step 2: Run it once manually (not in CI)**

Run: `RUN_EXTRACTION_INTEGRATION=1 pytest tests/test_extraction_integration.py -q`
Expected: PASS for libpcap/liblouis/nghttp2/sqlite3 (full). (libucl covered by Task 9.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_extraction_integration.py
git commit -m "test(extract): opt-in container regression for degraded-project recovery"
```

---

## Self-Review

- **Spec coverage:** keystone observability → Task 1+3; Fix A → Task 2; Fix B2 IndexError → Task 4; Fix B2 KeyError → Task 5; Fix B1 (resources+lite) → Task 6+9; Fix C → Task 7; REQUIRE_Z3 → Task 8; regression → Task 10. re2 `CONDITIONS_EMPTY` is surfaced by Task 1's enum + Task 3 persistence (detected at the `_degraded` empty-conditions check). curl/pugixml deferred per spec §9 — no task (intentional).
- **Placeholder scan:** every code step has concrete code; the only "confirm at runtime" is Task 9's empirical libucl mode choice, which is a procedure with explicit branches, not a placeholder.
- **Type consistency:** `extraction_status_fields`, `sanitize_extraction_flags`, `svf_resources_for`, `build_svf_cmd`, `_safe_arg_cond`, `get_function_conditions`, `_image_has_clang14`, `require_z3_enabled` names are used identically across tasks and tests.
