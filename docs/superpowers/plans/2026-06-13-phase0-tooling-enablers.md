# Phase 0 — Tooling Enablers (L2/L3/L5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the three deterministic tooling fixes that currently zero whole projects for non-quality reasons, so cross-project coverage numbers become honest and Phase-1 A/Bs are attributable.

**Architecture:** Three independent levers. **L2** makes the merge compile-validation gate compile the *configured* source tree (so c-ares's configure-generated `ares_build.h` exists) and runs the preflight smoke *inside the OSS-Fuzz container* (so container-glibc binaries don't fail the host loader). **L3** fixes the caller-alloc INIT producer render (`z_stream*` → stack `{0}` + address, not NULL) and guards public-typedef handle typing. **L5** adds a deterministic pre-build symbol/arity check (auto-drop hallucinated/wrong-arity calls) and two new compile-error→fix-strategy mappings.

**Tech Stack:** Python 3.11, pytest, the project's `liberator_adapter` + `src/` packages, OSS-Fuzz docker images (mocked in tests).

**Spec:** `docs/superpowers/specs/2026-06-13-knowledge-driven-coverage-optimization-design.md` (§5 Phase 0).

**Spec deltas discovered during planning (apply to spec too):**
- L3(b): handles are *already* keyed by typedef name in our layer — reframed from "type holes by typedef name" to "regression-guard + `_public_pointer_type` guard". No typing rewrite.
- L5(b): `implicit-function-declaration→ADD_INCLUDE` already correct and triage is already non-None per category — reframed to "add `FIX_ARGUMENTS` + `FIX_ENTRYPOINT` + regression test".

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `tools/merge_drivers/compile_validate.py` | merge compile gate (`_VALIDATE_SH` bash) | Modify — compile configured tree |
| `tools/merge_drivers/preflight.py` | 15s smoke-run of each candidate | Modify — run in container |
| `run_single_fuzz.py` | preflight call-site / candidate identity | Modify — pass project/target |
| `liberator_adapter/driver/synthesis/skeleton_generator.py` | C render of skeleton args | Modify — INIT struct stack-alloc; `_public_pointer_type` guard |
| `liberator_adapter/analysis/header_facts.py` | per-(api,arg) literal facts (ZLIB_VERSION, sizeof) | **Create** |
| `src/utils/unified_validator.py` | pre-build code validation | Modify — `_check_called_symbols` |
| `src/agents/prototyper.py` | hole-fill validation + auto-drop | Modify — drop hallucinated calls |
| `src/utils/compilation_error_triage.py` | build-error → fix strategy | Modify — FIX_ARGUMENTS, FIX_ENTRYPOINT |
| `tests/test_p0_*` | new tests | **Create** (5 files) |

Each task below is self-contained TDD. Run all tests from repo root.

---

## L2 — Compile-validation + preflight run under the project toolchain

### Task 1: Compile-validation gate compiles the CONFIGURED tree (c-ares `ares_build.h`)

**Files:**
- Modify: `tools/merge_drivers/compile_validate.py` (`_VALIDATE_SH`, ~lines 152-196)
- Test: `tests/test_p0_compile_validate_configured.py` (create)

Today `_VALIDATE_SH` runs `$CC ... -fsyntax-only` against the raw `/src/$PROJ` tree and discovers includes from a fixed `for d in /src/$PROJ/include ...` list — it never runs `build.sh`/configure, so configure-generated headers (`ares_build.h`) are absent and every c-ares driver is excluded. Fix: run the project's `compile` once (best-effort, fail-open) to populate generated headers, then add a `find`-based include sweep for `*_build.h`/`*_config.h`. The Python (`validate_compilable`/`_run_container_validation`) is unchanged, so existing parser/fail-open tests keep passing; we assert on the `_VALIDATE_SH` script content (mirrors the existing `test_c_compile_promotes_implicit_decl_to_error` style).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p0_compile_validate_configured.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.merge_drivers import compile_validate as cv


def test_validate_sh_runs_configure_and_sweeps_generated_headers():
    sh = cv._VALIDATE_SH
    # Best-effort configure/build so generated headers (ares_build.h) exist.
    assert "compile" in sh, "must invoke the project compile/build.sh once"
    # Include sweep for configure-generated headers.
    assert "_build.h" in sh or "_config.h" in sh, \
        "must -I the dirs holding configure-generated headers"
    # Fail-open preserved: the configure step must not hard-fail the gate.
    assert "|| true" in sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_compile_validate_configured.py -v`
Expected: FAIL (`assert "_build.h" in sh` — substring absent).

- [ ] **Step 3: Implement the minimal change in `_VALIDATE_SH`**

Insert, just before the per-TU compile loop (after the `EXT_INC` discovery `for d in ...` block, ~line 156), a best-effort configure + generated-header sweep:

```bash
# Populate configure/cmake-generated headers (e.g. c-ares ares_build.h) so the
# syntax check sees the SAME tree the real merged coverage build compiles (A≡B).
# Best-effort + fail-open: a failing/absent build must never drop candidates.
( compile >/dev/null 2>&1 || bash /src/build.sh >/dev/null 2>&1 || true )
for g in $(find /src/$PROJ /work -name '*_build.h' -o -name '*_config.h' 2>/dev/null); do
  EXT_INC="$EXT_INC -I$(dirname "$g")"
done
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_compile_validate_configured.py -v`
Expected: PASS. Then `pytest tests/test_p1_merge_compile_validate.py -v` — Expected: still PASS (Python untouched).

- [ ] **Step 5: Commit**

```bash
git add tools/merge_drivers/compile_validate.py tests/test_p0_compile_validate_configured.py
git commit -m "fix(merge-gate): compile the CONFIGURED tree so c-ares ares_build.h exists (L2a)"
```

---

### Task 2: Preflight smoke runs inside the OSS-Fuzz container (zlib `GLIBC_2.38`)

**Files:**
- Modify: `tools/merge_drivers/preflight.py` (`_smoke_one`, ~lines 82-149)
- Test: `tests/test_p0_preflight_in_container.py` (create)

The container-built binary (linked vs glibc 2.38) is run as a plain HOST subprocess (`cmd = [str(fuzzer_binary), str(corpus_dir), ...]`), so a host with glibc 2.35 fails the loader → `GLIBC_2.38 not found`. Minimal fix (smallest blast radius): run the binary under the base-runner image via `docker run`, mounting the binary dir + corpus, instead of executing it on the host. Seeds are preserved (corpus mounted). Fail-open behavior (docker missing → fall back to host run) is kept.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p0_preflight_in_container.py
import sys, pathlib, types
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.merge_drivers import preflight as pf


def test_smoke_cmd_runs_in_container(monkeypatch, tmp_path):
    captured = {}
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class P:  # libFuzzer-style log with a cov line
            returncode = 0
        (tmp_path / "log").write_bytes(b"cov: 12 ft: 30 exec/s: 100\n")
        return P()
    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda x: "/usr/bin/docker")
    binary = tmp_path / "out" / "03"
    binary.parent.mkdir(parents=True); binary.write_bytes(b"\x7fELF")
    pf._smoke_one(binary, tmp_path / "corpus", 15, tmp_path / "log",
                  project="zlib")
    cmd = captured["cmd"]
    assert cmd[0] == "docker" and "run" in cmd[:3]
    assert any("base-runner" in str(a) for a in cmd), "must use base-runner image"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_preflight_in_container.py -v`
Expected: FAIL (`_smoke_one` has no `project` kwarg / builds a host cmd, `cmd[0] != "docker"`).

- [ ] **Step 3: Implement the in-container run**

In `_smoke_one`, add a `project: str = ""` parameter and build a docker command when docker is available, else fall back to the existing host `cmd`:

```python
# inside _smoke_one, replacing the `cmd = [str(fuzzer_binary), ...]` construction
import shutil
host_cmd = [str(fuzzer_binary), str(corpus_dir),
            f"-max_total_time={duration_sec}", "-print_final_stats=1",
            "-detect_leaks=0"]
if shutil.which("docker") and project:
    # Run under the base-runner toolchain so the container-glibc binary loads.
    cmd = ["docker", "run", "--rm",
           "-v", f"{fuzzer_binary.parent.resolve()}:/o:ro",
           "-v", f"{pathlib.Path(corpus_dir).resolve()}:/c:ro",
           "--entrypoint", f"/o/{fuzzer_binary.name}",
           "gcr.io/oss-fuzz-base/base-runner",
           "/c", f"-max_total_time={duration_sec}",
           "-print_final_stats=1", "-detect_leaks=0"]
else:
    cmd = host_cmd  # fail-open: no docker → host run (legacy behavior)
```

Thread `project` from the caller: in `preflight()` accept/forward `project`, and at the `run_single_fuzz.py` call site (`_preflight_filter_candidates`) pass `benchmark.get('project')`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_preflight_in_container.py tests/test_p1_merge_preflight.py -v`
Expected: PASS (new test passes; existing preflight tests still pass via the host fallback when docker isn't mocked).

- [ ] **Step 5: Commit**

```bash
git add tools/merge_drivers/preflight.py run_single_fuzz.py tests/test_p0_preflight_in_container.py
git commit -m "fix(preflight): run smoke inside base-runner container so glibc-2.38 binaries load (L2b)"
```

---

## L3 — Caller-alloc INIT render + public-typedef handle typing

### Task 3: INIT producer struct renders as stack `{0}` + address (not NULL)

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` (`_create_variable_for_param` OUTPUT branch ~lines 1199-1238; `_complete_value_struct`/new helper ~line 156)
- Test: `tests/test_p0_init_struct_render.py` (create)

The INIT arg (`deflateInit_(z_stream*)`) is correctly assigned role `OUTPUT` (`api_semantic_model._ir_arg_roles:403-411`), but the renderer's OUTPUT branch routes a single-pointer-to-aggregate to `value_array=False` → `Type *name = NULL` (lines 1232-1238). `_complete_value_struct` would stack-alloc it but is gated on `DataLayout.is_a_struct("z_stream")`, which is `False`. Fix: a relaxed `_is_caller_alloc_struct` that treats "DataLayout can size it" as completeness, applied in the OUTPUT fallthrough before the NULL degrade — emitting the same `STACK {0}` + `&name` shape used at lines 1048-1052.

- [ ] **Step 1: Write the failing test** (mirrors `tests/test_p1_role_precision.py` + `tests/test_p2_value_struct_render.py`)

```python
# tests/test_p0_init_struct_render.py
import re, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, SkeletonRenderer)
from liberator_adapter.common.datalayout import DataLayout

_DEFLATE_INIT = {
    "function_name": "deflateInit_",
    "return_type": "int",
    "arguments": [
        {"type": "z_stream *", "name": "strm", "is_const": [False], "_svf_writes": True},
        {"type": "int", "name": "level", "is_const": [False]},
        {"type": "const char *", "name": "version", "is_const": [True]},
        {"type": "int", "name": "stream_size", "is_const": [False]},
    ],
}

def test_init_struct_renders_stack_alloc_not_null():
    DataLayout._instance = None
    dl = DataLayout.instance()
    dl.clang_to_llvm_struct["z_stream"] = "%struct.z_stream"
    dl.type_sizes = getattr(dl, "type_sizes", {}); dl.type_sizes["z_stream"] = 112
    model = reconcile({_DEFLATE_INIT["function_name"]: _DEFLATE_INIT})
    sk = SkeletonGenerator().generate(
        api_sequence=["deflateInit_"], driver_name="t", is_cpp=False,
        dep_model=model)
    code = SkeletonRenderer().render(sk)
    assert re.search(r"z_stream\s+\w+\s*=\s*\{0\}", code), code
    assert "deflateInit_(&" in code.replace(" ", "")
    assert not re.search(r"z_stream\s*\*\s*\w+\s*=\s*NULL", code), code
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_init_struct_render.py -v`
Expected: FAIL (renders `z_stream *strm = NULL;` → first assertion fails).

- [ ] **Step 3: Implement the relaxed INIT-struct render**

Add the helper near `_complete_value_struct` (~line 186):

```python
def _is_caller_alloc_struct(element_type: str) -> Optional[str]:
    """A single-level pointer to an aggregate the IR can SIZE is a caller-alloc
    init struct (e.g. z_stream*). Looser than _complete_value_struct's
    is_a_struct() gate, which misses opaque-by-convention structs."""
    bare = _bare_name(element_type)
    if not bare or bare == 'void' or _is_scalar_value_type(element_type):
        return None
    try:
        from liberator_adapter.common.datalayout import DataLayout
        dl = DataLayout.instance()
        if dl.get_type_size(bare):   # sizeable ⇒ complete enough to stack-alloc
            return bare
    except Exception:
        return None
    return None
```

In `_create_variable_for_param`, in the OUTPUT branch `else:` fallthrough (the `value_array = False` arm, ~line 1215), before the NULL degrade at ~1232:

```python
            else:
                _ca = _is_caller_alloc_struct(element)
                if _ca is not None:
                    return SkeletonVariable(
                        name=name, c_type=_ca, is_pointer=False,
                        allocation=AllocationType.STACK, init_value="{0}",
                        bound_expr=f"&{name}")
                value_array = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_init_struct_render.py tests/test_p2_value_struct_render.py -v`
Expected: PASS (new test passes; the color-math value-struct test still passes — we only ADD a fallthrough branch).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p0_init_struct_render.py
git commit -m "fix(render): caller-alloc INIT struct → stack {0} + address, not NULL (L3a)"
```

---

### Task 4: Header-fact literal fills for INIT scalar args (ZLIB_VERSION, sizeof)

**Files:**
- Create: `liberator_adapter/analysis/header_facts.py`
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` (scalar CONFIG fill, ~lines 1097-1110)
- Test: `tests/test_p0_header_facts.py` (create)

`deflateInit_`'s `version`/`stream_size` args must be `ZLIB_VERSION` and `sizeof(z_stream)` or Init returns `Z_VERSION_ERROR`. Mirror the existing process-global `constant_usage.legal_constants_for` pattern with a per-`(api,arg_idx)` literal map.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p0_header_facts.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from liberator_adapter.analysis import header_facts


def test_literal_for_set_and_read():
    header_facts.set_fact_map({"deflateInit_": {2: "ZLIB_VERSION",
                                                3: "(int)sizeof(z_stream)"}})
    assert header_facts.literal_for("deflateInit_", 2) == "ZLIB_VERSION"
    assert header_facts.literal_for("deflateInit_", 3) == "(int)sizeof(z_stream)"
    assert header_facts.literal_for("deflateInit_", 0) is None
    assert header_facts.literal_for("unknown", 0) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_header_facts.py -v`
Expected: FAIL (`ModuleNotFoundError: header_facts`).

- [ ] **Step 3: Implement the module (mirror `constant_usage.py:183-194`)**

```python
# liberator_adapter/analysis/header_facts.py
"""Deterministic per-(api, arg_idx) literal facts mined from headers
(e.g. ZLIB_VERSION, (int)sizeof(z_stream)). Process-global, set once, read in
the skeleton renderer — mirrors constant_usage.legal_constants_for."""
from __future__ import annotations
from typing import Dict, Optional

_FACT_MAP: Dict[str, Dict[int, str]] = {}


def set_fact_map(m: Optional[Dict[str, Dict[int, str]]]) -> None:
    global _FACT_MAP
    _FACT_MAP = m or {}


def literal_for(api_name: str, arg_idx: int) -> Optional[str]:
    try:
        return _FACT_MAP.get(api_name, {}).get(arg_idx)
    except Exception:
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_header_facts.py -v`
Expected: PASS.

- [ ] **Step 5: Wire consumption into the renderer + commit**

In `_create_variable_for_param`, in the scalar CONFIG branch (where `legal_constants_for(api_name, idx)` is consulted, ~line 1097), prefer a header fact when present:

```python
            _fact = header_facts.literal_for(api_name, idx)
            if _fact is not None:
                init_value = _fact
            else:
                _consts = legal_constants_for(api_name, idx)
                # ... existing legal-constant path unchanged ...
```

Add `from liberator_adapter.analysis import header_facts` at the top of `skeleton_generator.py`. (Populating `set_fact_map` from a real header scan in `data_context.py` is a Phase-1 wiring step — out of scope here; the unit test covers the mechanism.)

```bash
git add liberator_adapter/analysis/header_facts.py liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p0_header_facts.py
git commit -m "feat(render): header-fact literal fills for INIT scalar args (L3a)"
```

---

### Task 5: Public-typedef handle-distinctness regression guard

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` (`_public_pointer_type`, ~lines 149-154)
- Test: `tests/test_p0_typedef_distinct.py` (create)

Ground-truth: `normalize_handle_type` and Z3 `add_type_match_constraint` already keep `cmsContext` ≠ `cmsHPROFILE`. This task pins that as a regression guard and hardens `_public_pointer_type` so it never flattens a *public* typedef (only internal/underscore ones) — preventing a future collapse to `void*`.

- [ ] **Step 1: Write the failing/guard test**

```python
# tests/test_p0_typedef_distinct.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from liberator_adapter.analysis.usedef import normalize_handle_type
from liberator_adapter.driver.synthesis import skeleton_generator as sg


def test_public_typedef_handles_are_distinct():
    assert normalize_handle_type("cmsContext") != normalize_handle_type("cmsHPROFILE")

def test_public_typedef_not_flattened_to_void():
    # internal/underscore opaque → void*; public typedef → preserved
    assert sg._public_pointer_type("_cmsContext_struct *") == "void *"
    assert sg._public_pointer_type("cmsHPROFILE") == "cmsHPROFILE"
```

- [ ] **Step 2: Run test to verify it fails (or passes for #1)**

Run: `pytest tests/test_p0_typedef_distinct.py -v`
Expected: `test_public_typedef_handles_are_distinct` PASS (already true — regression guard); `test_public_typedef_not_flattened_to_void` PASS if `_public_pointer_type` already only flattens internal types. If the second FAILS, proceed to Step 3.

- [ ] **Step 3: Harden `_public_pointer_type` (only if Step 2 #2 failed)**

Confirm the guard — `_public_pointer_type` must return the input unchanged unless `_is_internal_opaque_type(c_type)` is true. If it currently flattens more broadly, restrict it to `if c_type.count('*') == 1 and _is_internal_opaque_type(c_type): return "void *"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_typedef_distinct.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p0_typedef_distinct.py
git commit -m "test(handles): guard public-typedef distinctness; never flatten to void* (L3b)"
```

---

## L5 — Pre-build symbol/arity check + triage strategies

### Task 6: `UnifiedCodeValidator._check_called_symbols` (symbol existence + arity)

**Files:**
- Modify: `src/utils/unified_validator.py` (add `ValidationCategory` members + `_check_called_symbols`, call from `validate()` ~line 379)
- Test: `tests/test_p0_hole_symbol_arity.py` (create)

apis_clang.json is JSONL; arity = `len(api["arguments_info"])`. No `is_vararg` in raw JSON, so flag only `actual < expected` (too-few) to stay false-positive-safe. Only judge library-prefixed calls (reuse the existing prefix gate).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p0_hole_symbol_arity.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.utils.unified_validator import UnifiedCodeValidator, ValidationCategory

KNOWN = [
    {"function_name": "cmsCreateTransform",
     "arguments_info": [{"type_clang": "cmsHPROFILE"}, {"type_clang": "cmsUInt32Number"}]},
    {"function_name": "cmsCloseProfile", "arguments_info": [{"type_clang": "cmsHPROFILE"}]},
]
CODE_UNDECLARED = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){cmsWhitePointFromTempDouble(0);return 0;}"
CODE_TOO_FEW = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){cmsCreateTransform(0);return 0;}"


def test_reject_undeclared_lib_call():
    r = UnifiedCodeValidator().validate(code=CODE_UNDECLARED, known_apis=KNOWN, is_c_target=True)
    cats = [i.category for i in r.issues]
    assert ValidationCategory.UNDECLARED_CALL in cats
    assert any("cmsWhitePointFromTempDouble" in i.message for i in r.issues)

def test_wrong_arity_too_few_flagged():
    r = UnifiedCodeValidator().validate(code=CODE_TOO_FEW, known_apis=KNOWN, is_c_target=True)
    assert ValidationCategory.WRONG_ARITY in [i.category for i in r.issues]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_hole_symbol_arity.py -v`
Expected: FAIL (`ValidationCategory.UNDECLARED_CALL` AttributeError / no such check).

- [ ] **Step 3: Implement the check**

Add to the `ValidationCategory` enum: `UNDECLARED_CALL = "undeclared_call"` and `WRONG_ARITY = "wrong_arity"`. Add the method and call it from `validate()` after the existing checks (gated on `known_apis`):

```python
    def _check_called_symbols(self, code, known_apis):
        import re
        issues = []
        arity = {a["function_name"]: len(a.get("arguments_info", []))
                 for a in known_apis if a.get("function_name")}
        known = set(arity)
        prefix = self._detect_lib_prefix(known)  # existing helper; '' ⇒ skip
        code_nc = self._strip_comments(code)     # existing helper
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", code_nc):
            name = m.group(1)
            if prefix and not name.startswith(prefix):
                continue
            if name not in known and name != "LLVMFuzzerTestOneInput":
                if self._looks_like_lib_call(name, known):  # prefix-gated
                    issues.append(ValidationIssue(
                        category=ValidationCategory.UNDECLARED_CALL,
                        severity=Severity.ERROR,
                        message=f"undeclared library call: {name}",
                        pattern=name, recoverable=False,
                        suggestion=self._suggest_similar_api(name, known)))
                continue
            actual = self._count_call_args(code_nc, m.end())  # balanced-paren split
            if actual is not None and actual < arity[name]:
                issues.append(ValidationIssue(
                    category=ValidationCategory.WRONG_ARITY,
                    severity=Severity.ERROR,
                    message=f"{name} called with {actual} args, expects >= {arity[name]}",
                    pattern=name, recoverable=False))
        return issues
```

Implement `_count_call_args(code, open_paren_idx)` as a small balanced-paren splitter returning the top-level comma count + 1 (0 for empty parens). Reuse `_detect_lib_prefix`/`_strip_comments`/`_suggest_similar_api` if present; else add minimal versions. Wire into `validate()` after line 379: `if known_apis: issues.extend(self._check_called_symbols(code, known_apis))`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_hole_symbol_arity.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/utils/unified_validator.py tests/test_p0_hole_symbol_arity.py
git commit -m "feat(validate): pre-build symbol-existence + arity check (L5a)"
```

---

### Task 7: Auto-drop hallucinated/undeclared calls before build

**Files:**
- Modify: `src/agents/prototyper.py` (`_validate_api_usage` ~line 1800, add `_drop_hallucinated_calls`)
- Test: `tests/test_p0_drop_hallucinated.py` (create)

When `_check_called_symbols` (or the existing `_scan_hole_hallucinations`) flags an undeclared library call, remove the *statement* containing it rather than inventing a substitute (per spec risk-mitigation).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p0_drop_hallucinated.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.agents.prototyper import _drop_hallucinated_calls  # module-level helper

def test_drops_offending_statement_no_substitute():
    code = "a();\n  cmsBogusApi(x, y);\n  b();\n"
    out = _drop_hallucinated_calls(code, {"cmsBogusApi"})
    assert "cmsBogusApi" not in out
    assert "a();" in out and "b();" in out
    # no invented replacement
    assert "cmsBogus" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_drop_hallucinated.py -v`
Expected: FAIL (`ImportError: cannot import name '_drop_hallucinated_calls'`).

- [ ] **Step 3: Implement the helper + wire it**

```python
# module-level in prototyper.py
def _drop_hallucinated_calls(code: str, names: set) -> str:
    """Remove whole statements that call an undeclared/hallucinated symbol.
    Never invents a substitute — a dropped call is safer than a fake one."""
    if not names:
        return code
    out_lines = []
    for line in code.splitlines():
        if any(re.search(rf"\b{re.escape(n)}\s*\(", line) for n in names):
            continue  # drop the statement
        out_lines.append(line)
    return "\n".join(out_lines)
```

In `_validate_api_usage`, after collecting hallucinated/undeclared names from the validator result, call `fuzz_target_code = _drop_hallucinated_calls(fuzz_target_code, fake_names)` before returning, and re-write the state's `fuzz_target_source`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_drop_hallucinated.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agents/prototyper.py tests/test_p0_drop_hallucinated.py
git commit -m "feat(prototyper): auto-drop undeclared calls pre-build, no substitute (L5a)"
```

---

### Task 8: Triage adds `FIX_ARGUMENTS` + `FIX_ENTRYPOINT`; regression-pin implicit-decl

**Files:**
- Modify: `src/utils/compilation_error_triage.py` (`FixStrategy` enum ~line 52; `_categorize_error` ~lines 315-452; `_get_recommended_strategy` ~line 549)
- Modify: `src/agents/fixer.py` (`_get_strategy_hints` ~line 333) — add hints for the two new strategies
- Test: `tests/test_p0_triage_strategies.py` (create)

- [ ] **Step 1: Write the failing test** (mirrors `tests/test_p0_triage_inconclusive.py`)

```python
# tests/test_p0_triage_strategies.py
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.utils.compilation_error_triage import (
    triage_build_errors, ErrorCategory, FixStrategy)

KNOWN = [{"function_name": "cmsFoo"}]

def test_implicit_decl_maps_to_add_include():  # regression pin (already correct)
    r = triage_build_errors(["a.c:5: warning: implicit declaration of function 'cmsFoo'"], KNOWN)
    assert r.primary_category == ErrorCategory.DECLARATION_MISSING
    assert r.recommended_strategy == FixStrategy.ADD_INCLUDE

def test_too_few_args_maps_to_fix_arguments():
    r = triage_build_errors(["a.c:5: error: too few arguments to function 'cmsFoo'"], KNOWN)
    assert r.recommended_strategy == FixStrategy.FIX_ARGUMENTS

def test_undefined_main_maps_to_fix_entrypoint():
    r = triage_build_errors(["a.c:(.text+0x0): undefined reference to `main'"], KNOWN)
    assert r.recommended_strategy == FixStrategy.FIX_ENTRYPOINT
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p0_triage_strategies.py -v`
Expected: FAIL (`FixStrategy.FIX_ARGUMENTS` AttributeError; undefined-main maps to INCLUDE_CPP_FILE).

- [ ] **Step 3: Implement**

Add to `FixStrategy`: `FIX_ARGUMENTS = "fix_arguments"`, `FIX_ENTRYPOINT = "fix_entrypoint"`. In `_categorize_error`:
- For the `too (few|many) arguments` match, set `fix_strategy=FixStrategy.FIX_ARGUMENTS` (keep `category=TYPE_ERROR`).
- In the LINK step, BEFORE `_is_system_symbol`, special-case the `main` symbol:

```python
        if symbol == "main":
            return TriagedError(
                category=ErrorCategory.LANGUAGE_MISMATCH,
                fix_strategy=FixStrategy.FIX_ENTRYPOINT,
                extracted_symbol="main", recoverable=True,
                details="stray int main / missing LLVMFuzzerTestOneInput")
```

In `_get_recommended_strategy`, the per-`TriagedError` strategy must win for these (the function already prefers an explicit `fix_strategy` if you return per-error strategies; if it only maps by category, add `if any(e.fix_strategy == FixStrategy.FIX_ARGUMENTS for e in errors): return FixStrategy.FIX_ARGUMENTS` and likewise for FIX_ENTRYPOINT before the category map). Add fixer hints in `_get_strategy_hints` for both.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p0_triage_strategies.py tests/test_p0_triage_inconclusive.py -v`
Expected: PASS (new + existing triage tests).

- [ ] **Step 5: Commit**

```bash
git add src/utils/compilation_error_triage.py src/agents/fixer.py tests/test_p0_triage_strategies.py
git commit -m "feat(triage): FIX_ARGUMENTS + FIX_ENTRYPOINT strategies (L5b)"
```

---

## Task 9: Full Phase-0 regression + integration verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full regression suite**

Run: `pytest tests/ -q`
Expected: all pass (375+ baseline + the new `test_p0_*` files). Fix any regression before proceeding.

- [ ] **Step 2: Lint the touched files**

Run: `pylint src/utils/unified_validator.py src/utils/compilation_error_triage.py liberator_adapter/driver/synthesis/skeleton_generator.py && pyright src/ liberator_adapter/ 2>&1 | tail -5`
Expected: no new errors.

- [ ] **Step 3: Integration re-measure (manual, records the Phase-0 payoff)**

Run (one at a time; these are slow, real OSS-Fuzz runs):
```bash
LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/c-ares.yaml -l gpt-4o --merge-drivers
LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/zlib.yaml   -l gpt-4o --merge-drivers
```
Expected/record:
- c-ares: `results/output-c-ares-project/merged/compile_validation.json` now shows `valid >= ~19` (was 0) — `ares_build.h` resolves.
- zlib: preflight no longer reports `binary_broken (GLIBC_2.38)`; ≥2 drivers survive → merge runs; deflate/inflate drivers show a real `z_stream` (no NULL) and `ZLIB_VERSION`.
- Record the merged-harness branch numbers as the honest post-Phase-0 baseline (gates Phase 1).

- [ ] **Step 4: Commit the verification notes**

```bash
git add docs/superpowers/plans/2026-06-13-phase0-tooling-enablers.md
git commit -m "docs(plan): record Phase-0 re-measurement baseline"
```

---

## Self-review (run before execution)

- **Spec coverage:** L2a (Task 1), L2b (Task 2), L3a render (Task 3), L3a header-facts (Task 4), L3b guard (Task 5), L5a symbol/arity (Task 6), L5a auto-drop (Task 7), L5b triage (Task 8), re-measure gate (Task 9). All §5-Phase-0 items covered.
- **Type consistency:** `ValidationCategory.{UNDECLARED_CALL,WRONG_ARITY}` (Task 6) used consistently; `FixStrategy.{FIX_ARGUMENTS,FIX_ENTRYPOINT}` (Task 8) used consistently; `header_facts.{set_fact_map,literal_for}` (Task 4) match call sites; `_is_caller_alloc_struct`/`_drop_hallucinated_calls` defined where used.
- **No placeholders:** every code step shows real code; integration step (9) names exact files/fields to inspect.
