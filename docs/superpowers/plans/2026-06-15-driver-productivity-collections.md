# Driver Productivity — Populate Handle-Collection Constructor Args Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a CREATOR's handle-collection arg (e.g. `cmsToneCurve* const Curves[]`) as a populated array of built producer handles instead of the degenerate `{0}`/NULL, so the deep constructor actually runs (measured +72% edges/driver vs PromeFuzz's pattern).

**Architecture:** A gated lever (`LOGICFUZZ_POPULATE_COLLECTIONS`, default-OFF, gate-off byte-identical). Render layer only for the MVP: detect a handle-collection arg, declare it as a fixed-size array, and emit element-assignment statements (`arr[i] = ret_<producer>;`) immediately before the consuming call — mirroring the existing `bound_expr` call-time wiring. Construction-side producer multiplication is a follow-up task, gated behind the same flag; the MVP reuses whatever producer rets already exist in the skeleton (reuse one K× when only one is present — a valid non-NULL array still runs the constructor).

**Tech Stack:** Python; `liberator_adapter/driver/synthesis/skeleton_generator.py`; pytest; the golden characterization net.

---

### Task 1: Gate helper

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` (near `_recover_init_handles`, ~line 144)
- Test: `tests/test_p4_collection_population.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p4_collection_population.py
import os, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from liberator_adapter.analysis import sequence_constructor as sc

def test_gate_default_off(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_POPULATE_COLLECTIONS", raising=False)
    assert sc._populate_collections() is False

def test_gate_on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "1")
    assert sc._populate_collections() is True
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/test_p4_collection_population.py -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_populate_collections'`

- [ ] **Step 3: Implement the gate**

```python
def _populate_collections() -> bool:
    """Gate (default-off): ``LOGICFUZZ_POPULATE_COLLECTIONS`` — render a CREATOR's
    handle-collection arg (``T* const []``) as a populated array of built producer
    handles instead of degenerate ``{0}``/NULL, so the deep constructor runs
    (measured +72% edges/driver vs PromeFuzz's build-and-chain pattern)."""
    return _os.environ.get("LOGICFUZZ_POPULATE_COLLECTIONS", "0").strip().lower() in (
        "1", "true", "yes", "on")
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_p4_collection_population.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add tests/test_p4_collection_population.py liberator_adapter/analysis/sequence_constructor.py
git commit -m "feat(productivity): LOGICFUZZ_POPULATE_COLLECTIONS gate"
```

---

### Task 2: Detect a handle-collection arg

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` (add a module-level helper near `_public_pointer_type`)
- Test: `tests/test_p4_collection_population.py`

A handle-collection arg is an array-of-handle-pointers passed to a CREATOR: 2 pointer
levels with a `const` inner element whose base is a handle type (`cmsToneCurve* const
Curves[]` → C type `cmsToneCurve * const *` or `cmsToneCurve **`). Distinguish from an
out-pointer (`cmsHPROFILE *Output`, 1 level / non-const) which is OUTPUT, not input.

- [ ] **Step 1: Write the failing test**

```python
from liberator_adapter.driver.synthesis.skeleton_generator import _is_handle_collection_type

def test_handle_collection_detect():
    assert _is_handle_collection_type("cmsToneCurve * const *") is True
    assert _is_handle_collection_type("cmsToneCurve **") is True
    assert _is_handle_collection_type("cmsHPROFILE *") is False     # single ptr = out/handle
    assert _is_handle_collection_type("unsigned int") is False
    assert _is_handle_collection_type("char **") is False           # not a handle base
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_p4_collection_population.py::test_handle_collection_detect -q`
Expected: FAIL — `ImportError: cannot import name '_is_handle_collection_type'`

- [ ] **Step 3: Implement the detector**

```python
def _is_handle_collection_type(c_type: str) -> bool:
    """True for an array/double-pointer of a HANDLE type (``cmsToneCurve **``),
    the input-collection arg a CREATOR reads. Excludes single-pointer (out/handle)
    and non-handle bases (``char **``). Uses the shared handle predicate."""
    from liberator_adapter.analysis.usedef import is_handle_type
    t = (c_type or "").replace("const", "").strip()
    if t.count("*") < 2:
        return False
    base = t.replace("*", "").strip()
    return is_handle_type(base)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_p4_collection_population.py::test_handle_collection_detect -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p4_collection_population.py
git commit -m "feat(productivity): _is_handle_collection_type detector"
```

---

### Task 3: Render the populated array (the core change)

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py`:
  - `SkeletonVariable` dataclass (~line 363): add `prepopulate: Optional[List[str]] = None`
  - `_generate_single_api_call` (~line 1468): before building args, for an array var with
    `prepopulate`, emit `arr[i] = expr;` statements; pass the array name as the arg.
  - `get_declaration` (~line 380): an array with no init already renders `T name[N]` — keep.
- Test: `tests/test_p4_collection_population.py`

The population must happen at CALL TIME (producer rets are NULL at declaration — the same
reason `bound_expr` exists). Emit assignments immediately before the call statement.

- [ ] **Step 1: Write the failing test**

```python
from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, DriverSkeleton, SkeletonVariable, AllocationType)

def _make_skeleton_with_collection():
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(
        name="curves_cmsCreateLinearizationDeviceLink",
        c_type="cmsToneCurve *", is_array=True, array_size="3",
        prepopulate=["ret_cmsBuildGamma", "ret_cmsBuildGamma", "ret_cmsBuildGamma"]))
    return sk

def test_collection_emits_population_assignments():
    gen = SkeletonGenerator()
    sk = _make_skeleton_with_collection()
    gen._emit_collection_population(sk, "curves_cmsCreateLinearizationDeviceLink")
    codes = [s.code for s in sk.statements]
    assert "curves_cmsCreateLinearizationDeviceLink[0] = ret_cmsBuildGamma;" in codes
    assert "curves_cmsCreateLinearizationDeviceLink[2] = ret_cmsBuildGamma;" in codes
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_p4_collection_population.py::test_collection_emits_population_assignments -q`
Expected: FAIL — `AttributeError: 'SkeletonVariable' object has no attribute 'prepopulate'` (then, after adding the field, `no attribute '_emit_collection_population'`)

- [ ] **Step 3: Implement**

Add to `SkeletonVariable` (after `bound_expr`):
```python
    # When set on an is_array var, the renderer emits ``name[i] = expr;`` for each
    # expr right before the consuming call (call-time population — decl-time rets are
    # NULL, same reason bound_expr exists). LOGICFUZZ_POPULATE_COLLECTIONS only.
    prepopulate: Optional[List[str]] = None
```

Add the emitter method to `SkeletonGenerator`:
```python
    def _emit_collection_population(self, skeleton, var_name: str) -> None:
        """Emit ``var[i] = producer_ret;`` assignments for a prepopulated handle
        array, immediately before the consuming call."""
        var = skeleton.variables.get(var_name)
        if var is None or not var.prepopulate:
            return
        for i, expr in enumerate(var.prepopulate):
            skeleton.add_statement(SkeletonStatement(
                kind=StatementKind.ASSIGNMENT,
                code=f"{var_name}[{i}] = {expr};",
                variables=[var_name], indent=1))
```

(If `StatementKind.ASSIGNMENT` does not exist, use `StatementKind.API_CALL`'s sibling
or add `ASSIGNMENT = auto()` to the `StatementKind` enum — check the enum at the top of
the file first; reuse an existing generic kind if one fits.)

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_p4_collection_population.py::test_collection_emits_population_assignments -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p4_collection_population.py
git commit -m "feat(productivity): emit handle-collection population assignments"
```

---

### Task 4: Wire detection→prepopulate into variable creation (gated)

**Files:**
- Modify: `liberator_adapter/driver/synthesis/skeleton_generator.py` `_create_variable_for_param`
  (the branch that currently renders a non-scalar/array arg as `{0}`/NULL) and
  `_generate_single_api_call` (call `_emit_collection_population` before the call).
- Test: `tests/test_p4_collection_population.py`

- [ ] **Step 1: Write the failing test** — gate-on, a CREATOR collection arg becomes an
array var with `prepopulate` drawn from same-type `ret_*` producers in the skeleton;
gate-off it stays the legacy `{0}`/NULL.

```python
def _arg_info_collection():
    return {"name": "Curves", "type": "cmsToneCurve * const *", "idx": 1,
            "api_name": "cmsCreateLinearizationDeviceLink", "is_input": True,
            "is_output": False, "is_callback": False, "varlen_target": None,
            "role": "CONFIG", "pairs_with": None, "deep_fuzz_buffer": False}

def test_creator_collection_populated_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "1")
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(name="ret_cmsBuildGamma",
        c_type="cmsToneCurve *", is_pointer=True, source_api="cmsBuildGamma"))
    var = gen._create_variable_for_param(
        "Curves_cmsCreateLinearizationDeviceLink", _arg_info_collection(), sk)
    assert var.is_array is True
    assert var.prepopulate and all(e == "ret_cmsBuildGamma" for e in var.prepopulate)

def test_creator_collection_legacy_when_off(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_POPULATE_COLLECTIONS", raising=False)
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param(
        "Curves_cmsCreateLinearizationDeviceLink", _arg_info_collection(), sk)
    assert not getattr(var, "prepopulate", None)   # unchanged legacy render
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_p4_collection_population.py -k creator_collection -q`
Expected: FAIL (gate-on test: `var.is_array` is False / `prepopulate` is None)

- [ ] **Step 3: Implement** — in `_create_variable_for_param`, BEFORE the legacy
`{0}`/NULL branch, add (K=3 default, reuse-one fallback):

```python
        from liberator_adapter.analysis.sequence_constructor import _populate_collections
        if (_populate_collections()
                and _is_handle_collection_type(arg_info.get("type", ""))):
            base = arg_info["type"].replace("const", "").replace("*", "").strip()
            prods = [v.name for v in skeleton.variables.values()
                     if v.source_api and v.c_type.replace("*", "").strip() == base]
            if prods:
                K = 3
                fill = (prods * K)[:K]   # reuse one K× if only one producer exists
                return SkeletonVariable(
                    name=name, c_type=f"{base} *", is_array=True, array_size=str(K),
                    prepopulate=fill)
```

In `_generate_single_api_call`, right before `args = []`, add:
```python
        for idx, arg in enumerate(api.arguments_info):
            vn = f"{arg.name or f'arg{idx}'}_{api.function_name}"
            v = skeleton.variables.get(vn)
            if v is not None and getattr(v, "prepopulate", None):
                self._emit_collection_population(skeleton, vn)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_p4_collection_population.py -q`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/driver/synthesis/skeleton_generator.py tests/test_p4_collection_population.py
git commit -m "feat(productivity): wire collection population into render (gated)"
```

---

### Task 5: Golden net byte-identical (gate-off regression guard)

**Files:** Test: `tests/test_golden_characterization.py` (existing)

- [ ] **Step 1: Run the golden net with the gate OFF**

Run: `python -m pytest tests/test_golden_characterization.py -q`
Expected: PASS (gate-off ⇒ no behavior change ⇒ snapshots byte-identical)

- [ ] **Step 2: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: PASS (all prior + the new collection tests)

- [ ] **Step 3: Commit** (if any snapshot/doc touched; otherwise skip)

---

### Task 6: Per-driver dynamic validation (the empirical gate)

**Files:** none (measurement)

- [ ] **Step 1: Regenerate one lcms collection-constructor driver, gate on**

Run:
```bash
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_POPULATE_COLLECTIONS=1 \
  python3 run_logicfuzz.py -y comparison/lcms.yaml --generate-drivers --num-drivers 20
```
Expected: at least one driver renders `cmsToneCurve* curves[3]; curves[0]=ret_...;` (a
populated array), NOT `= {0}`. Grep the generated `fuzz_targets/*.fuzz_target`.

- [ ] **Step 2: Build + measure that driver on instrumented lcms** (reuse the
`/tmp/prodval/run.sh` pattern: fresh leak-safe container, `-fsanitize=fuzzer-no-link`
CFLAGS, compile the driver, 20s smoke). Expected: edges > the degenerate baseline (194
in the reference run; target shape ~334).

- [ ] **Step 3: Record the number** in `project_promefuzz_methodology_resolved` memory.

---

### Task 7: End-to-end merged-coverage A/B (the goal metric)

**Files:** none (measurement)

- [ ] **Step 1: Regenerate + merge lcms, gate on vs off, identical other flags**

Run (treatment):
```bash
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_POPULATE_COLLECTIONS=1 LLM_NUM_EXP=3 \
  python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers
```

- [ ] **Step 2: Measure seeded merged coverage** (single merged harness, 12 real `.icc`,
30 min) via `scripts/run_extended_fuzzing.py -p lcms --fuzz-target-dir
results/output-lcms-project/merged/synthesized --seed-corpus-dir <icc dir> -d 1800`.
Expected: merged br > control 1708 (toward PromeFuzz 4560).

- [ ] **Step 3: If gain confirmed, default-on after the A/B** (flip `_populate_collections`
default per the codebase's gate-graduation pattern) + document in CLAUDE.md.
