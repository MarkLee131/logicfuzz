# Valid-by-Construction Validity Contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the fuzz-driver constructor produce lifecycle/nullability/type-valid sequences by construction — enforced by a Validity Contract driven by an evidence-based `nullable` signal — so the ~73% of currently-invalid lcms drivers (orphan/NULL-arg/type-confused) become valid and survive into the merged harness, raising merged coverage toward PromeFuzz.

**Architecture:** A read-only **contract validator** (`validity_contract.py`) is both the construction gate and the regression oracle. The model's per-arg `nullable` is first made evidence-based (doc `@param` ⊕ IR `_cmsAssert` ⊕ role fallback). The constructor then satisfies the 4 invariants by repair-not-reject (bind→inject→drop-consumer). All behind `LOGICFUZZ_VALIDITY_CONTRACT=1` (default-off) until A/B-proven, then default-on.

**Tech Stack:** Python 3.10 (analysis/construct/render), pytest, the cached `api_semantic_model.json` per project, the rendered `*.fuzz_target` C sources, OSS-Fuzz docker merge measurement. The IR provenance touches the C++ `condition_extractor`.

**Spec:** `docs/superpowers/specs/2026-06-16-valid-by-construction-contract.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `liberator_adapter/analysis/validity_contract.py` (NEW) | `Call`/`ArgBinding` views, `check_sequence(calls, model) -> ContractReport`, `from_rendered_c(src, model)` adapter. The gate + oracle. |
| `tests/test_validity_contract.py` (NEW) | Validator unit tests + the lcms-corpus quantification regression. |
| `src/knowledge/project_docs.py` (MODIFY) | `_param_nullability_from_text(text)` — mine `@param` nullable/non-null cues. |
| `liberator_adapter/analysis/api_semantic_model.py` (MODIFY) | `_reconcile_args`: populate `nullable` = doc ⊕ IR ⊕ role; assign `NULLABLE_HANDLE`. |
| `liberator_adapter/analysis/sequence_constructor.py` (MODIFY) | `_build_prefix`: resolve EVERY non-NULL handle arg (I2a); producer-before-consumer order (I1); I2b value completeness. Gated. |
| `liberator_adapter/driver/factory/constraint_based/CBFactory.py` (MODIFY) | `_signature_handle_bindings`: type-correct binding by handle family (I3), additive with void* fallback. |
| `liberator_adapter/driver/synthesis/skeleton_generator.py` (MODIFY) | consume `_as.nullable`; render-time defense-in-depth guard. |
| `liberator_adapter/liberator/condition_extractor/` (MODIFY, last) | per-arg `NON_NULL` provenance (additive). |
| `CLAUDE.md` (MODIFY) | `LOGICFUZZ_VALIDITY_CONTRACT` gate doc. |

**Measurement checkpoints** after Task 5 (I2a) and Task 11 (final): run `LOGICFUZZ_VALIDITY_CONTRACT=1 LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers`, then measure with `scripts/run_extended_fuzzing.py --project lcms --fuzz-target-dir results/output-lcms-project/merged/synthesized --duration 1800`.

---

## Task 1: Contract validator (the oracle)

**Files:**
- Create: `liberator_adapter/analysis/validity_contract.py`
- Test: `tests/test_validity_contract.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_validity_contract.py
from liberator_adapter.analysis.validity_contract import (
    Call, ArgBinding, check_sequence)

# minimal model: api -> list of {index, type_str, nullable}
MODEL = {
    "cmsCreate_sRGBProfile": {"args": []},
    "cmsCloseProfile": {"args": [{"index": 0, "type_str": "cmsHPROFILE", "nullable": False}]},
    "cmsGetColorSpace": {"args": [{"index": 0, "type_str": "cmsHPROFILE", "nullable": False}]},
}

def test_orphan_handle_is_flagged_i2a():
    # cmsGetColorSpace(NULL) with no producer -> I2a violation
    calls = [Call("cmsGetColorSpace", [ArgBinding(producer=None, produced_at=None, is_null=True)])]
    rep = check_sequence(calls, MODEL)
    assert rep.counts["I2a"] == 1
    assert rep.total() == 1

def test_produced_handle_is_valid():
    # produce profile, then consume it -> no violation
    calls = [
        Call("cmsCreate_sRGBProfile", []),                         # produces ret at idx 0
        Call("cmsGetColorSpace", [ArgBinding(producer="cmsCreate_sRGBProfile", produced_at=0, is_null=False)]),
    ]
    rep = check_sequence(calls, MODEL)
    assert rep.total() == 0

def test_use_before_produce_is_i1():
    calls = [
        Call("cmsGetColorSpace", [ArgBinding(producer="cmsCreate_sRGBProfile", produced_at=1, is_null=False)]),
        Call("cmsCreate_sRGBProfile", []),
    ]
    rep = check_sequence(calls, MODEL)
    assert rep.counts["I1"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_validity_contract.py -v`
Expected: FAIL — `ModuleNotFoundError: validity_contract`.

- [ ] **Step 3: Write minimal implementation**

```python
# liberator_adapter/analysis/validity_contract.py
"""Validity Contract validator — the construction gate AND the regression oracle.
Read-only. Checks four invariants against the APISemanticModel's per-arg
{nullable, type_str}:
  I1  producer-before-consumer (no use-before-produce / close-before-open)
  I2a every nullable=False HANDLE arg has a producer (no orphan NULL handle)
  I2b every nullable=False non-handle required arg is non-NULL
  I3  handle arg bound to a producer of the SAME handle family (no void* confusion)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import re

@dataclass
class ArgBinding:
    producer: Optional[str]      # producing api name, or None
    produced_at: Optional[int]   # stmt index of the producer, or None
    is_null: bool                # bound to NULL at the call site

@dataclass
class Call:
    api: str
    args: List[ArgBinding]

@dataclass
class ContractReport:
    counts: Dict[str, int] = field(default_factory=lambda: {"I1": 0, "I2a": 0, "I2b": 0, "I3": 0})
    detail: List[str] = field(default_factory=list)
    def total(self) -> int:
        return sum(self.counts.values())

_HANDLE_FAMILIES = ("transform", "profile", "tonecurve", "pipeline", "stage",
                    "context", "it8")
def _family(s: str) -> Optional[str]:
    t = (s or "").lower()
    for fam in _HANDLE_FAMILIES:
        if fam in t:
            return fam
    if "hprofile" in t:
        return "profile"
    if "htransform" in t:
        return "transform"
    return None

def _is_handle_type(type_str: str) -> bool:
    t = (type_str or "")
    return _family(t) is not None or bool(re.search(r"cmsH[A-Z]|cms\w+\s*\*", t))

def _is_string_type(type_str: str) -> bool:
    return "char" in (type_str or "").lower()

def _producer_family(api: str) -> str:
    return _family(api) or "other"

def check_sequence(calls: List[Call], model: Dict) -> ContractReport:
    rep = ContractReport()
    for i, call in enumerate(calls):
        margs = (model.get(call.api) or {}).get("args") or []
        for j, b in enumerate(call.args):
            ma = next((a for a in margs if a.get("index") == j), None)
            if ma is None or ma.get("nullable", True):
                continue  # unknown or nullable -> exempt
            ts = ma.get("type_str", "")
            if _is_handle_type(ts):
                if b.producer is None or b.is_null:
                    rep.counts["I2a"] += 1
                    rep.detail.append(f"{call.api} arg{j}: orphan non-NULL handle ({ts})")
                elif b.produced_at is not None and b.produced_at > i:
                    rep.counts["I1"] += 1
                    rep.detail.append(f"{call.api} arg{j}: use-before-produce")
                else:
                    pf = _producer_family(b.producer)
                    af = _family(ts)
                    if af and pf != "other" and pf != af:
                        rep.counts["I3"] += 1
                        rep.detail.append(f"{call.api} arg{j}: type-confusion {pf}->{af}")
            elif _is_string_type(ts) and b.is_null:
                rep.counts["I2b"] += 1
                rep.detail.append(f"{call.api} arg{j}: non-NULL string = NULL")
    return rep
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_validity_contract.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/validity_contract.py tests/test_validity_contract.py
git commit -m "feat(contract): validity-contract validator (I1/I2a/I2b/I3 oracle)"
```

---

## Task 2: `.c` adapter + lcms-corpus quantification regression

**Files:**
- Modify: `liberator_adapter/analysis/validity_contract.py` (add `from_rendered_c`)
- Test: `tests/test_validity_contract.py` (add corpus test)

- [ ] **Step 1: Write the failing test**

```python
def test_from_rendered_c_flags_orphan_getter():
    from liberator_adapter.analysis.validity_contract import from_rendered_c
    src = (
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){\n"
        "  void * arg0_cmsGetColorSpace = NULL;\n"
        "  cmsGetColorSpace(arg0_cmsGetColorSpace);\n"
        "  return 0; }\n"
    )
    rep = from_rendered_c(src, MODEL)
    assert rep.counts["I2a"] >= 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_validity_contract.py::test_from_rendered_c_flags_orphan_getter -v`
Expected: FAIL — `from_rendered_c` not defined.

- [ ] **Step 3: Implement `from_rendered_c`** (port the prototype `docs/superpowers/specs/assets/2026-06-16-validity-contract-checker-prototype.py` parsing into `Call`/`ArgBinding`, then call `check_sequence`). Parse: declarations `<type> <var> = NULL;` → null vars; `ret_<api> = <api>(...)` → producer var + index; each `<api>(args)` → `Call` with `ArgBinding(producer=<the ret var's producer if the arg is a produced ret>, produced_at=<idx>, is_null=<var in null_decls and not produced>)`.

- [ ] **Step 4: Run + verify pass**, then run the corpus quantification (informational, not asserted in CI):

```bash
python3 -c "
from liberator_adapter.analysis.validity_contract import from_rendered_c
import json, glob
model=json.load(open('results/lcms/state/api_semantic_model.json')); model=model.get('apis',model)
from collections import Counter; c=Counter(); inv=0; tot=0
for f in glob.glob('/tmp/inv_check/*.fuzz_target'):
    r=from_rendered_c(open(f).read(), model); tot+=1
    if r.total(): inv+=1
    for k,v in r.counts.items(): c[k]+=v
print('invalid drivers:', inv, '/', tot, '| counts:', dict(c))
"
```
Expected: matches the spec's quantification (~46/63 invalid, I2a dominant).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/validity_contract.py tests/test_validity_contract.py
git commit -m "feat(contract): rendered-C adapter + corpus quantification oracle"
```

---

## Task 3: Nullability doc-cue mining (`project_docs.py`)

**Files:**
- Modify: `src/knowledge/project_docs.py`
- Test: `tests/test_param_nullability.py` (NEW)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_param_nullability.py
from src.knowledge.project_docs import _param_nullability_from_text

def test_must_not_be_null():
    assert _param_nullability_from_text("the profile handle; must not be NULL") is False
def test_may_be_null():
    assert _param_nullability_from_text("context, or NULL for the global context") is True
def test_optional():
    assert _param_nullability_from_text("optional output buffer") is True
def test_unknown_returns_none():
    assert _param_nullability_from_text("the number of channels") is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_param_nullability.py -v`
Expected: FAIL — function not defined.

- [ ] **Step 3: Implement** in `src/knowledge/project_docs.py`:

```python
_NONNULL_CUES = re.compile(r"must not be null|non-?null|cannot be null|required|valid pointer", re.I)
_NULLABLE_CUES = re.compile(r"may be null|can be null|or null|optional|null to|if null", re.I)

def _param_nullability_from_text(text: str):
    """Return False (must be non-NULL), True (may be NULL), or None (unknown)
    from a doc @param description. Nullable cue wins ties (safer: don't over-constrain)."""
    t = text or ""
    if _NULLABLE_CUES.search(t):
        return True
    if _NONNULL_CUES.search(t):
        return False
    return None
```
Then capture it where params are parsed (`_parse_doxygen_structured`, ~line 401-407): set `params[i]['nullable'] = _param_nullability_from_text(ptext)`.

- [ ] **Step 4: Run + verify pass.**

Run: `python3 -m pytest tests/test_param_nullability.py -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/knowledge/project_docs.py tests/test_param_nullability.py
git commit -m "feat(docs): mine @param nullability cues (was extracted-but-discarded)"
```

---

## Task 4: Nullability reconcile + NULLABLE_HANDLE (`api_semantic_model.py`)

**Files:**
- Modify: `liberator_adapter/analysis/api_semantic_model.py` (`_reconcile_args`, ~597-700)
- Test: `tests/test_nullable_reconcile.py` (NEW)

- [ ] **Step 1: Read** `api_semantic_model.py:_reconcile_args` and line 694 (`nullable = role in (...)`) to see the role/doc evidence inputs.

- [ ] **Step 2: Write the failing test** — assert that a doc-`nullable=True` cue overrides the role default, and an optional handle gets `NULLABLE_HANDLE`:

```python
# tests/test_nullable_reconcile.py
from liberator_adapter.analysis.api_semantic_model import _reconcile_arg_nullable
def test_doc_nullable_overrides_role():
    # role would say False (handle), doc says may-be-NULL -> True
    assert _reconcile_arg_nullable(role_default=False, doc=True, ir_nonnull=None) is True
def test_ir_nonnull_overrides_doc_silence():
    assert _reconcile_arg_nullable(role_default=True, doc=None, ir_nonnull=True) is False
def test_role_fallback_when_no_evidence():
    assert _reconcile_arg_nullable(role_default=False, doc=None, ir_nonnull=None) is False
```

- [ ] **Step 3: Run to verify it fails.** Run: `python3 -m pytest tests/test_nullable_reconcile.py -v` → FAIL.

- [ ] **Step 4: Implement** `_reconcile_arg_nullable(role_default, doc, ir_nonnull)`:

```python
def _reconcile_arg_nullable(role_default: bool, doc, ir_nonnull):
    """Evidence priority: IR non-null > doc cue > role heuristic.
    ir_nonnull: True means proven non-null (-> nullable False). doc: bool or None."""
    if ir_nonnull is True:
        return False
    if doc is not None:
        return bool(doc)
    return bool(role_default)
```
Wire it at line 694: `nullable = _reconcile_arg_nullable(role in (ArgRole.NULLABLE_HANDLE, ArgRole.OUTPUT), doc_nullable_for_arg(i), ir_nonnull_for_arg(i))`, sourcing `doc_nullable_for_arg` from the params' `nullable` (Task 3) and `ir_nonnull_for_arg` from conditions.json (Task 9; `None` until then).

- [ ] **Step 5: Run + verify pass + commit.**

```bash
git add liberator_adapter/analysis/api_semantic_model.py tests/test_nullable_reconcile.py
git commit -m "feat(model): reconcile arg nullable from doc/IR/role (evidence-based)"
```

---

## Task 5: I2a orphan resolution in the constructor (HEADLINE)

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` (`_build_prefix`, the resolution loop)
- Test: `tests/test_construct_i2a.py` (NEW)

- [ ] **Step 1: Read** `sequence_constructor.py` `_build_prefix` (~936), the `requires` resolution, `_synthetic_producer` (~699), and the no-requires injection (~312-336). Note how `opened`/`produced` handle sets are tracked.

- [ ] **Step 2: Write the failing test** — a target whose model has a `nullable=False` handle arg NOT in `requires` must get a producer in the constructed prefix (gated):

```python
# tests/test_construct_i2a.py  (use a cached model + a synthetic target)
import os, json
from liberator_adapter.analysis.validity_contract import from_rendered_c
def test_gate_on_resolves_all_nonnull_handle_args():
    os.environ["LOGICFUZZ_VALIDITY_CONTRACT"] = "1"
    # build a sequence for an lcms transform target via the constructor entry point,
    # render it, and assert 0 I2a violations
    # (concrete construction call resolved when reading _build_prefix in Step 1)
    ...
    assert rep.counts["I2a"] == 0
```

- [ ] **Step 3: Implement** (gated `LOGICFUZZ_VALIDITY_CONTRACT`): in `_build_prefix`, after the `requires` resolution, iterate the target's model args; for each `nullable=False` arg whose `type_str` is a handle and is not yet bound to a producer, apply the layered policy: (a) bind an existing opened producer of the matching family; else (b) inject a synthetic no-requires producer (reuse `_synthetic_producer` / injection at 312-336); else (c) mark the consumer for drop. Ensure inserted producers precede the consumer (feeds I1).

- [ ] **Step 4: Run** the test + the corpus oracle; expect I2a → 0 on constructed lcms sequences. Run full suite: `python3 -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py tests/test_construct_i2a.py
git commit -m "feat(construct): I2a resolve every non-NULL handle arg (gated)"
```

---

## Task 6: MEASUREMENT CHECKPOINT (I2a)

- [ ] Run the gated merge + measure:

```bash
LOGICFUZZ_VALIDITY_CONTRACT=1 LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_EXERCISE_OBJECT=1 LOGICFUZZ_OBJCONSTRUCT_FIRST=1 \
  python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers 2>&1 | tee results/contract_i2a.log
python3 scripts/run_extended_fuzzing.py --project lcms \
  --fuzz-target-dir results/output-lcms-project/merged/synthesized --duration 1800 \
  --output-dir results/extended_fuzzing/lcms_contract_i2a
```
- [ ] Record: contract violations (validator on the new drivers), merged-driver count (expect 19→≥40), edges (expect past 2092 toward 3500). If no gain, STOP and re-investigate before continuing (systematic-debugging).

---

## Task 7: I1 order enforcement

**Files:** Modify `sequence_constructor.py` (emit producers before consumers); Test `tests/test_construct_i1.py`.
- [ ] Test: a constructed sequence has every producer at an index < its consumers (assert validator `counts["I1"] == 0`). Implement: topological emit in `_build_prefix`; never place a consumer/destroyer before its producer. Commit `feat(construct): I1 producer-before-consumer order`.

## Task 8: I2b value completeness

**Files:** Modify `sequence_constructor.py` / `hole_semantics.py`; Test `tests/test_construct_i2b.py`.
- [ ] Test: a `nullable=False` non-handle required arg (e.g. `char*`) is never left NULL — either filled with a valid value-intent or the consumer is dropped (assert `counts["I2b"] == 0`). Commit `feat(construct): I2b fill non-NULL value args`.

## Task 9: IR per-arg NON_NULL provenance (additive, heaviest)

**Files:** Modify `liberator_adapter/liberator/condition_extractor/` (`ProvenanceTracker.h` + the pass); `error_contracts.py` (consume per-arg). Test `tests/test_ir_nonnull.py`.
- [ ] Read the extractor's return-NULL provenance path (`error_contracts.py:195-199`). Add a per-ARG `NON_NULL` tag emitted from `assert(arg!=NULL)` / `__attribute__((nonnull))` / unconditional-deref-before-check. Wire into `ir_nonnull_for_arg` (Task 4). ADDITIVE: absent extractor support → `None` → role/doc fallback. Validate `conditions.json` carries it for lcms. Commit `feat(ir): per-arg NON_NULL provenance`.

## Task 10: I3 type-correct binding in CBFactory (additive)

**Files:** Modify `CBFactory.py` `_signature_handle_bindings` (~1384-1405); Test `tests/test_bind_i3.py` over cached lcms/zlib/cjson models.
- [ ] Read `_signature_handle_bindings`. Bind a consumer arg of handle family F to a producer ret of family F (match by `type_str` family, not nearest void*); keep the legacy void* binding as FALLBACK when family is unknown. Cross-project test: lcms `cmsCloseProfile` binds to a PROFILE not a transform; zlib/cjson/c-ares unchanged (no family info → fallback). Commit `feat(bind): I3 type-correct handle binding (additive)`.

## Task 11: Defense-in-depth render guard + gate doc + final measurement

**Files:** Modify `skeleton_generator.py` (consume `_as.nullable`; render `if(handle)` guard ONLY for residual runtime-NULL); `CLAUDE.md` (gate doc); Test `tests/test_render_nullable_guard.py`.
- [ ] Renderer reads `_as.nullable`; a `nullable=False` handle arg that is unbound at render is guarded (defense-in-depth), not emitted as a bare NULL consume. Document `LOGICFUZZ_VALIDITY_CONTRACT` in CLAUDE.md. Commit.
- [ ] **Multi-project no-op check:** run the validator + construct (gate-on) for cjson / c-ares / zlib — confirm no new failures, byte-identical where already-valid, I3 fallback inert. `python3 -m pytest tests/ -q` green; golden net green with gate OFF.
- [ ] **FINAL MEASUREMENT:** full gated merge + 1800s measure on lcms; record edges vs 2092 / 3500. Update `contract_report.json` before/after.

---

## Self-Review notes
- **Spec coverage:** §3.0 → Tasks 3,4,9; §I1 → 7; §I2a → 5; §I2b → 8; §I3 → 10; validator/oracle → 1,2; defense-in-depth → 11; gating → all (env `LOGICFUZZ_VALIDITY_CONTRACT`); multi-project → 11; measurement → 6,11.
- **Type consistency:** `Call`/`ArgBinding`/`ContractReport` (Task 1) reused in 2,5,7,8; `_reconcile_arg_nullable(role_default, doc, ir_nonnull)` (Task 4) consumed by 9; `nullable` key from Task 3 feeds Task 4.
- **Known read-first tasks:** 5, 9, 10 require reading the target function before final code (fragile constructor/binding/C++ extractor) — each has an explicit Step-1 read.
