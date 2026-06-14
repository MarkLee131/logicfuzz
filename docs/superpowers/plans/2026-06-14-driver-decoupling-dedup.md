# Driver Decoupling & De-duplication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce inter-driver coverage overlap so the merged portfolio gains real marginal coverage — by decoupling sequences at construction time and de-duplicating them at selection time over a doc-aware structural fingerprint.

**Architecture:** Each lever's logic lives in a small, unit-tested pure function in `liberator_adapter/analysis/` or `liberator_adapter/constraints/`; `src/context/data_context.py` wires each behind a `LOGICFUZZ_*` env gate (default-OFF, A/B control). The doc/LLM semantic layer is upstream: it supplies the partition keys (`workflow_id` from co-occurrence) and the fingerprint's value-domain signature (from G4 `value_intents`). All construction-side changes are deterministic.

**Tech Stack:** Python 3, pytest (monkeypatch + tmp_path, no conftest), Z3 (untouched here), existing modules: `sequence_constructor.py`, `coverage_ranker.py`, `hole_semantics.py`, `order_sets.py`, `subsystem_clusters.py`, `data_context.py`.

**Spec:** `docs/superpowers/specs/2026-06-14-driver-decoupling-dedup-design.md`

**Conventions (verified):**
- Tests live in `tests/test_pN_<topic>.py`. Run with `pytest tests/`.
- Env-gate read form used in newer code: `os.environ.get("LOGICFUZZ_X", "").strip().lower() in ("1", "true", "yes", "on")`.
- Test helpers (copy locally per test file): `_api(name, args, ret)`, `_arg(type_str, const, name)`, `reconcile(apis)` from `liberator_adapter.analysis.api_semantic_model`, `construct_sequences(model)` from `liberator_adapter.analysis.sequence_constructor`.
- All new gates default-OFF; gate-off behavior MUST be byte-identical to today (A/B control).

---

## Phase 1 — B-1 marginal depth selector + Layer E static telemetry

### Task 1: Shared marginal-coverage selection primitive

**Files:**
- Modify: `liberator_adapter/constraints/coverage_ranker.py` (add a module-level function near `_portfolio_config`, after the imports block ~line 44)
- Test: `tests/test_p2_marginal_select.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_marginal_select.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.constraints.coverage_ranker import select_marginal


def test_select_marginal_picks_max_new_api_each_step():
    items = [
        {"api_sequence": ["a", "b", "c"]},   # 3 new
        {"api_sequence": ["a", "b"]},        # subset of first → 0 new after it
        {"api_sequence": ["d", "e"]},        # 2 new
    ]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=2)
    seqs = [d["api_sequence"] for d in sel]
    assert seqs[0] == ["a", "b", "c"]      # highest marginal first
    assert seqs[1] == ["d", "e"]           # next-highest marginal, NOT the subset


def test_select_marginal_stops_when_nothing_new():
    items = [{"api_sequence": ["a", "b"]}, {"api_sequence": ["a"]}]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=5)
    assert len(sel) == 1                    # second adds nothing → stop


def test_select_marginal_respects_precovered():
    items = [{"api_sequence": ["a", "b"]}, {"api_sequence": ["c"]}]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=5,
                          covered={"a", "b"})
    assert [d["api_sequence"] for d in sel] == [["c"]]  # 'ab' already covered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_marginal_select.py -v`
Expected: FAIL with `ImportError: cannot import name 'select_marginal'`

- [ ] **Step 3: Write minimal implementation**

Add to `liberator_adapter/constraints/coverage_ranker.py` after the `_portfolio_config` function:

```python
def select_marginal(items, seq_of, budget, covered=None):
    """Greedy max-marginal-new-API selection (shared primitive).

    At each step picks the remaining item whose ``seq_of(item)`` adds the most
    APIs not yet in ``covered``; stops at ``budget`` or when nothing new is
    added. ``covered`` is an optional pre-covered API set (copied, not
    mutated). Returns the selected items in selection order.

    This is the SAME objective ``_coverage_complete_select`` Phase 2 uses; it
    exists so the data_context skeleton depth pass can stop using round-robin
    and share one marginal selector (B-1).
    """
    covered_set = set(covered or ())
    remaining = list(items)
    selected = []
    while remaining and len(selected) < budget:
        best_i = max(
            range(len(remaining)),
            key=lambda i: len(set(seq_of(remaining[i])) - covered_set),
        )
        best = remaining.pop(best_i)
        new = set(seq_of(best)) - covered_set
        if not new:
            break
        selected.append(best)
        covered_set.update(seq_of(best))
    return selected
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p2_marginal_select.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/constraints/coverage_ranker.py tests/test_p2_marginal_select.py
git commit -m "feat(dedup): shared marginal-coverage selection primitive (B-1 prep)"
```

---

### Task 2: B-1 — replace round-robin depth pass with marginal selection (gated)

**Files:**
- Modify: `src/context/data_context.py` — the Phase 2 depth pass inside the skeleton portfolio block (the region containing `if _pf_mode != 'minimal':` then `_depth_budget = int(round(_pf_depth * _n_cover))` then the `_used = [[(id(_d) in _sel_ids) ...` round-robin `while _added < _depth_budget:` loop).
- Test: covered by Task 1's unit test of `select_marginal` (the data_context wiring is a thin gated call; no separate unit test for the 3900-line module).

- [ ] **Step 1: Locate the exact block**

Run: `grep -n "_depth_budget = int(round(_pf_depth" src/context/data_context.py`
Expected: one line number inside the coverage-complete portfolio block (~1996).

- [ ] **Step 2: Replace the round-robin depth loop with a gated marginal pass**

Find this exact current code:

```python
                        if _pf_mode != 'minimal':
                            _depth_budget = int(round(_pf_depth * _n_cover))
                            _used = [[(id(_d) in _sel_ids) for _d in _b]
                                     for _b in _buckets]
                            _added = 0
                            while _added < _depth_budget:
                                _moved = False
                                for _j, _b in enumerate(_buckets):
                                    for _i, _d in enumerate(_b):
                                        if not _used[_j][_i]:
                                            _portfolio.append(_d)
                                            _used[_j][_i] = True
                                            _added += 1
                                            _moved = True
                                            break
                                    if _added >= _depth_budget:
                                        break
                                if not _moved:
                                    break
```

Replace it with (round-robin kept verbatim in the `else`, so gate-off is byte-identical behavior):

```python
                        if _pf_mode != 'minimal':
                            _depth_budget = int(round(_pf_depth * _n_cover))
                            _marginal_depth = (
                                os.environ.get("LOGICFUZZ_MARGINAL_DEPTH", "")
                                .strip().lower() in ("1", "true", "yes", "on"))
                            if _marginal_depth:
                                # B-1: pick depth drivers by MAX marginal new-API
                                # coverage over the already-selected cover set —
                                # the same objective coverage_ranker uses — instead
                                # of bucket round-robin (which admits near-twins).
                                from liberator_adapter.constraints.coverage_ranker \
                                    import select_marginal
                                _covered_apis = {
                                    a for _d in _portfolio
                                    for a in (_d.get('api_sequence') or [])}
                                _pool = [_d for _b in _buckets for _d in _b
                                         if id(_d) not in _sel_ids]
                                _depth_sel = select_marginal(
                                    _pool,
                                    lambda _d: _d.get('api_sequence') or [],
                                    _depth_budget, _covered_apis)
                                _portfolio.extend(_depth_sel)
                            else:
                                _used = [[(id(_d) in _sel_ids) for _d in _b]
                                         for _b in _buckets]
                                _added = 0
                                while _added < _depth_budget:
                                    _moved = False
                                    for _j, _b in enumerate(_buckets):
                                        for _i, _d in enumerate(_b):
                                            if not _used[_j][_i]:
                                                _portfolio.append(_d)
                                                _used[_j][_i] = True
                                                _added += 1
                                                _moved = True
                                                break
                                        if _added >= _depth_budget:
                                            break
                                    if not _moved:
                                        break
```

- [ ] **Step 3: Verify the module imports and the full suite is green (gate off = no change)**

Run: `python -c "import src.context.data_context"`
Expected: no error.
Run: `pytest tests/ -q`
Expected: same pass count as before this task (no regressions; gate is off by default).

- [ ] **Step 4: Commit**

```bash
git add src/context/data_context.py
git commit -m "feat(dedup): B-1 gated marginal depth selector (LOGICFUZZ_MARGINAL_DEPTH)"
```

---

### Task 3: Layer E — portfolio-redundancy metric (pure function)

**Files:**
- Create: `liberator_adapter/analysis/portfolio_redundancy.py`
- Test: `tests/test_p2_portfolio_redundancy.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_portfolio_redundancy.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.portfolio_redundancy import portfolio_redundancy


def test_disjoint_portfolio_scores_one():
    m = portfolio_redundancy([["a", "b"], ["c", "d"]])
    assert m["n_drivers"] == 2
    assert m["union_apis"] == 4
    assert m["sum_per_driver_apis"] == 4
    assert m["disjointness"] == 1.0
    assert m["mean_pairwise_jaccard"] == 0.0


def test_identical_portfolio_is_maximally_redundant():
    m = portfolio_redundancy([["a", "b"], ["a", "b"]])
    assert m["disjointness"] == 0.5          # union 2 / total 4
    assert m["mean_pairwise_jaccard"] == 1.0


def test_empty_is_safe():
    m = portfolio_redundancy([])
    assert m["n_drivers"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_portfolio_redundancy.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# liberator_adapter/analysis/portfolio_redundancy.py
"""Layer E: portfolio-redundancy telemetry — the A/B oracle for decoupling.

Pure, deterministic, no LLM. Computes how much the selected drivers overlap in
API-set terms; a *lower* mean pairwise Jaccard and a *higher* disjointness mean
the portfolio is better decoupled (merge gains more marginal coverage).
"""
from __future__ import annotations

import itertools
from typing import Any, Dict, List, Sequence


def portfolio_redundancy(sequences: Sequence[Sequence[str]]) -> Dict[str, Any]:
    """Return redundancy metrics for a list of driver API sequences.

    Keys: n_drivers, union_apis, sum_per_driver_apis, disjointness
    (union/total, 1.0 = fully disjoint), mean_pairwise_jaccard
    (0.0 = no pairwise overlap).
    """
    sets: List[set] = [set(s) for s in sequences if s]
    n = len(sets)
    out: Dict[str, Any] = {"n_drivers": n}
    if n == 0:
        return out
    union: set = set().union(*sets)
    total = sum(len(s) for s in sets)
    out["union_apis"] = len(union)
    out["sum_per_driver_apis"] = total
    out["disjointness"] = (len(union) / total) if total else 1.0
    if n > 1:
        jaccards: List[float] = []
        for a, b in itertools.combinations(sets, 2):
            u = a | b
            jaccards.append(len(a & b) / len(u) if u else 0.0)
        out["mean_pairwise_jaccard"] = sum(jaccards) / len(jaccards)
    else:
        out["mean_pairwise_jaccard"] = 0.0
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p2_portfolio_redundancy.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/portfolio_redundancy.py tests/test_p2_portfolio_redundancy.py
git commit -m "feat(dedup): Layer E portfolio-redundancy metric"
```

---

### Task 4: Emit redundancy telemetry to results/<project>/static_analysis/

**Files:**
- Modify: `src/context/data_context.py` — `save_intermediate_results(...)`, just before its final success log `log.info(f"✅ All intermediate results saved to: {results_path}")`.
- Test: covered by Task 3 (the writer is a thin gated dump of the tested metric).

- [ ] **Step 1: Locate the insertion point**

Run: `grep -n "All intermediate results saved to" src/context/data_context.py`
Expected: one line near the end of `save_intermediate_results`.

- [ ] **Step 2: Insert the telemetry dump before that log line**

Find this exact current code:

```python
        log.info(f"✅ All intermediate results saved to: {results_path}")
```

Insert immediately BEFORE it:

```python
        # Layer E: portfolio-redundancy telemetry (always-on, cheap) — the A/B
        # oracle for the decoupling/dedup levers. Lower mean_pairwise_jaccard /
        # higher disjointness ⇒ better-decoupled portfolio.
        if skeleton_drivers:
            try:
                from liberator_adapter.analysis.portfolio_redundancy import (
                    portfolio_redundancy)
                _red = portfolio_redundancy(
                    [d.get('api_sequence', []) for d in skeleton_drivers])
                with open(results_path / "redundancy_telemetry.json", 'w') as f:
                    json.dump(_red, f, indent=2)
                log.info("   📄 Saved redundancy telemetry: "
                         f"disjointness={_red.get('disjointness'):.3f} "
                         f"mean_jaccard={_red.get('mean_pairwise_jaccard'):.3f}")
            except Exception as _e:
                log.warning(f"redundancy telemetry failed (non-critical): {_e}")

        log.info(f"✅ All intermediate results saved to: {results_path}")
```

- [ ] **Step 3: Verify import + suite**

Run: `python -c "import src.context.data_context"`
Expected: no error.
Run: `pytest tests/ -q`
Expected: no regressions.

- [ ] **Step 4: Commit**

```bash
git add src/context/data_context.py
git commit -m "feat(dedup): emit redundancy_telemetry.json (Layer E)"
```

---

## Phase 2 — Layer C fingerprint + A-2a/A-2b densifier + B-2 gate

### Task 5: Layer C — doc-aware structural fingerprint

**Files:**
- Create: `liberator_adapter/analysis/driver_fingerprint.py`
- Test: `tests/test_p2_driver_fingerprint.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_driver_fingerprint.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.driver_fingerprint import (
    sequence_fingerprint, fingerprint_similarity, fingerprint_is_subset)


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _lib():
    return [
        _api("thing_create", [], ret="Thing *"),
        _api("thing_use", [_arg("Thing *")], ret="int"),
        _api("thing_free", [_arg("Thing *")]),
    ]


def test_identical_sequences_are_maximally_similar():
    m = reconcile(_lib())
    a = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    b = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    assert fingerprint_similarity(a, b) == 1.0


def test_different_value_domain_makes_distinct():
    m = reconcile(_lib())
    vi_x = [{"api": "thing_use", "role": "CONSUMER",
             "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE gamma"}]}]
    vi_y = [{"api": "thing_use", "role": "CONSUMER",
             "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE enum"}]}]
    a = sequence_fingerprint(["thing_create", "thing_use"], m, vi_x)
    b = sequence_fingerprint(["thing_create", "thing_use"], m, vi_y)
    assert fingerprint_similarity(a, b) == 0.0   # value-domain distinct → not redundant


def test_strict_subset_with_same_value_domain():
    m = reconcile(_lib())
    small = sequence_fingerprint(["thing_create", "thing_free"], m)
    big = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    assert fingerprint_is_subset(small, big) is True
    assert fingerprint_is_subset(big, small) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_driver_fingerprint.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# liberator_adapter/analysis/driver_fingerprint.py
"""Layer C: doc-aware structural fingerprint of a driver sequence.

A fingerprint is (api_set, root_producers, subchain_shape, value_domain_sig).
The value-domain signature is the keystone of doc/LLM integration: it is a hash
of the G4 ``value_intents`` CONFIG/enum/range intents, so two drivers with the
same APIs but doc-distinct value strategies are NON-redundant. Deterministic;
no LLM.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional, Sequence

# CREATOR->C, MUTATOR->M, CONSUMER->U, DESTROYER->D, UNKNOWN->?
_ROLE_CODE = {"CREATOR": "C", "MUTATOR": "M", "CONSUMER": "U",
              "DESTROYER": "D", "UNKNOWN": "?"}


@dataclass(frozen=True)
class Fingerprint:
    api_set: FrozenSet[str]
    root_producers: FrozenSet[str]
    subchain_shape: str          # ordered role codes, e.g. "CUD"
    value_domain_sig: str        # hash of CONFIG/enum/range intents ("" if none)


def _role_name(model, name: str) -> str:
    sem = model.get(name) if model else None
    role = getattr(sem, "role", None)
    return getattr(role, "name", "UNKNOWN") if role is not None else "UNKNOWN"


def _value_domain_signature(
        value_intents: Optional[Sequence[Dict[str, Any]]]) -> str:
    if not value_intents:
        return ""
    items = []
    for rec in value_intents:
        api = rec.get("api", "")
        for a in rec.get("args", []):
            role = a.get("role", "")
            intent = a.get("intent", "") or ""
            if role == "CONFIG" or intent.startswith(
                    ("FUZZ_DERIVE", "ENUM", "VARY_RANGE")):
                items.append([api, a.get("index"), role, intent])
    if not items:
        return ""
    items.sort(key=lambda t: (str(t[0]), -1 if t[1] is None else t[1], str(t[2])))
    blob = json.dumps(items, sort_keys=True, default=str)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def sequence_fingerprint(
        api_sequence: Sequence[str],
        model,
        value_intents: Optional[Sequence[Dict[str, Any]]] = None) -> Fingerprint:
    api_set = frozenset(a for a in api_sequence if a)
    roots = frozenset(
        a for a in api_sequence if _role_name(model, a) == "CREATOR")
    shape = "".join(_ROLE_CODE.get(_role_name(model, a), "?")
                    for a in api_sequence if a)
    return Fingerprint(api_set, roots, shape,
                       _value_domain_signature(value_intents))


def _jaccard(a: FrozenSet[str], b: FrozenSet[str]) -> float:
    if not a and not b:
        return 1.0
    u = a | b
    return len(a & b) / len(u) if u else 1.0


def fingerprint_similarity(a: Fingerprint, b: Fingerprint) -> float:
    """Pairwise similarity in [0,1] for the B-2 dedup gate.

    Value-domain-distinct drivers are NEVER redundant (return 0.0) — this is the
    doc-integration guard that prevents dropping a doc-meaningful value variant.
    Otherwise similarity is the API-set Jaccard.
    """
    if a.value_domain_sig != b.value_domain_sig:
        return 0.0
    return _jaccard(a.api_set, b.api_set)


def fingerprint_is_subset(a: Fingerprint, b: Fingerprint) -> bool:
    """True iff ``a`` is a strict, same-value-domain, same-or-fewer-roots subset
    of ``b`` (B-3 subset elimination). A value-distinct or root-distinct subset
    is NOT eliminated.
    """
    return (a.value_domain_sig == b.value_domain_sig
            and a.root_producers <= b.root_producers
            and a.api_set < b.api_set)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p2_driver_fingerprint.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/driver_fingerprint.py tests/test_p2_driver_fingerprint.py
git commit -m "feat(dedup): Layer C doc-aware structural fingerprint"
```

---

### Task 6: A-2a — sibling-rotated disjoint densifier slices (gated)

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` — `_densify(...)` signature + the `ordered = sorted(cands.values(), key=_rank)[:max(0, max_extra)]` slice; and the per-target call site `core = _densify(core, opened, idx, _dense_max_extra, _dense_repeat, _cooccur)`.
- Test: `tests/test_p2_densify_partition.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_densify_partition.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _wide_lib():
    """One handle with MANY consumers so densify has >max_extra candidates."""
    apis = [_api("h_create", [], ret="H *"), _api("h_free", [_arg("H *")])]
    for i in range(12):
        apis.append(_api(f"h_use{i}", [_arg("H *")], ret="int"))
    return apis


def test_sibling_slices_are_disjoint_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DENSE_PARTITION", "1")
    idx = SC._build_index(reconcile(_wide_lib()))
    opened = {"H *"}
    s0 = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                     sibling_rank=0)
    s1 = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                     sibling_rank=1)
    extra0 = set(s0) - {"h_create"}
    extra1 = set(s1) - {"h_create"}
    assert extra0 and extra1
    assert extra0.isdisjoint(extra1)        # siblings exercise different slices


def test_gate_off_is_unchanged(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DENSE_PARTITION", raising=False)
    idx = SC._build_index(reconcile(_wide_lib()))
    opened = {"H *"}
    a = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                    sibling_rank=0)
    b = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                    sibling_rank=3)
    assert a == b                            # rank ignored when gate off
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_densify_partition.py -v`
Expected: FAIL — `_densify() got an unexpected keyword argument 'sibling_rank'`.

- [ ] **Step 3: Add `sibling_rank` and the rotated slice**

In `_densify`, change the signature from:

```python
def _densify(core_seq: List[str], opened: Set[str], idx: _Index,
             max_extra: int, repeat: bool,
             cooccur: Optional[Dict[str, Set[str]]] = None) -> List[str]:
```

to:

```python
def _densify(core_seq: List[str], opened: Set[str], idx: _Index,
             max_extra: int, repeat: bool,
             cooccur: Optional[Dict[str, Set[str]]] = None,
             sibling_rank: int = 0) -> List[str]:
```

Then change the slice line from:

```python
    ordered = sorted(cands.values(), key=_rank)[:max(0, max_extra)]
```

to:

```python
    _ranked = sorted(cands.values(), key=_rank)
    # A-2a (LOGICFUZZ_DENSE_PARTITION): sibling chains sharing this handle set
    # take DISJOINT slices of the ranked candidate pool, so two near-twin chains
    # get DIFFERENT densifier suffixes (raises portfolio breadth, cuts overlap).
    # Deterministic: slice offset = sibling_rank * max_extra, wrap when exhausted.
    if (max_extra > 0 and os.environ.get("LOGICFUZZ_DENSE_PARTITION", "")
            .strip().lower() in ("1", "true", "yes", "on")):
        start = (sibling_rank * max_extra) % max(1, len(_ranked))
        rotated = _ranked[start:] + _ranked[:start]
        ordered = rotated[:max(0, max_extra)]
    else:
        ordered = _ranked[:max(0, max_extra)]
```

- [ ] **Step 4: Thread `sibling_rank` from the per-target call site**

Find this exact current code in `construct_sequences`:

```python
        for target in targets:
            n_attempted += 1
            prefix, opened = _build_prefix(target, idx, max_prefix_depth)
            # The target itself opens handles if it is also a producer.
            opened = set(opened) | set(target.produces)
            core = prefix + [target.name]
            if _dense:
                core = _densify(core, opened, idx, _dense_max_extra,
                                _dense_repeat, _cooccur)
```

Replace it with (add a per-opened-set sibling counter just before the loop and pass it in):

```python
        _sibling_rank: Dict[frozenset, int] = {}
        for target in targets:
            n_attempted += 1
            prefix, opened = _build_prefix(target, idx, max_prefix_depth)
            # The target itself opens handles if it is also a producer.
            opened = set(opened) | set(target.produces)
            core = prefix + [target.name]
            if _dense:
                _grp = frozenset(opened)
                _rank_i = _sibling_rank.get(_grp, 0)
                _sibling_rank[_grp] = _rank_i + 1
                core = _densify(core, opened, idx, _dense_max_extra,
                                _dense_repeat, _cooccur, sibling_rank=_rank_i)
```

- [ ] **Step 5: Run the test + full suite**

Run: `pytest tests/test_p2_densify_partition.py -v`
Expected: PASS (2 passed)
Run: `pytest tests/test_p1_sequence_constructor.py tests/ -q`
Expected: no regressions (gate off ⇒ identical output).

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py tests/test_p2_densify_partition.py
git commit -m "feat(dedup): A-2a sibling-rotated densifier slices (LOGICFUZZ_DENSE_PARTITION)"
```

---

### Task 7: A-2b — workflow-cluster-aware partition + `_rank` workflow affinity (gated)

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` — add a `_workflow_clusters(cooccur)` helper; thread a `workflow_of` map into `_densify`; add a `workflow_affinity` element to the nested `_rank` **strictly after `sat`**; make the A-2a rotation assign whole workflow clusters when this gate is on.
- Test: `tests/test_p2_densify_workflow.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_densify_workflow.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.sequence_constructor import _workflow_clusters


def test_workflow_clusters_are_connected_components():
    # a-b-c co-occur together; x-y co-occur together; two components.
    cooccur = {"a": {"b", "c"}, "b": {"a", "c"}, "c": {"a", "b"},
               "x": {"y"}, "y": {"x"}}
    wf = _workflow_clusters(cooccur)
    assert wf["a"] == wf["b"] == wf["c"]
    assert wf["x"] == wf["y"]
    assert wf["a"] != wf["x"]


def test_singletons_get_distinct_ids():
    wf = _workflow_clusters({"a": set(), "b": set()})
    assert wf["a"] != wf["b"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_densify_workflow.py -v`
Expected: FAIL with `ImportError: cannot import name '_workflow_clusters'`.

- [ ] **Step 3: Add the `_workflow_clusters` helper**

Add to `sequence_constructor.py` (module level, near `_build_index`):

```python
def _workflow_clusters(cooccur: Dict[str, Set[str]]) -> Dict[str, int]:
    """Connected components of the co-occurrence graph → a workflow_id per API.

    APIs that appear together in the library's real usage paths form one
    coherent workflow; A-2b keeps each workflow INTACT when partitioning
    densifier candidates across sibling chains (so it never splits a coherent
    workflow into two incoherent halves). Deterministic (sorted traversal).
    """
    seen: Dict[str, int] = {}
    wid = 0
    for node in sorted(cooccur.keys()):
        if node in seen:
            continue
        stack = [node]
        seen[node] = wid
        while stack:
            cur = stack.pop()
            for nb in sorted(cooccur.get(cur, ())):
                if nb not in seen:
                    seen[nb] = wid
                    stack.append(nb)
        wid += 1
    return seen
```

- [ ] **Step 4: Run the helper test**

Run: `pytest tests/test_p2_densify_workflow.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Use workflow clusters in the rotation + `_rank` (gated)**

In `_densify`, extend the signature to accept the map:

```python
def _densify(core_seq: List[str], opened: Set[str], idx: _Index,
             max_extra: int, repeat: bool,
             cooccur: Optional[Dict[str, Set[str]]] = None,
             sibling_rank: int = 0,
             workflow_of: Optional[Dict[str, int]] = None) -> List[str]:
```

In the nested `_rank`, add a workflow-affinity term **after `sat`** (so lifecycle-satisfiability still wins). Replace:

```python
    def _rank(sem: APISemantics):
        # handle-satisfiable extenders first (valid), then co-occurrence holes
        sat = 0 if set(getattr(sem, "requires", ()) or ()) <= opened else 1
        if sem.role is APIRole.MUTATOR:
            return (sat, 0, sem.name)
        is_getter = bool(getattr(sem, "requires", ())) and not getattr(sem, "produces", ())
        return (sat, 2 if is_getter else 1, sem.name)   # consumer(1) then getter(2)
```

with:

```python
    def _rank(sem: APISemantics):
        # handle-satisfiable extenders first (valid), then co-occurrence holes.
        # A-2b: workflow_affinity is inserted AFTER sat (lifecycle wins) and
        # BEFORE role so candidates from the same workflow cluster group together
        # and rotate as whole units.
        sat = 0 if set(getattr(sem, "requires", ()) or ()) <= opened else 1
        waff = (workflow_of or {}).get(sem.name, -1)
        if sem.role is APIRole.MUTATOR:
            return (sat, waff, 0, sem.name)
        is_getter = bool(getattr(sem, "requires", ())) and not getattr(sem, "produces", ())
        return (sat, waff, 2 if is_getter else 1, sem.name)
```

(Grouping by `waff` in the sort means the A-2a rotation slices across whole
workflow clusters; no further change to the rotation math is needed because
same-workflow candidates are now contiguous in `_ranked`.)

- [ ] **Step 6: Build and thread `workflow_of` at the call site (gated)**

Just after the `_cooccur` map is built in `construct_sequences` (the block that starts `_cooccur: Dict[str, Set[str]] = {}`), add:

```python
    # A-2b (LOGICFUZZ_DEDUP_WORKFLOW_PARTITION): group densifier candidates by
    # co-occurrence workflow so sibling partitioning keeps each coherent
    # workflow intact instead of splitting it. Empty/off ⇒ no effect.
    _workflow_of: Dict[str, int] = {}
    if (_cooccur and os.environ.get("LOGICFUZZ_DEDUP_WORKFLOW_PARTITION", "")
            .strip().lower() in ("1", "true", "yes", "on")):
        _workflow_of = _workflow_clusters(_cooccur)
```

Then change the densify call (from Task 6) to pass it:

```python
                core = _densify(core, opened, idx, _dense_max_extra,
                                _dense_repeat, _cooccur, sibling_rank=_rank_i,
                                workflow_of=_workflow_of)
```

- [ ] **Step 7: Run full suite**

Run: `pytest tests/ -q`
Expected: no regressions (both gates off ⇒ identical output; `workflow_of` empty ⇒ `waff` is a constant -1, sort order unchanged from Task 6's gate-off path).

- [ ] **Step 8: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py tests/test_p2_densify_workflow.py
git commit -m "feat(dedup): A-2b workflow-cluster densifier partition (LOGICFUZZ_DEDUP_WORKFLOW_PARTITION)"
```

---

### Task 8: Wire `idiom_chains` into construction (best-effort enrichment)

**Files:**
- Modify: `src/context/data_context.py` — the `construct_sequences(...)` call (Step 5h) currently omits `idiom_chains=`.
- Test: `tests/test_p2_construct_idiom_chains.py` (create) — proves `construct_sequences` consumes `idiom_chains` into co-occurrence.

- [ ] **Step 1: Write the failing test (behavior already supported by the param; this pins it)**

```python
# tests/test_p2_construct_idiom_chains.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import construct_sequences


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _lib():
    return [
        _api("h_create", [], ret="H *"),
        _api("h_cfg", [_arg("H *"), _arg("int", name="mode")], ret="int"),
        _api("h_use", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ]


def test_idiom_chains_accepted_and_seeded(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DENSE_CONSTRUCT", "1")
    m = reconcile(_lib())
    res = construct_sequences(m, idiom_chains=[["h_create", "h_cfg", "h_use", "h_free"]])
    # the idiom chain is seeded verbatim as one of the sequences.
    assert any(s == ["h_create", "h_cfg", "h_use", "h_free"] for s in res.sequences)
```

- [ ] **Step 2: Run test to verify it passes already (param exists) or fails on env**

Run: `pytest tests/test_p2_construct_idiom_chains.py -v`
Expected: PASS (the `idiom_chains` param is already wired in `construct_sequences`; this test pins that contract before we rely on it at the call site).

- [ ] **Step 3: Pass idiom chains at the data_context call site (best-effort)**

Find this exact current code (Step 5h):

```python
                _cres = construct_sequences(
                    api_semantic_model,
                    project_apis=project_apis,
                    lifecycle_pairs=_lc_pairs or None,
                    gap_apis=_gap_apis or None,
                    accepting_paths=_accept,
                    graft_fn=_graft,
                    construct_mode=_cmode)
```

Replace with (load cached idioms if present; safe no-op on first run / missing file):

```python
                # A-2b enrichment: feed the Phase-B distiller's semantic workflow
                # chains (state/idioms.json, from a prior run) into co-occurrence
                # so workflow partitioning has richer clusters. Best-effort:
                # absent file ⇒ None ⇒ accepting_paths remain the sole source.
                _idiom_chains = None
                try:
                    _idioms_path = Path(results_dir) / "state" / "idioms.json"
                    if _idioms_path.exists():
                        with open(_idioms_path) as _f:
                            _idoc = json.load(_f)
                        _idiom_chains = [c for c in _idoc.get("chains", [])
                                         if isinstance(c, list) and c] or None
                except Exception:
                    _idiom_chains = None
                _cres = construct_sequences(
                    api_semantic_model,
                    project_apis=project_apis,
                    lifecycle_pairs=_lc_pairs or None,
                    gap_apis=_gap_apis or None,
                    accepting_paths=_accept,
                    idiom_chains=_idiom_chains,
                    graft_fn=_graft,
                    construct_mode=_cmode)
```

> Note: confirm `results_dir` and `Path`/`json` are in scope at this point (they are used elsewhere in `prepare`). If the local variable holding the results directory has a different name here, run `grep -n "results_dir" src/context/data_context.py` and use the in-scope name; if `idioms.json` uses a different key than `chains`, run `grep -rn "idioms.json" src/knowledge/idiom_distiller.py` and match the real key.

- [ ] **Step 4: Verify import + suite**

Run: `python -c "import src.context.data_context"`
Expected: no error.
Run: `pytest tests/ -q`
Expected: no regressions.

- [ ] **Step 5: Commit**

```bash
git add src/context/data_context.py tests/test_p2_construct_idiom_chains.py
git commit -m "feat(dedup): wire idiom_chains into construction (A-2b enrichment)"
```

---

### Task 9: B-2 — pairwise dissimilarity gate + Stage-B VALID guard (gated)

**Files:**
- Create: `liberator_adapter/analysis/driver_dedup.py`
- Test: `tests/test_p2_driver_dedup.py` (create)
- Modify: `src/context/data_context.py` — apply the gate to `skeleton_drivers` immediately AFTER `annotate_skeletons(...)` (so `value_intents` are present for the fingerprint).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_driver_dedup.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.driver_dedup import pairwise_dedup_skeletons


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _model():
    return reconcile([
        _api("h_create", [], ret="H *"),
        _api("h_a", [_arg("H *")], ret="int"),
        _api("h_b", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ])


def test_near_twins_are_dropped():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},  # twin
        {"api_sequence": ["h_create", "h_b", "h_free"], "value_intents": []},  # distinct-ish
    ]
    kept = pairwise_dedup_skeletons(sks, m, tau=0.99)
    seqs = [k["api_sequence"] for k in kept]
    assert seqs.count(["h_create", "h_a", "h_free"]) == 1   # exact twin removed


def test_value_domain_distinct_twins_survive():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a"], "value_intents":
            [{"api": "h_a", "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE gamma"}]}]},
        {"api_sequence": ["h_create", "h_a"], "value_intents":
            [{"api": "h_a", "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE enum"}]}]},
    ]
    kept = pairwise_dedup_skeletons(sks, m, tau=0.5)
    assert len(kept) == 2          # different value domains → both kept


def test_valid_guard_protects_valid_seq():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},  # twin, but VALID
    ]
    valid = {("h_create", "h_a", "h_free")}
    kept = pairwise_dedup_skeletons(sks, m, tau=0.5, valid_seqs=valid)
    assert len(kept) == 2          # VALID twin not dropped
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p2_driver_dedup.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# liberator_adapter/analysis/driver_dedup.py
"""B-2 / B-3: pairwise dissimilarity gate + subset elimination over the
doc-aware structural fingerprint (Layer C). Deterministic; the only doc/LLM
touch is CONSUMING an existing Stage-B VALID verdict (no new LLM calls).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from liberator_adapter.analysis.driver_fingerprint import (
    sequence_fingerprint, fingerprint_similarity, fingerprint_is_subset)


def _is_valid(sk: Dict[str, Any], valid_seqs: Optional[Set[Tuple[str, ...]]]) -> bool:
    if not valid_seqs:
        return False
    return tuple(sk.get("api_sequence") or []) in valid_seqs


def pairwise_dedup_skeletons(
        skeletons: Sequence[Dict[str, Any]],
        model,
        tau: float = 0.8,
        valid_seqs: Optional[Set[Tuple[str, ...]]] = None) -> List[Dict[str, Any]]:
    """Drop a skeleton whose fingerprint similarity to an already-kept skeleton
    exceeds ``tau`` — UNLESS it is Stage-B VALID-protected. Order-preserving.
    """
    kept: List[Dict[str, Any]] = []
    kept_fps = []
    for sk in skeletons:
        fp = sequence_fingerprint(sk.get("api_sequence") or [], model,
                                  sk.get("value_intents"))
        redundant = any(fingerprint_similarity(fp, kfp) > tau for kfp in kept_fps)
        if redundant and not _is_valid(sk, valid_seqs):
            continue
        kept.append(sk)
        kept_fps.append(fp)
    return kept


def subset_eliminate_skeletons(
        skeletons: Sequence[Dict[str, Any]],
        model) -> List[Dict[str, Any]]:
    """Drop any skeleton whose fingerprint is a strict same-value-domain subset
    of another's (B-3). Order-preserving; keeps the superset.
    """
    fps = [sequence_fingerprint(sk.get("api_sequence") or [], model,
                                sk.get("value_intents")) for sk in skeletons]
    drop = set()
    for i, fi in enumerate(fps):
        for j, fj in enumerate(fps):
            if i != j and fingerprint_is_subset(fi, fj):
                drop.add(i)
                break
    return [sk for k, sk in enumerate(skeletons) if k not in drop]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_p2_driver_dedup.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Apply the B-2 gate in data_context after annotate_skeletons**

Find this exact current code (Step 10b):

```python
                _n_annot = annotate_skeletons(
                    skeleton_drivers, api_semantic_model, _const_vocab,
                    _svf_index, _ret_contracts)
```

Insert immediately AFTER it:

```python
                # B-2 (LOGICFUZZ_PAIRWISE_DEDUP): drop near-twin skeletons by
                # fingerprint similarity over the FULL Layer-C fingerprint (incl.
                # value-domain), so value-distinct variants survive. Optional
                # Stage-B VALID guard (LOGICFUZZ_DEDUP_SEMANTIC_GUARD) protects
                # semantically-VALID sequences from being dropped.
                if (os.environ.get("LOGICFUZZ_PAIRWISE_DEDUP", "").strip().lower()
                        in ("1", "true", "yes", "on")) and skeleton_drivers:
                    from liberator_adapter.analysis.driver_dedup import (
                        pairwise_dedup_skeletons)
                    try:
                        _tau = float(os.environ.get("LOGICFUZZ_PAIRWISE_TAU", "0.8"))
                    except ValueError:
                        _tau = 0.8
                    _valid_seqs = None
                    if (os.environ.get("LOGICFUZZ_DEDUP_SEMANTIC_GUARD", "")
                            .strip().lower() in ("1", "true", "yes", "on")):
                        _valid_seqs = {
                            tuple(s.get("sequence") or [])
                            for s in (self.sequence_semantics or [])
                            if str(s.get("semantic_status", "")).upper() == "VALID"}
                    _before = len(skeleton_drivers)
                    skeleton_drivers = pairwise_dedup_skeletons(
                        skeleton_drivers, api_semantic_model, _tau, _valid_seqs)
                    log.info("   🧬 pairwise dedup: %d → %d (tau=%.2f)",
                             _before, len(skeleton_drivers), _tau)
                    api_sequences = [s.get('api_sequence', [])
                                     for s in skeleton_drivers]
```

> Note: confirm the field name holding Stage-B verdicts. Run `grep -n "sequence_semantics" src/context/data_context.py` and `grep -n "semantic_status" src/knowledge/comprehender.py`; if the attribute on the context object differs (e.g. a local var rather than `self.sequence_semantics`), use the in-scope name. The guard is gated, so if the field is empty/absent the gate simply skips VALID-protection.

- [ ] **Step 6: Verify import + suite**

Run: `python -c "import src.context.data_context"`
Expected: no error.
Run: `pytest tests/ -q`
Expected: no regressions (gate off ⇒ unchanged).

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/analysis/driver_dedup.py tests/test_p2_driver_dedup.py src/context/data_context.py
git commit -m "feat(dedup): B-2 pairwise dissimilarity gate + Stage-B VALID guard"
```

---

## Phase 3 — B-3 subset elimination + A-1/A-1b/A-3

### Task 10: B-3 — subset elimination on the shipped pool (gated)

**Files:**
- Modify: `src/context/data_context.py` — apply `subset_eliminate_skeletons` in the SAME post-`annotate_skeletons` region, BEFORE the B-2 block (subset elim is the cheaper pre-filter).
- Test: covered by Task 9's `subset_eliminate_skeletons` unit test; add one more case below.

- [ ] **Step 1: Add a focused unit test for the subset eliminator**

Append to `tests/test_p2_driver_dedup.py`:

```python
def test_subset_eliminate_drops_strict_subset():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_free"], "value_intents": []},  # strict subset
    ]
    from liberator_adapter.analysis.driver_dedup import subset_eliminate_skeletons
    kept = subset_eliminate_skeletons(sks, m)
    assert [k["api_sequence"] for k in kept] == [["h_create", "h_a", "h_free"]]
```

- [ ] **Step 2: Run test to verify it passes (function already exists from Task 9)**

Run: `pytest tests/test_p2_driver_dedup.py::test_subset_eliminate_drops_strict_subset -v`
Expected: PASS

- [ ] **Step 3: Apply the B-3 gate in data_context (before the B-2 block)**

Find the B-2 block inserted in Task 9 (it starts with the comment `# B-2 (LOGICFUZZ_PAIRWISE_DEDUP): ...`). Insert immediately BEFORE that comment:

```python
                # B-3 (LOGICFUZZ_SUBSET_ELIM): drop skeletons whose fingerprint is
                # a strict same-value-domain subset of another's. Runs BEFORE B-2
                # so it removes only true subsets (never near-twins → that is B-2's
                # job under tau).
                if (os.environ.get("LOGICFUZZ_SUBSET_ELIM", "").strip().lower()
                        in ("1", "true", "yes", "on")) and skeleton_drivers:
                    from liberator_adapter.analysis.driver_dedup import (
                        subset_eliminate_skeletons)
                    _before_se = len(skeleton_drivers)
                    skeleton_drivers = subset_eliminate_skeletons(
                        skeleton_drivers, api_semantic_model)
                    log.info("   🧬 subset elim: %d → %d",
                             _before_se, len(skeleton_drivers))
                    api_sequences = [s.get('api_sequence', [])
                                     for s in skeleton_drivers]
```

- [ ] **Step 4: Verify import + suite**

Run: `python -c "import src.context.data_context"`
Expected: no error.
Run: `pytest tests/ -q`
Expected: no regressions.

- [ ] **Step 5: Commit**

```bash
git add src/context/data_context.py tests/test_p2_driver_dedup.py
git commit -m "feat(dedup): B-3 subset elimination on shipped pool (LOGICFUZZ_SUBSET_ELIM)"
```

---

### Task 11: A-1/A-1b — deterministic producer/root diversification (gated)

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` — `_build_prefix(...)` producer choice (the `producer = sorted(cands, key=_recovered_key if from_recovery else _creator_key)[0]` line). A-1 needs a per-handle sibling offset; thread a `producer_rank` map.
- Test: `tests/test_p3_producer_diversify.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p3_producer_diversify.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import construct_sequences


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _multi_producer_lib():
    """Two creators of H *, several consumers, so >1 chain shares the handle."""
    return [
        _api("h_make_a", [], ret="H *"),
        _api("h_make_b", [], ret="H *"),
        _api("h_use1", [_arg("H *")], ret="int"),
        _api("h_use2", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ]


def test_producers_rotate_across_siblings_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", "1")
    res = construct_sequences(reconcile(_multi_producer_lib()))
    used = set()
    for s in res.sequences:
        if "h_make_a" in s:
            used.add("h_make_a")
        if "h_make_b" in s:
            used.add("h_make_b")
    assert used == {"h_make_a", "h_make_b"}     # both producers exercised


def test_gate_off_uses_single_deterministic_producer(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", raising=False)
    res = construct_sequences(reconcile(_multi_producer_lib()))
    used = set()
    for s in res.sequences:
        used |= ({"h_make_a"} if "h_make_a" in s else set())
        used |= ({"h_make_b"} if "h_make_b" in s else set())
    assert used == {"h_make_a"}                 # deterministic single pick (sorted)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p3_producer_diversify.py -v`
Expected: FAIL on `test_producers_rotate_across_siblings_when_gated` (only one producer used today).

- [ ] **Step 3: Add gated producer rotation in `_build_prefix`**

`_build_prefix` builds a fresh prefix per target but has no cross-target state. Add an optional `producer_rank` dict param threaded from `construct_sequences`, and rotate the sorted `cands` by it when the gate is on.

Change the `_build_prefix` signature from:

```python
def _build_prefix(
    target: APISemantics,
    idx: _Index,
    max_depth: int,
) -> Tuple[List[str], Set[str]]:
```

to:

```python
def _build_prefix(
    target: APISemantics,
    idx: _Index,
    max_depth: int,
    producer_rank: Optional[Dict[str, int]] = None,
) -> Tuple[List[str], Set[str]]:
```

Then find the producer selection line:

```python
        producer = sorted(
            cands, key=_recovered_key if from_recovery else _creator_key)[0]
```

Replace with:

```python
        _sorted_cands = sorted(
            cands, key=_recovered_key if from_recovery else _creator_key)
        # A-1/A-1b (LOGICFUZZ_DIVERSIFY_PRODUCERS): when a handle type has >1
        # creator, rotate which one each sibling chain uses (deterministic,
        # per-handle round-robin) so the portfolio exercises the full producer
        # set instead of always the single sorted-first one. A-1b: confidence
        # ordering already lives in _creator_key/_recovered_key (role-authored).
        if (producer_rank is not None and len(_sorted_cands) > 1
                and os.environ.get("LOGICFUZZ_DIVERSIFY_PRODUCERS", "")
                .strip().lower() in ("1", "true", "yes", "on")):
            _r = producer_rank.get(t, 0)
            producer_rank[t] = _r + 1
            producer = _sorted_cands[_r % len(_sorted_cands)]
        else:
            producer = _sorted_cands[0]
```

- [ ] **Step 4: Thread `producer_rank` from the call sites**

In `construct_sequences`, create one shared dict and pass it to BOTH `_build_prefix` calls (the per-target loop and the create→destroy loop). Add near the `_sibling_rank` dict (from Task 6) initialization:

```python
        _producer_rank: Dict[str, int] = {}
```

Change the per-target call from:

```python
            prefix, opened = _build_prefix(target, idx, max_prefix_depth)
```

to:

```python
            prefix, opened = _build_prefix(target, idx, max_prefix_depth,
                                           producer_rank=_producer_rank)
```

And the create→destroy-loop call from:

```python
            prefix, opened = _build_prefix(creator, idx, max_prefix_depth)
```

to:

```python
            prefix, opened = _build_prefix(creator, idx, max_prefix_depth,
                                           producer_rank=_producer_rank)
```

- [ ] **Step 5: Run the test + full suite**

Run: `pytest tests/test_p3_producer_diversify.py -v`
Expected: PASS (2 passed)
Run: `pytest tests/ -q`
Expected: no regressions (gate off ⇒ `_sorted_cands[0]`, identical to today).

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py tests/test_p3_producer_diversify.py
git commit -m "feat(dedup): A-1/A-1b deterministic producer rotation (LOGICFUZZ_DIVERSIFY_PRODUCERS)"
```

---

### Task 12: A-3 — destroyer rotation across siblings (gated, same flag)

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` — `_closing_destroyers(...)` + its two call sites.
- Test: `tests/test_p3_destroyer_diversify.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p3_destroyer_diversify.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _two_destroyer_lib():
    return [
        _api("h_create", [], ret="H *"),
        _api("h_free_x", [_arg("H *")]),
        _api("h_free_y", [_arg("H *")]),
    ]


def test_destroyers_rotate_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", "1")
    idx = SC._build_index(reconcile(_two_destroyer_lib()))
    d0 = SC._closing_destroyers({"H *"}, idx, destroyer_rank={"H *": 0})
    d1 = SC._closing_destroyers({"H *"}, idx, destroyer_rank={"H *": 1})
    assert d0 != d1
    assert set(d0 + d1) == {"h_free_x", "h_free_y"}


def test_gate_off_picks_first_sorted(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", raising=False)
    idx = SC._build_index(reconcile(_two_destroyer_lib()))
    assert SC._closing_destroyers({"H *"}, idx) == ["h_free_x"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_p3_destroyer_diversify.py -v`
Expected: FAIL — `_closing_destroyers() got an unexpected keyword argument 'destroyer_rank'`.

- [ ] **Step 3: Add gated destroyer rotation**

Change `_closing_destroyers` from:

```python
def _closing_destroyers(opened: Set[str], idx: _Index) -> List[str]:
    """One destroyer per opened handle type (deterministic pick)."""
    out: List[str] = []
    for t in sorted(opened):
        dz = idx.destroyers.get(t)
        if dz:
            name = sorted(dz, key=lambda s: s.name)[0].name
            if name not in out:
                out.append(name)
    return out
```

to:

```python
def _closing_destroyers(opened: Set[str], idx: _Index,
                        destroyer_rank: Optional[Dict[str, int]] = None) -> List[str]:
    """One destroyer per opened handle type.

    A-3 (LOGICFUZZ_DIVERSIFY_PRODUCERS): when a handle has >1 destroyer, rotate
    which one each sibling chain closes with (deterministic per-handle
    round-robin). Gate-off ⇒ the sorted-first destroyer (unchanged).
    """
    _rotate = (destroyer_rank is not None
               and os.environ.get("LOGICFUZZ_DIVERSIFY_PRODUCERS", "")
               .strip().lower() in ("1", "true", "yes", "on"))
    out: List[str] = []
    for t in sorted(opened):
        dz = idx.destroyers.get(t)
        if dz:
            names = [s.name for s in sorted(dz, key=lambda s: s.name)]
            if _rotate and len(names) > 1:
                _r = destroyer_rank.get(t, 0)
                destroyer_rank[t] = _r + 1
                name = names[_r % len(names)]
            else:
                name = names[0]
            if name not in out:
                out.append(name)
    return out
```

- [ ] **Step 4: Thread `destroyer_rank` from the call sites**

In `construct_sequences`, add near `_producer_rank`:

```python
        _destroyer_rank: Dict[str, int] = {}
```

Change the per-target close from:

```python
            seq = core + _closing_destroyers(opened, idx)
```

to:

```python
            seq = core + _closing_destroyers(opened, idx,
                                             destroyer_rank=_destroyer_rank)
```

And the create→destroy-loop close from:

```python
            _add(_core + _closing_destroyers(opened, idx))
```

to:

```python
            _add(_core + _closing_destroyers(opened, idx,
                                             destroyer_rank=_destroyer_rank))
```

- [ ] **Step 5: Run the test + full suite**

Run: `pytest tests/test_p3_destroyer_diversify.py -v`
Expected: PASS (2 passed)
Run: `pytest tests/ -q`
Expected: no regressions.

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py tests/test_p3_destroyer_diversify.py
git commit -m "feat(dedup): A-3 destroyer rotation across siblings"
```

---

## Phase 4 — D-1 dynamic edge-set selection (DEFERRED to a follow-up plan)

D-1 (edge-set marginal selection, `LOGICFUZZ_EDGE_MARGINAL`) is intentionally
**out of scope for this plan**. It requires a feedback edge from the 15s
preflight (`run_single_fuzz._edges_weights_for`) back into pre-merge selection
that does not exist today (related to the unbuilt F6 CEGAR loop). Build it as a
separate plan **after** the static layer's A/B (Layer E telemetry on lcms) shows
the static decoupling earns its keep. The spec's acceptance criteria for D-1 are
recorded there.

---

## Documentation Task: update CLAUDE.md gate reference

**Files:**
- Modify: `CLAUDE.md` — the `LOGICFUZZ_*` knob section.

- [ ] **Step 1: Add the new gates to the knob list**

Add concise entries (matching the existing style) for: `LOGICFUZZ_MARGINAL_DEPTH`,
`LOGICFUZZ_DENSE_PARTITION`, `LOGICFUZZ_DEDUP_WORKFLOW_PARTITION`,
`LOGICFUZZ_PAIRWISE_DEDUP`/`_TAU`, `LOGICFUZZ_DEDUP_SEMANTIC_GUARD`,
`LOGICFUZZ_SUBSET_ELIM`, `LOGICFUZZ_DIVERSIFY_PRODUCERS`. Note each is default-OFF
(A/B pending) and reference `docs/superpowers/specs/2026-06-14-driver-decoupling-dedup-design.md`.
Note `redundancy_telemetry.json` (Layer E) is always-on.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document decoupling/dedup gates in CLAUDE.md"
```

---

## A/B Validation (run after Phase 3; not a code task)

- [ ] Baseline (all gates off): `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/lcms.yaml --extract-only` (or `--generate-drivers`), record `results/lcms*/static_analysis/redundancy_telemetry.json`.
- [ ] Static layer on:
```bash
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_MARGINAL_DEPTH=1 LOGICFUZZ_DENSE_PARTITION=1 \
LOGICFUZZ_DEDUP_WORKFLOW_PARTITION=1 LOGICFUZZ_PAIRWISE_DEDUP=1 \
LOGICFUZZ_SUBSET_ELIM=1 LOGICFUZZ_DIVERSIFY_PRODUCERS=1 \
python3 run_logicfuzz.py -y comparison/lcms.yaml --generate-drivers
```
- [ ] Confirm: lower `mean_pairwise_jaccard`, higher `disjointness` vs baseline.
- [ ] Full merged-coverage A/B (the real metric): run `--merge-drivers` both ways and compare merged-harness branch coverage. Gates graduate to default-on only if merged coverage rises.

---

## Self-Review (completed by plan author)

**Spec coverage:** B-1 (Task 2), B-2 (Task 9), B-3 (Task 10), Layer C (Task 5), A-1/A-1b (Task 11), A-2a (Task 6), A-2b + idiom wiring (Tasks 7-8), A-3 (Task 12), Layer E telemetry (Tasks 3-4), Stage-B VALID guard (Task 9), gate documentation (Doc task), D-1 explicitly deferred (Phase 4). All spec gates present in the gate table are implemented or deferred-with-reason.

**Placeholder scan:** No TBD/TODO; every code step shows full code. Two steps carry explicit `grep` verification notes for in-scope variable names in the 3900-line `data_context.py` (`results_dir`, `self.sequence_semantics`, the `idioms.json` key) — these are verification instructions, not placeholders, because those identifiers cannot be confirmed without the engineer running the grep at edit time.

**Type/name consistency:** `select_marginal(items, seq_of, budget, covered)` (Task 1) is called with matching args in Task 2. `sequence_fingerprint` / `fingerprint_similarity` / `fingerprint_is_subset` (Task 5) are imported and used identically in Tasks 9-10. `pairwise_dedup_skeletons` / `subset_eliminate_skeletons` (Task 9) used with matching signatures in Tasks 9-10. `_densify` gains `sibling_rank` (Task 6) then `workflow_of` (Task 7) — call site updated in the same tasks. `_build_prefix` gains `producer_rank` (Task 11), `_closing_destroyers` gains `destroyer_rank` (Task 12) — both call sites updated. `portfolio_redundancy` (Task 3) consumed in Task 4.
