"""Pin the model-driven sequence constructor (redesign G2).

The constructor grows lifecycle-complete creator→…→destroyer chains from the
``APISemanticModel`` instead of random-walking the type graph. These tests pin
its core contract and the viability property the redesign hinges on:
constructed sequences carry **no ordering faults** (use-before-init /
use-after-destroy / double-destroy) — they are valid by construction, so Z3
stops being a lifecycle gate.

See ``docs/generation_stage_redesign.md`` §2.3 / §5 (G2) and
``tools/g2_viability/run.py``.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APIRole, reconcile,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    construct_sequences,
)
from liberator_adapter.analysis.usedef import (  # noqa: E402
    UseDefGraph, Typestate, extract_api_effects,
)

_ORDERING_FAULTS = {"USE_BEFORE_INIT", "USE_AFTER_DESTROY",
                    "DOUBLE_DESTROY", "DESTROY_BEFORE_INIT"}


# --------------------------------------------------------------------------- helpers

def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _managed_lib():
    """create → use(+buffer) → free over one handle type ``Thing *``."""
    return [
        _api("thing_create", [], ret="Thing *"),
        _api("thing_use", [_arg("Thing *"),
                           _arg("const uint8_t *", const=True, name="data"),
                           _arg("size_t", name="len")], ret="int"),
        _api("thing_free", [_arg("Thing *")]),
    ]


def _lifecycle_pairs(model):
    producers = {}
    for s in model.apis.values():
        for t in s.produces:
            producers.setdefault(t, s.name)
    return [(producers[t], s.name)
            for s in model.apis.values() if s.role is APIRole.DESTROYER
            for t in s.destroys if t in producers]


def _ordering_clean(apis, model, sequences):
    ts = Typestate(UseDefGraph(extract_api_effects(
        apis, lifecycle_pairs=_lifecycle_pairs(model) or None)))
    for seq in sequences:
        if {r.kind.name for r in ts.check(seq)} & _ORDERING_FAULTS:
            return False
    return True


def _no_genuine_ordering_faults(apis, model, sequences):
    """Graceful-degradation contract (B): the only ordering fault allowed is a
    USE_BEFORE_INIT on an ORPHAN handle (no in-project producer) — those are
    island APIs intentionally kept as holes for the LLM. Any other fault, or a
    USE_BEFORE_INIT where a producer exists, is genuine."""
    graph = UseDefGraph(extract_api_effects(
        apis, lifecycle_pairs=_lifecycle_pairs(model) or None))
    producers = {h for e in graph.all_effects() for h in e.def_}
    ts = Typestate(graph)
    for seq in sequences:
        for r in ts.check(seq):
            if r.kind.name not in _ORDERING_FAULTS:
                continue
            if r.kind.name == "USE_BEFORE_INIT" and r.handle not in producers:
                continue  # orphan handle → allowed (graceful degradation)
            return False
    return True


# --------------------------------------------------------------------------- core contract

def test_constructs_lifecycle_complete_chain():
    apis = _managed_lib()
    model = reconcile(apis)
    res = construct_sequences(model)
    # The consumer target must yield create → use → free in dependency order.
    chain = next((s for s in res.sequences if "thing_use" in s), None)
    assert chain is not None
    assert chain.index("thing_create") < chain.index("thing_use") < chain.index("thing_free")


def test_ordering_clean_by_construction():
    apis = _managed_lib()
    model = reconcile(apis)
    res = construct_sequences(model)
    assert res.sequences
    assert _ordering_clean(apis, model, res.sequences)


def test_orphan_target_kept_for_graceful_degradation():
    """B graceful degradation: a consumer requiring a handle with NO creator (an
    island API — opaque / void* / no producer) is NOT dropped. The orphan's
    USE_BEFORE_INIT is kept so the unchecked render path leaves Ghost* as a hole
    for the LLM to construct/NULL — that is how we recover the ~302/452 gap APIs
    the baselines reach. The LOGICFUZZ_STRICT_ORDERING kill-switch restores the
    old drop behavior."""
    apis = [
        _api("orphan_use", [_arg("Ghost *")], ret="int"),  # no Ghost creator
        _api("thing_create", [], ret="Thing *"),
    ]
    model = reconcile(apis)
    # Default (graceful): the island API survives as a candidate.
    res = construct_sequences(model, project_apis=apis)
    assert any("orphan_use" in s for s in res.sequences)
    # Strict kill-switch: the old behavior — orphan dropped by the filter.
    os.environ["LOGICFUZZ_STRICT_ORDERING"] = "1"
    try:
        res_strict = construct_sequences(model, project_apis=apis)
        assert all("orphan_use" not in s for s in res_strict.sequences)
    finally:
        os.environ.pop("LOGICFUZZ_STRICT_ORDERING", None)


def test_creator_gets_create_destroy_coverage():
    apis = [_api("thing_create", [], ret="Thing *"),
            _api("thing_free", [_arg("Thing *")])]
    model = reconcile(apis)
    res = construct_sequences(model)
    seq = next((s for s in res.sequences if "thing_create" in s), None)
    assert seq is not None and "thing_free" in seq
    assert seq.index("thing_create") < seq.index("thing_free")


def test_seed_paths_preserved():
    apis = _managed_lib()
    model = reconcile(apis)
    res = construct_sequences(
        model, accepting_paths=[["thing_create", "thing_use", "thing_free"]])
    assert ["thing_create", "thing_use", "thing_free"] in res.sequences
    assert res.metrics["n_seeded_from_automaton"] >= 1


def test_seed_filters_unknown_apis():
    apis = _managed_lib()
    model = reconcile(apis)
    res = construct_sequences(
        model, accepting_paths=[["thing_create", "not_an_api", "thing_free"]])
    # unknown API dropped, rest kept
    assert all("not_an_api" not in s for s in res.sequences)


def test_metrics_shape():
    res = construct_sequences(reconcile(_managed_lib()))
    for k in ("n_sequences", "n_targets_attempted",
              "api_coverage", "handle_types", "avg_length"):
        assert k in res.metrics


# --------------------------------------------------------------------------- viability regression (real data)

_BENCHES = ["lcms", "cjson", "c-ares"]
_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("project", _BENCHES)
def test_viability_constructed_off_one_and_ordering_clean(project):
    """Redesign §6 viability bar pinned as regression: construction yields
    many sequences (lcms off ~1) and 100% are ordering-fault-free."""
    p = _ROOT / f"results/{project}/static_analysis/project_apis.json"
    if not p.is_file():
        pytest.skip(f"{project} static-analysis cache not present")
    apis = [a for a in json.load(open(p))["apis"] if isinstance(a, dict)]
    model = reconcile(apis, project=project)
    # Self-filter through the Typestate oracle (as the live pipeline does).
    res = construct_sequences(
        model, project_apis=apis, lifecycle_pairs=_lifecycle_pairs(model))
    assert len(res.sequences) > 1
    # New contract (B graceful degradation): no GENUINE ordering faults; orphan
    # USE_BEFORE_INIT (island APIs, no producer) is intentionally kept.
    assert _no_genuine_ordering_faults(apis, model, res.sequences)
    # Strict mode still yields fully ordering-clean output, and graceful keeps
    # at least as many sequences (the breadth gain).
    os.environ["LOGICFUZZ_STRICT_ORDERING"] = "1"
    try:
        res_strict = construct_sequences(
            model, project_apis=apis, lifecycle_pairs=_lifecycle_pairs(model))
        assert _ordering_clean(apis, model, res_strict.sequences)
        assert len(res.sequences) >= len(res_strict.sequences)
    finally:
        os.environ.pop("LOGICFUZZ_STRICT_ORDERING", None)
