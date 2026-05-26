"""Pin the APISemanticModel reconciler (redesign G1).

The model fuses three evidence sources into one per-API record and applies
the §2.2 authority rule: **doc/naming wins for role, IR wins for mechanism**.
These tests pin that rule and its falsifiable ship test
(``cmsFreeToneCurveTriple`` → DESTROYER), plus the structured doc-signal
parser and the comprehender role-authority routing.

Design intent — see ``docs/generation_stage_redesign.md`` §2 and the module
docstring of ``liberator_adapter/analysis/api_semantic_model.py``.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APIRole,
    ArgRole,
    APISemanticModel,
    reconcile,
)


# --------------------------------------------------------------------------- helpers

def _api(name, args=None, ret="void"):
    """Build a project-API dict matching the Liberator extract schema."""
    return {
        "function_name": name,
        "arguments": args or [],
        "return_type": ret,
        "is_vararg": False,
        "namespace": [],
    }


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


# --------------------------------------------------------------------------- role rule

def test_naming_destroyer_overrides_ir_creator():
    """The canonical inversion: a ``*_free`` whose ``T**`` arg reads as an IR
    out-pointer producer must reconcile to DESTROYER, with the IR CREATOR claim
    recorded as the loser."""
    api = _api("lib_thing_free", [_arg("Thing * *", const=False)])
    model = reconcile([api])
    sem = model.get("lib_thing_free")

    assert sem.role is APIRole.DESTROYER
    # Mechanism direction reassigned by the reconciled role: the IR "produces"
    # set is re-bucketed as ``destroys``.
    assert sem.produces == frozenset()
    assert sem.destroys == frozenset({"thing*"})

    role_ev = [e for e in sem.evidence if e.field == "role"]
    won = [e for e in role_ev if e.won]
    losers = [e for e in role_ev if not e.won]
    assert len(won) == 1 and won[0].value == "DESTROYER"
    assert won[0].source == "NAMING"
    assert any(l.source == "IR" and l.value == "CREATOR" for l in losers)


def test_creator_from_naming_and_ir_agree():
    api = _api("lib_thing_create", [], ret="Thing *")
    sem = reconcile([api]).get("lib_thing_create")
    assert sem.role is APIRole.CREATOR
    assert sem.produces == frozenset({"thing*"})
    assert sem.destroys == frozenset()


def test_weak_naming_does_not_override_ir():
    """Weak verb stems (``parse``) only fill IR silence; an IR CONSUMER role
    is retained and the weak hint is logged as a loser."""
    api = _api("lib_parse_thing", [_arg("Thing *")], ret="int")
    sem = reconcile([api]).get("lib_parse_thing")
    assert sem.role is APIRole.CONSUMER
    role_ev = [e for e in sem.evidence if e.field == "role"]
    assert any(e.won and e.source == "IR" for e in role_ev)
    assert any((not e.won) and e.source == "NAMING" and e.value == "CREATOR"
               for e in role_ev)


def test_doc_brief_overrides_ir():
    """An explicit @brief verb beats an IR producer signal."""
    api = _api("lib_thing_obtain", [_arg("Thing * *")])  # IR → CREATOR
    doc = {"lib_thing_obtain": {"brief": "Frees the thing and its children."}}
    sem = reconcile([api], doc_signals=doc).get("lib_thing_obtain")
    assert sem.role is APIRole.DESTROYER
    won = [e for e in sem.evidence if e.field == "role" and e.won][0]
    assert won.source == "DOC"


def test_unknown_when_no_signal():
    api = _api("lib_opaque", [_arg("int")], ret="int")
    sem = reconcile([api]).get("lib_opaque")
    assert sem.role is APIRole.UNKNOWN


def test_usage_bumps_confidence_not_role():
    api = _api("lib_thing_create", [], ret="Thing *")
    base = reconcile([api]).get("lib_thing_create")
    bumped = reconcile(
        [api], accepting_paths=[["lib_thing_create", "x"], ["y", "lib_thing_create"]]
    ).get("lib_thing_create")
    assert bumped.role is base.role is APIRole.CREATOR
    assert bumped.role_confidence > base.role_confidence
    assert any(e.source == "USAGE" for e in bumped.evidence)


# --------------------------------------------------------------------------- arg rule

def test_arg_buffer_length_pairing():
    api = _api("lib_consume",
               [_arg("const uint8_t *", const=True, name="data"),
                _arg("size_t", name="len")])
    sem = reconcile([api]).get("lib_consume")
    assert sem.args[0].role is ArgRole.INPUT_BUFFER
    assert sem.args[1].role is ArgRole.LENGTH
    assert sem.args[1].pairs_with == 0


def test_doc_param_role_overrides_type():
    api = _api("lib_emit", [_arg("char *", const=False, name="out")])
    doc = {"lib_emit": {"params": [{"index": 0, "name": "out", "role": "OUTPUT"}]}}
    sem = reconcile([api], doc_signals=doc).get("lib_emit")
    assert sem.args[0].role is ArgRole.OUTPUT
    assert any(e.field == "arg0" and e.won and e.source == "DOC"
               for e in sem.evidence)


# --------------------------------------------------------------------------- persistence / determinism

def test_json_roundtrip():
    apis = [_api("lib_thing_create", [], ret="Thing *"),
            _api("lib_thing_free", [_arg("Thing *")])]
    model = reconcile(apis, project="demo")
    restored = APISemanticModel.from_dict(model.to_dict())
    assert restored.to_dict() == model.to_dict()
    assert restored.role_of("lib_thing_free") is APIRole.DESTROYER


def test_determinism_repeated_reconcile():
    apis = [_api("lib_a_create", [], ret="A *"),
            _api("lib_a_free", [_arg("A *")]),
            _api("lib_a_step", [_arg("A *")], ret="int")]
    a = reconcile(apis, project="demo").to_dict()
    b = reconcile(apis, project="demo").to_dict()
    assert a == b  # deterministic-only; no LLM, no randomness


def test_save_and_load(tmp_path):
    model = reconcile([_api("lib_x_free", [_arg("X *")])], project="p")
    path = tmp_path / "state" / "api_semantic_model.json"
    model.save(path)
    assert path.is_file()
    loaded = APISemanticModel.load(path)
    assert loaded is not None
    assert loaded.role_of("lib_x_free") is APIRole.DESTROYER


# --------------------------------------------------------------------------- doc-signal parser

def test_structured_doxygen_parser():
    from src.knowledge.project_docs import _parse_doxygen_structured
    raw = (
        "/**\n"
        " * @brief Frees a tone curve allocated by the build API.\n"
        " * @param Curve the tone curve to release\n"
        " * @param size length of the data buffer\n"
        " * @return void\n"
        " */"
    )
    sig = _parse_doxygen_structured(raw)
    assert "frees" in sig["brief"].lower()
    params = sig["params"]
    assert params[0]["index"] == 0 and params[0]["name"] == "Curve"
    # "length of the data buffer" must read as LENGTH, not INPUT_BUFFER.
    assert params[1]["role"] == "LENGTH"


# --------------------------------------------------------------------------- comprehender routing

def test_comprehender_role_authority_overrides_condition_info():
    from src.knowledge.comprehender import _deterministic_usage
    api = {"function_name": "foo"}
    # ConditionManager says SOURCE (would produce "fresh data / handle"), but
    # the model says DESTROYER — the model must win.
    text = _deterministic_usage(
        api, condition_info={"sources": ["foo"]}, lifecycle_analysis={},
        api_roles={"foo": "DESTROYER"})
    assert text is not None and "releases ownership" in text


def test_comprehender_falls_back_to_condition_info():
    from src.knowledge.comprehender import _deterministic_usage
    api = {"function_name": "foo"}
    text = _deterministic_usage(
        api, condition_info={"sources": ["foo"]}, lifecycle_analysis={},
        api_roles=None)
    assert text is not None and "Produces fresh data" in text


# --------------------------------------------------------------------------- real-data ship test

_LCMS_APIS = Path(__file__).resolve().parent.parent / \
    "results/lcms/static_analysis/project_apis.json"


@pytest.mark.skipif(not _LCMS_APIS.is_file(),
                    reason="lcms static-analysis cache not present")
def test_lcms_ship_test_free_tonecurve_triple():
    """G1 ship test (redesign §6): on real lcms data,
    ``cmsFreeToneCurveTriple`` reconciles to DESTROYER and the evidence log
    shows doc/naming beating the IR CREATOR mislabel."""
    apis = [a for a in json.load(open(_LCMS_APIS))["apis"] if isinstance(a, dict)]
    model = reconcile(apis, project="lcms")
    sem = model.get("cmsFreeToneCurveTriple")
    assert sem is not None
    assert sem.role is APIRole.DESTROYER
    role_ev = [e for e in sem.evidence if e.field == "role"]
    won = [e for e in role_ev if e.won][0]
    assert won.value == "DESTROYER" and won.source in ("NAMING", "DOC")
    assert any(l.source == "IR" and l.value == "CREATOR"
               for l in role_ev if not l.won)
