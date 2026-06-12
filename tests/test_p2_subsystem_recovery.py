"""#4 — subsystem-aware opaque-handle recovery.

A generic opaque handle (cmsHANDLE = typedef void*) shared by several subsystems
leaves its CREATORs (cmsDictAlloc, cmsIT8Alloc) with produces=[] and its consumers
(cmsDictDup, cmsIT8SetDataRowCol require "cmshandle") as NULL-handle orphans
(shallow, edges=0). Recovery must bind producer↔consumer BY SUBSYSTEM
(Dict↔Dict, IT8↔IT8) — strict same-subsystem, never cross (the type
over-connection guardrail); no same-subsystem builder ⇒ leave a hole.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _build_index, _build_prefix, _subsystem_token,
)


def _api(name, role, produces=(), requires=(), destroys=()):
    return APISemantics(
        name=name, role=role, role_confidence=0.9, args=(),
        produces=frozenset(produces), requires=frozenset(requires),
        destroys=frozenset(destroys))


def _model(*apis):
    return APISemanticModel(project="lib", apis={a.name: a for a in apis})


def _generic_handle_model():
    # cmsHANDLE shared by Dict + IT8; cmsGenericConsume has no same-subsystem creator.
    return _model(
        _api("cmsDictAlloc", APIRole.CREATOR),                       # produces=[]
        _api("cmsDictDup", APIRole.CONSUMER, requires={"cmshandle"}),
        _api("cmsDictFree", APIRole.DESTROYER, destroys={"cmshandle"}),
        _api("cmsIT8Alloc", APIRole.CREATOR),
        _api("cmsIT8SetDataRowCol", APIRole.CONSUMER, requires={"cmshandle"}),
        _api("cmsGenericConsume", APIRole.CONSUMER, requires={"cmshandle"}),
    )


def test_subsystem_token():
    assert _subsystem_token("cmsDictAlloc", "cms") == "dict"
    assert _subsystem_token("cmsDictDup", "cms") == "dict"
    assert _subsystem_token("cmsIT8Alloc", "cms") == "it8"
    assert _subsystem_token("cmsIT8SetDataRowCol", "cms") == "it8"   # NOT split


def test_generic_handle_chains_same_subsystem():
    idx = _build_index(_generic_handle_model())
    assert "cmshandle" in idx.recovered_producers          # generic recovery fired
    pre, opened = _build_prefix(idx.by_name["cmsDictDup"], idx, 6)
    assert pre == ["cmsDictAlloc"]                          # same 'dict' subsystem
    assert "cmshandle" in opened


def test_no_cross_subsystem_overconnection():
    idx = _build_index(_generic_handle_model())
    pre, _ = _build_prefix(idx.by_name["cmsDictDup"], idx, 6)
    assert "cmsIT8Alloc" not in pre                         # never cross-subsystem
    pre2, _ = _build_prefix(idx.by_name["cmsIT8SetDataRowCol"], idx, 6)
    assert pre2 == ["cmsIT8Alloc"]                          # IT8 binds only IT8


def test_generic_consumer_no_same_subsystem_stays_hole():
    idx = _build_index(_generic_handle_model())
    pre, opened = _build_prefix(idx.by_name["cmsGenericConsume"], idx, 6)
    assert pre == []                                        # left unmet → hole
    assert "cmshandle" not in opened
