"""Recover void*-returning *Init/*Alloc/*New initializers as opaque producers
even when the IR role heuristic mis-labeled them CONSUMER/MUTATOR.

The breadth bug (measured on lcms): `cmsCIECAM02Init` returns `cmsHANDLE`
(a `void*`/`i8*` typedef) AND takes a config struct, so the role heuristic saw
`produces=[]` (void* return erased) + `requires` → CONSUMER, NOT CREATOR. It was
therefore excluded from the opaque-builder recovery pool, so every consumer in
its subsystem (`cmsCIECAM02Reverse/Forward/Done`) got a NULL handle → 0 coverage
→ culled by preflight. Whole deep subsystems (CIECAM02, gamut/GDB, IT8) were
lost this way.

The fix (gated `LOGICFUZZ_RECOVER_INIT_HANDLES`) adds name-idiom initializers
with empty `produces` to the recovery bucket. The existing same-subsystem gate
in `resolve()` still binds them ONLY to same-subsystem consumers, so a recovered
non-producer can never cross-wire to another subsystem.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APIRole, APISemantics, APISemanticModel,
)
from liberator_adapter.analysis import sequence_constructor as sc  # noqa: E402


def _model():
    # cmsCIECAM02Init: void*-return initializer mis-roled CONSUMER (produces=[]),
    # requires a viewing-conditions struct (caller-alloc).
    init = APISemantics(
        name="cmsCIECAM02Init", role=APIRole.CONSUMER, role_confidence=0.6,
        produces=frozenset(), requires=frozenset({"cmsviewingconditions*"}))
    # cmsCIECAM02Reverse: consumes the cmshandle from Init.
    rev = APISemantics(
        name="cmsCIECAM02Reverse", role=APIRole.CONSUMER, role_confidence=0.6,
        requires=frozenset({"cmshandle"}))
    # A DIFFERENT subsystem sharing the SAME generic cmshandle void* typedef —
    # this makes the recovered bucket multi-subsystem (the real lcms case that
    # arms the cross-wiring guard). cmsGDBAlloc is a real opaque CREATOR.
    gdb_alloc = APISemantics(
        name="cmsGDBAlloc", role=APIRole.CREATOR, role_confidence=0.6,
        produces=frozenset())
    gdb_use = APISemantics(
        name="cmsGDBAddPoint", role=APIRole.CONSUMER, role_confidence=0.6,
        requires=frozenset({"cmshandle"}))
    return APISemanticModel(
        project="lcms",
        apis={a.name: a for a in (init, rev, gdb_alloc, gdb_use)})


def _recover(model, gate):
    idx_creators = [s for s in model.apis.values()
                    if s.role is APIRole.CREATOR]
    producers = {}
    for s in model.apis.values():
        for t in s.produces:
            producers.setdefault(t, []).append(s)
    old = os.environ.get("LOGICFUZZ_RECOVER_INIT_HANDLES")
    if gate:
        os.environ["LOGICFUZZ_RECOVER_INIT_HANDLES"] = "1"
    else:
        os.environ.pop("LOGICFUZZ_RECOVER_INIT_HANDLES", None)
    try:
        return sc._recover_opaque_producers(model, producers, idx_creators)
    finally:
        if old is None:
            os.environ.pop("LOGICFUZZ_RECOVER_INIT_HANDLES", None)
        else:
            os.environ["LOGICFUZZ_RECOVER_INIT_HANDLES"] = old


def test_gate_off_does_not_recover_misroled_init():
    rec = _recover(_model(), gate=False)
    # gate off: cmsCIECAM02Init (role CONSUMER) is NOT a recovery candidate, so
    # the cmshandle bucket has no CIECAM02 producer.
    names = {s.name for s in rec.get("cmshandle", [])}
    assert "cmsCIECAM02Init" not in names, names


def test_gate_on_recovers_misroled_init_as_opaque_producer():
    rec = _recover(_model(), gate=True)
    names = {s.name for s in rec.get("cmshandle", [])}
    assert "cmsCIECAM02Init" in names, names


def test_recovered_init_binds_only_same_subsystem():
    # End-to-end: with the gate on, constructing for cmsCIECAM02Reverse prepends
    # cmsCIECAM02Init (same subsystem) and NEVER for cmsGDBAddPoint (the gate in
    # resolve() leaves it a hole rather than cross-wiring to CIECAM02Init).
    os.environ["LOGICFUZZ_RECOVER_INIT_HANDLES"] = "1"
    try:
        res = sc.construct_sequences(_model(), max_sequences=50)
    finally:
        os.environ.pop("LOGICFUZZ_RECOVER_INIT_HANDLES", None)
    seqs = res.sequences
    rev_chains = [s for s in seqs if "cmsCIECAM02Reverse" in s]
    assert rev_chains, "expected a cmsCIECAM02Reverse chain"
    assert any("cmsCIECAM02Init" in s for s in rev_chains), rev_chains
    # cmsCIECAM02Init must never co-occur with a DIFFERENT-subsystem handle
    # consumer (cmsGDBAddPoint): the cross-wiring guard keeps the generic
    # cmshandle out of density's free-sharing pool.
    for s in seqs:
        if "cmsCIECAM02Init" in s:
            assert "cmsGDBAddPoint" not in s, s
