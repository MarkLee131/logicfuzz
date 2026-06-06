"""T4: CALLSPEC renderer — the consolidated per-call typed view."""
from liberator_adapter.analysis.hole_semantics import (
    render_callspec, _kind_tag, _compact_intent,
)


def test_kind_tag_from_role():
    assert _kind_tag({"role": "HANDLE_IN"}) == "HANDLE"
    assert _kind_tag({"role": "OUTPUT"}) == "OUTPUT"
    assert _kind_tag({"role": "LENGTH"}) == "LENGTH"
    assert _kind_tag({"role": "INPUT_BUFFER"}) == "INPUT"
    assert _kind_tag({"role": "CONFIG", "intent": "ENUM (T): one of {A}"}) == "ENUM"
    assert _kind_tag({"role": "CONFIG", "intent": "VARY_RANGE: ..."}) == "RANGE"


def test_compact_intent_strips_redundant_label():
    assert _compact_intent("HANDLE: must be a live handle").startswith("must be a live")
    assert _compact_intent("ENUM (cmsColorSpaceSignature): pass a LEGAL constant") \
        .startswith("pass a LEGAL")
    assert _compact_intent("VARY_RANGE: cover both").startswith("cover both")
    assert _compact_intent("") == ""


def test_render_callspec_layout():
    intents = [
        {"api": "create", "role": "CREATOR", "args": [],
         "ret_contract": "⚠ returns NULL on failure → NULL-check"},
        {"api": "use", "role": "CONSUMER",
         "args": [
             {"index": 0, "role": "HANDLE_IN", "type": "H *",
              "intent": "HANDLE: must be live", "pairs_with": None},
             {"index": 1, "role": "CONFIG", "type": "int",
              "intent": "ENUM (E): one of {A, B}", "pairs_with": None},
             {"index": 2, "role": "OUTPUT", "type": "v *",
              "intent": "OUTPUT: fresh local", "pairs_with": None,
              "populated_from": [1]},
         ],
         "handle_provenance": ["needs handle H*: produced by create"]},
    ]
    out = render_callspec(intents, signatures={"create": "H create(void)"})
    assert "#1 create [CREATOR]" in out
    assert "sig: H create(void)" in out
    assert "NULL-check" in out
    assert "#2 use [CONSUMER]" in out
    assert "arg0 (H *) [HANDLE]" in out
    assert "arg1 (int) [ENUM]" in out and "one of {A, B}" in out
    assert "arg2 (v *) [OUTPUT]" in out and "data from arg1" in out
    assert "⚙ needs handle H*: produced by create" in out
    # the redundant "HANDLE:" label is stripped (kind tag carries it)
    assert "[HANDLE] — HANDLE:" not in out


def test_render_callspec_empty():
    assert render_callspec([]) == ""
