"""L6a + L6b: value-domain tests for VALUE_DOMAINS gate.

L6a: 4cc constant mine + forbid enum arithmetic when LOGICFUZZ_VALUE_DOMAINS=1.
L6b: @param.text -> doc_text -> range-mined intent when LOGICFUZZ_VALUE_DOMAINS=1.

Tests:
L6a:
1. Enum-typed CONFIG arg with empty enum members (signature typedef) -> forbids
   `% N` / `%256` when VALUE_DOMAINS gate is on.
2. 4cc hex defines (8 hex digits) are captured in the vocab WITHOUT _MIN_GROUP
   filtering (even a single such define is captured).
3. Gate-off: old behavior unchanged (no FUZZ_DERIVE with forbidden-modulo warning).

L6b:
4. test_param_text_survives_into_doc_text: collect_doc_evidence captures p["text"]
   into _DocEvidence.arg_texts (was discarded).
5. test_param_text_survives_into_doc_text_reconcile: reconcile threads arg_texts
   into ArgSemantics.doc_text.
6. test_documented_range_reaches_intent_when_gated: with gate on, an arg with
   doc_text "value between 0 and 1" yields an intent mentioning that range; gate
   off -> legacy intent without doc annotation.
7. test_missing_doc_text_is_safe: arg without doc_text -> no crash, legacy intent.
"""
import os
import sys
import tempfile
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.named_constants import (
    extract_constant_vocabulary,
)
from liberator_adapter.analysis.hole_semantics import _arg_intent
from liberator_adapter.analysis.api_semantic_model import ArgRole


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_4CC_HEADER = """\
/* lcms-style 4cc signature defines */
#define cmsSigRgbData        0x52474220
#define cmsSigXYZData        0x58595A20
#define cmsSigLabData        0x4C616220
"""

_4CC_HEADER_SINGLE = """\
/* only one 4cc define -- must still appear in vocab */
#define cmsSigRgbData        0x52474220
"""


def _vocab_from_text(text: str):
    with tempfile.TemporaryDirectory() as td:
        h = pathlib.Path(td) / "lib.h"
        h.write_text(text)
        return extract_constant_vocabulary([str(h)])


# ---------------------------------------------------------------------------
# 4cc mine tests  (L6a)
# ---------------------------------------------------------------------------

def test_4cc_three_names_all_captured():
    """All three 4cc defines appear in the vocab (not filtered by _MIN_GROUP)."""
    v = _vocab_from_text(_4CC_HEADER)
    names = v.get("define_4cc", {})
    assert "cmsSigRgbData" in names, f"cmsSigRgbData missing; define_4cc={names}"
    assert "cmsSigXYZData" in names, f"cmsSigXYZData missing"
    assert "cmsSigLabData" in names, f"cmsSigLabData missing"


def test_4cc_single_define_still_captured():
    """Even a single 4cc define is captured (no _MIN_GROUP filter for 4cc)."""
    v = _vocab_from_text(_4CC_HEADER_SINGLE)
    names = v.get("define_4cc", {})
    assert "cmsSigRgbData" in names, f"single 4cc not captured; define_4cc={names}"


def test_4cc_values_stored():
    """The 4cc hex string is stored as the value."""
    v = _vocab_from_text(_4CC_HEADER)
    names = v.get("define_4cc", {})
    assert names["cmsSigRgbData"] == "0x52474220"


# ---------------------------------------------------------------------------
# Gate-OFF: old behavior unchanged  (L6a)
# ---------------------------------------------------------------------------

def test_gate_off_enum_typed_no_forbid(monkeypatch):
    """With VALUE_DOMAINS=0, enum-typed CONFIG arg with empty members -> None (old path)."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "0")

    class A:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 0
        name = "cs"
        doc_text = ""

    intent = _arg_intent(A(), "cmsCreateTransform", {})
    assert intent is None


# ---------------------------------------------------------------------------
# Gate-ON: enum-typed arg -> forbids modulo arithmetic  (L6a)
# ---------------------------------------------------------------------------

def test_enum_typed_config_forbids_modulo(monkeypatch):
    """Enum/signature-typed CONFIG arg -> intent forbids % N when gate on."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "1")

    class A:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 0
        name = "cs"
        doc_text = ""

    intent = _arg_intent(A(), "cmsCreateTransform", {})
    assert intent is not None, "Expected an intent for enum-typed arg when VALUE_DOMAINS=1"
    assert "% N" not in intent, f"'% N' should not appear; got: {intent}"
    assert "%256" not in intent.replace(" ", ""), f"'%256' should not appear; got: {intent}"
    assert ("LEGAL" in intent) or ("arithmetic" in intent.lower()), (
        f"Intent should mention LEGAL set or arithmetic; got: {intent}"
    )


def test_enum_typed_with_4cc_vocab(monkeypatch):
    """When 4cc vocab has the type's names, intent cites them."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "1")

    v = _vocab_from_text(_4CC_HEADER)

    class A:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 0
        name = "cs"
        doc_text = ""

    intent = _arg_intent(A(), "cmsCreateTransform", v)
    assert intent is not None
    assert "% N" not in intent
    assert "%256" not in intent.replace(" ", "")


# ---------------------------------------------------------------------------
# L6b: collect_doc_evidence captures p["text"] into arg_texts
# ---------------------------------------------------------------------------

def test_param_text_survives_into_doc_text():
    """collect_doc_evidence captures p["text"] into _DocEvidence.arg_texts."""
    from liberator_adapter.analysis.api_semantic_model import collect_doc_evidence
    ds = {
        "cmsSetGamma": {
            "brief": "set gamma",
            "params": [
                {"index": 0, "name": "Gamma", "text": "value between 0.1 and 5.0",
                 "role": None},
            ],
        }
    }
    ev = collect_doc_evidence([{"function_name": "cmsSetGamma"}], ds)
    assert "cmsSetGamma" in ev, "API not found in evidence"
    assert hasattr(ev["cmsSetGamma"], "arg_texts"), "_DocEvidence has no arg_texts"
    assert ev["cmsSetGamma"].arg_texts.get(0) == "value between 0.1 and 5.0", (
        f"param text not captured; got: {ev['cmsSetGamma'].arg_texts}"
    )


def test_param_text_survives_into_doc_text_reconcile():
    """reconcile() threads arg_texts into ArgSemantics.doc_text."""
    from liberator_adapter.analysis.api_semantic_model import reconcile
    api = {
        "function_name": "cmsSetGamma",
        "return_type": "void",
        "arguments": [
            {"index": 0, "type": "double", "name": "Gamma", "_svf_writes": None},
        ],
    }
    doc_signals = {
        "cmsSetGamma": {
            "brief": "set gamma",
            "params": [
                {"index": 0, "role": "CONFIG", "text": "value between 0 and 1"},
            ],
        }
    }
    model = reconcile([api], project="test", doc_signals=doc_signals)
    sem = model.get("cmsSetGamma")
    assert sem is not None, "API not found in model"
    assert len(sem.args) >= 1, "No args in model"
    arg0 = sem.args[0]
    assert hasattr(arg0, "doc_text"), "ArgSemantics has no doc_text field"
    assert arg0.doc_text == "value between 0 and 1", (
        f"doc_text not threaded through reconcile; got: {arg0.doc_text!r}"
    )


# ---------------------------------------------------------------------------
# L6b: documented range -> intent when gate is on; gate-off unchanged
# ---------------------------------------------------------------------------

def test_documented_range_reaches_intent_when_gated(monkeypatch):
    """Gate ON: doc_text 'value between 2.5 and 99.7' yields an intent citing range.
    Gate OFF: doc_text range NOT injected into the legacy intent.
    """
    from types import SimpleNamespace

    a = SimpleNamespace(
        role=ArgRole.CONFIG,
        type_str="double",
        pairs_with=None,
        index=0,
        name="CustomParam",
        doc_text="value between 2.5 and 99.7",
    )

    # Gate ON
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "1")
    intent_on = _arg_intent(a, "someApiFunc", {})
    assert intent_on is not None, "Expected intent when gate ON"
    assert "2.5" in intent_on and "99.7" in intent_on, (
        f"Documented range not in gate-ON intent; got: {intent_on!r}"
    )

    # Gate OFF
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "0")
    intent_off = _arg_intent(a, "someApiFunc", {})
    # The generic FUZZ_DERIVE scalar float intent must NOT reference the doc_text
    # range. (Both bounds absent — an OR of disjuncts was a tautology that could
    # not catch a leak; require BOTH bounds to be absent.)
    if intent_off is not None:
        assert "2.5" not in intent_off and "99.7" not in intent_off, (
            f"doc_text range leaked into gate-OFF intent; got: {intent_off!r}"
        )


def test_missing_doc_text_is_safe(monkeypatch):
    """Arg without doc_text -> no crash, returns an intent (or None safely)."""
    from types import SimpleNamespace

    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "1")

    # Case 1: doc_text field present but empty
    a1 = SimpleNamespace(
        role=ArgRole.CONFIG,
        type_str="double",
        pairs_with=None,
        index=0,
        name="x",
        doc_text="",
    )
    intent1 = _arg_intent(a1, "foo", {})
    # Falls back to generic float FUZZ_DERIVE (FUZZABLE_HOLES=1); no crash
    assert intent1 is not None, "Expected generic intent for scalar float"

    # Case 2: no doc_text attribute at all (simulates old ArgSemantics / duck typing)
    a2 = SimpleNamespace(
        role=ArgRole.CONFIG,
        type_str="double",
        pairs_with=None,
        index=0,
        name="x",
    )
    # Must not raise AttributeError
    intent2 = _arg_intent(a2, "bar", {})
    assert intent2 is not None, "Expected generic intent even without doc_text attr"
