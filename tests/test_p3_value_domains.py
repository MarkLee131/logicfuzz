"""L6a: 4cc constant mine + forbid enum arithmetic when LOGICFUZZ_VALUE_DOMAINS=1.

Tests:
1. Enum-typed CONFIG arg with empty enum members (signature typedef) → forbids
   `% N` / `%256` when VALUE_DOMAINS gate is on.
2. 4cc hex defines (8 hex digits) are captured in the vocab WITHOUT _MIN_GROUP
   filtering (even a single such define is captured).
3. Gate-off: old behavior unchanged (no FUZZ_DERIVE with forbidden-modulo warning).
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
/* only one 4cc define — must still appear in vocab */
#define cmsSigRgbData        0x52474220
"""


def _vocab_from_text(text: str):
    with tempfile.TemporaryDirectory() as td:
        h = pathlib.Path(td) / "lib.h"
        h.write_text(text)
        return extract_constant_vocabulary([str(h)])


# ---------------------------------------------------------------------------
# 4cc mine tests
# ---------------------------------------------------------------------------

def test_4cc_three_names_all_captured():
    """All three 4cc defines appear in the vocab (not filtered by _MIN_GROUP)."""
    v = _vocab_from_text(_4CC_HEADER)
    # They land in define_4cc, NOT in define_groups (which needs _MIN_GROUP)
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
    # value should be the hex string
    assert names["cmsSigRgbData"] == "0x52474220"


# ---------------------------------------------------------------------------
# Gate-OFF: old behavior unchanged
# ---------------------------------------------------------------------------

def test_gate_off_enum_typed_no_forbid(monkeypatch):
    """With VALUE_DOMAINS=0, enum-typed CONFIG arg with empty members → None (old path)."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "0")

    class A:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 0
        name = "cs"

    # empty vocab → members=[] → no 4cc fallback when gate is OFF
    intent = _arg_intent(A(), "cmsCreateTransform", {})
    # With FUZZABLE_HOLES=1 but empty members and non-scalar type, no intent.
    assert intent is None


# ---------------------------------------------------------------------------
# Gate-ON: enum-typed arg → forbids modulo arithmetic
# ---------------------------------------------------------------------------

def test_enum_typed_config_forbids_modulo(monkeypatch):
    """Enum/signature-typed CONFIG arg → intent forbids % N when gate on."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "1")
    monkeypatch.setenv("LOGICFUZZ_VALUE_DOMAINS", "1")

    class A:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 0
        name = "cs"

    intent = _arg_intent(A(), "cmsCreateTransform", {})  # empty vocab
    assert intent is not None, "Expected an intent for enum-typed arg when VALUE_DOMAINS=1"
    # Must NOT suggest modulo arithmetic
    assert "% N" not in intent, f"'% N' should not appear; got: {intent}"
    # Also must not suggest %256 (stripped of spaces)
    assert "%256" not in intent.replace(" ", ""), f"'%256' should not appear; got: {intent}"
    # Must say something about LEGAL constants or forbid arithmetic
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

    intent = _arg_intent(A(), "cmsCreateTransform", v)
    assert intent is not None
    # With the gate on, we still shouldn't see modulo
    assert "% N" not in intent
    assert "%256" not in intent.replace(" ", "")
