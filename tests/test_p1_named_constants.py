"""T2: named-constant vocabulary extraction + enum CONFIG value-intent.

Validates that the symbolic side supplies the LEGAL constant set for enum
CONFIG args (so the LLM stops guessing out-of-enum numbers), and that the
plain-int / no-vocab paths still behave.
"""
import tempfile
from pathlib import Path

from liberator_adapter.analysis.named_constants import (
    extract_constant_vocabulary,
    enum_members_for_type,
    render_constant_vocabulary,
)
from liberator_adapter.analysis.hole_semantics import _arg_intent
from liberator_adapter.analysis.api_semantic_model import ArgRole


_HEADER = """
/* a fake public header */
typedef enum {
    cmsSigXYZData = 0x58595A20,
    cmsSigLabData,   // a comment
    cmsSigRgbData
} cmsColorSpaceSignature;

enum Plain { A, B = 2, C };

#define INTENT_PERCEPTUAL              0
#define INTENT_RELATIVE_COLORIMETRIC  1
#define INTENT_SATURATION             2
#define ONE_OFF_VERSION               123   /* singleton: no family */
#define TYPE_FN(x)                    ((x)+1)  /* function-like: skipped */
"""


def _vocab():
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "lib.h"
        h.write_text(_HEADER)
        return extract_constant_vocabulary([str(h)])


def test_true_enum_members_extracted():
    v = _vocab()
    assert v["enums"]["cmsColorSpaceSignature"] == [
        "cmsSigXYZData", "cmsSigLabData", "cmsSigRgbData"]
    assert v["enums"]["Plain"] == ["A", "B", "C"]


def test_define_family_grouped_and_filtered():
    v = _vocab()
    # INTENT_ has 3 members -> a family; ONE_OFF_ (1) and function-like are not.
    assert v["define_groups"]["INTENT_"] == [
        "INTENT_PERCEPTUAL", "INTENT_RELATIVE_COLORIMETRIC", "INTENT_SATURATION"]
    assert all(len(m) >= 3 for m in v["define_groups"].values())
    assert "ONE_OFF_" not in v["define_groups"]


def test_enum_members_for_type_lookup():
    v = _vocab()
    assert enum_members_for_type(v, "cmsColorSpaceSignature")[0] == "cmsSigXYZData"
    assert enum_members_for_type(v, "unsigned int") == []
    assert enum_members_for_type({}, "cmsColorSpaceSignature") == []


def test_config_enum_intent_carries_legal_set(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "0")  # pin the ENUM (off) path
    v = _vocab()

    class EnumArg:
        role = ArgRole.CONFIG
        type_str = "cmsColorSpaceSignature"
        pairs_with = None
        index = 2

    intent = _arg_intent(EnumArg(), "cmsDoTransform", v)
    assert intent is not None and intent.startswith("ENUM")
    assert "cmsSigXYZData" in intent
    # Without a vocab, a non-scalar enum-typed CONFIG arg yields no intent
    # (it isn't a plain scalar int), preserving prior behavior.
    assert _arg_intent(EnumArg(), "x", None) is None


def test_config_plain_int_still_varies_range(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "0")  # pin the VARY_RANGE (off) path
    v = _vocab()

    class IntArg:
        role = ArgRole.CONFIG
        type_str = "unsigned int"
        pairs_with = None
        index = 1

    intent = _arg_intent(IntArg(), "x", v)
    assert intent is not None and "VARY_RANGE" in intent


def test_render_is_token_bounded_and_nonempty():
    v = _vocab()
    block = render_constant_vocabulary(v)
    assert "cmsColorSpaceSignature" in block and "INTENT_" in block
    assert render_constant_vocabulary({}) == ""
