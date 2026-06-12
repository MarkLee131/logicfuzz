"""FIX D — deterministic legal-constant fill from the library's own call-sites.

A CONFIG scalar (cmsCreateTransform's InputFormat) renders =0 / the LLM guesses
``data[0] % 256`` — both INVALID formats → the API returns NULL → the whole
object-construction chain is dead → edges=0. The library's OWN tests call it with
the legal constants (``cmsCreateTransform(hSrc, TYPE_BGR_8, …)``). Mining those
call-sites lets the renderer fill the arg with a valid library constant by
construction — deterministic (no LLM), grounded in real usage.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.constant_usage import (  # noqa: E402
    mine_constant_usage, legal_constants_for, set_usage_map,
    _split_top_level_args, _looks_like_constant,
)
from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, SkeletonRenderer,
)

_SRC = """
/* a comment with cmsCreateTransform(NOPE, BOGUS) that must be ignored */
void t1(void){ h = cmsCreateTransform(hSrc, TYPE_RGB_8, hDst, TYPE_RGB_8, INTENT_PERCEPTUAL, 0); }
void t2(void){ h = cmsCreateTransform(a, TYPE_RGB_8, b, TYPE_GRAY_8, INTENT_PERCEPTUAL, cmsFLAGS_NOCACHE); }
void t3(void){ h = cmsCreateTransform(a, TYPE_CMYK_8, b, TYPE_RGB_8, lcms_sRGB, 0); }
"""


def _write_src(tmp_path):
    p = tmp_path / "uses.c"
    p.write_text(_SRC)
    return [str(p)]


def test_split_and_const_shape():
    assert _split_top_level_args("a, f(b,c), TYPE_RGB_8") == ["a", "f(b,c)", "TYPE_RGB_8"]
    assert _looks_like_constant("TYPE_BGR_8")
    assert not _looks_like_constant("hSrc")
    assert not _looks_like_constant("0")


def test_mine_ranks_by_frequency(tmp_path):
    vocab = {"define_groups": {"TYPE_": ["TYPE_RGB_8", "TYPE_GRAY_8", "TYPE_CMYK_8"],
                               "INTENT_": ["INTENT_PERCEPTUAL"],
                               "cmsFLAGS_": ["cmsFLAGS_NOCACHE"]}}
    m = mine_constant_usage(_write_src(tmp_path), {"cmsCreateTransform"}, vocab)
    # arg1 (InputFormat): TYPE_RGB_8 twice → modal first
    assert m["cmsCreateTransform"][1][0] == "TYPE_RGB_8", m
    # arg4 (Intent): comment ignored; lcms_sRGB is NOT a vocab member → dropped
    assert m["cmsCreateTransform"][4] == ["INTENT_PERCEPTUAL"], m
    assert "lcms_sRGB" not in str(m), m


def test_strict_vocab_filter_drops_nonmembers(tmp_path):
    # with NO vocab, the macro-shaped lcms_sRGB leaks; with vocab it's strict.
    no_vocab = mine_constant_usage(_write_src(tmp_path), {"cmsCreateTransform"}, None)
    assert "lcms_sRGB" in no_vocab["cmsCreateTransform"].get(4, [])
    vocab = {"define_groups": {"INTENT_": ["INTENT_PERCEPTUAL"]}}
    strict = mine_constant_usage(_write_src(tmp_path), {"cmsCreateTransform"}, vocab)
    assert "lcms_sRGB" not in strict["cmsCreateTransform"].get(4, [])


def _arg(n, t, c=False):
    return Arg(name=n, flag="", size=0, type=t, is_const=[c], is_type_incomplete=False)


def test_renderer_uses_modal_constant():
    apis = [{"function_name": "cmsCreateTransform", "arguments": [
        {"type": "void *", "is_const": [False], "name": "in"},
        {"type": "unsigned int", "is_const": [False], "name": "InputFormat"}],
        "return_type": "void *", "is_vararg": False, "namespace": []}]
    seq = [Api(function_name="cmsCreateTransform", is_vararg=False,
               return_info=_arg("r", "void *"),
               arguments_info=[_arg("in", "void *"), _arg("InputFormat", "unsigned int")],
               namespace=[])]
    set_usage_map({"cmsCreateTransform": {1: ["TYPE_RGB_8", "TYPE_GRAY_8"]}})
    try:
        sk = SkeletonGenerator().generate(api_sequence=seq, driver_name="t",
                                          is_cpp=False, dep_model=reconcile(apis))
        code = SkeletonRenderer().render(sk)
        assert "= TYPE_RGB_8" in code, code        # the modal, by construction
        assert "__INIT_" not in code, code         # not a hole (usage won)
    finally:
        set_usage_map({})


def test_lookup_empty_when_unset():
    set_usage_map({})
    assert legal_constants_for("cmsCreateTransform", 1) == []
