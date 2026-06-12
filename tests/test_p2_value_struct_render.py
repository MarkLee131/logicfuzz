"""FIX A — a complete public value-struct pointer is stack-allocated, not NULL.

A single pointer to a complete, non-opaque struct (``cmsCIELab *``, ``cmsCIEXYZ *``)
is NOT an opaque handle: the caller declares it on the stack and passes its
address. The renderer's "complete" set was scalar-only, so such args rendered
NULL in every branch (HANDLE_IN → NULL, OUTPUT → degraded NULL), and the API
no-ops / crashes on a NULL struct pointer → edges=0 (the lcms color-math
subsystem: cmsLab2LCh / cmsDeltaE / cmsD50_XYZ).

Gate is DataLayout completeness (``is_a_struct`` and not ``is_incomplete``) —
library-agnostic, no per-library list. An opaque/incomplete handle
(``cmsToneCurve *``, incomplete) and a ``void *`` keep the NULL render.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.common.datalayout import DataLayout  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, SkeletonRenderer, _complete_value_struct,
)


def _arg(n, t, c=False):
    return Arg(name=n, flag="", size=0, type=t, is_const=[c],
               is_type_incomplete=False)


def _api(n, rt, args):
    return Api(function_name=n, is_vararg=False,
               return_info=_arg("r", rt), arguments_info=args, namespace=[])


@pytest.fixture
def _layout():
    """Populate the DataLayout singleton with one complete struct, one
    incomplete handle, then restore the prior instance."""
    prev = DataLayout._instance
    DataLayout._instance = None
    dl = DataLayout.instance()
    dl.clang_to_llvm_struct = {
        "cmsCIELab": "%struct.cmsCIELab",         # complete value struct
        "cmsToneCurve": "%struct._cms_curve",     # named but incomplete (handle)
    }
    dl.incomplete_types = ["%cmsToneCurve"]
    dl.enum_type = []
    yield dl
    DataLayout._instance = prev


def test_helper_classifies_by_completeness(_layout):
    assert _complete_value_struct("cmsCIELab *") == "cmsCIELab"
    assert _complete_value_struct("const cmsCIELab *") == "cmsCIELab"
    assert _complete_value_struct("cmsToneCurve *") is None   # incomplete → handle
    assert _complete_value_struct("void *") is None           # not a struct
    assert _complete_value_struct("cmsCIELab **") is None      # T** stays OUTPUT
    assert _complete_value_struct("int") is None


def test_value_struct_arg_is_stack_allocated_and_addressed(_layout):
    # cmsLab2LCh(cmsCIELCh* out, cmsCIELab* in) — driver-15 archetype. Only the
    # complete struct (cmsCIELab) is stack+addressed; the opaque handle stays NULL.
    seq = [_api("cmsDeltaE", "double",
                [_arg("a", "cmsCIELab *"), _arg("b", "cmsCIELab *")])]
    sk = SkeletonGenerator().generate(
        api_sequence=seq, driver_name="t", is_cpp=False)
    code = SkeletonRenderer().render(sk)
    # value-struct declarations (not pointers), {0}-init
    assert re.search(r"cmsCIELab\s+\w+\s*=\s*\{0\}", code), code
    # call passes the ADDRESS of the stack struct, never NULL
    assert "&" in code and "cmsDeltaE(&" in code.replace(" ", ""), code
    assert "cmsCIELab * " not in code, ("must not declare a NULL struct pointer\n"
                                         + code)


def test_incomplete_handle_keeps_null(_layout):
    seq = [_api("cmsFreeToneCurve", "void", [_arg("c", "cmsToneCurve *")])]
    sk = SkeletonGenerator().generate(
        api_sequence=seq, driver_name="t", is_cpp=False)
    code = SkeletonRenderer().render(sk)
    # opaque/incomplete handle is NOT stack-allocated as a value
    assert not re.search(r"cmsToneCurve\s+\w+\s*=\s*\{0\}", code), code


def test_unpopulated_layout_is_a_noop():
    # No DataLayout set up → helper returns None → prior NULL render (no crash).
    prev = DataLayout._instance
    DataLayout._instance = None
    try:
        assert _complete_value_struct("cmsCIELab *") is None
    finally:
        DataLayout._instance = prev
