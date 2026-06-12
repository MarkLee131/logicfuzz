"""Keystone fix: the hole-merge must only apply fills keyed by actual ``__…__``
hole placeholders.

Root cause of the lcms object-construction edges=0 wave: hole-LESS skeletons get
LLM fillings keyed by VARIABLE NAME (e.g. {"arg0_cmsDictDup": "NULL"}); the blind
first-pass global string-replace rewrote the DECLARATION name slot too
(``void * arg0_cmsDictDup = NULL;`` → ``void * NULL = NULL;``), invalid C that
weak-stubs to an edges=0 driver. Name-keyed fills must be dropped; placeholder
fills must still apply.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402

_merge = LangGraphPrototyper._merge_holes_into_skeleton


class _Dummy:
    trial = 1

    def _fixup_min_size_guard(self, code):   # no-LLM passthrough for the test
        return code

    def _validate_filled_driver(self, code):  # warn-only post-merge step
        return None


def test_name_keyed_fills_dropped_no_decl_corruption():
    skel = (
        "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t s) {\n"
        "  void * arg0_cmsDictDup = NULL;\n"
        "  int arg1_cmsIT8SetDataRowCol = 0;\n"
        "  cmsDictDup(arg0_cmsDictDup);\n"
        "  cmsIT8SetDataRowCol(h, arg1_cmsIT8SetDataRowCol);\n"
        "  return 0;\n}")
    # the corrupting name-keyed fillings the LLM returns for a hole-less skeleton
    fills = {"arg0_cmsDictDup": "NULL",
             "arg1_cmsIT8SetDataRowCol": "data[0] % 10"}
    out = _merge(_Dummy(), skel, fills)
    # declarations stay intact (the floor), no value-in-name corruption
    assert "void * arg0_cmsDictDup = NULL;" in out, out
    assert "int arg1_cmsIT8SetDataRowCol = 0;" in out, out
    assert "void * NULL = NULL" not in out, out
    assert "int data[0] % 10 = 0" not in out, out


def test_placeholder_keyed_fills_still_apply():
    skel = "int f(){ void* p = __HOLE_buf_1__; int n = __BUFSIZE_len_1__; return 0; }"
    out = _merge(_Dummy(), skel,
                 {"__HOLE_buf_1__": "(void*)data", "__BUFSIZE_len_1__": "size"})
    assert "void* p = (void*)data;" in out, out
    assert "int n = size;" in out, out
    assert "__HOLE" not in out and "__BUFSIZE" not in out, out
