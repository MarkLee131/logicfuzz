"""Post-fill repair: zero-initialize uninitialized output-handle pointer arrays.

libpng driver 58 crashed in png_info_init_3 -> free():

    png_info *arg0[1];                       // UNINITIALIZED -> garbage pointer
    OSS_FUZZ_png_info_init_3(arg0, size);    // frees the garbage *arg0[0] -> SEGV

An array-of-pointers used as an output/handle backing must be zero-initialized so
an init/fill API sees NULL (and skips the free) instead of a garbage pointer.
Zero-init is always safe — it never changes the behavior of a correct driver, and
an input buffer it touches is overwritten anyway. This repair targets POINTER
arrays (the dangerous output-handle case); it must not touch already-initialized
declarations or non-array decls.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from src.agents.prototyper import _zero_init_output_handle_arrays as _repair  # noqa: E402
except ImportError:
    from src.agents.prototyper import _zero_init_output_handle_arrays as _repair  # noqa: E402


def test_zero_inits_uninitialized_pointer_array():
    code = "    png_info *arg0[1];\n    foo(arg0, n);\n"
    out = _repair(code)
    assert "png_info *arg0[1] = {0};" in out, out


def test_leaves_already_initialized_alone():
    code = "    png_info *arg0[1] = {0};\n"
    out = _repair(code)
    assert out.count("= {0}") == 1, out  # not doubled


def test_leaves_scalar_and_value_buffers_alone():
    # a non-pointer scalar decl is untouched
    code = "    int x;\n    char buf[8] = {0};\n"
    out = _repair(code)
    assert "int x;" in out
    assert out.count("= {0}") == 1, out


def test_handles_multi_star_output():
    code = "    png_struct **pp[2];\n"
    out = _repair(code)
    assert "png_struct **pp[2] = {0};" in out, out
