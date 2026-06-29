"""Unit tests for typedef-aware (buf, size) detection in _find_buffer_size_positions.
Library-agnostic: keyed on byte-family type-spelling substrings + _size_t/_len
length suffix + an SVF write-veto. No project-name special cases."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.usedef import _find_buffer_size_positions


def _arg(t, *, is_const=False, svf=None):
    a = {"type": t, "is_const": is_const}
    if svf is not None:
        a["_svf_writes"] = svf
    return a


def test_literal_const_void_buffer_still_detected():
    # Regression: the existing fast path must keep working.
    args = [_arg("const void *", is_const=True), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_const_voidp_typedef_with_size_t():
    # Buffer-gate fix: typedef spelling carries "void"; const is embedded.
    args = [_arg("png_const_voidp"), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_const_voidp_with_png_size_t_typedef_length():
    # Both gates fixed: typedef buffer + typedef length (the live libpng shape).
    args = [_arg("png_const_voidp"), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_const_void_with_png_size_t_length_typedef():
    # Length-gate fix in isolation.
    args = [_arg("const void *", is_const=True), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_bytep_buffer():
    # "byte" token; const embedded.
    args = [_arg("png_const_bytep"), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_svf_written_buffer_is_vetoed():
    # An SVF-observed WRITE means output buffer, not fuzz input.
    args = [_arg("const void *", is_const=True, svf=True), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_svf_read_only_buffer_not_vetoed():
    # _svf_writes False (read-only) must NOT suppress the match.
    args = [_arg("const void *", is_const=True, svf=False), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_non_byte_const_pointer_count_not_matched():
    # (const int* elems, int count) is NOT an input buffer — no over-broad match.
    args = [_arg("const int *", is_const=True), _arg("int")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_const_struct_pointer_not_matched():
    args = [_arg("const cmsHPROFILE *", is_const=True), _arg("int")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_lcms_uint8_buffer_unchanged_no_regression():
    # cmsUInt8Number* is handled by the separate FUZZ_BUFFERS path, NOT here;
    # it must stay unmatched so the fix doesn't shift lcms behavior.
    args = [_arg("const cmsUInt8Number *", is_const=True), _arg("cmsUInt32Number")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_non_const_buffer_skipped():
    # Const gate preserved: a non-const png_voidp is not matched.
    args = [_arg("png_voidp"), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (-1, -1)
