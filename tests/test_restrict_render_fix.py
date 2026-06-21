"""Regression: the renderer must not emit illegal C `restrict`/`__restrict` on a
non-pointer base type (libpng signatures arrive as `png_struct __restrict *`,
which gcc rejects with 'invalid use of restrict'). The trailing-anchored strip in
Factory.normalize_type misses mid-string qualifiers; the decl renderer must clean
them."""
from liberator_adapter.driver.synthesis.skeleton_generator import (
    const_qualified_type, _public_pointer_type, _strip_restrict)


def test_strip_restrict_midstring():
    assert _strip_restrict('png_struct __restrict *') == 'png_struct *'
    assert _strip_restrict('const png_struct __restrict *') == 'const png_struct *'
    assert _strip_restrict('png_byte') == 'png_byte'           # no-op
    assert _strip_restrict('char * restrict') == 'char *'      # trailing too


def test_const_qualified_strips_midstring_restrict():
    out = const_qualified_type('png_struct __restrict *', [True, False])
    assert 'restrict' not in out, out
    assert out == 'const png_struct *', out


def test_const_qualified_no_const_path_strips_restrict():
    # early-return path (is_const empty) must STILL emit legal C
    out = const_qualified_type('png_struct __restrict *', [])
    assert 'restrict' not in out, out
    assert out == 'png_struct *', out


def test_public_pointer_type_strips_restrict():
    assert 'restrict' not in _public_pointer_type('png_struct __restrict *')
