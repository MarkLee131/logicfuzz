"""Regression: sequence_constructor._norm_handle must strip cv/restrict qualifiers
so a consumer arg `png_struct * __restrict` keys identically to a producer's
`png_struct*` → the validity-repair producer-prepend fires. Without this, 229/295
libpng handle args carry __restrict, key as `png_struct*__restrict`, never match the
producer/handle_types key `png_struct`, and repair_sequence_validity silently bails
(key not in handle_types / no producer) → NULL handle → dead driver. (Sibling of the
#19 usedef.normalize_handle_type fix, in the function the repair actually uses.)"""
from liberator_adapter.analysis.sequence_constructor import _norm_handle


def test_strips_restrict():
    assert _norm_handle('png_struct * __restrict') == 'png_struct'   # was png_struct*__restrict
    assert _norm_handle('png_info * __restrict') == 'png_info'


def test_strips_const_and_plain_unchanged():
    assert _norm_handle('const png_struct *') == 'png_struct'
    assert _norm_handle('png_struct *') == 'png_struct'


def test_lcms_unchanged():
    assert _norm_handle('cmsHPROFILE') == 'cmshprofile'
    assert _norm_handle('cmsPipeline *') == 'cmspipeline'


def test_struct_keyword_keyword_vs_name():
    # the `struct` KEYWORD is dropped; the name png_struct keeps its 'struct'
    assert _norm_handle('struct png_struct_def *') == 'png_struct_def'
