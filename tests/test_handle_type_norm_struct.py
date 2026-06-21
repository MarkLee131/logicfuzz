"""Regression: normalize_handle_type must strip the `struct` KEYWORD but not the
substring inside a type NAME. The old `.replace("struct ", "")` turned
`png_struct *` into `png_*`, so png_create_read_struct's produces ('png_*') never
matched a `png_struct` consumer → handle stayed NULL → dead libpng harness. lcms
names (cmsHPROFILE/cmsPipeline) lack 'struct' so they were unaffected (which is
why lcms worked and png didn't)."""
from liberator_adapter.analysis.usedef import normalize_handle_type


def test_struct_keyword_not_corrupting_name():
    assert normalize_handle_type('png_struct *') == 'png_struct*'   # was 'png_*'
    assert normalize_handle_type('png_info *') == 'png_info*'       # unchanged


def test_leading_struct_keyword_stripped():
    # the C `struct` keyword (elaborated type) IS dropped; inner name kept
    assert normalize_handle_type('struct png_struct_def *') == 'png_struct_def*'


def test_lcms_handles_unchanged():
    assert normalize_handle_type('cmsHPROFILE') == 'cmshprofile'
    assert normalize_handle_type('cmsPipeline *') == 'cmspipeline*'
