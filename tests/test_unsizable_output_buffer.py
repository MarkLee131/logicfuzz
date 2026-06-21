"""#3 read_image safety: _has_unsizable_output_buffer flags an OUTPUT pointer-to-
pointer arg (png_read_image's png_bytepp row_pointers, sized by runtime height —
unsynthesizable → would render a size-1 garbage-pointer array → crash) but NOT a
HANDLE_IN T** (png_get_tRNS, lib sets one pointer) nor a scalar OUTPUT (int*)."""
from liberator_adapter.analysis.sequence_constructor import _has_unsizable_output_buffer
from liberator_adapter.analysis.api_semantic_model import ArgSemantics, ArgRole


def _sem(args):
    class S: pass
    s = S(); s.args = args; return s


def test_output_ptr_ptr_flagged():
    s = _sem([ArgSemantics(index=0, role=ArgRole.HANDLE_IN, type_str="png_struct * __restrict"),
              ArgSemantics(index=1, role=ArgRole.OUTPUT, type_str="png_byte * *")])
    assert _has_unsizable_output_buffer(s) is True


def test_handle_in_ptr_ptr_not_flagged():
    # get_tRNS: the ** args are HANDLE_IN (lib sets one pointer) — safe
    s = _sem([ArgSemantics(index=0, role=ArgRole.HANDLE_IN, type_str="png_bytep *"),
              ArgSemantics(index=1, role=ArgRole.OUTPUT, type_str="int *")])
    assert _has_unsizable_output_buffer(s) is False


def test_no_ptr_ptr_not_flagged():
    s = _sem([ArgSemantics(index=0, role=ArgRole.HANDLE_IN, type_str="png_struct *"),
              ArgSemantics(index=1, role=ArgRole.HANDLE_IN, type_str="png_info *")])
    assert _has_unsizable_output_buffer(s) is False
