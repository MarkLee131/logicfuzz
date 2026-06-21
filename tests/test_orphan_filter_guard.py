"""Regression: the merge orphan filter over-dropped guarded-safe drivers and
mis-kept the one genuinely-unsafe one (the 53->7 / 18->3 collapse).
(1) _is_creator used substring match: 'png_set_chunk_malloc_max' matched 'alloc'
    -> wrongly treated as a creator -> NULL first arg deemed legal -> KEPT (it is
    the real NULL-deref poison). Segment match fixes it.
(2) is_degenerate_orphan was NULL-guard-blind: a consume inside `if (h) { ... }`
    provably can't deref NULL, yet was flagged. Guard-awareness keeps it."""
from tools.merge_drivers.orphan_filter import _is_creator, is_degenerate_orphan


def test_is_creator_segment_not_substring():
    assert _is_creator('png_set_chunk_malloc_max') is False   # 'malloc' != 'alloc' segment
    assert _is_creator('png_get_io_ptr') is False
    assert _is_creator('png_create_read_struct') is True      # 'create' segment
    assert _is_creator('foo_alloc') is True                    # 'alloc' segment
    assert _is_creator('cmsCreateContext') is True             # prefix


def test_guarded_consume_not_orphan():
    code = ('png_struct * h = NULL;\n'
            'png_info * info = NULL;\n'
            'if (h && info) {\n'
            '    png_read_info(h, info);\n'
            '}\n')
    assert is_degenerate_orphan(code) is False   # guarded → safe


def test_unguarded_consume_is_orphan():
    code = ('png_struct * h = NULL;\n'
            'png_read_info(h, info);\n')
    assert is_degenerate_orphan(code) is True    # unguarded NULL handle → poison


def test_unguarded_setter_now_flagged():
    # the genuinely-unsafe driver that was previously MIS-KEPT as a creator
    code = ('png_struct * h = NULL;\n'
            'png_set_chunk_malloc_max(h, 100);\n')
    assert is_degenerate_orphan(code) is True


def test_produced_handle_never_orphan():
    code = ('png_struct * h = png_create_read_struct(s, 0, 0, 0);\n'
            'png_read_info(h, info);\n')
    assert is_degenerate_orphan(code) is False   # produced → not NULL
