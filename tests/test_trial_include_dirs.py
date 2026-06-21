"""Header fix (B, part 2): the per-trial build must put the project's public-header
dirs on -I so the driver's library #include resolves regardless of form. The driver
is COPYed to the stock fuzzer's location, so the dirs = the fuzzer's own dir + the
project root (where the stock fuzzer's `#include "../X.h"` points). Without this,
`<X.h>`/bare `"X.h"` failed HEADER_NOT_FOUND → ~40% of valid drivers dropped at build."""
from experiment.evaluator import _trial_include_dirs


def test_cjson_layout():
    assert _trial_include_dirs('/src/cjson/fuzzing/cjson_read_fuzzer.c') == \
        ['/src/cjson/fuzzing', '/src/cjson']


def test_libpng_nested_layout():
    assert _trial_include_dirs('/src/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc') == \
        ['/src/libpng/contrib/oss-fuzz', '/src/libpng/contrib']


def test_relative_or_empty_path_yields_none():
    assert _trial_include_dirs('relative/x.c') == []
    assert _trial_include_dirs('') == []
    assert _trial_include_dirs(None) == []


def test_root_level_fuzzer_filtered():
    # fuzzer directly in /src → fuzzer_dir=/src (excluded), parent=/ (excluded)
    assert _trial_include_dirs('/src/foo_fuzzer.c') == []
