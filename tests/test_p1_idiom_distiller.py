"""Pin Phase B (Idiom Distiller) L1 deterministic pattern extraction.

These tests use representative C snippets that match patterns seen in
real cjson / c-ares / lcms baseline drivers. Adding a new idiom kind
(or extending a regex) should keep these tests green; if not, the
new pattern is changing the distillation contract and needs
explicit consideration.

See ``src/knowledge/idiom_distiller.py`` for the module under test
and the Phase A→E roadmap (commit history around 2026-05-22) for
the system-design context.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.knowledge.idiom_distiller import (  # noqa: E402
    Idiom,
    IdiomKind,
    IdiomLibrary,
    distill_idioms,
    distill_and_persist,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _drv(path: str, source: str) -> dict:
    return {'path': path, 'source': source}


def _kinds(lib: IdiomLibrary):
    return [i.kind for i in lib.idioms]


# ---------------------------------------------------------------------------
# Per-pattern detection
# ---------------------------------------------------------------------------

def test_min_size_guard_strict_lt():
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size < 8) return 0;
        return 0;
    }"""
    lib = distill_idioms("any", [_drv("t.c", src)])
    assert IdiomKind.MIN_SIZE_GUARD in _kinds(lib)


def test_min_size_guard_le_with_variable():
    """cjson uses ``if (size <= offset) return 0;`` — the regex
    relaxed to accept ``<=`` plus identifier RHS."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        size_t offset = 4;
        if (size <= offset) return 0;
        return 0;
    }"""
    lib = distill_idioms("cjson", [_drv("cjson_read_fuzzer.c", src)])
    assert IdiomKind.MIN_SIZE_GUARD in _kinds(lib)


def test_null_termination_required_pattern():
    """cjson: ``if (data[size - 1] != '\\0') return 0;`` — input
    must already be null-terminated."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (data[size - 1] != '\\0') return 0;
        return 0;
    }"""
    lib = distill_idioms("cjson", [_drv("t.c", src)])
    assert IdiomKind.NULL_TERMINATION_REQUIRED in _kinds(lib)


def test_null_terminate_input_write_pattern():
    """c-ares: ``name[size] = '\\0';`` — driver writes the null."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        char name[1024];
        memcpy(name, data, size);
        name[size] = '\\0';
        return 0;
    }"""
    lib = distill_idioms("c-ares", [_drv("t.c", src)])
    assert IdiomKind.NULL_TERMINATE_INPUT in _kinds(lib)


def test_buffer_copy_pattern():
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        char buf[1024];
        memcpy(buf, data, size);
        return 0;
    }"""
    lib = distill_idioms("any", [_drv("t.c", src)])
    assert IdiomKind.BUFFER_COPY in _kinds(lib)


def test_header_flag_demux_pattern():
    """cjson uses 4 byte-flags at the head of the input."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (data[0] != '1' && data[0] != '0') return 0;
        if (data[1] != '1' && data[1] != '0') return 0;
        return 0;
    }"""
    lib = distill_idioms("cjson", [_drv("t.c", src)])
    assert IdiomKind.HEADER_FLAG_DEMUX in _kinds(lib)


def test_data_offset_parse_named_offset():
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        size_t offset = 4;
        cJSON_ParseWithOpts((const char *)data + offset, NULL, 0);
        return 0;
    }"""
    lib = distill_idioms("cjson", [_drv("t.c", src)])
    assert IdiomKind.DATA_OFFSET_PARSE in _kinds(lib)


def test_data_offset_parse_skips_loop_indices():
    """``data + i`` inside a loop body is noise, not a header/body split."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        for (size_t i = 0; i < size; i++) {
            char b = data[i] + 1; // unrelated
            (void)b;
        }
        return 0;
    }"""
    lib = distill_idioms("any", [_drv("t.c", src)])
    # ``data[i]`` is array access not ``data + i``; no DATA_OFFSET_PARSE.
    assert IdiomKind.DATA_OFFSET_PARSE not in _kinds(lib)


def test_context_null_pass_lcms_pattern():
    """lcms: ``cmsCreateContext(NULL, ...)`` — the canonical
    optional-context pattern. Drives the cmsOpenProfileFromMem fix
    we couldn't get from graft alone."""
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        cmsOpenProfileFromMem(NULL, data, size);
        cmsCreateContext(NULL, NULL);
        return 0;
    }"""
    lib = distill_idioms("lcms", [_drv("t.c", src)])
    kinds = _kinds(lib)
    assert IdiomKind.CONTEXT_NULL_PASS in kinds
    null_pass_hits = [i for i in lib.idioms
                      if i.kind == IdiomKind.CONTEXT_NULL_PASS]
    snippets = [i.snippet for i in null_pass_hits]
    assert any('cmsOpenProfileFromMem' in s for s in snippets), snippets
    assert any('cmsCreateContext' in s for s in snippets), snippets


def test_cleanup_pair_init_destroy():
    src = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        foo_init(data, size);
        foo_destroy();
        return 0;
    }"""
    lib = distill_idioms("any", [_drv("t.c", src)])
    pairs = [i for i in lib.idioms if i.kind == IdiomKind.CLEANUP_PAIR]
    assert pairs, _kinds(lib)
    assert "foo_init" in pairs[0].snippet
    assert "foo_destroy" in pairs[0].snippet


# ---------------------------------------------------------------------------
# IdiomLibrary aggregation + persistence
# ---------------------------------------------------------------------------

def test_idiom_dedup_across_drivers():
    """Same (kind, snippet) seen in two drivers reported once."""
    src = "if (size < 8) return 0;"
    lib = distill_idioms("any", [_drv("a.c", src), _drv("b.c", src)])
    guards = [i for i in lib.idioms if i.kind == IdiomKind.MIN_SIZE_GUARD]
    assert len(guards) == 1


def test_idiom_library_to_dict_roundtrip():
    lib = IdiomLibrary(project="testproj")
    lib.add(Idiom(
        kind=IdiomKind.CONTEXT_NULL_PASS,
        snippet="cmsCreateContext(NULL, ...)",
        rationale="rationale",
        source_driver="t.c",
    ))
    d = lib.to_dict()
    assert d['project'] == "testproj"
    assert d['idiom_count'] == 1
    assert d['by_kind_count'] == {'context_null_pass': 1}
    assert d['idioms'][0]['kind'] == 'context_null_pass'


def test_distill_and_persist_writes_state_file():
    src = "if (size < 8) return 0;"
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / 'state'
        lib = distill_and_persist(
            "myproj", [_drv("a.c", src)], state_dir=state)
        out = state / 'idioms.json'
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded['project'] == 'myproj'
        assert loaded['idiom_count'] == 1


def test_empty_drivers_no_idioms_no_crash():
    lib = distill_idioms("any", [])
    assert lib.idioms == []
    lib2 = distill_idioms("any", [_drv("t.c", "")])
    assert lib2.idioms == []
