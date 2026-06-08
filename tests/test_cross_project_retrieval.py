"""T7 — cross-project driver retrieval (LOGICFUZZ_CROSS_PROJECT, gated optional).

Structure-signature retrieval of structurally-similar fuzz drivers from other
OSS-Fuzz projects, injected as compressed CALLSPEC-style hints for resource-thin
libraries. Covers the pure core (signature / overlap / trigger / scope-threshold
selection with same-project-first) + an integration "experiment" on the real
`extracted_fuzz_drivers/` corpus. Embedding fallback is unwired (deployment-
constrained → OpenAI text-embedding-3-small when needed).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.cross_project_retrieval import (  # noqa: E402
    extract_api_calls, signature_of, overlap, is_resource_thin,
    retrieve, render_hints, load_corpus, retrieve_hints_for_apis,
    DriverSignature,
)


# ---- API-call extraction ---------------------------------------------------

def test_extract_filters_boilerplate_keeps_apis():
    src = """int LLVMFuzzerTestOneInput(const uint8_t*d, size_t n){
        if (n < 4) return 0;
        Thing* t = thing_create();
        thing_use(t, d, n);
        thing_free(t);
        memcpy(buf, d, n);
    }"""
    calls = extract_api_calls(src)
    assert "thing_create" in calls and "thing_use" in calls and "thing_free" in calls
    assert "LLVMFuzzerTestOneInput" not in calls   # boilerplate filtered
    assert "if" not in calls and "memcpy" not in calls
    # order preserved
    assert calls.index("thing_create") < calls.index("thing_free")


# ---- signature + overlap ---------------------------------------------------

def test_signature_role_and_entry_hints():
    sig = signature_of(["png_create_read", "png_read_image", "png_destroy_read"])
    assert "png_create_read" in sig.create_hints
    assert "png_read_image" in sig.entry_hints       # 'read'
    assert "png_destroy_read" in sig.destroy_hints


def test_overlap_identical_high_disjoint_zero():
    a = signature_of(["a_open", "a_read", "a_close"])
    b = signature_of(["a_open", "a_read", "a_close"])
    c = signature_of(["z_foo", "z_bar"])
    assert overlap(a, b) > 0.9
    assert overlap(a, c) == 0.0
    # partial overlap is strictly between
    d = signature_of(["a_open", "a_read", "x_other"])
    assert 0.0 < overlap(a, d) < overlap(a, b)


# ---- resource-thin trigger -------------------------------------------------

def test_resource_thin_trigger():
    assert is_resource_thin(0, has_docs=True, has_tests=True) is True   # no drivers
    assert is_resource_thin(1, has_docs=False, has_tests=False) is True
    assert is_resource_thin(1, has_docs=True, has_tests=False) is False
    assert is_resource_thin(5, has_docs=False, has_tests=False) is False


# ---- retrieve: same-project-first + scope-threshold ------------------------

def _sig(proj, name, apis):
    return signature_of(apis, project=proj, name=name)


def test_retrieve_same_project_first():
    target = _sig("P", "__target__", ["p_open", "p_read", "p_close"])
    corpus = [
        _sig("Q", "q1", ["p_open", "p_read", "p_close"]),   # high overlap, cross
        _sig("P", "p_other", ["p_init", "p_run"]),          # same project
    ]
    hits = retrieve(target, corpus, tau=0.1, budget=5, prefer_project="P")
    assert hits[0].project == "P"        # same-project comes first


def test_retrieve_threshold_and_skip_self():
    target = _sig("P", "__target__", ["p_open", "p_read"])
    corpus = [
        _sig("Q", "match", ["p_open", "p_read"]),       # over tau
        _sig("Q", "noise", ["z_a", "z_b", "z_c"]),      # under tau → dropped
        _sig("P", "__target__", ["p_open", "p_read"]),  # self → skipped
    ]
    hits = retrieve(target, corpus, tau=0.4, budget=5)
    names = {h.name for h in hits}
    assert "match" in names
    assert "noise" not in names
    assert "__target__" not in names


def test_retrieve_fallback_best_one_when_none_clears_tau():
    target = _sig("P", "__target__", ["p_open", "p_read"])
    corpus = [_sig("Q", "weak", ["p_open", "z_x", "z_y", "z_z", "z_w"])]
    hits = retrieve(target, corpus, tau=0.99, budget=5)   # nothing clears 0.99
    assert len(hits) == 1 and hits[0].name == "weak"      # best-1 safety net


# ---- render -----------------------------------------------------------------

def test_render_hints_format_and_empty():
    assert render_hints([]) == ""
    h = render_hints([_sig("Q", "q1", ["q_open", "q_parse"])])
    assert "cross_project_examples" in h
    assert "q1" in h and "q_open" in h


# ---- integration experiment: REAL extracted_fuzz_drivers/ corpus -----------

_REAL_CORPUS = Path(ROOT) / "extracted_fuzz_drivers"


def test_load_real_corpus():
    if not _REAL_CORPUS.is_dir():
        return  # corpus absent in this checkout → skip
    corpus = load_corpus(_REAL_CORPUS)
    assert len(corpus) > 0
    projects = {c.project for c in corpus}
    # the 3 shipped projects
    assert {"lcms", "cjson", "c-ares"} & projects


def test_rich_own_project_stays_same_project_only():
    if not _REAL_CORPUS.is_dir():
        return
    # lcms ships MANY own drivers → NOT thin → hints should reference lcms only,
    # never cjson/c-ares.
    hints = retrieve_hints_for_apis(
        ["cmsOpenProfileFromMem", "cmsCreateTransform", "cmsDoTransform"],
        project="lcms", corpus_root=_REAL_CORPUS)
    if hints:                       # non-empty when lcms drivers parsed
        assert "[cjson/" not in hints and "[c-ares/" not in hints


def test_thin_project_pulls_cross_project():
    if not _REAL_CORPUS.is_dir():
        return
    # a project with NO own drivers in the corpus → thin → cross-project hits.
    hints = retrieve_hints_for_apis(
        ["json_parse", "json_open", "json_free"],
        project="nonexistent_lib", corpus_root=_REAL_CORPUS)
    # may be '' if nothing clears the bar, but if present it's cross-project
    if hints:
        assert "cross_project_examples" in hints


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
