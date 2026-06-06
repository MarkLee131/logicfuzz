"""Pin the T3/T6② per-API return error/NULL contract extractor.

A creator return bound into a handle without a NULL-check SEGVs the merged
harness the moment the creator fails on adversarial input. The generator needs
a per-API ``may_return_null`` / ``error_sentinel`` contract so the hole prompt
can emit a guard. This test pins both sources:

  - IR: a pointer ``return`` (parent==0, ``type_string`` ends in ``*``) with no
    proof of non-null → ``may_return_null`` (``source="ir"``).
  - doc: ``@return`` text mined for "returns NULL on error" → may_return_null;
    "0 on success, negative on error" → ``error_sentinel`` (``source="doc"``).

Plus a presence-guarded smoke test over the real cached c-ares / lcms data.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.error_contracts import (  # noqa: E402
    extract_error_contracts,
)

_REPO = os.path.dirname(os.path.dirname(__file__))


# --------------------------------------------------------------- fixtures
def _ptr_return(type_string, provenance="UNKNOWN", access="create"):
    return {
        "access_type_set": [
            {"access": access, "fields": [], "parent": 0,
             "provenance": provenance, "type": "h", "type_string": type_string},
        ],
    }


def _scalar_return():
    return {
        "access_type_set": [
            {"access": "create", "fields": [], "parent": 0,
             "provenance": "STACK", "type": "h", "type_string": "i32"},
        ],
    }


def _empty_return():
    return {"access_type_set": []}


def _write_fixture(tmp_path, project, records, docstrings=None):
    proj_dir = tmp_path / project
    proj_dir.mkdir(parents=True, exist_ok=True)
    (proj_dir / "conditions.json").write_text(json.dumps(records))
    if docstrings is not None:
        comp = proj_dir / "comprehension"
        comp.mkdir(parents=True, exist_ok=True)
        (comp / "docs_priors.json").write_text(json.dumps(
            {"readme_purpose": "x", "api_docstrings": docstrings}))
    return tmp_path


# --------------------------------------------------------------- IR source
def test_ir_pointer_return_flags_may_return_null(tmp_path):
    records = [
        {"function_name": "thing_create", "return": _ptr_return("%struct.T*")},
        {"function_name": "thing_count", "return": _scalar_return()},
        {"function_name": "thing_free", "return": _empty_return()},
    ]
    root = _write_fixture(tmp_path, "proj", records)
    out = extract_error_contracts("proj", results_root=root)

    assert out["thing_create"] == {
        "may_return_null": True, "error_sentinel": None, "source": "ir"}
    # scalar return → not flagged from IR (no NULL semantics)
    assert "thing_count" not in out
    # empty return (void) → nothing
    assert "thing_free" not in out


def test_ir_void_pointer_creator_flagged(tmp_path):
    # lcms-style: many creators return i8* (void*-ish) — must be flagged.
    records = [
        {"function_name": "cmsCreateContext", "return": _ptr_return("i8*")},
    ]
    root = _write_fixture(tmp_path, "proj", records)
    out = extract_error_contracts("proj", results_root=root)
    assert out["cmsCreateContext"]["may_return_null"] is True
    assert out["cmsCreateContext"]["source"] == "ir"


# --------------------------------------------------------------- doc source
def test_doc_null_phrasing_overrides_and_flags(tmp_path):
    records = [
        {"function_name": "thing_make", "return": _ptr_return("%struct.T*")},
    ]
    docs = {"thing_make": "Build a thing. @return a Thing, or NULL on error."}
    root = _write_fixture(tmp_path, "proj", records, docstrings=docs)
    out = extract_error_contracts("proj", results_root=root)

    # doc verdict wins over the IR floor for the same API.
    assert out["thing_make"]["may_return_null"] is True
    assert out["thing_make"]["source"] == "doc"


def test_doc_scalar_sentinel_captured(tmp_path):
    records = [{"function_name": "do_op", "return": _scalar_return()}]
    docs = {"do_op": "@return 0 on success, negative on error."}
    root = _write_fixture(tmp_path, "proj", records, docstrings=docs)
    out = extract_error_contracts("proj", results_root=root)

    c = out["do_op"]
    assert c["source"] == "doc"
    assert c["may_return_null"] is False
    assert "negative on error" in (c["error_sentinel"] or "").lower()


def test_doc_signals_param_overrides_cache(tmp_path):
    # caller-supplied structured doc_signals take the doc path.
    records = [{"function_name": "alloc_x", "return": _ptr_return("%struct.X*")}]
    root = _write_fixture(tmp_path, "proj", records)
    signals = {"alloc_x": {"brief": "Allocate X",
                           "returns": "Pointer to X, or NULL if out-of-memory."}}
    out = extract_error_contracts("proj", results_root=root, doc_signals=signals)
    assert out["alloc_x"]["source"] == "doc"
    assert out["alloc_x"]["may_return_null"] is True


# --------------------------------------------------------------- robustness
def test_missing_project_returns_empty(tmp_path):
    assert extract_error_contracts("nope", results_root=tmp_path) == {}


def test_malformed_conditions_returns_empty(tmp_path):
    proj_dir = tmp_path / "bad"
    proj_dir.mkdir(parents=True)
    (proj_dir / "conditions.json").write_text("{not json")
    assert extract_error_contracts("bad", results_root=tmp_path) == {}


# --------------------------------------------------- real cached-data smoke
def _real_results_root():
    root = os.path.join(_REPO, "results")
    return root if os.path.isdir(root) else None


def test_real_cares_creators_flagged():
    root = _real_results_root()
    if not root or not os.path.isfile(
            os.path.join(root, "c-ares", "conditions.json")):
        import pytest
        pytest.skip("cached c-ares conditions.json not present")
    out = extract_error_contracts("c-ares", results_root=root)
    assert out, "expected non-empty contracts for c-ares"
    # a known pointer-returning getter in the cached data
    assert out.get("ares_dns_pton", {}).get("may_return_null") is True


def test_real_lcms_creators_flagged():
    root = _real_results_root()
    if not root or not os.path.isfile(
            os.path.join(root, "lcms", "conditions.json")):
        import pytest
        pytest.skip("cached lcms conditions.json not present")
    out = extract_error_contracts("lcms", results_root=root)
    assert out.get("cmsCreateContext", {}).get("may_return_null") is True
    assert out["cmsCreateContext"]["source"] == "ir"
