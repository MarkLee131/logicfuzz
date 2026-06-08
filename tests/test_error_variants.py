"""T11 — error-shape skeleton variants (LOGICFUZZ_ERROR_VARIANTS).

Unit tests for the pure `error_shape_variants` generator: from a happy-path
lifecycle sequence it derives error-shape variants (double-free / use-after-
destroy / skip-init) that exercise the library's error-handling branches. The
variant changes only the call-sequence SHAPE — the LLM still fills the same leaf
holes. The variants are appended to construct_sequences' output AFTER the
ordering self-filter (which would otherwise drop these deliberate faults).
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    error_shape_variants, _ERROR_VARIANT_SHAPES)

CREATORS = {"create"}
DESTROYERS = {"destroy"}


def _shapes(seq, creators=CREATORS, destroyers=DESTROYERS, **kw):
    return {label: v for v, label in
            error_shape_variants(seq, creators, destroyers, **kw)}


def test_double_destroy_appends_destroyer():
    v = _shapes(["create", "use", "destroy"])
    assert v["DOUBLE_DESTROY"] == ["create", "use", "destroy", "destroy"]


def test_use_after_destroy_moves_destroyer_before_rest():
    v = _shapes(["create", "use", "destroy"])
    # create, destroy, then the remaining (use) → use-after-destroy
    assert v["USE_AFTER_DESTROY"] == ["create", "destroy", "use"]


def test_skip_init_drops_first_creator():
    v = _shapes(["create", "use", "destroy"])
    assert v["SKIP_INIT"] == ["use", "destroy"]


def test_no_destroyer_skips_destroy_shapes():
    v = _shapes(["create", "use"])              # no destroyer present
    assert "DOUBLE_DESTROY" not in v
    assert "USE_AFTER_DESTROY" not in v
    assert v["SKIP_INIT"] == ["use"]            # creator still droppable


def test_no_creator_skips_creator_shapes():
    v = _shapes(["use", "destroy"], creators=set())
    assert "SKIP_INIT" not in v
    assert "USE_AFTER_DESTROY" not in v          # needs a creator too
    assert v["DOUBLE_DESTROY"] == ["use", "destroy", "destroy"]


def test_too_short_sequence_yields_nothing():
    assert error_shape_variants(["create"], CREATORS, DESTROYERS) == []
    assert error_shape_variants([], CREATORS, DESTROYERS) == []


def test_shapes_filter_restricts_output():
    v = _shapes(["create", "use", "destroy"], shapes=("DOUBLE_DESTROY",))
    assert set(v) == {"DOUBLE_DESTROY"}


def test_skip_init_not_emitted_when_all_calls_are_creators():
    # len(seq) == len(creators_in) → dropping the creator leaves a degenerate
    # all-creator body; guarded out.
    v = _shapes(["create", "create"], destroyers=set())
    assert "SKIP_INIT" not in v


def test_default_shapes_constant():
    assert _ERROR_VARIANT_SHAPES == (
        "DOUBLE_DESTROY", "USE_AFTER_DESTROY", "SKIP_INIT")


# ===================================================================
# Integration "experiment": variants through the real construct_sequences
# path (selectivity + gap-gating wiring), not just the pure generator.
# ===================================================================
from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    construct_sequences)


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _managed_lib():
    """create → use(+buffer) → free over one handle type ``Thing *``."""
    return [
        _api("thing_create", [], ret="Thing *"),
        _api("thing_use", [_arg("Thing *"),
                           _arg("const uint8_t *", const=True, name="data"),
                           _arg("size_t", name="len")], ret="int"),
        _api("thing_free", [_arg("Thing *")]),
    ]


def _has_double_free(seqs):
    return any(s.count("thing_free") >= 2 for s in seqs)


def test_gate_off_emits_no_variants(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_ERROR_VARIANTS", raising=False)
    apis = _managed_lib()
    res = construct_sequences(reconcile(apis), project_apis=apis)
    assert res.metrics.get("n_error_variants", 0) == 0
    assert not _has_double_free(res.sequences)


def test_gate_on_emits_selective_variants(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_ERROR_VARIANTS", "1")
    monkeypatch.delenv("LOGICFUZZ_ERROR_VARIANTS_AGGRESSIVE", raising=False)
    apis = _managed_lib()
    res = construct_sequences(reconcile(apis), project_apis=apis)
    assert res.metrics["n_error_variants"] > 0
    # DOUBLE_DESTROY shape present (thing_free twice).
    assert _has_double_free(res.sequences)
    # Safe default: USE_AFTER_DESTROY (create→free→use) NOT emitted.
    assert not any(
        "thing_free" in s and "thing_use" in s
        and s.index("thing_free") < s.index("thing_use")
        for s in res.sequences)


def test_aggressive_adds_use_after_destroy(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_ERROR_VARIANTS", "1")
    monkeypatch.setenv("LOGICFUZZ_ERROR_VARIANTS_AGGRESSIVE", "1")
    apis = _managed_lib()
    res = construct_sequences(reconcile(apis), project_apis=apis)
    # create → free → use now present (use-after-destroy).
    assert any(
        "thing_free" in s and "thing_use" in s
        and s.index("thing_free") < s.index("thing_use")
        for s in res.sequences)


def test_gap_gating_restricts_to_gap_touching_sequences(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_ERROR_VARIANTS", "1")
    apis = _managed_lib()
    # gap that no constructed sequence touches → no variants.
    res_off = construct_sequences(reconcile(apis), project_apis=apis,
                                  gap_apis={"unrelated_api"})
    assert res_off.metrics["n_error_variants"] == 0
    # gap that the chain touches → variants emit.
    res_on = construct_sequences(reconcile(apis), project_apis=apis,
                                 gap_apis={"thing_use"})
    assert res_on.metrics["n_error_variants"] > 0


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
