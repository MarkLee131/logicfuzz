"""Phase 2.2 correctness fix: density's co-occurrence source must never pull in
a DESTROYER or CREATOR.

A co-occurring DESTROYER, appended as a density extender, collides with the
closing destroyer added at the sequence's tail → DOUBLE_DESTROY → the Typestate
self-filter SILENTLY drops the whole sequence (a lost candidate). A CREATOR
opens a handle nothing here closes. Both belong to the prefix / closing-destroyer
machinery, not to density.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _build_index, _densify,
)


def _model():
    apis = [
        {"function_name": "thing_create", "arguments": [],
         "return_type": "Thing *", "is_vararg": False, "namespace": []},
        {"function_name": "thing_use",
         "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"}],
         "return_type": "int", "is_vararg": False, "namespace": []},
        {"function_name": "thing_free",      # naming → DESTROYER
         "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"}],
         "return_type": "void", "is_vararg": False, "namespace": []},
        {"function_name": "thing_create2",   # naming → CREATOR (same handle type)
         "arguments": [], "return_type": "Thing *", "is_vararg": False,
         "namespace": []},
    ]
    return reconcile(apis)


def test_densify_excludes_cooccurring_destroyer():
    model = _model()
    idx = _build_index(model)
    opened = set(model.apis["thing_create"].produces)
    assert opened, "creator must produce a handle for the test to be meaningful"
    # thing_free.requires == {Thing} ⊆ opened, so WITHOUT the role exclusion it
    # would pass the co-occurrence gate and be densified in (→ double-free).
    out = _densify(["thing_create", "thing_use"], opened, idx,
                   max_extra=8, repeat=False,
                   cooccur={"thing_use": {"thing_free"}})
    assert "thing_free" not in out, f"destroyer must not be densified in; got {out}"


def test_densify_excludes_cooccurring_creator():
    model = _model()
    idx = _build_index(model)
    opened = set(model.apis["thing_create"].produces)
    out = _densify(["thing_create", "thing_use"], opened, idx,
                   max_extra=8, repeat=False,
                   cooccur={"thing_use": {"thing_create2"}})
    assert "thing_create2" not in out, \
        f"creator must not be densified in (prefix's job); got {out}"


def test_densify_still_pulls_a_valid_consumer():
    """Guard: the exclusion is role-targeted — a genuine CONSUMER/getter of an
    open handle is still densified in (the feature isn't broken)."""
    apis = [
        {"function_name": "thing_create", "arguments": [],
         "return_type": "Thing *", "is_vararg": False, "namespace": []},
        {"function_name": "thing_get_count",   # CONSUMER/getter of the handle
         "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"}],
         "return_type": "int", "is_vararg": False, "namespace": []},
    ]
    model = reconcile(apis)
    idx = _build_index(model)
    opened = set(model.apis["thing_create"].produces)
    out = _densify(["thing_create"], opened, idx, max_extra=8, repeat=False,
                   cooccur={"thing_create": {"thing_get_count"}})
    assert "thing_get_count" in out, f"valid consumer should densify in; got {out}"
