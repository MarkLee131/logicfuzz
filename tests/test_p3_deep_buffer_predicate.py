"""Anti-over-fit lock for the depth lever's deep-buffer predicate.

`_has_deep_input_buffer(sem)` recognizes the lcms `cmsDoTransform` idiom — a
CONSUMER that processes a data buffer passed as a bare `void*` CONFIG arg
(read-buffer + write-buffer + count). It MUST be guarded so it does not mis-fire
on other projects: an over-fitting review found a naive version matched 11
function-pointer callbacks in libpng (100% FP → fuzzing fn-ptrs → crash) and 5
user-data/context args in nghttp2 (~100% FP). These tests load every cached
project model and assert the predicate helps lcms and is safe/inert everywhere
else — this is the regression lock against over-fitting.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import APISemanticModel
from liberator_adapter.analysis.sequence_constructor import _has_deep_input_buffer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _matches(project):
    # Load the CACHED, fully-reconciled model (SVF + doc + recovery) — the same
    # model construct_sequences sees in production. A bare reconcile(project_apis)
    # is degraded (no OUTPUT/HANDLE_IN args) and is NOT representative.
    p = Path(ROOT) / f"results/{project}/state/api_semantic_model.json"
    if not p.exists():
        pytest.skip(f"no cached api_semantic_model for {project}")
    model = APISemanticModel.load(p)
    assert model is not None, project
    return sorted(n for n, sem in model.apis.items() if _has_deep_input_buffer(sem))


def test_lcms_matches_dotransform_family():
    m = _matches("lcms")
    assert any("cmsDoTransform" in n for n in m), m
    # every match must be a real transform-shaped data processor, not a setter
    assert all(("Transform" in n or "transform" in n) for n in m), m


@pytest.mark.parametrize("project", ["libpng", "nghttp2"])
def test_no_misfire_on_callback_or_context_libs(project):
    # libpng = function-pointer callbacks; nghttp2 = user_data/context. Guards
    # MUST reject all of them.
    assert _matches(project) == [], _matches(project)


@pytest.mark.parametrize("project", ["cjson", "c-ares", "zlib", "sqlite3"])
def test_inert_on_non_buffer_idiom_libs(project):
    # these libs' depth lives in other idioms (struct fields / traversal); the
    # void*-buffer predicate must be inert (no matches), so it can't regress them.
    assert _matches(project) == [], _matches(project)
