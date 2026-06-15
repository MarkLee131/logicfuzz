"""Anti-over-fit + semantic-safety lock for the cross-source binding lever.

`_wants_cross_source(sem, idx)` marks a CREATOR that builds a new object from >=2
handles of the SAME type which has >=2 producers (incl. a synthetic) — the lcms
`cmsCreateTransform` cross-profile idiom. It is scoped to CREATOR + name-deny so
it CANNOT mis-fire on the semantically-unsafe shapes an over-fit review flagged:
copy/state APIs (zlib `deflateCopy(dest,src)`) and parent-child APIs (cjson
`cJSON_DetachItemViaPointer`) where the two handles need a specific relationship,
not two arbitrary instances. These tests lock that across cached projects.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import APISemanticModel
from liberator_adapter.analysis import sequence_constructor as sc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _matches(project):
    p = Path(ROOT) / f"results/{project}/state/api_semantic_model.json"
    if not p.exists():
        pytest.skip(f"no cached model for {project}")
    m = APISemanticModel.load(p)
    idx = sc._build_index(m)
    return sorted(n for n, sem in m.apis.items() if sc._wants_cross_source(sem, idx))


def test_lcms_matches_transform_creators():
    m = _matches("lcms")
    assert "cmsCreateTransform" in m, m
    assert "cmsCreateProofingTransform" in m, m


def test_no_misfire_on_copy_state_apis_zlib():
    m = _matches("zlib")
    # deflateCopy/inflateCopy need src=live-state, dest=fresh — NOT two arbitrary
    # producers. Must never be cross-source-bound.
    assert "deflateCopy" not in m and "inflateCopy" not in m, m


@pytest.mark.parametrize("project", ["cjson", "c-ares", "sqlite3"])
def test_no_misfire_on_mutator_or_parentchild_libs(project):
    m = _matches(project)
    # no detach/parent-child or add-to-container (mutators, not CREATORs) bound
    assert all(("Detach" not in n and "AddItem" not in n) for n in m), m
