"""Subsystem clustering — the foundation of coverage-complete portfolio
construction. A cluster = a subsystem handle type; the partition must keep
distinct fuzzing subsystems (pipeline / stage / tone-curve) SEPARATE despite
their shared handle types, must not let a plumbing handle (context) merge
everything, and must assign every API exactly once.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.subsystem_clusters import (  # noqa: E402
    subsystem_clusters, cluster_summary, _handle_token,
)


class _M:
    def __init__(self, d):
        self.apis = d


def test_plumbing_handle_does_not_merge_everything():
    # ctx is required by ALL → plumbing → must NOT be a cluster key; the two
    # real subsystems (foo / bar) stay distinct.
    apis = {f"op{i}": {"requires": ["ctx*"], "produces": []} for i in range(20)}
    apis["make_foo"] = {"requires": ["ctx*"], "produces": ["foo*"]}
    apis["use_foo"] = {"requires": ["ctx*", "foo*"], "produces": []}
    apis["make_bar"] = {"requires": ["ctx*"], "produces": ["bar*"]}
    apis["use_bar"] = {"requires": ["ctx*", "bar*"], "produces": []}
    cl = subsystem_clusters(_M(apis))
    assert cl["make_foo"] == cl["use_foo"] == "foo*"
    assert cl["make_bar"] == cl["use_bar"] == "bar*"
    assert cl["make_foo"] != cl["make_bar"]            # not merged via ctx
    # ctx never appears as a cluster id
    assert "ctx*" not in set(cl.values())


def test_shared_handle_subsystems_stay_separate_via_primary_handle():
    # A pipeline holds stages holds tone-curves (shared handle types). Pure
    # connected-components would merge all three; per-primary-handle keeps them
    # distinct, disambiguated by the earliest name-token.
    apis = {
        "cmsPipelineAlloc": {"produces": ["pipeline*"], "requires": ["ctx*"]},
        "cmsPipelineInsertStage": {"produces": [], "requires": ["pipeline*", "stage*"]},
        "cmsStageAllocToneCurves": {"produces": ["stage*", "tonecurve*"], "requires": ["ctx*"]},
        "cmsBuildToneCurve": {"produces": ["tonecurve*"], "requires": ["ctx*"]},
        # plumbing filler so ctx is the only >10%-touched handle
        **{f"f{i}": {"requires": ["ctx*"], "produces": []} for i in range(12)},
    }
    cl = subsystem_clusters(_M(apis))
    assert cl["cmsPipelineAlloc"] == "pipeline*"
    assert cl["cmsPipelineInsertStage"] == "pipeline*"     # earliest token "Pipeline"
    assert cl["cmsStageAllocToneCurves"] == "stage*"       # earliest token "Stage"
    assert cl["cmsBuildToneCurve"] == "tonecurve*"
    # three distinct subsystems, not one blob
    assert len({cl["cmsPipelineAlloc"], cl["cmsStageAllocToneCurves"],
                cl["cmsBuildToneCurve"]}) == 3


def test_handleless_family_falls_back_to_name_prefix():
    # APIs with no non-plumbing handle group by name token (the DeltaE-style
    # family), not scatter to singletons when they share a token.
    apis = {
        "cmsDeltaE": {"requires": ["ctx*"], "produces": []},
        "cmsCIE2000DeltaE": {"requires": ["ctx*"], "produces": []},
        **{f"f{i}": {"requires": ["ctx*"], "produces": []} for i in range(12)},
    }
    cl = subsystem_clusters(_M(apis))
    # both end in "DeltaE" token → same N: cluster
    assert cl["cmsDeltaE"] == cl["cmsCIE2000DeltaE"]
    assert cl["cmsDeltaE"].startswith("N:")


def test_partition_is_total_and_no_mega_merge_on_real_model():
    import json
    path = os.path.join(ROOT, "results/lcms/state/api_semantic_model.json")
    if not os.path.exists(path):
        import pytest
        pytest.skip("real lcms model not present")
    m = json.load(open(path))
    apis = m.get("apis", m)
    cl = subsystem_clusters(_M(apis))
    assert set(cl) == set(apis)                            # total partition
    summ = cluster_summary(cl)
    assert len(summ) >= 40                                 # many subsystems, not ~8
    biggest = max(len(v) for v in summ.values())
    assert biggest < len(apis) // 5                        # no mega-cluster
    # the object-construction subsystems are distinct, non-giant clusters
    assert cl["cmsPipelineAlloc"] == "cmspipeline*"
    assert cl["cmsMLUalloc"] == "cmsmlu*"
    assert cl["cmsPipelineAlloc"] != cl["cmsBuildParametricToneCurve"]


def test_handle_token():
    assert _handle_token("cmspipeline*") == "pipeline"
    assert _handle_token("_cmscontext_*") == "context"
    assert _handle_token("cmsnamedcolorlist*") == "namedcolorlist"
