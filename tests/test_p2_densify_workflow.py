import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.sequence_constructor import _workflow_clusters


def test_workflow_clusters_are_connected_components():
    # a-b-c co-occur together; x-y co-occur together; two components.
    cooccur = {"a": {"b", "c"}, "b": {"a", "c"}, "c": {"a", "b"},
               "x": {"y"}, "y": {"x"}}
    wf = _workflow_clusters(cooccur)
    assert wf["a"] == wf["b"] == wf["c"]
    assert wf["x"] == wf["y"]
    assert wf["a"] != wf["x"]


def test_singletons_get_distinct_ids():
    wf = _workflow_clusters({"a": set(), "b": set()})
    assert wf["a"] != wf["b"]
