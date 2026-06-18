import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.driver_dedup import pairwise_dedup_skeletons


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _model():
    return reconcile([
        _api("h_create", [], ret="H *"),
        _api("h_a", [_arg("H *")], ret="int"),
        _api("h_b", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ])


def test_near_twins_are_dropped():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},  # twin
        {"api_sequence": ["h_create", "h_b", "h_free"], "value_intents": []},  # distinct-ish
    ]
    kept = pairwise_dedup_skeletons(sks, m, tau=0.99)
    seqs = [k["api_sequence"] for k in kept]
    assert seqs.count(["h_create", "h_a", "h_free"]) == 1   # exact twin removed


def test_value_domain_distinct_twins_survive():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a"], "value_intents":
            [{"api": "h_a", "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE gamma"}]}]},
        {"api_sequence": ["h_create", "h_a"], "value_intents":
            [{"api": "h_a", "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE enum"}]}]},
    ]
    kept = pairwise_dedup_skeletons(sks, m, tau=0.5)
    assert len(kept) == 2          # different value domains → both kept


def test_valid_guard_protects_valid_seq():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},  # twin, but VALID
    ]
    valid = {("h_create", "h_a", "h_free")}
    kept = pairwise_dedup_skeletons(sks, m, tau=0.5, valid_seqs=valid)
    assert len(kept) == 2          # VALID twin not dropped


def test_subset_eliminate_drops_strict_subset():
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_free"], "value_intents": []},  # strict subset
    ]
    from liberator_adapter.analysis.driver_dedup import subset_eliminate_skeletons
    kept = subset_eliminate_skeletons(sks, m)
    assert [k["api_sequence"] for k in kept] == [["h_create", "h_a", "h_free"]]


def test_subset_eliminate_semantic_guard_protects_valid_subset():
    # The semantic guard (always-on) prevents a Comprehender-VALID subset
    # skeleton from being eliminated even though its fingerprint is a subset.
    m = _model()
    sks = [
        {"api_sequence": ["h_create", "h_a", "h_free"], "value_intents": []},
        {"api_sequence": ["h_create", "h_free"], "value_intents": []},  # subset, VALID
    ]
    from liberator_adapter.analysis.driver_dedup import subset_eliminate_skeletons
    valid = {("h_create", "h_free")}
    kept = subset_eliminate_skeletons(sks, m, valid_seqs=valid)
    assert len(kept) == 2          # VALID subset not dropped
