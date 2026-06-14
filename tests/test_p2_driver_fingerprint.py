import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.driver_fingerprint import (
    sequence_fingerprint, fingerprint_similarity, fingerprint_is_subset)


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _lib():
    return [
        _api("thing_create", [], ret="Thing *"),
        _api("thing_use", [_arg("Thing *")], ret="int"),
        _api("thing_free", [_arg("Thing *")]),
    ]


def test_identical_sequences_are_maximally_similar():
    m = reconcile(_lib())
    a = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    b = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    assert fingerprint_similarity(a, b) == 1.0


def test_different_value_domain_makes_distinct():
    m = reconcile(_lib())
    vi_x = [{"api": "thing_use", "role": "CONSUMER",
             "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE gamma"}]}]
    vi_y = [{"api": "thing_use", "role": "CONSUMER",
             "args": [{"index": 0, "role": "CONFIG", "intent": "FUZZ_DERIVE enum"}]}]
    a = sequence_fingerprint(["thing_create", "thing_use"], m, vi_x)
    b = sequence_fingerprint(["thing_create", "thing_use"], m, vi_y)
    assert fingerprint_similarity(a, b) == 0.0   # value-domain distinct → not redundant


def test_strict_subset_with_same_value_domain():
    m = reconcile(_lib())
    small = sequence_fingerprint(["thing_create", "thing_free"], m)
    big = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    assert fingerprint_is_subset(small, big) is True
    assert fingerprint_is_subset(big, small) is False
