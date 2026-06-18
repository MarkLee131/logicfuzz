import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.driver_fingerprint import (
    sequence_fingerprint, fingerprint_is_subset)


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


def test_strict_subset_with_same_value_domain():
    m = reconcile(_lib())
    small = sequence_fingerprint(["thing_create", "thing_free"], m)
    big = sequence_fingerprint(["thing_create", "thing_use", "thing_free"], m)
    assert fingerprint_is_subset(small, big) is True
    assert fingerprint_is_subset(big, small) is False
