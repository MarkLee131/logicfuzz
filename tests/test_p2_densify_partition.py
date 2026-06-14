import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _wide_lib():
    """One handle with MANY consumers so densify has >max_extra candidates."""
    apis = [_api("h_create", [], ret="H *"), _api("h_free", [_arg("H *")])]
    for i in range(12):
        apis.append(_api(f"h_use{i}", [_arg("H *")], ret="int"))
    return apis


def test_sibling_slices_are_disjoint_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DENSE_PARTITION", "1")
    idx = SC._build_index(reconcile(_wide_lib()))
    opened = set(idx.consumers_by_handle.keys())   # normalized handle key
    s0 = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                     sibling_rank=0)
    s1 = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                     sibling_rank=1)
    extra0 = set(s0) - {"h_create"}
    extra1 = set(s1) - {"h_create"}
    assert extra0 and extra1
    assert extra0.isdisjoint(extra1)        # siblings exercise different slices


def test_gate_off_is_unchanged(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DENSE_PARTITION", raising=False)
    idx = SC._build_index(reconcile(_wide_lib()))
    opened = set(idx.consumers_by_handle.keys())   # normalized handle key
    a = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                    sibling_rank=0)
    b = SC._densify(["h_create"], opened, idx, max_extra=4, repeat=False,
                    sibling_rank=3)
    assert a == b                            # rank ignored when gate off
