import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _two_destroyer_lib():
    return [
        _api("h_create", [], ret="H *"),
        _api("h_free_x", [_arg("H *")]),
        _api("h_free_y", [_arg("H *")]),
    ]


def test_destroyers_rotate_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", "1")
    idx = SC._build_index(reconcile(_two_destroyer_lib()))
    opened = set(idx.destroyers.keys())          # normalized handle key
    d0 = SC._closing_destroyers(opened, idx, destroyer_rank={k: 0 for k in opened})
    d1 = SC._closing_destroyers(opened, idx, destroyer_rank={k: 1 for k in opened})
    assert d0 != d1
    assert set(d0 + d1) == {"h_free_x", "h_free_y"}


def test_gate_off_picks_first_sorted(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", raising=False)
    idx = SC._build_index(reconcile(_two_destroyer_lib()))
    opened = set(idx.destroyers.keys())
    assert SC._closing_destroyers(opened, idx) == ["h_free_x"]
