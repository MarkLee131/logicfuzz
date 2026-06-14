import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import construct_sequences


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _lib():
    return [
        _api("h_create", [], ret="H *"),
        _api("h_cfg", [_arg("H *"), _arg("int", name="mode")], ret="int"),
        _api("h_use", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ]


def test_idiom_chains_accepted_and_seeded(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DENSE_CONSTRUCT", "1")
    m = reconcile(_lib())
    res = construct_sequences(m, idiom_chains=[["h_create", "h_cfg", "h_use", "h_free"]])
    # the idiom chain is seeded verbatim as one of the sequences.
    assert any(s == ["h_create", "h_cfg", "h_use", "h_free"] for s in res.sequences)
