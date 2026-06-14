import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC
from liberator_adapter.analysis.sequence_constructor import construct_sequences


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _multi_producer_lib():
    """Two creators of H *, several consumers, so >1 chain shares the handle."""
    return [
        _api("h_make_a", [], ret="H *"),
        _api("h_make_b", [], ret="H *"),
        _api("h_use1", [_arg("H *")], ret="int"),
        _api("h_use2", [_arg("H *")], ret="int"),
        _api("h_free", [_arg("H *")]),
    ]


def _producers_in_consumer_chains(res):
    """Producers appearing in chains that target a consumer (h_use*).

    The create->destroy coverage loop emits a sequence per creator regardless,
    so A-1's effect is only observable in the PREFIX producer of consumer
    chains.
    """
    used = set()
    for s in res.sequences:
        if "h_use1" in s or "h_use2" in s:
            if "h_make_a" in s:
                used.add("h_make_a")
            if "h_make_b" in s:
                used.add("h_make_b")
    return used


def _hermetic(monkeypatch):
    # Isolate the prefix-producer choice. _OBJCONSTRUCT_FIRST is a module-level
    # constant bound at import; another test reloads the module with it on and
    # does not restore it, leaking _OBJCONSTRUCT_FIRST=True (an env revert can't
    # undo a module reload). Force the module attr False (auto-reverted) so this
    # test is robust to that pollution; also pin dense off so creator chains
    # stay bare and don't pull consumers in.
    monkeypatch.setattr(SC, "_OBJCONSTRUCT_FIRST", False, raising=False)
    monkeypatch.setenv("LOGICFUZZ_DENSE_CONSTRUCT", "0")
    monkeypatch.delenv("LOGICFUZZ_OBJCONSTRUCT_FIRST", raising=False)


def test_producers_rotate_across_siblings_when_gated(monkeypatch):
    _hermetic(monkeypatch)
    monkeypatch.setenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", "1")
    res = construct_sequences(reconcile(_multi_producer_lib()))
    assert _producers_in_consumer_chains(res) == {"h_make_a", "h_make_b"}


def test_gate_off_uses_single_deterministic_producer(monkeypatch):
    _hermetic(monkeypatch)
    monkeypatch.delenv("LOGICFUZZ_DIVERSIFY_PRODUCERS", raising=False)
    res = construct_sequences(reconcile(_multi_producer_lib()))
    assert _producers_in_consumer_chains(res) == {"h_make_a"}  # always sorted-first
