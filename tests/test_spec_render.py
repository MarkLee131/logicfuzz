"""REPLACE #4: spec-guided LLM render — unit tests.

TDD coverage for:
  (A) spec emission  — annotate_skeletons / build_render_spec produce the
      expected flat render_spec from a small APISemanticModel-shaped input.
  (B) flag OFF       — the new author path is NOT taken; output is the
      deterministic hole-fill result (byte-identical behaviour).
  (C) conformance    — flag ON + conformant author → accepted; non-conformant
      → retried then fallback; recovery on a later retry; exception → fallback.

The LLM is always mocked (run_tool_calling_loop is stubbed) so tests are
hermetic — no network.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import src.workflow  # noqa: F401  warm the package (avoid circular import)
from src.agents.prototyper import LangGraphPrototyper, _spec_render_enabled  # noqa: E402
from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.hole_semantics import (  # noqa: E402
    build_render_spec, annotate_skeletons)


# --------------------------------------------------------------------------- #
# Build a real APISemanticModel via reconcile() — create → read → destroy.
# --------------------------------------------------------------------------- #
def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(t, const=False, name=""):
    return {"type": t, "is_const": [bool(const)], "name": name}


def _make_model():
    # lib_create carries a CONFIG arg so it bears an intent record (the
    # role-hint creators list is derived from intent records, per the plan).
    return reconcile([
        _api("lib_create", [_arg("int", name="flags")], ret="Handle *"),
        _api("lib_read", [_arg("Handle *", name="h"),
                          _arg("const uint8_t *", const=True, name="data"),
                          _arg("size_t", name="len")], ret="int"),
        _api("lib_destroy", [_arg("Handle *", name="h")]),
    ])


class _EmptyModel:
    """A model that knows nothing about the planned APIs (.get → None)."""
    apis: dict = {}

    def get(self, name):
        return None


def _make_skeleton():
    return {
        "name": "drv_0",
        "includes": ["lib.h"],
        "code": "/* skeleton code */",
        "holes": [],
        "api_sequence": ["lib_create", "lib_read", "lib_destroy"],
    }


# --------------------------------------------------------------------------- #
# (A) Spec emission
# --------------------------------------------------------------------------- #
def test_build_render_spec_shape():
    model = _make_model()
    sk = _make_skeleton()
    n = annotate_skeletons([sk], model, project_name="mylib")
    assert n == 1
    spec = sk["render_spec"]
    # required keys
    for k in ("driver_id", "library", "includes", "sequence", "_role_hints"):
        assert k in spec, f"missing key {k}"
    assert spec["driver_id"] == "drv_0"
    assert spec["library"] == "mylib"
    assert spec["includes"] == ["lib.h"]
    # sequence preserves api order
    apis = [r["api"] for r in spec["sequence"]]
    assert apis == ["lib_create", "lib_read", "lib_destroy"]
    # each arg carries index/type/intent/kind
    for rec in spec["sequence"]:
        for a in rec["args"]:
            for f in ("index", "type", "intent", "kind"):
                assert f in a
    # role hints derived from record roles
    hints = spec["_role_hints"]
    assert hints["creators"] == ["lib_create"]
    assert hints["destroyers"] == ["lib_destroy"]
    # terminal = last non-destroyer api in plan order
    assert hints["terminals"] == ["lib_read"]


def test_annotate_no_intents_no_spec():
    # A model that knows NOTHING about the planned APIs → no intents → no spec.
    sk = _make_skeleton()
    n = annotate_skeletons([sk], _EmptyModel(), project_name="mylib")
    assert n == 0
    assert "render_spec" not in sk  # entry guard will skip → fallback


def test_build_render_spec_empty_returns_empty():
    assert build_render_spec(_make_skeleton(), [], "mylib") == {}


# --------------------------------------------------------------------------- #
# Test harness for execute()-level behaviour
# --------------------------------------------------------------------------- #
def _make_proto():
    args = argparse.Namespace(max_round=5, multihop_prototyper=False)
    return LangGraphPrototyper(model_name="gpt-4o", trial=1, args=args)


def _state_with_skeleton(sk):
    return {
        "benchmark": {"project": "mylib", "language": "c",
                      "target_path": "/x/fuzz.c"},
        "function_analysis": {},
        "context": {
            "project_apis": [],
            "skeleton_drivers": [sk],
            "header_info": {},
        },
    }


_DETERMINISTIC_FLOOR = "/* DETERMINISTIC FLOOR DRIVER */\nint main(){return 0;}"

_CONFORMANT_DRIVER = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  Handle h = lib_create(0);
  lib_read(d, n);
  lib_destroy(h);
  return 0;
}
"""

# parser-revert / shallow: never calls the planned terminal lib_read
_NONCONFORMANT_DRIVER = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  Handle h = lib_create(0);
  return 0;
}
"""


def _enriched_skeleton():
    model = _make_model()
    sk = _make_skeleton()
    annotate_skeletons([sk], model, project_name="mylib")
    return sk


# --------------------------------------------------------------------------- #
# (B) Flag OFF → deterministic path, author path NOT taken
# --------------------------------------------------------------------------- #
def test_flag_off_byte_identical(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_SPEC_RENDER", raising=False)
    assert _spec_render_enabled() is False
    proto = _make_proto()
    sk = _enriched_skeleton()
    state = _state_with_skeleton(sk)

    # _author_from_spec must NOT be called when the flag is off.
    def _boom(*a, **k):
        raise AssertionError("author path taken with flag OFF")
    monkeypatch.setattr(proto, "_author_from_spec", _boom)

    # Stub the LLM to return a hole_fillings result (deterministic path).
    def _stub_loop(initial_prompt, state, max_rounds, log_prefix):
        return ({"mode": "hole_filling", "hole_fillings": {"__HOLE_x__": "0"}},
                ["<hole_fillings>{}</hole_fillings>"])
    monkeypatch.setattr(proto, "run_tool_calling_loop", _stub_loop)
    # Make the merge deterministic + observable.
    monkeypatch.setattr(proto, "_merge_holes_into_skeleton",
                        lambda code, fills: _DETERMINISTIC_FLOOR)
    monkeypatch.setattr(proto, "_is_structurally_valid", lambda c: True)
    monkeypatch.setattr(proto, "_get_active_skeleton",
                        lambda st: (sk["code"], sk["holes"],
                                    sk["api_sequence"]))

    out = proto.execute(state)
    assert out["fuzz_target_source"] == _DETERMINISTIC_FLOOR
    assert "spec_render_conformant" not in out


# --------------------------------------------------------------------------- #
# (C) Flag ON
# --------------------------------------------------------------------------- #
def test_spec_render_accepts_conformant(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_SPEC_RENDER", "1")
    proto = _make_proto()
    sk = _enriched_skeleton()
    state = _state_with_skeleton(sk)

    calls = {"loop": 0, "merge": 0}

    def _stub_loop(initial_prompt, state, max_rounds, log_prefix):
        calls["loop"] += 1
        return ({}, [f"<fuzz_target>{_CONFORMANT_DRIVER}</fuzz_target>"])
    monkeypatch.setattr(proto, "run_tool_calling_loop", _stub_loop)

    def _merge(code, fills):
        calls["merge"] += 1
        return _DETERMINISTIC_FLOOR
    monkeypatch.setattr(proto, "_merge_holes_into_skeleton", _merge)

    out = proto.execute(state)
    assert out["spec_render_conformant"] is True
    assert "lib_read" in out["fuzz_target_source"]  # authored code, not floor
    assert calls["loop"] == 1
    assert calls["merge"] == 0  # deterministic floor NOT used


def test_spec_render_rejects_then_retries(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_SPEC_RENDER", "1")
    proto = _make_proto()
    sk = _enriched_skeleton()
    state = _state_with_skeleton(sk)

    calls = {"loop": 0}

    def _stub_loop(initial_prompt, state, max_rounds, log_prefix):
        calls["loop"] += 1
        return ({}, [f"<fuzz_target>{_NONCONFORMANT_DRIVER}</fuzz_target>"])
    monkeypatch.setattr(proto, "run_tool_calling_loop", _stub_loop)

    # Deterministic floor (the fallback) — make it observable.
    monkeypatch.setattr(proto, "_merge_holes_into_skeleton",
                        lambda code, fills: _DETERMINISTIC_FLOOR)
    monkeypatch.setattr(proto, "_is_structurally_valid", lambda c: True)
    monkeypatch.setattr(proto, "_get_active_skeleton",
                        lambda st: (sk["code"], sk["holes"],
                                    sk["api_sequence"]))

    # The hole-fill path runs the loop again (returns no holes → floor fallback).
    out = proto.execute(state)
    # 3 author attempts; the deterministic path then runs the loop once more.
    assert calls["loop"] == 4
    assert out["fuzz_target_source"] == _DETERMINISTIC_FLOOR
    assert "spec_render_conformant" not in out


def test_spec_render_recovers_on_retry(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_SPEC_RENDER", "1")
    proto = _make_proto()
    sk = _enriched_skeleton()
    state = _state_with_skeleton(sk)

    seq = [_NONCONFORMANT_DRIVER, _CONFORMANT_DRIVER]
    calls = {"loop": 0}

    def _stub_loop(initial_prompt, state, max_rounds, log_prefix):
        drv = seq[calls["loop"]]
        calls["loop"] += 1
        return ({}, [f"<fuzz_target>{drv}</fuzz_target>"])
    monkeypatch.setattr(proto, "run_tool_calling_loop", _stub_loop)

    out = proto.execute(state)
    assert out["spec_render_conformant"] is True
    assert out["spec_render_attempt"] == 1
    assert calls["loop"] == 2
    assert "lib_read" in out["fuzz_target_source"]


def test_author_exception_falls_back(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_SPEC_RENDER", "1")
    proto = _make_proto()
    sk = _enriched_skeleton()
    state = _state_with_skeleton(sk)

    def _stub_loop(initial_prompt, state, max_rounds, log_prefix):
        return ({}, [f"<fuzz_target>{_CONFORMANT_DRIVER}</fuzz_target>"])
    monkeypatch.setattr(proto, "run_tool_calling_loop", _stub_loop)

    # Force analyze_conformance to raise inside _author_from_spec.
    import liberator_adapter.analysis.plan_conformance as pc
    monkeypatch.setattr(
        pc, "analyze_conformance",
        lambda **k: (_ for _ in ()).throw(RuntimeError("boom")))

    # Deterministic fallback observable.
    monkeypatch.setattr(proto, "_merge_holes_into_skeleton",
                        lambda code, fills: _DETERMINISTIC_FLOOR)
    monkeypatch.setattr(proto, "_is_structurally_valid", lambda c: True)
    monkeypatch.setattr(proto, "_get_active_skeleton",
                        lambda st: (sk["code"], sk["holes"],
                                    sk["api_sequence"]))

    out = proto.execute(state)
    assert out["fuzz_target_source"] == _DETERMINISTIC_FLOOR
    assert "spec_render_conformant" not in out
