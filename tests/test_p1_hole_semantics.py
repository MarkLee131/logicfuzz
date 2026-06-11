"""Pin the G4 semantic value-intent layer.

Holes must carry value *intent*, not just a type: scalar config →
in-range/out-of-range; parser buffer → structured input; length → pairing;
out-pointer → output; handle → live. See
``docs/generation_stage_redesign.md`` §5 (G4) and
``liberator_adapter/analysis/hole_semantics.py``.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.hole_semantics import (  # noqa: E402
    value_intents_for_sequence, render_value_intents, annotate_skeletons,
)


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def test_tier1_fuzzable_holes_gated():
    """Tier 1 (LOGICFUZZ_FUZZABLE_HOLES): tunable CONFIG scalars/enums get a
    FUZZ_DERIVE 'derive from the fuzz input' directive so the fuzzer sweeps
    them; validity-required args (handles) stay FIXED; gate-off is unchanged."""
    from types import SimpleNamespace
    from liberator_adapter.analysis.api_semantic_model import ArgRole
    from liberator_adapter.analysis import hole_semantics as H

    cfg = SimpleNamespace(role=ArgRole.CONFIG, type_str="double", index=1, pairs_with=None)
    handle = SimpleNamespace(role=ArgRole.HANDLE_IN, type_str="void *", index=0, pairs_with=None)
    saved = os.environ.pop("LOGICFUZZ_FUZZABLE_HOLES", None)
    try:
        # gate OFF (explicit =0 — the default is now ON): the float CONFIG has
        # no FUZZ_DERIVE (the gap that lets the LLM hardcode a constant gamma=1.0).
        os.environ["LOGICFUZZ_FUZZABLE_HOLES"] = "0"
        assert "FUZZ_DERIVE" not in (H._arg_intent(cfg, "set_gamma") or "")
        # gate ON: tunable scalar → FUZZ_DERIVE; a handle stays FIXED (never fuzzed).
        os.environ["LOGICFUZZ_FUZZABLE_HOLES"] = "1"
        on = H._arg_intent(cfg, "set_gamma") or ""
        assert on.startswith("FUZZ_DERIVE"), on
        assert "FUZZ_DERIVE" not in (H._arg_intent(handle, "use") or "")
        # the rendered block announces FuzzedDataProvider mode only when gated.
        block = render_value_intents([{"api": "set_gamma", "role": "MUTATOR",
                                       "args": [{"index": 1, "role": "CONFIG",
                                                 "type": "double", "intent": on}]}])
        assert "FuzzedDataProvider" in block
    finally:
        if saved is None:
            os.environ.pop("LOGICFUZZ_FUZZABLE_HOLES", None)
        else:
            os.environ["LOGICFUZZ_FUZZABLE_HOLES"] = saved


def _arg(t, const=False, name=""):
    return {"type": t, "is_const": [bool(const)], "name": name}


def _model():
    return reconcile([
        _api("thing_create", [], ret="Thing *"),
        _api("thing_parse", [_arg("const uint8_t *", const=True, name="data"),
                            _arg("size_t", name="len"),
                            _arg("int", name="flags")], ret="Thing *"),
        _api("thing_out", [_arg("Thing * *", name="out")]),
    ])


def _intents_for(name):
    recs = value_intents_for_sequence(_model(), [name])
    return {a["index"]: a["intent"] for r in recs for a in r["args"]} if recs else {}


def test_input_buffer_gets_structured_intent():
    intents = _intents_for("thing_parse")
    assert "STRUCTURED_INPUT" in intents[0]


def test_length_pairs_with_buffer():
    recs = value_intents_for_sequence(_model(), ["thing_parse"])
    args = {a["index"]: a for r in recs for a in r["args"]}
    assert "LENGTH" in args[1]["intent"]
    assert args[1]["pairs_with"] == 0


def test_scalar_config_gets_vary_range_intent(monkeypatch):
    """The P-gen-8 fix: a scalar config hole carries in/out-of-range intent on
    the FUZZABLE-OFF path (now the explicit opt-out; default is FUZZ_DERIVE)."""
    monkeypatch.setenv("LOGICFUZZ_FUZZABLE_HOLES", "0")
    intents = _intents_for("thing_parse")
    assert "VARY_RANGE" in intents[2]


def test_out_pointer_gets_output_intent():
    intents = _intents_for("thing_out")
    assert intents and "OUTPUT" in intents[0]


def test_render_is_nonempty_and_structured():
    recs = value_intents_for_sequence(_model(), ["thing_parse"])
    block = render_value_intents(recs)
    assert "thing_parse" in block and "arg0" in block


def test_annotate_skeletons_in_place():
    model = _model()
    skels = [{"api_sequence": ["thing_parse"], "holes": []},
             {"api_sequence": ["unknown_api"], "holes": []}]
    n = annotate_skeletons(skels, model)
    assert n == 1                                   # only thing_parse has intents
    assert skels[0]["value_intents"]                # attached in place
    assert skels[1]["value_intents"] == []          # unknown → empty, still set


def test_annotate_safe_on_empty():
    assert annotate_skeletons([], _model()) == 0
    assert annotate_skeletons(None, _model()) == 0


def test_g4_format_aware_decoder_intent_is_idempotent():
    """G4 decoder: a parser-entry buffer gets a format-specific, IDEMPOTENT
    normalize instruction (the clause that lets it coexist with seeds)."""
    apis = [_api("cmsOpenProfileFromMem",
                 [_arg("const void *", const=True, name="MemPtr"),
                  _arg("unsigned int", name="dwSize")], ret="void *")]
    model = reconcile(apis)
    recs = value_intents_for_sequence(model, ["cmsOpenProfileFromMem"])
    intents = {a["index"]: a["intent"] for r in recs for a in r["args"]}
    buf = intents[0]
    assert "ICC profile" in buf            # format detected
    assert "acsp" in buf                   # concrete recipe (magic)
    assert "idempotent" in buf.lower()     # passthrough-on-valid ⇒ seed coexistence
    assert "UNCHANGED" in buf              # explicit passthrough of valid seeds


def test_g4_unknown_format_falls_back_to_generic():
    apis = [_api("lib_consume",
                 [_arg("const uint8_t *", const=True, name="data"),
                  _arg("size_t", name="len")], ret="int")]
    model = reconcile(apis)
    recs = value_intents_for_sequence(model, ["lib_consume"])
    buf = next(a["intent"] for r in recs for a in r["args"] if a["index"] == 0)
    assert "STRUCTURED_INPUT" in buf and "ICC" not in buf  # generic, no format
