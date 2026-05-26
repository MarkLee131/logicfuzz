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


def test_scalar_config_gets_vary_range_intent():
    """The P-gen-8 fix: a scalar config hole must carry in/out-of-range intent."""
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
