"""Per-sequence symbolic evidence for Comprehender-B (SVF⊕typestate⊕LLM).

Validates that the adjudicator prompt now carries this sequence's use-def
effects + typestate verdict (handle type + position), and that the no-graph
path is a clean no-op (regression guard).
"""
from liberator_adapter.analysis.usedef import APIEffect, UseDefGraph
from src.knowledge.comprehender import _build_sequence_facts


def _graph():
    return UseDefGraph([
        APIEffect(name="open", use=frozenset(), def_=frozenset({"H*"})),
        APIEffect(name="use", use=frozenset({"H*"}), def_=frozenset()),
        APIEffect(name="close", use=frozenset(), def_=frozenset(), kill=frozenset({"H*"})),
    ])


def test_no_graph_is_noop():
    assert _build_sequence_facts(["use"], None) == ""


def test_positive_effects_rendered_for_sequence_apis_only():
    facts = _build_sequence_facts(["open", "use"], _graph())
    assert "open: DEF {H*}" in facts
    assert "use: USE {H*}" in facts
    # close is not in the sequence -> its effect line must not appear
    # (the USE/DEF/KILL legend mentions the words; assert on the API line).
    assert "close:" not in facts


def test_typestate_violation_carries_kind_handle_and_position():
    # USE before any producer -> USE_BEFORE_INIT at position 0 on H*
    facts = _build_sequence_facts(["use"], _graph())
    assert "use_before_init" in facts
    assert "handle H*" in facts
    assert "position 0" in facts


def test_valid_lifecycle_has_no_violation_block():
    facts = _build_sequence_facts(["open", "use", "close"], _graph())
    assert "Handle effects" in facts          # positive evidence still shown
    assert "EVIDENCE to adjudicate" not in facts  # no violations -> no warning block


def test_unknown_api_skipped_gracefully():
    facts = _build_sequence_facts(["open", "not_in_graph", "use"], _graph())
    assert "not_in_graph" not in facts
    assert "open: DEF {H*}" in facts
