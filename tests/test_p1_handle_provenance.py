"""T5: per-API handle provenance in hole value-intents.

Tells the LLM which creator produces a required handle — or, the load-bearing
case, that NO producer exists (opaque / direct-entry) so it should construct or
NULL the handle instead of waiting for a creator that never comes (B4 #3).
"""
from liberator_adapter.analysis.hole_semantics import (
    _producer_index, _handle_provenance, value_intents_for_sequence,
)


class _Sem:
    def __init__(self, produces=(), requires=(), role="CONSUMER", args=()):
        self.produces = frozenset(produces)
        self.requires = frozenset(requires)
        self.args = list(args)
        class _R:
            value = role
        self.role = _R()


class _Model:
    def __init__(self, apis):
        self.apis = apis
    def get(self, n):
        return self.apis.get(n)


def _model():
    return _Model({
        "create": _Sem(produces={"H*"}),
        "use":    _Sem(requires={"H*"}),
        "orphan": _Sem(requires={"Opaque*"}),
        "init":   _Sem(produces={"S*"}, requires={"S*"}),  # caller-alloc self-produce
    })


def test_producer_index():
    idx = _producer_index(_model())
    assert idx["H*"] == ["create"]
    assert "Opaque*" not in idx


def test_provenance_names_the_producer():
    m = _model()
    notes = _handle_provenance(m.get("use"), "use", set(), _producer_index(m))
    assert len(notes) == 1
    # Hard guard is always on now: the note names the producer in MUST-BUILD
    # form ("call create(...)") rather than the old soft "produced by create".
    assert "create" in notes[0] and "BUILD IT" in notes[0]


def test_provenance_satisfied_earlier_is_silent():
    m = _model()
    notes = _handle_provenance(m.get("use"), "use", {"H*"}, _producer_index(m))
    assert notes == []


def test_orphan_handle_says_construct_or_null():
    m = _model()
    notes = _handle_provenance(m.get("orphan"), "orphan", set(), _producer_index(m))
    assert len(notes) == 1
    assert "NO project API produces it" in notes[0]
    assert "NULL" in notes[0]


def test_caller_alloc_self_produce_not_flagged():
    # init both requires and produces S* (in-place init) -> not an orphan.
    m = _model()
    notes = _handle_provenance(m.get("init"), "init", set(), _producer_index(m))
    assert notes == []


def test_sequence_drops_note_once_producer_runs():
    m = _model()
    recs = value_intents_for_sequence(m, ["create", "use"])
    by = {r["api"]: r for r in recs}
    # 'use' after 'create' -> provenance satisfied -> no handle_provenance
    assert "handle_provenance" not in by.get("use", {})
    # 'use' alone -> provenance present
    solo = {r["api"]: r for r in value_intents_for_sequence(m, ["use"])}
    assert "handle_provenance" in solo["use"]
