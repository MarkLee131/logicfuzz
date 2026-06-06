"""LOGICFUZZ_DENSE_CONSTRUCT: thicken thin lifecycle chains with extenders that
USE already-open handles (mutator*->consumer*->getter*), bounded + ordering-safe."""
from liberator_adapter.analysis.sequence_constructor import _densify, _Index
from liberator_adapter.analysis.api_semantic_model import APIRole


class _S:
    def __init__(self, name, role, requires=(), produces=(), args=()):
        self.name = name
        self.role = role
        self.requires = frozenset(requires)
        self.produces = frozenset(produces)
        self.args = list(args)


def _idx(**kw):
    base = dict(producers={}, destroyers={}, mutators={}, entries=[],
                consumers=[], creators=[], consumers_by_handle={}, getters={})
    base.update(kw)
    return _Index(**base)


def test_appends_open_handle_users_in_canonical_order():
    mut = _S("mutate", APIRole.MUTATOR, requires={"H"})
    get = _S("get", APIRole.CONSUMER, requires={"H"})   # getter (no produces)
    idx = _idx(mutators={"H": [mut]}, consumers_by_handle={"H": [get]},
               getters={"H": [get]})
    out = _densify(["create"], {"H"}, idx, max_extra=4, repeat=False)
    assert "mutate" in out and "get" in out
    assert out.index("mutate") < out.index("get")   # mutator before getter


def test_skips_extender_needing_an_unopened_handle():
    needs2 = _S("needs2", APIRole.CONSUMER, requires={"H", "H2"})  # H2 not open
    idx = _idx(consumers=[needs2], consumers_by_handle={"H": [needs2]})
    out = _densify(["create"], {"H"}, idx, max_extra=4, repeat=False)
    assert "needs2" not in out   # requires ⊄ opened → would add an unmet handle


def test_caps_at_max_extra():
    cons = [_S(f"c{i}", APIRole.CONSUMER, requires={"H"}) for i in range(6)]
    idx = _idx(consumers=cons, consumers_by_handle={"H": cons})
    out = _densify(["create"], {"H"}, idx, max_extra=2, repeat=False)
    assert len(out) == 3   # core(1) + 2 extra


def test_no_candidates_returns_core_unchanged():
    out = _densify(["create"], {"H"}, _idx(), max_extra=4, repeat=False)
    assert out == ["create"]


def test_does_not_duplicate_apis_already_in_core():
    mut = _S("mutate", APIRole.MUTATOR, requires={"H"})
    idx = _idx(mutators={"H": [mut]})
    out = _densify(["create", "mutate"], {"H"}, idx, max_extra=4, repeat=False)
    assert out.count("mutate") == 1
