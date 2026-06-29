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
    out = _densify(["create"], {"H"}, idx, max_extra=4)
    assert "mutate" in out and "get" in out
    assert out.index("mutate") < out.index("get")   # mutator before getter


def test_skips_extender_needing_an_unopened_handle():
    needs2 = _S("needs2", APIRole.CONSUMER, requires={"H", "H2"})  # H2 not open
    idx = _idx(consumers=[needs2], consumers_by_handle={"H": [needs2]})
    out = _densify(["create"], {"H"}, idx, max_extra=4)
    assert "needs2" not in out   # requires ⊄ opened → would add an unmet handle


def test_caps_at_max_extra():
    cons = [_S(f"c{i}", APIRole.CONSUMER, requires={"H"}) for i in range(6)]
    idx = _idx(consumers=cons, consumers_by_handle={"H": cons})
    out = _densify(["create"], {"H"}, idx, max_extra=2)
    assert len(out) == 3   # core(1) + 2 extra


def test_no_candidates_returns_core_unchanged():
    out = _densify(["create"], {"H"}, _idx(), max_extra=4)
    assert out == ["create"]


def test_does_not_duplicate_apis_already_in_core():
    mut = _S("mutate", APIRole.MUTATOR, requires={"H"})
    idx = _idx(mutators={"H": [mut]})
    out = _densify(["create", "mutate"], {"H"}, idx, max_extra=4)
    assert out.count("mutate") == 1


def test_cooccurrence_pulls_in_related_api_without_shared_handle():
    # A standalone API that CO-OCCURS in a real path but shares no open handle
    # is pulled in (PromeFuzz call-scope/semantic grouping), not just handle users.
    mut = _S("mutate", APIRole.MUTATOR, requires={"H"})
    related = _S("related_op", APIRole.CONSUMER, requires=())   # no handle dep
    idx = _idx(mutators={"H": [mut]}, by_name={"mutate": mut, "related_op": related})
    cooccur = {"create": {"related_op"}}     # real path: create used with related_op
    out = _densify(["create"], {"H"}, idx, max_extra=4, cooccur=cooccur)
    assert "related_op" in out and "mutate" in out


def test_cooccurrence_skips_api_needing_unproducible_nonorphan_handle():
    # A co-occurring API needing a handle that HAS a producer (not open, not orphan)
    # is skipped — keeping the chain ordering-clean (only orphan deps become holes).
    needs = _S("needs_h2", APIRole.CONSUMER, requires={"H2"})
    idx = _idx(producers={"H2": [_S("mk_h2", APIRole.CREATOR, produces={"H2"})]},
               by_name={"needs_h2": needs})
    out = _densify(["create"], {"H"}, idx, max_extra=4,
                   cooccur={"create": {"needs_h2"}})
    assert "needs_h2" not in out
