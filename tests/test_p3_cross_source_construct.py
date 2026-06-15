"""Cross-source construction: for an eligible CREATOR (>=2 same-type handles),
inject a SYNTHETIC alternate producer of that type into the chain so the two
args can later bind cross-source (e.g. parsed profile + cmsCreate_sRGBProfile).
Gated `LOGICFUZZ_CROSS_SOURCE_BIND`, default-OFF (gate-off → unchanged)."""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import sequence_constructor as sc
from liberator_adapter.analysis.api_semantic_model import APIRole, ArgRole


class _Arg:
    def __init__(self, role, type_str=""):
        self.role = role
        self.type_str = type_str


class _Sem:
    def __init__(self, name, role, requires=(), args=()):
        self.name = name
        self.role = role
        self.requires = requires
        self.args = args


class _Idx:
    def __init__(self, producers=None, recovered=None):
        self.producers = producers or {}
        self.recovered_producers = recovered or {}


def _fixture():
    parser = _Sem("foo_parse", APIRole.CREATOR,
                  args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    synth = _Sem("foo_make", APIRole.CREATOR, args=())            # synthetic, no requires
    target = _Sem("foo_combine", APIRole.CREATOR,
                  args=(_Arg(ArgRole.HANDLE_IN, "Foo *"),
                        _Arg(ArgRole.HANDLE_IN, "Foo *")))
    idx = _Idx(recovered={"foo": [parser, synth]})
    return target, idx


def test_cross_source_producer_picks_synthetic_alternate():
    target, idx = _fixture()
    assert sc._cross_source_producer(target, idx) == "foo_make"


def test_cross_source_producer_none_when_no_synthetic():
    # only a parser producer → no synthetic alternate → None
    parser = _Sem("foo_parse", APIRole.CREATOR,
                  args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    target = _Sem("foo_combine", APIRole.CREATOR,
                  args=(_Arg(ArgRole.HANDLE_IN, "Foo *"),
                        _Arg(ArgRole.HANDLE_IN, "Foo *")))
    idx = _Idx(recovered={"foo": [parser]})
    assert sc._cross_source_producer(target, idx) is None


class _Model:
    def __init__(self, sems):
        self.apis = {s.name: s for s in sems}


def _full_fixture():
    parser = _Sem("foo_parse", APIRole.CREATOR,
                  args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    synth = _Sem("foo_make", APIRole.CREATOR, args=())
    target = _Sem("foo_combine", APIRole.CREATOR,
                  args=(_Arg(ArgRole.HANDLE_IN, "Foo *"),
                        _Arg(ArgRole.HANDLE_IN, "Foo *")))
    idx = _Idx(recovered={"foo": [parser, synth]})
    model = _Model([parser, synth, target])
    return model, idx


def test_inject_cross_source_inserts_synthetic_before_creator():
    model, idx = _full_fixture()
    out = sc._inject_cross_source(["foo_parse", "foo_combine"], model, idx)
    assert out == ["foo_parse", "foo_make", "foo_combine"], out
    assert out.index("foo_make") < out.index("foo_combine")


def test_inject_cross_source_idempotent_when_already_present():
    model, idx = _full_fixture()
    out = sc._inject_cross_source(
        ["foo_parse", "foo_make", "foo_combine"], model, idx)
    assert out.count("foo_make") == 1, out
    assert out == ["foo_parse", "foo_make", "foo_combine"], out


def test_inject_cross_source_noop_when_no_eligible_creator():
    # foo_combine demoted to a 1-handle CONSUMER → not cross-source → unchanged
    parser = _Sem("foo_parse", APIRole.CREATOR,
                  args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    synth = _Sem("foo_make", APIRole.CREATOR, args=())
    consumer = _Sem("foo_use", APIRole.CONSUMER,
                    args=(_Arg(ArgRole.HANDLE_IN, "Foo *"),))
    idx = _Idx(recovered={"foo": [parser, synth]})
    model = _Model([parser, synth, consumer])
    seq = ["foo_parse", "foo_use"]
    assert sc._inject_cross_source(seq, model, idx) == seq
