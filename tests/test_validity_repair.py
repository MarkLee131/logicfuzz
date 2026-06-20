"""I2a universal validity-repair: every nullable=False opaque-handle consumer
gets an earlier same-type producer, even in floor / densified sequences that
bypass _build_prefix. Gated LOGICFUZZ_VALIDITY_CONTRACT (gate-off → unchanged).

Root cause (2026-06-16): after the I3 binding fix, 130 of 137 lcms I2a orphans
were construction-gaps — consumers (105 cmsHPROFILE) with NO producer in the
driver at all, because floor/densified sequences never run _build_prefix's
producer resolution. This pass is the post-construction net.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import sequence_constructor as sc
from liberator_adapter.analysis.api_semantic_model import APIRole, ArgRole


class _Arg:
    def __init__(self, role, type_str="", nullable=True):
        self.role = role
        self.type_str = type_str
        self.nullable = nullable


class _Sem:
    def __init__(self, name, role, requires=(), produces=(), args=()):
        self.name = name
        self.role = role
        self.requires = requires
        self.produces = produces
        self.args = args


class _Idx:
    def __init__(self, producers=None, recovered=None, by_name=None):
        self.producers = producers or {}
        self.recovered_producers = recovered or {}
        self.by_name = by_name or {}


def _fixture():
    # synthetic profile creator (no INPUT_BUFFER → standalone), produces a profile
    make = _Sem("make_profile", APIRole.CREATOR, produces=("profile",), args=())
    # a parser creator of the same handle (has INPUT_BUFFER → not synthetic)
    parse = _Sem("parse_profile", APIRole.CREATOR, produces=("profile",),
                 args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    # consumer needing a NON-nullable profile handle
    use = _Sem("use_profile", APIRole.CONSUMER, requires=("profile",),
               args=(_Arg(ArgRole.HANDLE_IN, "Profile *", nullable=False),))
    # consumer needing a handle that has NO producer (genuinely unconstructable)
    orphan = _Sem("use_widget", APIRole.CONSUMER, requires=("widget",),
                  args=(_Arg(ArgRole.HANDLE_IN, "Widget *", nullable=False),))
    by_name = {s.name: s for s in (make, parse, use, orphan)}
    idx = _Idx(producers={"profile": [make, parse]}, by_name=by_name)
    return idx


def _on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_VALIDITY_CONTRACT", "1")


def test_floor_consumer_gets_producer_prepended(monkeypatch):
    _on(monkeypatch)
    idx = _fixture()
    out = sc.repair_sequence_validity(["use_profile"], idx=idx)
    # a profile producer must precede the consumer; synthetic preferred
    assert out == ["make_profile", "use_profile"]


def test_existing_producer_not_duplicated(monkeypatch):
    _on(monkeypatch)
    idx = _fixture()
    out = sc.repair_sequence_validity(["parse_profile", "use_profile"], idx=idx)
    assert out == ["parse_profile", "use_profile"]  # already satisfied, no prepend


def test_two_consumers_share_one_prepend(monkeypatch):
    _on(monkeypatch)
    idx = _fixture()
    out = sc.repair_sequence_validity(["use_profile", "use_profile"], idx=idx)
    assert out == ["make_profile", "use_profile", "use_profile"]


def test_producerless_handle_left_alone(monkeypatch):
    _on(monkeypatch)
    idx = _fixture()
    # widget has no producer in the model → no prepend (Task-11 guard covers it)
    out = sc.repair_sequence_validity(["use_widget"], idx=idx)
    assert out == ["use_widget"]


def test_nullable_handle_not_repaired(monkeypatch):
    _on(monkeypatch)
    idx = _fixture()
    # flip the consumer arg to nullable → NULL is legal, no producer needed
    idx.by_name["use_profile"].args[0].nullable = True
    out = sc.repair_sequence_validity(["use_profile"], idx=idx)
    assert out == ["use_profile"]


def test_non_handle_pointer_not_repaired(monkeypatch):
    _on(monkeypatch)
    # a CREATOR returning a string "version" (char*) is NOT a lifecycle handle —
    # no API ``requires`` it — so a consumer's non-NULL char* arg must NOT trigger
    # a producer-prepend (zlib zlibVersion / c-ares ares_library_initialized bug).
    version = _Sem("lib_version", APIRole.CREATOR, produces=("char",), args=())
    use = _Sem("use_str", APIRole.CONSUMER, requires=(),
               args=(_Arg(ArgRole.CONFIG, "char *", nullable=False),))
    by_name = {s.name: s for s in (version, use)}
    idx = _Idx(producers={"char": [version]}, by_name=by_name)
    out = sc.repair_sequence_validity(["use_str"], idx=idx)
    assert out == ["use_str"]  # char* is not a handle → renderer fills it


def test_internal_creator_never_prepended(monkeypatch):
    _on(monkeypatch)
    # only an INTERNAL (_-prefixed) producer exists → must NOT be prepended
    internal = _Sem("_make_profile", APIRole.CREATOR, produces=("profile",),
                    args=())
    use = _Sem("use_profile", APIRole.CONSUMER, requires=("profile",),
               args=(_Arg(ArgRole.HANDLE_IN, "Profile *", nullable=False),))
    by_name = {s.name: s for s in (internal, use)}
    idx = _Idx(producers={"profile": [internal]}, by_name=by_name)
    out = sc.repair_sequence_validity(["use_profile"], idx=idx)
    assert out == ["use_profile"]  # internal not linkable → guard covers it


def test_count_repairs_tallies_fired_and_prepended():
    # Breadth telemetry: count how many sequences the repair FIRES on and how
    # many producer calls it prepends in total (the A/B-confirmation signal).
    idx = _fixture()
    seqs = [
        ["use_profile"],                    # prepend make_profile -> fired, +1
        ["parse_profile", "use_profile"],   # already satisfied -> not fired
        ["use_widget"],                     # no producer in model -> not fired
        ["use_profile", "use_profile"],     # one shared prepend -> fired, +1
    ]
    stats = sc.count_repairs(seqs, idx=idx)
    assert stats["n_sequences"] == 4
    assert stats["n_repaired"] == 2
    assert stats["n_prepended"] == 2


def test_count_repairs_honors_known_names_guard():
    # Mirrors the gate's renderability guard: a repair that prepends an API NOT
    # in known_names is not counted (the gate would not materialize it either).
    idx = _fixture()
    stats = sc.count_repairs(
        [["use_profile"]], idx=idx, known_names={"use_profile"})
    assert stats["n_repaired"] == 0
    assert stats["n_prepended"] == 0


def test_prefers_synthetic_over_parser(monkeypatch):
    _on(monkeypatch)
    # producers list with parser first; synthetic must still win
    make = _Sem("make_profile", APIRole.CREATOR, produces=("profile",), args=())
    parse = _Sem("parse_profile", APIRole.CREATOR, produces=("profile",),
                 args=(_Arg(ArgRole.INPUT_BUFFER, "const uint8_t *"),))
    use = _Sem("use_profile", APIRole.CONSUMER, requires=("profile",),
               args=(_Arg(ArgRole.HANDLE_IN, "Profile *", nullable=False),))
    by_name = {s.name: s for s in (make, parse, use)}
    idx = _Idx(producers={"profile": [parse, make]}, by_name=by_name)
    out = sc.repair_sequence_validity(["use_profile"], idx=idx)
    assert out[0] == "make_profile"
