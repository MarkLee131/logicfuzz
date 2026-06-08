"""Unit tests for the transitive factory-chain recovery (LOGICFUZZ_FACTORY_CHAIN).

Covers: default-off no-op, transitive deep chaining of return-by-value opaque
typedef handles, byte-opener / deep-dependency preference, cycle termination,
pointer-leaf exclusion, and the camelCase word-boundary that rejects naming
false positives (handle ⊄ Handler).
"""
import pytest

from liberator_adapter.analysis.api_semantic_model import (
    APIRole, ArgRole, ArgSemantics, APISemantics, APISemanticModel,
)
from liberator_adapter.analysis.sequence_constructor import (
    _build_index, _build_prefix, _closing_destroyers, _word_in_name,
    _opaque_stems, _detect_lib_prefix,
)


def _api(name, role, produces=(), requires=(), destroys=(), input_buf=False):
    args = ()
    if input_buf:
        args = (ArgSemantics(0, ArgRole.INPUT_BUFFER, "void *"),
                ArgSemantics(1, ArgRole.LENGTH, "unsigned int"))
    return APISemantics(
        name=name, role=role, role_confidence=0.9, args=args,
        produces=frozenset(produces), requires=frozenset(requires),
        destroys=frozenset(destroys),
    )


def _model(*apis):
    return APISemanticModel(project="lib", apis={a.name: a for a in apis})


# A canonical opaque-handle library: typedef void* libHPROFILE / libHTRANSFORM,
# so the creators' `produces` is empty (IR desugars void* return) and only the
# consumer's `requires` records the handle type.
def _profile_transform_model():
    return _model(
        _api("libOpenProfileFromMem", APIRole.CREATOR, input_buf=True),
        _api("libCreateProfile", APIRole.CREATOR),
        _api("libCreateTransform", APIRole.CREATOR, requires={"libhprofile"}),
        _api("libDoTransform", APIRole.CONSUMER, requires={"libhtransform"}),
        _api("libDeleteTransform", APIRole.DESTROYER, destroys={"libhtransform"}),
    )


@pytest.fixture
def factory_on(monkeypatch):
    # Factory chain is always on now (gate removed); kept as a no-op anchor.
    monkeypatch.setenv("LOGICFUZZ_FACTORY_CHAIN", "1")


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------

def test_detect_lib_prefix():
    assert _detect_lib_prefix(
        ["cmsCreateTransform", "cmsDoTransform", "cmsOpenProfile"]) == "cms"
    assert _detect_lib_prefix([]) == ""


def test_opaque_stems_strips_prefix_and_h():
    assert set(_opaque_stems("cmshtransform", "cms")) == {"htransform", "transform"}
    assert set(_opaque_stems("cmshprofile", "cms")) == {"hprofile", "profile"}
    # too short after stripping -> no stem (avoids spurious matches)
    assert _opaque_stems("cmshfoo", "cms") == []


def test_word_boundary_accepts_camel_word():
    assert _word_in_name("transform", "cmsCreateTransform")
    assert _word_in_name("profile", "cmsOpenProfileFromMem")


def test_word_boundary_rejects_handler_and_substring():
    # "handle" inside "Handler" (trailing 'r') must NOT match.
    assert not _word_in_name("handle", "cmsSetLogErrorHandler")
    # "profile" inside "Multiprofile" (leading lowercase) must NOT match.
    assert not _word_in_name("profile", "cmsCreateMultiprofile")


# ---------------------------------------------------------------------------
# Recovery behaviour
# ---------------------------------------------------------------------------

def test_transitive_deep_chain(factory_on):
    m = _profile_transform_model()
    idx = _build_index(m)
    assert set(idx.recovered_producers) == {"libhprofile", "libhtransform"}
    pre, opened = _build_prefix(m.apis["libDoTransform"], idx, 6)
    # Deep-first: open the profile, build the transform from it, then DoTransform.
    assert pre == ["libOpenProfileFromMem", "libCreateTransform"]
    assert {"libhprofile", "libhtransform"} <= opened
    # Recovered handle gets a closing destroyer (opened.add(t) fix).
    assert _closing_destroyers(opened, idx) == ["libDeleteTransform"]


def test_prefers_byte_opener_over_synthetic(factory_on):
    # libOpenProfileFromMem (INPUT_BUFFER) must beat libCreateProfile (synthetic).
    m = _profile_transform_model()
    idx = _build_index(m)
    pre, _ = _build_prefix(m.apis["libCreateTransform"], idx, 6)
    assert pre == ["libOpenProfileFromMem"]


def test_prefers_deep_dependency_over_empty_factory(factory_on):
    # Two transform factories: one requires a (recoverable) profile -> genuinely
    # deep; one requires nothing -> would return NULL. Prefer the deep one.
    m = _model(
        _api("libOpenProfileFromMem", APIRole.CREATOR, input_buf=True),
        _api("libCreateTransform", APIRole.CREATOR, requires={"libhprofile"}),
        _api("libAllocTransform", APIRole.CREATOR),  # no inputs -> NULL risk
        _api("libDoTransform", APIRole.CONSUMER, requires={"libhtransform"}),
    )
    idx = _build_index(m)
    pre, _ = _build_prefix(m.apis["libDoTransform"], idx, 6)
    assert pre == ["libOpenProfileFromMem", "libCreateTransform"]


def test_cycle_terminates(factory_on):
    # A factory that requires its own product must not recurse infinitely.
    m = _model(
        _api("cycCreateWidget", APIRole.CREATOR, requires={"cychwidget"}),
        _api("cycUseWidget", APIRole.CONSUMER, requires={"cychwidget"}),
    )
    idx = _build_index(m)
    assert "cychwidget" in idx.recovered_producers
    pre, opened = _build_prefix(m.apis["cycUseWidget"], idx, 6)
    assert pre == ["cycCreateWidget"]      # placed once, no loop
    assert "cychwidget" in opened


def test_pointer_leaf_not_recovered(factory_on):
    # A required POINTER type (caller-allocated struct/scalar) is a leaf, not a
    # factory handle -> stays a hole even with a name-matching creator present.
    m = _model(
        _api("libCreateWidget", APIRole.CREATOR),
        _api("libUseWidget", APIRole.CONSUMER, requires={"libwidget*"}),
    )
    idx = _build_index(m)
    assert "libwidget*" not in idx.recovered_producers
    pre, opened = _build_prefix(m.apis["libUseWidget"], idx, 6)
    assert pre == []
    assert opened == set()


def test_depth_bound_respected(factory_on):
    # max_depth=0 stops recursion immediately: the top opaque arg still resolves
    # (depth 0) but its sub-dependency (depth 1 > 0) is left a hole.
    m = _profile_transform_model()
    idx = _build_index(m)
    pre, opened = _build_prefix(m.apis["libDoTransform"], idx, 0)
    assert pre == ["libCreateTransform"]      # profile sub-dep not chained
    assert "libhtransform" in opened
    assert "libhprofile" not in opened
