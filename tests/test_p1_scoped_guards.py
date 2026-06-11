"""Pin the B+D structural fix (LOGICFUZZ_SCOPED_GUARDS) that stops INDEPENDENT
APIs from being gated behind a failing input-parser.

Root cause (confirmed): ``_densify``'s co-occurrence branch appends an
INDEPENDENT scalar-only producer (e.g. ``cmsCreateBCHSWabstractProfile``,
``requires = ∅`` so ``∅ <= opened`` is trivially True) into a parser's chain.
The skeleton then renders the parser's HARD-NULLGUARD ``if (ret_parser == NULL)
return 0;`` BEFORE the independent producer → on random input the parser is ~always
NULL → the whole driver bails → the param-rich independent APIs never run.

The fix (gated, default-OFF):
  D — ``construct_sequences`` reorders a constructed ``core`` so dependency
      components are contiguous (shared helper ``_dependency_components``).
  B — ``skeleton_generator`` renders component-scoped NULL guards (B1 nested-if):
      a producer's failure only skips ITS dependents, the independent component
      renders OUTSIDE that ``if``.

Gate-OFF must be byte-identical to the legacy path; the rest of the suite pins
that. These tests pin the gate-ON contract + the shared helper.
"""
from __future__ import annotations

import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _dependency_components, _scoped_guards, construct_sequences,
)


# --------------------------------------------------------------------------- helpers

class _StubSem:
    def __init__(self, produces, requires):
        self.produces = frozenset(produces)
        self.requires = frozenset(requires)


class _StubModel:
    def __init__(self, apis):
        self.apis = apis


def _make_arg(name: str, type_str: str, is_const: bool = False):
    from liberator_adapter.common.api import Arg
    return Arg(name=name, flag="", size=0, type=type_str,
               is_const=[is_const], is_type_incomplete=False)


def _make_api(name: str, ret_type: str, args):
    from liberator_adapter.common.api import Api
    return Api(function_name=name, is_vararg=False,
              return_info=_make_arg("return", ret_type),
              arguments_info=args, namespace=[])


# --------------------------------------------------------------------------- _dependency_components

def test_dependency_components_archetype_splits_independent():
    """The lcms archetype: parser + its two consumers form ONE component; each
    independent cmsCreate* (scalar-only requires) starts its OWN component →
    ≥2 components, with the parser block first."""
    model = _StubModel({
        "cmsOpenProfileFromMem": _StubSem(["profile"], []),
        "cmsIsTag": _StubSem([], ["profile"]),
        "cmsGetColorSpace": _StubSem([], ["profile"]),
        "cmsCreateBCHSWabstractProfile": _StubSem(["abstract"], []),
        "cmsCreateXYZProfile": _StubSem(["xyz"], []),
    })
    seq = ["cmsOpenProfileFromMem", "cmsIsTag", "cmsGetColorSpace",
           "cmsCreateBCHSWabstractProfile", "cmsCreateXYZProfile"]
    comps = _dependency_components(seq, model)

    assert len(comps) >= 2
    # Component 1 = parser + its consumers (data-dependent on the profile).
    assert comps[0] == ["cmsOpenProfileFromMem", "cmsIsTag", "cmsGetColorSpace"]
    # The independent producers are NOT in the parser's component.
    assert ["cmsCreateBCHSWabstractProfile"] in comps
    assert ["cmsCreateXYZProfile"] in comps
    # No API dropped; concatenation == input (contiguous slices in order).
    assert [a for c in comps for a in c] == seq


def test_dependency_components_single_chain_is_one_component():
    """A fully data-dependent chain (create → use → free over one handle) is a
    single component — nothing to split."""
    model = _StubModel({
        "thing_create": _StubSem(["thing"], []),
        "thing_use": _StubSem([], ["thing"]),
        "thing_free": _StubSem([], ["thing"]),
    })
    comps = _dependency_components(
        ["thing_create", "thing_use", "thing_free"], model)
    assert comps == [["thing_create", "thing_use", "thing_free"]]


def test_dependency_components_non_adjacent_consumer_joins_producer():
    """Regression (the greedy-contiguous bug): a consumer that appears AFTER an
    INDEPENDENT producer must still join its OWN producer's component
    (transitive connected-components / most-recent-producer binding), NOT start a
    spurious new component. Under the greedy partition it started its own
    component → in scoped-guard rendering it ran OUTSIDE its producer's NULL
    guard (use-before-check). The fix groups it with its producer (reordering
    the interleaved independent out)."""
    model = _StubModel({
        "make_a": _StubSem(["A"], []),     # produces handle A
        "make_b": _StubSem(["B"], []),     # INDEPENDENT producer, interleaved
        "use_a": _StubSem([], ["A"]),      # consumes A — appears AFTER make_b
    })
    comps = _dependency_components(["make_a", "make_b", "use_a"], model)
    a_comp = next(c for c in comps if "make_a" in c)
    assert "use_a" in a_comp, f"use_a must join make_a's component; got {comps}"
    assert ["make_b"] in comps           # the independent producer stays separate
    # Components are grouped contiguously: make_b reorders out of make_a's block.
    assert comps == [["make_a", "use_a"], ["make_b"]]


def test_dependency_components_same_type_independent_producer_not_merged():
    """A second producer of the SAME handle TYPE that nothing downstream consumes
    must NOT be merged into the consumer's component (most-recent-producer rule,
    not type-wide union) — else an independent same-type cmsCreate* would render
    inside the parser's guard."""
    model = _StubModel({
        "open_profile": _StubSem(["hprofile"], []),       # parser
        "use_profile": _StubSem([], ["hprofile"]),        # consumes parser's handle
        "create_profile": _StubSem(["hprofile"], []),     # INDEPENDENT, same type
    })
    comps = _dependency_components(
        ["open_profile", "use_profile", "create_profile"], model)
    assert comps == [["open_profile", "use_profile"], ["create_profile"]]


def test_dependency_components_handles_unknown_and_empty():
    """Names absent from the model contribute no handle edges (scalar-only →
    independent); empties are skipped; partition stays robust."""
    model = _StubModel({"a": _StubSem(["h"], []), "b": _StubSem([], ["h"])})
    comps = _dependency_components(["a", "", "b", "unknown"], model)
    # a opens h, b consumes h (same comp); unknown is independent.
    assert comps == [["a", "b"], ["unknown"]]


# --------------------------------------------------------------------------- _scoped_guards gate

def test_scoped_guards_gate_default_off():
    os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)
    assert _scoped_guards() is False


def test_scoped_guards_gate_on():
    os.environ["LOGICFUZZ_SCOPED_GUARDS"] = "1"
    try:
        assert _scoped_guards() is True
    finally:
        os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)


# --------------------------------------------------------------------------- B: skeleton render

def _archetype_apis():
    """parser (produces handle) → consumer (requires it) → independent producer
    (produces its own handle, scalar-only args)."""
    # Single-pointer handle type so the signature-derived model links the
    # consumer's arg to the parser's return (mirrors lcms ``cmsHPROFILE`` whose
    # IR carries a pointer in arg/return position).
    parser = _make_api(
        "cmsOpenProfileFromMem", "cmsHPROFILE*",
        [_make_arg("mem", "const void*", True), _make_arg("size", "unsigned int")])
    consumer = _make_api(
        "cmsGetColorSpace", "int", [_make_arg("hProfile", "cmsHPROFILE*")])
    indep = _make_api(
        "cmsCreateBCHSWabstractProfile", "cmsHPROFILE*",
        [_make_arg("nLUTPoints", "int"), _make_arg("Bright", "double")])
    return parser, consumer, indep


def _render(apis):
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator, SkeletonRenderer,
    )
    sk = SkeletonGenerator().generate(
        api_sequence=list(apis), driver_name="t", is_cpp=False)
    return SkeletonRenderer().render(sk)


def _line_indent(code: str, needle: str) -> int:
    for line in code.splitlines():
        if needle in line:
            return len(line) - len(line.lstrip())
    raise AssertionError(f"{needle!r} not found in:\n{code}")


def test_scoped_render_independent_call_outside_parser_guard():
    """Gate-ON: the independent producer's call is NOT gated by the parser's
    NULL guard — no whole-driver ``return 0`` and the independent call is at
    function scope (NOT nested inside the parser's ``if`` block)."""
    os.environ["LOGICFUZZ_SCOPED_GUARDS"] = "1"
    try:
        code = _render(_archetype_apis())
    finally:
        os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)

    # No whole-driver bail on a producer return.
    assert "if (ret_cmsOpenProfileFromMem == NULL) return 0;" not in code
    assert "if (ret_cmsCreateBCHSWabstractProfile == NULL) return 0;" not in code
    # Parser's consumer is scoped to the parser's success.
    assert "if (ret_cmsOpenProfileFromMem != NULL) {" in code
    # The consumer (cmsGetColorSpace) is nested (deeper indent than the guard).
    guard_indent = _line_indent(code, "if (ret_cmsOpenProfileFromMem != NULL) {")
    consumer_indent = _line_indent(code, "cmsGetColorSpace(")
    assert consumer_indent > guard_indent
    # The INDEPENDENT producer renders at the SAME (function) scope as the guard,
    # i.e. OUTSIDE it — it runs regardless of the parser's failure.
    indep_indent = _line_indent(code, "cmsCreateBCHSWabstractProfile(")
    assert indep_indent == guard_indent

    # Structural proof: the independent call must appear AFTER the parser
    # component's closing brace, not between the `{` and its matching `}`.
    lines = code.splitlines()
    open_i = next(i for i, l in enumerate(lines)
                  if "if (ret_cmsOpenProfileFromMem != NULL) {" in l)
    # the matching close is the first '}' at the guard indent after open_i
    close_i = next(i for i in range(open_i + 1, len(lines))
                   if lines[i].strip() == "}"
                   and (len(lines[i]) - len(lines[i].lstrip())) == guard_indent)
    indep_i = next(i for i, l in enumerate(lines)
                   if "cmsCreateBCHSWabstractProfile(" in l and l.strip().startswith("ret_"))
    assert indep_i > close_i, (
        "independent producer must render after the parser guard block closes")


def test_gate_off_keeps_legacy_whole_driver_bail():
    """Gate-OFF: byte-identical legacy behavior — the parser emits the
    whole-driver ``if (ret == NULL) return 0;`` and there is NO component-scoped
    ``!= NULL`` block. This is the bug the fix targets, preserved off-gate."""
    os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)
    code = _render(_archetype_apis())
    assert "if (ret_cmsOpenProfileFromMem == NULL) return 0;" in code
    assert "if (ret_cmsOpenProfileFromMem != NULL) {" not in code


def test_scoped_render_uses_threaded_dep_model_over_signature_heuristic():
    """Phase 3.1B: when the reconcile model is threaded into generate(dep_model=),
    render-B partitions with IT — not the pointer-count _build_signature_model
    heuristic. A consumer taking the handle as a DOUBLE pointer (``Handle**``,
    which the heuristic's ``count('*')==1`` test MISSES) must still be grouped
    into — and NULL-guarded under — its producer's component via the threaded
    model. Without the model the heuristic splits it → it renders UNGUARDED."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator, SkeletonRenderer)
    parser = _make_api("p_open", "Handle*", [_make_arg("m", "const void*", True)])
    consumer = _make_api("p_use", "int", [_make_arg("h", "Handle**")])  # double ptr
    dep = _StubModel({"p_open": _StubSem(["handle"], []),
                      "p_use": _StubSem([], ["handle"])})

    def _render_dm(dm):
        os.environ["LOGICFUZZ_SCOPED_GUARDS"] = "1"
        try:
            sk = SkeletonGenerator().generate(
                api_sequence=[parser, consumer], driver_name="t",
                is_cpp=False, dep_model=dm)
            return SkeletonRenderer().render(sk)
        finally:
            os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)

    def _consumer_inside_guard(code: str) -> bool:
        lines = code.splitlines()
        gi = next((i for i, l in enumerate(lines)
                   if "if (ret_p_open != NULL) {" in l), None)
        if gi is None:
            return False
        close = next((i for i in range(gi + 1, len(lines))
                      if lines[i].strip() == "}"), len(lines))
        ci = next((i for i, l in enumerate(lines)
                   if "p_use(" in l and l.strip().startswith("ret_")), None)
        return ci is not None and gi < ci < close

    assert _consumer_inside_guard(_render_dm(dep)), \
        "threaded reconcile model must group + guard the double-ptr consumer"
    assert not _consumer_inside_guard(_render_dm(None)), \
        "the signature heuristic misses the double-ptr edge (the divergence)"


# --------------------------------------------------------------------------- D: construct reorder

def test_construct_reorders_components_gate_on():
    """Gate-ON D: ``construct_sequences`` reorders so dependency components are
    contiguous. We use a stub APISemanticModel built from real apis and assert
    that for any constructed sequence, no API that is independent of an earlier
    handle is interleaved between that handle's producer and consumers — i.e.
    the sequence equals the concatenation of its own dependency components."""
    from liberator_adapter.analysis.api_semantic_model import reconcile

    apis = [
        {"function_name": "thing_create", "arguments": [],
         "return_type": "Thing *", "is_vararg": False, "namespace": []},
        {"function_name": "thing_use",
         "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"},
                       {"type": "const uint8_t *", "is_const": [True], "name": "data"},
                       {"type": "size_t", "is_const": [False], "name": "len"}],
         "return_type": "int", "is_vararg": False, "namespace": []},
        {"function_name": "thing_free",
         "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"}],
         "return_type": "void", "is_vararg": False, "namespace": []},
    ]
    model = reconcile(apis)

    os.environ["LOGICFUZZ_SCOPED_GUARDS"] = "1"
    try:
        res = construct_sequences(model)
    finally:
        os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)

    assert res.sequences
    for seq in res.sequences:
        comps = _dependency_components(seq, model)
        assert [a for c in comps for a in c] == list(seq)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
