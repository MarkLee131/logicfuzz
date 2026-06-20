"""Task 7 — I1 (lifecycle order): every producer is emitted BEFORE its
consumers in a constructed sequence (no use-before-produce / close-before-open).
The validity contract is unconditional (graduated 2026-06-20, switch removed).
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole, ArgRole, ArgSemantics,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _enforce_producer_order, _build_index, construct_sequences,
)


def _arg(i, role, t="void", nullable=False):
    return ArgSemantics(index=i, role=role, type_str=t, nullable=nullable)


def _api(name, role, produces=(), requires=(), destroys=(), args=()):
    return APISemantics(
        name=name, role=role, role_confidence=0.9, args=tuple(args),
        produces=frozenset(produces), requires=frozenset(requires),
        destroys=frozenset(destroys),
    )


# A creator that produces a handle, a consumer that requires it, a destroyer.
CREATE = _api("makeProfile", APIRole.CREATOR, produces={"hprofile*"})
USE = _api(
    "useProfile", APIRole.CONSUMER, requires={"hprofile*"},
    args=(_arg(0, ArgRole.HANDLE_IN, "cmsHPROFILE"),),
)
CLOSE = _api("freeProfile", APIRole.DESTROYER, destroys={"hprofile*"},
             args=(_arg(0, ArgRole.HANDLE_IN, "cmsHPROFILE"),))

MODEL = APISemanticModel(project="t", apis={
    s.name: s for s in (CREATE, USE, CLOSE)})


def test_enforce_producer_order_moves_consumer_after_producer():
    idx = _build_index(MODEL)
    # consumer BEFORE its producer (use-before-produce)
    out = _enforce_producer_order(["useProfile", "makeProfile"], idx)
    assert out.index("makeProfile") < out.index("useProfile")


def test_enforce_producer_order_is_stable_when_already_ordered():
    idx = _build_index(MODEL)
    seq = ["makeProfile", "useProfile", "freeProfile"]
    assert _enforce_producer_order(seq, idx) == seq


def test_construct_gate_on_produces_ordered_sequences():
    res = construct_sequences(MODEL)
    seqs = res.sequences if hasattr(res, "sequences") else res
    # every sequence that contains both producer and consumer has them ordered
    for s in seqs:
        if "makeProfile" in s and "useProfile" in s:
            assert s.index("makeProfile") < s.index("useProfile")
