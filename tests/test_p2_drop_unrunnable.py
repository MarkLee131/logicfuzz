"""Mode C — construct_sequences must not SHIP a guaranteed-NULL-bail sequence.

A sequence in which every call is an unsatisfied-handle consumer (its handle
args render NULL → the call returns NULL → the next bails) is an edges=0 driver.
Drop it at construction so the portfolio slot goes to a runnable sequence instead.
Every shipped sequence must contain >=1 runnable anchor (a CREATOR/opaque builder,
a fuzz INPUT_BUFFER, or an in-sequence-satisfiable consumer).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    construct_sequences,
)

# Mode C is opt-in (LOGICFUZZ_DROP_UNRUNNABLE); enable it for these tests.


def setup_function(_):
    os.environ["LOGICFUZZ_DROP_UNRUNNABLE"] = "1"


def teardown_function(_):
    os.environ.pop("LOGICFUZZ_DROP_UNRUNNABLE", None)

_APIS = [
    {"function_name": "thing_create", "arguments": [],
     "return_type": "Thing *", "is_vararg": False, "namespace": []},
    {"function_name": "thing_use",
     "arguments": [{"type": "Thing *", "is_const": [False], "name": "t"}],
     "return_type": "int", "is_vararg": False, "namespace": []},
    {"function_name": "orphan_use",       # requires a handle NO api produces
     "arguments": [{"type": "Orphan *", "is_const": [False], "name": "o"}],
     "return_type": "int", "is_vararg": False, "namespace": []},
]


def _runnable_over_output(seq, model):
    """Mirror of the construction guard, checked over a SHIPPED sequence: a
    consumer is satisfiable iff its required handles are produced earlier IN the
    sequence (the constructor prepends the producer)."""
    produced = set()
    for n in seq:
        s = model.apis.get(n)
        if s is None:
            continue
        if any(a.role.name == "INPUT_BUFFER" for a in s.args):
            return True
        if s.role.name == "CREATOR" or s.produces:
            return True
        if set(s.requires) <= produced:
            return True
        produced |= set(s.produces)
    return False


def test_no_shipped_sequence_is_all_unrunnable():
    model = reconcile(_APIS)
    res = construct_sequences(model)
    assert res.sequences
    for seq in res.sequences:
        assert _runnable_over_output(seq, model), \
            f"shipped a guaranteed-bail sequence: {list(seq)}"


def test_orphan_consumer_only_is_dropped_creator_survives():
    model = reconcile(_APIS)
    res = construct_sequences(model)
    # the standalone orphan consumer (no producer for its handle) is never shipped
    assert ["orphan_use"] not in [list(s) for s in res.sequences]
    # the creator-anchored work survives
    assert any("thing_create" in s for s in res.sequences)
    # the drop is metered (no silent cap)
    assert "n_dropped_unrunnable" in res.metrics
