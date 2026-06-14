import sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from liberator_adapter.analysis.order_sets import OrderSet, normalize_traces, minimize_traces


def test_small_dropped():
    assert OrderSet.from_sequence(["a", "b"]) == []


def test_within_bounds_single():
    r = OrderSet.from_sequence(["a", "b", "c", "d"])
    assert len(r) == 1 and r[0].order_list == ["a", "b", "c", "d"]


def test_large_splits_preserve_apis():
    seq = [f"api_{i}" for i in range(30)]
    r = OrderSet.from_sequence(seq)
    assert len(r) >= 2 and {a for o in r for a in o.unique_apis} == set(seq)


def test_minimize_covers_all():
    traces = [["a", "b", "c"], ["c", "d", "e"], ["a", "d"], ["b", "e"], ["a", "b", "c", "d", "e"]]
    m = minimize_traces(traces)
    assert {a for s in m for a in s} == {"a", "b", "c", "d", "e"} and len(m) == 1


def test_end_to_end():
    raw = [[f"api_{i}" for i in range(20)], [f"api_{i}" for i in range(10, 30)]]
    m = minimize_traces(normalize_traces(raw))
    assert {a for s in m for a in s} == {f"api_{i}" for i in range(30)}


# --------------------------------------------------------------------------
# Required canonical test names (task spec L7a)
# --------------------------------------------------------------------------

def test_split_long_order_list():
    """A 12-API order list splits into >=2 size-bounded sub-sequences,
    each with <= MAX_SIZE (10) unique APIs."""
    # 12 distinct APIs — exceeds MAX_SIZE=10, so from_sequence must split.
    seq = [f"api_{i}" for i in range(12)]
    result = OrderSet.from_sequence(seq)
    assert len(result) >= 2, "12-unique-API sequence must split into >=2 sub-sequences"
    for os_ in result:
        assert os_.size <= OrderSet.MAX_SIZE, (
            f"sub-sequence has {os_.size} unique APIs, exceeds MAX_SIZE={OrderSet.MAX_SIZE}"
        )
    # Union of all sub-sequences must recover the full API set.
    recovered = {a for o in result for a in o.unique_apis}
    assert recovered == set(seq), "split sub-sequences must cover all original APIs"


def test_minimize_is_set_cover():
    """A collection of overlapping order-sets minimizes to the fewest
    sub-collection that covers all unique API names (greedy set-cover)."""
    # Three sets; the third covers everything by itself.
    traces = [
        ["init", "open", "read"],           # covers init, open, read
        ["write", "flush", "close"],         # covers write, flush, close
        ["init", "open", "read", "write", "flush", "close"],  # covers all
    ]
    minimized = minimize_traces(traces)
    # Greedy set-cover picks the single largest set first.
    assert len(minimized) == 1, (
        f"expected 1 set-cover winner, got {len(minimized)}: {minimized}"
    )
    assert set(minimized[0]) == {"init", "open", "read", "write", "flush", "close"}


def test_end_to_end_normalize():
    """from_sequence + minimize on a small fixture yields clean bounded
    sets that together cover all input APIs."""
    # 8 unique APIs — within MAX_SIZE, so each trace stays as-is.
    fixture = [
        ["create", "configure", "open", "read"],
        ["create", "configure", "write", "flush"],
        ["open", "read", "write", "close"],
        ["create", "configure", "open", "read", "write", "flush", "close", "destroy"],
    ]
    normalized = normalize_traces(fixture)
    # Every normalized sequence must be size-bounded.
    for seq in normalized:
        assert len(set(seq)) <= OrderSet.MAX_SIZE, (
            f"normalized sequence exceeds MAX_SIZE: unique={set(seq)}"
        )
    minimized = minimize_traces(normalized)
    # The minimized collection must still cover every API present in the fixture.
    all_input_apis = {api for trace in fixture for api in trace}
    all_covered = {api for seq in minimized for api in seq}
    assert all_input_apis == all_covered, (
        f"minimize dropped APIs: missing={all_input_apis - all_covered}"
    )
