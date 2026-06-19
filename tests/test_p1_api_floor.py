"""API-floor pass in coverage-complete selection (L7b).

LOGICFUZZ_API_FLOOR is DEFAULT-ON (graduated 2026-06-20). The ranker adds a
post-cover greedy pass that ensures EVERY API present anywhere in the candidate
pool is covered by at least one selected sequence — even APIs that live in a
cluster that was already covered by a different sequence that didn't include them.
Opt-out: LOGICFUZZ_API_FLOOR=0.

Gate OFF (=0) → no 'api_floor_residual_count' key in summary stats.
Gate ON (default / =1) → every pool API covered, api_floor_residual_count == 0.
"""
import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.constraints.coverage_ranker import (  # noqa: E402
    select_top_k_sequences,
)

# Setup:
#   Cluster A has two APIs: "make_a" and "api_orphan".
#   The cluster-cover phase will select ["make_a", "use_a"] to cover cluster A.
#   That leaves "api_orphan" (also in cluster A) uncovered.
#   Cluster B has one covering sequence.
#   "api_orphan" only appears in the separate sequence ["make_a", "api_orphan"].
_CLUSTERS = {
    "make_a": "A",
    "use_a": "A",
    "api_orphan": "A",  # same cluster as make_a/use_a
    "make_b": "B",
    "use_b": "B",
}

_SEQS = [
    ["make_a", "use_a"],           # covers cluster A (first visited in rank order)
    ["make_b", "use_b"],           # covers cluster B
    ["make_a", "api_orphan"],      # also cluster A, but api_orphan never covered above
]


def _all_pool_apis(selected, seqs=_SEQS):
    pool = {a for s in seqs for a in s}
    covered = {a for s in selected for a in s}
    return pool, covered


def setup_function(_):
    os.environ.pop("LOGICFUZZ_API_FLOOR", None)
    # Force complete mode so cluster-cover phase is active.
    os.environ["LOGICFUZZ_PORTFOLIO"] = "complete"


def _set_gate_off():
    """Explicitly opt-out of API_FLOOR (now default-ON) to test the OFF baseline."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "0"


def teardown_function(_):
    os.environ.pop("LOGICFUZZ_API_FLOOR", None)
    os.environ.pop("LOGICFUZZ_PORTFOLIO", None)


# ---------------------------------------------------------------------------
# Gate OFF: the key must NOT appear (old behavior unchanged)
# ---------------------------------------------------------------------------

def test_gate_off_no_floor_key():
    """When LOGICFUZZ_API_FLOOR=0 the summary stats must not contain
    api_floor_residual_count so callers that don't expect the key are
    unaffected."""
    _set_gate_off()  # explicit opt-out (gate is now default-ON)
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    stats = summary["stats"]
    assert "api_floor_residual_count" not in stats, (
        "Floor key must not appear when gate is OFF; got: " + str(stats)
    )


def test_gate_off_orphan_may_be_uncovered():
    """Gate OFF: api_orphan is not guaranteed to be selected — the cluster-cover
    phase chose a *different* A-cluster sequence, so api_orphan can remain
    uncovered.  (This test documents the pre-floor baseline, not a failure.)"""
    _set_gate_off()  # explicit opt-out (gate is now default-ON)
    selected, _ = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    pool, covered = _all_pool_apis(selected)
    # We do NOT assert api_orphan is covered here — that's the problem the floor
    # pass solves.  Just assert we got the cluster-cover minimum.
    assert "make_a" in covered
    assert "use_a" in covered
    assert "make_b" in covered
    assert "use_b" in covered


# ---------------------------------------------------------------------------
# Gate ON: every pool API must be covered; residual count == 0
# ---------------------------------------------------------------------------

def test_gate_on_floor_key_present():
    """When LOGICFUZZ_API_FLOOR=1 the summary stats must expose
    api_floor_residual_count."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    stats = summary["stats"]
    assert "api_floor_residual_count" in stats, (
        "api_floor_residual_count must appear in stats when gate is ON"
    )


def test_gate_on_api_orphan_covered():
    """Gate ON: api_orphan (only in the third sequence, not picked by
    cluster-cover) must appear in the final selected set."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    covered = {a for s in selected for a in s}
    assert "api_orphan" in covered, (
        f"api_orphan not covered; selected={selected}"
    )


def test_gate_on_residual_zero():
    """Gate ON: api_floor_residual_count must be 0 (all pool APIs covered)."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    stats = summary["stats"]
    assert stats["api_floor_residual_count"] == 0, (
        f"Expected residual 0, got {stats['api_floor_residual_count']}; "
        f"stats={stats}"
    )


def test_gate_on_api_floor_added_positive():
    """Gate ON: api_floor_added must be >= 1 (the third sequence was added)."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    stats = summary["stats"]
    assert stats.get("api_floor_added", 0) >= 1, (
        f"Expected at least 1 floor-added driver; stats={stats}"
    )


def test_gate_on_all_pool_apis_covered():
    """Gate ON: the union of selected sequences must cover every API in the pool."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    selected, summary = select_top_k_sequences(
        _SEQS, top_k=99, clusters=_CLUSTERS,
    )
    pool = {a for s in _SEQS for a in s}
    covered = {a for s in selected for a in s}
    uncovered = pool - covered
    assert not uncovered, (
        f"APIs in pool but not covered: {uncovered}; selected={selected}"
    )


# ---------------------------------------------------------------------------
# Regression: gate ON with no orphan → residual still 0, no extra sequences
# ---------------------------------------------------------------------------

def test_gate_on_no_orphan_no_extra():
    """When all pool APIs are already covered by the cluster-cover phase,
    the floor pass adds nothing extra."""
    os.environ["LOGICFUZZ_API_FLOOR"] = "1"
    # Pool where each cluster sequence covers all its APIs completely.
    seqs = [["make_a", "use_a"], ["make_b", "use_b"]]
    clusters = {"make_a": "A", "use_a": "A", "make_b": "B", "use_b": "B"}
    selected, summary = select_top_k_sequences(seqs, top_k=99, clusters=clusters)
    stats = summary["stats"]
    assert stats["api_floor_residual_count"] == 0
    assert stats.get("api_floor_added", 0) == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
