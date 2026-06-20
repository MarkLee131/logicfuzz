"""Coverage-complete selection (the objective swap, stage 2).

The legacy objective ranks globally and takes top_k, so subsystems beyond the
top_k are never selected (the lcms root cause). Coverage-complete selection
guarantees >=1 selected sequence per SUBSYSTEM CLUSTER present in the pool,
THEN a bounded depth pass — independent of top_k. UNCONDITIONAL: the
LOGICFUZZ_PORTFOLIO on/off/minimal switch was removed (2026-06-20); only
LOGICFUZZ_PORTFOLIO_DEPTH (the depth multiplier) remains tunable.
"""
import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.constraints.coverage_ranker import (  # noqa: E402
    select_top_k_sequences, _portfolio_depth,
)

# Three disjoint subsystem clusters A/B/C; top_k far below the cluster count.
_SEQS = [["make_a", "use_a"], ["make_b", "use_b"], ["make_c", "use_c"]]
_CLUSTERS = {
    "make_a": "A", "use_a": "A",
    "make_b": "B", "use_b": "B",
    "make_c": "C", "use_c": "C",
}


def _covered_clusters(selected):
    return {_CLUSTERS[a] for s in selected for a in s if a in _CLUSTERS}


def setup_function(_):
    os.environ.pop("LOGICFUZZ_PORTFOLIO", None)
    os.environ.pop("LOGICFUZZ_PORTFOLIO_DEPTH", None)


def teardown_function(_):
    os.environ.pop("LOGICFUZZ_PORTFOLIO", None)
    os.environ.pop("LOGICFUZZ_PORTFOLIO_DEPTH", None)


def test_portfolio_depth_default_and_tunable():
    assert _portfolio_depth() == 0.5
    os.environ["LOGICFUZZ_PORTFOLIO_DEPTH"] = "2"
    assert _portfolio_depth() == 2.0


def test_covers_every_cluster_despite_small_top_k():
    # top_k=1 would (legacy) select ONE sequence; coverage-complete must still
    # cover all 3 subsystem clusters.
    selected, summary = select_top_k_sequences(_SEQS, top_k=1, clusters=_CLUSTERS)
    assert _covered_clusters(selected) == {"A", "B", "C"}
    assert len(selected) >= 3                       # one per cluster, top_k ignored


def test_portfolio_mode_switch_removed_is_ignored():
    # The LOGICFUZZ_PORTFOLIO on/off/minimal switch was removed: setting it must
    # have NO effect — coverage-complete is unconditional when clusters exist.
    os.environ["LOGICFUZZ_PORTFOLIO"] = "off"
    selected, _ = select_top_k_sequences(_SEQS, top_k=1, clusters=_CLUSTERS)
    assert _covered_clusters(selected) == {"A", "B", "C"}


def test_no_clusters_falls_back_to_legacy_top_k():
    # Even in complete mode, with NO cluster map threaded the ranker must fall
    # back to top_k (existing callers unaffected).
    selected, _ = select_top_k_sequences(_SEQS, top_k=1)
    assert len(selected) <= 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
