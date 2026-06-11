"""Coverage-complete selection (the objective swap, stage 2).

The legacy objective ranks globally and takes top_k, so subsystems beyond the
top_k are never selected (the lcms root cause). Coverage-complete selection
guarantees >=1 selected sequence per SUBSYSTEM CLUSTER present in the pool,
THEN a bounded depth pass — independent of top_k. Default-ON; LOGICFUZZ_PORTFOLIO
controls it (complete | minimal | off).
"""
import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.constraints.coverage_ranker import (  # noqa: E402
    select_top_k_sequences, _portfolio_config,
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


def test_default_is_complete():
    mode, depth = _portfolio_config()
    assert mode == "complete" and depth == 0.5


def test_covers_every_cluster_despite_small_top_k():
    # top_k=1 would (legacy) select ONE sequence; coverage-complete must still
    # cover all 3 subsystem clusters.
    selected, summary = select_top_k_sequences(_SEQS, top_k=1, clusters=_CLUSTERS)
    assert _covered_clusters(selected) == {"A", "B", "C"}
    assert len(selected) >= 3                       # one per cluster, top_k ignored


def test_off_mode_respects_top_k_legacy():
    os.environ["LOGICFUZZ_PORTFOLIO"] = "off"
    selected, _ = select_top_k_sequences(_SEQS, top_k=1, clusters=_CLUSTERS)
    assert len(selected) <= 1                        # legacy fixed cap honoured


def test_no_clusters_falls_back_to_legacy_top_k():
    # Even in complete mode, with NO cluster map threaded the ranker must fall
    # back to top_k (existing callers unaffected).
    selected, _ = select_top_k_sequences(_SEQS, top_k=1)
    assert len(selected) <= 1


def test_minimal_mode_covers_without_depth():
    os.environ["LOGICFUZZ_PORTFOLIO"] = "minimal"
    # add an extra A-cluster sequence that a depth pass WOULD add; minimal must not.
    seqs = _SEQS + [["make_a", "use_a", "extra_a_op"]]
    clusters = dict(_CLUSTERS, extra_a_op="A")
    selected, _ = select_top_k_sequences(seqs, top_k=99, clusters=clusters)
    assert _covered_clusters(selected) == {"A", "B", "C"}
    # exactly the cover set (3), no depth driver pulled in
    assert len(selected) == 3


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
