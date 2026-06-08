"""Budgeted-max-coverage greedy selection (always on): _greedy_select picks the
MAX marginal new-API sequence each step, ties broken by acceptance order, and
stops once nothing adds new APIs. Reaches the API tail with fewer, more-diverse
drivers than a fixed-order walk. (The LOGICFUZZ_DIVERSITY_SELECT gate + the
legacy fixed-order path were removed — greedy is now the only selector.)"""
from typing import Any, List, cast

from liberator_adapter.constraints.coverage_ranker import CoverageRanker


class _Sc:
    """Minimal stand-in for SequenceScore — _greedy_select only reads .sequence."""
    def __init__(self, seq):
        self.sequence = seq


def _pool(*seqs) -> List[Any]:
    return [_Sc(list(s)) for s in seqs]


def test_diversity_covers_more_on_overlapping_pool():
    ranker = CoverageRanker()
    # Acceptance-sorted order: 3 high-acceptance sequences sharing popular {p,q};
    # one unique-covering sequence ranked LAST (lower acceptance).
    ranked = _pool(["p", "q", "x"], ["p", "q", "y"],
                   ["p", "q", "z"], ["m", "n", "o"])
    # Greedy: A{p,q,x} (3 new), then D{m,n,o} (3 new > B/C's 1) → 6 — beats a
    # fixed-order walk (which would take B for only {p,q,x,y} = 4).
    _, cov_div, _ = ranker._greedy_select(cast(Any, ranked), 2)
    assert len(cov_div) == 6


def test_diversity_ties_broken_by_acceptance_order():
    ranker = CoverageRanker()
    # All first-step marginals equal (3) → max() picks the first = highest
    # acceptance (ranked order is acceptance-sorted).
    ranked = _pool(["a", "b", "c"], ["d", "e", "f"])
    sel, _, _ = ranker._greedy_select(cast(Any, ranked), 1)
    assert sel == [["a", "b", "c"]]   # reachability-first among equal coverage


def test_diversity_stops_when_nothing_new():
    ranker = CoverageRanker()
    ranked = _pool(["a"], ["b"], ["c"], ["a"], ["b"])
    sel, cov, _ = ranker._greedy_select(cast(Any, ranked), 10)
    assert len(cov) == 3                # a,b,c
    assert len(sel) == 3                # stops at full coverage, no padding to top_k
