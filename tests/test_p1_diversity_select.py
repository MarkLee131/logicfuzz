"""LOGICFUZZ_DIVERSITY_SELECT: switch _greedy_select from acceptance-order
walk (accept >=1-new) to TRUE budgeted-max-coverage greedy (pick MAX marginal
new-API each step). Reaches the API tail with fewer, more-diverse drivers."""
from typing import Any, List, cast

from liberator_adapter.constraints.coverage_ranker import CoverageRanker


class _Sc:
    """Minimal stand-in for SequenceScore — _greedy_select only reads .sequence."""
    def __init__(self, seq):
        self.sequence = seq


def _pool(*seqs) -> List[Any]:
    return [_Sc(list(s)) for s in seqs]


def test_diversity_covers_more_than_legacy_on_overlapping_pool(monkeypatch):
    ranker = CoverageRanker()
    # Acceptance-sorted order: 3 high-acceptance sequences sharing popular {p,q};
    # one unique-covering sequence ranked LAST (lower acceptance).
    ranked = _pool(["p", "q", "x"], ["p", "q", "y"],
                   ["p", "q", "z"], ["m", "n", "o"])

    monkeypatch.setenv("LOGICFUZZ_DIVERSITY_SELECT", "0")
    _, cov_legacy, _ = ranker._greedy_select(cast(Any, ranked), 2)
    # legacy walks order: A{p,q,x} then B(+y) → {p,q,x,y} = 4
    assert len(cov_legacy) == 4

    monkeypatch.setenv("LOGICFUZZ_DIVERSITY_SELECT", "1")
    _, cov_div, _ = ranker._greedy_select(cast(Any, ranked), 2)
    # diversity: A{p,q,x} (3 new), then D{m,n,o} (3 new > B/C's 1) → 6
    assert len(cov_div) == 6
    assert len(cov_div) > len(cov_legacy)


def test_diversity_ties_broken_by_acceptance_order(monkeypatch):
    ranker = CoverageRanker()
    # All first-step marginals equal (3) → max() picks the first = highest
    # acceptance (ranked order is acceptance-sorted).
    ranked = _pool(["a", "b", "c"], ["d", "e", "f"])
    monkeypatch.setenv("LOGICFUZZ_DIVERSITY_SELECT", "1")
    sel, _, _ = ranker._greedy_select(cast(Any, ranked), 1)
    assert sel == [["a", "b", "c"]]   # reachability-first among equal coverage


def test_diversity_stops_when_nothing_new(monkeypatch):
    ranker = CoverageRanker()
    ranked = _pool(["a"], ["b"], ["c"], ["a"], ["b"])
    monkeypatch.setenv("LOGICFUZZ_DIVERSITY_SELECT", "1")
    sel, cov, _ = ranker._greedy_select(cast(Any, ranked), 10)
    assert len(cov) == 3                # a,b,c
    assert len(sel) == 3                # stops at full coverage, no padding to top_k


def test_legacy_unchanged_when_flag_off(monkeypatch):
    ranker = CoverageRanker()
    ranked = _pool(["p", "q", "x"], ["p", "q", "y"], ["m", "n", "o"])
    monkeypatch.delenv("LOGICFUZZ_DIVERSITY_SELECT", raising=False)
    sel, cov, _ = ranker._greedy_select(cast(Any, ranked), 3)
    # default = legacy order walk, all three accepted (each adds >=1 new)
    assert sel == [["p", "q", "x"], ["p", "q", "y"], ["m", "n", "o"]]
    assert len(cov) == 7               # {p,q,x,y,m,n,o}
