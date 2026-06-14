import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.portfolio_redundancy import portfolio_redundancy


def test_disjoint_portfolio_scores_one():
    m = portfolio_redundancy([["a", "b"], ["c", "d"]])
    assert m["n_drivers"] == 2
    assert m["union_apis"] == 4
    assert m["sum_per_driver_apis"] == 4
    assert m["disjointness"] == 1.0
    assert m["mean_pairwise_jaccard"] == 0.0


def test_identical_portfolio_is_maximally_redundant():
    m = portfolio_redundancy([["a", "b"], ["a", "b"]])
    assert m["disjointness"] == 0.5          # union 2 / total 4
    assert m["mean_pairwise_jaccard"] == 1.0


def test_empty_is_safe():
    m = portfolio_redundancy([])
    assert m["n_drivers"] == 0
