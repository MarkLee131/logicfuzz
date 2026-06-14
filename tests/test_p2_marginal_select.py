import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.constraints.coverage_ranker import select_marginal


def test_select_marginal_picks_max_new_api_each_step():
    items = [
        {"api_sequence": ["a", "b", "c"]},   # 3 new
        {"api_sequence": ["a", "b"]},        # subset of first → 0 new after it
        {"api_sequence": ["d", "e"]},        # 2 new
    ]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=2)
    seqs = [d["api_sequence"] for d in sel]
    assert seqs[0] == ["a", "b", "c"]      # highest marginal first
    assert seqs[1] == ["d", "e"]           # next-highest marginal, NOT the subset


def test_select_marginal_stops_when_nothing_new():
    items = [{"api_sequence": ["a", "b"]}, {"api_sequence": ["a"]}]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=5)
    assert len(sel) == 1                    # second adds nothing → stop


def test_select_marginal_respects_precovered():
    items = [{"api_sequence": ["a", "b"]}, {"api_sequence": ["c"]}]
    sel = select_marginal(items, lambda d: d["api_sequence"], budget=5,
                          covered={"a", "b"})
    assert [d["api_sequence"] for d in sel] == [["c"]]  # 'ab' already covered
