"""Keep-best: never ship a driver worse than the trial's best (all paths).

Guards the regression that improver-rollback missed (it only covered the
improver; fixer / §10B baseline-diff also regress) — e.g. c-ares 1419→804.
"""
from src.workflow.nodes.execution import _keep_best


def test_first_iteration_becomes_best():
    cov, src, bc, bs, restored = _keep_best(0.10, "A", None, None)
    assert (cov, src, bc, bs, restored) == (0.10, "A", 0.10, "A", False)


def test_improvement_updates_best():
    cov, src, bc, bs, restored = _keep_best(0.20, "B", 0.10, "A")
    assert (cov, src, bc, bs, restored) == (0.20, "B", 0.20, "B", False)


def test_substantive_regression_restores_best():
    # 0.09 / 0.16 = 0.57 < 0.85 -> restore the 0.16 "A" driver.
    cov, src, bc, bs, restored = _keep_best(0.09, "B", 0.16, "A")
    assert restored is True
    assert (cov, src) == (0.16, "A")          # shipped the best, not the regression
    assert (bc, bs) == (0.16, "A")


def test_minor_drop_within_noise_is_kept():
    # 0.15 / 0.16 = 0.94 >= 0.85 -> tolerate as noise, keep current; best stays peak.
    cov, src, bc, bs, restored = _keep_best(0.15, "B", 0.16, "A")
    assert restored is False
    assert (cov, src) == (0.15, "B")
    assert (bc, bs) == (0.16, "A")            # peak preserved for future compares


def test_no_prior_best_keeps_current_even_if_low():
    cov, src, bc, bs, restored = _keep_best(0.0, "crashy", 0.0, "")
    assert restored is False
    assert (cov, src) == (0.0, "crashy")
