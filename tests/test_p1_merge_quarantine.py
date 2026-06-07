"""Pre-ship quarantine: drop immediate-crash 0-coverage FP drivers from the
merge (they poison the single-process fused harness + add no coverage)."""
from run_single_fuzz import _is_immediate_crash_fp


class _BR:
    def __init__(self, crashes=False, cov_pcs=0, coverage=0.0):
        self.crashes = crashes
        self.cov_pcs = cov_pcs
        self.coverage = coverage


def test_immediate_crash_zero_cov_is_quarantined():
    assert _is_immediate_crash_fp(_BR(crashes=True, cov_pcs=0, coverage=0.0))


def test_crasher_that_made_progress_is_kept():
    # crashed but explored edges → normal fuzz target under -ignore_crashes
    assert not _is_immediate_crash_fp(_BR(crashes=True, cov_pcs=512, coverage=0.12))
    assert not _is_immediate_crash_fp(_BR(crashes=True, cov_pcs=0, coverage=0.05))


def test_non_crasher_never_quarantined():
    assert not _is_immediate_crash_fp(_BR(crashes=False, cov_pcs=0, coverage=0.0))


def test_missing_attrs_safe():
    class _Empty:
        pass
    assert not _is_immediate_crash_fp(_Empty())
