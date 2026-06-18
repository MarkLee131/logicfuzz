"""Merge quarantine: drop driver-FP crashers, keep real library bugs.

`_should_quarantine_from_merge` unconditionally drops ANY driver-FP crasher (it
crashed AND the triage did NOT confirm a real bug), covering both cov==0
immediate-SEGV FPs and cov>0 deterministic driver-FP crashers (libpng driver 116:
a `png_color` output array sized [1] for `png_build_grayscale_palette`, which
writes up to 256 entries → stack-overflow on ~every input — covers a few edges
then poisons the fused merge harness). A CONFIRMED real library bug is NEVER
dropped, regardless of coverage.
"""

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import run_single_fuzz as rsf  # noqa: E402


def _br(crashes, cov):
    return types.SimpleNamespace(
        crashes=crashes, cov_pcs=cov, coverage=(0.0 if cov == 0 else 0.5))


def _tr(real_bug):
    # _trial_confirms_real_bug = has an analysis result AND not is_semantic_error
    return types.SimpleNamespace(
        best_analysis_result=(object() if real_bug else None),
        is_semantic_error=(not real_bug))


def _q(br, tr):
    return rsf._should_quarantine_from_merge(br, tr)


def test_drops_all_driver_fp_crashers():
    # Unconditional: any driver-FP crasher is dropped regardless of coverage.
    assert _q(_br(True, 0), _tr(False)) is True        # cov0 FP → dropped
    # The libpng driver-116 class: crashes deterministically with cov>0, not a
    # confirmed real bug → now quarantined.
    assert _q(_br(True, 50), _tr(False)) is True       # cov>0 FP → dropped
    assert _q(_br(False, 50), _tr(False)) is False     # no crash → kept


def test_real_library_bug_never_dropped():
    # A CONFIRMED real library bug is NEVER dropped, regardless of coverage.
    assert _q(_br(True, 0), _tr(True)) is False        # real bug, cov0 → kept
    assert _q(_br(True, 50), _tr(True)) is False       # real bug, cov>0 → kept
