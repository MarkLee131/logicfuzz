"""Merge quarantine: drop driver-FP crashers, keep real library bugs.

`_is_immediate_crash_fp` only catches cov==0 crashers. A deterministic DRIVER-bug
crasher that covers a few edges before aborting (libpng driver 116: a `png_color`
output array sized [1] for `png_build_grayscale_palette`, which writes up to 256
entries → stack-overflow on ~every input) escapes it with cov>0 and poisons the
fused merge harness. `LOGICFUZZ_QUARANTINE_FP_CRASHERS` extends the quarantine to
cov>0 driver-FP crashers; a CONFIRMED real library bug is never dropped, and
gate-off is byte-identical to the prior cov==0-only rule.
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


def test_gate_off_is_cov0_only(monkeypatch):
    monkeypatch.delenv('LOGICFUZZ_QUARANTINE_FP_CRASHERS', raising=False)
    assert _q(_br(True, 0), _tr(False)) is True       # cov0 FP → dropped
    assert _q(_br(True, 50), _tr(False)) is False      # cov>0 FP → KEPT (legacy)
    assert _q(_br(True, 0), _tr(True)) is False         # real bug → never dropped
    assert _q(_br(False, 50), _tr(False)) is False      # no crash → kept


def test_gate_on_drops_cov_positive_fp_crashers(monkeypatch):
    monkeypatch.setenv('LOGICFUZZ_QUARANTINE_FP_CRASHERS', '1')
    # The libpng driver-116 class: crashes deterministically with cov>0, not a
    # confirmed real bug → now quarantined.
    assert _q(_br(True, 50), _tr(False)) is True
    # A CONFIRMED real library bug with cov>0 is still KEPT.
    assert _q(_br(True, 50), _tr(True)) is False
    # cov0 FP still dropped; no-crash still kept.
    assert _q(_br(True, 0), _tr(False)) is True
    assert _q(_br(False, 99), _tr(False)) is False
