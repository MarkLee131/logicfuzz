"""Regression tests for the crash-verdict-flow fix (audit #1 + #2).

BUG #1: `StateAdapter.state_to_result_history` gated the AnalysisResult on
`state["analysis_complete"]`, a key NOTHING ever wrote — so the crash verdict
(`true_bug` / `feasible`, from lean's deterministic frame classifier OR the LLM
path) never reached the trial result. Effect: `found_bug` counted EVERY crash,
and a real library bug was indistinguishable from a driver false-positive.

BUG #2: the pre-ship merge quarantine (`_is_immediate_crash_fp`) dropped ANY
0-coverage crasher, never consulting the verdict — so a genuine library bug that
aborts before accumulating edges was silently dropped from the merge.

Fix: adapters appends the AnalysisResult whenever a crash verdict exists and now
carries the feasibility (`crash_context_result`); the quarantine keeps a
verdict-confirmed real bug (`_trial_confirms_real_bug`).
"""
from __future__ import annotations

import os
import sys
import types
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from results import (AnalysisResult, RunResult, CrashResult,  # noqa: E402
                     CrashContextResult, TrialResult)
from src.workflow.adapters import StateAdapter  # noqa: E402
import run_single_fuzz as rsf  # noqa: E402


# ---- helpers ---------------------------------------------------------------

def _crash_state(true_bug: bool, feasible: bool) -> dict:
    return {
        "crash_analysis": {"true_bug": true_bug, "insight": "i", "stacktrace": "s"},
        "context_analysis": {"feasible": feasible, "analysis": "a"},
    }


def _analysis(crashes: bool, true_bug: bool, feasible: bool) -> AnalysisResult:
    """A minimal real AnalysisResult (object.__new__ to skip the heavy __init__);
    only the attributes best_analysis_result / is_semantic_error read are set."""
    rr = object.__new__(RunResult)
    rr.crashes = crashes
    ar = object.__new__(AnalysisResult)
    ar.run_result = rr
    cr = object.__new__(CrashResult)
    cr.true_bug = true_bug
    ar.crash_result = cr
    cc = object.__new__(CrashContextResult)
    cc.feasible = feasible
    ar.crash_context_result = cc
    ar.coverage_result = None
    ar.semantic_result = None
    return ar


def _run(crashes: bool) -> RunResult:
    """Minimal RunResult — TrialResult.crashes only counts RunResult items."""
    rr = object.__new__(RunResult)
    rr.crashes = crashes
    return rr


def _trial(result_history):
    return TrialResult(benchmark=types.SimpleNamespace(),
                       trial=1,
                       work_dirs=types.SimpleNamespace(),
                       result_history=result_history)


# ---- #1: the feasibility verdict is extracted ------------------------------

def test_extract_crash_context_result_maps_feasible():
    assert StateAdapter._extract_crash_context_result(
        _crash_state(True, True)).feasible is True
    assert StateAdapter._extract_crash_context_result(
        _crash_state(False, False)).feasible is False
    assert StateAdapter._extract_crash_context_result({}) is None


# ---- #1: verdict → is_semantic_error → found_bug accounting -----------------

def test_library_verdict_is_real_bug():
    tr = _trial([_run(True), _analysis(crashes=True, true_bug=True, feasible=True)])
    # found_bug counts: crashes and not is_semantic_error
    assert tr.is_semantic_error is False
    assert (tr.crashes and not tr.is_semantic_error) is True   # counted as a bug


def test_driver_verdict_is_not_a_real_bug():
    tr = _trial([_run(True), _analysis(crashes=True, true_bug=False, feasible=False)])
    assert tr.is_semantic_error is True
    assert (tr.crashes and not tr.is_semantic_error) is False  # NOT counted


def test_no_verdict_is_not_counted_as_confirmed_bug():
    # No AnalysisResult in history → best_analysis_result None → is_semantic_error
    # False, but _trial_confirms_real_bug must still be False (no verdict).
    tr = _trial([])
    assert rsf._trial_confirms_real_bug(tr) is False


# ---- #1: the adapter actually APPENDS the AnalysisResult (guard fix) --------

def test_state_to_result_history_appends_analysis_on_crash_verdict():
    state = {
        "benchmark": {}, "work_dirs": {}, "trial": 1,
        **_crash_state(true_bug=True, feasible=True),
    }
    with mock.patch("src.workflow.adapters.Benchmark.from_dict",
                    return_value=mock.MagicMock()), \
         mock.patch("src.workflow.adapters.WorkDirs.from_dict",
                    return_value=mock.MagicMock()):
        history = StateAdapter.state_to_result_history(state)  # type: ignore[arg-type]
    analyses = [r for r in history if isinstance(r, AnalysisResult)]
    assert len(analyses) == 1, "crash verdict must produce an AnalysisResult"
    assert analyses[0].crash_result.true_bug is True
    assert analyses[0].crash_context_result.feasible is True


def test_state_to_result_history_no_analysis_without_verdict():
    state = {"benchmark": {}, "work_dirs": {}, "trial": 1}
    with mock.patch("src.workflow.adapters.Benchmark.from_dict",
                    return_value=mock.MagicMock()), \
         mock.patch("src.workflow.adapters.WorkDirs.from_dict",
                    return_value=mock.MagicMock()):
        history = StateAdapter.state_to_result_history(state)  # type: ignore[arg-type]
    assert not [r for r in history if isinstance(r, AnalysisResult)]


# ---- #2: quarantine honors the verdict -------------------------------------

def test_trial_confirms_real_bug_truth_table():
    real = _trial([_analysis(True, True, True)])      # library / feasible
    fp = _trial([_analysis(True, False, False)])      # driver / infeasible
    none = _trial([])                                 # no verdict
    assert rsf._trial_confirms_real_bug(real) is True
    assert rsf._trial_confirms_real_bug(fp) is False
    assert rsf._trial_confirms_real_bug(none) is False


def test_immediate_crash_quarantine_keeps_real_library_bug():
    br = types.SimpleNamespace(crashes=True, cov_pcs=0, coverage=0.0)
    assert rsf._is_immediate_crash_fp(br) is True           # 0-cov crasher
    real = _trial([_analysis(True, True, True)])
    fp = _trial([_analysis(True, False, False)])
    # quarantine condition at the call site: immediate-crash AND not real-bug
    assert (rsf._is_immediate_crash_fp(br)
            and not rsf._trial_confirms_real_bug(real)) is False   # KEEP real bug
    assert (rsf._is_immediate_crash_fp(br)
            and not rsf._trial_confirms_real_bug(fp)) is True      # DROP driver FP


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
