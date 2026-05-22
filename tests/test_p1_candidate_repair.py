"""Pin Phase A (Candidate Repair Engine) behaviour.

The engine wraps repair strategies; first strategy that produces a
revalidatable sequence wins. Currently only ``graft_creator_prefix`` is
plugged in. These tests pin the contract so future strategies can be
added without surprises in the existing flow.

Design intent — see
``liberator_adapter/analysis/candidate_repair.py`` docstring and
the system-design roadmap (Phase A → E) discussed 2026-05-22.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.candidate_repair import (  # noqa: E402
    CandidateRepairTrace,
    RepairAttempt,
    RepairEngine,
    RepairLog,
    RepairStrategy,
)


# ---------------------------------------------------------------------------
# Fake strategies / validators
# ---------------------------------------------------------------------------

def _graft_prepend(constant):
    """Build a fake graft_fn that prepends ``constant`` if it isn't already there."""
    def fn(seq):
        if constant in seq:
            return None
        return [constant] + list(seq)
    return fn


def _accept_if_contains(token):
    return lambda seq: token in seq


def _always_reject():
    return lambda seq: False


# ---------------------------------------------------------------------------
# Core engine contract
# ---------------------------------------------------------------------------

def test_graft_succeeds_when_revalidate_accepts():
    eng = RepairEngine(graft_fn=_graft_prepend('creator_X'))
    trace = eng.attempt(['use_X'], _accept_if_contains('creator_X'),
                        candidate_index=0)
    assert trace.final_success
    assert trace.final_sequence == ['creator_X', 'use_X']
    assert len(trace.attempts) == 1
    assert trace.attempts[0].strategy == RepairStrategy.GRAFT_CREATOR_PREFIX
    assert trace.attempts[0].inserted_apis == ['creator_X']
    assert trace.attempts[0].success is True


def test_graft_fails_when_revalidate_rejects():
    eng = RepairEngine(graft_fn=_graft_prepend('creator_X'))
    trace = eng.attempt(['use_X'], _always_reject(), candidate_index=1)
    assert not trace.final_success
    assert trace.final_sequence is None
    assert trace.attempts[0].success is False
    assert 'revalidate' in trace.attempts[0].rejection_reason


def test_graft_skipped_when_already_grounded():
    """graft_fn returning None or unchanged seq → no attempt recorded."""
    eng = RepairEngine(graft_fn=_graft_prepend('creator_X'))
    trace = eng.attempt(['creator_X', 'use_X'], _accept_if_contains('creator_X'),
                        candidate_index=2)
    assert not trace.final_success  # no strategy produced a candidate
    assert len(trace.attempts) == 0


def test_revalidate_exception_caught_not_propagated():
    eng = RepairEngine(graft_fn=_graft_prepend('creator_X'))

    def boom(_seq):
        raise RuntimeError("boom")

    trace = eng.attempt(['use_X'], boom, candidate_index=3)
    assert not trace.final_success
    assert 'RuntimeError' in trace.attempts[0].rejection_reason


def test_no_graft_fn_means_no_strategies():
    eng = RepairEngine(graft_fn=None)
    trace = eng.attempt(['use_X'], _accept_if_contains('anything'),
                        candidate_index=0)
    assert not trace.final_success
    assert len(trace.attempts) == 0


# ---------------------------------------------------------------------------
# RepairLog aggregation
# ---------------------------------------------------------------------------

def test_repair_log_counts_and_buckets():
    log = RepairLog()
    # 1 accepted no-repair (no attempts, final_success=True)
    log.record(CandidateRepairTrace(
        candidate_index=0,
        original_sequence=['a'],
        final_success=True,
        final_sequence=['a'],
    ))
    # 1 repaired success
    log.record(CandidateRepairTrace(
        candidate_index=1,
        original_sequence=['use_X'],
        attempts=[RepairAttempt(
            strategy=RepairStrategy.GRAFT_CREATOR_PREFIX,
            original_sequence=['use_X'],
            repaired_sequence=['creator_X', 'use_X'],
            inserted_apis=['creator_X'],
            success=True,
        )],
        final_success=True,
        final_sequence=['creator_X', 'use_X'],
    ))
    # 1 unrepairable
    log.record(CandidateRepairTrace(
        candidate_index=2,
        original_sequence=['use_Y'],
        attempts=[RepairAttempt(
            strategy=RepairStrategy.GRAFT_CREATOR_PREFIX,
            original_sequence=['use_Y'],
            repaired_sequence=['creator_Y', 'use_Y'],
            success=False,
            rejection_reason='revalidate returned False',
        )],
        final_success=False,
    ))

    d = log.to_dict()
    s = d['summary']
    assert s['candidates_total'] == 3
    assert s['candidates_accepted_no_repair'] == 1
    assert s['candidates_repaired_success'] == 1
    assert s['candidates_unrepairable'] == 1
    assert s['by_strategy_attempt']['graft_creator_prefix'] == 2
    assert s['by_strategy_success']['graft_creator_prefix'] == 1


def test_repair_log_persist_roundtrip():
    log = RepairLog()
    log.record(CandidateRepairTrace(
        candidate_index=0,
        original_sequence=['use_X'],
        attempts=[RepairAttempt(
            strategy=RepairStrategy.GRAFT_CREATOR_PREFIX,
            original_sequence=['use_X'],
            repaired_sequence=['creator_X', 'use_X'],
            inserted_apis=['creator_X'],
            success=True,
        )],
        final_success=True,
        final_sequence=['creator_X', 'use_X'],
    ))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'nested' / 'repair_log.json'
        log.persist(path)
        assert path.exists()
        import json
        with path.open(encoding='utf-8') as f:
            loaded = json.load(f)
        assert loaded['summary']['candidates_repaired_success'] == 1
        assert loaded['traces'][0]['attempts'][0]['inserted_apis'] == ['creator_X']
