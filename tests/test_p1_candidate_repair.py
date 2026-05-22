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
# F1 (2026-05-23): idioms_payload → graft prefer_filter
# ---------------------------------------------------------------------------

def _idiom(kind, snippet, src='t.c'):
    return {'kind': kind, 'snippet': snippet, 'rationale': 'r',
            'source_driver': src, 'confidence': 1.0}


def test_extract_idiom_blessed_apis_collects_creator_kinds():
    """Phase B kinds that imply creator selection feed the blessed set;
    shape-only kinds (min_size_guard etc.) don't."""
    from liberator_adapter.analysis.candidate_repair import (
        extract_idiom_blessed_apis,
    )
    payload = {'idioms': [
        _idiom('context_null_pass', 'cmsOpenProfileFromMem(NULL, ...)'),
        _idiom('cleanup_pair', 'foo_init(...)  →  foo_destroy(...);'),
        _idiom('data_offset_parse', 'cJSON_ParseWithOpts(data + offset)'),
        _idiom('buffer_copy', 'memcpy(buf, data, size);'),
        # shape-only kinds — must NOT contribute
        _idiom('min_size_guard', 'if (size < 8) return 0;'),
        _idiom('null_termination_required',
               "if (data[size-1] != '\\0') return 0;"),
        _idiom('header_flag_demux', 'data[0] == \'1\''),
    ]}
    blessed = extract_idiom_blessed_apis(payload)
    assert 'cmsOpenProfileFromMem' in blessed
    assert 'foo_init' in blessed
    assert 'foo_destroy' in blessed   # cleanup_pair captures both
    assert 'cJSON_ParseWithOpts' in blessed
    assert 'memcpy' in blessed
    # Shape-only kinds shouldn't add any APIs
    assert 'size' not in blessed


def test_extract_idiom_blessed_apis_safe_on_none():
    from liberator_adapter.analysis.candidate_repair import (
        extract_idiom_blessed_apis,
    )
    assert extract_idiom_blessed_apis(None) == set()
    assert extract_idiom_blessed_apis({}) == set()
    assert extract_idiom_blessed_apis({'idioms': []}) == set()


def test_graft_prefers_idiom_blessed_root():
    """The lcms acceptance test for F1: a graft_fn that exposes 3
    candidate roots — including a "bad" IR-mod/ref false positive
    (cmsFreeToneCurveTriple) and the real creator
    (cmsCreateContext, idiom-blessed) — should pick the blessed one."""
    captured_filter = {}

    def graft_fn(seq, prefer_filter=None):
        # Simulate: top-1 root is the bad creator; only the blessed
        # root passes the filter.
        captured_filter['fn'] = prefer_filter
        candidate_roots = ['cmsFreeToneCurveTriple', 'cmsCreateContext']
        if prefer_filter is not None:
            preferred = [r for r in candidate_roots if prefer_filter(r)]
            if preferred:
                return [preferred[0]] + list(seq)
        return [candidate_roots[0]] + list(seq)

    idioms = {'idioms': [_idiom('context_null_pass',
                                'cmsCreateContext(NULL, ...)')]}
    eng = RepairEngine(graft_fn=graft_fn, idioms_payload=idioms)
    trace = eng.attempt(
        ['cmsOpenProfileFromMem'],
        revalidate=lambda s: 'cmsCreateContext' in s,
        candidate_index=0,
    )
    # Filter was passed (engine offered F1 path)
    assert captured_filter['fn'] is not None
    # Engine picked the blessed creator
    assert trace.final_success
    assert trace.final_sequence is not None
    assert trace.final_sequence[0] == 'cmsCreateContext'
    # Rejection-reason field carries the F1 telemetry note
    assert 'idiom-blessed' in trace.attempts[0].rejection_reason


def test_graft_falls_back_when_no_idiom_match():
    """If no candidate root is idiom-blessed, graft falls back to
    the top-1 root (existing behavior). No regression."""
    def graft_fn(seq, prefer_filter=None):
        candidates = ['someUnrelated', 'anotherUnrelated']
        if prefer_filter is not None:
            preferred = [r for r in candidates if prefer_filter(r)]
            if preferred:
                return [preferred[0]] + list(seq)
        return [candidates[0]] + list(seq)

    idioms = {'idioms': [_idiom('context_null_pass',
                                'completelyUnrelatedAPI(NULL, ...)')]}
    eng = RepairEngine(graft_fn=graft_fn, idioms_payload=idioms)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'someUnrelated' in s,
        candidate_index=0,
    )
    assert trace.final_success
    assert trace.final_sequence is not None
    assert trace.final_sequence[0] == 'someUnrelated'
    # No idiom-blessed inserts → empty telemetry note
    assert 'idiom-blessed' not in trace.attempts[0].rejection_reason


def test_graft_legacy_api_without_prefer_filter_still_works():
    """If the wrapped graft_fn predates F1 (no prefer_filter kwarg),
    the engine catches TypeError and falls back to legacy call."""
    def legacy_graft(seq):
        return ['prepended'] + list(seq)

    idioms = {'idioms': [_idiom('context_null_pass', 'prepended(NULL, ...)')]}
    eng = RepairEngine(graft_fn=legacy_graft, idioms_payload=idioms)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'prepended' in s,
        candidate_index=0,
    )
    assert trace.final_success
    assert trace.final_sequence == ['prepended', 'useX']


def test_no_idioms_engine_works_normally():
    """No idioms_payload → engine works exactly as before F1."""
    def graft_fn(seq, prefer_filter=None):
        # Even when filter is None, graft should still return.
        return ['creator_X'] + list(seq)

    eng = RepairEngine(graft_fn=graft_fn, idioms_payload=None)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'creator_X' in s,
        candidate_index=0,
    )
    assert trace.final_success
    assert trace.final_sequence == ['creator_X', 'useX']


# ---------------------------------------------------------------------------
# F2 (2026-05-23): intra-engine retry — graft tries multiple roots
# ---------------------------------------------------------------------------

def test_graft_retries_with_exclude_filter():
    """When the first graft attempt fails revalidation, the engine
    excludes that root and retries with a different one. This is the
    F2 acceptance test: a graft path where root[0] is feasible but
    revalidate-rejected, and root[1] is the right answer.
    """
    call_count = {'n': 0}

    def graft_fn(seq, prefer_filter=None, exclude_filter=None):
        # Two-root behaviour: top-1 is 'bad_root', top-2 is 'good_root'.
        candidates = ['bad_root', 'good_root']
        if exclude_filter is not None:
            candidates = [r for r in candidates if not exclude_filter(r)]
        if prefer_filter is not None:
            preferred = [r for r in candidates if prefer_filter(r)]
            if preferred:
                candidates = preferred
        call_count['n'] += 1
        if not candidates:
            return None
        return [candidates[0]] + list(seq)

    # revalidate accepts ONLY sequences with good_root
    eng = RepairEngine(graft_fn=graft_fn)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'good_root' in s,
        candidate_index=0,
    )
    assert trace.final_success
    assert trace.final_sequence == ['good_root', 'useX']
    # Two attempts recorded: first with bad_root (failed), second with good_root.
    assert len(trace.attempts) == 2
    assert trace.attempts[0].inserted_apis == ['bad_root']
    assert trace.attempts[0].success is False
    assert trace.attempts[1].inserted_apis == ['good_root']
    assert trace.attempts[1].success is True
    # graft_fn was called twice (initial + retry).
    assert call_count['n'] == 2


def test_graft_retry_caps_at_max_retries():
    """If every root revalidates to False, the engine stops at
    MAX_GRAFT_RETRIES rather than looping forever."""
    def graft_fn(seq, prefer_filter=None, exclude_filter=None):
        # Always returns a fresh unique creator name; revalidate
        # always rejects.
        excluded = set()
        if exclude_filter is not None:
            # Walk a deterministic pool
            for i in range(20):
                name = f'root_{i}'
                if not exclude_filter(name):
                    return [name] + list(seq)
            return None
        return ['root_0'] + list(seq)

    eng = RepairEngine(graft_fn=graft_fn)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: False,
        candidate_index=0,
    )
    assert not trace.final_success
    assert len(trace.attempts) == RepairEngine.MAX_GRAFT_RETRIES


def test_graft_first_try_success_no_retry():
    """If the first graft attempt revalidates True, we stop — no retry."""
    call_count = {'n': 0}

    def graft_fn(seq, prefer_filter=None, exclude_filter=None):
        call_count['n'] += 1
        return ['creator_X'] + list(seq)

    eng = RepairEngine(graft_fn=graft_fn)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'creator_X' in s,
        candidate_index=0,
    )
    assert trace.final_success
    assert len(trace.attempts) == 1
    assert call_count['n'] == 1  # no retry


def test_graft_retry_with_legacy_api_no_exclude_filter_kwarg():
    """If graft_fn doesn't accept exclude_filter, the engine detects
    that retries yield the same answer and stops — no infinite loop,
    no spurious extra attempts recorded."""
    call_count = {'n': 0}

    def legacy_graft(seq):
        call_count['n'] += 1
        return ['always_same_root'] + list(seq)

    eng = RepairEngine(graft_fn=legacy_graft)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: False,  # always reject
        candidate_index=0,
    )
    assert not trace.final_success
    # Only one ATTEMPT is recorded (the same-answer detection stops the
    # retry loop before yielding a redundant second attempt).
    assert len(trace.attempts) == 1
    # graft_fn is called twice: once for the initial attempt, once for
    # the retry that turns up the same answer and triggers stop. Two is
    # the minimum to detect saturation on a legacy graft API.
    assert call_count['n'] == 2


def test_graft_retry_attempt_records_carry_excluded_set():
    """The retry attempts' rejection_reason should mention which roots
    were excluded so operators can debug retry decisions."""
    def graft_fn(seq, prefer_filter=None, exclude_filter=None):
        # Always returns next-numbered root not in excluded
        for i in range(5):
            name = f'r{i}'
            if exclude_filter is None or not exclude_filter(name):
                return [name] + list(seq)
        return None

    eng = RepairEngine(graft_fn=graft_fn)
    trace = eng.attempt(
        ['useX'],
        revalidate=lambda s: 'r2' in s,  # only r2 accepted
        candidate_index=0,
    )
    assert trace.final_success
    # The retry attempts (idx 1+) carry "retry #N" + excluded set in
    # the rejection_reason.
    assert any('retry #' in a.rejection_reason for a in trace.attempts[1:])


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
