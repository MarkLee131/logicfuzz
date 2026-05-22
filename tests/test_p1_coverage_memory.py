"""Pin Phase C foundation (CoverageMemory) shape and math.

Asserts the on-disk JSON schema, snapshot derivation logic, and
saturation detection. Phase D Planner and Phase E Adaptive Shape will
consume this memory; breaking its shape is a downstream contract
violation, hence the tight pins here.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.state.coverage_memory import (  # noqa: E402
    SCHEMA_VERSION,
    CoverageMemory,
    IterationSnapshot,
    TrialOutcome,
    make_snapshot,
    persist_snapshot,
)


# ---------------------------------------------------------------------------
# Snapshot construction + derivation
# ---------------------------------------------------------------------------

def test_make_snapshot_derives_baseline_ratio():
    trs = [
        TrialOutcome(trial_id=1, api_sequence=['a', 'b'],
                    final_coverage_pct=0.20, final_line_diff_pct=0.02,
                    success=True),
        TrialOutcome(trial_id=2, api_sequence=['c'],
                    final_coverage_pct=0.25, final_line_diff_pct=0.05,
                    success=True),
    ]
    snap = make_snapshot(
        iteration_idx=0, trial_results=trs,
        baseline_line_count=1000, baseline_covered_lines=500,
    )
    assert snap.aggregate_max_coverage_pct == 0.25  # best of the two
    assert snap.aggregate_line_diff_pct == 0.05
    assert snap.baseline_coverage_pct == 0.5
    assert snap.coverage_ratio_to_baseline == 0.5  # 0.25 / 0.5


def test_make_snapshot_no_baseline_leaves_ratio_none():
    trs = [TrialOutcome(trial_id=1, api_sequence=['a'],
                       final_coverage_pct=0.30, success=True)]
    snap = make_snapshot(iteration_idx=0, trial_results=trs)
    assert snap.coverage_ratio_to_baseline is None
    assert snap.baseline_coverage_pct is None


def test_failed_trials_excluded_from_aggregate():
    trs = [
        TrialOutcome(trial_id=1, api_sequence=['a'],
                    final_coverage_pct=0.50, success=False),  # excluded
        TrialOutcome(trial_id=2, api_sequence=['b'],
                    final_coverage_pct=0.10, success=True),
    ]
    snap = make_snapshot(iteration_idx=0, trial_results=trs)
    assert snap.aggregate_max_coverage_pct == 0.10


def test_empty_trials_safe():
    snap = make_snapshot(iteration_idx=0, trial_results=[])
    assert snap.trial_count == 0
    assert snap.aggregate_max_coverage_pct is None


# ---------------------------------------------------------------------------
# Memory persistence + roundtrip
# ---------------------------------------------------------------------------

def test_persist_roundtrip_preserves_snapshots():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'state' / 'coverage_memory.json'
        snap = make_snapshot(
            iteration_idx=0,
            trial_results=[TrialOutcome(
                trial_id=1, api_sequence=['cJSON_Parse'],
                final_coverage_pct=0.25, success=True,
                skeleton_repair_applied=True,
                skeleton_repair_inserted=['cJSON_Parse'],
            )],
            merged_driver_path='/tmp/merged.c',
            merged_driver_count=1,
            baseline_line_count=2321, baseline_covered_lines=1022,
            repair_summary={'candidates_total': 10,
                           'candidates_repaired_success': 2},
        )
        mem = CoverageMemory(project='cjson')
        mem.append(snap)
        mem.persist(path)
        loaded = CoverageMemory.load_or_create('cjson', path)
        assert loaded.project == 'cjson'
        assert loaded.schema_version == SCHEMA_VERSION
        assert len(loaded.snapshots) == 1
        rt = loaded.snapshots[0]
        assert rt.iteration_idx == 0
        assert rt.trial_count == 1
        assert rt.trial_results[0].skeleton_repair_applied is True
        assert rt.trial_results[0].skeleton_repair_inserted == ['cJSON_Parse']
        assert rt.repair_summary['candidates_repaired_success'] == 2
        # Derived fields preserved
        assert abs(rt.baseline_coverage_pct - 1022 / 2321) < 1e-9


def test_load_or_create_returns_empty_when_missing():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'missing.json'
        mem = CoverageMemory.load_or_create('cjson', path)
        assert mem.project == 'cjson'
        assert mem.snapshots == []


def test_schema_mismatch_starts_fresh():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'memory.json'
        path.write_text(json.dumps({
            'project': 'cjson',
            'schema_version': 999,
            'snapshots': [],
        }))
        mem = CoverageMemory.load_or_create('cjson', path)
        assert mem.snapshots == []
        assert mem.schema_version == SCHEMA_VERSION


def test_persist_snapshot_helper_appends_existing():
    with tempfile.TemporaryDirectory() as td:
        state_dir = Path(td) / 'state'
        s1 = make_snapshot(0, [TrialOutcome(trial_id=1, api_sequence=['a'],
                                           final_coverage_pct=0.1, success=True)])
        mem = persist_snapshot('p', s1, state_dir=state_dir)
        assert len(mem.snapshots) == 1
        s2 = make_snapshot(1, [TrialOutcome(trial_id=2, api_sequence=['b'],
                                           final_coverage_pct=0.2, success=True)])
        mem = persist_snapshot('p', s2, state_dir=state_dir)
        assert len(mem.snapshots) == 2
        assert mem.snapshots[0].iteration_idx == 0
        assert mem.snapshots[1].iteration_idx == 1


# ---------------------------------------------------------------------------
# Saturation detection
# ---------------------------------------------------------------------------

def _snap_with_ratio(idx, ratio):
    return IterationSnapshot(
        iteration_idx=idx, timestamp='2026-05-22T00:00:00+00:00',
        trial_count=1, coverage_ratio_to_baseline=ratio,
    )


def test_saturation_needs_enough_history():
    mem = CoverageMemory(project='p')
    assert not mem.is_saturated(lookback=2)
    mem.append(_snap_with_ratio(0, 0.5))
    assert not mem.is_saturated(lookback=2)
    mem.append(_snap_with_ratio(1, 0.5))
    assert not mem.is_saturated(lookback=2)  # need 3 snapshots for lookback=2
    mem.append(_snap_with_ratio(2, 0.5))
    assert mem.is_saturated(lookback=2)  # 3 snapshots, no change


def test_saturation_triggers_on_flat_ratio():
    mem = CoverageMemory(project='p')
    for i, r in enumerate([0.30, 0.305, 0.31]):  # max delta 0.005 < 0.01
        mem.append(_snap_with_ratio(i, r))
    assert mem.is_saturated(lookback=2, ratio_delta=0.01)


def test_saturation_does_not_trigger_on_climbing_ratio():
    mem = CoverageMemory(project='p')
    for i, r in enumerate([0.30, 0.40, 0.55]):  # big jumps
        mem.append(_snap_with_ratio(i, r))
    assert not mem.is_saturated(lookback=2, ratio_delta=0.01)


def test_saturation_safe_with_none_ratios():
    mem = CoverageMemory(project='p')
    mem.append(_snap_with_ratio(0, None))
    mem.append(_snap_with_ratio(1, 0.5))
    mem.append(_snap_with_ratio(2, 0.5))
    # any None in the lookback window → not saturated
    assert not mem.is_saturated(lookback=2)
