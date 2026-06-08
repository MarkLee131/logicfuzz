"""T12 — dynamic value feedback (LOGICFUZZ_VALUE_FEEDBACK).

coverage_memory.json was write-only. T12 closes the loop: capture a trial's
filled hole values (side file), persist them into the snapshot, then on a LATER
run read back the values that reached the deepest coverage for a skeleton and pin
them into that skeleton's holes.

Cross-run matching is by the API-SEQUENCE CONTENT key (``sequence_key``), NOT the
positional ``cbfactory_skeleton_{i}`` name — index ``i`` can denote a different
sequence next run, so a positional match would mis-pin values onto an unrelated
API chain (regression-tested below).
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.state.coverage_memory import (  # noqa: E402
    CoverageMemory, IterationSnapshot, TrialOutcome,
    sequence_key, proven_hole_values, attach_proven_holes,
    record_trial_hole_values, load_trial_hole_values,
)


def _mem(*trials) -> CoverageMemory:
    m = CoverageMemory(project="p")
    m.append(IterationSnapshot(iteration_idx=0, timestamp="t",
                               trial_count=len(trials),
                               trial_results=list(trials)))
    return m


def _trial(tid, cov, key, holes, success=True):
    return TrialOutcome(trial_id=tid, api_sequence=[], final_coverage_pct=cov,
                        success=success, skeleton_name="n", skeleton_key=key,
                        hole_values=holes)


# ---- sequence_key: stable content hash ------------------------------------

def test_sequence_key_is_content_stable_and_order_sensitive():
    assert sequence_key(["a", "b"]) == sequence_key(["a", "b"])
    assert sequence_key(["a", "b"]) != sequence_key(["b", "a"])
    assert sequence_key([]) == ""               # empty never matches
    assert sequence_key(["a"]) != ""


# ---- read side: highest-coverage selection (by key) ------------------------

def test_proven_picks_highest_coverage_for_key():
    mem = _mem(
        _trial(1, 10.0, "kA", {"__HOLE_a__": "1"}),
        _trial(2, 40.0, "kA", {"__HOLE_a__": "2"}),   # higher cov → wins
        _trial(3, 99.0, "kB", {"__HOLE_a__": "9"}),   # other sequence
    )
    assert proven_hole_values(mem, "kA") == {"__HOLE_a__": "2"}
    assert proven_hole_values(mem, "kB") == {"__HOLE_a__": "9"}


def test_proven_unknown_key_is_empty():
    mem = _mem(_trial(1, 10.0, "kA", {"__HOLE_a__": "1"}))
    assert proven_hole_values(mem, "nope") == {}
    assert proven_hole_values(mem, "") == {}


def test_proven_skips_failed_and_empty_trials():
    mem = _mem(
        _trial(1, 90.0, "kA", {"__HOLE_a__": "fail"}, success=False),  # skip
        _trial(2, 80.0, "kA", {}),                                     # skip
        _trial(3, 5.0, "kA", {"__HOLE_a__": "ok"}),                    # only valid
    )
    assert proven_hole_values(mem, "kA") == {"__HOLE_a__": "ok"}


# ---- attach by api-sequence content key ------------------------------------

def test_attach_matches_by_sequence_content():
    seq = ["create", "use", "destroy"]
    mem = _mem(_trial(1, 40.0, sequence_key(seq), {"__HOLE_a__": "2"}))
    sks = [{"name": "sk0", "api_sequence": seq, "holes": []},
           {"name": "skX", "api_sequence": ["unrelated"]}]
    n = attach_proven_holes(sks, mem)
    assert n == 1
    assert sks[0]["proven_holes"] == {"__HOLE_a__": "2"}
    assert "proven_holes" not in sks[1]


def test_positional_name_collision_does_not_mispin():
    # THE bug the key fix prevents: run1's skeleton_0 was sequence A; run2's
    # skeleton_0 is a DIFFERENT sequence B → A's values must NOT pin onto B.
    seqA = ["createA", "useA"]
    seqB = ["createB", "useB"]
    mem = _mem(_trial(1, 50.0, sequence_key(seqA), {"__HOLE_a__": "A"}))
    sks_b = [{"name": "cbfactory_skeleton_0", "api_sequence": seqB}]
    assert attach_proven_holes(sks_b, mem) == 0
    assert "proven_holes" not in sks_b[0]
    # but the SAME sequence recurring (any position) DOES get pinned
    sks_a = [{"name": "cbfactory_skeleton_5", "api_sequence": seqA}]
    assert attach_proven_holes(sks_a, mem) == 1
    assert sks_a[0]["proven_holes"] == {"__HOLE_a__": "A"}


def test_attach_empty_memory_noop():
    assert attach_proven_holes(
        [{"name": "sk0", "api_sequence": ["x"]}], CoverageMemory(project="p")) == 0


# ---- capture/load roundtrip (side file) -----------------------------------

def test_record_load_roundtrip(tmp_path):
    record_trial_hole_values("p", 3, "sk1", ["a", "b"], {"__HOLE_x__": "5"},
                             state_dir=tmp_path)
    got = load_trial_hole_values("p", 3, state_dir=tmp_path)
    assert got["skeleton_name"] == "sk1"
    assert got["skeleton_key"] == sequence_key(["a", "b"])
    assert got["hole_values"] == {"__HOLE_x__": "5"}


def test_record_empty_values_writes_nothing(tmp_path):
    record_trial_hole_values("p", 4, "sk1", ["a"], {}, state_dir=tmp_path)
    assert load_trial_hole_values("p", 4, state_dir=tmp_path) == {}


def test_load_missing_trial_is_empty(tmp_path):
    assert load_trial_hole_values("p", 999, state_dir=tmp_path) == {}


# ---- forward compatibility: old JSON lacks the T12 fields ------------------

def test_old_json_loads_with_defaults(tmp_path):
    old = {
        "project": "p", "schema_version": 1, "iteration_count": 1,
        "latest_ratio_to_baseline": None,
        "snapshots": [{
            "iteration_idx": 0, "timestamp": "t", "trial_count": 1,
            "merged_driver_path": None, "merged_driver_count": 0,
            "aggregate_max_coverage_pct": None, "baseline_line_count": None,
            "baseline_covered_lines": None, "baseline_coverage_pct": None,
            "coverage_ratio_to_baseline": None, "aggregate_line_diff_pct": None,
            "trial_results": [{
                "trial_id": 1, "api_sequence": [], "final_coverage_pct": 5.0,
                "final_line_diff_pct": None, "crashes_found": 0, "success": True,
            }],
        }],
    }
    p = tmp_path / "coverage_memory.json"
    p.write_text(json.dumps(old), encoding="utf-8")
    mem = CoverageMemory.load_or_create("p", p)
    t = mem.snapshots[0].trial_results[0]
    assert t.skeleton_key is None
    assert t.hole_values == {}


def test_new_fields_survive_roundtrip(tmp_path):
    mem = _mem(_trial(1, 40.0, "kA", {"__HOLE_a__": "2"}))
    p = tmp_path / "coverage_memory.json"
    mem.persist(p)
    back = CoverageMemory.load_or_create("p", p)
    t = back.snapshots[0].trial_results[0]
    assert t.skeleton_key == "kA"
    assert t.hole_values == {"__HOLE_a__": "2"}


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
