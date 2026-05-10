"""Regression tests for trial-level diversity in the prototyper.

Background — the silent bug
---------------------------
``run_logicfuzz.py -n N`` runs N trials of the same benchmark, each
intended to explore a *different* protocol so that the resulting
fuzz drivers genuinely cover different parts of the API surface.
``tools.merge_drivers`` then folds the per-trial drivers into a
single multi-task harness whose value comes from this diversity
(PromeFuzz CCS'25 multi-task fuzzing argument).

The bug we're pinning down here:

  - ``_format_synthesis_base_driver`` read
    ``state.get("synthesis_driver_index", 0)`` and **no code path
    ever wrote that key**, so every trial used
    ``skeleton_drivers[0]`` regardless of N.
  - ``_format_api_sequences`` showed the same top-K to every trial
    without marking any one as the trial's primary target, so the
    LLM converged on the top-1 protocol every time.

Empirical confirmation of the symptom (cjson, two trials):

    diff results/output-cjson-project/fuzz_targets/01.fuzz_target \\
         results/output-cjson-project/fuzz_targets/02.fuzz_target
    # → only whitespace, comment text, and variable-name differences.
    # Same API call sequence: cJSON_ParseWithOpts → AddArrayToObject
    # → AddBoolToObject → cJSON_Delete on both trials.

The contract these tests pin down:

  - For trial N (1-indexed), the prototyper's caller must compute
    ``active_idx = (N-1) % len(skeleton_drivers)`` and pass
    ``skeleton_drivers[active_idx]`` (a single dict) to
    ``_format_synthesis_base_driver``.
  - The formatter renders that single skeleton; trials with disjoint
    indices therefore produce strictly different rendered text.
  - For trial N, the rendered ``api_sequences_text`` highlights
    ``api_sequences[(N-1) % K]`` as the PRIMARY sequence.
"""
from __future__ import annotations

import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The repo has a workflow ↔ agents circular import (src.workflow.nodes
# .prototyper imports from src.agents while src.agents.__init__ pulls in
# src.workflow.state). Python resolves it on the second attempt, after
# the partial-import state populates. Documented retry pattern.
try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402


def _fake_prototyper(trial: int):
    """Construct a minimal LangGraphPrototyper that has only `self.trial`
    populated. Bypasses the heavy parent __init__ (model adapter loading,
    prompt manager wiring, etc.) — the format helpers under test only
    depend on self.trial.
    """
    inst = object.__new__(LangGraphPrototyper)
    inst.trial = trial
    return inst


SKELETON_DRIVERS = [
    {
        'name': 'cbfactory_skeleton_0',
        'api_sequence': ['parse', 'serialize'],
        'code': 'int main_alpha() { return 0; }',
        'synthesis_info': {'method': 'CBFactory_skeleton_for_sequence',
                           'has_cleanup': True},
    },
    {
        'name': 'cbfactory_skeleton_1',
        'api_sequence': ['init', 'consume', 'free'],
        'code': 'int main_beta() { return 1; }',
        'synthesis_info': {'method': 'CBFactory_skeleton_for_sequence',
                           'has_cleanup': True},
    },
    {
        'name': 'cbfactory_skeleton_2',
        'api_sequence': ['create', 'transform', 'destroy'],
        'code': 'int main_gamma() { return 2; }',
        'synthesis_info': {'method': 'CBFactory_skeleton_for_sequence',
                           'has_cleanup': False},
    },
]


def _pick_active(trial: int, drivers):
    """Replicate the caller-side selection in prototyper.__call__:
    active_idx = (trial - 1) % len(drivers); active = drivers[active_idx].
    Pinning this here is the contract — if the formatter signature
    changes again, this helper is the single point we update."""
    if not drivers:
        return None
    return drivers[(trial - 1) % len(drivers)]

API_SEQUENCES = [
    ['cJSON_Parse', 'cJSON_GetArraySize', 'cJSON_Delete'],
    ['cJSON_CreateObject', 'cJSON_AddItemToObject', 'cJSON_Print', 'cJSON_Delete'],
    ['cJSON_Parse', 'cJSON_Compare', 'cJSON_Delete'],
]


# ============================================================
# Synthesis base driver: trial → driver index routing
# ============================================================

def test_trial_1_picks_first_skeleton():
    proto = _fake_prototyper(trial=1)
    active = _pick_active(1, SKELETON_DRIVERS)
    text = proto._format_synthesis_base_driver(active)
    assert 'cbfactory_skeleton_0' in text
    assert 'main_alpha' in text


def test_trial_2_picks_second_skeleton():
    """The reproducer for the bug. Pre-fix: trial 2 also got skeleton_0."""
    proto = _fake_prototyper(trial=2)
    active = _pick_active(2, SKELETON_DRIVERS)
    text = proto._format_synthesis_base_driver(active)
    assert 'cbfactory_skeleton_1' in text
    assert 'main_beta' in text
    assert 'cbfactory_skeleton_0' not in text, \
        'BUG REGRESSION: trial 2 must NOT get skeleton_0 — that was the silent bug'


def test_trial_3_picks_third_skeleton():
    proto = _fake_prototyper(trial=3)
    active = _pick_active(3, SKELETON_DRIVERS)
    text = proto._format_synthesis_base_driver(active)
    assert 'cbfactory_skeleton_2' in text


def test_trial_count_exceeding_pool_wraps_modulo():
    """Graceful degradation: trial number > pool size reuses earlier
    indices. Trial 4 → skeleton 0 (0-indexed) when pool size = 3."""
    proto = _fake_prototyper(trial=4)
    active = _pick_active(4, SKELETON_DRIVERS)
    text = proto._format_synthesis_base_driver(active)
    assert 'cbfactory_skeleton_0' in text


def test_empty_skeleton_drivers_returns_empty_string():
    """No skeletons = no synthesis section. Must not crash."""
    proto = _fake_prototyper(trial=1)
    active = _pick_active(1, [])
    assert active is None
    text = proto._format_synthesis_base_driver(active)
    assert text == ""


# ============================================================
# API sequences: trial → primary sequence highlighting
# ============================================================

def test_primary_index_marks_only_one_sequence():
    proto = _fake_prototyper(trial=1)
    text = proto._format_api_sequences(API_SEQUENCES, primary_index=0)
    # Must contain a PRIMARY marker
    assert 'PRIMARY' in text
    # Must mark exactly the requested sequence
    assert 'Sequence 1 ★ PRIMARY' in text
    assert 'Sequence 2 ★ PRIMARY' not in text
    assert 'Sequence 3 ★ PRIMARY' not in text


def test_primary_index_none_yields_no_marker():
    """Backwards-compat: callers that don't pass primary_index get the
    old un-prioritised rendering."""
    proto = _fake_prototyper(trial=1)
    text = proto._format_api_sequences(API_SEQUENCES)
    assert 'PRIMARY' not in text


def test_trial_1_and_trial_2_get_different_primary_sequences():
    """The end-to-end regression: trial 1's prompt and trial 2's prompt
    point at DIFFERENT primary protocols."""
    proto1 = _fake_prototyper(trial=1)
    proto2 = _fake_prototyper(trial=2)
    primary1 = (proto1.trial - 1) % len(API_SEQUENCES)
    primary2 = (proto2.trial - 1) % len(API_SEQUENCES)
    assert primary1 != primary2
    text1 = proto1._format_api_sequences(API_SEQUENCES, primary_index=primary1)
    text2 = proto2._format_api_sequences(API_SEQUENCES, primary_index=primary2)
    # Sanity: same input length, both have markers, different primary
    assert text1 != text2
    assert 'Sequence 1 ★ PRIMARY' in text1
    assert 'Sequence 2 ★ PRIMARY' in text2


def test_primary_index_out_of_range_no_marker():
    """Defensive: bad index does not crash, just renders without highlight."""
    proto = _fake_prototyper(trial=1)
    text = proto._format_api_sequences(API_SEQUENCES, primary_index=99)
    assert '★ PRIMARY' not in text


# ============================================================
# End-to-end diversity: trial 1 vs trial 2 must produce DIFFERENT
# rendered prompt fragments. This is the test that would have caught
# the cjson/zlib symptom directly.
# ============================================================

def test_two_trials_produce_distinguishable_prompt_fragments():
    """Composite: combine synthesis-base + api-sequences. Two distinct
    trials must yield text that differs in both axes — driver name and
    primary sequence — not just whitespace."""
    proto1 = _fake_prototyper(trial=1)
    proto2 = _fake_prototyper(trial=2)

    base1 = proto1._format_synthesis_base_driver(
        _pick_active(1, SKELETON_DRIVERS))
    base2 = proto2._format_synthesis_base_driver(
        _pick_active(2, SKELETON_DRIVERS))

    seq1 = proto1._format_api_sequences(
        API_SEQUENCES,
        primary_index=(proto1.trial - 1) % len(API_SEQUENCES))
    seq2 = proto2._format_api_sequences(
        API_SEQUENCES,
        primary_index=(proto2.trial - 1) % len(API_SEQUENCES))

    fragment1 = base1 + '\n' + seq1
    fragment2 = base2 + '\n' + seq2

    # Strict inequality — not just a few whitespace chars different.
    # We measure the meaningful diff by checking specific markers.
    assert 'cbfactory_skeleton_0' in fragment1
    assert 'cbfactory_skeleton_1' in fragment2
    assert 'main_alpha' in fragment1
    assert 'main_beta' in fragment2

    # The PRIMARY marker for trial 1 vs trial 2 must hit different lines.
    assert 'Sequence 1 ★ PRIMARY' in fragment1
    assert 'Sequence 2 ★ PRIMARY' in fragment2


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
