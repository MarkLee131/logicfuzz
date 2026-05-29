"""Tests for the Z3-validated per-sequence skeleton synthesis path.

Background — the design choice
------------------------------
Earlier we found two parallel skeleton paths in the codebase:

1. ``SkeletonGenerator.generate(api_sequence)`` — TEMPLATE-based.
   Walks the sequence, type-string-matches arguments, drops Holes for
   uncertain bits. No Z3, no Provenance, no constraint solving.
2. ``CBFactory.create_random_driver_skeleton()`` — Z3-CONSTRAINED.
   Honours type matching, init-chain backtracking, lifecycle pairs,
   varlen relations. But internally calls ``_generate_api_sequence()``
   which RANDOMLY picks a source API; you cannot supply a target seq.

The user-facing intent: "skeleton + LLM-fill-holes, but skeleton must
be from program synthesis, not a simple pattern". Neither existing
path satisfies this. The fix is the public method
``CBFactory.create_skeleton_for_sequence(target_seq)`` that:

  - Validates ``target_seq`` against Z3 + provenance + lifecycle
    (``validate_sequence_with_z3``). Infeasible ⇒ returns None
    (viability self-decide; caller drops the sequence).
  - If valid, calls ``_create_skeleton_from_sequence`` which extracts
    varlen_relations from CBFactory.conditions and renders a skeleton
    with Holes. The structure is correct-by-construction.

The integration ``_synthesize_skeletons_per_sequence`` in
``data_context.py`` Step 10 loops the L4-viable list through this
method, producing 1 Z3-validated skeleton per accepted sequence.
"""
from __future__ import annotations

import os
import sys
import types
from unittest import mock

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# Lazy import inside helpers below — CBFactory pulls in heavy LLVM /
# liberator infrastructure that's slow at module load.


def _make_cbfactory_stub():
    """Build a CBFactory bound only to its three methods we care about
    (validate_sequence_with_z3, _create_skeleton_from_sequence,
    create_skeleton_for_sequence). Bypasses the real __init__ which
    needs api_list / conditions / Bias()."""
    from liberator_adapter.driver.factory.constraint_based.CBFactory import CBFactory
    inst = object.__new__(CBFactory)
    inst.enable_z3_validation = False  # validate falls through
    inst.z3_validator = None
    inst.conditions_map = {}
    return inst


class _FakeApi:
    def __init__(self, name):
        self.function_name = name


def test_returns_none_on_empty_sequence():
    cb = _make_cbfactory_stub()
    assert cb.create_skeleton_for_sequence([]) is None
    assert cb.create_skeleton_for_sequence(None) is None  # type: ignore[arg-type]


def test_returns_none_when_z3_rejects():
    """Z3 says infeasible → drop this sequence (viability self-decides)."""
    cb = _make_cbfactory_stub()
    seq = [_FakeApi('cJSON_Parse'), _FakeApi('cJSON_NoSuchAPI')]

    # Force the Z3 validator to reject.
    with mock.patch.object(
            cb, 'validate_sequence_with_z3',
            return_value=(False, ['type mismatch on arg 0'])):
        result = cb.create_skeleton_for_sequence(seq)

    assert result is None, \
        "Z3-rejected sequences must return None so caller can drop them"


def test_calls_create_skeleton_from_sequence_when_z3_accepts():
    """Z3 accepts → forward to _create_skeleton_from_sequence with the
    SAME sequence the caller supplied (not a re-randomized one)."""
    cb = _make_cbfactory_stub()
    seq = [_FakeApi('cJSON_Parse'), _FakeApi('cJSON_Delete')]
    sentinel_skeleton = object()  # any object; we only check identity

    with mock.patch.object(cb, 'validate_sequence_with_z3',
                           return_value=(True, [])) as m_val, \
         mock.patch.object(cb, '_create_skeleton_from_sequence',
                           return_value=sentinel_skeleton) as m_create:
        result = cb.create_skeleton_for_sequence(seq)

    assert result is sentinel_skeleton
    m_val.assert_called_once_with(seq)
    m_create.assert_called_once_with(seq)
    # Critically: the caller's sequence is what flows into the skeleton
    # generator, not a freshly-randomized one. This is the whole point
    # of the new method (vs create_random_driver_skeleton).
    args_passed = m_create.call_args[0][0]
    assert args_passed is seq


def test_returns_none_when_skeleton_infrastructure_unavailable():
    """If SKELETON_AVAILABLE is False (skeleton package not importable),
    the method must short-circuit cleanly, not raise."""
    # The package re-exports the class with the same dotted name as the
    # module file (`from .CBFactory import CBFactory`). Direct attribute
    # access via that path returns the class; the module itself lives in
    # sys.modules under the same key. Grab it from sys.modules.
    import sys
    _cbf_mod = sys.modules[
        'liberator_adapter.driver.factory.constraint_based.CBFactory']
    assert hasattr(_cbf_mod, 'SKELETON_AVAILABLE'), \
        'precondition: module must expose SKELETON_AVAILABLE'

    cb = _make_cbfactory_stub()
    seq = [_FakeApi('cJSON_Parse')]

    with mock.patch.object(_cbf_mod, 'SKELETON_AVAILABLE', False):
        result = cb.create_skeleton_for_sequence(seq)

    assert result is None


def test_z3_validation_disabled_falls_through_as_valid():
    """When enable_z3_validation=False, validate_sequence_with_z3 returns
    (True, []) by contract. The new method must respect that and still
    forward to _create_skeleton_from_sequence."""
    cb = _make_cbfactory_stub()
    cb.enable_z3_validation = False
    seq = [_FakeApi('foo')]
    sentinel = object()

    with mock.patch.object(
            cb, '_create_skeleton_from_sequence',
            return_value=sentinel) as m_create:
        result = cb.create_skeleton_for_sequence(seq)

    assert result is sentinel
    m_create.assert_called_once_with(seq)


# ============================================================
# _synthesize_skeletons_per_sequence: the data_context.py integration
# ============================================================

def _fake_generator(missing_prereq=None):
    """Fake ProjectDriverGenerator with the four prerequisites the helper
    checks. Set ``missing_prereq`` to one of {'condition_manager',
    'function_conditions', 'all_apis', 'dependency_graph'} to simulate
    that prerequisite being absent."""
    g = types.SimpleNamespace(
        condition_manager=object(),
        function_conditions=types.SimpleNamespace(
            fun_cond_set={'cJSON_Parse': None, 'cJSON_Delete': None}),
        all_apis=[_FakeApi('cJSON_Parse'), _FakeApi('cJSON_Delete')],
        dependency_graph={'cJSON_Parse': ['cJSON_Delete']},
    )
    if missing_prereq:
        setattr(g, missing_prereq,
                None if missing_prereq != 'all_apis' else [])
    return g


def test_skeleton_helper_returns_empty_on_missing_prereq():
    """Bug #6 fix (2026-05-29) — split by which prereq is missing.

    The only TRULY required prerequisites are all_apis + dependency_graph
    (CBFactory's unchecked render path needs nothing else). When
    condition_manager / function_conditions are missing we now degrade
    gracefully into the model-unchecked path instead of collapsing the whole
    portfolio to 1 LLM-only trial. The helper must not crash either way.
    """
    from src.context.data_context import _synthesize_skeletons_per_sequence
    import logging

    # Hard prerequisites: missing these still returns [] (no driver possible).
    for missing in ('all_apis', 'dependency_graph'):
        gen = _fake_generator(missing_prereq=missing)
        out = _synthesize_skeletons_per_sequence(
            generator=gen,
            target_sequences=[[_FakeApi('cJSON_Parse')]],
            driver_size=5,
            benchmark=types.SimpleNamespace(target_path='/src/x.c'),
            log=logging.getLogger('test'),
        )
        assert out == [], f'missing {missing} should return empty list'

    # Degraded prerequisites: must not raise. The helper attempts the
    # model-unchecked render path. With synthetic ``SimpleNamespace`` APIs the
    # renderer may produce nothing usable, but the helper must NOT crash with
    # an exception (real projects with real Api objects produce skeletons —
    # the bug #6 validation runs are in the commit message).
    for missing in ('condition_manager', 'function_conditions'):
        gen = _fake_generator(missing_prereq=missing)
        try:
            _synthesize_skeletons_per_sequence(
                generator=gen,
                target_sequences=[[_FakeApi('cJSON_Parse')]],
                driver_size=5,
                benchmark=types.SimpleNamespace(target_path='/src/x.c'),
                log=logging.getLogger('test'),
            )
        except Exception as exc:
            raise AssertionError(
                f'degraded mode (missing {missing}) must not raise; got '
                f'{type(exc).__name__}: {exc}')


def test_skeleton_helper_returns_empty_on_empty_target_sequences():
    from src.context.data_context import _synthesize_skeletons_per_sequence
    import logging
    out = _synthesize_skeletons_per_sequence(
        generator=_fake_generator(),
        target_sequences=[],
        driver_size=5,
        benchmark=types.SimpleNamespace(target_path='/src/x.c'),
        log=logging.getLogger('test'),
    )
    assert out == []


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
