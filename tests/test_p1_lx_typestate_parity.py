"""Pin down L2/L3 validate_sequence semantics after the typestate migration.

Background
----------
``LifecycleAnalyzer.validate_sequence`` and ``StateMachineAnalyzer.validate_sequence``
used to carry their own per-resource walkers, duplicating the typestate
semantics already implemented in ``liberator_adapter/analysis/usedef.py::Typestate.check``.
The 2026-05 migration deletes those walkers and routes both filters through
``Typestate.check`` (with a per-analysis cached ``UseDefGraph`` built from
each filter's domain model — lifecycle pairs / state constraints).

These tests guard against regressions in the *external surface* of each
validator: result-type shape, violation classification, and the
``final_states`` / ``unclosed_resources`` / ``unopened_closes`` fields the
downstream filters depend on.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.constraints.lifecycle_analyzer import (  # noqa: E402
    DiscoveryMethod,
    LifecycleAnalysis,
    LifecycleAnalyzer,
    LifecyclePair,
)
from liberator_adapter.constraints.state_machine_analyzer import (  # noqa: E402
    APIRole,
    ResourceState,
    StateConstraint,
    StateMachineAnalysis,
    StateMachineAnalyzer,
    ViolationType,
)


# ---------------------------------------------------------------------------
# L2: LifecycleAnalyzer.validate_sequence
# ---------------------------------------------------------------------------

def _l2_single_pair_analysis():
    pair = LifecyclePair(
        init_api='cJSON_Parse', destroy_api='cJSON_Delete',
        resource_type='cJSON_handle',
        discovery_method=DiscoveryMethod.NAME_PATTERN,
        confidence=0.9,
    )
    a = LifecycleAnalysis(pairs=[pair], total_apis=2)
    a._build_lookups()
    return a


def test_l2_valid_init_destroy_pair_is_valid():
    a = _l2_single_pair_analysis()
    r = LifecycleAnalyzer().validate_sequence(['cJSON_Parse', 'cJSON_Delete'], a)
    assert r.is_valid
    assert r.unclosed_resources == []
    assert r.unopened_closes == []


def test_l2_unclosed_resource_surfaces_init_and_cleanup():
    a = _l2_single_pair_analysis()
    r = LifecycleAnalyzer().validate_sequence(['cJSON_Parse'], a)
    assert not r.is_valid
    assert r.unclosed_resources == ['cJSON_Parse']
    assert r.suggested_cleanup == ['cJSON_Delete']


def test_l2_destroy_before_init_surfaces_as_unopened_close():
    a = _l2_single_pair_analysis()
    r = LifecycleAnalyzer().validate_sequence(['cJSON_Delete'], a)
    assert not r.is_valid
    assert r.unopened_closes == ['cJSON_Delete']


def test_l2_double_destroy_flagged_via_unopened_closes():
    a = _l2_single_pair_analysis()
    r = LifecycleAnalyzer().validate_sequence(
        ['cJSON_Parse', 'cJSON_Delete', 'cJSON_Delete'], a)
    assert not r.is_valid
    assert 'cJSON_Delete' in r.unopened_closes


def test_l2_shared_destroy_across_multiple_inits():
    p1 = LifecyclePair('ucl_parser_new', 'ucl_parser_free',
                       resource_type='ucl_parser')
    p2 = LifecyclePair('ucl_parser_new_with_pool', 'ucl_parser_free',
                       resource_type='ucl_parser')
    a = LifecycleAnalysis(pairs=[p1, p2], total_apis=3)
    a._build_lookups()
    lc = LifecycleAnalyzer()
    assert lc.validate_sequence(
        ['ucl_parser_new', 'ucl_parser_free'], a).is_valid
    assert lc.validate_sequence(
        ['ucl_parser_new_with_pool', 'ucl_parser_free'], a).is_valid


# ---------------------------------------------------------------------------
# L3: StateMachineAnalyzer.validate_sequence
# ---------------------------------------------------------------------------

def _l3_full_analysis():
    init_c = StateConstraint(
        api_name='cJSON_Parse',
        postconditions={'cJSON': ResourceState.INITIALIZED},
        roles={'cJSON': APIRole.INITIALIZER},
    )
    user_c = StateConstraint(
        api_name='cJSON_Print',
        preconditions={'cJSON': ResourceState.INITIALIZED},
        postconditions={'cJSON': ResourceState.INITIALIZED},
        roles={'cJSON': APIRole.USER},
    )
    destroy_c = StateConstraint(
        api_name='cJSON_Delete',
        preconditions={'cJSON': ResourceState.INITIALIZED},
        postconditions={'cJSON': ResourceState.DESTROYED},
        roles={'cJSON': APIRole.DESTROYER},
    )
    return StateMachineAnalysis(
        constraints={
            'cJSON_Parse': init_c,
            'cJSON_Print': user_c,
            'cJSON_Delete': destroy_c,
        },
        resource_types={'cJSON'},
        total_apis=3,
    )


def test_l3_valid_parse_use_destroy_is_valid():
    r = StateMachineAnalyzer().validate_sequence(
        ['cJSON_Parse', 'cJSON_Print', 'cJSON_Delete'], _l3_full_analysis())
    assert r.is_valid


def test_l3_use_before_init():
    r = StateMachineAnalyzer().validate_sequence(['cJSON_Print'], _l3_full_analysis())
    assert {v.violation_type for v in r.violations} == {ViolationType.USE_BEFORE_INIT}


def test_l3_use_after_destroy():
    r = StateMachineAnalyzer().validate_sequence(
        ['cJSON_Parse', 'cJSON_Delete', 'cJSON_Print'], _l3_full_analysis())
    assert {v.violation_type for v in r.violations} == {ViolationType.USE_AFTER_DESTROY}


def test_l3_double_destroy_clean_no_spurious_use_after_destroy():
    """Pin against the bug found during migration: the typestate graph
    must not assign a USE on destroy APIs, otherwise the second destroy
    would falsely emit USE_AFTER_DESTROY in addition to DOUBLE_DESTROY."""
    r = StateMachineAnalyzer().validate_sequence(
        ['cJSON_Parse', 'cJSON_Delete', 'cJSON_Delete'], _l3_full_analysis())
    assert {v.violation_type for v in r.violations} == {ViolationType.DOUBLE_DESTROY}


def test_l3_destroy_before_init():
    r = StateMachineAnalyzer().validate_sequence(['cJSON_Delete'], _l3_full_analysis())
    assert {v.violation_type for v in r.violations} == {ViolationType.DESTROY_BEFORE_INIT}


def test_l3_reinit_strict_gating():
    sa = StateMachineAnalyzer()
    r = sa.validate_sequence(['cJSON_Parse', 'cJSON_Parse'], _l3_full_analysis(),
                             strict=False)
    assert r.is_valid, 'non-strict mode must NOT report REINIT_WITHOUT_DESTROY'
    # New analysis object so the typestate-graph cache doesn't carry state
    # across strict-mode toggles (it doesn't — caching is structural — but
    # the test stays clean either way).
    r = sa.validate_sequence(['cJSON_Parse', 'cJSON_Parse'], _l3_full_analysis(),
                             strict=True)
    assert {v.violation_type for v in r.violations} == {
        ViolationType.REINIT_WITHOUT_DESTROY,
    }


def test_l3_final_states_track_trajectory():
    """``final_states`` must reflect the postcondition trajectory even when
    no violations fire."""
    r = StateMachineAnalyzer().validate_sequence(['cJSON_Parse'], _l3_full_analysis())
    assert r.final_states['cJSON'] == ResourceState.INITIALIZED
