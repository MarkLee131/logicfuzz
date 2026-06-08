"""Regression tests for workflow-routing fixes (audit #3 + #5).

#3: a deterministic crash-FP (crash_analyzer / lean) emits BOTH crash_analysis
    (true_bug=False) AND context_analysis (feasible=False), so the supervisor
    routes straight to the (capped) fixer instead of burning a redundant LLM
    crash_feasibility_analyzer turn.
#5: route_condition END-with-error on a missing/unknown next_action instead of
    raising (an uncaught raise is re-raised by workflow.run as a fatal
    RuntimeError that kills the whole trial).
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.workflow.nodes.supervisor import (  # noqa: E402
    route_condition, _handle_execution_failure)


# ---- #5: route_condition graceful END --------------------------------------

def test_route_known_actions():
    assert route_condition({"next_action": "fixer", "trial": 1}) == "fixer"
    assert route_condition({"next_action": "crash_analyzer", "trial": 1}) \
        == "crash_analyzer"
    assert route_condition({"next_action": "END", "trial": 1}) == "__end__"


def test_route_unknown_action_ends_not_raises():
    # was: raise ValueError → fatal RuntimeError kills the trial
    assert route_condition({"next_action": "typo_node", "trial": 1}) == "__end__"


def test_route_missing_next_action_ends_not_raises():
    assert route_condition({"trial": 1}) == "__end__"


# ---- #3: crash-FP routes to fixer, skipping feasibility LLM -----------------

def _crash_state(**kw):
    s = {"crashes": True, "crash_fix_retry_count": 0}
    s.update(kw)
    return s


def test_no_crash_analysis_routes_to_crash_analyzer():
    assert _handle_execution_failure(_crash_state(), 1) == "crash_analyzer"


def test_crash_analysis_without_context_routes_to_feasibility():
    s = _crash_state(crash_analysis={"true_bug": False})
    assert _handle_execution_failure(s, 1) == "crash_feasibility_analyzer"


def test_fp_with_context_routes_straight_to_fixer():
    # #3 fix: crash_analyzer FP now emits context_analysis too → no redundant
    # crash_feasibility_analyzer turn; infeasible → capped fixer.
    s = _crash_state(crash_analysis={"true_bug": False},
                     context_analysis={"feasible": False})
    assert _handle_execution_failure(s, 1) == "fixer"


def test_feasible_crash_ends_keeping_the_bug():
    s = _crash_state(crash_analysis={"true_bug": True},
                     context_analysis={"feasible": True})
    assert _handle_execution_failure(s, 1) == "END"


def test_fp_fixer_capped():
    s = _crash_state(crash_analysis={"true_bug": False},
                     context_analysis={"feasible": False},
                     crash_fix_retry_count=1)  # >= MAX_CRASH_FIX_RETRIES
    assert _handle_execution_failure(s, 1) == "END"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
