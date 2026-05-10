"""Tests for the build_node telemetry robustness contract.

Background — found via a real zlib run (trial 03):

    Trial 03 hit a LANGUAGE_MISMATCH (LLM included
    <fuzzer/FuzzedDataProvider.h> in a pure-C target). Build failed,
    fixer ran 2 retries, supervisor ENDed. Yet build_attempts.json
    contained ZERO records — the very failure data the telemetry was
    designed to capture.

Root cause: the original try/except wrapped the ENTIRE telemetry block,
so any exception during *classification* (triage, context shape, etc.)
silently dropped the *whole record* — losing the success flag, error
count, and fixer-attempt counter, not just the category label.

Contract these tests pin down:

  - The base record (success/binary/error_count/attempt_idx) ALWAYS
    lands in build_attempts, regardless of triage outcome.
  - When triage works, primary_category and categories get filled.
  - When state.get('context') returns a non-dict (or None), the record
    still lands, just with empty categories.
  - Repeated invocations accumulate (the cjson regression).
"""
from __future__ import annotations

import os
import sys
import types

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _call_telemetry(state: dict, build_errors: list, compile_success: bool):
    """Replicate the telemetry logic from build_node in isolation.

    We import the *real* triage module so a regression in
    compilation_error_triage immediately surfaces here, but we drive the
    state-mutation logic via the helper (the build_node function itself
    requires a full LangGraph state which is heavy to fixture).

    The shape mirrors execution.py exactly — if those two ever diverge,
    grep for `base_record =` to find the canonical definition.
    """
    from src.utils.compilation_error_triage import triage_build_errors

    state_update = {
        "build_errors": build_errors,
        "binary_exists": compile_success,
    }

    base_record = {
        "attempt_idx": len(state.get("build_attempts", [])),
        "phase": state.get("workflow_phase", "compilation"),
        "compile_success": compile_success,
        "binary_exists": state_update["binary_exists"],
        "error_count": len(state_update["build_errors"]),
        "primary_category": None,
        "categories": {},
        "fixer_calls_before": state.get("node_visit_counts", {}).get("fixer", 0),
        "compilation_retry_count": state.get("compilation_retry_count", 0),
    }
    try:
        _ctx_for_triage = state.get("context") or {}
        if hasattr(_ctx_for_triage, 'get'):
            project_apis = _ctx_for_triage.get("project_apis", []) or []
        else:
            project_apis = []
        triage = triage_build_errors(state_update["build_errors"], project_apis)
        base_record["primary_category"] = (
            triage.primary_category.name if triage.primary_category else None)
        base_record["categories"] = {
            cat.name: count for cat, count in triage.summary.items()}
    except Exception:
        # The contract says the BASE record must still land.
        pass
    state_update["build_attempts"] = (
        state.get("build_attempts", []) + [base_record])
    return state_update


def test_base_record_lands_on_compile_success():
    state = {"build_attempts": [], "context": {"project_apis": []}}
    upd = _call_telemetry(state, build_errors=[], compile_success=True)
    assert len(upd["build_attempts"]) == 1
    rec = upd["build_attempts"][0]
    assert rec["compile_success"] is True
    assert rec["error_count"] == 0
    assert rec["primary_category"] is None  # no errors → no category


def test_base_record_lands_on_language_mismatch_failure():
    """The exact failure pattern from zlib trial 03."""
    errors = [
        "Language mismatch: C++ features detected in C project code.",
        "This will cause compilation failure. Please regenerate using "
        "pure C patterns.",
        "Common issues: FuzzedDataProvider (use memcpy), std::string (use char*).",
    ]
    state = {"build_attempts": [], "context": {"project_apis": []}}
    upd = _call_telemetry(state, build_errors=errors, compile_success=False)
    rec = upd["build_attempts"][0]
    assert rec["compile_success"] is False
    assert rec["error_count"] == 3, \
        "the count must be the number of error strings, not the triage classes"


def test_record_lands_even_when_context_is_none():
    """state['context'] may be None on early-error paths; record still fires."""
    state = {"build_attempts": [], "context": None}
    upd = _call_telemetry(state, build_errors=[
        "/src/x.c: undefined reference to `cJSON_Parse`"
    ], compile_success=False)
    assert len(upd["build_attempts"]) == 1
    # Without project_apis, triage falls through to LINK_ERROR (per the
    # P0-3 INCONCLUSIVE_LINK gating tests).
    assert upd["build_attempts"][0]["primary_category"] == "LINK_ERROR"


def test_record_lands_when_context_is_unexpected_shape():
    """state['context'] could in theory be a non-dict; record still fires."""
    # Pydantic-style object without .get() — the helper handles it
    # gracefully via hasattr check.
    fake_ctx = types.SimpleNamespace(
        not_a_dict=True,
        # SimpleNamespace doesn't have .get(); the hasattr branch should
        # catch this and fall through to project_apis=[].
    )
    state = {"build_attempts": [], "context": fake_ctx}
    upd = _call_telemetry(state, build_errors=[
        "/src/x.c:1: error: 'foo' was not declared in this scope"
    ], compile_success=False)
    rec = upd["build_attempts"][0]
    assert rec["compile_success"] is False
    assert rec["primary_category"] is not None, \
        "triage should still run when context is non-dict"


def test_records_accumulate_across_invocations():
    """The cjson regression: 4 build_node calls → 4 records in the list."""
    state = {"build_attempts": [], "context": {"project_apis": []}}
    for i in range(4):
        upd = _call_telemetry(state, build_errors=[], compile_success=True)
        # Mirror the LangGraph reducer-less merge (REPLACE) — the next
        # invocation reads back the merged state.
        state["build_attempts"] = upd["build_attempts"]
    assert len(state["build_attempts"]) == 4
    assert [r["attempt_idx"] for r in state["build_attempts"]] == [0, 1, 2, 3]


def test_workflow_phase_is_recorded():
    """Compilation vs optimization distinction must reach the record."""
    state = {
        "build_attempts": [],
        "context": {"project_apis": []},
        "workflow_phase": "optimization",
    }
    upd = _call_telemetry(state, [], compile_success=True)
    assert upd["build_attempts"][0]["phase"] == "optimization"


def test_fixer_calls_before_increments():
    """For p95 budget calibration we need to know the attempt count BEFORE
    the current build, not after."""
    state = {
        "build_attempts": [],
        "context": {"project_apis": []},
        "node_visit_counts": {"fixer": 2},
    }
    upd = _call_telemetry(state, [], compile_success=True)
    assert upd["build_attempts"][0]["fixer_calls_before"] == 2


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
