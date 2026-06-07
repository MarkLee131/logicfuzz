"""LOGICFUZZ_LEAN_MODE crash-triage routing: _lean_crash_triage maps the
deterministic crash_frame verdict to the crash_analysis/context_analysis the
LLM agents would have written — library→keep(feasible), driver→fix(not
feasible), unknown→None(LLM fallback). Off / no-crash / already-triaged → None.
classify_crash_frame itself is covered by test_p1_crash_frame.py; here we
monkeypatch it to isolate the routing logic."""
from typing import Any

import tools.merge_drivers.crash_frame as crash_frame_mod
from src.workflow.nodes.supervisor import _lean_crash_triage


def _crash_state(crash_analysis=None) -> Any:
    return {
        "crashes": True,
        "run_error": "crash detected",
        "crash_analysis": crash_analysis,
        "crash_info": {"stack_trace": "==ERROR: AddressSanitizer: SEGV", "error_message": ""},
        "run_log": "",
    }


def test_off_returns_none(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_LEAN_MODE", raising=False)
    assert _lean_crash_triage(_crash_state(), 1) is None


def test_library_verdict_keeps_crash(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_LEAN_MODE", "1")
    monkeypatch.setattr(crash_frame_mod, "classify_crash_frame", lambda *a, **k: "library")
    v = _lean_crash_triage(_crash_state(), 1)
    assert v is not None
    assert v["crash_analysis"]["true_bug"] is True
    assert v["context_analysis"]["feasible"] is True   # → router returns END (keep real bug)


def test_driver_verdict_routes_to_fix(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_LEAN_MODE", "1")
    monkeypatch.setattr(crash_frame_mod, "classify_crash_frame", lambda *a, **k: "driver")
    v = _lean_crash_triage(_crash_state(), 1)
    assert v is not None
    assert v["context_analysis"]["feasible"] is False  # → router goes to fixer (FP)


def test_unknown_falls_back_to_llm(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_LEAN_MODE", "1")
    monkeypatch.setattr(crash_frame_mod, "classify_crash_frame", lambda *a, **k: "unknown")
    assert _lean_crash_triage(_crash_state(), 1) is None   # no injection → LLM path runs


def test_no_crash_returns_none(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_LEAN_MODE", "1")
    s = _crash_state()
    s["crashes"] = False
    s["run_error"] = ""
    assert _lean_crash_triage(s, 1) is None


def test_already_triaged_returns_none(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_LEAN_MODE", "1")
    monkeypatch.setattr(crash_frame_mod, "classify_crash_frame", lambda *a, **k: "library")
    # crash_analysis already set (e.g. LLM fallback ran for a prior 'unknown') → don't re-inject
    assert _lean_crash_triage(_crash_state(crash_analysis={"analyzed": True}), 1) is None
