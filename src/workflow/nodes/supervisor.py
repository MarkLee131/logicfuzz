"""
Supervisor node for LangGraph workflow routing.

This module provides the routing logic for the fuzzing workflow,
determining which agents to execute next based on the current state.

State Machine:
==============

COMPILATION PHASE:
┌─────────────┐
│  prototyper │ ◄─── no fuzz_target_source
└──────┬──────┘
       ▼
┌─────────────┐  fail   ┌─────────────┐
│    build    │────────►│    fixer    │ (max 3 retries, then END)
└──────┬──────┘         └──────┬──────┘
       │ success               │
       ▼                       ▼
   [OPTIMIZATION]           build ───► ...

OPTIMIZATION PHASE:
                    ┌─────────────────────────────────────────────────────┐
                    │                                                     │
                    ▼                                                     │
┌─────────────┐  fail   ┌─────────────┐                                   │
│    build    │────────►│    fixer    │ (max 3 retries, then END)         │
└──────┬──────┘         └──────┬──────┘                                   │
       │ success               │                                          │
       ▼                       ▼                                          │
┌─────────────┐             build ───► ...                                │
│  execution  │                                                           │
└──────┬──────┘                                                           │
       │                                                                  │
       ├─── crash ──► crash_analyzer ──► crash_feasibility_analyzer       │
       │                                        │                         │
       │                        ┌───────────────┴──────────┐              │
       │                        ▼                          ▼              │
       │                      END (true bug)            fixer ────────────┤
       │                                                                  │
       │                                            (resets retry count)  │
       └─── success ──► END
"""
from typing import Dict, Any, Optional, cast

from langchain_core.runnables import RunnableConfig
import logger
from src.workflow.state import FuzzingWorkflowState, consolidate_session_memory
from src.utils.compilation_error_triage import (
    triage_build_errors, ErrorCategory)


# ==================== Configuration Constants ====================
MAX_COMPILATION_RETRIES = 2          # Max fixer attempts during compilation
MAX_CRASH_FIX_RETRIES = 1            # Max fixer attempts after crash (false positive)
MAX_TOTAL_BUILD_FAILURES = 5         # Global safety limit
MAX_NODE_VISITS = 6                  # Loop detection threshold
MAX_FIXER_INVOCATIONS = 3            # Hard cap on total fixer invocations per trial


# ==================== Lean Mode (roadmap item 4) ====================
def _crash_asan_log(state: FuzzingWorkflowState) -> str:
    """Best-effort ASan/backtrace text for deterministic frame attribution.

    ``execution_node`` stashes the libFuzzer/ASan output in
    ``crash_info.stack_trace`` / ``crash_info.error_message`` (both populated
    from ``run_result.crash_info``) and the condensed run summary in
    ``run_log`` (which retains the ``AddressSanitizer`` / ``#N 0x.. in ..``
    frames via ``extract_fuzzing_summary``). Concatenate what's available so
    ``classify_crash_frame`` sees the in-source backtrace frames.
    """
    ci = state.get("crash_info") or {}
    parts = [
        ci.get("stack_trace", ""),
        ci.get("error_message", ""),
        state.get("run_log", ""),
    ]
    return "\n".join(p for p in parts if p)


def _lean_crash_triage(state: FuzzingWorkflowState,
                       trial: int) -> Optional[Dict[str, Any]]:
    """Lean deterministic crash triage (runs unconditionally; no env gate).

    Returns synthetic ``crash_analysis`` + ``context_analysis`` verdicts that
    the EXISTING router + caps + fixer plumbing consume exactly as if the LLM
    CrashAnalyzer/CrashFeasibilityAnalyzer had produced them — but computed
    from the ASan stack frames via ``classify_crash_frame`` (0 LLM calls):

      * ``library`` frame → real bug → ``feasible=True``  → router END.
      * ``driver``  frame → false positive → ``feasible=False`` → router
        fixer (capped at MAX_CRASH_FIX_RETRIES, then END), unchanged.
      * ``unknown``       → return ``None`` → fall back to the LLM path.

    Returns ``None`` when there is no fresh crash, or when a crash has already
    been triaged (so the 'unknown' LLM fallback runs once and is not
    re-classified on the next supervisor visit).
    """
    crashes = state.get("crashes", False)
    run_error = state.get("run_error", "") or ""
    is_crash = crashes or ("crash" in run_error.lower())
    if not is_crash:
        return None
    if state.get("crash_analysis") is not None:
        return None  # already triaged (e.g. LLM fallback for a prior 'unknown')

    from tools.merge_drivers.crash_frame import classify_crash_frame
    asan_log = _crash_asan_log(state)
    driver_basename = f'{trial:02d}.fuzz_target'
    verdict = classify_crash_frame(asan_log, driver_basename)
    if verdict == "unknown":
        logger.info(
            'LEAN crash triage: unknown frame attribution, falling back to '
            'LLM CrashAnalyzer/CrashFeasibilityAnalyzer', trial=trial)
        return None

    feasible = (verdict == "library")
    logger.info(
        f'LEAN crash triage: deterministic verdict={verdict} '
        f'(feasible={feasible}) — skipping LLM crash analysis '
        f'(saved 2 LLM calls)', trial=trial)
    note = ('real library bug (keep)' if feasible
            else 'driver false-positive (fix / merge-quarantine)')
    return {
        "crash_analysis": {
            "source": "lean_crash_frame_classifier",
            "verdict": verdict,
            "true_bug": feasible,
            "insight": (f'Deterministic ASan frame attribution: first '
                        f'in-source crash frame is {verdict} code.'),
            "analysis": f'Crash frame attributed to {verdict} → {note}.',
            "analyzed": True,
        },
        "context_analysis": {
            "source": "lean_crash_frame_classifier",
            "verdict": verdict,
            "feasible": feasible,
            "analysis": f'Lean-mode deterministic verdict: {verdict}-frame '
                        f'crash → {note}.',
            "analyzed": True,
        },
    }


def supervisor_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Supervisor node that determines the next action in the workflow.

    Args:
        state: Current LangGraph workflow state
        config: Configuration containing workflow parameters

    Returns:
        Dictionary with next_action and routing decisions
    """
    trial = state["trial"]
    logger.info('Starting Supervisor node', trial=trial)

    # Global error limit check
    errors = state.get("errors", [])
    max_errors = config.get("configurable", {}).get("max_errors", 5)
    if len(errors) >= max_errors:
        logger.warning(f'Too many errors ({len(errors)}), terminating workflow', trial=trial)
        return _end_workflow("too_many_errors", f"Workflow terminated due to {len(errors)} errors")

    # Lean deterministic crash triage (runs UNCONDITIONALLY — there is no env
    # gate): replace the 2-call LLM crash triage with a deterministic crash-frame
    # verdict. We synthesize the crash_analysis + context_analysis the LLMs would
    # have produced and merge them into the routing state, so the existing
    # router / caps / fixer plumbing handle them unchanged. An 'unknown' ASan
    # frame attribution → no injection (None) → the LLM crash path runs as a
    # fallback.
    lean_crash_verdict = _lean_crash_triage(state, trial)
    if lean_crash_verdict:
        state = cast(FuzzingWorkflowState, {**state, **lean_crash_verdict})

    # Determine next action
    next_action = _determine_next_action(state, trial)

    # Track per-node visit counts for loop detection
    node_visit_counts = state.get("node_visit_counts", {}).copy()
    if next_action != "END":
        node_visit_counts[next_action] = node_visit_counts.get(next_action, 0) + 1

        if node_visit_counts[next_action] > MAX_NODE_VISITS:
            logger.warning(f'Node {next_action} visited {node_visit_counts[next_action]} times, '
                          f'possible loop detected', trial=trial)
            return _end_workflow("node_loop_detected",
                               f"Workflow terminated: {next_action} visited {node_visit_counts[next_action]} times",
                               node_visit_counts=node_visit_counts)

        if next_action == "fixer" and node_visit_counts["fixer"] > MAX_FIXER_INVOCATIONS:
            logger.warning(f'Fixer hit hard cap ({MAX_FIXER_INVOCATIONS}); ending trial', trial=trial)
            return _end_workflow("fixer_cap_exceeded",
                               f"Workflow terminated: fixer reached MAX_FIXER_INVOCATIONS={MAX_FIXER_INVOCATIONS}",
                               node_visit_counts=node_visit_counts)

    logger.info(f'Supervisor routing to: {next_action} '
               f'(visits: {node_visit_counts.get(next_action, 0)})', trial=trial)

    result = {
        "next_action": next_action,
        "node_visit_counts": node_visit_counts,
        "session_memory": consolidate_session_memory(state),
    }

    # Persist the deterministic lean crash verdicts (if any) so downstream
    # consumers (CrashResult extraction, trial summary) and the crash_fix_info
    # block below see the same crash_analysis + context_analysis the LLM path
    # would have written.
    if lean_crash_verdict:
        result.update(lean_crash_verdict)

    # Pass error triage to fixer when routing due to build failure
    if next_action == "fixer" and state.get("compile_success") is False:
        build_errors = state.get("build_errors", [])
        context = state.get("context", {})
        project_apis = context.get("project_apis", [])
        triage_result = triage_build_errors(build_errors, project_apis)
        result["error_triage"] = triage_result.to_dict()
        logger.debug(f'Passing error triage to fixer: primary={triage_result.primary_category}, '
                    f'strategy={triage_result.recommended_strategy}', trial=trial)

    # When routing to fixer after crash analysis, pass crash info for context
    if next_action == "fixer" and state.get("context_analysis") is not None:
        crash_fix_retry_count = state.get("crash_fix_retry_count", 0) + 1
        result["crash_fix_retry_count"] = crash_fix_retry_count
        logger.debug(f'Incrementing crash_fix_retry_count to {crash_fix_retry_count}', trial=trial)

        # Pass crash analysis info to fixer so it can understand what went wrong
        result["crash_fix_info"] = {
            "crash_info": state.get("crash_info"),
            "crash_analysis": state.get("crash_analysis"),
            "context_analysis": state.get("context_analysis"),
        }

    return result


def _end_workflow(reason: str, message: str, **extra) -> Dict[str, Any]:
    """Helper to create END workflow response.

    The ``reason`` argument is embedded in the assistant message so the
    rationale shows up in trial logs / state dumps. The previous
    ``termination_reason`` state field has been removed — it was never
    read anywhere (the only reader was a dead ``is_terminal_state``
    helper), and tagging a non-schema field on the way out just
    obscured what state actually carries.
    """
    result = {
        "next_action": "END",
        "messages": [{
            "role": "assistant",
            "content": f"[{reason}] {message}",
        }],
    }
    result.update(extra)
    return result


def _determine_next_action(state: FuzzingWorkflowState, trial: int) -> str:
    """
    Determine the next action based on current workflow state.

    Two-phase workflow:
    - COMPILATION: Get code to compile (prototyper → build → fixer loop)
    - OPTIMIZATION: Improve coverage (execution → analysis → improve)
    """
    workflow_phase = state.get("workflow_phase", "compilation")

    # === Safety checks ===
    if workflow_phase == "terminated":
        logger.error('Workflow already terminated', trial=trial)
        return "END"

    total_build_failures = state.get("total_build_failure_count", 0)
    if total_build_failures >= MAX_TOTAL_BUILD_FAILURES:
        logger.error(f'Global build failure limit reached ({total_build_failures})', trial=trial)
        return "END"

    # === Entry point: need fuzz target? ===
    if not state.get("fuzz_target_source"):
        logger.debug('No fuzz_target_source, routing to prototyper', trial=trial)
        return "prototyper"

    # === PHASE 1: COMPILATION ===
    if workflow_phase == "compilation":
        return _handle_compilation_phase(state, trial)

    # === PHASE 2: OPTIMIZATION ===
    if workflow_phase == "optimization":
        return _handle_optimization_phase(state, trial)

    logger.error(f'Unknown workflow phase: {workflow_phase}', trial=trial)
    return "END"


def _handle_compilation_phase(state: FuzzingWorkflowState, trial: int) -> str:
    """Handle COMPILATION phase routing."""
    compile_success = state.get("compile_success")

    if compile_success is None:
        return "build"

    if not compile_success:
        build_errors = state.get("build_errors", [])
        context = state.get("context", {})
        project_apis = context.get("project_apis", [])

        # Triage errors for better diagnostics
        triage_result = triage_build_errors(build_errors, project_apis)

        # Log error category breakdown
        if triage_result.summary:
            category_str = ", ".join(
                f"{cat.name}:{count}" for cat, count in triage_result.summary.items()
            )
            logger.info(f'Error triage: {category_str}', trial=trial)

        # Check for unrecoverable errors (fake definitions, language mismatch in C)
        if triage_result.has_category(ErrorCategory.FAKE_DEFINITION):
            fake_errors = triage_result.get_errors_by_category(ErrorCategory.FAKE_DEFINITION)
            fake_funcs = [e.extracted_symbol for e in fake_errors if e.extracted_symbol]
            logger.error(f'Fake definitions detected: {fake_funcs}. Cannot fix.', trial=trial)
            return "END"

        compilation_retry_count = state.get("compilation_retry_count", 0)
        if compilation_retry_count < MAX_COMPILATION_RETRIES:
            strategy_name = triage_result.recommended_strategy.name if triage_result.recommended_strategy else "UNKNOWN"
            logger.info(f'Compilation failed (attempt {compilation_retry_count + 1}/{MAX_COMPILATION_RETRIES}), '
                       f'primary error: {triage_result.primary_category.name if triage_result.primary_category else "UNKNOWN"}, '
                       f'strategy: {strategy_name}, routing to fixer', trial=trial)
            return "fixer"
        else:
            logger.error(f'Compilation failed after {MAX_COMPILATION_RETRIES} retries. Ending.', trial=trial)
            return "END"

    # Compilation succeeded → switch to optimization
    logger.info('✓ Compilation successful! Switching to OPTIMIZATION phase', trial=trial)
    return "execution"


def _handle_optimization_phase(state: FuzzingWorkflowState, trial: int) -> str:
    """Handle OPTIMIZATION phase routing."""
    compile_success = state.get("compile_success")
    run_success = state.get("run_success")

    # Stub-only binary detected during the last execution → regenerate
    # from scratch rather than patch incrementally. The fixer's bias is
    # toward fixing whatever compile/link error is in front of it; for
    # a stub binary the source already compiles, so fixer is a wrong
    # tool. The prototyper sees the stub-detection reason via run_error
    # and can emit a fresh driver that resolves real headers.
    if state.get("is_stub_binary"):
        logger.info(
            'Stub binary detected, routing to prototyper for regeneration',
            trial=trial,
        )
        return "prototyper"

    # Code was modified (by the fixer) → need to rebuild
    if compile_success is None:
        logger.debug('Code modified, need to rebuild', trial=trial)
        return "build"

    # Build failed in optimization phase → fixer
    if not compile_success:
        build_errors = state.get("build_errors", [])
        context = state.get("context", {})
        project_apis = context.get("project_apis", [])

        # Triage errors for better diagnostics
        triage_result = triage_build_errors(build_errors, project_apis)

        # Check for unrecoverable errors
        if triage_result.has_category(ErrorCategory.FAKE_DEFINITION):
            fake_errors = triage_result.get_errors_by_category(ErrorCategory.FAKE_DEFINITION)
            fake_funcs = [e.extracted_symbol for e in fake_errors if e.extracted_symbol]
            logger.error(f'Fake definitions in optimization phase: {fake_funcs}. Cannot fix.', trial=trial)
            return "END"

        compilation_retry_count = state.get("compilation_retry_count", 0)
        if compilation_retry_count < MAX_COMPILATION_RETRIES:
            primary_cat = triage_result.primary_category.name if triage_result.primary_category else "UNKNOWN"
            logger.info(f'Build failed in optimization phase (attempt {compilation_retry_count + 1}), '
                       f'error type: {primary_cat}, routing to fixer', trial=trial)
            return "fixer"
        else:
            logger.error(f'Build failed after {MAX_COMPILATION_RETRIES} retries in optimization. Ending.', trial=trial)
            return "END"

    # Haven't executed yet (after successful build)
    if run_success is None:
        return "execution"

    # Execution failed
    if not run_success:
        return _handle_execution_failure(state, trial)

    # A clean build+run ends the trial. Breadth comes from many-drivers + merge +
    # gap-direction, so there is NO per-driver coverage-optimize loop: the
    # coverage_analyzer / improver / baseline_diff_analyzer (§10B) subsystem was
    # removed. Cross-round coverage feedback, if ever needed, is the Phase C
    # CEGAR loop (built fresh), not per-trial refinement.
    logger.info('Clean build+run → END', trial=trial)
    return "END"


def _handle_execution_failure(state: FuzzingWorkflowState, trial: int) -> str:
    """Handle execution failure (crash or other error)."""
    crashes = state.get("crashes", False)
    run_error = state.get("run_error", "")

    # Check if it's a crash
    if crashes or (run_error and "crash" in run_error.lower()):
        crash_analysis = state.get("crash_analysis")
        if not crash_analysis:
            logger.debug('Crash detected, routing to crash_analyzer', trial=trial)
            return "crash_analyzer"

        context_analysis = state.get("context_analysis")
        if not context_analysis:
            logger.debug('Crash analyzed, routing to crash_feasibility_analyzer', trial=trial)
            return "crash_feasibility_analyzer"

        # Both analyses done
        if context_analysis.get("feasible", False):
            logger.info('Found a feasible crash (true bug)!', trial=trial)
            return "END"
        else:
            # Check crash-fix retry limit
            crash_fix_retry_count = state.get("crash_fix_retry_count", 0)
            if crash_fix_retry_count >= MAX_CRASH_FIX_RETRIES:
                logger.error(f'Crash fix failed after {MAX_CRASH_FIX_RETRIES} retries. Ending.', trial=trial)
                return "END"
            logger.info(f'Crash is not feasible (false positive), routing to fixer '
                       f'(attempt {crash_fix_retry_count + 1}/{MAX_CRASH_FIX_RETRIES})', trial=trial)
            return "fixer"

    # Execution failed but not a crash
    logger.debug('Execution failed (not a crash), routing to fixer', trial=trial)
    return "fixer"


def route_condition(state: FuzzingWorkflowState) -> str:
    """LangGraph conditional routing function.

    The keys here MUST stay in sync with the conditional-edge map in
    `workflow.py` (`add_conditional_edges`). On a missing/unknown `next_action`
    we END this trial with a loud error instead of raising: an uncaught raise
    here is re-raised by `workflow.run` as a fatal RuntimeError that kills the
    whole trial, whereas a routing slip should fail explicitly but scoped — end
    just this trial cleanly. (Not a silent fallback: the error is logged.)
    """
    action_to_node = {
        "prototyper": "prototyper",
        "fixer": "fixer",
        "build": "build",
        "execution": "execution",
        "crash_analyzer": "crash_analyzer",
        "crash_feasibility_analyzer": "crash_feasibility_analyzer",
        "END": "__end__",
    }

    next_action = state.get("next_action")
    node = action_to_node.get(next_action)
    if node is None:
        logger.error(
            'route_condition: missing/unknown next_action=%r → ending trial',
            next_action, trial=state.get("trial", 0))
        return "__end__"
    return node


__all__ = ['supervisor_node', 'route_condition']
