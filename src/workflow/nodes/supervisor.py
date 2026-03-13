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
       └─── success ──► coverage_analyzer (×1) ──► improver (×1) ────────┘
                                                         │
                                                         ▼
                                                 (already ran once)
                                                         │
                                                         ▼
                                                       END
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from src.workflow.state import FuzzingWorkflowState, consolidate_session_memory
from src.utils.fake_definition_validator import should_terminate_on_fake_definitions
from src.utils.compilation_error_triage import (
    triage_build_errors, ErrorCategory, FixStrategy)


# ==================== Configuration Constants ====================
MAX_COMPILATION_RETRIES = 3          # Max fixer attempts during compilation
MAX_TOTAL_BUILD_FAILURES = 10        # Global safety limit
MAX_NODE_VISITS = 10                 # Loop detection threshold
MAX_COVERAGE_IMPROVE_ITERATIONS = 1  # coverage_analyzer and improver run at most once
LINE_COVERAGE_THRESHOLD = 0.1        # 10% real project coverage to consider "good"


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

    logger.info(f'Supervisor routing to: {next_action} '
               f'(visits: {node_visit_counts.get(next_action, 0)})', trial=trial)

    result = {
        "next_action": next_action,
        "node_visit_counts": node_visit_counts,
        "session_memory": consolidate_session_memory(state),
    }

    # Pass error triage to fixer when routing due to build failure
    if next_action == "fixer" and state.get("compile_success") is False:
        build_errors = state.get("build_errors", [])
        context = state.get("context", {})
        project_apis = context.get("project_apis", [])
        triage_result = triage_build_errors(build_errors, project_apis)
        result["error_triage"] = triage_result.to_dict()
        logger.debug(f'Passing error triage to fixer: primary={triage_result.primary_category}, '
                    f'strategy={triage_result.recommended_strategy}', trial=trial)

    return result


def _end_workflow(reason: str, message: str, **extra) -> Dict[str, Any]:
    """Helper to create END workflow response."""
    result = {
        "next_action": "END",
        "termination_reason": reason,
        "messages": [{"role": "assistant", "content": message}]
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

    # Code was modified (by improver/fixer) → need to rebuild
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

    # Execution succeeded → check coverage
    return _handle_coverage_improvement(state, trial)


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
            logger.info('Crash is not feasible (false positive), routing to fixer', trial=trial)
            return "fixer"

    # Execution failed but not a crash
    logger.debug('Execution failed (not a crash), routing to fixer', trial=trial)
    return "fixer"


def _handle_coverage_improvement(state: FuzzingWorkflowState, trial: int) -> str:
    """Handle coverage improvement logic after successful execution."""
    coverage_diff = state.get("line_coverage_diff", 0.0)
    coverage_percent = state.get("coverage_percent", 0.0)
    node_visit_counts = state.get("node_visit_counts", {})

    coverage_analyzer_visits = node_visit_counts.get("coverage_analyzer", 0)
    improver_visits = node_visit_counts.get("improver", 0)

    logger.debug(f'Coverage: line_diff={coverage_diff:.2%}, PC={coverage_percent:.2%}', trial=trial)

    # Good coverage → done
    if coverage_diff >= LINE_COVERAGE_THRESHOLD:
        logger.info(f'Good coverage achieved (line_diff={coverage_diff:.2%})', trial=trial)
        return "END"

    # Try coverage_analyzer (once)
    coverage_analysis = state.get("coverage_analysis")
    if not coverage_analysis:
        if coverage_analyzer_visits < MAX_COVERAGE_IMPROVE_ITERATIONS:
            logger.info(f'Low coverage (line_diff={coverage_diff:.2%}), routing to coverage_analyzer', trial=trial)
            return "coverage_analyzer"
        else:
            logger.info(f'Coverage analyzer already ran {coverage_analyzer_visits} time(s), skipping', trial=trial)

    # Try improver (once) if coverage_analysis suggests improvement
    if coverage_analysis and coverage_analysis.get("improve_required", False):
        if improver_visits < MAX_COVERAGE_IMPROVE_ITERATIONS:
            logger.info('Coverage analysis suggests improvement, routing to improver', trial=trial)
            return "improver"
        else:
            logger.info(f'Improver already ran {improver_visits} time(s), skipping', trial=trial)

    # Done - no more improvement possible within limits
    logger.info(f'Workflow complete: line_diff={coverage_diff:.2%}, PC={coverage_percent:.2%}', trial=trial)
    return "END"


def route_condition(state: FuzzingWorkflowState) -> str:
    """LangGraph conditional routing function."""
    if "next_action" not in state:
        raise KeyError("Workflow state is missing required 'next_action' for routing")

    next_action = state["next_action"]

    action_to_node = {
        "prototyper": "prototyper",
        "fixer": "fixer",
        "improver": "improver",
        "build": "build",
        "execution": "execution",
        "crash_analyzer": "crash_analyzer",
        "coverage_analyzer": "coverage_analyzer",
        "crash_feasibility_analyzer": "crash_feasibility_analyzer",
        "END": "__end__"
    }

    if next_action not in action_to_node:
        raise ValueError(f"Unknown next_action for routing: {next_action}")

    return action_to_node[next_action]


__all__ = ['supervisor_node', 'route_condition']
