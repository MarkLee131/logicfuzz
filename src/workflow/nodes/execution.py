"""
Execution node for LangGraph workflow.

This module provides the LangGraph-compatible node wrapper for the original
ExecutionStage functionality.
"""
import os
import re
from typing import Dict, Any, List, Optional

from langchain_core.runnables import RunnableConfig
import logger
from src.workflow.adapters import StateAdapter
from src.workflow.state import FuzzingWorkflowState
from src.utils.unified_validator import UnifiedCodeValidator, format_validation_report
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as evaluator_lib
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from experiment.evaluator import Evaluator
from experiment.workdir import WorkDirs


def validate_target_api_calls(
    fuzz_target_source: str,
    context: Dict[str, Any],
    language: str = "c++",
) -> Dict[str, Any]:
    """
    Validate that the fuzz target actually calls the expected target APIs.

    Uses UnifiedCodeValidator (libclang FunctionBodyWalker post-2026-05
    V1-refactor) to check whether the driver's body actually references
    the target API sequence.

    Args:
        fuzz_target_source: Source code of the fuzz target
        context: FuzzingContext dict containing api_sequences and header_info
        language: Target language ("c" or "c++")

    Returns:
        Dict with validation results
    """
    # Extract target APIs from api_sequences in context
    api_sequences = context.get("api_sequences", [])
    if not api_sequences:
        logger.warning("No api_sequences in context, skipping target API validation")
        return {
            "success": True,
            "actual_called_apis": [],
            "missing_apis": [],
            "coverage_ratio": 1.0,
            "validation_method": "skipped",
            "report": "No target API sequences to validate"
        }

    # Flatten all API names from sequences (first sequence is the target)
    target_apis = []
    if api_sequences:
        target_apis = list(api_sequences[0]) if api_sequences[0] else []

    if not target_apis:
        return {
            "success": True,
            "actual_called_apis": [],
            "missing_apis": [],
            "coverage_ratio": 1.0,
            "validation_method": "skipped",
            "report": "No target APIs in sequence"
        }

    # Extract include paths from header_info
    header_info = context.get("header_info", {})
    include_paths = []

    if "project_headers" in header_info:
        for header in header_info["project_headers"]:
            header_dir = os.path.dirname(header)
            if header_dir and header_dir not in include_paths:
                include_paths.append(header_dir)

    if "include_dirs" in header_info:
        include_paths.extend(header_info["include_dirs"])

    # Use UnifiedCodeValidator (CGProcessor pass-through removed in
    # 2026-05 workflow refactor — the validator's cgprocessor_path
    # argument has been a no-op since the V1 libclang-Python rewrite).
    validator = UnifiedCodeValidator()

    result = validator.validate(
        code=fuzz_target_source,
        target_apis=target_apis,
        include_paths=include_paths if include_paths else None,
        is_c_target=(language == "c")
    )

    report = format_validation_report(result)

    return {
        "success": True,
        "actual_called_apis": result.actual_called_apis,
        "missing_apis": result.missing_apis,
        "coverage_ratio": result.target_api_coverage,
        "validation_method": result.validation_methods_used[-1] if result.validation_methods_used else "unknown",
        "report": report
    }


def extract_fuzzing_summary(raw_log: str) -> str:
    """
    Extract key information from fuzzing log to reduce token usage.

    Extracts:
    - Initialization info (first ~15 lines)
    - NEW_FUNC discoveries (functions reached by fuzzer)
    - Error/crash information
    - Final statistics (last ~30 lines)

    Args:
        raw_log: The full fuzzing log content

    Returns:
        A condensed summary of the fuzzing log
    """
    if not raw_log:
        return ""

    lines = raw_log.split('\n')
    summary_parts: List[str] = []

    # 1. Initialization info (first 15 lines)
    summary_parts.append("=== Fuzzer Initialization ===")
    summary_parts.extend(lines[:15])

    # 2. NEW_FUNC discoveries - functions the fuzzer reached
    new_funcs = [line for line in lines if 'NEW_FUNC' in line]
    if new_funcs:
        summary_parts.append("\n=== Discovered Functions (NEW_FUNC) ===")
        # Deduplicate and limit
        seen_funcs = set()
        for line in new_funcs:
            # Extract function name for deduplication
            match = re.search(r'in\s+(\S+)\s', line)
            func_name = match.group(1) if match else line
            if func_name not in seen_funcs:
                seen_funcs.add(func_name)
                summary_parts.append(line)
        summary_parts.append(f"(Total: {len(new_funcs)} NEW_FUNC entries, {len(seen_funcs)} unique functions)")

    # 3. Error/crash information
    error_keywords = ['ERROR', 'SUMMARY:', 'AddressSanitizer', 'LeakSanitizer',
                      'UndefinedBehaviorSanitizer', 'ABORTING', 'deadly signal']
    error_lines = [line for line in lines
                   if any(kw in line for kw in error_keywords)]
    if error_lines:
        summary_parts.append("\n=== Errors/Crashes ===")
        summary_parts.extend(error_lines[:50])  # Limit error lines

    # 4. Final statistics (last 30 lines, skip dictionary entries)
    summary_parts.append("\n=== Final Statistics ===")
    # Find where statistics start (after dictionary section ends)
    stats_lines = []
    in_dict_section = False
    for line in lines[-100:]:  # Check last 100 lines
        if '##### End of recommended dictionary' in line:
            in_dict_section = False
            continue
        if '##### Recommended dictionary' in line or in_dict_section:
            in_dict_section = True
            continue
        if line.startswith('Done ') or line.startswith('stat::') or 'runs in' in line:
            stats_lines.append(line)

    if stats_lines:
        summary_parts.extend(stats_lines)
    else:
        # Fallback: just take last 20 lines
        summary_parts.extend(lines[-20:])

    summary = '\n'.join(summary_parts)

    # Final size check - if still too large, truncate
    MAX_SUMMARY_SIZE = 30000  # ~7500 tokens
    if len(summary) > MAX_SUMMARY_SIZE:
        summary = summary[:MAX_SUMMARY_SIZE] + '\n... (summary truncated)'

    return summary


def execution_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    LangGraph node that wraps the original ExecutionStage functionality.
    This node executes fuzz targets by running the fuzz target using OSS-Fuzz infrastructure.
    """
    # Extract configuration from LangGraph's configurable system
    configurable = config.get("configurable", {})
    args = configurable["args"]
    
    # Deserialize benchmark and work_dirs from dicts
    from experiment.benchmark import Benchmark
    from experiment.workdir import WorkDirs
    benchmark = Benchmark.from_dict(state["benchmark"])
    trial = state["trial"]
    work_dirs = WorkDirs.from_dict(state["work_dirs"])
    
    logger.info('Starting Execution node', trial=trial)
    
    # Check if we have a fuzz target to execute
    fuzz_target_source = state.get("fuzz_target_source", "")
    build_script_source = state.get("build_script_source", "")
    
    if not fuzz_target_source:
        raise ValueError("No fuzz target source available for execution")
    
    # Set up builder runner
    if args.cloud_experiment_name:
        builder_runner = builder_runner_lib.CloudBuilderRunner(
            benchmark=benchmark,
            work_dirs=work_dirs,
            run_timeout=args.run_timeout,
            experiment_name=args.cloud_experiment_name,
            experiment_bucket=args.cloud_experiment_bucket,
        )
    else:
        builder_runner = builder_runner_lib.BuilderRunner(
            benchmark=benchmark,
            work_dirs=work_dirs,
            run_timeout=args.run_timeout,
        )
    
    # Set up evaluator
    evaluator = Evaluator(builder_runner, benchmark, work_dirs)
    generated_target_name = os.path.basename(benchmark.target_path)
    generated_oss_fuzz_project = f'{benchmark.id}-{trial}'
    generated_oss_fuzz_project = oss_fuzz_checkout.rectify_docker_tag(
        generated_oss_fuzz_project)
    
    # Write fuzz target and build script to files
    fuzz_target_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.fuzz_target')
    build_script_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.build_script')
    
    with open(fuzz_target_path, 'w') as f:
        f.write(fuzz_target_source)
    
    if build_script_source:
        with open(build_script_path, 'w') as f:
            f.write(build_script_source)
    
    # Create OSS-Fuzz project
    generated_project_path = evaluator.create_ossfuzz_project(
        benchmark, generated_oss_fuzz_project, fuzz_target_path,
        build_script_path if build_script_source else None)
    
    # Create status directory
    status_path = os.path.join(work_dirs.status, f'{trial:02d}')
    os.makedirs(status_path, exist_ok=True)
    
    # Execute the fuzz target
    logger.info('Executing fuzz target', trial=trial)
    
    # Build and run the target
    build_result, run_result = builder_runner.build_and_run(
        generated_oss_fuzz_project,
        fuzz_target_path,
        0,  # iteration
        benchmark.language,
        cloud_build_tags=[
            str(trial),
            'Execution',
            'ofg',
            benchmark.project,
        ] if args.cloud_experiment_name else None,
        trial=trial
    )
    
    # Handle build failures gracefully - return to compilation phase for fixing
    if not run_result:
        # Build failed - return state that triggers fixer
        build_error_msg = "Build failed during execution phase"
        if build_result:
            # Try to extract build error details
            if hasattr(build_result, 'errors') and build_result.errors:
                build_error_msg = f"Build failed: {build_result.errors[:500]}"
            elif hasattr(build_result, 'succeeded') and not build_result.succeeded:
                build_error_msg = "Build failed (no detailed error available)"

        # Track total build failures across all phases to prevent infinite loops
        total_build_failures = state.get("total_build_failure_count", 0) + 1
        MAX_TOTAL_BUILD_FAILURES = 10  # Hard limit on total build failures

        if total_build_failures >= MAX_TOTAL_BUILD_FAILURES:
            logger.error(
                f'❌ Total build failures ({total_build_failures}) exceeded limit ({MAX_TOTAL_BUILD_FAILURES}). '
                f'Ending workflow to prevent infinite loop.',
                trial=trial
            )
            # Return state that will terminate the workflow
            return {
                "compile_success": False,
                "build_errors": [build_error_msg, f"Exceeded max total build failures ({MAX_TOTAL_BUILD_FAILURES})"],
                "run_success": False,
                "total_build_failure_count": total_build_failures,
                "workflow_phase": "terminated",  # Special phase to signal termination
                "messages": [{
                    "role": "assistant",
                    "content": f"Workflow terminated: exceeded max build failures. Last error: {build_error_msg}"
                }]
            }

        logger.warning(
            f'Build failed in execution phase (total failures: {total_build_failures}/{MAX_TOTAL_BUILD_FAILURES}): {build_error_msg}',
            trial=trial
        )

        return {
            "compile_success": False,
            "build_errors": [build_error_msg],
            "run_success": False,
            "total_build_failure_count": total_build_failures,
            "workflow_phase": "compilation",  # Go back to compilation phase
            "messages": [{
                "role": "assistant",
                "content": f"Build failed during execution: {build_error_msg}"
            }]
        }
    
    # Process coverage information
    coverage_percent = 0.0
    coverage_diff = 0.0
    
    # 🚨 STUB DETECTION: Check if fuzzer is only testing stub code.
    # Pre-2026-05 this returned ``compile_success=False`` to force the
    # fixer loop, conflating "compilation failed" with "binary built but
    # exercising trivial stubs". Now we set a dedicated ``is_stub_binary``
    # flag and let the supervisor route to the prototyper for genuine
    # regeneration instead of the fixer's incremental patches.
    MINIMUM_PCS_THRESHOLD = 10
    if run_result.total_pcs and run_result.total_pcs < MINIMUM_PCS_THRESHOLD:
        logger.warning(
            f'⚠️  Suspiciously low PC count ({run_result.total_pcs}), '
            f'fuzzer appears to be exercising stub code only. Routing '
            f'to prototyper for regeneration.',
            trial=trial
        )
        return {
            "is_stub_binary": True,
            "run_success": False,
            "run_error": (
                f"Stub code detected: total_pcs={run_result.total_pcs} "
                f"< {MINIMUM_PCS_THRESHOLD}. The fuzzer was built and "
                f"executed but the binary appears to exercise only "
                f"fake/stub implementations instead of real project "
                f"code. Likely cause: header paths could not resolve and "
                f"the prototyper emitted stub class fallbacks. The "
                f"prototyper will regenerate from scratch."
            ),
            "messages": [{
                "role": "assistant",
                "content": (
                    f"Detected stub-only fuzzer "
                    f"(total_pcs={run_result.total_pcs}); requesting "
                    f"prototyper regeneration."
                ),
            }],
        }
    
    if run_result.total_pcs:
        coverage_percent = run_result.cov_pcs / run_result.total_pcs
        logger.info(f'Coverage: {coverage_percent:.2%} ({run_result.cov_pcs}/{run_result.total_pcs})', 
                   trial=trial)
    
    if run_result.coverage_summary:
        generated_target_name = os.path.basename(benchmark.target_path)
        from experiment import evaluator as evaluator_lib
        total_lines = evaluator_lib.compute_total_lines_without_fuzz_targets(
            run_result.coverage_summary, generated_target_name)
        
        # Load existing textcov and compute diff
        existing_textcov = evaluator.load_existing_textcov()
        run_result.coverage.subtract_covered_lines(existing_textcov)
        
        if total_lines:
            coverage_diff = run_result.coverage.covered_lines / total_lines
            logger.info(f'Coverage diff: {coverage_diff:.2%}', trial=trial)
    
    # Read run log from file and extract summary (best-effort)
    run_log = ""
    if hasattr(run_result, 'log_path') and run_result.log_path and os.path.exists(run_result.log_path):
        try:
            with open(run_result.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_log = f.read()
            # Extract summary to reduce token usage for LLM
            run_log = extract_fuzzing_summary(raw_log)
            logger.debug(
                f'Read run log from {run_result.log_path} ({len(raw_log)} bytes -> {len(run_log)} bytes summary)',
                trial=trial
            )
        except Exception as e:
            logger.warning(f'Failed to read run log from {run_result.log_path}: {e}', trial=trial)
    
    # Extract crash information if any.
    # TODO(2026-05 workflow review): error_message and stack_trace both
    # populated from run_result.crash_info; downstream consumers see
    # identical text in both fields. RunResult doesn't expose a
    # dedicated stacktrace yet — either the run_result schema needs a
    # `stacktrace` field carved out of the libFuzzer stderr, or one of
    # these state keys should be dropped. Tracked in
    # docs/workflow_refactor_2026_05.md §2.
    crash_info = {}
    if run_result.crashes:
        crash_info = {
            "error_message": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
            "stack_trace": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
            "artifact_path": run_result.artifact_path if hasattr(run_result, 'artifact_path') else "",
            "artifact_name": run_result.artifact_name if hasattr(run_result, 'artifact_name') else "",
            "crash_func": run_result.semantic_check.crash_func if (hasattr(run_result, 'semantic_check') and run_result.semantic_check) else "",
            "sanitizer": run_result.sanitizer if hasattr(run_result, 'sanitizer') else "",
        }
    
    # Track consecutive iterations without coverage improvement
    IMPROVEMENT_THRESHOLD = 0.01  # At least 1% improvement
    prev_no_improvement_count = state.get("no_coverage_improvement_count", 0)
    
    if coverage_diff > IMPROVEMENT_THRESHOLD:
        # Coverage improved, reset the counter
        no_improvement_count = 0
        logger.debug(f'Coverage improved by {coverage_diff:.2%}, resetting no_improvement_count', 
                    trial=trial)
    else:
        # No significant improvement, increment counter
        no_improvement_count = prev_no_improvement_count + 1
        logger.debug(f'Coverage did not improve (diff={coverage_diff:.2%}), '
                    f'no_improvement_count={no_improvement_count}', 
                    trial=trial)
    
    # Increment iteration counter (each execution in optimization phase counts as one iteration)
    current_iteration = state.get("current_iteration", 0) + 1

    # Create state update
    state_update = {
        "run_success": run_result.succeeded if hasattr(run_result, 'succeeded') else True,
        "run_error": run_result.crash_info if hasattr(run_result, 'crash_info') else "",
        "run_log": run_log,  # Add the run log content
        "crashes": run_result.crashes if hasattr(run_result, 'crashes') else False,
        "crash_info": crash_info,
        "crash_func": run_result.semantic_check.crash_func if (hasattr(run_result, 'semantic_check') and run_result.semantic_check) else "",
        "coverage_summary": run_result.coverage_summary,
        "coverage_percent": coverage_percent,
        "line_coverage_diff": coverage_diff,
        "no_coverage_improvement_count": no_improvement_count,  # Track consecutive iterations without improvement
        "current_iteration": current_iteration,  # Increment iteration counter
        "reproducer_path": run_result.reproducer_path if hasattr(run_result, 'reproducer_path') else "",
        "artifact_path": run_result.artifact_path if hasattr(run_result, 'artifact_path') else "",
        "coverage_report_path": run_result.coverage_report_path if hasattr(run_result, 'coverage_report_path') else "",
        "cov_pcs": run_result.cov_pcs if hasattr(run_result, 'cov_pcs') else 0,
        "total_pcs": run_result.total_pcs if hasattr(run_result, 'total_pcs') else 0,
        # Clear old analysis results to force re-analysis of new crashes/coverage
        # This ensures each execution's results are analyzed fresh
        "crash_analysis": None,
        "context_analysis": None,
        "coverage_analysis": None,
        "messages": [{
            "role": "assistant",
            "content": f"Execution {'successful' if run_result.succeeded else 'failed'}"
        }]
    }
    
    logger.info(f'Execution completed: success={state_update["run_success"]}, '
               f'crashes={state_update["crashes"]}, coverage={coverage_percent:.2%}, '
               f'iteration={current_iteration}',
               trial=trial)
    
    return state_update

def build_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    LangGraph node for building fuzz targets without execution.
    
    This node only builds the fuzz target to check compilation success.
    
    Args:
        state: Current LangGraph workflow state
        config: Configuration containing args, etc.
        
    Returns:
        Dictionary of state updates
    """
    # Extract configuration from LangGraph's configurable system
    configurable = config.get("configurable", {})
    args = configurable["args"]
    
    # Deserialize benchmark and work_dirs from dicts
    from experiment.benchmark import Benchmark
    from experiment.workdir import WorkDirs
    benchmark = Benchmark.from_dict(state["benchmark"])
    trial = state["trial"]
    work_dirs = WorkDirs.from_dict(state["work_dirs"])
    
    logger.info('Starting Build node', trial=trial)
    
    # Check if we have a fuzz target to build
    fuzz_target_source = state.get("fuzz_target_source", "")
    build_script_source = state.get("build_script_source", "")

    if not fuzz_target_source:
        raise ValueError("No fuzz target source available for building")

    # Pre-build language validation: detect C++ features in C targets
    target_path = benchmark.target_path
    cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
    is_c_target = not target_path.lower().endswith(cpp_extensions)

    if is_c_target:
        validator = UnifiedCodeValidator()
        result = validator.validate(code=fuzz_target_source, is_c_target=True)

        if not result.is_language_compatible:
            lang_report = format_validation_report(result)
            logger.warning(
                f"Language mismatch detected: C++ features in C target. {lang_report}",
                trial=trial
            )
            return {
                "compile_success": False,
                "build_errors": [
                    "Language mismatch: C++ features detected in C project code.",
                    "This will cause compilation failure. Please regenerate using pure C patterns.",
                    "Common issues: FuzzedDataProvider (use memcpy), std::string (use char*)."
                ],
                "compile_log": lang_report,
                "binary_exists": False,
                "is_function_referenced": False,
                "messages": [{
                    "role": "assistant",
                    "content": "Build failed: C++ features detected in C project code"
                }]
            }

    # Set up builder runner for build-only
    builder_runner = builder_runner_lib.BuilderRunner(
        benchmark=benchmark,
        work_dirs=work_dirs,
        run_timeout=args.run_timeout,
    )
    
    # Set up evaluator
    evaluator = Evaluator(builder_runner, benchmark, work_dirs)
    generated_oss_fuzz_project = f'{benchmark.id}-{trial}-build'
    generated_oss_fuzz_project = oss_fuzz_checkout.rectify_docker_tag(
        generated_oss_fuzz_project)
    
    # Write fuzz target and build script to files
    fuzz_target_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.fuzz_target')
    build_script_path = os.path.join(work_dirs.fuzz_targets, f'{trial:02d}.build_script')
    
    with open(fuzz_target_path, 'w') as f:
        f.write(fuzz_target_source)
    
    if build_script_source:
        with open(build_script_path, 'w') as f:
            f.write(build_script_source)
    
    # Create OSS-Fuzz project
    generated_project_path = evaluator.create_ossfuzz_project(
        benchmark, generated_oss_fuzz_project, fuzz_target_path,
        build_script_path if build_script_source else None)
    
    # Only build, don't run
    logger.info('Building fuzz target', trial=trial)
    
    build_result = evaluator.build_only(generated_project_path)
    
    # Log build result details
    logger.info(f"Build result: success={build_result.get('success')}, "
               f"binary_exists={build_result.get('binary_exists')}, "
               f"errors={len(build_result.get('errors', []))}",
               trial=trial)
    
    # Create state update based on build result
    compile_success = build_result.get("success", False)
    state_update = {
        "compile_success": compile_success,
        "build_errors": build_result.get("errors", []),
        "compile_log": build_result.get("log", ""),
        "binary_exists": build_result.get("binary_exists", False),
        # Real nm-based symbol check now happens inside evaluator.build_only
        # (post-2026-05 workflow refactor). False here means the binary
        # exists but ``LLVMFuzzerTestOneInput`` is not defined as a
        # callable global symbol — typically a link-time silent failure.
        "is_function_referenced":
            build_result.get("is_function_referenced", True),
        "messages": [{
            "role": "assistant",
            "content": f"Build {'successful' if compile_success else 'failed'}"
        }]
    }

    # Track total build failures to prevent infinite loops
    if not compile_success:
        total_build_failures = state.get("total_build_failure_count", 0) + 1
        state_update["total_build_failure_count"] = total_build_failures
        logger.debug(f'Build failed, total_build_failure_count={total_build_failures}', trial=trial)

    # === Telemetry: append per-attempt record for retry-budget calibration ===
    # Read-only data flow: nothing routes off this list. Used post-hoc to
    # compute fixer success curves per error category.
    #
    # Robustness contract: the BASE record (success/binary/error_count) must
    # always make it into build_attempts even if classification fails. The
    # earlier version wrapped the entire block in try/except, so any triage
    # exception (we hit one on zlib trial 03 — context shape varied) silently
    # dropped the whole attempt — exactly the failure data we need most.
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
        from src.utils.compilation_error_triage import triage_build_errors
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
    except Exception as exc:  # classification failure must NOT drop the record
        logger.debug(f'build_attempts triage classification failed: {exc}',
                     trial=trial)
    state_update["build_attempts"] = (
        state.get("build_attempts", []) + [base_record])

    # If compilation successful and we're in compilation phase, switch to optimization phase
    if compile_success and state.get("workflow_phase") == "compilation":
        logger.info('Compilation successful, switching workflow_phase to optimization', trial=trial)
        state_update["workflow_phase"] = "optimization"
        state_update["compilation_retry_count"] = 0  # Reset for potential future use

        # === Target API Validation (AST-based) ===
        # Validate that the driver actually calls the expected target APIs
        context = state.get("context", {})
        if context:
            target_language = "c" if is_c_target else "c++"
            api_validation = validate_target_api_calls(
                fuzz_target_source,
                context,
                language=target_language
            )

            state_update["target_api_validation"] = api_validation

            if api_validation["success"]:
                coverage_ratio = api_validation["coverage_ratio"]
                missing_count = len(api_validation["missing_apis"])

                if coverage_ratio < 1.0:
                    logger.warning(
                        f'Target API validation: {coverage_ratio:.1%} coverage, '
                        f'{missing_count} APIs missing: {api_validation["missing_apis"]}',
                        trial=trial
                    )
                else:
                    logger.info(
                        f'Target API validation: 100% coverage, all target APIs called',
                        trial=trial
                    )
            else:
                logger.warning(
                    f'Target API validation failed: {api_validation.get("report", "unknown error")}',
                    trial=trial
                )

    logger.info('Build node completed', trial=trial)

    return state_update

__all__ = ['execution_node', 'build_node']
