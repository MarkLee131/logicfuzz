"""
Adapter layer for migrating original agents to LangGraph.

This module provides the compatibility layer between LangGraph state management
and the original agent system's Result objects.
"""
import argparse
from typing import Dict, Any, List, Optional

from experiment.workdir import WorkDirs
from experiment.benchmark import Benchmark
from results import (Result, BuildResult, RunResult, AnalysisResult,
                     FunctionAnalysisResult, CrashResult, CoverageResult)
from src.workflow.state import FuzzingWorkflowState


class StateAdapter:
    """
    Adapter for converting between LangGraph state and Result objects.
    
    This is the core compatibility layer that allows original agents
    to work with LangGraph state management.
    """

    @staticmethod
    def state_to_result_history(state: FuzzingWorkflowState) -> List[Result]:
        """
        Convert LangGraph state to a Result history list that original agents expect.
        
        Args:
            state: Current LangGraph workflow state
            
        Returns:
            List of Result objects reconstructed from state
        """
        # Deserialize benchmark and work_dirs from dicts
        benchmark = Benchmark.from_dict(state["benchmark"])
        work_dirs = WorkDirs.from_dict(state["work_dirs"])
        trial = state["trial"]

        result_history = []

        # Create base Result
        base_result = Result(
            benchmark=benchmark,
            trial=trial,
            work_dirs=work_dirs,
            fuzz_target_source=state.get("fuzz_target_source", ""),
            build_script_source=state.get("build_script_source", ""),
            function_analysis=StateAdapter._extract_function_analysis(state))
        result_history.append(base_result)

        # Add BuildResult if build information exists
        if state.get("compile_success") is not None:
            build_result = BuildResult(
                benchmark=benchmark,
                trial=trial,
                work_dirs=work_dirs,
                fuzz_target_source=state.get("fuzz_target_source", ""),
                build_script_source=state.get("build_script_source", ""),
                compiles=state.get("compile_success", False),
                compile_error="\n".join(state.get("build_errors", [])),
                compile_log=state.get("compile_log", ""),
                binary_exists=state.get("binary_exists", False),
                is_function_referenced=state.get("is_function_referenced",
                                                 False))
            # Set function_analysis as an attribute (not via __init__)
            build_result.function_analysis = StateAdapter._extract_function_analysis(
                state)
            result_history.append(build_result)

        # Add RunResult if execution information exists
        # 🔧 CRITICAL FIX: If we have execution results, the build MUST have succeeded
        # Otherwise we wouldn't have cov_pcs/total_pcs data
        if state.get("run_success") is not None:
            # If we reached execution phase (optimization), compilation must have succeeded
            # Override compile_success if we have actual coverage data
            compile_success_final = state.get("compile_success", False)
            if state.get("workflow_phase") == "optimization" or state.get(
                    "total_pcs", 0) > 0:
                compile_success_final = True

            run_result = RunResult(
                benchmark=benchmark,
                trial=trial,
                work_dirs=work_dirs,
                fuzz_target_source=state.get("fuzz_target_source", ""),
                build_script_source=state.get("build_script_source", ""),
                compiles=compile_success_final,
                run_error=state.get("run_error", ""),
                run_log=state.get("run_log", ""),
                artifact_path=state.get("artifact_path", ""),
                crash_func=state.get("crash_func", {}),
                crashes=state.get("crashes", False),
                coverage=state.get("coverage_percent", 0.0),
                line_coverage_diff=state.get("line_coverage_diff", 0.0),
                coverage_summary=state.get("coverage_summary", {}),
                compile_error="\n".join(state.get("build_errors", [])),
                compile_log=state.get("compile_log", ""),
                binary_exists=state.get("binary_exists", False),
                is_function_referenced=state.get("is_function_referenced",
                                                 False),
                reproducer_path=state.get("reproducer_path", ""),
                sanitizer=state.get("sanitizer", ""),
                log_path=state.get("log_path", ""),
                corpus_path=state.get("corpus_path", ""),
                coverage_report_path=state.get("coverage_report_path", ""),
                cov_pcs=state.get("cov_pcs", 0),
                total_pcs=state.get("total_pcs", 0),
                textcov_diff=state.get("textcov_diff"))
            # Set function_analysis as an attribute (not via __init__)
            run_result.function_analysis = StateAdapter._extract_function_analysis(
                state)
            result_history.append(run_result)

        # Add AnalysisResult if analysis information exists
        if state.get("analysis_complete"):
            # Get the most recent RunResult or create a minimal one
            run_result_for_analysis = None
            for r in reversed(result_history):
                if isinstance(r, RunResult):
                    run_result_for_analysis = r
                    break

            if run_result_for_analysis is None:
                # Create a minimal RunResult if none exists
                run_result_for_analysis = RunResult(benchmark=benchmark,
                                                    trial=trial,
                                                    work_dirs=work_dirs)

            analysis_result = AnalysisResult(
                author=None,  # AnalysisResult expects author as first param
                run_result=run_result_for_analysis,
                crash_result=StateAdapter._extract_crash_result(
                    state, benchmark, trial, work_dirs),
                coverage_result=StateAdapter._extract_coverage_result(
                    state, benchmark, trial, work_dirs))
            # Set function_analysis as an attribute (not via __init__)
            analysis_result.function_analysis = StateAdapter._extract_function_analysis(
                state)
            result_history.append(analysis_result)

        return result_history

    @staticmethod
    def _extract_function_analysis(
            state: FuzzingWorkflowState) -> Optional[FunctionAnalysisResult]:
        """Extract function analysis from state."""
        fa_data = state.get("function_analysis")
        if not fa_data:
            return None

        return FunctionAnalysisResult(
            description=fa_data.get("description", ""),
            function_signature=fa_data.get("function_signature", ""),
            project_name=fa_data.get("project_name", ""),
            requirements=fa_data.get("requirements", ""),
            function_analysis_path=fa_data.get("function_analysis_path", ""))

    @staticmethod
    def _extract_crash_result(state: FuzzingWorkflowState,
                              benchmark: Benchmark, trial: int,
                              work_dirs: WorkDirs) -> Optional[CrashResult]:
        """Extract crash result from state."""
        crash_data = state.get("crash_analysis")
        if not crash_data:
            return None

        return CrashResult(benchmark=benchmark,
                           trial=trial,
                           work_dirs=work_dirs,
                           true_bug=crash_data.get("true_bug", False),
                           insight=crash_data.get("insight", ""),
                           stacktrace=crash_data.get("stacktrace", ""),
                           chat_history={})

    @staticmethod
    def _extract_coverage_result(
            state: FuzzingWorkflowState, benchmark: Benchmark, trial: int,
            work_dirs: WorkDirs) -> Optional[CoverageResult]:
        """Extract coverage result from state."""
        cov_data = state.get("coverage_analysis")
        if not cov_data:
            return None

        return CoverageResult(
            benchmark=benchmark,
            trial=trial,
            work_dirs=work_dirs,
            coverage_summary=cov_data.get("coverage_summary", ""),
            line_coverage_report=cov_data.get("line_coverage_report", ""),
            function_coverage_report=cov_data.get("function_coverage_report",
                                                  ""),
            coverage_rate=cov_data.get("coverage_rate", 0.0),
            chat_history={})


class ConfigAdapter:
    """
    Adapter for managing configuration objects needed by original agents.

    This handles the conversion between LangGraph's config system and
    the original agents' parameter expectations.
    """

    @staticmethod
    def create_config(model_name: str, args: argparse.Namespace,
                      **kwargs) -> Dict[str, Any]:
        """
        Create a configuration dictionary for LangGraph nodes.

        Args:
            model_name: Name of the LLM model (e.g., "gpt-4o", "deepseek-chat")
            args: Command line arguments
            **kwargs: Additional configuration parameters

        Returns:
            Configuration dictionary for LangGraph
        """
        config = {"model_name": model_name, "args": args, **kwargs}
        return config
