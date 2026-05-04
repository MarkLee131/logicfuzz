"""
LangGraphCrashFeasibilityAnalyzer agent for LangGraph workflow.

Analyzes whether a crash is reachable from the project's external entry points.
The FuzzIntrospector tool surface was removed; the agent only retains the bash
inspection tool for container exploration.
"""
import argparse
import os
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.utils.prompt_loader import get_prompt_manager
from src.tools.execution import BashExecuteTool


class LangGraphCrashFeasibilityAnalyzer(LangGraphAgent, ToolCallingMixin):
    """Crash feasibility analyzer with bash-only tool access."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt(
            "crash_feasibility_analyzer")

        super().__init__(name="crash_feasibility_analyzer",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.inspect_tool = None
        self.benchmark = None
        self.project_name = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """Return bash execution only; FI tool surface removed."""
        return [
            BashExecuteTool(executor=self._execute_bash),
        ]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """
        Parse final LLM response to extract feasibility analysis using XML tags.

        Expected format:
        <feasible>true/false</feasible>
        <analysis>...</analysis>
        <source_code_evidence>...</source_code_evidence>
        <recommendations>...</recommendations>
        """
        import re

        result = {
            'feasible': False,
            'analysis': '',
            'source_code_evidence': '',
            'recommendations': '',
            'analyzed': True
        }

        content_lower = content.lower()

        # XML format: <feasible>true/false</feasible>
        if m := re.search(r'<feasible>\s*(true|false)\s*</feasible>',
                          content_lower):
            result['feasible'] = m.group(1) == 'true'
        else:
            logger.warning(
                'No <feasible> tag found in crash feasibility response',
                trial=self.trial)

        # XML format: <analysis>...</analysis>
        if m := re.search(r'<analysis>(.*?)</analysis>', content,
                          re.DOTALL | re.IGNORECASE):
            result['analysis'] = m.group(1).strip()

        # XML format: <source_code_evidence>...</source_code_evidence>
        if m := re.search(
                r'<source_code_evidence>(.*?)</source_code_evidence>', content,
                re.DOTALL | re.IGNORECASE):
            result['source_code_evidence'] = m.group(1).strip()

        # XML format: <recommendations>...</recommendations>
        if m := re.search(r'<recommendations>(.*?)</recommendations>', content,
                          re.DOTALL | re.IGNORECASE):
            result['recommendations'] = m.group(1).strip()

        return result

    # =========================================================================
    # Tool Executors
    # =========================================================================

    def _execute_bash(self, command: str) -> str:
        """Execute bash command."""
        result = self.inspect_tool.execute(command)
        return self._format_bash_result(result)

    def _format_bash_result(self, result: Any) -> str:
        """Format bash execution result."""
        if hasattr(result, 'stdout'):
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            # Limit output size
            max_output_len = 10000
            if len(stdout) > max_output_len:
                stdout = stdout[:max_output_len] + f'\n... (truncated {len(stdout) - max_output_len} chars)'
            if len(stderr) > max_output_len:
                stderr = stderr[:max_output_len] + f'\n... (truncated {len(stderr) - max_output_len} chars)'

            result_parts = [f"Command: {result.args}"]
            result_parts.append(f"Return code: {result.returncode}")

            if stdout:
                result_parts.append(f"STDOUT:\n{stdout}")
            if stderr:
                result_parts.append(f"STDERR:\n{stderr}")

            return "\n".join(result_parts)

        return str(result)

    # =========================================================================
    # Main Execution
    # =========================================================================

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze crash feasibility by examining project context.

        Determines if a crash is reachable from project's external entry points.
        """
        from tool.container_tool import ProjectContainerTool
        from experiment import benchmark as benchmarklib
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates)

        # Get benchmark object
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)

        # Validate that we have crash analysis result
        crash_analysis = state.get("crash_analysis", {})
        if not crash_analysis:
            logger.error('No crash_analysis in state', trial=self.trial)
            return {"errors": [{"message": "No crash analysis found"}]}

        # Store benchmark for FI tool initialization
        self.benchmark = benchmark
        self.project_name = benchmark.project

        # Initialize inspect_tool for bash command execution
        self.inspect_tool = ProjectContainerTool(benchmark)
        self.inspect_tool.compile(
            extra_commands=' && rm -rf /out/* > /dev/null')

        # Get function requirements
        function_requirements = self._get_function_requirements(state)

        # Build initial prompt using PromptManager
        prompt_manager = get_prompt_manager()

        # Get crash analysis from previous step
        crash_insight = crash_analysis.get("insight", "")
        stack_trace = state.get("crash_info", {}).get("stack_trace", "")
        fuzz_target = state.get("fuzz_target_source", "")

        # Build base user prompt with crash feasibility information
        base_prompt = prompt_manager.build_user_prompt(
            "crash_feasibility_analyzer",
            PROJECT_NAME=benchmark.project,
            FUZZ_TARGET=fuzz_target,
            FUNCTION_REQUIREMENTS=function_requirements,
            CRASH_STACKTRACE=stack_trace,
            CRASH_ANALYSIS=crash_insight,
            ADDITIONAL_CONTEXT=
            f"Project directory: {self.inspect_tool.project_dir}")

        # Inject session_memory
        user_prompt = build_prompt_with_session_memory(state,
                                                       base_prompt,
                                                       agent_name=self.name)

        try:
            # Use the mixin's tool calling loop
            context_result, all_responses = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=self.args.max_round,
                log_prefix="CRASH_FEASIBILITY")
        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug('Stopping and removing inspect container',
                             trial=self.trial)
                self.inspect_tool.terminate()

        # Extract session_memory updates from all responses
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0))

        # Merge updates to session_memory
        updated_session_memory = merge_session_memory_updates(
            state, session_memory_updates)

        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)

        return {
            "context_analysis": context_result,
            "session_memory": updated_session_memory
        }

    def _get_function_requirements(self, state: FuzzingWorkflowState) -> str:
        """Get function requirements from previous analysis."""
        # Try to read from requirements file
        work_dirs_dict = state.get("work_dirs", {})
        requirements_dir = work_dirs_dict.get("requirements", "")

        if requirements_dir and os.path.isdir(requirements_dir):
            requirements_path = os.path.join(requirements_dir,
                                             f'{self.trial:02d}.txt')
            if os.path.exists(requirements_path):
                with open(requirements_path, 'r') as f:
                    return f.read()

        # Fallback to state
        function_analysis = state.get("function_analysis", {})
        return function_analysis.get("raw_analysis", "")
