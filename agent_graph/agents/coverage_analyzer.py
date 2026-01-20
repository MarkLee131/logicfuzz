"""
LangGraphCoverageAnalyzer agent for LangGraph workflow.

Refactored to use ToolCallingMixin for reduced code duplication.
"""
import argparse
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState, add_coverage_attempt
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.tool_calling_mixin import ToolCallingMixin
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.tools.langchain_adapters import BashExecuteTool


class LangGraphCoverageAnalyzer(LangGraphAgent, ToolCallingMixin):
    """
    Coverage analyzer agent for LangGraph.
    Uses ToolCallingMixin for standardized multi-round tool interaction.
    Multi-round interaction until conclusion is detected in text response.
    """

    # Mixin configuration
    MAX_TOOL_CALLS: int = 10
    PROMPT_FOR_CONCLUSION_MESSAGE: str = "Tool call limit reached. Please provide your conclusion now."
    PROMPT_WHEN_NO_TOOLS_MESSAGE: str = "Please provide your final conclusion with CONCLUSION, INSIGHTS, and SUGGESTIONS."

    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("coverage_analyzer")

        super().__init__(
            name="coverage_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
        self.inspect_tool = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_langchain_tools(self) -> List[BaseTool]:
        """Return LangChain tools for coverage analysis."""
        return [
            BashExecuteTool(executor=self._execute_bash)
        ]

    def has_conclusion(self, content: str) -> bool:
        """Check if the response contains a conclusion."""
        text_lower = content.lower()

        # Check for XML format: <conclusion>true/false</conclusion>
        xml_pattern = r'<conclusion>\s*(true|false)\s*</conclusion>'
        if re.search(xml_pattern, text_lower):
            return True

        # Check for text format markers
        conclusion_markers = [
            "CONCLUSION:",
            "Final conclusion:",
            "My conclusion:",
            "In conclusion",
            "improve_required:",
            "Coverage improvement required:",
        ]
        return any(marker.lower() in text_lower for marker in conclusion_markers)

    def parse_conclusion(self, content: str) -> Dict[str, Any]:
        """
        Parse conclusion from LLM text response.

        Supports both formats:
        1. XML: <conclusion>true/false</conclusion>, <insights>...</insights>, <suggestions>...</suggestions>
        2. Text: CONCLUSION: true/false, INSIGHTS: ..., SUGGESTIONS: ...
        """
        result = {
            'improve_required': False,
            'insights': '',
            'suggestions': '',
            'analyzed': True
        }

        text_lower = content.lower()

        # Try XML format first: <conclusion>true/false</conclusion>
        conclusion_match = re.search(r'<conclusion>\s*(true|false)\s*</conclusion>', text_lower)
        if conclusion_match:
            result['improve_required'] = conclusion_match.group(1) == 'true'

            # Extract insights from XML (case-insensitive)
            insights_match = re.search(r'<insights?>(.*?)</insights?>', content, re.DOTALL | re.IGNORECASE)
            if insights_match:
                result['insights'] = insights_match.group(1).strip()

            # Extract suggestions from XML (case-insensitive)
            suggestions_match = re.search(r'<suggestions?>(.*?)</suggestions?>', content, re.DOTALL | re.IGNORECASE)
            if suggestions_match:
                result['suggestions'] = suggestions_match.group(1).strip()

            # If no XML insights/suggestions, try to extract from text
            if not result['insights'] and not result['suggestions']:
                pass  # Fall through to text parsing
            else:
                return result

        # Text format parsing
        lines = content.split('\n')
        current_section = None
        content_buffer = []

        for line in lines:
            line_lower = line.lower().strip()

            # Check for section headers
            if 'conclusion:' in line_lower or 'improve_required:' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []

                # Extract true/false value (only if not already set by XML)
                if not conclusion_match:
                    if 'true' in line_lower:
                        result['improve_required'] = True
                    elif 'false' in line_lower:
                        result['improve_required'] = False
                current_section = None

            elif 'insights:' in line_lower or '## insights' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'insights'

            elif 'suggestions:' in line_lower or 'recommendations:' in line_lower or '## suggestions' in line_lower or '## improvement' in line_lower:
                if content_buffer and current_section:
                    result[current_section] = '\n'.join(content_buffer).strip()
                    content_buffer = []
                current_section = 'suggestions'

            elif current_section:
                content_buffer.append(line)

        # Save last section
        if content_buffer and current_section:
            result[current_section] = '\n'.join(content_buffer).strip()

        return result

    def get_default_result(self) -> Dict[str, Any]:
        """Return default result when no conclusion reached."""
        return {
            'improve_required': False,
            'insights': '',
            'suggestions': '',
            'analyzed': False
        }

    # =========================================================================
    # Tool Executors
    # =========================================================================

    def _execute_bash(self, command: str) -> str:
        """Execute bash command and return formatted result."""
        result = self.inspect_tool.execute(command)
        return self._format_bash_result(result)

    def _format_bash_result(self, process) -> str:
        """Format bash execution result."""
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        # Limit output size to avoid token overflow
        max_output_len = 10000
        if len(stdout) > max_output_len:
            stdout = stdout[:max_output_len] + f'\n... (truncated {len(stdout) - max_output_len} chars)'
        if len(stderr) > max_output_len:
            stderr = stderr[:max_output_len] + f'\n... (truncated {len(stderr) - max_output_len} chars)'

        result_parts = [f"Command: {process.args}"]
        result_parts.append(f"Return code: {process.returncode}")

        if stdout:
            result_parts.append(f"STDOUT:\n{stdout}")
        if stderr:
            result_parts.append(f"STDERR:\n{stderr}")

        return "\n".join(result_parts)

    # =========================================================================
    # Main Execution
    # =========================================================================

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze coverage to understand why it's low and provide insights.
        """
        from tool.container_tool import ProjectContainerTool
        from experiment import benchmark as benchmarklib
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )

        # Get benchmark object (need to convert from dict)
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)

        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")

        # Get function requirements
        function_requirements = self._get_function_requirements(state)

        # Get fuzzing log from state
        fuzzing_log = state.get("run_log", "")
        if not fuzzing_log:
            logger.warning(
                "Missing run_log; skipping coverage analysis for project %s (trial %02d, log_path=%s)",
                benchmark.project,
                self.trial,
                state.get("log_path", "")
            )
            self._langgraph_logger.flush_agent_logs(self.name)
            return {
                "coverage_analysis": {
                    "status": "skipped",
                    "reason": "Missing fuzzing log; cannot analyze coverage."
                },
                "session_memory": state.get("session_memory", {})
            }

        # Initialize inspect_tool with the fuzz target and build script
        self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
        self.inspect_tool.write_to_file(content=fuzz_target_source,
                                       file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(
                content=build_script_source,
                file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

        # Build base prompt using the new prompt_loader
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "coverage_analyzer",
            project=benchmark.project,
            language=benchmark.file_type.value,
            fuzz_target=fuzz_target_source,
            fuzzing_log=fuzzing_log,
            function_requirements=function_requirements,
            additional_context=""
        )

        # Inject session_memory
        user_prompt = build_prompt_with_session_memory(
            state,
            base_prompt,
            agent_name=self.name
        )

        try:
            # Use the mixin's tool calling loop
            coverage_result, all_responses = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=self.args.max_round,
                log_prefix="COVERAGE_ANALYZER"
            )
        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug(
                    'Stopping and removing inspect container',
                    trial=self.trial
                )
                self.inspect_tool.terminate()

        # Extract session_memory updates from all responses
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )

        # Merge updates to session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)

        # Record coverage analysis attempt
        try:
            coverage_percent = state.get("coverage_percent", 0.0)
            line_coverage_diff = state.get("line_coverage_diff", 0.0)
            no_improvement_count = state.get("no_coverage_improvement_count", 0)
            outcome = "analysis_improve_required" if coverage_result.get("improve_required", False) else "analysis_no_improvement_needed"
            add_coverage_attempt(
                state=state,
                attempt_type="coverage_analysis",
                outcome=outcome,
                coverage_percent=coverage_percent,
                line_coverage_diff=line_coverage_diff,
                no_improvement_count=no_improvement_count,
                iteration=state.get("current_iteration", 0),
                notes="CoverageAnalyzer completed"
            )
            updated_session_memory = state.get("session_memory", updated_session_memory)
        except Exception as e:
            logger.warning(f"Failed to record coverage_analysis attempt in session_memory: {e}", trial=self.trial)

        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)

        return {
            "coverage_analysis": coverage_result,
            "session_memory": updated_session_memory
        }

    def _get_function_requirements(self, state: FuzzingWorkflowState) -> str:
        """Get function requirements from previous analysis."""
        import os

        # Try to read from requirements file
        work_dirs_dict = state.get("work_dirs", {})
        requirements_dir = work_dirs_dict.get("requirements", "")

        if requirements_dir and os.path.isdir(requirements_dir):
            requirements_path = os.path.join(requirements_dir, f'{self.trial:02d}.txt')
            if os.path.exists(requirements_path):
                with open(requirements_path, 'r') as f:
                    return f.read()

        # Fallback to state
        function_analysis = state.get("function_analysis", {})
        return function_analysis.get("raw_analysis", "")
