"""
LangGraphCrashFeasibilityAnalyzer agent for LangGraph workflow.

This agent analyzes whether a crash is reachable from the project's external entry points.
Refactored to use consolidated tools for reduced token usage.
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
from src.tools.introspector import FuzzIntrospectorQueryTool, QueryType


class LangGraphCrashFeasibilityAnalyzer(LangGraphAgent, ToolCallingMixin):
    """
    Crash feasibility analyzer agent for LangGraph - analyzes crash reachability.

    Uses ToolCallingMixin for standardized multi-round tool interaction.
    Provides 2 consolidated tools: bash execution and FuzzIntrospector queries.
    """

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt(
            "crash_feasibility_analyzer")

        super().__init__(name="crash_feasibility_analyzer",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.inspect_tool = None
        self.fi_tool = None  # FuzzIntrospector tool
        self.benchmark = None  # Store benchmark for FI tool initialization
        self.project_name = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """Return consolidated tools for crash feasibility analysis.

        Uses 2 tools instead of 9:
        - BashExecuteTool: For container command execution
        - FuzzIntrospectorQueryTool: Unified tool for all FI queries
        """
        return [
            BashExecuteTool(executor=self._execute_bash),
            FuzzIntrospectorQueryTool(
                get_implementation=self._get_function_implementation,
                get_signature=self._get_function_signature,
                get_cross_refs=self._get_sample_cross_references,
                get_type_defs=self._get_type_definitions,
                get_headers=self._get_headers_for_function,
                get_tests=self._get_tests_for_functions,
                get_debug_types=self._get_function_debug_types,
                get_by_return_type=self._get_functions_by_return_type,
            ),
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

    def _get_function_implementation(self, function_name: str) -> str:
        """Get function implementation via FuzzIntrospector."""
        impl = self.fi_tool.get_function_implementation(
            self.project_name, function_name)
        if impl:
            return f"Function implementation for '{function_name}':\n```c\n{impl}\n```"
        return f"Error: Could not find implementation for function '{function_name}'"

    def _get_function_signature(self, function_name: str) -> str:
        """Get function signature via FuzzIntrospector."""
        signature = self.fi_tool.get_function_signature(function_name)
        if signature:
            return f"Function signature: {signature}"
        return f"Error: Could not find signature for function '{function_name}'"

    def _get_sample_cross_references(self, function_signature: str) -> str:
        """Get sample cross references via FuzzIntrospector."""
        cross_refs = self.fi_tool.get_sample_cross_references(
            function_signature)
        if cross_refs:
            result = f"Sample usage examples for '{function_signature}':\n\n"
            for i, ref in enumerate(cross_refs[:5], 1):  # Limit to 5 examples
                result += f"Example {i}:\n```c\n{ref}\n```\n\n"
            return result
        return f"No cross-references found for '{function_signature}'"

    def _get_type_definitions(self) -> str:
        """Get type definitions via FuzzIntrospector."""
        type_defs = self.fi_tool.get_type_definitions()
        if type_defs:
            result = "Type definitions in project:\n\n"
            for typedef in type_defs[:
                                     20]:  # Limit to 20 to avoid token overflow
                name = typedef.get("name", "Unknown")
                kind = typedef.get("kind", "Unknown")
                defn = typedef.get("definition", "")
                result += f"- {name} ({kind})\n"
                if defn:
                    result += f"  ```c\n  {defn}\n  ```\n"
            if len(type_defs) > 20:
                result += f"\n... and {len(type_defs) - 20} more type definitions"
            return result
        return "No type definitions found"

    def _get_headers_for_function(self, function_signature: str) -> str:
        """Get headers for function via FuzzIntrospector."""
        headers = self.fi_tool.get_headers_for_function(function_signature)
        if headers:
            result = f"Required headers for '{function_signature}':\n"
            for header in headers:
                result += f"  #include <{header}>\n"
            return result
        return f"No header information found for '{function_signature}'"

    def _get_tests_for_functions(self, function_names: List[str]) -> str:
        """Get tests for functions via FuzzIntrospector."""
        tests = self.fi_tool.get_tests_for_functions(function_names)
        if tests:
            result = f"Test examples for functions: {', '.join(function_names)}\n\n"
            for func, test_code in tests.items():
                if test_code:
                    result += f"Tests for '{func}':\n```c\n{test_code}\n```\n\n"
            return result
        return f"No tests found for functions: {', '.join(function_names)}"

    def _get_function_debug_types(self, function_signature: str) -> str:
        """Get function debug types via FuzzIntrospector."""
        debug_types = self.fi_tool.get_function_debug_types(function_signature)
        if debug_types:
            result = f"Debug type information for '{function_signature}':\n"
            for i, dtype in enumerate(debug_types, 1):
                result += f"  Parameter {i}: {dtype}\n"
            return result
        return f"No debug type information found for '{function_signature}'"

    def _get_functions_by_return_type(self, return_type: str) -> str:
        """Get functions by return type via FuzzIntrospector."""
        functions = self.fi_tool.get_functions_by_return_type(return_type)
        if functions:
            result = f"Functions returning '{return_type}':\n"
            for func in functions[:10]:  # Limit to 10
                func_name = func.get("function_name", "Unknown")
                func_sig = func.get("function_signature", "")
                result += f"  - {func_name}\n"
                if func_sig:
                    result += f"    Signature: {func_sig}\n"
            if len(functions) > 10:
                result += f"\n... and {len(functions) - 10} more functions"
            return result
        return f"No functions found returning '{return_type}'"

    def _init_fi_tool(self):
        """Initialize FuzzIntrospector tool for the project."""
        if self.fi_tool is None and self.benchmark is not None:
            from tool.fuzz_introspector_tool import FuzzIntrospectorTool
            logger.info(
                f"Initializing FuzzIntrospector for project: {self.benchmark.project}",
                trial=self.trial)
            self.fi_tool = FuzzIntrospectorTool(self.benchmark)
            self.project_name = self.benchmark.project

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

        # Initialize FuzzIntrospector tool for API calls
        self._init_fi_tool()

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
