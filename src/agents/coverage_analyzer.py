"""
LangGraphCoverageAnalyzer agent - analyzes coverage and suggests improvements.
"""
import argparse
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState, add_coverage_attempt
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.utils.prompt_loader import get_prompt_manager
from src.tools.langchain_adapters import BashExecuteTool


class LangGraphCoverageAnalyzer(LangGraphAgent, ToolCallingMixin):
    """Coverage analyzer using ReAct-style tool calling."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        super().__init__(
            name="coverage_analyzer",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=prompt_manager.get_system_prompt("coverage_analyzer")
        )
        self.inspect_tool = None

    def get_tools(self) -> List[BaseTool]:
        return [BashExecuteTool(executor=self._execute_bash)]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse final response to extract coverage analysis result."""
        result = {'improve_required': False, 'insights': '', 'suggestions': '', 'analyzed': True}

        text_lower = content.lower()

        # XML format: <conclusion>true/false</conclusion>
        match = re.search(r'<conclusion>\s*(true|false)\s*</conclusion>', text_lower)
        if match:
            result['improve_required'] = match.group(1) == 'true'

        # Extract insights
        insights_match = re.search(r'<insights?>(.*?)</insights?>', content, re.DOTALL | re.IGNORECASE)
        if insights_match:
            result['insights'] = insights_match.group(1).strip()

        # Extract suggestions
        suggestions_match = re.search(r'<suggestions?>(.*?)</suggestions?>', content, re.DOTALL | re.IGNORECASE)
        if suggestions_match:
            result['suggestions'] = suggestions_match.group(1).strip()

        # Fallback: text format
        if not match:
            if 'true' in text_lower and ('improve' in text_lower or 'conclusion' in text_lower):
                result['improve_required'] = True

        return result

    def _execute_bash(self, command: str) -> str:
        result = self.inspect_tool.execute(command)
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        parts = [f"$ {command}", f"exit={result.returncode}"]
        if stdout:
            parts.append(stdout)
        if stderr:
            parts.append(f"STDERR: {stderr}")
        return "\n".join(parts)

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        from tool.container_tool import ProjectContainerTool
        from experiment import benchmark as benchmarklib
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )

        benchmark = benchmarklib.Benchmark.from_dict(state["benchmark"])
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        fuzzing_log = state.get("run_log", "")

        if not fuzzing_log:
            logger.warning("Missing run_log; skipping coverage analysis", trial=self.trial)
            self._langgraph_logger.flush_agent_logs(self.name)
            return {
                "coverage_analysis": {"status": "skipped", "reason": "Missing fuzzing log"},
                "session_memory": state.get("session_memory", {})
            }

        # Setup container
        self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
        self.inspect_tool.write_to_file(content=fuzz_target_source, file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(content=build_script_source, file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

        # Determine target language from file extension (same logic as prototyper/improver)
        target_path = benchmark.target_path
        cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
        is_cpp_target = target_path.lower().endswith(cpp_extensions)
        target_language = 'c++' if is_cpp_target else 'c'

        # Build prompt with language-specific template
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "coverage_analyzer",
            language=target_language,  # For prompt template selection
            project=benchmark.project,
            fuzz_target=fuzz_target_source,
            fuzzing_log=fuzzing_log,
            function_requirements=self._get_function_requirements(state),
            additional_context=""
        )
        user_prompt = build_prompt_with_session_memory(state, base_prompt, agent_name=self.name)

        try:
            result, all_responses = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=self.args.max_round,
                log_prefix="COV"
            )
        finally:
            if self.inspect_tool:
                self.inspect_tool.terminate()

        # Session memory
        combined = "\n\n".join(all_responses)
        updates = extract_session_memory_updates_from_response(combined, self.name, state.get("current_iteration", 0))
        session_memory = merge_session_memory_updates(state, updates)

        # Record attempt
        try:
            add_coverage_attempt(
                state=state,
                attempt_type="coverage_analysis",
                outcome="improve_required" if result.get("improve_required") else "no_improvement_needed",
                coverage_percent=state.get("coverage_percent", 0.0),
                line_coverage_diff=state.get("line_coverage_diff", 0.0),
                no_improvement_count=state.get("no_coverage_improvement_count", 0),
                iteration=state.get("current_iteration", 0),
                notes="CoverageAnalyzer completed"
            )
            session_memory = state.get("session_memory", session_memory)
        except Exception as e:
            logger.warning(f"Failed to record attempt: {e}", trial=self.trial)

        self._langgraph_logger.flush_agent_logs(self.name)
        return {"coverage_analysis": result, "session_memory": session_memory}

    def _get_function_requirements(self, state: FuzzingWorkflowState) -> str:
        import os
        work_dirs = state.get("work_dirs", {})
        req_dir = work_dirs.get("requirements", "")
        if req_dir and os.path.isdir(req_dir):
            path = os.path.join(req_dir, f'{self.trial:02d}.txt')
            if os.path.exists(path):
                with open(path) as f:
                    return f.read()
        return state.get("function_analysis", {}).get("raw_analysis", "")
