"""
LangGraphFixer agent - fixes compilation errors.
"""
import argparse
import os
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.tool_calling_mixin import ToolCallingMixin
from agent_graph.agents.utils import parse_tag, strip_cdata
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.tools.langchain_adapters import BashExecuteTool


class LangGraphFixer(LangGraphAgent, ToolCallingMixin):
    """Fixer agent using ReAct-style tool calling."""

    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        super().__init__(
            name="fixer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=prompt_manager.get_system_prompt("fixer")
        )
        self.inspect_tool = None

    def get_langchain_tools(self) -> List[BaseTool]:
        return [BashExecuteTool(executor=self._execute_bash)]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Extract fixed code from response."""
        code = parse_tag(content, 'fuzz_target') or strip_cdata(content)
        return {'fuzz_target_code': code, 'raw_response': content, 'fixed': bool(code)}

    def _execute_bash(self, command: str) -> str:
        result = self.inspect_tool.execute(command)
        stdout = (result.stdout or "").strip()[:8000]
        stderr = (result.stderr or "").strip()[:8000]
        parts = [f"$ {command}", f"exit={result.returncode}"]
        if stdout:
            parts.append(stdout)
        if stderr:
            parts.append(f"STDERR: {stderr}")
        return "\n".join(parts)

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        from tool.container_tool import ProjectContainerTool
        from experiment import benchmark as benchmarklib
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )

        benchmark = benchmarklib.Benchmark.from_dict(state["benchmark"])
        current_code = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        build_errors = state.get("build_errors", [])
        workflow_phase = state.get("workflow_phase", "compilation")

        # Setup container
        self.inspect_tool = ProjectContainerTool(benchmark, name='fixer_inspect')
        self.inspect_tool.write_to_file(content=current_code, file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(content=build_script_source, file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

        # Build prompt
        error_text = "\n".join(build_errors[:10])
        code_context = self._generate_code_context(current_code, build_errors)
        additional = self._build_additional_context(benchmark, state, build_errors)

        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "fixer",
            project_name=benchmark.project,
            language=benchmark.file_type.value if hasattr(benchmark.file_type, 'value') else 'C++',
            current_code=code_context,
            build_errors=error_text,
            additional_context=additional
        )
        user_prompt = build_prompt_with_session_memory(state, base_prompt, agent_name=self.name)

        try:
            result, all_responses = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=3,
                log_prefix="FIX"
            )
        finally:
            if self.inspect_tool:
                self.inspect_tool.terminate()

        # Extract code
        fuzz_target_code = result.get('fuzz_target_code')
        if not fuzz_target_code and all_responses:
            fuzz_target_code = strip_cdata(all_responses[-1])

        # Session memory
        combined = "\n\n".join(all_responses)
        updates = extract_session_memory_updates_from_response(combined, self.name, state.get("current_iteration", 0))
        session_memory = merge_session_memory_updates(state, updates)

        state_update = {
            "fuzz_target_source": fuzz_target_code or current_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "build_errors": [],
            "session_memory": session_memory
        }

        if workflow_phase == "compilation":
            state_update["compilation_retry_count"] = state.get("compilation_retry_count", 0) + 1
        else:
            state_update["retry_count"] = state.get("retry_count", 0) + 1

        self._langgraph_logger.flush_agent_logs(self.name)
        return state_update

    def _generate_code_context(self, code: str, errors: list) -> str:
        if not code:
            return ""
        error_lines = set()
        for err in errors:
            for m in re.findall(r':(\d+):', err) or re.findall(r'line (\d+)', err):
                try:
                    ln = int(m)
                    error_lines.update(range(max(1, ln-10), ln+11))
                except ValueError:
                    pass
        if error_lines:
            lines = code.split('\n')
            relevant = []
            last = -100
            for ln in sorted(error_lines):
                if ln <= len(lines):
                    if ln - last > 1 and last != -100:
                        relevant.append("// ...")
                    relevant.append(f"/* {ln} */ {lines[ln-1]}")
                    last = ln
            if relevant:
                return "```cpp\n" + "\n".join(relevant) + "\n```"
        return code if len(code) < 5000 else code[:2500] + "\n// ...\n" + code[-2500:]

    def _build_additional_context(self, benchmark, state, errors) -> str:
        parts = []
        if benchmark.target_path:
            parts.append(f"**Target**: `{benchmark.target_path}`")

        header_info = state.get("function_analysis", {}).get("header_information", {})
        if header_info and any('file not found' in e.lower() or '#include' in e.lower() for e in errors):
            parts.append("\n**Header hints**: Use `bash_execute` to find headers with `find /src -name '*.h'`")

        if state.get("api_validation_warnings"):
            parts.append(f"\n**API warnings**: {state['api_validation_warnings']}")

        return "\n".join(parts)
