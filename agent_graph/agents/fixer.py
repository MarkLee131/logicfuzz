"""
LangGraphFixer agent for LangGraph workflow.

Fixes compilation errors with optional tool calling for context exploration.
"""
from typing import Any, Dict
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.tools import get_bash_tool


class LangGraphFixer(LangGraphAgent):
    """
    Fixer agent for LangGraph.

    Uses tool calling to explore project structure when needed for fixing
    header paths, finding correct include locations, etc.
    """

    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("fixer")
        super().__init__(
            name="fixer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
        self.inspect_tool = None

    def _get_tool_definitions(self) -> list[dict]:
        """Define tools available to Fixer."""
        return [get_bash_tool()]

    def _execute_tool(self, tool_call: dict) -> str:
        """Execute a tool call and return the result."""
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})

        if tool_name == "bash_execute":
            command = arguments.get("command", "")
            if not command:
                return "Error: bash_execute requires 'command' argument"

            # Execute via ProjectContainerTool
            result = self.inspect_tool.execute(command)
            return self._format_bash_result(result)

        return f"Error: Unknown tool '{tool_name}'"

    def _format_bash_result(self, process) -> str:
        """Format bash execution result."""
        stdout = process.stdout.strip() if process.stdout else ""
        stderr = process.stderr.strip() if process.stderr else ""

        # Limit output size to avoid token overflow
        max_output_len = 8000
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

    def _has_conclusion(self, text: str) -> bool:
        """Check if the response contains a conclusion with fixed code."""
        if not text:
            return False
        # Look for code block which indicates the fix is ready
        return "```cpp" in text or "```c" in text or "**Conclusion:**" in text

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Fix compilation errors with optional tool calling."""
        from tool.container_tool import ProjectContainerTool
        from experiment import benchmark as benchmarklib
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )

        # Get benchmark object
        benchmark_dict = state["benchmark"]
        benchmark = benchmarklib.Benchmark.from_dict(benchmark_dict)

        current_code = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        build_errors = state.get("build_errors", [])
        workflow_phase = state.get("workflow_phase", "compilation")

        error_text = "\n".join(build_errors[:10])
        code_context = self._generate_code_context(current_code, build_errors)

        function_analysis = state.get("function_analysis", {})
        header_info = function_analysis.get("header_information", {})
        header_hints = self._format_header_hints(header_info, build_errors)
        api_warnings = state.get("api_validation_warnings", "")

        additional_context_parts = []

        # Add target path info for include path context
        target_path = benchmark.target_path
        if target_path:
            additional_context_parts.append(f"**Fuzz target location**: `{target_path}`")
            import os
            target_dir = os.path.dirname(target_path)
            additional_context_parts.append(f"**Target directory**: `{target_dir}`")
            additional_context_parts.append("")

        if header_hints:
            additional_context_parts.append(header_hints)
        if api_warnings:
            additional_context_parts.append("\n---\n\n# ⚠️  API Validation Warnings\n\n" + api_warnings)

        additional_context = "\n".join(additional_context_parts)

        # Initialize inspect_tool for bash execution
        self.inspect_tool = ProjectContainerTool(benchmark, name='fixer_inspect')
        self.inspect_tool.write_to_file(content=current_code,
                                        file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(
                content=build_script_source,
                file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

        # Build base prompt
        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "fixer",
            project_name=benchmark.project,
            language=benchmark.file_type.value if hasattr(benchmark.file_type, 'value') else 'C++',
            current_code=code_context,
            build_errors=error_text,
            additional_context=additional_context
        )

        user_prompt = build_prompt_with_session_memory(state, base_prompt, agent_name=self.name)

        # Multi-round interaction with tool calling
        tools = self._get_tool_definitions()
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": user_prompt}
        ]

        fuzz_target_code = None
        cur_round = 0
        max_round = 3  # Fixer should be quick - max 3 rounds
        total_tool_calls = 0
        MAX_TOOL_CALLS = 3  # Limit tool calls for fixer
        all_responses = []

        try:
            while cur_round < max_round:
                # Call LLM with tools
                response_data = self.call_llm_with_tools(
                    messages=messages,
                    tools=tools,
                    state=state,
                    log_prefix=f"FIXER_ROUND_{cur_round:02d}"
                )

                assistant_message = response_data["message"]
                text_response = assistant_message.get("content", "") or ""
                tool_calls = assistant_message.get("tool_calls", []) or []

                messages.append(assistant_message)

                if text_response:
                    all_responses.append(text_response)

                logger.info(
                    f'<FIXER ROUND {cur_round}>\n{text_response[:500]}...\n</FIXER ROUND {cur_round}>',
                    trial=self.trial
                )

                # Check if we have a conclusion with fixed code
                if text_response and self._has_conclusion(text_response):
                    logger.info(f'Fixer provided fix at round {cur_round}', trial=self.trial)
                    fuzz_target_code = parse_tag(text_response, 'fuzz_target')
                    if not fuzz_target_code:
                        from agent_graph.agents.utils import strip_cdata
                        fuzz_target_code = strip_cdata(text_response)
                    break

                # Execute tool calls if any
                if tool_calls:
                    for tool_call in tool_calls:
                        if total_tool_calls >= MAX_TOOL_CALLS:
                            logger.warning(
                                f"Max tool calls ({MAX_TOOL_CALLS}) reached",
                                trial=self.trial
                            )
                            break

                        total_tool_calls += 1
                        tool_result = self._execute_tool(tool_call)

                        tool_message = {
                            "role": "tool",
                            "tool_call_id": tool_call.get("id", ""),
                            "content": tool_result
                        }
                        messages.append(tool_message)

                    if total_tool_calls >= MAX_TOOL_CALLS:
                        messages.append({
                            "role": "user",
                            "content": "Tool call limit reached. Please provide your fix now."
                        })

                    cur_round += 1
                    continue

                # If no tool calls and no conclusion, prompt for fix
                if not tool_calls and text_response:
                    messages.append({
                        "role": "user",
                        "content": "Please provide the fixed code in a ```cpp code block."
                    })

                cur_round += 1

        finally:
            # Cleanup container
            if self.inspect_tool:
                logger.debug('Stopping fixer inspect container', trial=self.trial)
                self.inspect_tool.terminate()

        # If no code was extracted, use the last response
        if not fuzz_target_code and all_responses:
            from agent_graph.agents.utils import strip_cdata
            fuzz_target_code = strip_cdata(all_responses[-1])

        # Extract session memory updates
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)

        state_update = {
            "fuzz_target_source": fuzz_target_code or current_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "build_errors": [],
            "session_memory": updated_session_memory
        }

        if workflow_phase == "compilation":
            compilation_retry_count = state.get("compilation_retry_count", 0)
            state_update["compilation_retry_count"] = compilation_retry_count + 1
            logger.info(f'Compilation retry count: {compilation_retry_count + 1}', trial=self.trial)
        else:
            retry_count = state.get("retry_count", 0)
            state_update["retry_count"] = retry_count + 1

        self._langgraph_logger.flush_agent_logs(self.name)

        return state_update

    def _generate_code_context(self, current_code: str, build_errors: list) -> str:
        """
        Generate code context for fixer based on diff strategy.

        Strategy: Extract only the error-relevant parts of code to reduce token usage.
        """
        if not current_code:
            return ""

        error_lines = set()
        for error in build_errors:
            import re
            matches = re.findall(r':(\d+):', error) or re.findall(r'line (\d+)', error)
            for match in matches:
                try:
                    line_num = int(match)
                    for i in range(max(1, line_num - 10), line_num + 11):
                        error_lines.add(i)
                except (ValueError, IndexError):
                    continue

        if error_lines:
            code_lines = current_code.split('\n')
            relevant_lines = []
            last_included = -100

            for line_num in sorted(error_lines):
                if line_num <= len(code_lines):
                    if line_num - last_included > 1 and last_included != -100:
                        relevant_lines.append("// ... (lines omitted) ...")
                    relevant_lines.append(f"/* Line {line_num} */ {code_lines[line_num - 1]}")
                    last_included = line_num

            if relevant_lines:
                context = "**Code sections relevant to errors:**\n```cpp\n" + "\n".join(relevant_lines) + "\n```"
                logger.debug(f'Extracted {len(relevant_lines)} relevant lines from {len(code_lines)} total lines',
                            trial=self.trial)
                return context

        if len(current_code) < 5000:
            return current_code

        code_lines = current_code.split('\n')
        if len(code_lines) > 100:
            first_50 = '\n'.join(code_lines[:50])
            last_50 = '\n'.join(code_lines[-50:])
            return f"{first_50}\n\n// ... (middle section omitted) ...\n\n{last_50}"

        return current_code

    def _format_header_hints(self, header_info: dict, build_errors: list) -> str:
        """
        Format header information as hints for the Fixer to fix header-related errors.
        """
        if not header_info:
            return ""

        has_header_errors = any(
            'file not found' in error.lower() or
            'no such file' in error.lower() or
            '#include' in error.lower()
            for error in build_errors
        )

        if not has_header_errors:
            return ""

        hint_lines = [
            "",
            "# ⚡ Known Header Information",
            "",
            "⚠️  If you need to find the correct header path, use `bash_execute` to explore:",
            "  - `find /src -name '*.h' | head -20` - List header files",
            "  - `ls -la /src/{project}/` - Check project structure",
            "  - `cat /src/{project}/fuzzing/*.c | head -30` - See existing fuzzer includes",
            ""
        ]

        # Priority 0: Headers from existing fuzzers (HIGHEST PRIORITY)
        existing_headers = header_info.get('existing_fuzzer_headers', {})
        existing_proj = existing_headers.get('project_headers', [])

        if existing_proj:
            hint_lines.extend([
                "## 🥇 Reference includes from existing fuzzers (COPY THESE):",
                ""
            ])
            for h in sorted(set(existing_proj))[:8]:
                hint_lines.append(f'  #include "{h}"')
            hint_lines.append("")

        # Priority 1: Public API headers
        definition_headers = header_info.get('definition_file_headers', {})
        proj_headers = definition_headers.get('project_headers', [])

        if proj_headers:
            hint_lines.extend([
                "## 🥈 Public API headers:",
                ""
            ])
            for h in sorted(set(proj_headers))[:8]:
                hint_lines.append(f"  {h}")
            hint_lines.append("")

        return "\n".join(hint_lines)


# Keep old name for backward compatibility
LangGraphEnhancer = LangGraphFixer
