"""
LangGraphFixer agent - fixes compilation errors.
"""
import argparse
import os
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.agents.utils import parse_tag
from src.utils.prompt_loader import get_prompt_manager
from src.tools.langchain_adapters import BashExecuteTool


class LangGraphFixer(LangGraphAgent, ToolCallingMixin):
    """Fixer agent using ReAct-style tool calling."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        super().__init__(
            name="fixer",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=prompt_manager.get_system_prompt("fixer"))
        self.inspect_tool = None

    def get_tools(self) -> List[BaseTool]:
        return [BashExecuteTool(executor=self._execute_bash)]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Extract fixed code from response."""
        code = parse_tag(content, 'fuzz_target')
        if not code:
            # No fallback - if LLM didn't follow format, keep code empty
            # The execute() method will fall back to current_code
            logger.warning('No <fuzz_target> tag found in fixer response',
                           trial=self.trial)
        return {
            'fuzz_target_code': code,
            'raw_response': content,
            'fixed': bool(code)
        }

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
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates)

        benchmark = benchmarklib.Benchmark.from_dict(state["benchmark"])
        current_code = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        build_errors = state.get("build_errors", [])

        # Setup container
        self.inspect_tool = ProjectContainerTool(benchmark,
                                                 name='fixer_inspect')
        self.inspect_tool.write_to_file(content=current_code,
                                        file_path=benchmark.target_path)
        if build_script_source:
            self.inspect_tool.write_to_file(
                content=build_script_source,
                file_path=self.inspect_tool.build_script_path)
        self.inspect_tool.compile(
            extra_commands=' && rm -rf /out/* > /dev/null')

        # Build prompt
        error_text = "\n".join(build_errors[:10])
        code_context = self._generate_code_context(current_code, build_errors)
        additional = self._build_additional_context(benchmark, state,
                                                    build_errors)

        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "fixer",
            project_name=benchmark.project,
            language=benchmark.file_type.value if hasattr(
                benchmark.file_type, 'value') else 'C++',
            current_code=code_context,
            build_errors=error_text,
            additional_context=additional)
        user_prompt = build_prompt_with_session_memory(state,
                                                       base_prompt,
                                                       agent_name=self.name)

        try:
            result, all_responses = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=3,
                log_prefix="FIX")
        finally:
            if self.inspect_tool:
                self.inspect_tool.terminate()

        # Extract code - no fallback to raw response
        # If LLM didn't output <fuzz_target> tag, we keep current_code (line 117)
        fuzz_target_code = result.get('fuzz_target_code')

        # Session memory
        combined = "\n\n".join(all_responses)
        updates = extract_session_memory_updates_from_response(
            combined, self.name, state.get("current_iteration", 0))
        session_memory = merge_session_memory_updates(state, updates)

        state_update = {
            "fuzz_target_source": fuzz_target_code or current_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "build_errors": [],
            "session_memory": session_memory,
            # Always increment compilation_retry_count when fixer is called for build errors
            "compilation_retry_count":
            state.get("compilation_retry_count", 0) + 1
        }

        self._langgraph_logger.flush_agent_logs(self.name)
        return state_update

    def _generate_code_context(self, code: str, errors: list) -> str:
        if not code:
            return ""
        error_lines = set()
        for err in errors:
            for m in re.findall(r':(\d+):', err) or re.findall(
                    r'line (\d+)', err):
                try:
                    ln = int(m)
                    error_lines.update(range(max(1, ln - 10), ln + 11))
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
        return code if len(
            code) < 5000 else code[:2500] + "\n// ...\n" + code[-2500:]

    def _build_additional_context(self, benchmark, state, errors) -> str:
        from src.utils.compilation_error_triage import (
            triage_build_errors, get_fix_guidance, TriageResult)

        parts = []
        if benchmark.target_path:
            parts.append(f"**Target**: `{benchmark.target_path}`")

        # Get context (used for triage fallback and driver knowledge)
        context = state.get("context", {})

        # Use triage result from state if available (passed from supervisor)
        # This avoids duplicate triage computation
        triage_dict = state.get("error_triage")
        if triage_dict:
            triage_result = TriageResult.from_dict(triage_dict)
            logger.info(f'Using triage from supervisor: primary={triage_result.primary_category}, '
                       f'strategy={triage_result.recommended_strategy}', trial=self.trial)
        else:
            # Fallback: compute triage if not provided by supervisor
            project_apis = context.get("project_apis", [])
            triage_result = triage_build_errors(errors, project_apis)

        # Add triage-based guidance
        if triage_result.errors:
            fix_guidance = get_fix_guidance(triage_result)
            parts.append(f"\n{fix_guidance}")

        # Add strategy-specific hints
        if triage_result.recommended_strategy:
            strategy_hints = self._get_strategy_hints(triage_result)
            if strategy_hints:
                parts.append(f"\n{strategy_hints}")

        header_info = state.get("function_analysis",
                                {}).get("header_information", {})
        if header_info and any(
                'file not found' in e.lower() or '#include' in e.lower()
                for e in errors):
            parts.append(
                "\n**Header hints**: Use `bash_execute` to find headers with `find /src -name '*.h'`"
            )

        if state.get("api_validation_warnings"):
            parts.append(
                f"\n**API warnings**: {state['api_validation_warnings']}")

        # Add existing driver knowledge as reference for fixing
        existing_driver_knowledge = context.get("existing_driver_knowledge", {})
        driver_ref = self._format_driver_knowledge_for_fixer(
            existing_driver_knowledge, errors)
        if driver_ref:
            parts.append(driver_ref)

        return "\n".join(parts)

    def _format_driver_knowledge_for_fixer(self, driver_knowledge: Dict[str, Any],
                                           errors: List[str]) -> str:
        """Format existing driver knowledge as reference for fixing errors."""
        if not driver_knowledge:
            return ""

        driver_sources = driver_knowledge.get('driver_sources', [])
        analysis = driver_knowledge.get('analysis', {}) or {}

        if not driver_sources and not analysis:
            return ""

        # Check if errors are related to headers/includes
        has_header_errors = any(
            'file not found' in e.lower() or
            '#include' in e.lower() or
            'no such file' in e.lower()
            for e in errors
        )

        # Check if errors are related to undefined references (linker)
        has_linker_errors = any(
            'undefined reference' in e.lower() or
            'undefined symbol' in e.lower()
            for e in errors
        )

        lines = ["\n<existing_driver_reference>"]
        lines.append(
            "The following patterns are from working OSS-Fuzz drivers for this project."
        )
        lines.append("Use them as reference for fixing compilation errors.\n")

        # Add setup/teardown patterns if available
        if analysis.get('setup_teardown'):
            lines.append("<setup_teardown_patterns>")
            lines.append(analysis['setup_teardown'])
            lines.append("</setup_teardown_patterns>\n")

        # Add code patterns if available
        if analysis.get('code_patterns'):
            lines.append("<code_patterns>")
            lines.append(analysis['code_patterns'])
            lines.append("</code_patterns>\n")

        # For header/include errors, show include patterns from existing drivers
        if has_header_errors and driver_sources:
            lines.append("<working_includes>")
            lines.append("Include patterns from working fuzzers:")
            for driver in driver_sources[:2]:
                source = driver.get('source', '')
                # Extract include lines
                includes = [
                    line.strip() for line in source.split('\n')
                    if line.strip().startswith('#include')
                ][:10]
                if includes:
                    lines.append(f"\n// From {driver.get('path', 'unknown')}:")
                    lines.extend(includes)
            lines.append("</working_includes>\n")

        # For linker errors, show full driver as reference
        if has_linker_errors and driver_sources:
            lines.append("<linker_reference>")
            lines.append(
                "For undefined reference errors, check how existing fuzzers handle linking:"
            )
            # Show first driver's approach (truncated)
            driver = driver_sources[0]
            source = driver.get('source', '')
            if len(source) > 1500:
                source = source[:1500] + "\n// ... (truncated)"
            lines.append(f"\n// Reference: {driver.get('path', 'unknown')}")
            lines.append("```cpp")
            lines.append(source)
            lines.append("```")
            lines.append("</linker_reference>")

        lines.append("</existing_driver_reference>")
        return "\n".join(lines)

    def _get_strategy_hints(self, triage_result) -> str:
        """Get strategy-specific hints based on recommended fix strategy."""
        from src.utils.compilation_error_triage import FixStrategy

        strategy = triage_result.recommended_strategy
        if not strategy:
            return ""

        hints = {
            FixStrategy.ADD_LIBRARY_LINK: (
                "### Strategy: Add Library Link\n"
                "Use `bash_execute` to find the library:\n"
                "- `find /src -name '*.a' -o -name '*.so'`\n"
                "- Check build script for existing `-l` flags"
            ),
            FixStrategy.INCLUDE_CPP_FILE: (
                "### Strategy: Include Implementation File\n"
                "Some libraries require including .cpp files directly:\n"
                "- Check existing fuzzers for `#include \"*.cpp\"` patterns\n"
                "- Common pattern: `#include \"impl.cpp\"` or `#include \"library.cpp\"`"
            ),
            FixStrategy.FIX_INCLUDE_PATH: (
                "### Strategy: Fix Include Path\n"
                "Use `bash_execute` to locate headers:\n"
                "- `find /src -name 'header_name.h'`\n"
                "- Check if relative path needs adjustment"
            ),
            FixStrategy.ADD_INCLUDE: (
                "### Strategy: Add Missing Include\n"
                "Find the header declaring the missing symbol:\n"
                "- `grep -r 'symbol_name' /src --include='*.h'`\n"
                "- Check existing fuzzers for include patterns"
            ),
            FixStrategy.FIX_SIGNATURE: (
                "### Strategy: Fix Type/Signature\n"
                "Common type errors:\n"
                "- C requires `struct`/`enum`/`union` keywords before type names\n"
                "- Check parameter types match function declarations\n"
                "- Verify pointer vs value semantics"
            ),
            FixStrategy.USE_C_PATTERNS: (
                "### Strategy: Use Pure C Patterns\n"
                "Replace C++ features with C equivalents:\n"
                "- NO `FuzzedDataProvider` - use raw `data`/`size` directly\n"
                "- NO `std::` types - use C types (`char*`, `size_t`)\n"
                "- NO C++ casts - use C-style casts if needed"
            ),
            FixStrategy.USE_PUBLIC_API: (
                "### Strategy: Use Public API\n"
                "Internal/private headers are not available:\n"
                "- Replace with public API equivalents\n"
                "- Check existing fuzzers for correct public includes"
            ),
        }

        return hints.get(strategy, "")
