"""
LangGraphImprover agent for LangGraph workflow.

Refactored to use ToolCallingMixin for FuzzIntrospector tool access.
LLM can query function source code and usage examples when improving coverage.
"""
from typing import Any, Dict, List
import argparse

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState, add_coverage_attempt
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.agents.utils import parse_tag
from src.utils.prompt_loader import get_prompt_manager
from src.tools.introspector import FuzzIntrospectorQueryTool, QueryType


class LangGraphImprover(LangGraphAgent, ToolCallingMixin):
    """
    Improver agent for LangGraph - improves fuzz drivers based on coverage analysis.

    Uses consolidated FuzzIntrospectorQueryTool (1 tool instead of 4) for querying:
    - function_implementation: Get source code to understand uncovered code paths
    - function_signature: Verify parameter types for new API calls
    - cross_references: Learn correct API patterns from usage examples
    - tests_for_functions: See test code for exercising specific functionality

    LLM can decide when to use tools based on coverage analysis suggestions.
    """

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("improver")
        super().__init__(name="improver",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.fi_tool = None
        self.project_name = None
        self.benchmark = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """Return consolidated FuzzIntrospector tool for querying API information.

        Uses 1 unified tool instead of 4 separate tools.
        Supported query types: function_implementation, function_signature,
        cross_references, tests_for_functions
        """
        return [
            FuzzIntrospectorQueryTool(
                get_implementation=self._get_function_implementation,
                get_signature=self._get_function_signature,
                get_cross_refs=self._get_sample_cross_references,
                get_type_defs=lambda: "Not supported in improver",
                get_headers=lambda x: "Not supported in improver",
                get_tests=self._get_tests_for_functions,
                get_debug_types=lambda x: "Not supported in improver",
                get_by_return_type=lambda x: "Not supported in improver",
            ),
        ]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse final LLM response to extract improved fuzz target code."""
        improved_code = parse_tag(content, 'fuzz_target')
        return {'improved_code': improved_code, 'raw_response': content}

    # =========================================================================
    # Tool Executors
    # =========================================================================

    def _init_fi_tool(self):
        """Initialize FuzzIntrospector tool for the project."""
        if self.fi_tool is None and self.benchmark is not None:
            from tool.fuzz_introspector_tool import FuzzIntrospectorTool
            from experiment import benchmark as benchmarklib
            benchmark_obj = benchmarklib.Benchmark.from_dict(self.benchmark)
            logger.info(
                f"Initializing FuzzIntrospector for project: {benchmark_obj.project}",
                trial=self.trial)
            self.fi_tool = FuzzIntrospectorTool(benchmark_obj)
            self.project_name = benchmark_obj.project

    def _get_function_implementation(self, function_name: str) -> str:
        """Get function source code via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool or not self.project_name:
            return f"Error: FuzzIntrospector not available"
        impl = self.fi_tool.get_function_implementation(
            self.project_name, function_name)
        if impl:
            return f"Source code for '{function_name}':\n```c\n{impl}\n```"
        return f"Error: Could not find source code for function '{function_name}'"

    def _get_function_signature(self, function_name: str) -> str:
        """Get function signature via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        signature = self.fi_tool.get_function_signature(function_name)
        if signature:
            return f"Function signature: {signature}"
        return f"Error: Could not find signature for function '{function_name}'"

    def _get_sample_cross_references(self, function_signature: str) -> str:
        """Get sample usage examples via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool or not self.project_name:
            return f"Error: FuzzIntrospector not available"
        cross_refs = self.fi_tool.get_sample_cross_references(
            function_signature)
        if cross_refs:
            result = f"Usage examples for '{function_signature}':\n\n"
            for i, ref in enumerate(cross_refs[:5], 1):
                result += f"Example {i}:\n```c\n{ref}\n```\n\n"
            return result
        return f"No usage examples found for '{function_signature}'"

    def _get_tests_for_functions(self, function_names: List[str]) -> str:
        """Get test code that uses these functions."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        tests = self.fi_tool.get_tests_for_functions(function_names)
        if tests and tests.get('source'):
            result = f"Test examples using functions: {', '.join(function_names)}\n\n"
            for i, snippet in enumerate(tests['source'][:3], 1):
                result += f"Test {i}:\n```c\n{snippet}\n```\n\n"
            return result
        return f"No tests found for functions: {', '.join(function_names)}"

    # =========================================================================
    # Main Execution
    # =========================================================================

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Improve fuzz driver based on coverage analysis recommendations."""
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates)

        benchmark = state["benchmark"]
        self.benchmark = benchmark  # Store for FI tool initialization
        current_code = state.get("fuzz_target_source", "")
        coverage_analysis = state.get("coverage_analysis", {})

        project_name = benchmark.get('project', 'unknown')

        suggestions = coverage_analysis.get(
            "suggestions", "No specific suggestions provided")
        insights = coverage_analysis.get("insights", "")
        improve_required = coverage_analysis.get("improve_required", True)

        if not improve_required:
            logger.info(
                'Coverage analyzer says no improvement required, skipping',
                trial=self.trial)
            return {"session_memory": state.get("session_memory", {})}

        coverage_percent = state.get("coverage_percent", 0.0)
        line_coverage_diff = state.get("line_coverage_diff", 0.0)

        compressed_insights = self._compress_coverage_insights(insights)
        compressed_suggestions = self._compress_coverage_suggestions(
            suggestions)

        # Determine target language from file extension
        target_path = benchmark.get('target_path', '')
        cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
        is_cpp_target = target_path.lower().endswith(cpp_extensions)
        target_language = 'c++' if is_cpp_target else 'c'

        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "improver",
            language=target_language,
            project_name=project_name,
            current_code=current_code,
            coverage_percent=f"{coverage_percent:.2%}",
            line_coverage_diff=f"{line_coverage_diff:.2%}",
            coverage_insights=compressed_insights,
            improvement_suggestions=compressed_suggestions)

        # Add tool usage guidance
        base_prompt += """

<tool_usage_guidance>
**You have access to fuzz_introspector_query tool for querying API information:**

Query types:
- function_implementation: Get source code for a function (target=function_name)
- function_signature: Get full signature for a function (target=function_name)
- cross_references: Get usage examples (target=function_signature)
- tests_for_functions: Get test examples (use function_names list)

Example: fuzz_introspector_query(query_type="function_implementation", target="parse_data")

**When to use:**
- Coverage mentions uncovered branches → query source code to understand the logic
- Want to add new API calls → query signatures and cross_references
- Unsure how to trigger a code path → query usage examples
- Straightforward improvement → no need to query, just improve the code

**Tool calls are optional** - use only when you need more information.
</tool_usage_guidance>
"""

        prompt = build_prompt_with_session_memory(state,
                                                  base_prompt,
                                                  agent_name=self.name)

        # Use tool calling loop - LLM can optionally use tools
        parsed_result, all_responses = self.run_tool_calling_loop(
            initial_prompt=prompt,
            state=state,
            max_rounds=getattr(self.args, 'max_round', 5),
            log_prefix="IMPROVER")

        # Extract session memory updates
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0))
        updated_session_memory = merge_session_memory_updates(
            state, session_memory_updates)

        improved_code = parsed_result.get('improved_code', '')
        if not improved_code:
            # No fallback - keep current code if LLM didn't follow format
            logger.warning(
                'No <fuzz_target> tag found in improver response, keeping current code',
                trial=self.trial)
            improved_code = current_code

        improvement_count = state.get("improvement_attempt_count", 0) + 1
        notes = f"Improver attempt #{improvement_count}"
        add_coverage_attempt(state=state,
                             attempt_type="improver",
                             outcome="driver_rewritten",
                             coverage_percent=coverage_percent,
                             line_coverage_diff=line_coverage_diff,
                             no_improvement_count=state.get(
                                 "no_coverage_improvement_count", 0),
                             iteration=state.get("current_iteration", 0),
                             notes=notes)
        updated_session_memory = state.get("session_memory",
                                           updated_session_memory)

        state_update = {
            "fuzz_target_source": improved_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "run_success": None,
            "build_errors": [],
            "coverage_analysis": None,
            "session_memory": updated_session_memory,
            "no_coverage_improvement_count": 0,
            "improvement_attempt_count": improvement_count,
        }

        logger.info(f'Improvement attempt count: {improvement_count}',
                    trial=self.trial)

        self._langgraph_logger.flush_agent_logs(self.name)

        return state_update

    def _compress_coverage_insights(self, insights: str) -> str:
        """
        Compress coverage insights to reduce prompt tokens while preserving key information.

        Strategy:
        - Extract core issues (max 3 bullet points)
        - Remove verbose explanations and code examples
        - Keep only actionable problems

        Expected reduction: ~80% (from ~4000 chars to ~800 chars)
        """
        if not insights or len(insights) < 100:
            return insights

        import re

        lines = insights.split('\n')
        bullet_points = []
        for line in lines:
            stripped = line.strip()
            if re.match(r'^[\-\*•]\s+\*\*.*?\*\*:', stripped):
                bullet_points.append(stripped)

        if bullet_points:
            compressed = "\n".join(bullet_points[:3])
        else:
            root_cause_match = re.search(
                r'##\s*Root Cause[^\n]*\n(.*?)(?=\n##|\n\n\n|$)', insights,
                re.DOTALL)
            if root_cause_match:
                root_cause_text = root_cause_match.group(1).strip()
                compressed = root_cause_text[:500]
                if len(root_cause_text) > 500:
                    compressed += "..."
            else:
                compressed = insights[:400] + "..." if len(
                    insights) > 400 else insights

        return compressed

    def _compress_coverage_suggestions(self, suggestions: str) -> str:
        """
        Compress coverage suggestions to reduce prompt tokens.

        Strategy:
        - Extract top 3 actionable recommendations
        - Remove code examples (main prompt has templates)
        - Keep only the recommendation text, not the code blocks

        Expected reduction: ~75% (from ~5000 chars to ~1200 chars)
        """
        if not suggestions or len(suggestions) < 100:
            return suggestions

        import re

        no_code = re.sub(r'```[a-z]*\n.*?\n```',
                         '[code example removed - see main template]',
                         suggestions,
                         flags=re.DOTALL)

        recommendations = []
        pattern = r'(\d+)\.\s+\*\*([^:]+)\*\*:?\s*([^\n]*(?:\n(?!\d+\.)[^\n]*)*)'
        matches = re.finditer(pattern, no_code, re.MULTILINE)

        for match in matches:
            num = match.group(1)
            title = match.group(2)
            description = match.group(3).strip()
            if len(description) > 200:
                description = description[:200] + "..."
            recommendations.append(f"{num}. **{title}**: {description}")

        if recommendations:
            compressed = "\n\n".join(recommendations[:3])
        else:
            compressed = no_code[:600] + "..." if len(
                no_code) > 600 else no_code

        return compressed
