"""
LangGraphImprover agent for LangGraph workflow.

Improves fuzz drivers based on coverage analysis. The FuzzIntrospector tool
surface was removed; coverage insights / suggestions are pre-fetched into the
prompt by the workflow.
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


class LangGraphImprover(LangGraphAgent, ToolCallingMixin):
    """Improver agent that rewrites a driver from pre-fetched coverage context."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("improver")
        super().__init__(name="improver",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.project_name = None
        self.benchmark = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """No tools - context is pre-fetched into the prompt."""
        return []

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse final LLM response to extract improved fuzz target code."""
        improved_code = parse_tag(content, 'fuzz_target')
        return {'improved_code': improved_code, 'raw_response': content}

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

        # Validate the improved code for hallucinated / internal-API usage,
        # matching the same check Prototyper does. Without this, Improver's
        # rewrites could re-introduce hallucinated symbols that Fixer never
        # sees a warning for. 2026-05 Agent review (cluster C).
        validation_warnings = self._validate_api_usage(
            improved_code, project_name)

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
            "api_validation_warnings": validation_warnings,
        }

        logger.info(f'Improvement attempt count: {improvement_count}',
                    trial=self.trial)

        self._langgraph_logger.flush_agent_logs(self.name)

        return state_update

    def _validate_api_usage(self, code: str, project_name: str) -> str:
        """Validate improved code for hallucinated / internal-API usage.

        Same UnifiedCodeValidator check Prototyper runs. 2026-05 Agent
        review (cluster C): Improver freely rewrites without skeleton
        constraint and without this gate, the Fixer downstream never
        sees the validation warning that Prototyper's flow produces.
        Adding it here keeps validation discipline consistent across
        both LLM-driven code-producing agents.
        """
        try:
            from src.utils.unified_validator import UnifiedCodeValidator, format_validation_report
            validator = UnifiedCodeValidator()
            result = validator.validate(code=code, project_name=project_name)
            if not result.success:
                logger.warning('Improved code contains internal API usage',
                               trial=self.trial)
                return format_validation_report(result)
            logger.info('Improved code passed API validation',
                        trial=self.trial)
            return ""
        except Exception as e:
            logger.warning(
                f'API validation crashed with {type(e).__name__}: {e}',
                trial=self.trial)
            return f"validator_error: {type(e).__name__}: {e}"

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
