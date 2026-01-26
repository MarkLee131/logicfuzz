"""
LangGraphImprover agent for LangGraph workflow.
"""
from typing import Any, Dict
import argparse

import logger
from src.workflow.state import FuzzingWorkflowState, add_coverage_attempt
from src.agents.base import LangGraphAgent
from src.agents.utils import parse_tag
from src.utils.prompt_loader import get_prompt_manager


class LangGraphImprover(LangGraphAgent):
    """
    Improver agent for LangGraph.

    This agent is responsible for improving fuzz driver quality based on
    coverage analysis recommendations. Unlike fixer (which fixes compilation errors),
    improver rewrites the driver to increase code coverage.
    """

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("improver")
        super().__init__(
            name="improver",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Improve fuzz driver based on coverage analysis recommendations."""
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        coverage_analysis = state.get("coverage_analysis", {})

        project_name = benchmark.get('project', 'unknown')

        suggestions = coverage_analysis.get("suggestions", "No specific suggestions provided")
        insights = coverage_analysis.get("insights", "")
        improve_required = coverage_analysis.get("improve_required", True)

        if not improve_required:
            logger.info('Coverage analyzer says no improvement required, skipping', trial=self.trial)
            return {"session_memory": state.get("session_memory", {})}

        coverage_percent = state.get("coverage_percent", 0.0)
        line_coverage_diff = state.get("line_coverage_diff", 0.0)

        compressed_insights = self._compress_coverage_insights(insights)
        compressed_suggestions = self._compress_coverage_suggestions(suggestions)

        # Determine target language from file extension (same logic as prototyper)
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
            improvement_suggestions=compressed_suggestions
        )

        prompt = build_prompt_with_session_memory(state, base_prompt, agent_name=self.name)
        response = self.chat_llm(state, prompt)

        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)

        improved_code = parse_tag(response, 'fuzz_target')
        if not improved_code:
            # No fallback - keep current code if LLM didn't follow format
            logger.warning('No <fuzz_target> tag found in improver response, keeping current code', trial=self.trial)
            improved_code = current_code

        try:
            improvement_count = state.get("improvement_attempt_count", 0) + 1
            notes = f"Improver attempt #{improvement_count}"
            add_coverage_attempt(
                state=state,
                attempt_type="improver",
                outcome="driver_rewritten",
                coverage_percent=coverage_percent,
                line_coverage_diff=line_coverage_diff,
                no_improvement_count=state.get("no_coverage_improvement_count", 0),
                iteration=state.get("current_iteration", 0),
                notes=notes
            )
            updated_session_memory = state.get("session_memory", updated_session_memory)
        except Exception as e:
            logger.warning(f"Failed to record improver coverage attempt in session_memory: {e}", trial=self.trial)

        state_update = {
            "fuzz_target_source": improved_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "run_success": None,
            "build_errors": [],
            "coverage_analysis": None,
            "session_memory": updated_session_memory,
            "no_coverage_improvement_count": 0
        }

        improvement_count = state.get("improvement_attempt_count", 0)
        state_update["improvement_attempt_count"] = improvement_count + 1
        logger.info(f'Improvement attempt count: {improvement_count + 1}', trial=self.trial)

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
            root_cause_match = re.search(r'##\s*Root Cause[^\n]*\n(.*?)(?=\n##|\n\n\n|$)', insights, re.DOTALL)
            if root_cause_match:
                root_cause_text = root_cause_match.group(1).strip()
                compressed = root_cause_text[:500]
                if len(root_cause_text) > 500:
                    compressed += "..."
            else:
                compressed = insights[:400] + "..." if len(insights) > 400 else insights

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

        no_code = re.sub(r'```[a-z]*\n.*?\n```', '[code example removed - see main template]',
                        suggestions, flags=re.DOTALL)

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
            compressed = no_code[:600] + "..." if len(no_code) > 600 else no_code

        return compressed
    

