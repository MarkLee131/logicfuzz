"""BaselineDiffAnalyzer node for LangGraph workflow (§10B v2)."""
from typing import Any, Dict

from langchain_core.runnables import RunnableConfig

import logger
from src.workflow.state import FuzzingWorkflowState
from src.agents import LangGraphBaselineDiffAnalyzer


def baseline_diff_analyzer_node(
        state: FuzzingWorkflowState,
        config: RunnableConfig) -> Dict[str, Any]:
    """Compare current driver vs baseline and write ``baseline_diff_analysis``.

    The supervisor routes here when ``baseline_regression_alert`` is
    set AND the project ships an OSS-Fuzz baseline driver AND we
    haven't yet exhausted the diff-retry budget. The node's output
    is then consumed by the Prototyper on the immediately following
    re-prototype pass.
    """
    trial = state["trial"]
    logger.info("Starting BaselineDiffAnalyzer node (§10B v2)", trial=trial)

    configurable = config.get("configurable", {})
    agent = LangGraphBaselineDiffAnalyzer(
        model_name=configurable["model_name"],
        trial=trial,
        args=configurable["args"],
    )
    result = agent.execute(state)
    logger.info("BaselineDiffAnalyzer node completed", trial=trial)
    return result
