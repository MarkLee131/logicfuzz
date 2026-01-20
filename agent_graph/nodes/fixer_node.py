"""
Fixer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphFixer


def fixer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Fix compilation errors in fuzz target.

    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.

    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting Fixer node', trial=trial)

    # Extract config
    configurable = config.get("configurable", {})
    model_name = configurable["model_name"]
    args = configurable["args"]

    # Create agent
    agent = LangGraphFixer(
        model_name=model_name,
        trial=trial,
        args=args
    )

    # Execute agent – let real errors bubble up
    result = agent.execute(state)

    logger.info('Fixer node completed', trial=trial)
    return result
