"""
CoverageAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphCoverageAnalyzer


def coverage_analyzer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Analyze coverage information to provide insights for improvement.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting CoverageAnalyzer node', trial=trial)
    
    # Extract config
    configurable = config.get("configurable", {})
    model_name = configurable["model_name"]
    args = configurable["args"]

    # Create agent
    agent = LangGraphCoverageAnalyzer(
        model_name=model_name,
        trial=trial,
        args=args
    )
    
    # Execute agent – if coverage analysis itself is broken, fail loudly
    result = agent.execute(state)
    
    logger.info('CoverageAnalyzer node completed', trial=trial)
    return result

