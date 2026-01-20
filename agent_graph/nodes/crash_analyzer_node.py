"""
CrashAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphCrashAnalyzer


def crash_analyzer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Analyze crash information.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting CrashAnalyzer node', trial=trial)
    
    # Extract config
    configurable = config.get("configurable", {})
    model_name = configurable["model_name"]
    args = configurable["args"]

    # Create agent
    agent = LangGraphCrashAnalyzer(
        model_name=model_name,
        trial=trial,
        args=args
    )
    
    # Execute agent – unexpected failures should stop the workflow
    result = agent.execute(state)
    
    logger.info('CrashAnalyzer node completed', trial=trial)
    return result
