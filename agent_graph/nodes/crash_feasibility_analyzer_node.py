"""
CrashFeasibilityAnalyzer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphCrashFeasibilityAnalyzer


def crash_feasibility_analyzer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Analyze crash feasibility in the context of the project.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting CrashFeasibilityAnalyzer node', trial=trial)
    
    # Extract config
    configurable = config.get("configurable", {})
    llm = configurable["llm"]
    args = configurable["args"]
    
    # Create agent
    agent = LangGraphCrashFeasibilityAnalyzer(
        llm=llm,
        trial=trial,
        args=args
    )
    
    # Execute agent – if feasibility analysis is broken, fail fast
    result = agent.execute(state)
    
    logger.info('CrashFeasibilityAnalyzer node completed', trial=trial)
    return result

