"""
Enhancer node for LangGraph workflow.

Uses agent-specific messages for clean context management.
"""
from typing import Dict, Any

from langchain_core.runnables import RunnableConfig
import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents import LangGraphEnhancer


def enhancer_node(state: FuzzingWorkflowState, config: RunnableConfig) -> Dict[str, Any]:
    """
    Fix compilation errors in fuzz target.
    
    Args:
        state: Current workflow state
        config: Configuration containing LLM, args, etc.
    
    Returns:
        State updates
    """
    trial = state["trial"]
    logger.info('Starting Enhancer node', trial=trial)
    
    # Extract config
    configurable = config.get("configurable", {})
    llm = configurable["llm"]
    args = configurable["args"]
    
    # Create agent
    agent = LangGraphEnhancer(
        llm=llm,
        trial=trial,
        args=args
    )
    
    # Execute agent – let real errors bubble up
    result = agent.execute(state)
    
    logger.info('Enhancer node completed', trial=trial)
    return result
