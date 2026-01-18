"""
Memory management utilities for LangGraph agents.

This module provides checkpointing for LangGraph workflow state persistence.

NOTE: Agent message history functions (get_agent_messages, add_agent_message,
trim_messages_by_tokens) were removed as part of memory optimization.
All context now flows through session_memory instead of conversation history.
"""
from langgraph.checkpoint.memory import MemorySaver


def create_memory_checkpointer() -> MemorySaver:
    """
    Create a LangGraph memory checkpointer for state persistence.

    Returns:
        MemorySaver instance for checkpointing
    """
    return MemorySaver()
