"""
Base tool classes and utilities for agent tools.

This module provides the foundation for all agent tools with:
- Common input schemas
- Tool registration utilities
- Executor injection patterns
- Three-layer tool access strategy

Three-Layer Tool Access Strategy:
=================================
1. NECESSARY: Pre-fetch into prompt (always needed info)
   - Context that is required for the task regardless of LLM decisions
   - Examples: API sequence, error triage, existing driver patterns
   - Implementation: Loaded in execute() and included in prompt

2. OPTIONAL: Keep as tools for on-demand calling
   - Context that may be needed depending on task complexity
   - LLM decides when to query based on initial information
   - Examples: Function implementations, cross-references, additional file reads
   - Implementation: LangChain tools with executor injection

3. EXPENSIVE: Require confirmation or special handling
   - Operations that are costly (time, resources, API calls)
   - May require user confirmation or batching
   - Examples: GDB session setup, long-running bash commands
   - Implementation: Separate tool with explicit warnings in description
"""

from typing import Any, Callable, List, Optional, Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
from enum import Enum


# =============================================================================
# Common Input Schemas
# =============================================================================

class CommandInput(BaseModel):
    """Input schema for command-based tools (Bash, GDB)."""
    command: str = Field(description="The command to execute")


class EmptyInput(BaseModel):
    """Input schema for tools with no arguments."""
    pass


# =============================================================================
# Tool Access Levels
# =============================================================================

class ToolAccessLevel(Enum):
    """Access levels for agent tools based on cost and necessity.

    NECESSARY: Always pre-fetch into prompt (no tool call needed)
    OPTIONAL: Available as tool, LLM decides when to use
    EXPENSIVE: Available as tool, but costly - use sparingly
    """
    NECESSARY = "necessary"   # Pre-fetch into prompt
    OPTIONAL = "optional"     # Available for on-demand calling
    EXPENSIVE = "expensive"   # Costly operation, use sparingly


# =============================================================================
# Tool Registration Utilities
# =============================================================================

class ToolCategory(Enum):
    """Categories of agent tools."""
    EXECUTION = "execution"        # Bash, GDB
    INTROSPECTOR = "introspector"  # FuzzIntrospector queries


def create_tool_with_executor(
    tool_class: Type[BaseTool],
    executor: Callable,
    **kwargs
) -> BaseTool:
    """
    Create a tool instance with an injected executor.

    Args:
        tool_class: The LangChain tool class
        executor: The function to execute when tool is called
        **kwargs: Additional arguments for tool initialization

    Returns:
        Configured tool instance
    """
    return tool_class(executor=executor, **kwargs)
