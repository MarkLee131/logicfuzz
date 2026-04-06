"""
Agent tools for LangGraph workflow.

This module provides tools organized by category:

1. Execution Tools (src/tools/execution.py):
   - BashExecuteTool: Execute bash commands in project container
   - GDBExecuteTool: Execute GDB commands in debug session

2. FuzzIntrospector Tools (src/tools/introspector.py):
   - FuzzIntrospectorQueryTool: Unified query tool for all FI operations
   - create_introspector_tool: Factory function for configured tool

3. Context Pre-fetcher (src/tools/context_prefetcher.py):
   - AgentContextSpec: Defines NECESSARY vs OPTIONAL context per agent
   - Three-layer tool access: NECESSARY, OPTIONAL, EXPENSIVE
"""

from src.tools.base import (
    CommandInput,
    EmptyInput,
    ToolCategory,
    ToolAccessLevel,
    create_tool_with_executor,
)

from src.tools.context_prefetcher import (
    AgentContextSpec,
    AGENT_CONTEXT_SPECS,
    get_agent_context_spec,
    get_necessary_context,
    validate_necessary_context,
)

from src.tools.execution import (
    BashExecuteTool,
    GDBExecuteTool,
)

from src.tools.introspector import (
    QueryType,
    FuzzIntrospectorInput,
    FuzzIntrospectorQueryTool,
    create_introspector_tool,
)

__all__ = [
    # Base
    "CommandInput",
    "EmptyInput",
    "ToolCategory",
    "ToolAccessLevel",
    "create_tool_with_executor",
    # Context pre-fetcher
    "AgentContextSpec",
    "AGENT_CONTEXT_SPECS",
    "get_agent_context_spec",
    "get_necessary_context",
    "validate_necessary_context",
    # Execution
    "BashExecuteTool",
    "GDBExecuteTool",
    # Introspector
    "QueryType",
    "FuzzIntrospectorInput",
    "FuzzIntrospectorQueryTool",
    "create_introspector_tool",
]
