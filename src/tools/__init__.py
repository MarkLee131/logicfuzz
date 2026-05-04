"""Agent tools for the LangGraph workflow.

Modules:
- src/tools/execution.py: BashExecuteTool, GDBExecuteTool
- src/tools/context_prefetcher.py: AgentContextSpec + helpers

The FuzzIntrospector tool surface was removed; agents now consume pre-fetched
context only (see context_prefetcher.AGENT_CONTEXT_SPECS).
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

__all__ = [
    "CommandInput",
    "EmptyInput",
    "ToolCategory",
    "ToolAccessLevel",
    "create_tool_with_executor",
    "AgentContextSpec",
    "AGENT_CONTEXT_SPECS",
    "get_agent_context_spec",
    "get_necessary_context",
    "validate_necessary_context",
    "BashExecuteTool",
    "GDBExecuteTool",
]
