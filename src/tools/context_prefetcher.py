"""
Context pre-fetcher for agent prompts.

This module defines what context is NECESSARY (always pre-fetched) vs OPTIONAL
(available as tools) for each agent in the workflow.

Three-Layer Tool Access Strategy:
=================================
1. NECESSARY: Pre-fetched into prompt (saves tool call overhead)
2. OPTIONAL: Available as LangChain tools (LLM decides when to use)
3. EXPENSIVE: Available but with warnings (GDB, long-running commands)

Agent Context Requirements:
===========================
Each agent has different context needs based on its task:

Prototyper:
  - NECESSARY: API sequence, function signatures, existing driver patterns
  - OPTIONAL: Function implementations, cross-references, test examples
  - EXPENSIVE: None

Fixer:
  - NECESSARY: Current code, build errors, error triage, fix guidance
  - OPTIONAL: Bash (file exploration, header search)
  - EXPENSIVE: None

CoverageAnalyzer:
  - NECESSARY: Fuzz target, fuzzing log, function requirements
  - OPTIONAL: Bash (coverage inspection)
  - EXPENSIVE: None

Improver:
  - NECESSARY: Current code, coverage insights, improvement suggestions
  - OPTIONAL: FuzzIntrospector queries (function source, examples)
  - EXPENSIVE: None

CrashAnalyzer:
  - NECESSARY: Crash info, stack trace, fuzz target code
  - OPTIONAL: Bash (file inspection)
  - EXPENSIVE: GDB (debug session)

CrashFeasibilityAnalyzer:
  - NECESSARY: Crash analysis, fuzz target, function requirements
  - OPTIONAL: Bash, FuzzIntrospector queries
  - EXPENSIVE: None
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum

from src.tools.base import ToolAccessLevel


@dataclass
class AgentContextSpec:
    """Specification of context requirements for an agent.

    Defines what information is NECESSARY (pre-fetched) vs OPTIONAL (tools).
    """
    agent_name: str
    necessary_context: List[str]  # Keys from state that are always needed
    optional_tools: List[str]     # Tool names available for on-demand use
    expensive_tools: List[str] = field(default_factory=list)  # Costly tools


# Context specifications for each agent
AGENT_CONTEXT_SPECS = {
    "prototyper": AgentContextSpec(
        agent_name="prototyper",
        necessary_context=[
            "api_sequence",           # Target API sequence to implement
            "function_signatures",    # Signatures of APIs in sequence
            "existing_driver_knowledge",  # Patterns from working fuzzers
            "header_information",     # Required includes
            "language",               # c or c++
        ],
        optional_tools=[
            "fuzz_introspector_query",  # For implementation details
        ],
        expensive_tools=[],
    ),

    "fixer": AgentContextSpec(
        agent_name="fixer",
        necessary_context=[
            "fuzz_target_source",     # Current code to fix
            "build_errors",           # Compilation errors
            "error_triage",           # Categorized errors with fix guidance
            "existing_driver_knowledge",  # Reference patterns
        ],
        optional_tools=[
            "bash_execute",           # For exploring headers, build artifacts
        ],
        expensive_tools=[],
    ),

    "coverage_analyzer": AgentContextSpec(
        agent_name="coverage_analyzer",
        necessary_context=[
            "fuzz_target_source",     # Current driver code
            "run_log",                # Fuzzing log with coverage info
            "function_requirements",   # Expected API coverage
        ],
        optional_tools=[
            "bash_execute",           # For detailed coverage inspection
        ],
        expensive_tools=[],
    ),

    "improver": AgentContextSpec(
        agent_name="improver",
        necessary_context=[
            "fuzz_target_source",     # Current code to improve
            "coverage_analysis",      # Insights and suggestions
            "coverage_percent",       # Current coverage metric
            "line_coverage_diff",     # Coverage change
        ],
        optional_tools=[
            "fuzz_introspector_query",  # For understanding uncovered code
        ],
        expensive_tools=[],
    ),

    "crash_analyzer": AgentContextSpec(
        agent_name="crash_analyzer",
        necessary_context=[
            "crash_info",             # Error type, stack trace
            "fuzz_target_source",     # Driver code that crashed
        ],
        optional_tools=[
            "bash_execute",           # For file inspection
        ],
        expensive_tools=[
            "gdb_execute",            # Debug session (resource intensive)
        ],
    ),

    "crash_feasibility_analyzer": AgentContextSpec(
        agent_name="crash_feasibility_analyzer",
        necessary_context=[
            "crash_analysis",         # Previous crash analysis result
            "fuzz_target_source",     # Driver code
            "function_requirements",  # Entry point info
        ],
        optional_tools=[
            "bash_execute",
            "fuzz_introspector_query",
        ],
        expensive_tools=[],
    ),
}


def get_agent_context_spec(agent_name: str) -> Optional[AgentContextSpec]:
    """Get context specification for an agent."""
    return AGENT_CONTEXT_SPECS.get(agent_name)


def get_necessary_context(agent_name: str, state: Dict[str, Any]) -> Dict[str, Any]:
    """Extract NECESSARY context from state for an agent.

    Args:
        agent_name: Name of the agent
        state: Workflow state dictionary

    Returns:
        Dictionary containing only the necessary context keys
    """
    spec = AGENT_CONTEXT_SPECS.get(agent_name)
    if not spec:
        return {}

    context = {}
    for key in spec.necessary_context:
        if key in state:
            context[key] = state[key]
        # Also check nested locations
        elif key in state.get("context", {}):
            context[key] = state["context"][key]
        elif key in state.get("function_analysis", {}):
            context[key] = state["function_analysis"][key]
    return context


def validate_necessary_context(agent_name: str, state: Dict[str, Any]) -> List[str]:
    """Validate that all NECESSARY context is available.

    Args:
        agent_name: Name of the agent
        state: Workflow state dictionary

    Returns:
        List of missing context keys (empty if all present)
    """
    spec = AGENT_CONTEXT_SPECS.get(agent_name)
    if not spec:
        return []

    missing = []
    for key in spec.necessary_context:
        found = (
            key in state or
            key in state.get("context", {}) or
            key in state.get("function_analysis", {})
        )
        if not found:
            missing.append(key)
    return missing
