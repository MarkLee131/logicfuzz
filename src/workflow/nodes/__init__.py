"""
LangGraph nodes for the fuzzing workflow.

This module provides LangGraph-compatible node functions using agent-specific messages.
"""

# LLM-based nodes with agent-specific messages
from src.workflow.nodes.prototyper import prototyper_node
from src.workflow.nodes.fixer import fixer_node
from src.workflow.nodes.improver import improver_node
from src.workflow.nodes.crash_analyzer import crash_analyzer_node
from src.workflow.nodes.coverage_analyzer import coverage_analyzer_node
from src.workflow.nodes.crash_feasibility_analyzer import crash_feasibility_analyzer_node
from src.workflow.nodes.baseline_diff_analyzer import baseline_diff_analyzer_node

# Build and execution nodes don't use LLM, keep as is
from src.workflow.nodes.execution import execution_node, build_node

# Supervisor doesn't use LLM, keep as is
from src.workflow.nodes.supervisor import supervisor_node, route_condition

__all__ = [
    'prototyper_node',
    'fixer_node',
    'improver_node',
    'crash_analyzer_node',
    'coverage_analyzer_node',
    'crash_feasibility_analyzer_node',
    'baseline_diff_analyzer_node',
    'execution_node',
    'build_node',
    'supervisor_node',
    'route_condition',
]
