"""
Execution tools for agent interactions.

This module provides tools for executing commands in containers:
- BashExecuteTool: Execute bash commands in project container
- GDBExecuteTool: Execute GDB commands in debug session
"""

from typing import Any, Callable, Type
from langchain_core.tools import BaseTool
from pydantic import Field

from src.tools.base import CommandInput


class BashExecuteTool(BaseTool):
    """
    Execute bash commands in a project container.

    Used by: Fixer, CoverageAnalyzer, CrashAnalyzer, CrashFeasibilityAnalyzer
    """

    name: str = "bash_execute"
    description: str = (
        "Run a bash command inside the project container. "
        "Use for reading files, grepping patterns, or inspecting build artifacts. "
        "Avoid multi-command shells or long-running processes."
    )
    args_schema: Type[CommandInput] = CommandInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, command: str = "", **kwargs: Any) -> str:
        if not command:
            return "Error: bash_execute requires 'command' argument"
        return self.executor(command)

    async def _arun(self, command: str = "", **kwargs: Any) -> str:
        return self._run(command)


class GDBExecuteTool(BaseTool):
    """
    Execute GDB commands in a debug session.

    Used by: CrashAnalyzer
    """

    name: str = "gdb_execute"
    description: str = (
        "Run a GDB command in the debug session. "
        "Use for reproducing crashes, capturing backtraces, switching frames, "
        "inspecting locals, or printing memory."
    )
    args_schema: Type[CommandInput] = CommandInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, command: str = "", **kwargs: Any) -> str:
        if not command:
            return "Error: gdb_execute requires 'command' argument"
        return self.executor(command)

    async def _arun(self, command: str = "", **kwargs: Any) -> str:
        return self._run(command)
