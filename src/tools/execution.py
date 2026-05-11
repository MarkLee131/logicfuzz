"""
Execution tools for agent interactions.

This module provides tools for executing commands in containers:
- BashExecuteTool: Execute bash commands in project container
- GDBExecuteTool: Execute GDB commands in debug session

It also exposes ``format_bash_result``, the shared helper that every
agent's ``_execute_bash`` delegates to. Prior to the 2026-05 execution
review there were four near-duplicate implementations of this format
spread across Fixer / CoverageAnalyzer / CrashAnalyzer /
CrashFeasibilityAnalyzer, with three different truncation behaviours
(silent slice, joined-message cap, per-stream cap with indicator).
The helper standardises on per-stream cap + indicator — every stream
that exceeds the cap surfaces ``... (truncated N chars)`` so the LLM
never silently sees clipped output as if it were complete.
"""

from typing import Any, Callable, Type
from langchain_core.tools import BaseTool
from pydantic import Field

from src.tools.base import CommandInput


# Per-stream output cap (chars). Matches the 8KB CLAUDE.md target and
# the joined-message cap in ``LangGraphAgent.truncate_tool_output`` /
# ``ToolCallingMixin._truncate`` (aligned in the 2026-05 Agent review,
# cluster A). Stdout and stderr each get their own budget, so a long
# stdout can no longer eat the budget before stderr is rendered — the
# previous joined-cap behaviour in CrashAnalyzer regularly lost the
# stderr tail that crash triage cares about.
_DEFAULT_PER_STREAM_CAP = 8000


def format_bash_result(command: str,
                       result: Any,
                       max_per_stream: int = _DEFAULT_PER_STREAM_CAP) -> str:
    """Render a CompletedProcess-like result as the LLM-facing tool reply.

    Shape:

        $ <command>
        exit=<returncode>
        <stdout, truncated per-stream with explicit indicator>
        STDERR: <stderr, same>

    The helper duck-types ``result`` — anything exposing ``stdout`` /
    ``stderr`` / ``returncode`` works. Missing attributes degrade to
    empty / ``?`` rather than raising, mirroring the defensive shape
    that CrashFeasibilityAnalyzer carried before consolidation
    (containerised execution always returns a real CompletedProcess,
    but the fallback covers test doubles and future executor swaps).
    """
    stdout = (getattr(result, 'stdout', '') or '').strip()
    stderr = (getattr(result, 'stderr', '') or '').strip()

    if len(stdout) > max_per_stream:
        stdout = (stdout[:max_per_stream]
                  + f'\n... (truncated {len(stdout) - max_per_stream} chars)')
    if len(stderr) > max_per_stream:
        stderr = (stderr[:max_per_stream]
                  + f'\n... (truncated {len(stderr) - max_per_stream} chars)')

    parts = [f"$ {command}", f"exit={getattr(result, 'returncode', '?')}"]
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(f"STDERR: {stderr}")
    return "\n".join(parts)


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
        # TODO: sync fall-through. None of our ReAct loops are async, so
        # this only matters if someone wires the tool into an async
        # LangGraph runtime — at which point this should dispatch the
        # underlying executor through asyncio.to_thread to avoid
        # serialising parallel tool calls.
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
        # TODO: see BashExecuteTool._arun — same caveat.
        return self._run(command)
