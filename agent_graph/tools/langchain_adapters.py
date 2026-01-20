"""
LangChain BaseTool adapters for LangGraph ToolNode integration.

This module provides LangChain-compatible tool wrappers that delegate execution
to injected executor functions. These adapters enable use of LangGraph's ToolNode
for parallel tool execution and standardized error handling.
"""

from typing import Any, Callable, Dict, List, Optional, Type
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


# =============================================================================
# Input schemas for tools
# =============================================================================

class CommandInput(BaseModel):
    """Input schema for command-based tools."""
    command: str = Field(description="The command to execute")


class FunctionNameInput(BaseModel):
    """Input schema for function name based tools."""
    function_name: str = Field(description="The function name to look up")


class FunctionSignatureInput(BaseModel):
    """Input schema for function signature based tools."""
    function_signature: str = Field(description="The full function signature")


class FunctionNamesInput(BaseModel):
    """Input schema for multiple function names."""
    function_names: List[str] = Field(description="List of function names")


class ReturnTypeInput(BaseModel):
    """Input schema for return type based tools."""
    return_type: str = Field(description="The return type to search for")


class EmptyInput(BaseModel):
    """Input schema for tools with no arguments."""
    pass


# =============================================================================
# Tool implementations
# =============================================================================

class BashExecuteTool(BaseTool):
    """
    LangChain tool for executing bash commands in a project container.

    Used by: CoverageAnalyzer, Fixer, CrashFeasibilityAnalyzer
    """

    name: str = "bash_execute"
    description: str = (
        "Run a single bash command inside the project container to read files, "
        "grep for patterns, or inspect build artifacts. Avoid multi-command shells "
        "or long-running processes."
    )
    args_schema: Type[BaseModel] = CommandInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, command: str = "", **kwargs: Any) -> str:
        """Execute the bash command via the injected executor."""
        if not command:
            return "Error: bash_execute requires 'command' argument"
        return self.executor(command)

    async def _arun(self, command: str = "", **kwargs: Any) -> str:
        """Async execution - delegates to sync for now."""
        return self._run(command)


class GDBExecuteTool(BaseTool):
    """
    LangChain tool for executing GDB commands in a debug session.

    Used by: CrashAnalyzer
    """

    name: str = "gdb_execute"
    description: str = (
        "Run a single GDB command inside the already-launched screen session. "
        "Use it whenever you need runtime evidence: reproducing the crash, "
        "capturing a backtrace, switching frames, inspecting locals, or printing memory."
    )
    args_schema: Type[BaseModel] = CommandInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, command: str = "", **kwargs: Any) -> str:
        """Execute the GDB command via the injected executor."""
        if not command:
            return "Error: gdb_execute requires 'command' argument"
        return self.executor(command)

    async def _arun(self, command: str = "", **kwargs: Any) -> str:
        """Async execution - delegates to sync for now."""
        return self._run(command)


class GetFunctionImplementationTool(BaseTool):
    """
    LangChain tool for retrieving function implementation via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_function_implementation"
    description: str = (
        "Retrieve the full source implementation of a function by name. "
        "Returns a C/C++ snippet bounded by ```c fences."
    )
    args_schema: Type[BaseModel] = FunctionNameInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, function_name: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_name:
            return "Error: get_function_implementation requires 'function_name' argument"
        return self.executor(function_name)

    async def _arun(self, function_name: str = "", **kwargs: Any) -> str:
        return self._run(function_name)


class GetFunctionSignatureTool(BaseTool):
    """
    LangChain tool for retrieving function signature via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_function_signature"
    description: str = (
        "Get the canonical signature (return type + name + parameters) for a function. "
        "Use this first when you only know the symbol name."
    )
    args_schema: Type[BaseModel] = FunctionNameInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, function_name: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_name:
            return "Error: get_function_signature requires 'function_name' argument"
        return self.executor(function_name)

    async def _arun(self, function_name: str = "", **kwargs: Any) -> str:
        return self._run(function_name)


class GetSampleCrossReferencesTool(BaseTool):
    """
    LangChain tool for retrieving sample cross references via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_sample_cross_references"
    description: str = (
        "Return representative call sites for a function so you can trace callers. "
        "Best used after you already have the full signature to avoid collisions."
    )
    args_schema: Type[BaseModel] = FunctionSignatureInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, function_signature: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_signature:
            return "Error: get_sample_cross_references requires 'function_signature' argument"
        return self.executor(function_signature)

    async def _arun(self, function_signature: str = "", **kwargs: Any) -> str:
        return self._run(function_signature)


class GetTypeDefinitionsTool(BaseTool):
    """
    LangChain tool for retrieving type definitions via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_type_definitions"
    description: str = (
        "List structs/enums/typedefs present in the project. "
        "Call sparingly - results are truncated to the first 20 definitions."
    )
    args_schema: Type[BaseModel] = EmptyInput
    executor: Callable[[], str] = Field(exclude=True)

    def _run(self, **kwargs: Any) -> str:
        """Execute via the injected executor."""
        return self.executor()

    async def _arun(self, **kwargs: Any) -> str:
        return self._run()


class GetHeadersForFunctionTool(BaseTool):
    """
    LangChain tool for retrieving headers for a function via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_headers_for_function"
    description: str = (
        "Report which headers must be included to call a function. "
        "Useful for confirming whether the crash path could be exercised from public APIs."
    )
    args_schema: Type[BaseModel] = FunctionSignatureInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, function_signature: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_signature:
            return "Error: get_headers_for_function requires 'function_signature' argument"
        return self.executor(function_signature)

    async def _arun(self, function_signature: str = "", **kwargs: Any) -> str:
        return self._run(function_signature)


class GetTestsForFunctionsTool(BaseTool):
    """
    LangChain tool for retrieving tests for functions via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_tests_for_functions"
    description: str = (
        "Provide example test bodies that invoke the given functions. "
        "Use when you need real entry-point usage. Accepts 1-5 function names."
    )
    args_schema: Type[BaseModel] = FunctionNamesInput
    executor: Callable[[List[str]], str] = Field(exclude=True)

    def _run(self, function_names: Optional[List[str]] = None, **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_names:
            return "Error: get_tests_for_functions requires 'function_names' array argument"
        return self.executor(function_names)

    async def _arun(self, function_names: Optional[List[str]] = None, **kwargs: Any) -> str:
        return self._run(function_names)


class GetFunctionDebugTypesTool(BaseTool):
    """
    LangChain tool for retrieving function debug types via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_function_debug_types"
    description: str = (
        "Return DWARF-derived parameter/return type info for a function. "
        "Call after gathering the signature when you need struct field-level detail."
    )
    args_schema: Type[BaseModel] = FunctionSignatureInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, function_signature: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not function_signature:
            return "Error: get_function_debug_types requires 'function_signature' argument"
        return self.executor(function_signature)

    async def _arun(self, function_signature: str = "", **kwargs: Any) -> str:
        return self._run(function_signature)


class GetFunctionsByReturnTypeTool(BaseTool):
    """
    LangChain tool for retrieving functions by return type via FuzzIntrospector.

    Used by: CrashFeasibilityAnalyzer
    """

    name: str = "get_functions_by_return_type"
    description: str = (
        "Enumerate functions that return the supplied type so you can find factories or builders."
    )
    args_schema: Type[BaseModel] = ReturnTypeInput
    executor: Callable[[str], str] = Field(exclude=True)

    def _run(self, return_type: str = "", **kwargs: Any) -> str:
        """Execute via the injected executor."""
        if not return_type:
            return "Error: get_functions_by_return_type requires 'return_type' argument"
        return self.executor(return_type)

    async def _arun(self, return_type: str = "", **kwargs: Any) -> str:
        return self._run(return_type)
