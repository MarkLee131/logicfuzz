"""
FuzzIntrospector query tools for agent interactions.

This module provides a consolidated tool for querying FuzzIntrospector:
- Single unified tool with query_type parameter
- Reduces agent prompt complexity
- Easier to extend with new query types
"""

from typing import Any, Callable, Dict, List, Optional, Type, Union
from enum import Enum
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class QueryType(str, Enum):
    """Types of FuzzIntrospector queries."""
    FUNCTION_IMPL = "function_implementation"      # Get function source code
    FUNCTION_SIG = "function_signature"            # Get function signature
    CROSS_REFS = "cross_references"                # Get usage examples
    TYPE_DEFS = "type_definitions"                 # Get struct/enum definitions
    HEADERS = "headers_for_function"               # Get required headers
    TESTS = "tests_for_functions"                  # Get test examples
    DEBUG_TYPES = "debug_types"                    # Get DWARF type info
    FUNCTIONS_BY_TYPE = "functions_by_return_type" # Find functions by return type


class FuzzIntrospectorInput(BaseModel):
    """Input schema for FuzzIntrospector queries."""
    query_type: QueryType = Field(
        description="Type of query: function_implementation, function_signature, "
                    "cross_references, type_definitions, headers_for_function, "
                    "tests_for_functions, debug_types, or functions_by_return_type"
    )
    target: str = Field(
        default="",
        description="Query target: function name, function signature, or return type "
                    "(depending on query_type). Leave empty for type_definitions."
    )
    function_names: List[str] = Field(
        default=[],
        description="List of function names (only for tests_for_functions query)"
    )


class FuzzIntrospectorQueryTool(BaseTool):
    """
    Unified tool for querying FuzzIntrospector API.

    Consolidates 8 separate query tools into one with query_type parameter.
    This reduces prompt complexity and makes it easier to add new query types.

    Used by: Prototyper, Improver, CrashFeasibilityAnalyzer
    """

    name: str = "fuzz_introspector_query"
    description: str = """Query FuzzIntrospector for project information.

Query types:
- function_implementation: Get source code for a function (target=function_name)
- function_signature: Get full signature for a function (target=function_name)
- cross_references: Get usage examples (target=function_signature)
- type_definitions: Get struct/enum definitions (no target needed)
- headers_for_function: Get required headers (target=function_signature)
- tests_for_functions: Get test examples (use function_names list)
- debug_types: Get DWARF type info (target=function_signature)
- functions_by_return_type: Find functions returning a type (target=type_name)
"""
    args_schema: Type[FuzzIntrospectorInput] = FuzzIntrospectorInput

    # Executor functions injected at construction time
    get_implementation: Callable[[str], str] = Field(exclude=True)
    get_signature: Callable[[str], str] = Field(exclude=True)
    get_cross_refs: Callable[[str], str] = Field(exclude=True)
    get_type_defs: Callable[[], str] = Field(exclude=True)
    get_headers: Callable[[str], str] = Field(exclude=True)
    get_tests: Callable[[List[str]], str] = Field(exclude=True)
    get_debug_types: Callable[[str], str] = Field(exclude=True)
    get_by_return_type: Callable[[str], str] = Field(exclude=True)

    def _run(
        self,
        query_type: Union[QueryType, str] = QueryType.FUNCTION_IMPL,
        target: str = "",
        function_names: Optional[List[str]] = None,
        **kwargs: Any
    ) -> str:
        """Execute the appropriate query based on query_type.

        The executor functions should return formatted strings ready for display.
        """
        # Convert string to enum if needed
        if isinstance(query_type, str):
            try:
                query_type = QueryType(query_type)
            except ValueError:
                return f"Error: Unknown query_type '{query_type}'. Valid types: {[q.value for q in QueryType]}"

        try:
            if query_type == QueryType.FUNCTION_IMPL:
                if not target:
                    return "Error: function_implementation requires 'target' (function name)"
                return self.get_implementation(target)

            elif query_type == QueryType.FUNCTION_SIG:
                if not target:
                    return "Error: function_signature requires 'target' (function name)"
                return self.get_signature(target)

            elif query_type == QueryType.CROSS_REFS:
                if not target:
                    return "Error: cross_references requires 'target' (function signature)"
                return self.get_cross_refs(target)

            elif query_type == QueryType.TYPE_DEFS:
                return self.get_type_defs()

            elif query_type == QueryType.HEADERS:
                if not target:
                    return "Error: headers_for_function requires 'target' (function signature)"
                return self.get_headers(target)

            elif query_type == QueryType.TESTS:
                names = function_names or []
                if not names:
                    return "Error: tests_for_functions requires 'function_names' list"
                return self.get_tests(names)

            elif query_type == QueryType.DEBUG_TYPES:
                if not target:
                    return "Error: debug_types requires 'target' (function signature)"
                return self.get_debug_types(target)

            elif query_type == QueryType.FUNCTIONS_BY_TYPE:
                if not target:
                    return "Error: functions_by_return_type requires 'target' (type name)"
                return self.get_by_return_type(target)

            else:
                return f"Error: Unhandled query_type '{query_type}'"

        except AttributeError as e:
            # Handle case where executor is not set
            return f"Error: Executor not configured for {query_type.value}: {str(e)}"
        except Exception as e:
            return f"Error executing {query_type.value} query: {str(e)}"

    async def _arun(self, **kwargs: Any) -> str:
        return self._run(**kwargs)


# =============================================================================
# Factory function for creating configured tool
# =============================================================================

def create_introspector_tool(
    fi_tool,  # FuzzIntrospectorTool instance
    project_name: str
) -> FuzzIntrospectorQueryTool:
    """
    Create a configured FuzzIntrospectorQueryTool.

    Args:
        fi_tool: FuzzIntrospectorTool instance
        project_name: Name of the project being analyzed

    Returns:
        Configured FuzzIntrospectorQueryTool
    """

    def get_impl(func_name: str) -> str:
        impl = fi_tool.get_function_implementation(project_name, func_name)
        if impl:
            return f"Source code for '{func_name}':\n```c\n{impl}\n```"
        return f"Error: Could not find source for '{func_name}'"

    def get_sig(func_name: str) -> str:
        sig = fi_tool.get_function_signature(func_name)
        if sig:
            return f"Function signature: {sig}"
        return f"Error: Could not find signature for '{func_name}'"

    def get_xrefs(func_sig: str) -> str:
        refs = fi_tool.get_sample_cross_references(func_sig)
        if refs:
            result = f"Usage examples for '{func_sig}':\n\n"
            for i, ref in enumerate(refs[:5], 1):
                result += f"Example {i}:\n```c\n{ref}\n```\n\n"
            return result
        return f"No usage examples found for '{func_sig}'"

    def get_types() -> str:
        types = fi_tool.get_type_definitions()
        if types:
            return f"Type definitions (first 20):\n{types}"
        return "No type definitions found"

    def get_hdrs(func_sig: str) -> str:
        headers = fi_tool.get_headers_for_function(func_sig)
        if headers:
            return f"Headers for '{func_sig}':\n{headers}"
        return f"No header info for '{func_sig}'"

    def get_tsts(func_names: List[str]) -> str:
        tests = fi_tool.get_tests_for_functions(func_names)
        if tests and tests.get('source'):
            result = f"Test examples for: {', '.join(func_names)}\n\n"
            for i, snippet in enumerate(tests['source'][:3], 1):
                result += f"Test {i}:\n```c\n{snippet}\n```\n\n"
            return result
        return f"No tests found for: {', '.join(func_names)}"

    def get_dbg(func_sig: str) -> str:
        debug = fi_tool.get_function_debug_types(func_sig)
        if debug:
            return f"Debug types for '{func_sig}':\n{debug}"
        return f"No debug types for '{func_sig}'"

    def get_by_ret(ret_type: str) -> str:
        funcs = fi_tool.get_functions_by_return_type(ret_type)
        if funcs:
            return f"Functions returning '{ret_type}':\n{funcs}"
        return f"No functions found returning '{ret_type}'"

    return FuzzIntrospectorQueryTool(
        get_implementation=get_impl,
        get_signature=get_sig,
        get_cross_refs=get_xrefs,
        get_type_defs=get_types,
        get_headers=get_hdrs,
        get_tests=get_tsts,
        get_debug_types=get_dbg,
        get_by_return_type=get_by_ret,
    )
