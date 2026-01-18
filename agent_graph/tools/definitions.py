"""
Shared tool definitions for OpenAI Function Calling.

This module centralizes all tool schemas used by LangGraph agents.
Tool execution logic remains in individual agents since it depends on agent-specific context.
"""

from typing import List, Dict, Any


# =============================================================================
# Bash Execute Tool - Used by CrashAnalyzer, CoverageAnalyzer, CrashFeasibilityAnalyzer
# =============================================================================

BASH_EXECUTE_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "bash_execute",
        "description": (
            "Run a single bash command inside the project container to read files, "
            "grep for patterns, or inspect build artifacts. Avoid multi-command shells "
            "or long-running processes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Single bash command (<= 400 chars). Include absolute paths when possible. "
                        "Examples: 'grep -Rn \"TargetFunc\" /src', 'cat /src/foo/api.h'. "
                        "The response echoes the command, return code, stdout, stderr."
                    ),
                    "minLength": 1,
                    "maxLength": 400
                }
            },
            "required": ["command"],
            "additionalProperties": False
        }
    }
}


# =============================================================================
# GDB Execute Tool - Used by CrashAnalyzer only
# =============================================================================

GDB_EXECUTE_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "gdb_execute",
        "description": (
            "Run a single GDB command inside the already-launched screen session. "
            "Use it whenever you need runtime evidence: reproducing the crash, "
            "capturing a backtrace, switching frames, inspecting locals, or printing memory. "
            "Do not use it for file I/O or shell operations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Exact GDB command (<= 200 chars). Typical calls: "
                        "'run -runs=1 {artifact}' to rerun the crash, "
                        "'bt' to dump stack, "
                        "'frame 4' and 'info locals', "
                        "'x/16gx $rsp', "
                        "'print *(foo*)bar'. "
                        "Response includes '(gdb) <command>' followed by stdout/stderr blocks."
                    ),
                    "minLength": 1,
                    "maxLength": 200,
                    "examples": [
                        "run -runs=1 /tmp/crash-42",
                        "bt",
                        "frame 3",
                        "info locals",
                        "x/32bx $rsp"
                    ]
                }
            },
            "required": ["command"],
            "additionalProperties": False
        }
    }
}


# =============================================================================
# FuzzIntrospector API Tools - Used by CrashFeasibilityAnalyzer
# =============================================================================

FI_GET_FUNCTION_IMPLEMENTATION_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_function_implementation",
        "description": (
            "Retrieve the full source implementation of a function by name. "
            "Call this after you know the exact function identifier. "
            "Returns a C/C++ snippet bounded by ```c fences."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Exact function symbol (case-sensitive), e.g., 'sam_hrecs_remove_ref_altnames'"
                }
            },
            "required": ["function_name"],
            "additionalProperties": False
        }
    }
}

FI_GET_FUNCTION_SIGNATURE_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_function_signature",
        "description": (
            "Get the canonical signature (return type + name + parameters) for a function. "
            "Use this first when you only know the symbol name."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Function symbol to resolve (e.g., 'archive_read_new')"
                }
            },
            "required": ["function_name"],
            "additionalProperties": False
        }
    }
}

FI_GET_SAMPLE_CROSS_REFERENCES_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_sample_cross_references",
        "description": (
            "Return representative call sites for a function so you can trace callers. "
            "Best used after you already have the full signature to avoid collisions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_signature": {
                    "type": "string",
                    "description": "Full signature from get_function_signature (e.g., 'void foo(int x)')"
                }
            },
            "required": ["function_signature"],
            "additionalProperties": False
        }
    }
}

FI_GET_TYPE_DEFINITIONS_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_type_definitions",
        "description": (
            "List structs/enums/typedefs present in the project. "
            "Call sparingly - results are truncated to the first 20 definitions."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False
        }
    }
}

FI_GET_HEADERS_FOR_FUNCTION_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_headers_for_function",
        "description": (
            "Report which headers must be included to call a function. "
            "Useful for confirming whether the crash path could be exercised from public APIs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_signature": {
                    "type": "string",
                    "description": "Full signature text for the target function"
                }
            },
            "required": ["function_signature"],
            "additionalProperties": False
        }
    }
}

FI_GET_TESTS_FOR_FUNCTIONS_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_tests_for_functions",
        "description": (
            "Provide example test bodies that invoke the given functions. "
            "Use when you need real entry-point usage. Accepts 1-5 function names."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 5,
                    "description": "List of symbols to search in tests (e.g., ['archive_read_new'])"
                }
            },
            "required": ["function_names"],
            "additionalProperties": False
        }
    }
}

FI_GET_FUNCTION_DEBUG_TYPES_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_function_debug_types",
        "description": (
            "Return DWARF-derived parameter/return type info for a function. "
            "Call after gathering the signature when you need struct field-level detail."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "function_signature": {
                    "type": "string",
                    "description": "Full signature text, identical to what the debug DB stores"
                }
            },
            "required": ["function_signature"],
            "additionalProperties": False
        }
    }
}

FI_GET_FUNCTIONS_BY_RETURN_TYPE_TOOL: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "get_functions_by_return_type",
        "description": (
            "Enumerate functions that return the supplied type so you can find factories or builders."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "return_type": {
                    "type": "string",
                    "description": "Type string to search for (e.g., 'sam_hrecs_t *', 'int')"
                }
            },
            "required": ["return_type"],
            "additionalProperties": False
        }
    }
}


# =============================================================================
# Convenience Functions
# =============================================================================

def get_bash_tool() -> Dict[str, Any]:
    """Get bash_execute tool definition."""
    return BASH_EXECUTE_TOOL.copy()


def get_gdb_tool() -> Dict[str, Any]:
    """Get gdb_execute tool definition."""
    return GDB_EXECUTE_TOOL.copy()


def get_fuzz_introspector_tools() -> List[Dict[str, Any]]:
    """Get all FuzzIntrospector API tool definitions."""
    return [
        FI_GET_FUNCTION_IMPLEMENTATION_TOOL.copy(),
        FI_GET_FUNCTION_SIGNATURE_TOOL.copy(),
        FI_GET_SAMPLE_CROSS_REFERENCES_TOOL.copy(),
        FI_GET_TYPE_DEFINITIONS_TOOL.copy(),
        FI_GET_HEADERS_FOR_FUNCTION_TOOL.copy(),
        FI_GET_TESTS_FOR_FUNCTIONS_TOOL.copy(),
        FI_GET_FUNCTION_DEBUG_TYPES_TOOL.copy(),
        FI_GET_FUNCTIONS_BY_RETURN_TYPE_TOOL.copy(),
    ]


def get_all_crash_analyzer_tools() -> List[Dict[str, Any]]:
    """Get all tools for CrashAnalyzer (gdb + bash)."""
    return [get_gdb_tool(), get_bash_tool()]


def get_all_crash_feasibility_tools() -> List[Dict[str, Any]]:
    """Get all tools for CrashFeasibilityAnalyzer (bash + FI APIs)."""
    return [get_bash_tool()] + get_fuzz_introspector_tools()
