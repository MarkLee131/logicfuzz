#!/usr/bin/env python3
"""
Fake Definition Validator - Detects LLM-hallucinated function definitions.

This module identifies when LLM generates calls to non-existent functions
by comparing undefined reference errors against known project APIs.

Inspired by Scheduzz's fake definition check approach.
"""

import re
import logging
from typing import List, Dict, Set, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FakeDefinitionResult:
    """Result of fake definition check."""
    has_fake_definitions: bool
    fake_functions: List[str]  # Functions that don't exist in project
    real_undefined: List[str]  # Functions that exist but have linker issues
    details: Dict[str, Any]  # Detailed info for each function


class FakeDefinitionValidator:
    """
    Validates that undefined references are not LLM-invented functions.

    When compilation fails with "undefined reference" errors, this validator
    distinguishes between:
    1. Fake definitions: Functions invented by LLM (not in project APIs)
    2. Real undefined: Functions that exist but have linking issues

    Fake definitions cannot be fixed by the Fixer agent and should terminate
    the workflow early to avoid wasted retries.
    """

    # Patterns to extract undefined reference errors from build logs
    UNDEFINED_REFERENCE_PATTERNS = [
        # GCC/ld linker errors
        r"undefined reference to [`']([^'`]+)[`']",
        r"undefined reference to\s+[`']?(\w+)[`']?",

        # Clang linker errors
        r"error: undefined symbol:\s*(\w+)",
        r"ld\.lld: error: undefined symbol:\s*(\w+)",

        # Generic linker error
        r"symbol[s]? not found.*[`'](\w+)[`']",

        # C++ mangled symbols (extract base name)
        r"undefined reference to [`']_Z\d+(\w+)",
    ]

    # Patterns for declaration errors (function not declared)
    UNDECLARED_PATTERNS = [
        # GCC: implicit declaration
        r"implicit declaration of function [`'](\w+)[`']",
        r"warning: implicit declaration of function [`'](\w+)[`']",

        # GCC/Clang: undeclared identifier
        r"[`'](\w+)[`'] was not declared in this scope",
        r"error: use of undeclared identifier [`'](\w+)[`']",
        r"error: [`'](\w+)[`'] undeclared",

        # ISO C undeclared
        r"error: [`'](\w+)[`'] is not declared",
    ]

    # Functions to ignore (common system/compiler functions)
    IGNORE_FUNCTIONS = {
        # Compiler builtins
        '__stack_chk_fail',
        '__cxa_allocate_exception',
        '__cxa_throw',
        '__gxx_personality_v0',
        '__cxa_begin_catch',
        '__cxa_end_catch',

        # C++ ABI
        '_Unwind_Resume',
        '__cxa_atexit',
        '__dso_handle',

        # Common libc functions that might have linking issues
        'memcpy',
        'memset',
        'malloc',
        'free',
        'printf',
        'strlen',
        'strcpy',
        'strncpy',
        'strcmp',

        # Sanitizer functions
        '__asan_report_load',
        '__asan_report_store',
        '__ubsan_handle',
        '__msan_',
    }

    def __init__(self):
        """Initialize the validator with compiled regex patterns."""
        self.undefined_ref_re = [
            re.compile(p, re.IGNORECASE)
            for p in self.UNDEFINED_REFERENCE_PATTERNS
        ]
        self.undeclared_re = [
            re.compile(p, re.IGNORECASE) for p in self.UNDECLARED_PATTERNS
        ]

    def extract_undefined_functions(self, build_errors: List[str]) -> Set[str]:
        """
        Extract function names from undefined reference/declaration errors.

        Args:
            build_errors: List of build error strings

        Returns:
            Set of function names that are undefined/undeclared
        """
        undefined_functions = set()

        error_text = '\n'.join(build_errors) if isinstance(
            build_errors, list) else str(build_errors)

        # Extract from undefined reference patterns
        for pattern_re in self.undefined_ref_re:
            matches = pattern_re.findall(error_text)
            for match in matches:
                func_name = self._clean_function_name(match)
                if func_name and not self._should_ignore(func_name):
                    undefined_functions.add(func_name)

        # Extract from undeclared patterns
        for pattern_re in self.undeclared_re:
            matches = pattern_re.findall(error_text)
            for match in matches:
                func_name = self._clean_function_name(match)
                if func_name and not self._should_ignore(func_name):
                    undefined_functions.add(func_name)

        return undefined_functions

    def _clean_function_name(self, name: str) -> Optional[str]:
        """Clean and normalize function name."""
        if not name:
            return None

        # Remove common prefixes/suffixes
        name = name.strip()

        # Handle C++ mangled names - extract base name
        if name.startswith('_Z'):
            # Try to demangle or extract readable part
            # Pattern: _Z<length><name>... -> extract <name>
            match = re.match(r'_Z\d+(\w+)', name)
            if match:
                name = match.group(1)

        # Remove trailing numbers (template instantiations)
        name = re.sub(r'\d+$', '', name)

        # Must be a valid C/C++ identifier
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return None

        return name

    def _should_ignore(self, func_name: str) -> bool:
        """Check if function should be ignored (system/compiler function)."""
        # Exact match
        if func_name in self.IGNORE_FUNCTIONS:
            return True

        # Prefix match for sanitizer/compiler functions
        ignore_prefixes = ('__asan', '__ubsan', '__msan', '__tsan', '__cxa',
                           '_Unwind')
        if func_name.startswith(ignore_prefixes):
            return True

        return False

    def validate(
            self,
            build_errors: List[str],
            known_apis: List[Dict[str, Any]],
            fuzz_target_source: Optional[str] = None) -> FakeDefinitionResult:
        """
        Validate undefined references against known project APIs.

        Args:
            build_errors: List of build error strings
            known_apis: List of API dictionaries from FuzzingContext.project_apis
                       Each dict has 'function_name', 'return_type', 'arguments', etc.
            fuzz_target_source: Optional source code for additional analysis

        Returns:
            FakeDefinitionResult with detection results
        """
        # Extract undefined function names
        undefined_funcs = self.extract_undefined_functions(build_errors)

        if not undefined_funcs:
            return FakeDefinitionResult(
                has_fake_definitions=False,
                fake_functions=[],
                real_undefined=[],
                details={'message': 'No undefined reference errors found'})

        # Build set of known API names
        known_api_names = set()
        known_api_map = {}
        for api in known_apis:
            func_name = api.get('function_name', '')
            if func_name:
                known_api_names.add(func_name)
                known_api_map[func_name] = api

        # Categorize undefined functions
        fake_functions = []
        real_undefined = []
        details = {}

        for func_name in undefined_funcs:
            if func_name in known_api_names:
                # Function exists in project - this is a linker issue, not fake
                real_undefined.append(func_name)
                details[func_name] = {
                    'is_fake': False,
                    'reason':
                    'Function exists in project APIs but has linking issue',
                    'api_info': known_api_map.get(func_name, {}),
                    'recoverable': True
                }
            else:
                # Function does NOT exist - LLM invented it
                fake_functions.append(func_name)
                details[func_name] = {
                    'is_fake':
                    True,
                    'reason':
                    f"Function '{func_name}' not found in project APIs - likely LLM hallucination",
                    'recoverable':
                    False,
                    'suggestion':
                    self._suggest_similar_api(func_name, known_api_names)
                }

        has_fake = len(fake_functions) > 0

        if has_fake:
            logger.warning(
                f"Detected {len(fake_functions)} fake function(s): {fake_functions}. "
                f"These are LLM hallucinations and cannot be fixed.")

        if real_undefined:
            logger.info(
                f"Found {len(real_undefined)} real undefined reference(s): {real_undefined}. "
                f"These may be fixable (linking issues).")

        return FakeDefinitionResult(has_fake_definitions=has_fake,
                                    fake_functions=fake_functions,
                                    real_undefined=real_undefined,
                                    details=details)

    def _suggest_similar_api(self, fake_name: str,
                             known_apis: Set[str]) -> Optional[str]:
        """Suggest similar API names that might be what the LLM intended."""
        if not known_apis:
            return None

        # Simple similarity: find APIs with common prefix or containing key parts
        fake_lower = fake_name.lower()
        candidates = []

        for api in known_apis:
            api_lower = api.lower()

            # Check for common prefix (at least 4 chars)
            prefix_len = 0
            for i, (c1, c2) in enumerate(zip(fake_lower, api_lower)):
                if c1 == c2:
                    prefix_len = i + 1
                else:
                    break

            if prefix_len >= 4:
                candidates.append((api, prefix_len))

        if candidates:
            # Return the one with longest common prefix
            candidates.sort(key=lambda x: -x[1])
            return f"Did you mean '{candidates[0][0]}'?"

        return None

    def format_report(self, result: FakeDefinitionResult) -> str:
        """Format validation result as human-readable report."""
        lines = []

        if not result.has_fake_definitions and not result.real_undefined:
            return "✅ No undefined reference errors detected"

        if result.has_fake_definitions:
            lines.extend([
                "❌ FAKE FUNCTION DEFINITIONS DETECTED", "",
                "The following functions were invented by the LLM and do not exist in the project:",
                ""
            ])

            for func in result.fake_functions:
                detail = result.details.get(func, {})
                lines.append(f"  • {func}")
                lines.append(f"    Reason: {detail.get('reason', 'Unknown')}")
                if suggestion := detail.get('suggestion'):
                    lines.append(f"    💡 {suggestion}")
                lines.append("")

            lines.extend([
                "⚠️  These errors CANNOT be fixed by the Fixer agent.",
                "    The workflow should terminate and regenerate the driver.",
                ""
            ])

        if result.real_undefined:
            lines.extend([
                "⚠️  REAL UNDEFINED REFERENCES (Potentially Fixable)", "",
                "The following functions exist but have linking issues:", ""
            ])

            for func in result.real_undefined:
                detail = result.details.get(func, {})
                lines.append(f"  • {func}")
                if api_info := detail.get('api_info'):
                    lines.append(
                        f"    Return type: {api_info.get('return_type', 'unknown')}"
                    )
                lines.append("")

            lines.append(
                "These may be fixable by adding correct library linkage.")

        return '\n'.join(lines)


def check_for_fake_definitions(
    build_errors: List[str],
    project_apis: List[Dict[str, Any]],
    fuzz_target_source: Optional[str] = None
) -> Tuple[bool, FakeDefinitionResult]:
    """
    Convenience function to check for fake definitions.

    Args:
        build_errors: List of build error strings
        project_apis: List of API dicts from FuzzingContext
        fuzz_target_source: Optional source code

    Returns:
        Tuple of (has_fake_definitions: bool, result: FakeDefinitionResult)
    """
    validator = FakeDefinitionValidator()
    result = validator.validate(build_errors, project_apis, fuzz_target_source)
    return result.has_fake_definitions, result


def should_terminate_on_fake_definitions(
    state,  # FuzzingWorkflowState (TypedDict) - avoid import cycle
    min_fake_count: int = 1
) -> Tuple[bool, Optional[str]]:
    """
    Check if workflow should terminate due to fake definitions.

    This is called from the supervisor to decide routing.

    Args:
        state: FuzzingWorkflowState dict
        min_fake_count: Minimum number of fake functions to trigger termination

    Returns:
        Tuple of (should_terminate: bool, reason: Optional[str])
    """
    build_errors = state.get('build_errors', [])
    if not build_errors:
        return False, None

    # Get project APIs from context
    context = state.get('context', {})
    project_apis = context.get('project_apis', [])

    if not project_apis:
        # No API info available - can't validate
        logger.warning(
            "No project_apis in context, skipping fake definition check")
        return False, None

    # Check for fake definitions
    has_fake, result = check_for_fake_definitions(
        build_errors, project_apis, state.get('fuzz_target_source'))

    if has_fake and len(result.fake_functions) >= min_fake_count:
        reason = (
            f"Detected {len(result.fake_functions)} LLM-hallucinated function(s): "
            f"{result.fake_functions}. These cannot be fixed - terminating workflow."
        )
        return True, reason

    return False, None


# Example usage
if __name__ == '__main__':
    # Test with sample error messages
    test_errors = [
        "fuzz_target.c:15: undefined reference to `cJSON_ParseWithOptions'",
        "fuzz_target.c:20: undefined reference to `cJSON_GetObjectItemCaseSensitive'",
        "fuzz_target.c:25: undefined reference to `cJSON_FreeMemory'",  # Fake!
        "error: 'cJSON_MagicFunction' was not declared in this scope",  # Fake!
    ]

    # Sample known APIs
    test_apis = [
        {
            'function_name': 'cJSON_Parse',
            'return_type': 'cJSON*'
        },
        {
            'function_name': 'cJSON_ParseWithOptions',
            'return_type': 'cJSON*'
        },
        {
            'function_name': 'cJSON_GetObjectItemCaseSensitive',
            'return_type': 'cJSON*'
        },
        {
            'function_name': 'cJSON_Delete',
            'return_type': 'void'
        },
        {
            'function_name': 'cJSON_Print',
            'return_type': 'char*'
        },
    ]

    has_fake, result = check_for_fake_definitions(test_errors, test_apis)

    validator = FakeDefinitionValidator()
    print(validator.format_report(result))
    print(f"\nHas fake definitions: {has_fake}")
    print(f"Fake functions: {result.fake_functions}")
    print(f"Real undefined: {result.real_undefined}")
