#!/usr/bin/env python3
"""
Compilation Error Triage - Categorizes build errors for targeted fixing.

This module classifies compilation errors into distinct categories to enable
targeted fix strategies. Different error types require different approaches:
- Link errors: Need library flags or .cpp includes
- Header errors: Need correct include paths
- Declaration errors: Need proper #include statements
- Type errors: Need signature fixes
- Language mismatch: Need C/C++ compatibility fixes

Inspired by Scheduzz's compilation error triage approach.
"""

import re
import logging
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Categories of compilation errors."""
    LINK_ERROR = auto()           # undefined reference, undefined symbol
    HEADER_NOT_FOUND = auto()     # file not found, no such file
    DECLARATION_MISSING = auto()  # undeclared identifier, implicit declaration
    TYPE_ERROR = auto()           # type mismatch, incompatible types
    SYNTAX_ERROR = auto()         # syntax errors
    LANGUAGE_MISMATCH = auto()    # C++ features in C code
    INTERNAL_API = auto()         # internal/private API usage
    FAKE_DEFINITION = auto()      # LLM-invented functions
    OTHER = auto()                # unclassified errors


class FixStrategy(Enum):
    """Recommended fix strategies for each error category."""
    ADD_LIBRARY_LINK = auto()     # -l flag or find .a file
    INCLUDE_CPP_FILE = auto()     # #include "impl.cpp"
    FIX_INCLUDE_PATH = auto()     # correct #include path
    ADD_INCLUDE = auto()          # add missing #include
    FIX_SIGNATURE = auto()        # fix function signature/types
    FIX_SYNTAX = auto()           # fix syntax error
    USE_C_PATTERNS = auto()       # rewrite with pure C
    USE_PUBLIC_API = auto()       # replace internal with public API
    REGENERATE = auto()           # cannot fix, need to regenerate
    MANUAL_REVIEW = auto()        # needs human review


@dataclass
class TriagedError:
    """A single triaged error with category and fix strategy."""
    raw_error: str
    category: ErrorCategory
    fix_strategy: FixStrategy
    extracted_symbol: Optional[str] = None  # function/file name extracted
    line_number: Optional[int] = None
    details: str = ""
    recoverable: bool = True


@dataclass
class TriageResult:
    """Complete triage result for all build errors."""
    errors: List[TriagedError]
    summary: Dict[ErrorCategory, int]
    primary_category: Optional[ErrorCategory] = None
    recommended_strategy: Optional[FixStrategy] = None
    recoverable: bool = True
    details: Dict[str, Any] = field(default_factory=dict)

    def has_category(self, category: ErrorCategory) -> bool:
        """Check if any error has the given category."""
        return any(e.category == category for e in self.errors)

    def get_errors_by_category(self, category: ErrorCategory) -> List[TriagedError]:
        """Get all errors of a specific category."""
        return [e for e in self.errors if e.category == category]


class CompilationErrorTriage:
    """
    Categorizes and triages compilation errors.

    Analyzes build errors to determine:
    1. Error category (link, header, type, etc.)
    2. Recommended fix strategy
    3. Whether the error is recoverable by Fixer agent
    """

    # === Pattern definitions ===

    # Link errors - undefined reference/symbol
    LINK_ERROR_PATTERNS = [
        (r"undefined reference to [`']([^'`]+)[`']", "undefined_reference"),
        (r"ld\.lld: error: undefined symbol:\s*(\w+)", "undefined_symbol"),
        (r"error: undefined symbol:\s*(\w+)", "undefined_symbol"),
        (r"symbol[s]? not found.*[`'](\w+)[`']", "symbol_not_found"),
        (r"cannot find -l(\w+)", "library_not_found"),
        (r"library not found for -l(\w+)", "library_not_found"),
    ]

    # Header not found errors
    HEADER_NOT_FOUND_PATTERNS = [
        (r"fatal error:\s*[`']?([^'`\n:]+)[`']?\s*file not found", "file_not_found"),
        (r"error:\s*[`']?([^'`\n:]+\.h)[`']?:\s*No such file", "no_such_file"),
        (r"#include\s*[<\"]([^>\"]+)[>\"].*not found", "include_not_found"),
        (r"cannot find include file:\s*[`']?([^'`\n]+)[`']?", "include_not_found"),
        (r"fatal error:\s*'([^']+)'.*file not found", "file_not_found"),
    ]

    # Declaration missing errors
    DECLARATION_MISSING_PATTERNS = [
        (r"implicit declaration of function [`'](\w+)[`']", "implicit_declaration"),
        (r"[`'](\w+)[`'] was not declared in this scope", "undeclared_scope"),
        (r"error: use of undeclared identifier [`'](\w+)[`']", "undeclared_identifier"),
        (r"error: [`'](\w+)[`'] undeclared", "undeclared"),
        (r"error: unknown type name [`'](\w+)[`']", "unknown_type"),
        (r"error: [`'](\w+)[`'] does not name a type", "not_a_type"),
    ]

    # Type errors
    TYPE_ERROR_PATTERNS = [
        (r"error: incompatible type", "incompatible_type"),
        (r"error: cannot convert", "cannot_convert"),
        (r"error: invalid conversion", "invalid_conversion"),
        (r"error: no matching function", "no_matching_function"),
        (r"error: too (few|many) arguments", "argument_count"),
        (r"error:.*expects.*argument.*but.*provided", "argument_mismatch"),
        (r"error: invalid operands", "invalid_operands"),
        (r"error: passing.*to parameter of incompatible type", "incompatible_param"),
    ]

    # Syntax errors
    SYNTAX_ERROR_PATTERNS = [
        (r"error: expected.*before", "expected_before"),
        (r"error: expected.*at end", "expected_at_end"),
        (r"error: missing.*before", "missing_before"),
        (r"error: stray.*in program", "stray_char"),
        (r"error: unterminated", "unterminated"),
        (r"error: expected.*;.*before", "missing_semicolon"),
    ]

    # C++ in C code (language mismatch)
    LANGUAGE_MISMATCH_PATTERNS = [
        (r"error:.*'class'.*C\+\+", "cpp_class"),
        (r"error:.*'namespace'.*C\+\+", "cpp_namespace"),
        (r"error:.*'template'", "cpp_template"),
        (r"error:.*unknown type name 'std'", "cpp_std"),
        (r"FuzzedDataProvider.*not found", "cpp_fuzzed_data_provider"),
        (r"error:.*'extern \"C\"'", "cpp_extern_c"),
    ]

    # Internal API usage
    INTERNAL_API_PATTERNS = [
        (r"#include.*internal/", "internal_header"),
        (r"#include.*private/", "private_header"),
        (r"#include.*detail/", "detail_header"),
        (r"#include.*impl/", "impl_header"),
    ]

    def __init__(self):
        """Initialize compiled regex patterns."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for efficiency."""
        self.link_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.LINK_ERROR_PATTERNS]
        self.header_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.HEADER_NOT_FOUND_PATTERNS]
        self.decl_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.DECLARATION_MISSING_PATTERNS]
        self.type_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.TYPE_ERROR_PATTERNS]
        self.syntax_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.SYNTAX_ERROR_PATTERNS]
        self.lang_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.LANGUAGE_MISMATCH_PATTERNS]
        self.internal_re = [(re.compile(p, re.IGNORECASE), t) for p, t in self.INTERNAL_API_PATTERNS]
        self.line_number_re = re.compile(r':(\d+):|line\s+(\d+)', re.IGNORECASE)

    def triage(self, build_errors: List[str],
               known_apis: Optional[List[Dict[str, Any]]] = None) -> TriageResult:
        """
        Triage build errors into categories.

        Args:
            build_errors: List of build error strings
            known_apis: Optional list of known project APIs for fake definition check

        Returns:
            TriageResult with categorized errors and recommendations
        """
        triaged_errors = []
        error_text = '\n'.join(build_errors) if isinstance(build_errors, list) else str(build_errors)

        # Process each error line
        for error in build_errors:
            triaged = self._categorize_error(error, known_apis)
            if triaged:
                triaged_errors.append(triaged)

        # Build summary
        summary = {}
        for err in triaged_errors:
            summary[err.category] = summary.get(err.category, 0) + 1

        # Determine primary category (most common)
        primary_category = None
        if summary:
            primary_category = max(summary.keys(), key=lambda k: summary[k])

        # Determine recommended strategy based on primary category
        recommended_strategy = self._get_recommended_strategy(primary_category, triaged_errors)

        # Determine if recoverable
        recoverable = all(e.recoverable for e in triaged_errors)
        # Fake definitions are not recoverable
        if any(e.category == ErrorCategory.FAKE_DEFINITION for e in triaged_errors):
            recoverable = False

        return TriageResult(
            errors=triaged_errors,
            summary=summary,
            primary_category=primary_category,
            recommended_strategy=recommended_strategy,
            recoverable=recoverable,
            details={
                'total_errors': len(triaged_errors),
                'categories_found': list(summary.keys()),
            }
        )

    def _categorize_error(self, error: str,
                          known_apis: Optional[List[Dict[str, Any]]] = None) -> Optional[TriagedError]:
        """Categorize a single error line."""
        if not error.strip():
            return None

        # Extract line number if present
        line_number = None
        line_match = self.line_number_re.search(error)
        if line_match:
            line_number = int(line_match.group(1) or line_match.group(2))

        # Try each category in order of specificity

        # 1. Link errors
        for pattern_re, error_type in self.link_re:
            match = pattern_re.search(error)
            if match:
                symbol = match.group(1) if match.groups() else None
                # Check if this is a fake definition
                if known_apis and symbol:
                    known_names = {api.get('function_name', '') for api in known_apis}
                    if symbol not in known_names and not self._is_system_symbol(symbol):
                        return TriagedError(
                            raw_error=error,
                            category=ErrorCategory.FAKE_DEFINITION,
                            fix_strategy=FixStrategy.REGENERATE,
                            extracted_symbol=symbol,
                            line_number=line_number,
                            details=f"Function '{symbol}' not found in project APIs",
                            recoverable=False
                        )
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.LINK_ERROR,
                    fix_strategy=FixStrategy.ADD_LIBRARY_LINK if 'library' in error_type else FixStrategy.INCLUDE_CPP_FILE,
                    extracted_symbol=symbol,
                    line_number=line_number,
                    details=error_type
                )

        # 2. Header not found
        for pattern_re, error_type in self.header_re:
            match = pattern_re.search(error)
            if match:
                header = match.group(1) if match.groups() else None
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.HEADER_NOT_FOUND,
                    fix_strategy=FixStrategy.FIX_INCLUDE_PATH,
                    extracted_symbol=header,
                    line_number=line_number,
                    details=error_type
                )

        # 3. Internal API
        for pattern_re, error_type in self.internal_re:
            if pattern_re.search(error):
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.INTERNAL_API,
                    fix_strategy=FixStrategy.USE_PUBLIC_API,
                    line_number=line_number,
                    details=error_type
                )

        # 4. Language mismatch
        for pattern_re, error_type in self.lang_re:
            if pattern_re.search(error):
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.LANGUAGE_MISMATCH,
                    fix_strategy=FixStrategy.USE_C_PATTERNS,
                    line_number=line_number,
                    details=error_type
                )

        # 5. Declaration missing
        for pattern_re, error_type in self.decl_re:
            match = pattern_re.search(error)
            if match:
                symbol = match.group(1) if match.groups() else None
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.DECLARATION_MISSING,
                    fix_strategy=FixStrategy.ADD_INCLUDE,
                    extracted_symbol=symbol,
                    line_number=line_number,
                    details=error_type
                )

        # 6. Type errors
        for pattern_re, error_type in self.type_re:
            if pattern_re.search(error):
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.TYPE_ERROR,
                    fix_strategy=FixStrategy.FIX_SIGNATURE,
                    line_number=line_number,
                    details=error_type
                )

        # 7. Syntax errors
        for pattern_re, error_type in self.syntax_re:
            if pattern_re.search(error):
                return TriagedError(
                    raw_error=error,
                    category=ErrorCategory.SYNTAX_ERROR,
                    fix_strategy=FixStrategy.FIX_SYNTAX,
                    line_number=line_number,
                    details=error_type
                )

        # 8. Other/unclassified (only if it looks like an error)
        if 'error:' in error.lower() or 'fatal error' in error.lower():
            return TriagedError(
                raw_error=error,
                category=ErrorCategory.OTHER,
                fix_strategy=FixStrategy.MANUAL_REVIEW,
                line_number=line_number,
                details="unclassified"
            )

        return None

    def _is_system_symbol(self, symbol: str) -> bool:
        """Check if symbol is a system/compiler function."""
        system_prefixes = ('__', '_Z', '_Unwind')
        system_names = {
            'memcpy', 'memset', 'malloc', 'free', 'printf', 'strlen',
            'strcpy', 'strncpy', 'strcmp', 'main'
        }
        return symbol.startswith(system_prefixes) or symbol in system_names

    def _get_recommended_strategy(self, primary_category: Optional[ErrorCategory],
                                   errors: List[TriagedError]) -> Optional[FixStrategy]:
        """Get recommended fix strategy based on error pattern."""
        if not primary_category:
            return None

        # Map category to default strategy
        category_strategy = {
            ErrorCategory.LINK_ERROR: FixStrategy.INCLUDE_CPP_FILE,
            ErrorCategory.HEADER_NOT_FOUND: FixStrategy.FIX_INCLUDE_PATH,
            ErrorCategory.DECLARATION_MISSING: FixStrategy.ADD_INCLUDE,
            ErrorCategory.TYPE_ERROR: FixStrategy.FIX_SIGNATURE,
            ErrorCategory.SYNTAX_ERROR: FixStrategy.FIX_SYNTAX,
            ErrorCategory.LANGUAGE_MISMATCH: FixStrategy.USE_C_PATTERNS,
            ErrorCategory.INTERNAL_API: FixStrategy.USE_PUBLIC_API,
            ErrorCategory.FAKE_DEFINITION: FixStrategy.REGENERATE,
            ErrorCategory.OTHER: FixStrategy.MANUAL_REVIEW,
        }

        return category_strategy.get(primary_category)

    def format_report(self, result: TriageResult) -> str:
        """Format triage result as human-readable report."""
        lines = ["📋 Compilation Error Triage Report", "=" * 40, ""]

        if not result.errors:
            lines.append("✅ No errors to triage")
            return '\n'.join(lines)

        # Summary
        lines.append(f"**Total Errors**: {len(result.errors)}")
        lines.append(f"**Primary Category**: {result.primary_category.name if result.primary_category else 'None'}")
        lines.append(f"**Recommended Strategy**: {result.recommended_strategy.name if result.recommended_strategy else 'None'}")
        lines.append(f"**Recoverable**: {'Yes' if result.recoverable else 'No'}")
        lines.append("")

        # Category breakdown
        lines.append("**Category Breakdown**:")
        for category, count in sorted(result.summary.items(), key=lambda x: -x[1]):
            emoji = self._get_category_emoji(category)
            lines.append(f"  {emoji} {category.name}: {count}")
        lines.append("")

        # Detailed errors by category
        for category in ErrorCategory:
            cat_errors = result.get_errors_by_category(category)
            if cat_errors:
                emoji = self._get_category_emoji(category)
                lines.append(f"\n{emoji} **{category.name}** ({len(cat_errors)} errors):")
                for err in cat_errors[:5]:  # Limit to 5 per category
                    symbol_info = f" [{err.extracted_symbol}]" if err.extracted_symbol else ""
                    line_info = f" (line {err.line_number})" if err.line_number else ""
                    lines.append(f"  • {err.details}{symbol_info}{line_info}")
                    lines.append(f"    Strategy: {err.fix_strategy.name}")
                if len(cat_errors) > 5:
                    lines.append(f"  ... and {len(cat_errors) - 5} more")

        return '\n'.join(lines)

    def _get_category_emoji(self, category: ErrorCategory) -> str:
        """Get emoji for category."""
        emojis = {
            ErrorCategory.LINK_ERROR: "🔗",
            ErrorCategory.HEADER_NOT_FOUND: "📁",
            ErrorCategory.DECLARATION_MISSING: "📝",
            ErrorCategory.TYPE_ERROR: "🔄",
            ErrorCategory.SYNTAX_ERROR: "⚠️",
            ErrorCategory.LANGUAGE_MISMATCH: "🌐",
            ErrorCategory.INTERNAL_API: "🔒",
            ErrorCategory.FAKE_DEFINITION: "❌",
            ErrorCategory.OTHER: "❓",
        }
        return emojis.get(category, "•")


def triage_build_errors(build_errors: List[str],
                        known_apis: Optional[List[Dict[str, Any]]] = None) -> TriageResult:
    """
    Convenience function to triage build errors.

    Args:
        build_errors: List of build error strings
        known_apis: Optional list of known project APIs

    Returns:
        TriageResult with categorized errors
    """
    triage = CompilationErrorTriage()
    return triage.triage(build_errors, known_apis)


def get_fix_guidance(result: TriageResult) -> str:
    """
    Generate fix guidance based on triage result.

    Returns actionable guidance for the Fixer agent.
    """
    if not result.errors:
        return "No errors to fix."

    guidance_lines = ["## Fix Guidance\n"]

    # Category-specific guidance
    if result.has_category(ErrorCategory.FAKE_DEFINITION):
        guidance_lines.append("### ❌ CRITICAL: Fake Definitions Detected")
        guidance_lines.append("The following functions were invented by the LLM and do not exist:")
        for err in result.get_errors_by_category(ErrorCategory.FAKE_DEFINITION):
            guidance_lines.append(f"  - `{err.extracted_symbol}`")
        guidance_lines.append("**Action**: Cannot fix. Workflow should regenerate the driver.\n")

    if result.has_category(ErrorCategory.LINK_ERROR):
        guidance_lines.append("### 🔗 Link Errors")
        guidance_lines.append("Undefined references usually need one of:")
        guidance_lines.append("1. Add `#include \"implementation.cpp\"` (check existing fuzzers)")
        guidance_lines.append("2. Add library link flag in build script (`-lfoo`)")
        guidance_lines.append("3. Find and link the correct .a/.so file\n")

    if result.has_category(ErrorCategory.HEADER_NOT_FOUND):
        guidance_lines.append("### 📁 Header Not Found")
        headers = [err.extracted_symbol for err in result.get_errors_by_category(ErrorCategory.HEADER_NOT_FOUND) if err.extracted_symbol]
        guidance_lines.append(f"Missing headers: {', '.join(headers[:5])}")
        guidance_lines.append("Use `find /src -name '*.h'` to locate correct paths.\n")

    if result.has_category(ErrorCategory.DECLARATION_MISSING):
        guidance_lines.append("### 📝 Missing Declarations")
        symbols = [err.extracted_symbol for err in result.get_errors_by_category(ErrorCategory.DECLARATION_MISSING) if err.extracted_symbol]
        guidance_lines.append(f"Undeclared symbols: {', '.join(symbols[:5])}")
        guidance_lines.append("Add missing `#include` statements for these symbols.\n")

    if result.has_category(ErrorCategory.LANGUAGE_MISMATCH):
        guidance_lines.append("### 🌐 Language Mismatch (C++ in C code)")
        guidance_lines.append("C++ features detected in C code:")
        for err in result.get_errors_by_category(ErrorCategory.LANGUAGE_MISMATCH)[:3]:
            guidance_lines.append(f"  - {err.details}")
        guidance_lines.append("**Action**: Rewrite using pure C patterns (no FuzzedDataProvider, no std::)\n")

    if result.has_category(ErrorCategory.INTERNAL_API):
        guidance_lines.append("### 🔒 Internal API Usage")
        guidance_lines.append("Internal/private headers are not available in OSS-Fuzz.")
        guidance_lines.append("**Action**: Replace with public API from existing fuzzers.\n")

    if result.has_category(ErrorCategory.TYPE_ERROR):
        guidance_lines.append("### 🔄 Type Errors")
        guidance_lines.append("Fix type mismatches, casts, and function signatures.\n")

    return '\n'.join(guidance_lines)


# Example usage
if __name__ == '__main__':
    test_errors = [
        "fuzz_target.c:15: error: 'cJSON_FreeMemory' was not declared in this scope",
        "fuzz_target.c:20: undefined reference to `cJSON_ParseWithOpts'",
        "fatal error: 'cjson/internal/parser.h' file not found",
        "error: incompatible type for argument 1 of 'cJSON_Parse'",
        "error: unknown type name 'std'",
        "#include <fuzzer/FuzzedDataProvider.h> not found",
    ]

    result = triage_build_errors(test_errors)
    triage = CompilationErrorTriage()
    print(triage.format_report(result))
    print("\n" + "=" * 40 + "\n")
    print(get_fix_guidance(result))
