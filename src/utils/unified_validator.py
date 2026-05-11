#!/usr/bin/env python3
"""
Unified Code Validator - Consolidated validation for generated fuzz drivers.

This module consolidates multiple validation concerns into a single-pass scanner:
1. Fake Definition Detection - LLM-hallucinated functions
2. Internal API Detection - Private/internal API usage
3. Language Compatibility - C++ features in C code
4. Target API Validation - Verify target APIs are actually called

Benefits of consolidation:
- Single pass through source code
- Unified reporting format
- Consistent error categorization
- Reduced code duplication
"""

import logging
import re
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Data Classes
# =============================================================================

class ValidationCategory(Enum):
    """Categories of validation issues."""
    FAKE_DEFINITION = auto()      # LLM-invented functions
    INTERNAL_API = auto()         # Internal/private API usage
    INTERNAL_HEADER = auto()      # Internal header includes
    THIRD_PARTY_HEADER = auto()   # Third-party dependencies
    LANGUAGE_MISMATCH = auto()    # C++ features in C code
    DIRECT_STRUCT_ACCESS = auto() # Direct struct member access
    MISSING_TARGET_API = auto()   # Target API not called


class Severity(Enum):
    """Severity levels for validation issues."""
    ERROR = "error"       # Must fix - will cause build failure
    WARNING = "warning"   # Should fix - may cause issues
    INFO = "info"         # Informational


@dataclass
class ValidationIssue:
    """A single validation issue found in the code."""
    category: ValidationCategory
    severity: Severity
    message: str
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    pattern: Optional[str] = None
    suggestion: Optional[str] = None
    recoverable: bool = True


@dataclass
class CallingInfo:
    """Information about a function call extracted from AST."""
    caller_name: str
    caller_decl_loc: str
    callee_name: str
    callee_decl_loc: str
    calling_loc: str


@dataclass
class UnifiedValidationResult:
    """Comprehensive validation result."""
    # Overall status
    success: bool
    has_errors: bool
    has_warnings: bool

    # All issues found
    issues: List[ValidationIssue] = field(default_factory=list)

    # Fake definition specific
    fake_functions: List[str] = field(default_factory=list)
    real_undefined: List[str] = field(default_factory=list)

    # Target API specific
    actual_called_apis: List[str] = field(default_factory=list)
    missing_apis: List[str] = field(default_factory=list)
    target_api_coverage: float = 1.0

    # Language compatibility
    is_language_compatible: bool = True
    cpp_features_in_c: List[str] = field(default_factory=list)

    # Metadata
    validation_methods_used: List[str] = field(default_factory=list)

    def get_issues_by_category(self, category: ValidationCategory) -> List[ValidationIssue]:
        """Get all issues of a specific category."""
        return [i for i in self.issues if i.category == category]

    def get_errors(self) -> List[ValidationIssue]:
        """Get all error-level issues."""
        return [i for i in self.issues if i.severity == Severity.ERROR]

    def get_warnings(self) -> List[ValidationIssue]:
        """Get all warning-level issues."""
        return [i for i in self.issues if i.severity == Severity.WARNING]


# =============================================================================
# Unified Code Validator
# =============================================================================

class UnifiedCodeValidator:
    """
    Consolidated validator for generated fuzz driver code.

    Performs multiple validation checks in a single pass through the source code,
    providing unified reporting and consistent error handling.

    AST-based target-API validation uses ``liberator_adapter.analysis.static_trace.FunctionBodyWalker``,
    the same libclang-Python walker the automaton subsystem uses for
    trace extraction. The earlier ``CGProcessor`` external-binary path
    was replaced in the 2026-05 Supervisor+Validator refactor because:
      * It was duplicating capability we already maintain in Python.
      * Its default path was hardcoded to one developer's home directory,
        so every other machine silently fell back to the naive regex check.
      * Keeping two libclang-AST front-ends doubles the maintenance
        surface for a code path with sub-second cost on single drivers.
    """

    # =========================
    # Pattern Definitions
    # =========================

    # Internal function patterns
    INTERNAL_FUNCTION_PATTERNS = [
        r'\b\w+_internal\s*\(',
        r'\b\w+_impl\s*\(',
        r'\b\w+_detail\s*\(',
        r'\b\w+_private\s*\(',
        r'\b_[a-z]\w+\s*\(',
        r'\b\w+_get_default\s*\(',
        r'\bget_internal_\w+\s*\(',
        r'\bset_internal_\w+\s*\(',
    ]

    # Internal header patterns
    INTERNAL_HEADER_PATTERNS = [
        r'#include\s*[<"].*internal/',
        r'#include\s*[<"].*private/',
        r'#include\s*[<"].*detail/',
        r'#include\s*[<"].*impl/',
        r'#include\s*[<"].*_impl\.h[">]',
        r'#include\s*[<"].*_detail\.h[">]',
        r'#include\s*[<"].*_internal\.h[">]',
        r'#include\s*[<"].*_private\.h[">]',
        r'#include\s*"\.\.\/\.\.\/\.\.+/',
    ]

    # Third-party header patterns
    THIRD_PARTY_HEADER_PATTERNS = [
        r'#include\s*<cs/cs\.h>',
        r'#include\s*<suitesparse/',
        r'#include\s*<boost/',
        r'#include\s*<eigen/',
        r'#include\s*<gtest/',
        r'#include\s*<gmock/',
        r'#include\s*<catch2/',
        r'#include\s*<benchmark/',
    ]

    # C++ include patterns (not allowed in C code)
    CPP_INCLUDE_PATTERNS = [
        (r'#include\s*<fuzzer/FuzzedDataProvider\.h>', 'FuzzedDataProvider is C++ only'),
        (r'#include\s*<algorithm>', 'algorithm is a C++ header'),
        (r'#include\s*<string>', 'string is a C++ header'),
        (r'#include\s*<vector>', 'vector is a C++ header'),
        (r'#include\s*<map>', 'map is a C++ header'),
        (r'#include\s*<memory>', 'memory is a C++ header'),
        (r'#include\s*<iostream>', 'iostream is a C++ header'),
        (r'#include\s*<cstdint>', 'cstdint is C++ (use stdint.h for C)'),
        (r'#include\s*<cstddef>', 'cstddef is C++ (use stddef.h for C)'),
        (r'#include\s*<cstring>', 'cstring is C++ (use string.h for C)'),
        (r'#include\s*<cstdlib>', 'cstdlib is C++ (use stdlib.h for C)'),
    ]

    # C++ syntax patterns (not allowed in C code)
    CPP_SYNTAX_PATTERNS = [
        (r'\bstd::\w+', 'std:: namespace is C++ only'),
        (r'\bFuzzedDataProvider\s+\w+', 'FuzzedDataProvider is a C++ class'),
        (r'\.Consume\w+\s*\(', 'FuzzedDataProvider methods are C++ only'),
        (r'\bfdp\.\w+', 'fdp (FuzzedDataProvider) is C++ only'),
        (r'\bnew\s+\w+', 'new operator is C++ only'),
        (r'\bdelete\s+', 'delete operator is C++ only'),
        (r'\bclass\s+\w+', 'class keyword is C++ only'),
        (r'\btemplate\s*<', 'templates are C++ only'),
        (r'\bnamespace\s+\w+', 'namespaces are C++ only'),
        (r'::\w+\s*\(', 'scope resolution operator is C++ only'),
        (r'\bauto\s+\w+\s*=', 'auto type deduction is C++ only'),
    ]

    # Undefined reference patterns for fake definition detection
    UNDEFINED_REFERENCE_PATTERNS = [
        r"undefined reference to [`']([^'`]+)[`']",
        r"error: undefined symbol:\s*(\w+)",
        r"ld\.lld: error: undefined symbol:\s*(\w+)",
        r"symbol[s]? not found.*[`'](\w+)[`']",
    ]

    UNDECLARED_PATTERNS = [
        r"implicit declaration of function [`'](\w+)[`']",
        r"[`'](\w+)[`'] was not declared in this scope",
        r"error: use of undeclared identifier [`'](\w+)[`']",
        r"error: [`'](\w+)[`'] undeclared",
    ]

    # System functions to ignore in fake definition check.
    # 2026-05 Supervisor+Validator review (V5): expanded to cover the
    # common libc surface that LLM-generated fuzz drivers actually use.
    # Missing entries previously caused false positives that flagged
    # legitimate fuzz driver code as containing "LLM-hallucinated
    # functions".
    IGNORE_FUNCTIONS = {
        # C++ ABI / unwinding
        '__stack_chk_fail', '__cxa_allocate_exception', '__cxa_throw',
        '__gxx_personality_v0', '__cxa_begin_catch', '__cxa_end_catch',
        '_Unwind_Resume', '__cxa_atexit', '__dso_handle',
        # Memory / string / printf family
        'memcpy', 'memset', 'memcmp', 'memmove',
        'malloc', 'free', 'calloc', 'realloc', 'aligned_alloc', 'posix_memalign',
        'printf', 'fprintf', 'sprintf', 'snprintf', 'vfprintf', 'vsnprintf',
        'puts', 'fputs', 'fgets', 'fputc', 'fgetc', 'putchar', 'getchar',
        'fread', 'fwrite', 'fseek', 'ftell', 'fopen', 'fclose', 'fflush', 'rewind',
        'strlen', 'strcpy', 'strncpy', 'strcat', 'strncat',
        'strcmp', 'strncmp', 'strcasecmp', 'strncasecmp',
        'strchr', 'strrchr', 'strstr', 'strdup', 'strndup', 'strtok',
        # Conversion
        'atoi', 'atol', 'atoll', 'atof', 'strtol', 'strtoll', 'strtoul', 'strtoull',
        'strtof', 'strtod',
        # Process / exit
        'exit', '_exit', 'abort', 'getenv', 'setenv', 'unsetenv',
        # I/O
        'open', 'close', 'read', 'write', 'lseek',
        # Time
        'time', 'clock', 'gettimeofday',
    }

    # Whitelist for internal function check.
    # 2026-05 Supervisor+Validator review (V4): the original
    # ``\b_[a-z]\w+\(`` pattern over-matches common compiler intrinsics
    # and language constructs. Add the false-positive surface here so
    # those legitimate forms pass the internal-API check.
    FUNCTION_WHITELIST = {
        # Language constructs that look like _underscore functions
        '__attribute__', '_Generic', '_Static_assert',
        '_Atomic', '_Alignof', '_Alignas',
        # Compiler intrinsics (GCC / Clang). Listed explicitly rather
        # than wildcarded so we still catch genuinely-internal symbols
        # like ``_internal_helper`` that LLMs do occasionally invent.
        '__builtin_expect', '__builtin_unreachable', '__builtin_trap',
        '__builtin_memcpy', '__builtin_memset', '__builtin_alloca',
        '__builtin_strlen', '__builtin_constant_p',
        '__builtin_choose_expr', '__builtin_types_compatible_p',
        '__builtin_clz', '__builtin_ctz', '__builtin_popcount',
        '__builtin_bswap16', '__builtin_bswap32', '__builtin_bswap64',
        '__builtin_va_arg', '__builtin_va_end', '__builtin_va_start',
        '__builtin_va_copy',
        # Pragma / control
        '_Pragma',
        # libfuzzer entry point
        'LLVMFuzzerTestOneInput', 'LLVMFuzzerInitialize',
    }

    def __init__(self, cgprocessor_path: Optional[Path] = None):
        """
        Initialize the unified validator.

        Args:
            cgprocessor_path: Kept for backward compatibility with
                existing callers (e.g. ``execution.py`` still passes
                the kwarg) but ignored — AST-based target-API
                validation now goes through
                ``FunctionBodyWalker`` (Python libclang). The CGProcessor
                external-binary path was retired in the 2026-05 refactor.
        """
        # The cgprocessor_path argument is intentionally ignored.
        # Eat the parameter so existing callers don't break, but document
        # that the AST path is libclang-Python now.
        _ = cgprocessor_path

        # Compile regex patterns
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all regex patterns for efficiency."""
        self.internal_func_re = [re.compile(p) for p in self.INTERNAL_FUNCTION_PATTERNS]
        self.internal_header_re = [re.compile(p) for p in self.INTERNAL_HEADER_PATTERNS]
        self.third_party_header_re = [re.compile(p) for p in self.THIRD_PARTY_HEADER_PATTERNS]
        self.cpp_include_re = [(re.compile(p), msg) for p, msg in self.CPP_INCLUDE_PATTERNS]
        self.cpp_syntax_re = [(re.compile(p), msg) for p, msg in self.CPP_SYNTAX_PATTERNS]
        self.undefined_ref_re = [re.compile(p, re.IGNORECASE) for p in self.UNDEFINED_REFERENCE_PATTERNS]
        self.undeclared_re = [re.compile(p, re.IGNORECASE) for p in self.UNDECLARED_PATTERNS]

    def is_cgprocessor_available(self) -> bool:
        """Always True now — AST-based validation goes through libclang-Python
        (``FunctionBodyWalker``), which is in-process. Kept as a method for
        backward compat with any caller that gated on it. The naive fallback
        still runs as a last resort if libclang itself fails.
        """
        try:
            import clang.cindex  # noqa: F401
            return True
        except Exception:
            return False

    # =========================
    # Main Validation Entry Point
    # =========================

    def validate(
        self,
        code: str,
        target_apis: Optional[List[str]] = None,
        known_apis: Optional[List[Dict[str, Any]]] = None,
        build_errors: Optional[List[str]] = None,
        is_c_target: bool = False,
        include_paths: Optional[List[str]] = None,
        project_name: Optional[str] = None
    ) -> UnifiedValidationResult:
        """
        Perform comprehensive validation on fuzz driver code.

        Args:
            code: Source code of the fuzz driver
            target_apis: List of target API function names that should be called
            known_apis: List of known project APIs (for fake definition check)
            build_errors: List of build error strings (for fake definition check)
            is_c_target: True if target is pure C (enables language compatibility check)
            include_paths: List of include paths for AST-based validation
            project_name: Optional project name for project-specific rules

        Returns:
            UnifiedValidationResult with all validation findings
        """
        issues: List[ValidationIssue] = []
        validation_methods: List[str] = []

        # Parse code once
        lines = code.split('\n')
        code_no_comments = self._remove_comments(code)

        # 1. Check for internal API usage
        issues.extend(self._check_internal_apis(lines))
        validation_methods.append("internal_api_scan")

        # 2. Check for internal/third-party headers
        issues.extend(self._check_headers(lines))
        validation_methods.append("header_scan")

        # 3. Check language compatibility (if C target)
        cpp_features = []
        is_language_compatible = True
        if is_c_target:
            lang_issues, cpp_features = self._check_language_compatibility(lines)
            issues.extend(lang_issues)
            is_language_compatible = len(cpp_features) == 0
            validation_methods.append("language_compatibility")

        # 4. Check for fake definitions (if build errors provided)
        fake_functions = []
        real_undefined = []
        if build_errors and known_apis:
            fake_issues, fake_functions, real_undefined = self._check_fake_definitions(
                build_errors, known_apis
            )
            issues.extend(fake_issues)
            validation_methods.append("fake_definition_check")

        # 5. Check target API calls
        actual_called = []
        missing_apis = []
        target_coverage = 1.0
        if target_apis:
            api_issues, actual_called, missing_apis, target_coverage = self._check_target_apis(
                code, code_no_comments, target_apis, include_paths
            )
            issues.extend(api_issues)
            validation_methods.append("target_api_check")

        # Calculate overall status
        errors = [i for i in issues if i.severity == Severity.ERROR]
        warnings = [i for i in issues if i.severity == Severity.WARNING]

        return UnifiedValidationResult(
            success=len(errors) == 0,
            has_errors=len(errors) > 0,
            has_warnings=len(warnings) > 0,
            issues=issues,
            fake_functions=fake_functions,
            real_undefined=real_undefined,
            actual_called_apis=actual_called,
            missing_apis=missing_apis,
            target_api_coverage=target_coverage,
            is_language_compatible=is_language_compatible,
            cpp_features_in_c=cpp_features,
            validation_methods_used=validation_methods
        )

    # =========================
    # Individual Check Methods
    # =========================

    def _check_internal_apis(self, lines: List[str]) -> List[ValidationIssue]:
        """Check for internal/private API usage."""
        issues = []

        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern_re in self.internal_func_re:
                matches = pattern_re.finditer(line)
                for match in matches:
                    func_name = match.group(0).strip('( ')
                    if func_name in self.FUNCTION_WHITELIST:
                        continue

                    issues.append(ValidationIssue(
                        category=ValidationCategory.INTERNAL_API,
                        severity=Severity.ERROR,
                        message=f"Internal API usage: {func_name}",
                        line_number=line_num,
                        line_content=line.strip(),
                        pattern=func_name,
                        suggestion=self._suggest_internal_api_fix(func_name)
                    ))

        return issues

    def _check_headers(self, lines: List[str]) -> List[ValidationIssue]:
        """Check for internal and third-party header includes."""
        issues = []

        for line_num, line in enumerate(lines, 1):
            # Check internal headers
            for pattern_re in self.internal_header_re:
                if pattern_re.search(line):
                    issues.append(ValidationIssue(
                        category=ValidationCategory.INTERNAL_HEADER,
                        severity=Severity.ERROR,
                        message=f"Internal header include",
                        line_number=line_num,
                        line_content=line.strip(),
                        suggestion="Remove internal header and use public API headers"
                    ))
                    break

            # Check third-party headers
            for pattern_re in self.third_party_header_re:
                if pattern_re.search(line):
                    issues.append(ValidationIssue(
                        category=ValidationCategory.THIRD_PARTY_HEADER,
                        severity=Severity.ERROR,
                        message=f"Third-party header include",
                        line_number=line_num,
                        line_content=line.strip(),
                        suggestion="Remove third-party header - not available in OSS-Fuzz"
                    ))
                    break

        return issues

    def _check_language_compatibility(self, lines: List[str]) -> Tuple[List[ValidationIssue], List[str]]:
        """Check for C++ features in C code."""
        issues = []
        cpp_features = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check C++ includes
            for pattern_re, reason in self.cpp_include_re:
                match = pattern_re.search(line)
                if match:
                    cpp_features.append(match.group(0))
                    issues.append(ValidationIssue(
                        category=ValidationCategory.LANGUAGE_MISMATCH,
                        severity=Severity.ERROR,
                        message=reason,
                        line_number=line_num,
                        line_content=line.strip(),
                        pattern=match.group(0),
                        suggestion="Use C equivalent header/pattern"
                    ))

            # Check C++ syntax
            for pattern_re, reason in self.cpp_syntax_re:
                match = pattern_re.search(line)
                if match:
                    cpp_features.append(match.group(0))
                    issues.append(ValidationIssue(
                        category=ValidationCategory.LANGUAGE_MISMATCH,
                        severity=Severity.ERROR,
                        message=reason,
                        line_number=line_num,
                        line_content=line.strip(),
                        pattern=match.group(0),
                        suggestion="Rewrite using pure C patterns"
                    ))

        return issues, cpp_features

    def _check_fake_definitions(
        self,
        build_errors: List[str],
        known_apis: List[Dict[str, Any]]
    ) -> Tuple[List[ValidationIssue], List[str], List[str]]:
        """Check for LLM-invented functions not in project APIs."""
        issues = []
        fake_functions = []
        real_undefined = []

        # Extract undefined function names from build errors
        undefined_funcs = self._extract_undefined_functions(build_errors)

        if not undefined_funcs:
            return issues, fake_functions, real_undefined

        # Build set of known API names
        known_api_names = {api.get('function_name', '') for api in known_apis if api.get('function_name')}

        for func_name in undefined_funcs:
            if func_name in known_api_names:
                # Function exists in project - linking issue, not fake
                real_undefined.append(func_name)
            else:
                # Function does NOT exist - LLM hallucination
                fake_functions.append(func_name)
                issues.append(ValidationIssue(
                    category=ValidationCategory.FAKE_DEFINITION,
                    severity=Severity.ERROR,
                    message=f"LLM-hallucinated function: {func_name}",
                    pattern=func_name,
                    suggestion=self._suggest_similar_api(func_name, known_api_names),
                    recoverable=False
                ))

        return issues, fake_functions, real_undefined

    def _check_target_apis(
        self,
        code: str,
        code_no_comments: str,
        target_apis: List[str],
        include_paths: Optional[List[str]]
    ) -> Tuple[List[ValidationIssue], List[str], List[str], float]:
        """Check if target APIs are actually called."""
        issues = []

        # Try AST-based validation first
        if self.is_cgprocessor_available():
            actual_called, missing = self._check_target_apis_ast(code, target_apis, include_paths)
            method = "AST"
        else:
            actual_called, missing = self._check_target_apis_naive(code_no_comments, target_apis)
            method = "naive"

        # Create issues for missing APIs
        for api in missing:
            issues.append(ValidationIssue(
                category=ValidationCategory.MISSING_TARGET_API,
                severity=Severity.WARNING,
                message=f"Target API not called: {api}",
                pattern=api,
                suggestion=f"Add call to {api} in the fuzz driver"
            ))

        coverage = len(actual_called) / len(target_apis) if target_apis else 1.0

        logger.info(f"Target API check ({method}): {len(actual_called)}/{len(target_apis)} APIs called ({coverage:.1%})")

        return issues, actual_called, missing, coverage

    def _check_target_apis_ast(
        self,
        code: str,
        target_apis: List[str],
        include_paths: Optional[List[str]]
    ) -> Tuple[List[str], List[str]]:
        """AST-based target API check using libclang Python via
        ``FunctionBodyWalker`` — the same walker the automaton subsystem
        uses. 2026-05 refactor replaced the external CGProcessor binary
        path with this in-process implementation; see
        ``docs/supervisor_validator_refactor_2026_05.md``.
        """
        try:
            from liberator_adapter.analysis.static_trace import (
                FunctionBodyWalker, _function_definitions,
            )
            from clang.cindex import Index, TranslationUnit
        except Exception as exc:
            logger.warning(
                "libclang Python bindings unavailable (%s); "
                "falling back to naive check", exc,
            )
            return self._check_target_apis_naive(self._remove_comments(code), target_apis)

        # ``target_apis`` may include namespace prefixes (``foo::bar``); the
        # walker matches by simple name, so expand both forms into a single
        # ``public_apis`` set used as the membership filter.
        target_set: Set[str] = set()
        simple_to_full: Dict[str, str] = {}
        for api in target_apis:
            target_set.add(api)
            simple = api.rsplit("::", 1)[-1] if "::" in api else api
            target_set.add(simple)
            simple_to_full.setdefault(simple, api)

        with tempfile.TemporaryDirectory(prefix="logicfuzz_walker_") as tmp_dir:
            tmp_path = Path(tmp_dir) / "fuzz_target.cc"
            tmp_path.write_text(code)
            try:
                index = Index.create()
                args: List[str] = []
                if include_paths:
                    args.extend(f"-I{p}" for p in include_paths)
                args.append("-I/usr/include")
                tu = index.parse(
                    str(tmp_path),
                    args=args,
                    options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                )

                called: Set[str] = set()
                for func in _function_definitions(tu):
                    walker = FunctionBodyWalker(
                        public_apis=target_set,
                        file_str=str(tmp_path),
                        func_name=func.spelling,
                    )
                    walker.seed_parameter_defs(func)
                    from clang.cindex import CursorKind
                    for child in func.get_children():
                        if child.kind == CursorKind.COMPOUND_STMT:
                            walker.walk(child)
                            break
                    for call in walker.calls:
                        called.add(call.api_name)
            except Exception as exc:
                logger.warning(
                    "libclang walker raised %r; falling back to naive check",
                    exc,
                )
                return self._check_target_apis_naive(
                    self._remove_comments(code), target_apis)

        actual_called: List[str] = []
        missing: List[str] = []
        for api in target_apis:
            simple = api.rsplit("::", 1)[-1] if "::" in api else api
            if api in called or simple in called:
                actual_called.append(api)
            else:
                missing.append(api)
        return actual_called, missing

    def _check_target_apis_naive(
        self,
        code_no_comments: str,
        target_apis: List[str]
    ) -> Tuple[List[str], List[str]]:
        """Naive string-based target API check."""
        actual_called = []
        missing = []

        for api in target_apis:
            simple_name = api.split("::")[-1] if "::" in api else api
            pattern = rf'\b{re.escape(simple_name)}\s*\('
            if re.search(pattern, code_no_comments):
                actual_called.append(api)
            else:
                missing.append(api)

        return actual_called, missing

    # =========================
    # Helper Methods
    # =========================

    def _remove_comments(self, code: str) -> str:
        """Remove C/C++ comments from code."""
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

    def _extract_undefined_functions(self, build_errors: List[str]) -> Set[str]:
        """Extract undefined function names from build errors."""
        undefined = set()
        error_text = '\n'.join(build_errors) if isinstance(build_errors, list) else str(build_errors)

        for pattern_re in self.undefined_ref_re + self.undeclared_re:
            matches = pattern_re.findall(error_text)
            for match in matches:
                func_name = self._clean_function_name(match)
                if func_name and not self._should_ignore_function(func_name):
                    undefined.add(func_name)

        return undefined

    def _clean_function_name(self, name: str) -> Optional[str]:
        """Clean and normalize function name."""
        if not name:
            return None
        name = name.strip()
        if name.startswith('_Z'):
            match = re.match(r'_Z\d+(\w+)', name)
            if match:
                name = match.group(1)
        name = re.sub(r'\d+$', '', name)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            return None
        return name

    def _should_ignore_function(self, func_name: str) -> bool:
        """Check if function should be ignored."""
        if func_name in self.IGNORE_FUNCTIONS:
            return True
        ignore_prefixes = ('__asan', '__ubsan', '__msan', '__tsan', '__cxa', '_Unwind')
        return func_name.startswith(ignore_prefixes)

    def _suggest_internal_api_fix(self, func_name: str) -> str:
        """Suggest fix for internal API usage."""
        if '_get_default' in func_name:
            base = func_name.replace('_get_default', '')
            return f'Use {base}_init() instead'
        elif func_name.startswith('_'):
            return 'Find public equivalent in existing fuzzers'
        elif '_internal' in func_name or '_impl' in func_name:
            return 'Use public API from existing fuzzers'
        return 'Replace with public API function'

    def _suggest_similar_api(self, fake_name: str, known_apis: Set[str]) -> Optional[str]:
        """Suggest similar API name."""
        if not known_apis:
            return None

        fake_lower = fake_name.lower()
        candidates = []

        for api in known_apis:
            api_lower = api.lower()
            prefix_len = 0
            for i, (c1, c2) in enumerate(zip(fake_lower, api_lower)):
                if c1 == c2:
                    prefix_len = i + 1
                else:
                    break
            if prefix_len >= 4:
                candidates.append((api, prefix_len))

        if candidates:
            candidates.sort(key=lambda x: -x[1])
            return f"Did you mean '{candidates[0][0]}'?"
        return None


# =============================================================================
# Formatting Functions
# =============================================================================

def format_validation_report(result: UnifiedValidationResult) -> str:
    """Format validation result as human-readable report."""
    lines = []

    status = "PASSED" if result.success else "FAILED"
    lines.append(f"Unified Validation Report: {status}")
    lines.append("=" * 50)

    if result.has_errors:
        lines.append(f"\nERRORS ({len(result.get_errors())}):")
        for issue in result.get_errors():
            lines.append(f"  [{issue.category.name}] {issue.message}")
            if issue.line_number:
                lines.append(f"    Line {issue.line_number}: {issue.line_content}")
            if issue.suggestion:
                lines.append(f"    Suggestion: {issue.suggestion}")

    if result.has_warnings:
        lines.append(f"\nWARNINGS ({len(result.get_warnings())}):")
        for issue in result.get_warnings():
            lines.append(f"  [{issue.category.name}] {issue.message}")

    if result.fake_functions:
        lines.append(f"\nFake Definitions: {result.fake_functions}")

    if result.missing_apis:
        lines.append(f"\nMissing Target APIs ({len(result.missing_apis)}):")
        for api in result.missing_apis:
            lines.append(f"  - {api}")
        lines.append(f"  Coverage: {result.target_api_coverage:.1%}")

    if not result.is_language_compatible:
        lines.append(f"\nC++ Features in C Code: {len(result.cpp_features_in_c)} found")

    lines.append(f"\nValidation methods: {', '.join(result.validation_methods_used)}")

    return "\n".join(lines)


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    test_code = '''
#include <cjson/cJSON.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *str = (char *)malloc(size + 1);
    memcpy(str, data, size);
    str[size] = '\\0';

    cJSON *json = cJSON_Parse(str);
    if (json) {
        char *printed = cJSON_Print(json);
        if (printed) {
            free(printed);
        }
        cJSON_Delete(json);
    }

    free(str);
    return 0;
}
'''

    validator = UnifiedCodeValidator()
    result = validator.validate(
        code=test_code,
        target_apis=["cJSON_Parse", "cJSON_Print", "cJSON_Delete", "cJSON_GetObjectItem"],
        is_c_target=False
    )

    print(format_validation_report(result))
