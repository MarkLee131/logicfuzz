"""Tests for FIX_ARGUMENTS and FIX_ENTRYPOINT triage strategies (Task 8 / L5b).

These tests pin the new per-error FixStrategy variants:
  - FIX_ARGUMENTS : "too few / too many arguments" type errors → caller fixes
                    the call-site argument list, NOT the function signature.
  - FIX_ENTRYPOINT: undefined reference to `main` at link time → the driver is
                    missing LLVMFuzzerTestOneInput (wrote a main() instead, or
                    forgot the entrypoint entirely).

Prior behavior:
  - too-(few|many)-arguments → TYPE_ERROR / FIX_SIGNATURE (wrong hint)
  - undefined `main`  → swallowed into LINK_ERROR / INCLUDE_CPP_FILE via
                        _is_system_symbol (wrong category and strategy)
"""
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.utils.compilation_error_triage import (  # noqa: E402
    triage_build_errors,
    ErrorCategory,
    FixStrategy,
)

KNOWN = [{"function_name": "cmsFoo"}]


def test_implicit_decl_maps_to_add_include():
    """Baseline: implicit declaration should still map to ADD_INCLUDE (pre-existing)."""
    r = triage_build_errors(
        ["a.c:5: warning: implicit declaration of function 'cmsFoo'"], KNOWN
    )
    assert r.primary_category == ErrorCategory.DECLARATION_MISSING
    assert r.recommended_strategy == FixStrategy.ADD_INCLUDE


def test_too_few_args_maps_to_fix_arguments():
    """'too few arguments' is a call-site error, not a signature error."""
    r = triage_build_errors(
        ["a.c:5: error: too few arguments to function 'cmsFoo'"], KNOWN
    )
    assert r.recommended_strategy == FixStrategy.FIX_ARGUMENTS


def test_too_many_args_maps_to_fix_arguments():
    """'too many arguments' also maps to FIX_ARGUMENTS."""
    r = triage_build_errors(
        ["a.c:10: error: too many arguments to function 'cmsFoo'"], KNOWN
    )
    assert r.recommended_strategy == FixStrategy.FIX_ARGUMENTS


def test_undefined_main_maps_to_fix_entrypoint():
    """Undefined reference to `main` at link time → LANGUAGE_MISMATCH / FIX_ENTRYPOINT.

    The driver wrote `main()` instead of `LLVMFuzzerTestOneInput`, or the
    entrypoint was omitted entirely.  Swallowing it into INCLUDE_CPP_FILE /
    LINK_ERROR gives the Fixer the wrong hint.
    """
    r = triage_build_errors(
        ["a.c:(.text+0x0): undefined reference to `main'"], KNOWN
    )
    assert r.recommended_strategy == FixStrategy.FIX_ENTRYPOINT


def test_undefined_main_category_is_language_mismatch():
    """The category for a missing `main` should be LANGUAGE_MISMATCH."""
    r = triage_build_errors(
        ["a.c:(.text+0x0): undefined reference to `main'"], KNOWN
    )
    assert r.primary_category == ErrorCategory.LANGUAGE_MISMATCH


def test_fix_arguments_strategy_exists():
    """FixStrategy.FIX_ARGUMENTS must be a valid enum member."""
    assert hasattr(FixStrategy, "FIX_ARGUMENTS")
    assert isinstance(FixStrategy.FIX_ARGUMENTS, FixStrategy)


def test_fix_entrypoint_strategy_exists():
    """FixStrategy.FIX_ENTRYPOINT must be a valid enum member."""
    assert hasattr(FixStrategy, "FIX_ENTRYPOINT")
    assert isinstance(FixStrategy.FIX_ENTRYPOINT, FixStrategy)


if __name__ == "__main__":
    import pytest  # type: ignore[import-not-found]

    sys.exit(pytest.main([__file__, "-v"]))
