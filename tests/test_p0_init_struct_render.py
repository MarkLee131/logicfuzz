"""Task 3 — caller-alloc INIT struct renders as stack {0} + address, not NULL.

``deflateInit_(z_stream* strm, ...)`` is a caller-alloc initializer: the
caller stack-allocates the struct and passes its address. The reconciler marks
``strm`` as OUTPUT (init-named + single pointer + SVF writes).

The bug path:
  ``_complete_value_struct`` is gated on ``DataLayout.is_a_struct(bare)``, which
  requires ``bare in clang_to_llvm_struct``. When z_stream is known to the
  layout table (``dl.layout["z_stream"] = 112``) but NOT recorded in
  ``clang_to_llvm_struct`` (e.g. because the LLVM-IR analysis ran but the type
  was not directly in the cross-reference table), ``is_a_struct`` returns False →
  ``_complete_value_struct`` returns None → the code falls to the OUTPUT-branch
  ``else: value_array = False`` → degrades to ``z_stream * strm = NULL`` →
  deflateInit_ no-ops → 0 edges.

Fix: a new ``_is_caller_alloc_struct`` helper (looser gate: just requires
``DataLayout.get_type_size(bare)`` to be truthy) is checked in the OUTPUT-branch
``else`` fallthrough before the NULL degrade.
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, SkeletonRenderer,
)
from liberator_adapter.common.datalayout import DataLayout
from liberator_adapter.common.api import Api, Arg


# ---------------------------------------------------------------------------
# Helpers for building Api / Arg objects (mirrors test_p2_value_struct_render)
# ---------------------------------------------------------------------------

def _arg(n, t, c=False):
    return Arg(name=n, flag="", size=0, type=t, is_const=[c],
               is_type_incomplete=False)


def _api(n, rt, args):
    return Api(function_name=n, is_vararg=False,
               return_info=_arg("r", rt), arguments_info=args, namespace=[])


# ---------------------------------------------------------------------------
# Fixture data — deflateInit_ (zlib caller-alloc INIT shape)
# ---------------------------------------------------------------------------

# The dict representation fed to reconcile().
# _svf_writes=True on strm triggers the INIT-producer channel in _ir_arg_roles
# (levels==1, not const, is_handle_type, init-named → ArgRole.OUTPUT).
_DEFLATE_INIT_DICT = {
    "function_name": "deflateInit_",
    "return_type": "int",
    "arguments": [
        {
            "type": "z_stream *",
            "name": "strm",
            "is_const": [False],
            "_svf_writes": True,
        },
        {
            "type": "int",
            "name": "level",
            "is_const": [False],
        },
        {
            "type": "const char *",
            "name": "version",
            "is_const": [True],
        },
        {
            "type": "int",
            "name": "stream_size",
            "is_const": [False],
        },
    ],
}

# The Api-object representation fed to SkeletonGenerator.generate().
_DEFLATE_INIT_API = _api(
    "deflateInit_",
    "int",
    [
        _arg("strm",        "z_stream *",    c=False),
        _arg("level",       "int",           c=False),
        _arg("version",     "const char *",  c=True),
        _arg("stream_size", "int",           c=False),
    ],
)


def _layout_with_size_only(dl: DataLayout) -> None:
    """Populate ONLY ``dl.layout`` — NOT ``clang_to_llvm_struct``.

    This exercises the gap the plan targets:
    - ``get_type_size("z_stream")`` → 112 (truthy)  [via layout fallback]
    - ``is_a_struct("z_stream")``   → False          [not in clang_to_llvm_struct]
    So ``_complete_value_struct("z_stream *")`` returns None, and the code
    reaches the OUTPUT-branch ``else`` fallthrough — where the NULL degrade
    previously happened and the new ``_is_caller_alloc_struct`` check should
    catch it.
    """
    dl.layout["z_stream"] = 112          # truthy → get_type_size returns 112
    # Deliberately do NOT set dl.clang_to_llvm_struct["z_stream"].


def _layout_with_full_struct(dl: DataLayout) -> None:
    """Populate both layout AND clang_to_llvm_struct.

    This exercises the existing ``_complete_value_struct`` path (which also
    produces the correct stack-alloc + address render). The test here verifies
    that the fix does not break the full-struct path.
    """
    dl.clang_to_llvm_struct["z_stream"] = "%struct.internal_state"
    dl.layout["z_stream"] = 112


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_init_struct_renders_stack_alloc_not_null_layout_only():
    """OUTPUT z_stream* (size-only layout, no clang_to_llvm_struct entry)
    → stack z_stream strm = {0}; call passes &strm, not NULL.

    This is the primary regression: ``_complete_value_struct`` returns None
    (is_a_struct is False), so only the new ``_is_caller_alloc_struct`` in the
    OUTPUT fallthrough saves it from the NULL degrade.
    """
    prev = DataLayout._instance
    DataLayout._instance = None
    try:
        dl = DataLayout.instance()
        _layout_with_size_only(dl)

        model = reconcile([_DEFLATE_INIT_DICT])
        sk = SkeletonGenerator().generate(
            api_sequence=[_DEFLATE_INIT_API],
            driver_name="t",
            is_cpp=False,
            dep_model=model,
        )
        code = SkeletonRenderer().render(sk)

        # 1. A VALUE struct declaration (no '*'), zero-initted with {0}.
        assert re.search(r"z_stream\s+\w+\s*=\s*\{0\}", code), (
            "Expected 'z_stream <name> = {0};' but got:\n" + code)

        # 2. The API call passes the ADDRESS of that stack struct.
        code_nospace = code.replace(" ", "")
        assert "deflateInit_(&" in code_nospace, (
            "Expected deflateInit_(&<var>, …) but got:\n" + code)

        # 3. No 'z_stream * name = NULL' declaration.
        assert not re.search(r"z_stream\s*\*\s*\w+\s*=\s*NULL", code), (
            "Got NULL pointer for z_stream — _is_caller_alloc_struct fix missing:\n"
            + code)
    finally:
        DataLayout._instance = prev


def test_init_struct_renders_stack_alloc_full_struct():
    """OUTPUT z_stream* (full struct mapping) → same stack + address shape.

    Exercises the existing ``_complete_value_struct`` path. The fix must not
    break this case (it only adds a fallback after _complete_value_struct fails).
    """
    prev = DataLayout._instance
    DataLayout._instance = None
    try:
        dl = DataLayout.instance()
        _layout_with_full_struct(dl)

        model = reconcile([_DEFLATE_INIT_DICT])
        sk = SkeletonGenerator().generate(
            api_sequence=[_DEFLATE_INIT_API],
            driver_name="t",
            is_cpp=False,
            dep_model=model,
        )
        code = SkeletonRenderer().render(sk)

        assert re.search(r"z_stream\s+\w+\s*=\s*\{0\}", code), (
            "Expected 'z_stream <name> = {0};' but got:\n" + code)
        code_nospace = code.replace(" ", "")
        assert "deflateInit_(&" in code_nospace, code
        assert not re.search(r"z_stream\s*\*\s*\w+\s*=\s*NULL", code), code
    finally:
        DataLayout._instance = prev


def test_unpopulated_layout_falls_back_gracefully():
    """Without DataLayout sizing info, fall back to NULL without crashing."""
    prev = DataLayout._instance
    DataLayout._instance = None
    try:
        DataLayout.instance()     # empty layout, no z_stream entry
        model = reconcile([_DEFLATE_INIT_DICT])
        sk = SkeletonGenerator().generate(
            api_sequence=[_DEFLATE_INIT_API],
            driver_name="t",
            is_cpp=False,
            dep_model=model,
        )
        code = SkeletonRenderer().render(sk)
        # Must not crash; the API call must appear (even with NULL arg).
        assert "deflateInit_" in code
    finally:
        DataLayout._instance = prev
