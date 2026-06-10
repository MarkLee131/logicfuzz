"""Pin down VALID-C-BY-CONSTRUCTION on the skeleton renderer.

Six classes of invalid C were observed on real lcms skeletons (each fails to
build → the driver is excluded/stubbed in the merged harness):

  1. ``void name[N]``                      — a VOID array (illegal C).
  2. undeclared ``ret_*`` referenced in a guard/cleanup as a function.
  3. a struct/union VALUE initialized with ``= 0`` / NULL-compared.
  4. an opaque/incomplete struct used as a VALUE ARRAY (``cmsToneCurve x[N]``).
  5. ``#include "*_internal.h"`` — a non-public header.
  6. an internal opaque struct name (``_cmsContext_struct *``) — not visible
     through the public header.

These tests render skeletons for representative API *shapes* (not lcms by
name) and assert none of the six classes can be emitted. The fix lives in
``liberator_adapter/driver/synthesis/skeleton_generator.py`` (type/decl/header
rules), so the guard is shape-driven and survives renaming.
"""
from __future__ import annotations

import os
import re
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ------------------------------------------------------------------ fixtures

def _make_arg(name: str, type_str: str, is_const: bool = False, flag: str = ""):
    from liberator_adapter.common.api import Arg
    return Arg(
        name=name,
        flag=flag,
        size=0,
        type=type_str,
        is_const=[is_const] * (type_str.count('*') + 1 or 1),
        is_type_incomplete=False,
    )


def _make_api(name: str, ret_type: str, args, flag: str = ""):
    from liberator_adapter.common.api import Api
    return Api(
        function_name=name,
        is_vararg=False,
        return_info=_make_arg("return", ret_type, flag=flag),
        arguments_info=args,
        namespace=[],
    )


def _render(api_sequence, **kwargs):
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator, SkeletonRenderer,
    )
    sk = SkeletonGenerator().generate(
        api_sequence=api_sequence,
        driver_name="t_valid_c",
        is_cpp=False,
        **kwargs,
    )
    return sk, SkeletonRenderer().render(sk)


# ------------------------------------------------------------ generic asserts

def _assert_no_void_array(code: str):
    """No declaration of the form ``void <name>[`` (a void array)."""
    bad = re.findall(r'\bvoid\s+\w+\s*\[', code)
    assert not bad, f"void array(s) emitted: {bad}\n---\n{code}"


def _assert_no_undeclared_ret_calls(code: str):
    """Every ``ret_<x>`` used as a CALLEE (``ret_x(...)``) must be declared
    as a variable somewhere. (Declared ``ret_x`` vars are fine as arguments;
    only an undeclared identifier used as a *function* is the bug.)"""
    declared = set(re.findall(r'\b(ret_\w+)\s*=', code))  # ``ret_x = ...``
    declared |= set(re.findall(r'\b\w[\w\s\*]*?\b(ret_\w+)\s*[;=]', code))
    callees = set(re.findall(r'\b(ret_\w+)\s*\(', code))
    undeclared = callees - declared
    assert not undeclared, (
        f"undeclared ret_* used as a function: {undeclared}\n---\n{code}")


def _assert_no_internal_header(code: str):
    bad = re.findall(r'#include\s*[<"][^>"]*'
                     r'(?:_internal|_private|_impl|_detail)\.h', code)
    assert not bad, f"internal header included: {bad}\n---\n{code}"


def _assert_no_internal_typename(code: str):
    """No leading-underscore opaque struct typedef name in a declaration."""
    bad = re.findall(r'\b_\w*_struct\b', code)
    assert not bad, f"internal opaque type name emitted: {bad}\n---\n{code}"


def _assert_no_struct_eq_null_or_zero(code: str, struct_var: str):
    assert f"{struct_var} == NULL" not in code, (
        f"struct value NULL-compared: {struct_var}\n---\n{code}")
    assert not re.search(rf'\b{re.escape(struct_var)}\s*=\s*0\s*;', code), (
        f"struct value initialized with = 0: {struct_var}\n---\n{code}")


# ============================================================ per-bug tests

def test_void_pointer_output_arg_is_byte_buffer_not_void_array():
    """Bug 1: a ``void *`` output arg on a NON-entry API must render as a
    ``uint8_t`` buffer, never ``void name[N]``. (The entry API's pointer is
    rebound to the fuzz stream by the B4 safety net, a separate path.)"""
    entry = _make_api(
        "lib_entry",
        ret_type="int",
        args=[_make_arg("in", "const char *", is_const=True)],
    )
    api = _make_api(
        "lib_get_blob",
        ret_type="int",
        args=[_make_arg("out", "void *")],   # non-const ptr ⇒ output param
    )
    _, code = _render([entry, api])
    _assert_no_void_array(code)
    assert re.search(r'\b(uint8_t|unsigned char)\s+\w+\s*\[', code), (
        f"expected a uint8_t/unsigned char byte buffer\n---\n{code}")


def test_opaque_handle_arg_is_pointer_not_value_array():
    """Bug 4: an opaque handle type (forward-declared / by-ref) used as a
    pointer-to-pointer output must become an ARRAY OF POINTERS (each element
    is a complete pointer), never a value array of the incomplete type."""
    entry = _make_api("lib_entry", "int",
                      [_make_arg("in", "const char *", is_const=True)])
    api = _make_api(
        "lib_get_curves",
        ret_type="int",
        args=[_make_arg("curves", "OpaqueCurve * *")],
    )
    _, code = _render([entry, api])
    # No bare value array of the incomplete element type.
    assert not re.search(r'\bOpaqueCurve\s+\w+\s*\[', code), (
        f"opaque type used as a value array\n---\n{code}")
    # It MUST appear as a pointer (array-of-pointers or single pointer).
    assert re.search(r'OpaqueCurve\s*\*', code), (
        f"opaque handle not rendered as a pointer\n---\n{code}")


def test_opaque_single_pointer_output_degrades_to_pointer():
    """Bug 4 variant: a single-pointer opaque handle out-arg (can't size the
    incomplete element) degrades to a typed pointer, not a value array."""
    entry = _make_api("lib_entry", "int",
                      [_make_arg("in", "const char *", is_const=True)])
    api = _make_api(
        "lib_open_io",
        ret_type="int",
        args=[_make_arg("io", "cmsIOHANDLER *")],
    )
    sk, code = _render([entry, api])
    var = sk.variables.get("io_lib_open_io")
    assert var is not None
    assert not var.is_array, "opaque single-pointer must not be a value array"
    assert var.is_pointer
    assert not re.search(r'\bcmsIOHANDLER\s+\w+\s*\[', code), code


def test_scalar_output_arg_is_value_array():
    """Recognized scalar element types KEEP the buffer behavior (valid C).

    Uses an ``unsigned short`` element (a primitive) on a NON-entry API.
    (``uint16_t`` is avoided: its ``_t`` suffix trips the renderer's
    callback-param heuristic — a pre-existing, separate false-positive.)"""
    entry = _make_api("lib_entry", "int",
                      [_make_arg("in", "const char *", is_const=True)])
    api = _make_api(
        "lib_read_u16",
        ret_type="int",
        args=[_make_arg("buf", "unsigned short *")],
    )
    sk, code = _render([entry, api])
    var = sk.variables.get("buf_lib_read_u16")
    assert var is not None and var.is_array
    _assert_no_void_array(code)


def test_internal_opaque_return_type_rendered_as_void_pointer():
    """Bug 6: a return whose type is an internal opaque struct
    (``_cmsContext_struct *``) must be declared as ``void *`` — the internal
    name is not visible through the public header."""
    api = _make_api(
        "lib_get_ctx",
        ret_type="_cmsContext_struct *",
        args=[_make_arg("h", "void *")],
        flag="ref",
    )
    sk, code = _render([api])
    _assert_no_internal_typename(code)
    ret = sk.variables.get("ret_lib_get_ctx")
    assert ret is not None
    assert ret.c_type.strip() == "void *", ret.c_type
    assert ret.init_value == "NULL"


def test_internal_opaque_pointer_arg_rendered_as_void_pointer():
    """Bug 6 variant: an internal opaque struct POINTER arg also becomes
    ``void *`` (so the driver compiles against the public API surface)."""
    api = _make_api(
        "lib_use_ctx",
        ret_type="int",
        args=[_make_arg("ctx", "_cmsContext_struct *", flag="ref")],
    )
    sk, code = _render([api])
    _assert_no_internal_typename(code)


def test_struct_by_value_arg_zero_initialized_with_braces():
    """Bug 3: a struct/union VALUE arg must be ``{0}``-initialized, never
    ``= 0`` (illegal for an aggregate) and never NULL-compared."""
    api = _make_api(
        "lib_take_id",
        ret_type="int",
        args=[_make_arg("id", "struct ProfileID")],
    )
    sk, code = _render([api])
    var = sk.variables.get("id_lib_take_id")
    assert var is not None
    assert var.init_value == "{0}", var.init_value
    _assert_no_struct_eq_null_or_zero(code, "id_lib_take_id")


def test_enum_by_value_arg_uses_plain_zero_not_braces():
    """Counter-case to bug 3: an enum / scalar typedef value must keep
    ``= 0`` (``{0}`` is rejected for a scoped enum under C++)."""
    api = _make_api(
        "lib_take_sig",
        ret_type="int",
        args=[_make_arg("sig", "cmsTagSignature")],
    )
    sk, _ = _render([api])
    var = sk.variables.get("sig_lib_take_sig")
    assert var is not None
    assert var.init_value == "0", var.init_value


def test_internal_header_never_included():
    """Bug 5: the renderer must only emit public headers."""
    api = _make_api("lib_noop", ret_type="int",
                    args=[_make_arg("x", "int")])
    _, code = _render([api])
    _assert_no_internal_header(code)


def test_destroyer_cleanup_references_only_declared_vars():
    """Bug 2: cleanup/guards must never reference an undeclared ``ret_*`` as a
    function. A producer→consumer chain (the shape that triggered the bug:
    ``source_api`` was set to a wired var name like ``ret_open`` → cleanup
    emitted ``ret_close(...)``) must keep every ``ret_*`` callee declared."""
    creator = _make_api(
        "lib_open",
        ret_type="Handle *",
        args=[_make_arg("path", "const char *", is_const=True)],
    )
    consumer = _make_api(
        "lib_write",
        ret_type="int",
        args=[
            _make_arg("h", "void *"),          # consumes the handle
            _make_arg("n", "unsigned int"),
        ],
    )
    bindings = {("lib_write", 0): "ret_lib_open"}
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator, SkeletonRenderer,
    )
    sk = SkeletonGenerator().generate(
        api_sequence=[creator, consumer],
        driver_name="t_chain_cleanup",
        is_cpp=False,
        arg_bindings=bindings,
    )
    code = SkeletonRenderer().render(sk)
    _assert_no_undeclared_ret_calls(code)
    # The consumer arg that was wired must NOT carry source_api (it owns no
    # resource) — only the producer return handle may.
    consumer_arg = sk.variables.get("h_lib_write")
    assert consumer_arg is not None
    assert consumer_arg.source_api is None
    ret_handle = sk.variables.get("ret_lib_open")
    assert ret_handle is not None
    assert ret_handle.source_api == "lib_open"


# ------------------------------------------------------ combined / end-to-end

def test_mixed_lcms_like_sequence_is_clean_of_all_six_classes():
    """An lcms-shaped sequence (the one that surfaced all six classes) must
    render free of every class at once."""
    seq = [
        _make_api("cmsOpenProfileFromMem", "void *",
                  [_make_arg("MemPtr", "const void *", is_const=True),
                   _make_arg("dwSize", "unsigned int")]),
        _make_api("cmsWriteRawTag", "int",
                  [_make_arg("hProfile", "void *"),
                   _make_arg("sig", "cmsTagSignature"),
                   _make_arg("data", "const void *", is_const=True),
                   _make_arg("Size", "unsigned int")]),
        _make_api("cmsGetProfileContextID", "_cmsContext_struct *",
                  [_make_arg("hProfile", "void *")], flag="ref"),
        _make_api("cmsCreateLinearizationDeviceLink", "void *",
                  [_make_arg("ColorSpace", "cmsColorSpaceSignature"),
                   _make_arg("TransferFunctions", "cmsToneCurve * *")]),
        _make_api("cmsCloseProfile", "int",
                  [_make_arg("hProfile", "void *")]),
    ]
    _, code = _render([
        a for a in seq
    ], arg_bindings={
        ("cmsWriteRawTag", 0): "ret_cmsOpenProfileFromMem",
        ("cmsGetProfileContextID", 0): "ret_cmsOpenProfileFromMem",
        ("cmsCloseProfile", 0): "ret_cmsOpenProfileFromMem",
    })
    _assert_no_void_array(code)
    _assert_no_undeclared_ret_calls(code)
    _assert_no_internal_header(code)
    _assert_no_internal_typename(code)
    # cmsToneCurve must never be a value array (it's opaque/forward-declared).
    assert not re.search(r'\bcmsToneCurve\s+\w+\s*\[', code), code


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
