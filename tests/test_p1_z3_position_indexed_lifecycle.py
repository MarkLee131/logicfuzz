"""Pin position-indexed Z3 lifecycle validation behaviour.

Regression test for the 2026-05-22 fix to ``Z3SequenceValidator``: the
legacy encoding quantified lifecycle constraints over the *API-name set*
and generated cyclic ``order_c < order_u`` pairs whenever a single API
name appeared in both ``creates`` and ``uses`` for the same type
(chained-builder APIs like cjson's ``cJSON_Add*`` family — return a
fresh node AND mutate the parent). That structurally rejected 10/10
cjson sequences. The fix re-quantifies over *positions* and reduces
the check to a deterministic left-to-right walk.

See ``docs/z3_skeleton_synthesis_problem_2026_05.md`` §3.6 for the
empirical root-cause analysis.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.common import (  # noqa: E402
    Api,
    Access,
    AccessType,
    AccessTypeSet,
    FunctionConditions,
    ValueMetadata,
)
from liberator_adapter.common.api import Arg  # noqa: E402
from liberator_adapter.constraints.z3_solver import (  # noqa: E402
    Z3SequenceValidator,
)


def _ats(*entries) -> AccessTypeSet:
    """Build an AccessTypeSet from (access, type_string) tuples."""
    s = AccessTypeSet(set())
    for access, type_string in entries:
        s.access_type_set.add(
            AccessType(access=access, type=type_string,
                       type_string=type_string, fields=[])
        )
    return s


def _vmd(*entries) -> ValueMetadata:
    return ValueMetadata(
        ats=_ats(*entries),
        is_array=False, is_malloc_size=False, is_file_path=False,
        len_depends_on="", setby_dependencies=[],
    )


def _api(name: str, return_type: str = "") -> Api:
    return Api(
        function_name=name, is_vararg=False,
        return_info=Arg(name="", flag="", size=0, type=return_type,
                        is_const=False),
        arguments_info=[], namespace=[],
    )


# ---------------------------------------------------------------------------
# Test fixtures modeling the cjson failure mode
# ---------------------------------------------------------------------------

def _cjson_like_conditions():
    """Minimal conditions matching the cjson Add*/Create* duality.

    - ``Parse``: return CREATEs cJSON*, arg READs i8* (fuzzer input).
    - ``AddBool``: return CREATEs cJSON* AND READ/WRITE on cJSON* arg
      (the chained-builder duality that broke the legacy encoder).
    - ``Delete``: arg has DELETE on cJSON*.
    - ``IsArray``: arg READ on cJSON*, return is i32.
    """
    parse = FunctionConditions(
        function_name="cJSON_Parse",
        argument_at=[_vmd((Access.READ, "i8*"))],
        return_at=_vmd((Access.CREATE, "cJSON*")),
    )
    add_bool = FunctionConditions(
        function_name="cJSON_AddBool",
        argument_at=[
            _vmd((Access.READ, "cJSON*"), (Access.WRITE, "cJSON*")),
            _vmd((Access.READ, "i8*")),
            _vmd((Access.READ, "i32")),
        ],
        return_at=_vmd((Access.CREATE, "cJSON*")),
    )
    delete = FunctionConditions(
        function_name="cJSON_Delete",
        argument_at=[_vmd((Access.DELETE, "cJSON*"))],
        return_at=_vmd(),
    )
    is_array = FunctionConditions(
        function_name="cJSON_IsArray",
        argument_at=[_vmd((Access.READ, "cJSON*"))],
        return_at=_vmd(),
    )
    return {
        "cJSON_Parse": parse, "cJSON_AddBool": add_bool,
        "cJSON_Delete": delete, "cJSON_IsArray": is_array,
    }


def _apis(*names: str) -> List[Api]:
    return [_api(n) for n in names]


# ---------------------------------------------------------------------------
# Position-indexed lifecycle: the cases that broke the legacy encoder
# ---------------------------------------------------------------------------

def test_chained_builder_sequence_passes():
    """``[Parse, AddBool, AddBool]`` — Parse creates cJSON*, then two
    Adds use+create. Legacy: UNSAT (cyclic order over the API-name
    set). New: pass — position-indexed sees Parse at 0 creates cJSON*,
    AddBool at 1/2 has its USE satisfied by position 0."""
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(
        _apis("cJSON_Parse", "cJSON_AddBool", "cJSON_AddBool"), cm)
    assert ok, f"expected pass, got violations: {viols}"


def test_parse_then_delete_passes():
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(
        _apis("cJSON_Parse", "cJSON_Delete"), cm)
    assert ok, viols


def test_use_before_create_rejected():
    """USE on cJSON* at position 0 with no prior CREATE → real violation."""
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(
        _apis("cJSON_IsArray", "cJSON_Parse"), cm)
    assert not ok
    assert any("uses type cJSON*" in v for v in viols), viols


def test_delete_before_create_rejected():
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(
        _apis("cJSON_Delete", "cJSON_Parse"), cm)
    assert not ok
    assert any("deletes type cJSON*" in v for v in viols), viols


def test_fuzzer_input_primitive_not_required_to_be_created():
    """``cJSON_Parse(const char* input)`` USEs ``i8*`` but no cjson API
    creates ``i8*`` (it's fuzzer input). Position-indexed should NOT
    require a creator for types nothing in the sequence creates."""
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(_apis("cJSON_Parse"), cm)
    assert ok, f"single Parse(i8*) must pass; got: {viols}"


def test_empty_sequence_passes():
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence([], cm)
    assert ok and viols == []


def test_repeated_chained_builder_no_cyclic_unsat():
    """The legacy encoder rejected ``[Parse, AddBool, AddBool]`` because
    ``order_AddBool == 1`` (first occurrence) and the lifecycle pair
    ``order_AddBool < order_Parse`` (AddBool both creates and uses
    cJSON*) gave ``1 < 0`` → UNSAT. Position-indexed has no per-name
    order var, so this can't happen."""
    cm = _cjson_like_conditions()
    v = Z3SequenceValidator()
    ok, viols = v.validate_sequence(
        _apis("cJSON_Parse",
              "cJSON_AddBool", "cJSON_AddBool", "cJSON_AddBool"), cm)
    assert ok, f"chained-builder repeat must pass; got: {viols}"
