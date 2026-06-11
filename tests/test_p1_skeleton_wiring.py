"""Pin down the producer→consumer wiring contract on SkeletonGenerator.

Background — the bug we're guarding against
-------------------------------------------
``SkeletonGenerator.generate(api_sequence, ...)`` historically created a
fresh per-API local variable for every input arg, initialised to NULL/0.
For sequences that chain handles across APIs (cJSON_Parse → cJSON_Print,
ucl_parser_new → ucl_parser_add_chunk), that meant the consumer call
received NULL even though the right value was sitting in ``ret_<prev>``.

The fix splits responsibility:
  - **Upstream Liberator's RunningContext** (the adapter port at
    ``liberator_adapter/constraints/RunningContext.py``) does the wiring
    decision via ``try_to_get_var`` (sink/init/setby/source aware).
  - **CBFactory** drives ``try_to_instantiate_api_call`` over the
    caller's sequence and translates Variable identities into a
    ``(api_name, arg_idx) -> "ret_<prev_api>"`` map.
  - **SkeletonGenerator** (this module's tests) consumes that map via
    the ``arg_bindings`` kwarg on ``generate``. It does NOT make wiring
    decisions on its own — it just renders.

These tests pin SkeletonGenerator's renderer contract: given bindings,
it overrides consumer var ``init_value``; without bindings, it falls
back to NULL/0.
"""
from __future__ import annotations

import os
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _make_arg(name: str, type_str: str, is_const: bool = False):
    """Minimal Arg fixture. flag='' since LLVM-IR struct detection is not
    needed for our handle-chain tests (we use plain typedef pointers)."""
    from liberator_adapter.common.api import Arg
    return Arg(
        name=name,
        flag="",
        size=0,
        type=type_str,
        is_const=[is_const],
        is_type_incomplete=False,
    )


def _make_api(name: str, ret_type: str, args):
    from liberator_adapter.common.api import Api
    return Api(
        function_name=name,
        is_vararg=False,
        return_info=_make_arg("return", ret_type),
        arguments_info=args,
        namespace=[],
    )


# ============================================================
# arg_bindings consumption — positive cases
# ============================================================

def test_arg_binding_wires_live_producer_return_into_call():
    """When arg_bindings provides a wiring for (api, idx), the consumer arg must
    receive the producer's LIVE return at the CALL SITE — not via the decl init.

    Regression for the 2026-06 NULL-snapshot bug: the wiring used to be applied
    as ``var.init_value`` → the declaration ``cJSON* item = ret_cJSON_Parse;``
    rendered in the decl block BEFORE the producer call ran, so ``item`` captured
    NULL. The fix stores it on ``var.bound_expr`` and passes it directly as the
    call argument."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator,
    )

    parse = _make_api(
        "cJSON_Parse",
        ret_type="cJSON*",
        args=[_make_arg("value", "const char*", is_const=True)],
    )
    printer = _make_api(
        "cJSON_Print",
        ret_type="char*",
        args=[_make_arg("item", "const cJSON*", is_const=True)],
    )

    bindings = {("cJSON_Print", 0): "ret_cJSON_Parse"}

    sk = SkeletonGenerator().generate(
        api_sequence=[parse, printer],
        driver_name="t_chain",
        is_cpp=False,
        arg_bindings=bindings,
    )

    item_var = sk.variables.get("item_cJSON_Print")
    assert item_var is not None
    # Wiring lives on bound_expr (the call-site expression), NOT init_value (the
    # decl snapshot that would capture NULL).
    assert item_var.bound_expr == "ret_cJSON_Parse", (
        f"expected wired bound_expr=ret_cJSON_Parse, got {item_var.bound_expr!r}"
    )
    # And the rendered consumer call must pass the LIVE producer return.
    rendered = sk.to_dict().get('code', '')
    assert "cJSON_Print(ret_cJSON_Parse)" in rendered, (
        f"consumer call must pass the live producer return, not a NULL "
        f"snapshot; rendered:\n{rendered}"
    )
    assert sk.metadata.get('wired_args', 0) == 1


def test_no_bindings_means_default_null():
    """Without arg_bindings, the renderer keeps NULL/0 inits — the
    pre-fix behavior. This pins the 'no regression' invariant for
    callers that don't compute bindings (e.g. the legacy
    ``generate_skeleton_for_sequence`` convenience helper).

    Note: type avoids ``_t`` / ``_func`` / ``_callback`` / ``_handler``
    suffixes, which the SkeletonGenerator's heuristic ``_is_callback_param``
    treats as function-pointer typedefs (a known false-positive)."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator,
    )

    api = _make_api(
        "stand_alone_api",
        ret_type="int",
        args=[_make_arg("handle", "const MyObj*", is_const=True)],
    )

    sk = SkeletonGenerator().generate(
        api_sequence=[api],
        driver_name="t_fallback",
        is_cpp=False,
    )
    handle_var = sk.variables.get("handle_stand_alone_api")
    assert handle_var is not None
    assert handle_var.init_value == "NULL"
    assert 'wired_args' not in sk.metadata


def test_empty_bindings_is_no_op():
    """Empty bindings dict (CBFactory found no cross-API reuse) must
    behave identically to no bindings — pure NULL fallback."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator,
    )

    api = _make_api(
        "stand_alone_api",
        ret_type="int",
        args=[_make_arg("handle", "const MyObj*", is_const=True)],
    )

    sk = SkeletonGenerator().generate(
        api_sequence=[api],
        driver_name="t_emptybindings",
        is_cpp=False,
        arg_bindings={},
    )
    handle_var = sk.variables.get("handle_stand_alone_api")
    assert handle_var is not None
    assert handle_var.init_value == "NULL"
    assert sk.metadata.get('wired_args', 0) == 0


# ============================================================
# arg_bindings consumption — negative / safety cases
# ============================================================

def test_callback_var_not_overridden_by_binding():
    """Callback args become CALLBACK_IMPL holes (var.init_value is a
    placeholder starting with ``__``). A binding for that arg must be
    ignored — callbacks are LLM territory, not handle reuse."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator,
    )

    register = _make_api(
        "register_handler",
        ret_type="int",
        args=[
            _make_arg("on_event", "void (*on_event)(int)"),
        ],
    )
    bindings = {("register_handler", 0): "ret_some_other_api"}

    sk = SkeletonGenerator().generate(
        api_sequence=[register],
        driver_name="t_cb",
        is_cpp=False,
        arg_bindings=bindings,
    )
    cb_var = sk.variables.get("on_event_register_handler")
    assert cb_var is not None
    # Callback hole placeholder retained; binding ignored.
    assert cb_var.init_value is not None
    assert cb_var.init_value.startswith("__"), (
        f"callback param must keep its hole placeholder, "
        f"got {cb_var.init_value!r}"
    )


def test_unmatched_binding_key_is_ignored():
    """A binding for a (api, idx) that doesn't exist in the skeleton's
    var map must not crash and must not bind anything."""
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator,
    )

    api = _make_api(
        "lone_api",
        ret_type="int",
        args=[_make_arg("only_arg", "const Widget*", is_const=True)],
    )
    bindings = {
        # Wrong api name — should be ignored.
        ("phantom_api", 0): "ret_phantom",
        # Wrong idx — out of range; should be ignored.
        ("lone_api", 99): "ret_phantom",
    }
    sk = SkeletonGenerator().generate(
        api_sequence=[api],
        driver_name="t_unmatched",
        is_cpp=False,
        arg_bindings=bindings,
    )
    only_var = sk.variables.get("only_arg_lone_api")
    assert only_var is not None
    assert only_var.init_value == "NULL"
    assert sk.metadata.get('wired_args', 0) == 0


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
