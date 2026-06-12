"""Role-first skeleton rendering (binding/render bug fix).

The deterministic renderer was role-BLIND: it re-guessed each arg from its C
type, rendering NULL on a real INPUT_BUFFER (parser bails every input → preflight
edges=0) and ``(void*)data`` on a HANDLE (garbage handle). When the reconciled
model is threaded in (dep_model), the renderer must route by ArgRole:
  INPUT_BUFFER → (void*)data ;  LENGTH → size ;  HANDLE_IN → NULL (never data).
With no model the legacy heuristics stay byte-identical.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.api_semantic_model import reconcile, ArgRole  # noqa: E402
from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, SkeletonRenderer,
)


def _arg(n, t, c=False):
    return Arg(name=n, flag="", size=0, type=t, is_const=[c],
               is_type_incomplete=False)


def _api(n, rt, args):
    return Api(function_name=n, is_vararg=False,
               return_info=_arg("r", rt), arguments_info=args, namespace=[])


# A non-entry parser: HANDLE_IN, INPUT_BUFFER, LENGTH — the driver-33/16 archetype.
_APIS_DICT = [
    {"function_name": "thing_create", "arguments": [],
     "return_type": "Thing *", "is_vararg": False, "namespace": []},
    {"function_name": "thing_parse",
     "arguments": [
         {"type": "Thing *", "is_const": [False], "name": "t"},        # HANDLE_IN
         {"type": "const void *", "is_const": [True], "name": "mem"},   # INPUT_BUFFER
         {"type": "unsigned int", "is_const": [False], "name": "len"},  # LENGTH
     ], "return_type": "int", "is_vararg": False, "namespace": []},
]


def _seq():
    return [
        _api("thing_create", "Thing *", []),
        _api("thing_parse", "int", [
            _arg("t", "Thing *"), _arg("mem", "const void *", True),
            _arg("len", "unsigned int")]),
    ]


def _render(dep_model):
    os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)
    sk = SkeletonGenerator().generate(
        api_sequence=_seq(), driver_name="t", is_cpp=False, dep_model=dep_model)
    return SkeletonRenderer().render(sk)


def test_model_assigns_the_roles_we_rely_on():
    model = reconcile(_APIS_DICT)
    roles = {a.index: a.role for a in model.apis["thing_parse"].args}
    assert roles.get(1) is ArgRole.INPUT_BUFFER, roles
    assert roles.get(2) is ArgRole.LENGTH, roles
    assert roles.get(0) is ArgRole.HANDLE_IN, roles


def test_role_first_wires_buffer_and_length_not_handle():
    code = _render(reconcile(_APIS_DICT))
    # INPUT_BUFFER (mem) → (void*)data, and it is the ONLY data-wired arg
    # (the HANDLE must NOT get (void*)data — that was the bug).
    assert "(void*)data" in code, code
    assert code.count("(void*)data") == 1, code
    # LENGTH (len) → size, not 0
    assert re.search(r"=\s*\(unsigned int\)size", code), code
    # thing_parse is actually called with the wired buffer
    assert "thing_parse(" in code


def test_no_model_leaves_buffer_unwired_legacy():
    # The contrast: with NO model, the non-entry const-void* buffer stays the
    # legacy degraded NULL (this is exactly the edges=0 bug the role fix cures).
    code = _render(None)
    assert "(void*)data" not in code, (
        "without a model the non-entry buffer must stay legacy (NULL), proving "
        "role-routing is what wires it:\n" + code)
