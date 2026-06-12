"""FIX C — a tunable CONFIG scalar/enum arg renders as a FUZZABLE value hole.

A hole-LESS skeleton makes the LLM key its value rewrite by VARIABLE NAME →
dropped by the #1a merge whitelist → floor ``= 0`` (e.g. cmsCreateTransform
InputFormat=0 → returns NULL → the object-construction chain is dead → edges=0).
Rendering the CONFIG scalar as ``__INIT_<var>__`` lets the LLM's valid-constant
fill (TYPE_RGB_8) apply PLACEHOLDER-keyed (survives #1a) so construction
succeeds. An UNFILLED hole degrades to ``0`` in the merge (floor-safe). Opt-out
``LOGICFUZZ_FUZZABLE_HOLES=0`` restores the fixed ``= 0`` floor.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:  # double-attempt works around the src.agents↔src.workflow import cycle
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
from liberator_adapter.analysis.api_semantic_model import reconcile, ArgRole  # noqa: E402
from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, SkeletonRenderer, _is_tunable_scalar,
)


def _arg(n, t, c=False):
    return Arg(name=n, flag="", size=0, type=t, is_const=[c],
               is_type_incomplete=False)


def _api(n, rt, args):
    return Api(function_name=n, is_vararg=False,
               return_info=_arg("r", rt), arguments_info=args, namespace=[])


# A creator + a CONFIG-heavy consumer (the cmsCreateTransform archetype):
# handle in, two integer format CONFIG args.
_APIS_DICT = [
    {"function_name": "make_xform",
     "arguments": [
         {"type": "void *", "is_const": [False], "name": "prof"},     # HANDLE_IN
         {"type": "unsigned int", "is_const": [False], "name": "fmt"},  # CONFIG scalar
     ], "return_type": "void *", "is_vararg": False, "namespace": []},
]


def _seq():
    return [_api("make_xform", "void *",
                 [_arg("prof", "void *"), _arg("fmt", "unsigned int")])]


def _render(env=None):
    if env is not None:
        os.environ["LOGICFUZZ_FUZZABLE_HOLES"] = env
    else:
        os.environ.pop("LOGICFUZZ_FUZZABLE_HOLES", None)
    sk = SkeletonGenerator().generate(
        api_sequence=_seq(), driver_name="t", is_cpp=False,
        dep_model=reconcile(_APIS_DICT))
    return SkeletonRenderer().render(sk)


def test_tunable_scalar_predicate():
    assert _is_tunable_scalar("unsigned int")
    assert _is_tunable_scalar("cmsUInt32Number")        # integer typedef
    assert _is_tunable_scalar("cmsColorSpaceSignature")  # signature typedef
    assert _is_tunable_scalar("double")
    assert not _is_tunable_scalar("void *")              # pointer
    assert not _is_tunable_scalar("cmsCIELab *")         # pointer
    assert not _is_tunable_scalar("char[8]")             # array


def test_model_assigns_config_to_scalar():
    model = reconcile(_APIS_DICT)
    roles = {a.index: a.role for a in model.apis["make_xform"].args}
    assert roles.get(1) is ArgRole.CONFIG, roles


def test_config_scalar_renders_as_init_hole():
    code = _render(env=None)   # default-on
    # the integer CONFIG arg is a fillable hole, NOT a fixed ``= 0``
    assert re.search(r"=\s*__INIT_\w*fmt\w*__", code), code
    assert not re.search(r"unsigned int\s+\w*fmt\w*\s*=\s*0\s*;", code), code


def test_optout_restores_fixed_zero():
    code = _render(env="0")
    assert "__INIT_" not in code, code
    assert re.search(r"=\s*0", code), code
    os.environ.pop("LOGICFUZZ_FUZZABLE_HOLES", None)


class _Dummy:
    trial = 1
    def _fixup_min_size_guard(self, c): return c
    def _validate_filled_driver(self, c): return None


def test_unfilled_config_hole_degrades_to_zero_in_merge():
    # #1b floor path: empty fills → the CONFIG hole must become ``0`` (valid C),
    # never a leftover placeholder.
    skel = ("int LLVMFuzzerTestOneInput(const uint8_t* d, size_t s){\n"
            "  unsigned int fmt = __INIT_fmt_make_xform__;\n"
            "  make_xform(p, fmt);\n  return 0;\n}")
    out = LangGraphPrototyper._merge_holes_into_skeleton(_Dummy(), skel, {})
    assert "__INIT_" not in out, out
    assert "unsigned int fmt = 0;" in out, out


def test_placeholder_keyed_fill_survives():
    # the LLM's valid-constant fill, keyed by the placeholder, applies (the whole
    # point: it survives #1a where a NAME-keyed fill would be dropped).
    skel = ("int f(){ unsigned int fmt = __INIT_fmt_make_xform__; "
            "make_xform(p, fmt); return 0; }")
    out = LangGraphPrototyper._merge_holes_into_skeleton(
        _Dummy(), skel, {"__INIT_fmt_make_xform__": "TYPE_RGB_8"})
    assert "unsigned int fmt = TYPE_RGB_8;" in out, out
    assert "__INIT_" not in out, out
