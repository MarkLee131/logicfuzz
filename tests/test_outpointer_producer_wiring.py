"""A-1 follow-up: out-pointer / caller-alloc-init producers must wire their
DOWNSTREAM consumer.

The model already marks ares_init / deflateInit_ as CREATORs that `produces`
their handle via an OUTPUT arg (not the return value). skeleton_generator already
RENDERS the producer's output local (an array `T *name[N]` for a `T**` out-pointer;
a stack `T name = {0}` for a caller-alloc init struct). But no binder ever pointed
a later consumer's handle arg at that local — every binding value emitted anywhere
is `ret_<api>`, and ares_init/deflateInit_ return `int`. So the consumer rendered
NULL → guard → dead.

These pin the wiring: a consumer handle arg whose type matches an EARLIER OUTPUT
producer's handle binds to that producer's output local — `name[0]` for the `T**`
array shape, `&name` for the caller-alloc value-struct shape — and stays NULL
(safe under-approx) when no such producer was rendered.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator,
)
from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole, ArgRole, ArgSemantics,
)


def _arg(name, t, const=False):
    return Arg(name=name, flag="", size=0, type=t, is_const=[const],
               is_type_incomplete=False)


def _api(name, ret, args):
    return Api(function_name=name, is_vararg=False,
               return_info=_arg("ret", ret),
               arguments_info=[_arg(n, t) for n, t in args], namespace=[])


def _msem(name, role, args):
    return APISemantics(
        name=name, role=role, role_confidence=0.9,
        args=tuple(ArgSemantics(index=i, role=r, type_str=t, nullable=False)
                   for i, (r, t) in enumerate(args)))


def test_outpointer_producer_wires_consumer_to_array_element():
    # ares_init(ares_channel_t **) writes the handle into a T** out-pointer
    # (star_count==2 → renderer makes an array local); ares_destroy consumes the
    # 1-star handle. The consumer must bind to element [0] of the producer local.
    ares_init = _api("ares_init", "int", [("channelptr", "ares_channel_t * *")])
    ares_destroy = _api("ares_destroy", "void", [("channel", "ares_channel_t *")])
    model = APISemanticModel("c-ares", {
        "ares_init": _msem("ares_init", APIRole.CREATOR,
                           [(ArgRole.OUTPUT, "ares_channel_t * *")]),
        "ares_destroy": _msem("ares_destroy", APIRole.DESTROYER,
                              [(ArgRole.HANDLE_IN, "ares_channel_t *")]),
    })
    sk = SkeletonGenerator().generate(
        api_sequence=[ares_init, ares_destroy],
        driver_name="t_ares", is_cpp=False, dep_model=model)

    prod = sk.variables.get("channelptr_ares_init")
    assert prod is not None and prod.is_array, f"producer local: {prod!r}"
    cons = sk.variables.get("channel_ares_destroy")
    assert cons is not None
    assert cons.bound_expr == "channelptr_ares_init[0]", \
        f"consumer must bind to the out-local element, got {cons.bound_expr!r}"
    code = sk.to_dict().get('code', '')
    assert "ares_destroy(channelptr_ares_init[0])" in code, code


def test_outpointer_producer_array_is_zero_initialized():
    # Safety for the wiring above: the consumer now READS producer_local[0]. If
    # the producer FAILED (returned error without writing [0]), an uninitialized
    # array would hand the consumer GARBAGE → crash (over-approx / crash-poison).
    # Zero-initialize the OUTPUT array so the failure path is a safe NULL handle.
    ares_init = _api("ares_init", "int", [("channelptr", "ares_channel_t * *")])
    ares_destroy = _api("ares_destroy", "void", [("channel", "ares_channel_t *")])
    model = APISemanticModel("c-ares", {
        "ares_init": _msem("ares_init", APIRole.CREATOR,
                           [(ArgRole.OUTPUT, "ares_channel_t * *")]),
        "ares_destroy": _msem("ares_destroy", APIRole.DESTROYER,
                              [(ArgRole.HANDLE_IN, "ares_channel_t *")]),
    })
    sk = SkeletonGenerator().generate(
        api_sequence=[ares_init, ares_destroy],
        driver_name="t_ares_zi", is_cpp=False, dep_model=model)
    prod = sk.variables.get("channelptr_ares_init")
    assert prod is not None and prod.is_array
    assert prod.init_value == "{0}", prod.init_value
    assert prod.get_declaration().rstrip().endswith("= {0}"), \
        prod.get_declaration()


def test_caller_alloc_init_wires_consumer_with_address_of():
    # zlib shape: deflateInit_(z_stream*) renders a caller-alloc value local
    # ``z_stream strm = {0}`` and the producing call passes ``&strm``. A later
    # deflate(z_stream*) consumer must bind to that SAME ``&strm`` address. This
    # exercises the caller-alloc (``&name``) branch of _wire_output_producers
    # directly (the renderer's caller-alloc gate needs a real DataLayout, whose
    # singleton must not be mutated in a unit test — see the known cross-test
    # DataLayout pollution), constructing the post-render skeleton state by hand.
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        DriverSkeleton, SkeletonVariable, AllocationType,
    )
    deflate_init = _api("deflateInit_", "int", [("strm", "z_stream *")])
    deflate = _api("deflate", "int",
                   [("strm", "z_stream *"), ("flush", "int")])
    sk = DriverSkeleton(name="t_zlib", target_apis=[deflate_init, deflate])
    # producer's already-rendered caller-alloc local (value struct, &-passed)
    sk.add_variable(SkeletonVariable(
        name="strm_deflateInit_", c_type="z_stream",
        allocation=AllocationType.STACK, init_value="{0}",
        bound_expr="&strm_deflateInit_"))
    # consumer's unbound NULL handle local
    sk.add_variable(SkeletonVariable(
        name="strm_deflate", c_type="z_stream *", is_pointer=True,
        init_value="NULL"))
    var_requirements = {
        "deflateInit_": {"args": [
            {"idx": 0, "name": "strm", "role": "OUTPUT", "type": "z_stream *"}]},
        "deflate": {"args": [
            {"idx": 0, "name": "strm", "role": "HANDLE_IN", "type": "z_stream *"},
            {"idx": 1, "name": "flush", "role": "CONFIG", "type": "int"}]},
    }
    wired = SkeletonGenerator()._wire_output_producers(
        sk, var_requirements, [deflate_init, deflate])
    assert wired == 1
    assert sk.variables["strm_deflate"].bound_expr == "&strm_deflateInit_", \
        sk.variables["strm_deflate"].bound_expr


def test_no_producer_consumer_stays_null():
    # Under-approx: a handle consumer with NO earlier OUTPUT producer of its type
    # stays NULL (unbound), never a fabricated binding.
    ares_destroy = _api("ares_destroy", "void", [("channel", "ares_channel_t *")])
    model = APISemanticModel("c-ares", {
        "ares_destroy": _msem("ares_destroy", APIRole.DESTROYER,
                              [(ArgRole.HANDLE_IN, "ares_channel_t *")]),
    })
    sk = SkeletonGenerator().generate(
        api_sequence=[ares_destroy], driver_name="t_lone", is_cpp=False,
        dep_model=model)
    cons = sk.variables.get("channel_ares_destroy")
    assert cons is not None
    assert cons.bound_expr is None, cons.bound_expr
