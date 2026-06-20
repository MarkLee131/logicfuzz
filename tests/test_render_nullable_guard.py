"""Task 11 — defense-in-depth render guard: the renderer reads the model's
evidence-based ``ArgSemantics.nullable`` and, for a ``nullable=False`` HANDLE_IN
arg STILL UNBOUND at render, wraps the consumer call in ``if (handle) { ... }``
instead of passing a bare NULL. The validity contract is unconditional
(graduated 2026-06-20, switch removed).
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.common import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, render_skeleton,
)
from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole, ArgRole, ArgSemantics,
)


def _arg(name, t):
    return Arg(name=name, flag="", size=0, type=t, is_const=[False])


# A lone consumer that REQUIRES a non-null handle, with NO producer in the
# sequence -> the handle var renders NULL/unbound.
CONSUMER = Api(
    function_name="cmsGetColorSpace", is_vararg=False,
    return_info=_arg("ret", "int"),
    arguments_info=[_arg("hProfile", "void *")],
    namespace=[],
)


def _model(nullable):
    return APISemanticModel("lcms", {
        "cmsGetColorSpace": APISemantics(
            name="cmsGetColorSpace", role=APIRole.CONSUMER, role_confidence=0.9,
            args=(ArgSemantics(index=0, role=ArgRole.HANDLE_IN,
                               type_str="cmsHPROFILE", nullable=nullable),),
        )})


def _render(model):
    gen = SkeletonGenerator()
    sk = gen.generate(api_sequence=[CONSUMER], driver_name="t", dep_model=model)
    return render_skeleton(sk)


def test_gate_on_wraps_unbound_nonnull_handle_in_guard():
    code = _render(_model(nullable=False))
    # the consumer call is wrapped in if (hProfile...) { ... }
    assert "if (hProfile_cmsGetColorSpace)" in code
    # and the call is inside that guard
    guard_pos = code.index("if (hProfile_cmsGetColorSpace)")
    call_pos = code.index("cmsGetColorSpace(hProfile_cmsGetColorSpace)")
    assert guard_pos < call_pos


def test_nullable_handle_not_guarded_even_gate_on():
    code = _render(_model(nullable=True))
    assert "if (hProfile_cmsGetColorSpace)" not in code
