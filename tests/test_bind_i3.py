"""Task 10 — I3 (type-correct binding): in CBFactory._signature_handle_bindings,
a consumer handle arg of family F binds to a producer return of family F (by
handle family from the model's type_str / producer name), NOT the nearest
collapsed void*. ADDITIVE: legacy void* binding is the FALLBACK when family is
unknown. The validity contract is unconditional (graduated 2026-06-20, switch removed).
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.common import Api, Arg  # noqa: E402
from liberator_adapter.driver.factory.constraint_based.CBFactory import (  # noqa: E402
    CBFactory,
)
from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole, ArgRole, ArgSemantics,
)


def _arg(name, t):
    return Arg(name=name, flag="", size=0, type=t, is_const=[False])


def _api(name, ret_type, arg_types):
    return Api(
        function_name=name, is_vararg=False,
        return_info=_arg("ret", ret_type),
        arguments_info=[_arg(f"a{i}", t) for i, t in enumerate(arg_types)],
        namespace=[],
    )


def _msem(name, role, args=()):
    return APISemantics(
        name=name, role=role, role_confidence=0.9,
        args=tuple(ArgSemantics(index=i, role=r, type_str=t, nullable=False)
                   for i, (r, t) in enumerate(args)),
    )


# Opaque-collapsed Api objects: cmsHPROFILE / cmsHTRANSFORM both desugar to
# ``void *`` in the IR, so the legacy binder (nearest void*) wires a profile arg
# to the LAST void* producer = the transform. The model carries the REAL family.
OPEN = _api("cmsOpenProfileFromMem", "void *", ["const void *", "unsigned int"])
XFORM = _api("cmsCreateTransform", "void *",
             ["void *", "unsigned int", "void *", "unsigned int"])
CLOSE = _api("cmsCloseProfile", "void", ["void *"])

SEQ = [OPEN, XFORM, CLOSE]

MODEL = APISemanticModel("lcms", {
    "cmsOpenProfileFromMem": _msem(
        "cmsOpenProfileFromMem", APIRole.CREATOR,
        ((ArgRole.INPUT_BUFFER, "const void *"), (ArgRole.LENGTH, "unsigned int"))),
    "cmsCreateTransform": _msem(
        "cmsCreateTransform", APIRole.CREATOR,
        ((ArgRole.CONFIG, "cmsHPROFILE"), (ArgRole.CONFIG, "unsigned int"),
         (ArgRole.CONFIG, "cmsHPROFILE"), (ArgRole.CONFIG, "unsigned int"))),
    "cmsCloseProfile": _msem(
        "cmsCloseProfile", APIRole.DESTROYER, ((ArgRole.CONFIG, "cmsHPROFILE"),)),
})


def _factory():
    # _signature_handle_bindings only needs `self`; build a bare instance.
    f = CBFactory.__new__(CBFactory)
    return f


def test_gate_on_binds_close_to_profile_not_transform():
    f = _factory()
    b = f._signature_handle_bindings(SEQ, dep_model=MODEL)
    # cmsCloseProfile arg0 must bind to the PROFILE producer, never the xform
    assert b.get(("cmsCloseProfile", 0)) == "ret_cmsOpenProfileFromMem"


def test_no_model_unchanged():
    # No dep_model at all (cjson/zlib path): legacy behavior, no family info.
    f = _factory()
    b = f._signature_handle_bindings(SEQ)   # no dep_model
    assert b.get(("cmsCloseProfile", 0)) == "ret_cmsCreateTransform"


def test_real_typedef_args_bind_by_type_unchanged():
    # When the Api carries the REAL typedef (cmsHTRANSFORM, has no '*' so the
    # current code skips it) the binding stays whatever the legacy path made —
    # the I3 family pass is ADDITIVE and must not break the void*-typed cases.
    seq2 = [OPEN, XFORM,
            _api("cmsDeleteTransform", "void", ["void *"])]
    model2 = APISemanticModel("lcms", dict(MODEL.apis))
    model2.apis["cmsDeleteTransform"] = _msem(
        "cmsDeleteTransform", APIRole.DESTROYER,
        ((ArgRole.CONFIG, "cmsHTRANSFORM"),))
    f = _factory()
    b = f._signature_handle_bindings(seq2, dep_model=model2)
    # transform-family arg binds to the transform producer
    assert b.get(("cmsDeleteTransform", 0)) == "ret_cmsCreateTransform"


# --- Generalization (over-fit BREAKING #1): the legacy type-exact binding must
# fire for DISTINCT named struct-pointer handles on non-lcms libs. The old guard
# `not (i3 and fam is None)` suppressed EVERY non-lcms handle (fam None) → unbound
# → NULL → dead. Suppress ONLY a genuinely-collapsed void* (the cross-wire hazard).
def test_non_lcms_distinct_handle_binds_despite_no_family():
    prod = _api("cJSON_CreateObject", "cJSON *", [])
    cons = _api("cJSON_Delete", "void", ["cJSON *"])
    model = APISemanticModel("cjson", {
        "cJSON_CreateObject": _msem("cJSON_CreateObject", APIRole.CREATOR, ()),
        "cJSON_Delete": _msem("cJSON_Delete", APIRole.DESTROYER,
                              ((ArgRole.CONFIG, "cJSON *"),)),
    })
    b = _factory()._signature_handle_bindings([prod, cons], dep_model=model)
    assert b.get(("cJSON_Delete", 0)) == "ret_cJSON_CreateObject"  # was unbound (bug)


def test_generic_voidstar_no_family_stays_unbound():
    # genuine void* + no family (lcms cmsHANDLE class) → produced[] pools wrong
    # types → must NOT bind via the legacy match (cross-wire → crash). Protected.
    prod = _api("cmsGBDAlloc", "void *", ["void *"])
    cons = _api("cmsGBDFree", "void", ["void *"])
    model = APISemanticModel("lcms", {
        "cmsGBDAlloc": _msem("cmsGBDAlloc", APIRole.CREATOR, ((ArgRole.CONFIG, "void *"),)),
        "cmsGBDFree": _msem("cmsGBDFree", APIRole.DESTROYER, ((ArgRole.CONFIG, "void *"),)),
    })
    b = _factory()._signature_handle_bindings([prod, cons], dep_model=model)
    assert ("cmsGBDFree", 0) not in b
