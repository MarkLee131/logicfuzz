"""Task 8 — I2b (non-NULL value completeness): a ``nullable=False`` non-handle
required pointer arg (e.g. an opaque ``char* FileName`` the renderer cannot
synthesize) must never be left NULL — the renderer's value-struct/string fill
covers the fillable cases, and the constructor DROPS a target consumer whose
required value arg is genuinely unfillable AND has no producer. Gated behind
``LOGICFUZZ_VALIDITY_CONTRACT``; gate-off is byte-identical.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APISemanticModel, APIRole, ArgRole, ArgSemantics,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _i2b_unfillable_consumer, _build_index, construct_sequences,
)


def _arg(i, role, t="void", nullable=False):
    return ArgSemantics(index=i, role=role, type_str=t, nullable=nullable)


def _api(name, role, produces=(), requires=(), args=()):
    return APISemantics(
        name=name, role=role, role_confidence=0.9, args=tuple(args),
        produces=frozenset(produces), requires=frozenset(requires),
        destroys=frozenset(),
    )


# An opaque non-handle pointer arg the renderer can't synthesize (a function
# pointer / opaque struct ptr, marked non-null) with no producer -> unfillable.
OPAQUE_PTR_CONSUMER = _api(
    "needsOpaquePtr", APIRole.CONSUMER,
    args=(_arg(0, ArgRole.CONFIG, "struct _opaque_thing *", nullable=False),),
)
# A char* string arg is FILLABLE (string-wrapped) -> never dropped.
STRING_CONSUMER = _api(
    "needsName", APIRole.CONSUMER,
    args=(_arg(0, ArgRole.CONFIG, "const char *", nullable=False),),
)
# A value-struct arg is FILLABLE (stack-alloc) -> never dropped.
VSTRUCT_CONSUMER = _api(
    "needsLab", APIRole.CONSUMER,
    args=(_arg(0, ArgRole.CONFIG, "cmsCIELab *", nullable=False),),
)
# A nullable arg is EXEMPT.
NULLABLE_CONSUMER = _api(
    "optPlugin", APIRole.CONSUMER,
    args=(_arg(0, ArgRole.CONFIG, "void *", nullable=True),),
)


def test_opaque_nonnull_ptr_is_unfillable():
    idx = _build_index(APISemanticModel("t", {OPAQUE_PTR_CONSUMER.name: OPAQUE_PTR_CONSUMER}))
    assert _i2b_unfillable_consumer(OPAQUE_PTR_CONSUMER, idx) is True


def test_string_arg_is_fillable():
    idx = _build_index(APISemanticModel("t", {STRING_CONSUMER.name: STRING_CONSUMER}))
    assert _i2b_unfillable_consumer(STRING_CONSUMER, idx) is False


def test_value_struct_arg_is_fillable():
    idx = _build_index(APISemanticModel("t", {VSTRUCT_CONSUMER.name: VSTRUCT_CONSUMER}))
    assert _i2b_unfillable_consumer(VSTRUCT_CONSUMER, idx) is False


def test_nullable_arg_is_exempt():
    idx = _build_index(APISemanticModel("t", {NULLABLE_CONSUMER.name: NULLABLE_CONSUMER}))
    assert _i2b_unfillable_consumer(NULLABLE_CONSUMER, idx) is False


def test_construct_gate_on_drops_unfillable_target():
    model = APISemanticModel("t", {
        s.name: s for s in (OPAQUE_PTR_CONSUMER, STRING_CONSUMER)})
    os.environ["LOGICFUZZ_VALIDITY_CONTRACT"] = "1"
    try:
        res = construct_sequences(model)
        seqs = res.sequences
        flat = {a for s in seqs for a in s}
        assert "needsOpaquePtr" not in flat   # unfillable -> dropped
    finally:
        os.environ.pop("LOGICFUZZ_VALIDITY_CONTRACT", None)


