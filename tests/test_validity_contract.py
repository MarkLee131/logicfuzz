"""Validity Contract validator — the construction gate AND the regression oracle.
Checks the 4 invariants against the APISemanticModel's per-arg {nullable, type_str}:
  I1  producer-before-consumer (no use-before-produce / close-before-open)
  I2a every nullable=False HANDLE arg has a producer (no orphan NULL handle)
  I2b every nullable=False non-handle required arg is non-NULL
  I3  handle arg bound to a producer of the SAME handle family (no void* confusion)
"""
from liberator_adapter.analysis.validity_contract import (
    Call, ArgBinding, check_sequence)

# minimal model: api -> {"args": [...], "requires": [...]}. A HANDLE type is one
# some API `requires` (cmshprofile, cmshtransform) — that's how the validator
# distinguishes handles from value/scalar args.
MODEL = {
    "cmsCreate_sRGBProfile": {"args": [], "requires": []},
    "cmsCloseProfile": {"args": [{"index": 0, "type_str": "cmsHPROFILE", "nullable": False}],
                        "requires": ["cmshprofile"]},
    "cmsGetColorSpace": {"args": [{"index": 0, "type_str": "cmsHPROFILE", "nullable": False}],
                         "requires": ["cmshprofile"]},
    "cmsCreateTransform": {"args": [
        {"index": 0, "type_str": "cmsHPROFILE", "nullable": False},
        {"index": 1, "type_str": "unsigned int", "nullable": False},
    ], "requires": ["cmshprofile"]},
    "cmsDoTransform": {"args": [{"index": 0, "type_str": "cmsHTRANSFORM", "nullable": False}],
                       "requires": ["cmshtransform"]},
}


def test_orphan_handle_is_flagged_i2a():
    # cmsGetColorSpace(NULL) with no producer -> I2a violation
    calls = [Call("cmsGetColorSpace", [ArgBinding(producer=None, produced_at=None, is_null=True)])]
    rep = check_sequence(calls, MODEL)
    assert rep.counts["I2a"] == 1
    assert rep.total() == 1


def test_produced_handle_is_valid():
    calls = [
        Call("cmsCreate_sRGBProfile", []),  # produces ret at idx 0
        Call("cmsGetColorSpace", [ArgBinding(producer="cmsCreate_sRGBProfile", produced_at=0, is_null=False)]),
    ]
    rep = check_sequence(calls, MODEL)
    assert rep.total() == 0


def test_use_before_produce_is_i1():
    calls = [
        Call("cmsGetColorSpace", [ArgBinding(producer="cmsCreate_sRGBProfile", produced_at=1, is_null=False)]),
        Call("cmsCreate_sRGBProfile", []),
    ]
    rep = check_sequence(calls, MODEL)
    assert rep.counts["I1"] == 1


def test_type_confusion_is_i3():
    # cmsCloseProfile (wants profile) bound to a transform producer
    calls = [
        Call("cmsCreateTransform", []),
        Call("cmsCloseProfile", [ArgBinding(producer="cmsCreateTransform", produced_at=0, is_null=False)]),
    ]
    rep = check_sequence(calls, MODEL)
    assert rep.counts["I3"] == 1


def test_nullable_arg_is_exempt():
    # an arg the model marks nullable=True is never flagged even when NULL
    model = {"cmsX": {"args": [{"index": 0, "type_str": "cmsContext", "nullable": True}]}}
    calls = [Call("cmsX", [ArgBinding(producer=None, produced_at=None, is_null=True)])]
    assert check_sequence(calls, model).total() == 0
