"""Lever A — populate a CREATOR's handle-collection arg (``cmsToneCurve* const []``)
with built producer handles instead of the degenerate ``{0}``/NULL, so the deep
constructor runs. Measured +72% edges/driver vs PromeFuzz's build-and-chain pattern
(334 vs 194 on instrumented lcms). Gated ``LOGICFUZZ_POPULATE_COLLECTIONS``,
DEFAULT-ON (opt-out =0); graduated 2026-06-20 — lcms 300s-fuzz edges 325→943,
cov 0.86%→16.81%.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import sequence_constructor as sc


def test_gate_default_on(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_POPULATE_COLLECTIONS", raising=False)
    assert sc._populate_collections() is True


def test_gate_explicit_off(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "0")
    assert sc._populate_collections() is False


def test_gate_on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "1")
    assert sc._populate_collections() is True


class _A:
    def __init__(self, type_str):
        self.type_str = type_str


class _S:
    def __init__(self, args):
        self.args = args


def test_collection_elem_keys():
    # cmsCreateLinearizationDeviceLink(sig, cmsToneCurve* const Curves[])
    sem = _S([_A("cmsColorSpaceSignature"), _A("cmsToneCurve * *")])
    assert sc._collection_elem_keys(sem) == ["cmstonecurve*"]
    # no collection arg → empty
    assert sc._collection_elem_keys(_S([_A("unsigned int"), _A("void *")])) == []
    # char** is not a handle collection
    assert sc._collection_elem_keys(_S([_A("char * *")])) == []


from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    _is_handle_collection_type,
)


def test_handle_collection_detect():
    assert _is_handle_collection_type("cmsToneCurve * const *") is True
    assert _is_handle_collection_type("cmsToneCurve **") is True
    assert _is_handle_collection_type("cmsHPROFILE *") is False     # single ptr
    assert _is_handle_collection_type("unsigned int") is False
    assert _is_handle_collection_type("char **") is False           # non-handle base
    # function pointers must NOT be treated as handle collections
    assert _is_handle_collection_type("int (*)(float*, float*, void*)") is False
    assert _is_handle_collection_type("cmsSAMPLER16") is False


from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, DriverSkeleton, SkeletonVariable)


def _skeleton_with_collection():
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(
        name="curves_cmsCreateLinearizationDeviceLink",
        c_type="cmsToneCurve *", is_array=True, array_size="3",
        prepopulate=["ret_cmsBuildGamma", "ret_cmsBuildGamma", "ret_cmsBuildGamma"]))
    return sk


def test_collection_emits_population_assignments():
    gen = SkeletonGenerator()
    sk = _skeleton_with_collection()
    gen._emit_collection_population(sk, "curves_cmsCreateLinearizationDeviceLink")
    codes = [s.code for s in sk.statements]
    assert "curves_cmsCreateLinearizationDeviceLink[0] = ret_cmsBuildGamma;" in codes
    assert "curves_cmsCreateLinearizationDeviceLink[2] = ret_cmsBuildGamma;" in codes


from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    _fuzzable_scalar_buffer_base,
)


def test_fuzzable_scalar_buffer_base():
    # single-pointer to a fuzz-friendly scalar number → the base type
    assert _fuzzable_scalar_buffer_base("cmsUInt16Number *") == "cmsUInt16Number"
    assert _fuzzable_scalar_buffer_base("cmsFloat32Number *") == "cmsFloat32Number"
    assert _fuzzable_scalar_buffer_base("const cmsUInt16Number *") == "cmsUInt16Number"
    # NOT a scalar buffer:
    assert _fuzzable_scalar_buffer_base("cmsToneCurve *") is None   # opaque handle
    assert _fuzzable_scalar_buffer_base("cmsHPROFILE") is None      # handle, no ptr
    assert _fuzzable_scalar_buffer_base("void *") is None           # opaque
    assert _fuzzable_scalar_buffer_base("char *") is None           # string
    assert _fuzzable_scalar_buffer_base("unsigned int") is None     # not a pointer
    assert _fuzzable_scalar_buffer_base("cmsUInt16Number **") is None  # double ptr


from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    _scalar_buffer_pairs,
)


def test_scalar_buffer_pairs_finds_buffer_and_preceding_length():
    # cmsBuildTabulatedToneCurve16(ctx, unsigned int nEntries, cmsUInt16Number* values)
    types = ["void *", "unsigned int", "cmsUInt16Number *"]
    pairs = _scalar_buffer_pairs(types)
    assert pairs == {2: ("cmsUInt16Number", 1)}, pairs   # buf@2, length@1


def test_scalar_buffer_pairs_skips_when_no_preceding_length():
    # a scalar buffer with NO preceding integer length → not safe to fuzz → skip
    types = ["cmsUInt16Number *", "void *"]
    assert _scalar_buffer_pairs(types) == {}


def test_scalar_buffer_pairs_ignores_handles_and_void():
    types = ["void *", "cmsToneCurve *", "unsigned int"]
    assert _scalar_buffer_pairs(types) == {}


def test_value_struct_fuzz_fill_emits_guarded_memcpy():
    # a by-value struct CONFIG arg (cmsCIExyYTRIPLE) of a CREATOR: gate-on fills
    # it from fuzz data via a size-guarded memcpy (seed-independent + non-degenerate)
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(
        name="primaries_cmsCreateRGBProfile", c_type="cmsCIExyYTRIPLE",
        is_pointer=False, init_value="{0}", bound_expr="&primaries_cmsCreateRGBProfile",
        fuzz_fill_struct="cmsCIExyYTRIPLE"))
    gen._emit_struct_fuzz_fill(sk, "primaries_cmsCreateRGBProfile")
    codes = [s.code for s in sk.statements]
    assert any("memcpy(&primaries_cmsCreateRGBProfile, data," in c
               and "sizeof(cmsCIExyYTRIPLE)" in c and "size >=" in c
               for c in codes), codes


def _buf_arg_info(extra):
    base = {"name": "Values", "type": "cmsUInt16Number *", "idx": 2,
            "api_name": "cmsBuildTabulatedToneCurve16", "is_input": True,
            "is_output": False, "is_callback": False, "varlen_target": None,
            "role": "HANDLE_IN", "pairs_with": None, "deep_fuzz_buffer": False}
    base.update(extra)
    return base


def test_scalar_buffer_renders_fuzz_data_when_flagged():
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param(
        "Values_cmsBuildTabulatedToneCurve16",
        _buf_arg_info({"fuzz_scalar_buffer": "cmsUInt16Number"}), sk)
    assert var.bound_expr == "(cmsUInt16Number*)data", var.bound_expr


def test_buffer_length_renders_size_over_sizeof_when_flagged():
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param(
        "nEntries_cmsBuildTabulatedToneCurve16",
        {"name": "nEntries", "type": "unsigned int", "idx": 1,
         "api_name": "cmsBuildTabulatedToneCurve16", "is_input": True,
         "is_output": False, "is_callback": False, "varlen_target": None,
         "role": "CONFIG", "pairs_with": None, "deep_fuzz_buffer": False,
         "buffer_length_sizeof": "cmsUInt16Number"}, sk)
    assert var.init_value == (
        "(unsigned int)((size/sizeof(cmsUInt16Number)) < 256 ? "
        "(size/sizeof(cmsUInt16Number)) : 256)"), var.init_value


def test_scalar_buffer_unchanged_without_flag():
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param(
        "Values_cmsBuildTabulatedToneCurve16", _buf_arg_info({}), sk)
    assert var.bound_expr != "(cmsUInt16Number*)data"   # legacy render


def _arg_info_collection():
    return {"name": "Curves", "type": "cmsToneCurve * const *", "idx": 1,
            "api_name": "cmsCreateLinearizationDeviceLink", "is_input": True,
            "is_output": False, "is_callback": False, "varlen_target": None,
            "role": "CONFIG", "pairs_with": None, "deep_fuzz_buffer": False}


def test_creator_collection_populated_when_gated(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "1")
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(name="ret_cmsBuildGamma", c_type="cmsToneCurve *",
                                     is_pointer=True, source_api="cmsBuildGamma"))
    var = gen._create_variable_for_param(
        "Curves_cmsCreateLinearizationDeviceLink", _arg_info_collection(), sk)
    assert var.is_array is True
    assert var.prepopulate and all(e == "ret_cmsBuildGamma" for e in var.prepopulate)


def test_creator_collection_legacy_when_off(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "0")
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(name="ret_cmsBuildGamma", c_type="cmsToneCurve *",
                                     is_pointer=True, source_api="cmsBuildGamma"))
    var = gen._create_variable_for_param(
        "Curves_cmsCreateLinearizationDeviceLink", _arg_info_collection(), sk)
    assert not getattr(var, "prepopulate", None)   # unchanged legacy render
