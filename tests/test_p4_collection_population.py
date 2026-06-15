"""Lever A — populate a CREATOR's handle-collection arg (``cmsToneCurve* const []``)
with built producer handles instead of the degenerate ``{0}``/NULL, so the deep
constructor runs. Measured +72% edges/driver vs PromeFuzz's build-and-chain pattern
(334 vs 194 on instrumented lcms). Gated ``LOGICFUZZ_POPULATE_COLLECTIONS``,
default-OFF, gate-off byte-identical.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import sequence_constructor as sc


def test_gate_default_off(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_POPULATE_COLLECTIONS", raising=False)
    assert sc._populate_collections() is False


def test_gate_on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_POPULATE_COLLECTIONS", "1")
    assert sc._populate_collections() is True


from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    _is_handle_collection_type,
)


def test_handle_collection_detect():
    assert _is_handle_collection_type("cmsToneCurve * const *") is True
    assert _is_handle_collection_type("cmsToneCurve **") is True
    assert _is_handle_collection_type("cmsHPROFILE *") is False     # single ptr
    assert _is_handle_collection_type("unsigned int") is False
    assert _is_handle_collection_type("char **") is False           # non-handle base


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
    monkeypatch.delenv("LOGICFUZZ_POPULATE_COLLECTIONS", raising=False)
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    sk.add_variable(SkeletonVariable(name="ret_cmsBuildGamma", c_type="cmsToneCurve *",
                                     is_pointer=True, source_api="cmsBuildGamma"))
    var = gen._create_variable_for_param(
        "Curves_cmsCreateLinearizationDeviceLink", _arg_info_collection(), sk)
    assert not getattr(var, "prepopulate", None)   # unchanged legacy render
