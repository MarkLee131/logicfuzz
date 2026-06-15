"""Render side of the depth lever (Lever B): a deep consumer's input ``void*``
data buffer must render as ``(void*)data`` (fuzz bytes) when the sub-gate is on
(``deep_fuzz_buffer`` flag set), instead of the by-construction ``NULL`` that a
plain CONFIG pointer gets. Gate-off (flag unset) must stay ``NULL`` — byte-
identical to today.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, DriverSkeleton, AllocationType)


def _arg_info(deep):
    return {
        "name": "in_buf", "type": "void *", "idx": 1,
        "api_name": "cmsDoTransform", "is_input": False, "is_output": False,
        "is_callback": False, "varlen_target": None, "role": "CONFIG",
        "pairs_with": None, "deep_fuzz_buffer": deep,
    }


def test_deep_buffer_renders_fuzz_data_when_flagged():
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param("in_buf", _arg_info(True), sk)
    assert var is not None
    assert var.init_value == "(void*)data", var.init_value
    assert var.allocation == AllocationType.FUZZ_INPUT


def test_config_void_ptr_stays_null_when_not_flagged():
    gen = SkeletonGenerator()
    sk = DriverSkeleton(name="t", target_apis=[])
    var = gen._create_variable_for_param("in_buf", _arg_info(False), sk)
    assert var is not None
    assert var.init_value == "NULL", var.init_value  # legacy by-construction default
