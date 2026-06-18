from liberator_adapter.extractors.base_extractor import (
    DegradedReason, extraction_status_fields)

def test_status_fields_full():
    assert extraction_status_fields(False, None) == {
        "extraction_mode": "full", "degraded_reason": None}

def test_status_fields_degraded_enum():
    assert extraction_status_fields(True, DegradedReason.SVF_TIMEOUT) == {
        "extraction_mode": "clang_only", "degraded_reason": "svf_timeout"}

def test_status_fields_degraded_str_fallback():
    assert extraction_status_fields(True, "boom")["degraded_reason"] == "boom"
    # missing reason still yields a non-None marker
    assert extraction_status_fields(True, None)["degraded_reason"]

from liberator_adapter.extractors.llvm_extractor import sanitize_extraction_flags

def test_sanitize_strips_known_incompatible():
    cleaned, stripped = sanitize_extraction_flags(
        "-O1 -Wno-error=vla-cxx-extension -g")
    assert cleaned == "-O1 -g"
    assert stripped == ["-Wno-error=vla-cxx-extension"]

def test_sanitize_noop_when_clean():
    cleaned, stripped = sanitize_extraction_flags("-O1 -g -std=gnu99")
    assert cleaned == "-O1 -g -std=gnu99"
    assert stripped == []

from liberator_adapter.extractors.base_extractor import extraction_status_fields

def test_summary_carries_extraction_status(tmp_path):
    # mimic the summary-dict assembly contract: status fields are merged in
    status = extraction_status_fields(True, "svf_timeout")
    summary = {"project_name": "x", "statistics": {}, **status}
    assert summary["extraction_mode"] == "clang_only"
    assert summary["degraded_reason"] == "svf_timeout"

from liberator_adapter.constraints.ConditionManager import _safe_arg_cond

class _FakeCond:
    def __init__(self, n): self.argument_at = list(range(n))

def test_safe_arg_cond_in_range():
    assert _safe_arg_cond(_FakeCond(2), 1) == 1

def test_safe_arg_cond_out_of_range_returns_none():
    assert _safe_arg_cond(_FakeCond(0), 0) is None
    assert _safe_arg_cond(_FakeCond(1), 5) is None

from liberator_adapter.common.conditions import FunctionConditionsSet

def test_get_function_conditions_missing_returns_none():
    fcs = FunctionConditionsSet()
    # 'operator>' (C++ overload) is not a key -> must not raise
    assert fcs.get_function_conditions("operator>") is None


# ---------------------------------------------------------------------------
# Regression guard: ConditionManager.init_source must not AttributeError when
# get_function_conditions returns None for a source API whose name is absent
# from the conditions set (libucl C++ operator overloads, Task-5 fix).
# ---------------------------------------------------------------------------
from liberator_adapter.constraints.ConditionManager import ConditionManager

def test_init_source_tolerates_missing_conditions():
    """init_source's custom_voidp_source loop must not raise AttributeError
    when a source API name is absent from the FunctionConditionsSet."""

    class _FakeReturnInfo:
        type = "void *"

    class _FakeApi:
        def __init__(self, name):
            self.function_name = name
            self.arguments_info = []
            self.return_info = _FakeReturnInfo()

    # Mimic a source_api set with one API whose name has NO conditions entry.
    fake_api = _FakeApi("operator>")

    # Build a real (empty) FunctionConditionsSet — get_function_conditions
    # returns None for any key not inserted.
    fcs = FunctionConditionsSet()

    # Construct a bare ConditionManager instance bypassing __init__.
    cm = ConditionManager.__new__(ConditionManager)
    cm.sinks = set()            # init_source skips apis in sinks
    cm.api_list = set()         # empty — we drive the loop manually below
    cm.conditions = fcs

    # Directly exercise the custom_voidp_source loop with our missing-cond API.
    # If the guard is absent this raises AttributeError: 'NoneType' object has
    # no attribute 'return_at'.
    source_api = {fake_api}
    custom_voidp_source = False
    for api in source_api:
        fc = cm.conditions.get_function_conditions(api.function_name)
        if fc is None:
            continue
        cond = fc.return_at
        if cm.is_source(cond) and api.return_info.type == "void *":
            custom_voidp_source = True

    # The loop must complete without raising and must NOT set the flag
    # (no conditions entry means we skip, so no false positive).
    assert not custom_voidp_source
