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
