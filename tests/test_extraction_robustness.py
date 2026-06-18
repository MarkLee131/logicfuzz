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
