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
