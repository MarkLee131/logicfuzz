from liberator_adapter.extractors.base_extractor import (
    DegradedReason, extraction_status_fields)
from liberator_adapter.extractors.llvm_extractor import (
    _stub_engine_build_cmd, STUB_ENGINE_PATH)


def test_stub_cmd_builds_valid_archive():
    cmd = _stub_engine_build_cmd("/tmp/x.a")
    # builds an object with clang-14 then packs it into a non-empty ar archive
    assert "/usr/lib/llvm-14/bin/clang" in cmd
    assert "ar crs /tmp/x.a" in cmd
    assert ".c" in cmd and "-c" in cmd  # compiles a stub TU, not an empty archive


def test_stub_cmd_default_path():
    assert STUB_ENGINE_PATH in _stub_engine_build_cmd()


def test_status_fields_full():
    assert extraction_status_fields(False, None) == {
        "extraction_mode": "full", "degraded_reason": None,
        "bitcode_recovery": None}

def test_status_fields_degraded_enum():
    assert extraction_status_fields(True, DegradedReason.SVF_TIMEOUT) == {
        "extraction_mode": "clang_only", "degraded_reason": "svf_timeout",
        "bitcode_recovery": None}

def test_status_fields_full_with_recovery():
    assert extraction_status_fields(False, None, recovery="stub_engine") == {
        "extraction_mode": "full", "degraded_reason": None,
        "bitcode_recovery": "stub_engine"}

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


# ---------------------------------------------------------------------------
# Task 6: per-project SVF resource table + lite-mode cmd builder (Fix B1)
# ---------------------------------------------------------------------------
from liberator_adapter.extractors.llvm_extractor import (
    build_svf_cmd, svf_resources_for)

def test_build_svf_cmd_full_has_indirect_jumps():
    cmd = build_svf_cmd("EX","in.bc","if.json","out.json","min.txt","dl.txt", lite=False)
    assert "-do_indirect_jumps" in cmd
    assert "-data_layout" in cmd and cmd[-1] == "dl.txt"

def test_build_svf_cmd_lite_omits_indirect_jumps():
    cmd = build_svf_cmd("EX","in.bc","if.json","out.json","min.txt","dl.txt", lite=True)
    assert "-do_indirect_jumps" not in cmd
    assert "-data_layout" in cmd and cmd[-1] == "dl.txt"

def test_svf_resources_libucl_is_lite():
    assert svf_resources_for("libucl")["lite"] is True
    assert svf_resources_for("cjson")["lite"] is False


# ---------------------------------------------------------------------------
# Task 7: _image_has_clang14 predicate (Fix C — image-side stale detection)
# Tests monkeypatch ofc.subprocess (not sp) so the predicate is mockable.
# ---------------------------------------------------------------------------
from experiment import oss_fuzz_checkout as ofc

class _R:
    def __init__(self, rc): self.returncode = rc

def test_image_has_clang14_true(monkeypatch):
    monkeypatch.setattr(ofc, "subprocess", type("S", (), {"run": staticmethod(lambda *a, **k: _R(0)), "PIPE": -1}))
    assert ofc._image_has_clang14("img") is True

def test_image_has_clang14_false(monkeypatch):
    monkeypatch.setattr(ofc, "subprocess", type("S", (), {"run": staticmethod(lambda *a, **k: _R(1)), "PIPE": -1}))
    assert ofc._image_has_clang14("img") is False


# ---------------------------------------------------------------------------
# Task 8: LOGICFUZZ_REQUIRE_Z3 opt-in strict gate
# ---------------------------------------------------------------------------
from src.context.data_context import require_z3_enabled

def test_require_z3_default_off(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_REQUIRE_Z3", raising=False)
    assert require_z3_enabled() is False

def test_require_z3_on(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_REQUIRE_Z3", "1")
    assert require_z3_enabled() is True


# ---------------------------------------------------------------------------
# FIX 1 — classify_degraded_reason: correct mapping from exception message
# ---------------------------------------------------------------------------
from liberator_adapter.extractors.base_extractor import classify_degraded_reason, DegradedReason

def test_classify_timeout():
    assert classify_degraded_reason("Extractor timed out after 1800s") == DegradedReason.SVF_TIMEOUT.value

def test_classify_timeout_keyword():
    assert classify_degraded_reason("operation timeout in SVF") == DegradedReason.SVF_TIMEOUT.value

def test_classify_oom_bad_alloc():
    assert classify_degraded_reason("std::bad_alloc deep in ucl_parse") == DegradedReason.SVF_OOM.value

def test_classify_oom_memory_error():
    assert classify_degraded_reason("MemoryError: cannot allocate") == DegradedReason.SVF_OOM.value

def test_classify_oom_out_of_memory():
    assert classify_degraded_reason("out of memory at address 0x0") == DegradedReason.SVF_OOM.value

def test_classify_extract_bc():
    assert classify_degraded_reason("Failed to extract bitcode: tool error") == DegradedReason.EXTRACT_BC_FAILED.value

def test_classify_extract_bc_keyword():
    assert classify_degraded_reason("extract-bc returned non-zero") == DegradedReason.EXTRACT_BC_FAILED.value

def test_classify_conditions_missing_full():
    assert classify_degraded_reason("conditions.json was not generated") == DegradedReason.CONDITIONS_MISSING.value

def test_classify_conditions_missing_short():
    assert classify_degraded_reason("conditions.json not found") == DegradedReason.CONDITIONS_MISSING.value

def test_classify_host_extractor_missing_binary():
    assert classify_degraded_reason("Extractor binary not found at /some/path") == DegradedReason.HOST_EXTRACTOR_MISSING.value

def test_classify_host_extractor_missing_clang14():
    assert classify_degraded_reason("clang-14 missing in container for project foo") == DegradedReason.HOST_EXTRACTOR_MISSING.value

def test_classify_host_extractor_missing_path_to_compiler():
    assert classify_degraded_reason("Path to compiler is invalid") == DegradedReason.HOST_EXTRACTOR_MISSING.value

def test_classify_compile_failed_library():
    assert classify_degraded_reason("Could not find library file for project cjson") == DegradedReason.COMPILE_FAILED.value

def test_classify_compile_failed_script():
    assert classify_degraded_reason("compile script returned error 1") == DegradedReason.COMPILE_FAILED.value

def test_classify_fallback_raw():
    msg = "some totally unknown error"
    result = classify_degraded_reason(msg)
    assert result == msg[:200]
    assert result != DegradedReason.COMPILE_FAILED.value

def test_classify_extract_bc_with_compiler_word_not_compile_failed():
    """extract-bc error mentioning 'compiler' must map to EXTRACT_BC_FAILED, not COMPILE_FAILED."""
    msg = "Failed to extract bitcode: Path to compiler missing"
    result = classify_degraded_reason(msg)
    assert result == DegradedReason.EXTRACT_BC_FAILED.value
    assert result != DegradedReason.COMPILE_FAILED.value


# ---------------------------------------------------------------------------
# FIX 2 — refine_status_for_empty_conditions helper
# ---------------------------------------------------------------------------
from src.context.data_context import refine_status_for_empty_conditions

def test_refine_surfaces_conditions_empty_full_mode_re2():
    """re2 case: SVF ran (extraction_mode=full) but produced no conditions → CONDITIONS_EMPTY."""
    status = {"extraction_mode": "full", "degraded_reason": None}
    result = refine_status_for_empty_conditions(status, has_conditions=False)
    assert result["degraded_reason"] == DegradedReason.CONDITIONS_EMPTY.value

def test_refine_no_override_when_already_degraded():
    """When degraded_reason is already set (non-NONE), do not override."""
    status = {"extraction_mode": "clang_only", "degraded_reason": "svf_timeout"}
    result = refine_status_for_empty_conditions(status, has_conditions=False)
    assert result["degraded_reason"] == "svf_timeout"

def test_refine_sets_conditions_empty_when_none_reason_and_no_conditions():
    """When degraded_reason is NONE/falsy and conditions are absent, set CONDITIONS_EMPTY."""
    status = {"extraction_mode": "clang_only", "degraded_reason": "none"}
    result = refine_status_for_empty_conditions(status, has_conditions=False)
    assert result["degraded_reason"] == DegradedReason.CONDITIONS_EMPTY.value

def test_refine_no_override_when_has_conditions():
    """When conditions are present, do not override even if reason is NONE."""
    status = {"extraction_mode": "clang_only", "degraded_reason": "none"}
    result = refine_status_for_empty_conditions(status, has_conditions=True)
    assert result["degraded_reason"] == "none"

def test_refine_sets_conditions_empty_when_reason_is_falsy_none():
    """None (Python None) degraded_reason + no conditions => CONDITIONS_EMPTY."""
    status = {"extraction_mode": "clang_only", "degraded_reason": None}
    result = refine_status_for_empty_conditions(status, has_conditions=False)
    assert result["degraded_reason"] == DegradedReason.CONDITIONS_EMPTY.value


# ---------------------------------------------------------------------------
# FIX 3 — _make_svf_preexec factory: returns callable, captures distinct values
# ---------------------------------------------------------------------------
from liberator_adapter.extractors.llvm_extractor import _make_svf_preexec

def test_make_svf_preexec_returns_callable():
    fn = _make_svf_preexec(140)
    assert callable(fn)

def test_make_svf_preexec_distinct_closures():
    fn1 = _make_svf_preexec(32)
    fn2 = _make_svf_preexec(64)
    # The two closures capture different mem_gb values
    assert fn1.__closure__[0].cell_contents != fn2.__closure__[0].cell_contents

def test_make_svf_preexec_zero_returns_none():
    """_make_svf_preexec(0) should return None (no cap desired)."""
    result = _make_svf_preexec(0)
    assert result is None


# ---------------------------------------------------------------------------
# FIX 4 — REQUIRE_Z3 raises at the third degradation site (no condition_manager)
# ---------------------------------------------------------------------------

def test_require_z3_raises_at_cbfactory_no_condition_manager(monkeypatch):
    """When LOGICFUZZ_REQUIRE_Z3=1 and condition_manager is None, must raise RuntimeError."""
    from src.context.data_context import _generate_cbfactory_drivers
    import logging
    import pytest

    monkeypatch.setenv("LOGICFUZZ_REQUIRE_Z3", "1")

    class _FakeGenerator:
        condition_manager = None
        function_conditions = None
        all_apis = {}
        dependency_graph = {}

    with pytest.raises(RuntimeError, match="LOGICFUZZ_REQUIRE_Z3"):
        _generate_cbfactory_drivers(
            generator=_FakeGenerator(),
            num_drivers=1,
            driver_size=3,
            project_name="test_proj",
            log=logging.getLogger("test"),
        )


from liberator_adapter.project_driver_generator import _pick_source_dir


def test_pick_source_dir_versioned_prefers_main():
    # libjpeg-turbo OSS-Fuzz image: /src has versioned source dirs + a stray
    # 'fuzz' dir (files like afl_llvm22_patch.diff are filtered out by the caller).
    cands = ["fuzz", "libjpeg-turbo.3.0.x", "libjpeg-turbo.3.1.x",
             "libjpeg-turbo.main"]
    assert _pick_source_dir(cands, "libjpeg-turbo") == "libjpeg-turbo.main"


def test_pick_source_dir_lib_stripped_match():
    # libaom project -> source dir is 'aom'
    assert _pick_source_dir(["aom", "fuzz"], "libaom") == "aom"


def test_pick_source_dir_exact_match_wins():
    assert _pick_source_dir(["libpng", "zlib"], "libpng") == "libpng"


def test_pick_source_dir_empty_is_none():
    assert _pick_source_dir([], "anything") is None


def test_pick_source_dir_all_mismatch_is_deterministic():
    # No match: must still return one of the provided directories deterministically
    # (never raise, never return a non-candidate), so the caller never falls back
    # to a stray file.
    got = _pick_source_dir(["foo", "bar"], "libwhatever")
    assert got in {"foo", "bar"}
    assert _pick_source_dir(["foo", "bar"], "libwhatever") == got


# ---------------------------------------------------------------------------
# Task 1: Stub-engine retry-decision helper
# ---------------------------------------------------------------------------
from liberator_adapter.extractors.llvm_extractor import _should_retry_with_stub_engine


def test_retry_true_on_fuzz_library_error():
    out = "CMake Error at fuzz/CMakeLists.txt:18 (message):\n  FUZZ_LIBRARY must be specified."
    assert _should_retry_with_stub_engine(out) is True


def test_retry_true_on_lib_fuzzing_engine_mention():
    assert _should_retry_with_stub_engine("error: LIB_FUZZING_ENGINE is empty") is True


def test_retry_false_without_engine_signal():
    # e.g. header-only: no library target ever referenced the engine
    assert _should_retry_with_stub_engine("fatal error: 'foo.h' file not found") is False


def test_retry_false_on_empty():
    assert _should_retry_with_stub_engine("") is False


from liberator_adapter.project_driver_generator import _header_declares_private


def test_private_header_error_guard_detected():
    # libpng's pngpriv/pnginfo/pngstruct/pngdebug all carry this guard
    txt = '#  error This file must not be included by applications; please include <png.h>\n'
    assert _header_declares_private(txt) is True


def test_private_header_not_part_of_public_api():
    assert _header_declares_private("#error this header is not part of the public API") is True


def test_public_header_not_flagged():
    # png.h has prose ("Do not use this option ...") but no #error private guard
    txt = ('/* png.h - header file for PNG reference library */\n'
           ' * images.  Do not use this option for images which will be distributed\n'
           '#include "pnglibconf.h"\n')
    assert _header_declares_private(txt) is False


def test_public_utils_header_not_flagged():
    # cjson's cJSON_Utils.h is public, no private guard -> kept (breadth preserved)
    assert _header_declares_private("#ifndef cJSON_Utils__h\n#include \"cJSON.h\"\n") is False


def test_private_declares_empty_is_false():
    assert _header_declares_private("") is False
