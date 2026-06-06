"""Deterministic crash-frame attribution: driver bug (drop) vs library bug (keep)."""
from tools.merge_drivers.crash_frame import classify_crash_frame

_DRIVER_FRAME = """==12==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x4a1 in cmsDoTransform /src/lcms/src/cmstrans.c:120:5
    #1 0x5b2 in LLVMFuzzerTestOneInput /out/01.fuzz_target.cpp:14:3
"""

_LIBRARY_FRAME = """==9==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x33 in _cmsReadUInt /src/lcms/src/cmsio0.c:88:9
    #1 0x44 in cmsOpenProfileFromMem /src/lcms/src/cmsio0.c:301:5
    #2 0x55 in LLVMFuzzerTestOneInput /out/01.fuzz_target.cpp:9:3
"""


def test_driver_frame_when_first_source_frame_is_the_driver():
    # First in-source frame is cmstrans.c (library) here -> library; flip example:
    log = """==1==ERROR: AddressSanitizer: SEGV
    #0 0x1 in LLVMFuzzerTestOneInput /out/01.fuzz_target.cpp:14:3
"""
    assert classify_crash_frame(log, "01.fuzz_target") == "driver"


def test_library_frame_is_kept():
    assert classify_crash_frame(_LIBRARY_FRAME, "01.fuzz_target") == "library"


def test_first_in_source_frame_decides():
    # cmstrans.c (library) is the first in-source frame -> library (real bug, keep)
    assert classify_crash_frame(_DRIVER_FRAME, "01.fuzz_target") == "library"


def test_libc_top_frame_skipped_to_first_source():
    log = """==2==ERROR: AddressSanitizer: SEGV
    #0 0x0 in memcpy
    #1 0x1 in __asan_memcpy
    #2 0x2 in LLVMFuzzerTestOneInput /out/02.fuzz_target.c:7:3
"""
    assert classify_crash_frame(log, "02.fuzz_target") == "driver"


def test_no_source_frame_but_driver_stem_present():
    log = "==3==ERROR: AddressSanitizer: SEGV\n    in 03.fuzz_target+0x123\n"
    assert classify_crash_frame(log, "03.fuzz_target") == "driver"


def test_unknown_when_nothing_matches():
    assert classify_crash_frame("==4==ERROR: AddressSanitizer: SEGV\n", "05.fuzz_target") == "unknown"
    assert classify_crash_frame("", "01.fuzz_target") == "unknown"
