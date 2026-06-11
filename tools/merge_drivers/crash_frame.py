"""Deterministic crash-frame attribution (driver bug vs library bug).

A SEGV/ASan abort is either OUR bug (the driver dereffed an unchecked creator
return / passed garbage to an opaque arg → a false positive) or a REAL library
bug (keep it). PromeFuzz decides this structurally from the ASan stack trace
(``src/analyzer/asan.py``); we mirror that here — a STRUCTURAL, location-based
fact that should be deterministic, not an LLM verdict. Used by the pre-ship gate
to DROP driver-frame crashers while KEEPING library-frame real bugs.

Pure + dependency-free; conservative ('library'/'unknown' = keep, never a false
drop of a real finding).
"""
from __future__ import annotations

import os
import re
from typing import Literal

# A backtrace frame with an in-source location: ``#3 0x.. in func /path/f.c:12:5``
_FRAME = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+(?P<path>[^\s:]+):\d+")
_SRC_EXTS = (".c", ".cc", ".cpp", ".cxx", ".cint", ".h", ".hpp", ".hh")


def classify_crash_frame(asan_log: str, driver_basename: str) -> Literal["driver", "library", "unknown"]:
    """Attribute a crash to the driver file or a library file.

    Walks frames top-down; the FIRST frame whose location is a *source* file
    decides: that file is the driver (-> 'driver', our bug, DROP/FIX) or a
    library file (-> 'library', real bug, KEEP). No in-source frame but the
    driver binary stem appears in the log -> 'driver'; otherwise 'unknown'
    (keep — let the LLM feasibility analyzer judge the residual).
    """
    if not asan_log or not driver_basename:
        return "unknown"
    # NB: don't splitext the driver name — files are ``NN.fuzz_target`` where
    # ``.fuzz_target`` is part of the name, not an extension, and the compiled
    # source is ``NN.fuzz_target.cpp``. Match the frame basename against it.
    drv_base = os.path.basename(driver_basename)
    for m in _FRAME.finditer(asan_log):
        path = m.group("path")
        base = os.path.basename(path)
        # ASan/UBSan/LSan/MSan runtime + interceptor frames carry compiler-rt
        # SOURCE locations (e.g. .../compiler-rt/lib/asan/asan_malloc_linux.cpp)
        # that END IN .cpp. Without this skip the FIRST such frame — the top of
        # a DRIVER double-free / invalid-free — is misread as a LIBRARY frame
        # (i.e. a real bug) when it is the driver's own fault, inflating bug
        # counts and corrupting the low-FP claim (systematic under error-shape
        # variants). Skip sanitizer-runtime frames before the source check.
        if any(mark in path for mark in (
                "compiler-rt/", "/sanitizer_common/", "/interception/",
                "/lib/asan/", "/lib/ubsan/", "/lib/lsan/", "/lib/msan/")):
            continue
        if not base.lower().endswith(_SRC_EXTS):
            continue  # non-source (libc / asan runtime) — keep walking
        if (base == drv_base or os.path.splitext(base)[0] == drv_base
                or base.startswith(drv_base + ".")):
            return "driver"
        return "library"  # first in-source frame is library code → real bug
    if drv_base and drv_base in asan_log:
        return "driver"
    return "unknown"
