"""Phase 1.2: the hole-fill hallucination guard.

Construct-then-fill skeletons are valid-by-construction, but LLM-authored hole
bodies are the one remaining hallucination surface (e.g. a fabricated
``cmsGetNumberOfToneCurveSegments`` — the 10.c class). The pre-compile scan flags
a library-prefixed call absent from the project whitelist as a directed Fixer
hint, WITHOUT terminating (hole fills are recoverable). It must NOT flag real
APIs, libc, or local helpers.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Documented workflow<->agents circular import; resolves on the retry.
try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402

_KNOWN = [{"function_name": n} for n in (
    "cmsOpenProfileFromMem", "cmsGetToneCurveSegment", "cmsCloseProfile",
    "cmsCreateContext", "cmsDeleteContext")]

# The method uses only its (code, known_apis) args, never `self` — call unbound
# with a dummy self so the test needs no agent construction.
_scan = LangGraphPrototyper._scan_hole_hallucinations


class _Dummy:
    trial = 1


def test_flags_hallucinated_library_call():
    code = (
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){\n"
        "  void* p = cmsOpenProfileFromMem((void*)d,s);\n"
        "  int n = cmsGetNumberOfToneCurveSegments(p);  // hallucinated\n"
        "  cmsCloseProfile(p); return 0; }")
    out = _scan(_Dummy(), code, _KNOWN)
    assert "cmsGetNumberOfToneCurveSegments" in out
    # real APIs must not be flagged
    assert "cmsOpenProfileFromMem" not in out
    assert "cmsCloseProfile" not in out
    # difflib suggests the closest real API
    assert "did you mean" in out


def test_clean_driver_yields_no_warning():
    code = (
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){\n"
        "  void* c = cmsCreateContext(0,0);\n"
        "  void* p = cmsOpenProfileFromMem((void*)d,s);\n"
        "  cmsCloseProfile(p); cmsDeleteContext(c); return 0; }")
    assert _scan(_Dummy(), code, _KNOWN) == ""


def test_does_not_flag_libc_or_local_helpers():
    # memcpy/malloc/free (libc) and a local helper without the library prefix
    # must never be flagged — the scan is library-prefix-gated.
    code = (
        "static int my_helper(int x){ return x+1; }\n"
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){\n"
        "  char* b = malloc(s); memcpy(b,d,s); my_helper(s);\n"
        "  void* p = cmsOpenProfileFromMem(b,s); cmsCloseProfile(p);\n"
        "  free(b); return 0; }")
    assert _scan(_Dummy(), code, _KNOWN) == ""


def test_no_whitelist_is_noop():
    # Without a project whitelist there is no basis to flag anything.
    assert _scan(_Dummy(), "x(); cmsFoo();", []) == ""
    assert _scan(_Dummy(), "cmsFoo();", None) == ""
