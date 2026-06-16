"""A merged sub-driver that calls a handle-consuming API on an UN-PRODUCED handle
(declared `T* x = NULL;` and never assigned a producer return) dereferences NULL
inside the library → SEGV (lcms: cmsGetColorSpace(NULL) → read field at 0x8c).
These 'orphan' drivers pass compile-validation (they compile) and slipped past
preflight (crashed=False), then POISON the merged harness + corrupt the coverage
-merge. `is_degenerate_orphan` flags them for exclusion at merge time — without
STRICT_ORDERING's breadth loss. These tests pin the detector against the real
lcms crashers (28/63) and guard against false-positives on valid drivers.
"""
from tools.merge_drivers.orphan_filter import is_degenerate_orphan


# lcms driver 63: pure getters on NULL handles, no producer — the SEGV@0x8c crasher
DRIVER_63 = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    void * arg0_cmsGetColorSpace = NULL;
    void * arg0_cmsGetPCS = NULL;
    cmsColorSpaceSignature ret = cmsGetColorSpace(arg0_cmsGetColorSpace);
    cmsColorSpaceSignature r2 = cmsGetPCS(arg0_cmsGetPCS);
    return 0;
}
"""

# lcms driver 28: cmsGDBCompute(NULL, ...) — un-produced handle
DRIVER_28 = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    void * arg0_cmsGDBCompute = NULL;
    int ret = cmsGDBCompute(arg0_cmsGDBCompute, 0);
    return 0;
}
"""

# VALID: the handle IS produced (cmsBuildGamma) and guarded before use
DRIVER_VALID_PRODUCED = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    cmsContext ctx = cmsCreateContext(NULL, NULL);
    if (ctx == NULL) return 0;
    cmsToneCurve* gamma = NULL;
    gamma = cmsBuildGamma(ctx, 2.2);
    if (gamma == NULL) return 0;
    double g = cmsEstimateGamma(gamma, 0.01);
    cmsFreeToneCurve(gamma);
    return 0;
}
"""

# VALID: handle from a creator, used by a consumer (no NULL decl-then-consume)
DRIVER_VALID_CREATOR = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsHPROFILE h = cmsCreate_sRGBProfile();
    if (h == NULL) return 0;
    cmsColorSpaceSignature cs = cmsGetColorSpace(h);
    cmsCloseProfile(h);
    return 0;
}
"""


def test_detects_orphan_getter_chain_driver63():
    assert is_degenerate_orphan(DRIVER_63) is True


def test_detects_orphan_driver28():
    assert is_degenerate_orphan(DRIVER_28) is True


def test_valid_produced_handle_not_flagged():
    assert is_degenerate_orphan(DRIVER_VALID_PRODUCED) is False


def test_valid_creator_consumer_not_flagged():
    assert is_degenerate_orphan(DRIVER_VALID_CREATOR) is False


def test_empty_or_trivial_not_flagged():
    assert is_degenerate_orphan("int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){return 0;}") is False
