"""The cleanup-destroyer inference (`_infer_paired_destroy`) is a NAME-pattern
heuristic: for `cmsCreateContext` the ("Create","Destroy") infix rule yields
`cms`+`Destroy` = `cmsDestroy` — a NON-EXISTENT lcms symbol (the real destroyer
is `cmsDeleteContext`). Emitting it makes the driver fail to LINK ('undefined
reference to cmsDestroy'), so compile-validation drops the whole driver — a
breadth loss (~16/41 lcms drivers). `_real_destroy` only emits the inferred
destroyer when it is a REAL project API; otherwise None (skip — a leak is
harmless, LSan is off). Empty valid-set ⇒ keep legacy behavior (no model).
"""
from liberator_adapter.driver.synthesis.skeleton_generator import _real_destroy


def test_hallucinated_destroyer_dropped():
    # cmsCreateContext -> 'cmsDestroy' is NOT a real lcms API → skip
    out = _real_destroy("cmsCreateContext", "ctx",
                        {"cmsCreateContext", "cmsDeleteContext", "cmsBuildGamma"})
    assert out is None


def test_real_destroyer_kept():
    out = _real_destroy("cJSON_Parse", "j", {"cJSON_Parse", "cJSON_Delete"})
    assert out == "cJSON_Delete(j)"


def test_empty_validset_keeps_legacy_inference():
    # no model available → don't suppress (preserve prior behavior)
    out = _real_destroy("cJSON_Parse", "j", set())
    assert out == "cJSON_Delete(j)"


def test_unrelated_producer_returns_none():
    out = _real_destroy("cmsGetColorSpace", "x", {"cmsGetColorSpace"})
    assert out is None
