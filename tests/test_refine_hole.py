from liberator_adapter.driver.synthesis.hole import RefineHole, HoleKind


def test_refine_hole_placeholder_and_fields():
    h = RefineHole(name="src0", default_value="gzopen(p,\"rb\")",
                   fill_reason="path vs content?")
    assert h.get_placeholder() == "__REFINE_src0__"
    assert h.kind is HoleKind.REFINE
    assert h.default_value == "gzopen(p,\"rb\")"
    assert h.fill_reason == "path vs content?"
