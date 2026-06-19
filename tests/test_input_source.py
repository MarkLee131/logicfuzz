# tests/test_input_source.py
from liberator_adapter.analysis.input_source import classify_input_source, materialize
from liberator_adapter.analysis.api_semantic_model import APIRole

def test_classify_file_star_high():
    assert classify_input_source("FILE *", APIRole.CREATOR) == ("FILE_STAR", "HIGH")

def test_classify_char_path_low():
    assert classify_input_source("const char *", APIRole.CREATOR) == ("PATH", "LOW")

def test_classify_buffer_and_non_creator_none():
    assert classify_input_source("const uint8_t *", APIRole.CREATOR) is None
    assert classify_input_source("const char *", APIRole.CONSUMER) is None

def test_materialize_file_star():
    m = materialize("FILE_STAR", "src0")
    assert any("fmemopen" in s for s in m.stmts)
    assert m.bind_expr == "src0_f"
    assert any("fclose" in c for c in m.cleanup)
    assert "<stdio.h>" in m.includes

def test_materialize_path():
    m = materialize("PATH", "src0")
    assert any("mkstemp" in s for s in m.stmts) and any("write(" in s for s in m.stmts)
    assert m.bind_expr == "src0_path"
    assert any("unlink" in c for c in m.cleanup)
    assert "<unistd.h>" in m.includes


def test_skeleton_to_dict_serializes_refine_hole_default_value():
    """Serialization glue: to_dict must preserve RefineHole.default_value.

    This test is RED before the 'default_value' key is added to the hole_dict
    in DriverSkeleton.to_dict (~line 574-582 of skeleton_generator.py).
    """
    from liberator_adapter.driver.synthesis.skeleton_generator import DriverSkeleton
    from liberator_adapter.driver.synthesis.hole import RefineHole

    skel = DriverSkeleton(name="test_driver", target_apis=[])
    hole = RefineHole(
        name="src0",
        default_value="src0_path",
        fill_reason="rendered arg as a temp-file PATH",
    )
    skel.holes.add(hole)

    d = skel.to_dict()
    holes = d["holes"]
    refine_holes = [h for h in holes if h.get("hole_type") == "REFINE"]
    assert refine_holes, "No REFINE hole found in serialized dict"
    assert refine_holes[0]["default_value"] == "src0_path", (
        f"Expected default_value='src0_path', got: {refine_holes[0]}"
    )
