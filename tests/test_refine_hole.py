from liberator_adapter.driver.synthesis.hole import (
    RefineHole, HoleKind, seed_refine_defaults)


def test_refine_hole_placeholder_and_fields():
    h = RefineHole(name="src0", default_value="gzopen(p,\"rb\")",
                   fill_reason="path vs content?")
    assert h.get_placeholder() == "__REFINE_src0__"
    assert h.kind is HoleKind.REFINE
    assert h.default_value == "gzopen(p,\"rb\")"
    assert h.fill_reason == "path vs content?"


def test_seed_refine_defaults_object_form():
    h = RefineHole(name="src0", default_value="DEFAULT")
    # No LLM fillings — default is kept.
    result = seed_refine_defaults([h], {})
    assert result == {"__REFINE_src0__": "DEFAULT"}
    # LLM filling overrides the symbolic default.
    result = seed_refine_defaults([h], {"__REFINE_src0__": "LLM_VALUE"})
    assert result["__REFINE_src0__"] == "LLM_VALUE"


def test_seed_refine_defaults_dict_form():
    d = {"hole_type": "REFINE", "placeholder": "__REFINE_src0__",
         "default_value": "DEFAULT"}
    assert seed_refine_defaults([d], {}) == {"__REFINE_src0__": "DEFAULT"}
    assert seed_refine_defaults([d], {"__REFINE_src0__": "X"})["__REFINE_src0__"] == "X"


def test_seed_refine_defaults_dict_form_missing_default():
    """dict form without default_value (Task 5 not yet landed) must not crash."""
    d = {"hole_type": "REFINE", "placeholder": "__REFINE_x__"}
    result = seed_refine_defaults([d], {})
    assert result == {"__REFINE_x__": ""}
