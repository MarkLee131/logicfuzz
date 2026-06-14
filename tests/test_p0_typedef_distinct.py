import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from liberator_adapter.analysis.usedef import normalize_handle_type
from liberator_adapter.driver.synthesis import skeleton_generator as sg
def test_public_typedef_handles_are_distinct():
    assert normalize_handle_type("cmsContext") != normalize_handle_type("cmsHPROFILE")
def test_public_typedef_not_flattened_to_void():
    assert sg._public_pointer_type("_cmsContext_struct *") == "void *"
    assert sg._public_pointer_type("cmsHPROFILE") == "cmsHPROFILE"
