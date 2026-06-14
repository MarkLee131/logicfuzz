import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from src.utils.unified_validator import UnifiedCodeValidator, ValidationCategory
KNOWN = [
    {"function_name": "cmsCreateTransform", "arguments_info": [{"type_clang": "cmsHPROFILE"}, {"type_clang": "cmsUInt32Number"}]},
    {"function_name": "cmsCloseProfile", "arguments_info": [{"type_clang": "cmsHPROFILE"}]},
]
CODE_UNDECLARED = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){cmsWhitePointFromTempDouble(0);return 0;}"
CODE_TOO_FEW = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){cmsCreateTransform(0);return 0;}"
def test_reject_undeclared_lib_call():
    r = UnifiedCodeValidator().validate(code=CODE_UNDECLARED, known_apis=KNOWN, is_c_target=True)
    assert ValidationCategory.UNDECLARED_CALL in [i.category for i in r.issues]
    assert any("cmsWhitePointFromTempDouble" in i.message for i in r.issues)
def test_wrong_arity_too_few_flagged():
    r = UnifiedCodeValidator().validate(code=CODE_TOO_FEW, known_apis=KNOWN, is_c_target=True)
    assert ValidationCategory.WRONG_ARITY in [i.category for i in r.issues]
