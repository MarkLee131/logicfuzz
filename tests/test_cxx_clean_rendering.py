"""C++-clean driver rendering + validation (C1/C2/C3).

C-language OSS-Fuzz fuzzers are compiled with $CXX (clang++) + extern "C", so
generated drivers must be C++-compilation-clean. These tests pin the pure helpers.
"""
from liberator_adapter.driver.synthesis.skeleton_generator import const_qualified_type


# ---- C1: const-qualified pointer arg rendering ----

def test_const_qualified_double_pointer():
    # cJSON_ParseWithOpts return_parse_end: 'char * *' + [True,False,False] -> const char **
    assert const_qualified_type("char * *", [True, False, False]).replace(" ", "") == "constchar**"


def test_const_qualified_single_pointer():
    assert const_qualified_type("char *", [True, False]).replace(" ", "") == "constchar*"


def test_no_const_unchanged():
    assert const_qualified_type("int", [False]) == "int"
    assert const_qualified_type("cJSON *", [False, False]) == "cJSON *"


def test_missing_is_const_is_noop():
    assert const_qualified_type("char * *", None) == "char * *"
    assert const_qualified_type("char * *", []) == "char * *"


def test_pointer_level_const():
    # 'char *' with const on the pointer (char * const): is_const=[False, True]
    assert const_qualified_type("char *", [False, True]).replace(" ", "") == "char*const"


# ---- C2: extern "C" balance repair ----

from src.utils.cxx_clean import balance_extern_c

_UNBALANCED = '''#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
'''


def test_balance_adds_missing_close():
    out = balance_extern_c(_UNBALANCED)
    assert out.count('extern "C" {') == 1
    assert out.count('#ifdef __cplusplus') == 2  # open guard + close guard
    assert out.rstrip().endswith('#endif')


def test_balance_noop_when_balanced():
    balanced = _UNBALANCED + '\n#ifdef __cplusplus\n}\n#endif\n'
    assert balance_extern_c(balanced) == balanced


def test_balance_noop_without_extern_c():
    plain = 'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s){return 0;}\n'
    assert balance_extern_c(plain) == plain


# ---- C3a: C++ error triage routing ----

from src.utils.compilation_error_triage import (
    CompilationErrorTriage, ErrorCategory, FixStrategy)

_INCLUDE_STRATEGIES = (FixStrategy.ADD_INCLUDE, FixStrategy.FIX_INCLUDE_PATH)


def test_no_matching_function_is_type_error_not_include():
    t = CompilationErrorTriage().triage(
        ["error: no matching function for call to 'cJSON_ParseWithOpts'"])
    assert t.primary_category == ErrorCategory.TYPE_ERROR
    assert t.recommended_strategy not in _INCLUDE_STRATEGIES


def test_unterminated_extern_c_not_routed_to_include():
    t = CompilationErrorTriage().triage(
        ["error: expected '}'", "note: to match this '{'  extern \"C\" {"])
    assert t.recommended_strategy not in _INCLUDE_STRATEGIES
