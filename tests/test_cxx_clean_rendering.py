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
