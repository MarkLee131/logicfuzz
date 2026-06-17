"""Arg.is_function_pointer — a first-class STRUCTURAL flag (like is_type_incomplete).

Callback classification should read a structural signal, not match name
substrings. A function pointer is identified by its C declarator ``(*`` in the
clang type string (``void (*)(void *)``, ``int (*)(const void *, const void *)``).
This centralises the signal so ``_is_callback_param`` consumes a flag instead of
re-deriving it, and so an opaque handle / scalar / enum is never a function
pointer.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.common.api import Arg  # noqa: E402


def _arg(type_str):
    return Arg("a", "", 0, type_str, [False])


def test_function_pointer_types_detected():
    assert _arg("void (*)(void *)").is_function_pointer is True
    assert _arg("int (*)(const void *, const void *)").is_function_pointer is True
    assert _arg("void (*cb)(int)").is_function_pointer is True


def test_non_function_pointers_are_false():
    # Opaque handle (the c-ares SEGV type), scalar, enum, plain struct pointer.
    assert _arg("ares_dns_rr_t *").is_function_pointer is False
    assert _arg("size_t").is_function_pointer is False
    assert _arg("ares_dns_rr_key_t").is_function_pointer is False
    assert _arg("cJSON *").is_function_pointer is False
    assert _arg("const char *").is_function_pointer is False


def test_explicit_override_respected():
    # A typedef'd function pointer whose string can't be desugared can still be
    # marked by the extractor.
    a = Arg("a", "", 0, "ares_callback", [False], is_function_pointer=True)
    assert a.is_function_pointer is True
