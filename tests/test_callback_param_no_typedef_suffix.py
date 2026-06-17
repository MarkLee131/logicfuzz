"""Root-cause regression: ``_is_callback_param`` must NOT treat the ``_t``
typedef suffix as a callback marker.

Crash found 2026-06-18 (c-ares merged harness, 38,405 SEGVs over 2h, all from
driver 14):

    ares_dns_rr_t * dns_rr = ((ares_dns_rr_t *)data) /* HOLE[CALLBACK_IMPL] */;
    ares_dns_rr_get_u32(dns_rr, key);   // derefs fuzz-bytes-as-handle → SEGV

Root cause: ``callback_suffixes`` included ``'_t'`` and matched it as a SUBSTRING
of the type. ``_t`` is the standard C typedef convention (``size_t``,
``uint8_t``, opaque handles like ``ares_dns_rr_t``, enums like
``ares_dns_rr_key_t``) — NOT a callback marker. The misclassification turned an
opaque-handle arg into a CALLBACK_IMPL hole, which the LLM "filled" by casting
raw ``data`` to the handle type → dereference of garbage → SEGV.

Real callbacks are detected by function-pointer syntax ``(*)`` or by a
callback-ish name/type token (``callback``/``_cb``/``_func``/``handler``), none
of which this fix removes.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.common.api import Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator,
)


def _arg(name, type_str, incomplete=False):
    return Arg(name, "", 0, type_str, [False], incomplete)


def _is_cb(arg):
    gen = SkeletonGenerator.__new__(SkeletonGenerator)
    return gen._is_callback_param(arg)


def test_opaque_handle_t_typedef_is_not_callback():
    # The exact crasher: an opaque struct-pointer handle ending in `_t`.
    assert _is_cb(_arg("dns_rr", "ares_dns_rr_t *", incomplete=True)) is False


def test_scalar_and_enum_t_typedefs_are_not_callbacks():
    assert _is_cb(_arg("n", "size_t")) is False
    assert _is_cb(_arg("b", "uint8_t")) is False
    assert _is_cb(_arg("key", "ares_dns_rr_key_t")) is False


def test_function_pointer_is_still_callback():
    assert _is_cb(_arg("cb", "void (*)(void *)")) is True


def test_named_callback_is_still_callback():
    assert _is_cb(_arg("handler", "ares_callback")) is True
    assert _is_cb(_arg("on_done", "some_handler_fn")) is True
