"""Structural opaque-handle render invariant (heuristic-proof).

Reproduces the c-ares merged-harness crash (2026-06-18): driver 14 rendered

    ares_dns_rr_t * dns_rr = ((ares_dns_rr_t *)data) /* HOLE[CALLBACK_IMPL] */;
    ares_dns_rr_get_u32(dns_rr, key);   // derefs fuzz-bytes-as-handle → SEGV

An opaque handle (``is_type_incomplete``) consumed by an API must NEVER be a
raw ``(T*)data`` fuzz cast and never a callback hole. With no producer it must
render NULL and the consuming call must be GUARDED — regardless of the
validity-contract gate. Keyed on the IR's structural ``is_type_incomplete``, so
no name heuristic can route it into a fuzz-data branch.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.common.api import Api, Arg  # noqa: E402
from liberator_adapter.driver.synthesis.skeleton_generator import (  # noqa: E402
    SkeletonGenerator, SkeletonRenderer,
)


def _arg(name, type_str, incomplete=False, is_const=False):
    return Arg(name, "", 0, type_str, [is_const] * (type_str.count("*") + 1 or 1),
               incomplete)


def _api(name, ret, args):
    return Api(function_name=name, is_vararg=False,
               return_info=_arg("return", ret), arguments_info=args, namespace=[])


def _render(seq):
    sk = SkeletonGenerator().generate(
        api_sequence=seq, driver_name="t_opaque", is_cpp=False)
    return sk, SkeletonRenderer().render(sk)


def test_opaque_handle_consumer_never_casts_fuzz_data():
    # The exact crasher shape: a consumer taking an opaque handle + an enum key.
    entry = _api("lib_entry", "int", [_arg("in", "const char *", is_const=True)])
    consumer = _api(
        "ares_dns_rr_get_u32",
        "unsigned int",
        [_arg("dns_rr", "ares_dns_rr_t *", incomplete=True),
         _arg("key", "ares_dns_rr_key_t")],
    )
    sk, code = _render([entry, consumer])

    # 1. No raw fuzz-bytes cast to the opaque handle type (the SEGV root).
    assert not re.search(r'\(\s*ares_dns_rr_t\s*\*\s*\)\s*data', code), code

    # 2. The handle var renders NULL (producer-wired later if one exists),
    #    not a callback placeholder.
    var = sk.variables.get("dns_rr_ares_dns_rr_get_u32")
    assert var is not None
    assert var.init_value == "NULL", (var.init_value, code)
    assert var.opaque_handle is True
    assert "__CALLBACK_" not in code, code

    # 3. The consuming call is GUARDED (ungated) so a NULL/garbage handle is
    #    never passed in.
    assert re.search(r'if\s*\(\s*dns_rr_ares_dns_rr_get_u32\s*\)', code), code
