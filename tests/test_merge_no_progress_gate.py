"""The merge preflight `no_progress` (15s edge-growth) gate is the wrong selector
for a MERGED harness AND, on lcms, was measured on the wrong binary (the preflight
build produced the stock cms_gdb_fuzzer, not the generated driver — all 63 binaries
collapsed to 2 hashes). It culled 67% of drivers (105->20), including merge-valuable
build+exercise drivers whose construction edges DO add to the union regardless of
15s growth (PromeFuzz filters on compile, not runtime growth). `_preflight_rejection_set`
drops crashers (dead_on_empty) always but `no_progress` only when explicitly opted in.
"""
from collections import namedtuple
from run_single_fuzz import _preflight_rejection_set

_R = namedtuple("_R", "driver_path accepted rejection_reason")


def _mk():
    return [
        _R("a", True, ""),                              # accepted
        _R("b", False, "no_progress (edges=0 < 1)"),    # merge-valuable, bogus gate
        _R("c", False, "dead_on_empty (crash on empty)"),  # real crasher
        _R("d", False, "no_progress (edges=0 < 1)"),
    ]


def test_default_keeps_no_progress_drops_only_crashers():
    rej = _preflight_rejection_set(_mk(), drop_no_progress=False)
    assert rej == {"c"}            # only the crasher dropped; b,d kept


def test_optin_drops_no_progress_too():
    rej = _preflight_rejection_set(_mk(), drop_no_progress=True)
    assert rej == {"b", "c", "d"}  # legacy behavior


def test_accepted_never_dropped():
    rej = _preflight_rejection_set(_mk(), drop_no_progress=True)
    assert "a" not in rej
