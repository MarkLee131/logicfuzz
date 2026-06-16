"""The merge preflight `no_progress` (15s edge-growth) gate is the wrong selector
for a MERGED harness AND, on lcms, was measured on the wrong binary (the preflight
build produced the stock cms_gdb_fuzzer, not the generated driver — all 63 binaries
collapsed to 2 hashes). It culled 67% of drivers (105->20), including merge-valuable
build+exercise drivers whose construction edges DO add to the union regardless of
15s growth (PromeFuzz filters on compile, not runtime growth). `_preflight_rejection_set`
drops crashers (dead_on_empty) always but `no_progress` only when explicitly opted in.
"""
from collections import namedtuple
from run_single_fuzz import _preflight_rejection_set, _is_degenerate_binary_set

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


# Cross-project safety: the no_progress gate is only TRUSTWORTHY when the preflight
# binaries are real per-driver builds. lcms+c-ares collapse to 2 hashes (stock-
# binary bug) → phantom signal; zlib (18 distinct)/libucl (13 distinct) are real.
def test_degenerate_lcms_cares_2_hashes():
    assert _is_degenerate_binary_set(["h1"] * 42 + ["h2"] * 21) is True   # lcms 63→2
    assert _is_degenerate_binary_set(["a"] * 14 + ["b"] * 15) is True     # c-ares 29→2


def test_real_zlib_libucl_distinct():
    assert _is_degenerate_binary_set([f"z{i}" for i in range(18)]) is False  # zlib 18→18
    assert _is_degenerate_binary_set([f"u{i}" for i in range(13)]) is False  # libucl 13→13


def test_too_few_candidates_not_judged():
    # <5 candidates: can't conclude degeneracy (a tiny project may legitimately
    # share a binary); don't suppress the gate.
    assert _is_degenerate_binary_set(["a", "a"]) is False
    assert _is_degenerate_binary_set([]) is False
