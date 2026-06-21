# tests/test_dominance_filter.py
from pathlib import Path
from tools.merge_drivers.select import DriverCoverage, dominance_filter


def _cov(name, funcs, edges=0, real=True):
    return DriverCoverage(
        driver_path=Path(f"/x/{name}.fuzz_target"),
        reached_funcs=frozenset(funcs),
        edges_15s=edges,
        has_real_data=real,
    )


def test_drops_strict_subset_keeps_partial_overlap():
    a = _cov("a", {1, 2})
    b = _cov("b", {2, 3})
    c = _cov("c", {1, 3})
    sub = _cov("sub", {2})           # strict subset of a and b
    res = dominance_filter([a, b, c, sub])
    kept = {d.driver_path.stem for d in res.kept}
    assert kept == {"a", "b", "c"}   # partial-overlap all kept; only the subset drops
    assert {d.driver_path.stem for d in res.dropped} == {"sub"}


def test_distinct_api_union_is_preserved():
    drivers = [_cov("a", {1, 2}), _cov("b", {2, 3}), _cov("c", {1, 3}), _cov("sub", {2})]
    res = dominance_filter(drivers)
    union_in = set().union(*(d.reached_funcs for d in drivers))
    union_kept = set().union(*(d.reached_funcs for d in res.kept))
    assert union_kept == union_in    # the dominance guarantee


def test_exact_duplicate_tiebreak_keeps_higher_edges_then_name():
    hi = _cov("zz", {1, 2}, edges=99)
    lo = _cov("aa", {1, 2}, edges=1)
    res = dominance_filter([lo, hi])
    assert [d.driver_path.stem for d in res.kept] == ["zz"]   # higher edges wins
    assert [d.driver_path.stem for d in res.dropped] == ["aa"]


def test_no_data_driver_always_kept():
    real = _cov("real", {1, 2, 3})
    fb = _cov("fb", {"__fallback__:fb"}, real=False)
    res = dominance_filter([real, fb])
    assert {d.driver_path.stem for d in res.kept} == {"real", "fb"}


def test_deterministic_under_input_reordering():
    # includes a no-data driver to exercise the sorted-nodata ordering path
    drivers = [_cov("a", {1, 2}), _cov("b", {2, 3}), _cov("c", {1, 3}),
               _cov("sub", {2}), _cov("nd", {"__fallback__:nd"}, real=False)]
    r1 = [d.driver_path.stem for d in dominance_filter(drivers).kept]
    r2 = [d.driver_path.stem for d in dominance_filter(list(reversed(drivers))).kept]
    assert r1 == r2          # identical SET *and* order, not just same members


def test_empty_coverage_real_driver_is_dropped():
    full = _cov("full", {1, 2, 3})
    empty = _cov("empty", set())          # real driver, zero coverage
    res = dominance_filter([full, empty])
    assert [d.driver_path.stem for d in res.kept] == ["full"]
    assert [d.driver_path.stem for d in res.dropped] == ["empty"]
