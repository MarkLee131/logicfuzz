"""Property test for the dominance-filter's formal safety net: the merge-time
selector may only drop fully-dominated drivers, so the union of reached functions
over the kept set must ALWAYS equal the union over the input pool. This is the
guarantee that lets the filter be integrated with no flag (it can never lose a
distinct API). Fixed RNG seed → deterministic, no PYTHONHASHSEED dependence."""
import random
from pathlib import Path

from tools.merge_drivers.select import DriverCoverage, dominance_filter


def test_union_preserved_over_random_pools():
    rng = random.Random(0)
    for _ in range(200):
        n = rng.randint(1, 12)
        funcs = [f"f{x}" for x in range(8)]
        drivers = [
            DriverCoverage(
                driver_path=Path(f"/x/{i}.fuzz_target"),
                reached_funcs=frozenset(rng.sample(funcs, rng.randint(0, len(funcs)))),
                edges_15s=rng.randint(0, 5),
            )
            for i in range(n)
        ]
        res = dominance_filter(drivers)
        union_in = set().union(*(d.reached_funcs for d in drivers)) if drivers else set()
        union_kept = set().union(*(d.reached_funcs for d in res.kept)) if res.kept else set()
        assert union_kept == union_in            # never lose a reached function
        assert len(res.kept) <= len(drivers)     # only ever drops, never invents
        assert len(res.kept) + len(res.dropped) == len(drivers)  # partition
