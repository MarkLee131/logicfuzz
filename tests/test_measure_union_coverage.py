"""Unit tests for scripts.measure_union_coverage — the standalone SynapseFlow-style
per-binary union evaluator: build+fuzz each driver as its OWN binary, retain each
profdata, then union offline via tools.merge_drivers.coverage_union.

Tests cover the pure orchestration (driver discovery + the collect/union control
flow) with the per-driver build/fuzz and the union step INJECTED, so no docker /
llvm / heavy project deps are needed. Runnable with plain ``python3``.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.measure_union_coverage import (  # noqa: E402
    discover_drivers,
    union_over_drivers,
    UnionReport,
)
from tools.merge_drivers.coverage_union import UnionCoverage  # noqa: E402


class DiscoverDrivers(unittest.TestCase):
    def test_lists_per_driver_sources_excluding_fused_dispatcher(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "00.c").write_text("x")
            (root / "01.c").write_text("x")
            (root / "05.cc").write_text("x")
            (root / "entry.c").write_text("x")      # fused dispatcher — excluded
            (root / "entry.cpp").write_text("x")     # fused dispatcher — excluded
            (root / "README.md").write_text("x")     # not a source
            got = sorted(p.name for p in discover_drivers(root))
            self.assertEqual(got, ["00.c", "01.c", "05.cc"])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(discover_drivers(Path("/no/such/dir")), [])


class UnionOverDrivers(unittest.TestCase):
    def test_runs_each_collects_profiles_and_unions(self):
        with tempfile.TemporaryDirectory() as d:
            stage = Path(d) / "stage"
            stage.mkdir()
            drivers = [Path("00.c"), Path("01.c"), Path("02.c")]
            seen = []

            def run_one(driver, sd, idx):
                seen.append((driver.name, idx))
                if driver.name == "02.c":
                    return None  # build/fuzz failed for this driver
                p = sd / f"{idx:02d}.profdata"
                p.write_bytes(b"x")
                return p

            def union_fn(sd, binary, image):
                return UnionCoverage(420, 1000, 66, 534, 1800, 8000, n_profiles=2)

            rep = union_over_drivers(
                drivers, run_one=run_one, union_fn=union_fn,
                stage_dir=stage, image="gcr.io/oss-fuzz/zlib",
                binary_name="checksum_fuzzer", project="zlib")

            self.assertIsInstance(rep, UnionReport)
            self.assertEqual(rep.n_drivers, 3)
            self.assertEqual(rep.n_profiles, 2)          # only 2 produced profdata
            self.assertIsNotNone(rep.union)
            self.assertEqual(rep.union["branches_covered"], 420)
            self.assertEqual([r.ok for r in rep.per_driver], [True, True, False])
            self.assertEqual(seen, [("00.c", 0), ("01.c", 1), ("02.c", 2)])

    def test_no_profiles_never_calls_union(self):
        with tempfile.TemporaryDirectory() as d:
            called = {"n": 0}

            def run_one(driver, sd, idx):
                return None  # everything fails

            def union_fn(sd, binary, image):
                called["n"] += 1
                return None

            rep = union_over_drivers(
                [Path("00.c")], run_one=run_one, union_fn=union_fn,
                stage_dir=Path(d), image="i", binary_name="b")
            self.assertIsNone(rep.union)
            self.assertEqual(rep.n_profiles, 0)
            self.assertEqual(called["n"], 0)  # nothing to union → skip docker


if __name__ == "__main__":
    unittest.main()
