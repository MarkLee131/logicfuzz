"""Unit tests for tools.merge_drivers.coverage_union — the per-binary
profdata-union coverage measurement (SynapseFlow-style: measure each driver as
its own binary, then union their profiles offline), the reliable replacement for
the merged-dispatcher llvm-cov replay that HANGS.

Pure-stdlib tests (no docker/llvm) covering the testable core: parsing the
``llvm-cov export -summary-only`` JSON, discovering per-driver profdata, and
building the merge/export commands. Runnable with plain ``python3`` (the repo's
pytest env is unavailable); pytest can also collect it.
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.merge_drivers.coverage_union import (  # noqa: E402
    UnionCoverage,
    parse_llvm_cov_export,
    discover_profdata,
    build_merge_cmd,
    build_union_docker_cmd,
    union_coverage,
    _run_cli,
)


_EXPORT = """
{"data":[{"totals":{
  "branches":{"count":1000,"covered":420,"percent":42.0},
  "functions":{"count":534,"covered":66,"percent":12.35},
  "lines":{"count":8000,"covered":1800,"percent":22.5}
}}],"type":"llvm.coverage.json.export","version":"2.0.1"}
"""


class ParseLlvmCovExport(unittest.TestCase):
    def test_extracts_branch_function_line_totals(self):
        cov = parse_llvm_cov_export(_EXPORT)
        self.assertIsNotNone(cov)
        self.assertEqual(cov.branches_covered, 420)
        self.assertEqual(cov.branches_total, 1000)
        self.assertEqual(cov.functions_covered, 66)
        self.assertEqual(cov.functions_total, 534)
        self.assertEqual(cov.lines_covered, 1800)
        self.assertEqual(cov.lines_total, 8000)

    def test_branch_percent_derived_not_trusted_from_json(self):
        # percent must be recomputed from covered/total, not copied from the
        # (per-profile, non-unionable) JSON percent field.
        cov = parse_llvm_cov_export(_EXPORT)
        self.assertAlmostEqual(cov.branch_percent, 42.0, places=3)

    def test_empty_totals_rejected_as_uninstrumented(self):
        # count==0 on both lines and branches == un-instrumented garbage (the
        # "1-file harness only" profile) → None, so the caller fails open.
        empty = '{"data":[{"totals":{"branches":{"count":0,"covered":0},' \
                '"lines":{"count":0,"covered":0},' \
                '"functions":{"count":0,"covered":0}}}]}'
        self.assertIsNone(parse_llvm_cov_export(empty))

    def test_malformed_json_returns_none(self):
        self.assertIsNone(parse_llvm_cov_export("not json"))
        self.assertIsNone(parse_llvm_cov_export(""))
        self.assertIsNone(parse_llvm_cov_export('{"data":[]}'))


class DiscoverProfdata(unittest.TestCase):
    def test_finds_per_driver_profdata_excluding_union(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "00.profdata").write_bytes(b"x")
            (root / "01.profdata").write_bytes(b"x")
            # the union output itself must never be re-merged into itself
            (root / "union.profdata").write_bytes(b"x")
            (root / "merged.profdata").write_bytes(b"x")
            (root / "notes.txt").write_bytes(b"x")
            found = discover_profdata(root)
            names = sorted(p.name for p in found)
            self.assertEqual(names, ["00.profdata", "01.profdata"])

    def test_missing_dir_returns_empty(self):
        self.assertEqual(discover_profdata(Path("/no/such/dir")), [])


class BuildMergeCmd(unittest.TestCase):
    def test_sparse_merge_of_all_inputs(self):
        cmd = build_merge_cmd(
            [Path("/a/00.profdata"), Path("/a/01.profdata")],
            Path("/a/union.profdata"),
        )
        self.assertEqual(cmd[:3], ["llvm-profdata", "merge", "-sparse"])
        self.assertIn("/a/00.profdata", cmd)
        self.assertIn("/a/01.profdata", cmd)
        self.assertEqual(cmd[-2:], ["-o", "/a/union.profdata"])

    def test_no_inputs_raises(self):
        with self.assertRaises(ValueError):
            build_merge_cmd([], Path("/a/union.profdata"))


class BuildUnionDockerCmd(unittest.TestCase):
    def test_merges_then_exports_in_project_image(self):
        cmd = build_union_docker_cmd(
            image="gcr.io/oss-fuzz/zlib",
            mount_dir=Path("/w/dumps"),
            binary_name="checksum_fuzzer",
            profdata_names=["00.profdata", "01.profdata"],
            union_name="union.profdata",
        )
        self.assertEqual(cmd[:5], ["docker", "run", "--rm", "-v", "/w/dumps:/cov"])
        self.assertIn("gcr.io/oss-fuzz/zlib", cmd)
        self.assertEqual(cmd[-3:-1], ["bash", "-c"])
        script = cmd[-1]
        # merge unions all per-driver profiles into the union output IN-container
        # (project image → matching llvm toolchain, no host llvm-version skew)
        self.assertIn("llvm-profdata merge -sparse", script)
        self.assertIn("/cov/00.profdata", script)
        self.assertIn("/cov/01.profdata", script)
        self.assertIn("-o /cov/union.profdata", script)
        # then export the UNION against a library-linked binary
        self.assertIn("llvm-cov export /cov/checksum_fuzzer", script)
        self.assertIn("-instr-profile=/cov/union.profdata", script)
        self.assertIn("-summary-only", script)

    def test_no_profdata_raises(self):
        with self.assertRaises(ValueError):
            build_union_docker_cmd("img", Path("/w"), "bin", [], "union.profdata")


class _FakeProc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


class UnionCoverageOrchestration(unittest.TestCase):
    def _dumps(self, tmp):
        root = Path(tmp)
        (root / "00.profdata").write_bytes(b"x")
        (root / "01.profdata").write_bytes(b"x")
        return root

    def test_discovers_runs_and_parses_union(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = self._dumps(d)
            captured = {}

            def fake_runner(cmd):
                captured["cmd"] = cmd
                return _FakeProc(0, _EXPORT)

            cov = union_coverage(root, "checksum_fuzzer",
                                 "gcr.io/oss-fuzz/zlib", runner=fake_runner)
            self.assertIsNotNone(cov)
            self.assertEqual(cov.branches_covered, 420)
            self.assertEqual(cov.n_profiles, 2)  # two per-driver profiles unioned
            self.assertIn("llvm-profdata merge -sparse", captured["cmd"][-1])

    def test_no_profdata_returns_none_without_running(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ran = {"n": 0}

            def fake_runner(cmd):
                ran["n"] += 1
                return _FakeProc(0, _EXPORT)

            cov = union_coverage(Path(d), "bin", "img", runner=fake_runner)
            self.assertIsNone(cov)
            self.assertEqual(ran["n"], 0)  # nothing to union → never invokes docker

    def test_runner_failure_returns_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = self._dumps(d)
            cov = union_coverage(root, "bin", "img",
                                 runner=lambda cmd: _FakeProc(1, ""))
            self.assertIsNone(cov)


class RunCli(unittest.TestCase):
    def test_prints_union_json_and_returns_zero(self):
        calls = {}

        def fake_union(dumps, binary, image, **kw):
            calls["args"] = (dumps, binary, image)
            return UnionCoverage(420, 1000, 66, 534, 1800, 8000, 2)

        out = io.StringIO()
        rc = _run_cli(
            ["--image", "gcr.io/oss-fuzz/zlib", "--dumps", "/d",
             "--binary", "checksum_fuzzer"],
            union_fn=fake_union, out=out,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(calls["args"],
                         (Path("/d"), "checksum_fuzzer", "gcr.io/oss-fuzz/zlib"))
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["branches_covered"], 420)
        self.assertEqual(payload["branches_total"], 1000)
        self.assertEqual(payload["n_profiles"], 2)

    def test_returns_one_when_no_coverage(self):
        rc = _run_cli(
            ["--image", "i", "--dumps", "/d", "--binary", "b"],
            union_fn=lambda *a, **k: None, out=io.StringIO(),
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
