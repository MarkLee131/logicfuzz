"""Per-binary profdata-union coverage measurement.

The SynapseFlow-style measurement recipe (``run_fuzzer/merge_coverage.sh``):
measure each surviving driver as its OWN coverage-instrumented binary, retain
its ``*.profdata``, then union the profiles offline with ``llvm-profdata merge``
and read the totals with ``llvm-cov export -summary-only``.

Why this exists: our shipped merged harness is a single fused *dispatcher*
binary; replaying it through ``llvm-cov`` HANGS (slow/looping inputs, no
per-input timeout) and, worse, splits the fuzz budget ~24h/N across N
sub-drivers — a structural coverage suppressor independent of driver quality.
Unioning independent per-driver profiles avoids both.

This module holds the pure, unit-testable core (parse / discover / command
construction); the docker/llvm orchestration is a thin wrapper on top that
injects a runner so it stays testable.
"""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

# profdata basenames that are OUTPUTS of a union, never per-driver inputs — must
# never be fed back into their own merge.
_UNION_STEMS = frozenset({"union", "merged"})


@dataclass(frozen=True)
class UnionCoverage:
    """Unioned coverage totals across a set of per-driver profiles."""

    branches_covered: int
    branches_total: int
    functions_covered: int
    functions_total: int
    lines_covered: int
    lines_total: int
    n_profiles: int = 0

    @property
    def branch_percent(self) -> float:
        return 100.0 * self.branches_covered / self.branches_total \
            if self.branches_total else 0.0

    @property
    def function_percent(self) -> float:
        return 100.0 * self.functions_covered / self.functions_total \
            if self.functions_total else 0.0

    @property
    def line_percent(self) -> float:
        return 100.0 * self.lines_covered / self.lines_total \
            if self.lines_total else 0.0


def parse_llvm_cov_export(stdout: str) -> Optional[UnionCoverage]:
    """Parse ``llvm-cov export -summary-only`` JSON into ``UnionCoverage``.

    Returns ``None`` (caller fails open) when the output is unparseable, has no
    data, or reports all-zero counts (an un-instrumented / garbage profile).
    Percentages are recomputed from covered/total, never copied from the JSON
    ``percent`` field (that field is per-profile and not meaningful post-union).
    """
    try:
        totals = json.loads(stdout)["data"][0]["totals"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    b = totals.get("branches", {}) or {}
    f = totals.get("functions", {}) or {}
    ln = totals.get("lines", {}) or {}
    # Reject an un-instrumented profile: no lines AND no branches counted. Use a
    # non-empty-totals check (not a file-count floor) so a single-source library
    # (e.g. cJSON.c) is not false-rejected.
    if ln.get("count", 0) == 0 and b.get("count", 0) == 0:
        return None
    return UnionCoverage(
        branches_covered=b.get("covered", 0),
        branches_total=b.get("count", 0),
        functions_covered=f.get("covered", 0),
        functions_total=f.get("count", 0),
        lines_covered=ln.get("covered", 0),
        lines_total=ln.get("count", 0),
    )


def discover_profdata(root: Path) -> List[Path]:
    """Return per-driver ``*.profdata`` files under ``root``, sorted by name.

    Excludes union outputs (``union.profdata`` / ``merged.profdata``) so a
    re-run never folds a previous union back into itself. Missing dir → ``[]``.
    """
    if not root.is_dir():
        return []
    return sorted(
        p for p in root.glob("*.profdata") if p.stem not in _UNION_STEMS
    )


def build_merge_cmd(profdata_paths: List[Path], out_path: Path) -> List[str]:
    """``llvm-profdata merge -sparse <inputs...> -o <out>``. Raises on no input."""
    if not profdata_paths:
        raise ValueError("build_merge_cmd: no input profdata paths")
    return [
        "llvm-profdata", "merge", "-sparse",
        *[str(p) for p in profdata_paths],
        "-o", str(out_path),
    ]


def build_union_docker_cmd(
    image: str,
    mount_dir: Path,
    binary_name: str,
    profdata_names: List[str],
    union_name: str = "union.profdata",
) -> List[str]:
    """Docker command that unions per-driver profiles and exports totals.

    Runs BOTH steps inside the project image (``gcr.io/oss-fuzz/<project>``) so
    the llvm toolchain matches the one that produced the profiles — no host
    llvm-version skew (the same reason SynapseFlow's ``merge_coverage.sh`` runs
    llvm-profdata/llvm-cov in-container). ``mount_dir`` holds the per-driver
    ``*.profdata`` and a library-linked ``binary_name``; it is mounted at
    ``/cov``.
    """
    if not profdata_names:
        raise ValueError("build_union_docker_cmd: no input profdata")
    inputs = " ".join(f"/cov/{n}" for n in profdata_names)
    script = (
        f"llvm-profdata merge -sparse {inputs} -o /cov/{union_name} && "
        f"llvm-cov export /cov/{binary_name} "
        f"-instr-profile=/cov/{union_name} -summary-only"
    )
    return [
        "docker", "run", "--rm",
        "-v", f"{mount_dir}:/cov",
        image, "bash", "-c", script,
    ]


def _default_runner(cmd: List[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1200)


def union_coverage(
    dumps_dir: Path,
    binary_name: str,
    image: str,
    *,
    union_name: str = "union.profdata",
    runner: Callable[[List[str]], "subprocess.CompletedProcess[str]"]
    = _default_runner,
) -> Optional[UnionCoverage]:
    """Union every per-driver profdata under ``dumps_dir`` and return the totals.

    Discovers ``*.profdata`` (excluding a prior union output), unions + exports
    them in-container via ``image``, and parses the totals. Returns ``None``
    (caller fails open to another signal) when there are no profiles, the
    command fails, or the profile is un-instrumented. ``runner`` is injected for
    testability; it defaults to a real ``subprocess.run``.
    """
    profiles = discover_profdata(dumps_dir)
    if not profiles:
        logger.warning("union_coverage: no per-driver profdata under %s", dumps_dir)
        return None
    cmd = build_union_docker_cmd(
        image, dumps_dir, binary_name, [p.name for p in profiles], union_name)
    try:
        res = runner(cmd)
    except Exception as e:  # noqa: BLE001 — fail open on any docker/llvm error
        logger.warning("union_coverage: runner failed: %s", e)
        return None
    if res.returncode != 0 or not (res.stdout or "").strip():
        logger.warning("union_coverage: merge/export returned rc=%s (no totals)",
                       res.returncode)
        return None
    cov = parse_llvm_cov_export(res.stdout)
    if cov is None:
        return None
    # stamp how many profiles fed the union (the frozen dataclass is rebuilt)
    return UnionCoverage(
        branches_covered=cov.branches_covered, branches_total=cov.branches_total,
        functions_covered=cov.functions_covered, functions_total=cov.functions_total,
        lines_covered=cov.lines_covered, lines_total=cov.lines_total,
        n_profiles=len(profiles),
    )


def _run_cli(argv, *, union_fn=union_coverage, out=None) -> int:
    """CLI: union per-driver profdata under ``--dumps`` and print totals as JSON.

    Returns 0 when a union number was produced, 1 when coverage is
    unavailable (no profdata / command failed / un-instrumented).
    """
    import argparse
    import sys as _sys

    out = out if out is not None else _sys.stdout
    ap = argparse.ArgumentParser(
        prog="python -m tools.merge_drivers.coverage_union",
        description="Per-binary profdata-union coverage (SynapseFlow-style).")
    ap.add_argument("--image", required=True,
                    help="project docker image, e.g. gcr.io/oss-fuzz/zlib")
    ap.add_argument("--dumps", required=True,
                    help="dir holding per-driver *.profdata + a library-linked binary")
    ap.add_argument("--binary", required=True,
                    help="a library-linked coverage binary name inside --dumps")
    ns = ap.parse_args(argv)
    cov = union_fn(Path(ns.dumps), ns.binary, ns.image)
    if cov is None:
        print(json.dumps({"error": "no union coverage available"}), file=out)
        return 1
    print(json.dumps({
        "branches_covered": cov.branches_covered,
        "branches_total": cov.branches_total,
        "branch_percent": round(cov.branch_percent, 4),
        "functions_covered": cov.functions_covered,
        "functions_total": cov.functions_total,
        "lines_covered": cov.lines_covered,
        "lines_total": cov.lines_total,
        "n_profiles": cov.n_profiles,
    }, indent=2), file=out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys
    _sys.exit(_run_cli(_sys.argv[1:]))
