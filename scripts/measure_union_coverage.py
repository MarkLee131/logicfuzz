"""Standalone per-binary UNION coverage evaluator (SynapseFlow-style).

Instead of replaying our single fused-dispatcher harness through ``llvm-cov``
(which HANGS, and splits the fuzz budget ~24h/N across N sub-drivers), this
measures each surviving driver as its OWN coverage-instrumented binary, retains
each ``dumps/merged.profdata``, and unions the profiles offline via
``tools.merge_drivers.coverage_union`` — the same recipe as SynapseFlow's
``run_fuzzer.py`` + ``merge_coverage.sh``. It doubles as the fair head-to-head
runner (point ``--drivers-dir`` at ``baseline/synapseflow``'s ``harness_RQ1``).

Structure: the pure orchestration (``discover_drivers`` + ``union_over_drivers``)
is unit-tested with the per-driver build/fuzz and the union step INJECTED. The
real per-driver runner reuses ``scripts.run_extended_fuzzing.ExtendedFuzzer``
(imported lazily, so this module stays importable without heavy project deps)
and is validated by a live small run, not by unit tests.
"""
from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from tools.merge_drivers.coverage_union import UnionCoverage, union_coverage

logger = logging.getLogger(__name__)

# The fused merge dispatcher is emitted as entry.c / entry.cpp — never a
# per-driver binary; exclude it from the driver set we measure independently.
_DISPATCHER_STEMS = frozenset({"entry"})
_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".C"})


@dataclass
class DriverResult:
    driver: str
    profdata: Optional[str]
    ok: bool


@dataclass
class UnionReport:
    project: str
    n_drivers: int
    n_profiles: int
    union: Optional[dict]
    per_driver: List[DriverResult] = field(default_factory=list)


def discover_drivers(merged_dir: Path) -> List[Path]:
    """List per-driver sources under ``merged_dir``, excluding the fused
    dispatcher (``entry.c``/``entry.cpp``). Missing dir → ``[]``."""
    if not merged_dir.is_dir():
        return []
    return sorted(
        p for p in merged_dir.iterdir()
        if p.is_file() and p.suffix in _SOURCE_SUFFIXES
        and p.stem not in _DISPATCHER_STEMS
    )


def _cov_to_dict(cov: UnionCoverage) -> dict:
    return {
        "branches_covered": cov.branches_covered,
        "branches_total": cov.branches_total,
        "branch_percent": round(cov.branch_percent, 4),
        "functions_covered": cov.functions_covered,
        "functions_total": cov.functions_total,
        "lines_covered": cov.lines_covered,
        "lines_total": cov.lines_total,
        "n_profiles": cov.n_profiles,
    }


def union_over_drivers(
    drivers: List[Path],
    *,
    run_one: Callable[[Path, Path, int], Optional[Path]],
    union_fn: Callable[[Path, str, str], Optional[UnionCoverage]],
    stage_dir: Path,
    image: str,
    binary_name: str,
    project: str = "",
) -> UnionReport:
    """Build+fuzz each driver independently, retain its profdata, union offline.

    ``run_one(driver, stage_dir, idx)`` returns the staged per-driver profdata
    path (or ``None`` if that driver failed to build/fuzz). ``union_fn`` unions
    everything staged so far. The union step is SKIPPED when no driver produced
    a profile (nothing to union). Both callables are injected for testability.
    """
    stage_dir.mkdir(parents=True, exist_ok=True)
    per: List[DriverResult] = []
    n_profiles = 0
    for idx, driver in enumerate(drivers):
        try:
            pd = run_one(driver, stage_dir, idx)
        except Exception as e:  # noqa: BLE001 — one bad driver never aborts the sweep
            logger.warning("union_over_drivers: driver %s failed: %s", driver.name, e)
            pd = None
        ok = pd is not None
        if ok:
            n_profiles += 1
        per.append(DriverResult(driver=str(driver),
                                profdata=str(pd) if pd else None, ok=ok))

    union: Optional[dict] = None
    if n_profiles > 0:
        cov = union_fn(stage_dir, binary_name, image)
        if cov is not None:
            union = _cov_to_dict(cov)
    else:
        logger.warning("union_over_drivers: no driver produced a profile — "
                       "nothing to union")
    return UnionReport(project=project, n_drivers=len(drivers),
                       n_profiles=n_profiles, union=union, per_driver=per)


# --------------------------------------------------------------------------- #
# Real per-driver runner + CLI (docker/OSS-Fuzz integration; validated by a
# live run, not unit tests). ExtendedFuzzer is imported lazily so importing this
# module for the pure orchestration never pulls in heavy project deps.
# --------------------------------------------------------------------------- #
def _real_run_one(
    driver: Path,
    stage_dir: Path,
    idx: int,
    *,
    project: str,
    duration: int,
    seed_corpus_dir: Optional[str],
) -> Optional[Path]:
    """Build+fuzz ``driver`` ``duration`` s (address build) with a separate
    coverage build, and stage its ``dumps/merged.profdata`` as ``<idx>.profdata``.
    Also stages one library-linked binary for the union export. Returns the
    staged profdata path, or ``None`` on failure.

    The OSS-Fuzz ``build/out`` dir is read FROM the fuzzer instance
    (``_get_oss_fuzz_dir()`` — a session-stable checkout), not passed in, since
    it is resolved per-process, not at a fixed path."""
    from scripts.run_extended_fuzzing import ExtendedFuzzer  # lazy: heavy deps

    work = stage_dir / f"work_{idx:02d}"
    fz = ExtendedFuzzer(
        project=project,
        fuzz_target_path=str(driver),
        output_dir=str(work),
        duration=duration,
        seed_corpus_dir=seed_corpus_dir,
    )
    fz.run()
    cov_proj = getattr(fz, "coverage_project_name", None) or \
        getattr(fz, "generated_project_name", None)
    if not cov_proj:
        logger.warning("driver %s: no coverage project name after run", driver.name)
        return None
    build_out = fz._get_oss_fuzz_dir() / "build" / "out" / cov_proj
    src_pd = build_out / "dumps" / "merged.profdata"
    if not src_pd.is_file():
        logger.warning("driver %s: no profdata at %s", driver.name, src_pd)
        return None
    dst_pd = stage_dir / f"{idx:02d}.profdata"
    shutil.copy2(src_pd, dst_pd)
    # Stage one library-linked binary (once) for the union llvm-cov export.
    tgt = getattr(fz, "target_name", None)
    if tgt:
        src_bin = build_out / tgt
        dst_bin = stage_dir / tgt
        if src_bin.is_file() and not dst_bin.exists():
            shutil.copy2(src_bin, dst_bin)
    return dst_pd


def _run_cli(argv, *, run_one=None, union_fn=union_coverage, out=None) -> int:
    import argparse
    import functools
    import sys as _sys

    out = out if out is not None else _sys.stdout
    ap = argparse.ArgumentParser(
        prog="python -m scripts.measure_union_coverage",
        description="Per-binary UNION coverage (SynapseFlow-style).")
    ap.add_argument("--project", required=True, help="OSS-Fuzz project name")
    ap.add_argument("--drivers-dir", required=True,
                    help="dir of per-driver sources (e.g. <base>/merged/synthesized)")
    ap.add_argument("--stage-dir", required=True,
                    help="scratch dir to stage per-driver profdata + the export binary")
    ap.add_argument("--duration", type=int, default=300,
                    help="per-driver fuzz seconds (default 300)")
    ap.add_argument("--seed-corpus", default=None, help="shared seed corpus dir")
    ap.add_argument("--image", default=None,
                    help="project image (default gcr.io/oss-fuzz/<project>)")
    ap.add_argument("--binary", default=None,
                    help="library-linked binary name for the union export "
                         "(default: auto-staged by the runner)")
    ap.add_argument("--report", default=None, help="write the JSON report here too")
    ns = ap.parse_args(argv)

    image = ns.image or f"gcr.io/oss-fuzz/{ns.project}"
    drivers = discover_drivers(Path(ns.drivers_dir))
    if not drivers:
        print(json.dumps({"error": f"no drivers under {ns.drivers_dir}"}), file=out)
        return 1

    if run_one is None:
        run_one = functools.partial(
            _real_run_one, project=ns.project, duration=ns.duration,
            seed_corpus_dir=ns.seed_corpus)

    stage = Path(ns.stage_dir)

    # The union export binary is staged by the runner DURING the loop, so resolve
    # it lazily at union time (after staging), not before — wrap the union fn.
    def _resolving_union(sd, binary, img):
        return union_fn(sd, binary or _resolve_staged_binary(sd), img)

    rep = union_over_drivers(
        drivers, run_one=run_one, union_fn=_resolving_union, stage_dir=stage,
        image=image, binary_name=ns.binary or "", project=ns.project)

    payload = {
        "project": rep.project, "n_drivers": rep.n_drivers,
        "n_profiles": rep.n_profiles, "union": rep.union,
        "per_driver": [{"driver": r.driver, "ok": r.ok} for r in rep.per_driver],
    }
    text = json.dumps(payload, indent=2)
    print(text, file=out)
    if ns.report:
        Path(ns.report).write_text(text)
    return 0 if rep.union else 1


def _resolve_staged_binary(stage_dir: Path) -> str:
    """Best-effort: the runner copies a library-linked binary into the stage dir;
    pick the first non-profdata file as the union export binary."""
    if stage_dir.is_dir():
        for p in sorted(stage_dir.iterdir()):
            if p.is_file() and p.suffix != ".profdata":
                return p.name
    return ""


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _sys.exit(_run_cli(_sys.argv[1:]))
