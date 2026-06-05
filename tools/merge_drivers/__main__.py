"""CLI for ``python -m tools.merge_drivers``.

Subcommands:

  ``merge``       emit synthesized/ + entry + build snippet (no preflight,
                  no coverage selection — just rename + dispatcher).
  ``preflight``   smoke-fuzz N built binaries → JSON report (no merge).
  ``pipeline``    full O1 → O2 → O3 → O4 chain. Smoke-fuzzes all
                  candidate binaries, picks Top-K by max-coverage greedy
                  using OSS-Fuzz coverage reports, emits the synthesized
                  harness with CDF-weighted dispatch and a tagged
                  corpus union.

Typical usage::

    # End-to-end (preflight built binaries, select+merge survivors):
    python -m tools.merge_drivers pipeline \\
        --project libucl \\
        --project-root results/output-libucl-project \\
        --pair fuzz_targets/01.fuzz_target=oss-fuzz/build/out/.../01_fuzzer \\
        --pair fuzz_targets/02.fuzz_target=oss-fuzz/build/out/.../02_fuzzer \\
        ... \\
        --output results/output-libucl-project/merged \\
        --top-k 12 --mode cdf --position tail --smoke-duration 15

    # Just merge (no smoke / coverage data — uniform dispatch, no corpus):
    python -m tools.merge_drivers merge \\
        --inputs results/.../01.fuzz_target ...05.fuzz_target \\
        --output /tmp/synthesized
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

# Make the package importable when invoked as ``python -m tools.merge_drivers``
# from the repo root, regardless of pyright's project-root config.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.merge_drivers.merge import (  # noqa: E402
    DispatchMode,
    SelectorPosition,
    SynthesizedDriver,
)
from tools.merge_drivers.preflight import (  # noqa: E402
    PreflightResult,
    preflight,
    write_report,
)
from tools.merge_drivers.select import (  # noqa: E402
    DriverCoverage,
    select_top_k,
)
from tools.merge_drivers.corpus import union_corpus  # noqa: E402


def _parse_pair(spec: str) -> tuple[Path, Path]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"--pair expects SRC=BIN, got {spec!r}"
        )
    src, _, binary = spec.partition("=")
    return Path(src), Path(binary)


def _cmd_merge(args: argparse.Namespace) -> int:
    inputs = [Path(p) for p in args.inputs]
    missing = [p for p in inputs if not p.exists()]
    if missing:
        print(f"error: missing inputs: {missing}", file=sys.stderr)
        return 2
    # Only merge drivers whose trial actually BUILT. ``fuzz_targets/`` holds the
    # best source of EVERY trial — including ones that failed to compile (the
    # eval still writes ``best_result.fuzz_target_source`` regardless of
    # ``compiles``). Those failures take two shapes that both poison the fused
    # build: an unfilled bare skeleton (LLM never produced a buildable driver →
    # leftover ``HOLE[...]`` + unsafe defaults) and a driver that references a
    # hallucinated / non-exported symbol (compiles but won't link, e.g. lcms
    # ``cmsBuildGammaTHR``). The pipeline merge
    # (run_single_fuzz._maybe_merge_drivers) excludes both via the trial's
    # ``compiles==True`` flag. We reuse that SAME authoritative signal — it is
    # persisted per trial at ``<base>/status/<NN>/result.json`` — instead of any
    # build-independent heuristic, so the filter can't regress a driver that
    # genuinely builds. Fallback (no status file, e.g. ad-hoc inputs): drop bare
    # skeletons by their leftover ``HOLE[`` marker.
    def _trial_failed_to_build(p: Path) -> bool:
        status = p.parent.parent / "status" / p.stem / "result.json"
        if status.exists():
            try:
                return json.load(status.open()).get("compiles") is False
            except Exception:
                pass  # unreadable status → fall through to the static check
        return "HOLE[" in p.read_text(encoding="utf-8", errors="replace")

    kept = [p for p in inputs if not _trial_failed_to_build(p)]
    dropped = [p for p in inputs if p not in kept]
    if dropped:
        print(f"[merge] skipped {len(dropped)} non-compiling driver(s) "
              f"(trial compiles=False / unfilled skeleton): "
              f"{[p.name for p in dropped]}", file=sys.stderr)
    if len(kept) < 2:
        print(f"error: only {len(kept)} buildable driver(s) after dropping "
              f"non-compiling ones; need >=2 to merge", file=sys.stderr)
        return 2
    inputs = kept
    drv = SynthesizedDriver.from_paths(
        inputs,
        mode=DispatchMode(args.mode),
        position=SelectorPosition(args.position),
        weights=None,  # uniform — pipeline command supplies weights
    )
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    synth_dir = drv.save(out)

    if args.libs or args.includes or args.target_name != "synthesized_fuzzer":
        snippet = drv.emit_oss_fuzz_build_snippet(
            target_name=args.target_name,
            extra_libs=args.libs or "",
            extra_includes=args.includes or "",
        )
        (out / "oss_fuzz_build_snippet.sh").write_text(snippet)

    print(
        f"[merge] {drv.driver_count} drivers → {synth_dir}  "
        f"(mode={drv.mode.value}, position={drv.position.value}, "
        f"selector_bytes={drv.selector_bytes}, "
        f"lang={'C++' if drv.is_cpp else 'C'})"
    )
    print(f"[merge] build snippet: {out / 'oss_fuzz_build_snippet.sh'}")
    return 0


def _cmd_preflight(args: argparse.Namespace) -> int:
    pairs: List[tuple[Path, Path]] = args.pair
    workspace = Path(args.workspace) if args.workspace else None
    results = preflight(
        candidates=pairs,
        smoke_duration_sec=args.smoke_duration,
        workspace_root=workspace,
        min_edges=args.min_edges,
        drop_on_crash=not args.keep_crashing,
    )
    write_report(results, Path(args.output))

    accepted = [r for r in results if r.accepted]
    print(f"[preflight] {len(accepted)}/{len(results)} accepted "
          f"→ {args.output}")
    for r in results:
        tag = "ACCEPT" if r.accepted else "REJECT"
        print(f"  [{tag}] edges={r.edges_seen:>5} "
              f"ex/s={r.execs_per_sec:>7.0f} "
              f"{Path(r.driver_path).name}"
              + (f"  ({r.rejection_reason})" if not r.accepted else ""))
    if args.print_accepted_sources:
        for r in accepted:
            print(r.driver_path)
    return 0


def _resolve_coverage_report(
    project_root: Path, driver_path: Path
) -> Optional[Path]:
    """Find the OSS-Fuzz coverage report dir for a sub-driver source.

    Layout: ``<project_root>/code-coverage-reports/<driver_filename>/``
    Returns None if absent — the selector then falls back to the
    singleton placeholder.
    """
    candidate = (
        project_root / "code-coverage-reports" / driver_path.name
    )
    return candidate if candidate.exists() else None


def _cmd_pipeline(args: argparse.Namespace) -> int:
    pairs: List[tuple[Path, Path]] = args.pair
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    project_root = Path(args.project_root) if args.project_root else None

    # ----------------- O1: Pre-flight -----------------
    if args.skip_preflight:
        accepted: List[PreflightResult] = [
            PreflightResult(
                driver_path=str(src),
                fuzzer_binary=str(b),
                duration_sec=0,
                exit_code=0,
                edges_seen=1,
                execs_per_sec=0.0,
                crashed=False,
                accepted=True,
                rejection_reason="",
            )
            for src, b in pairs
        ]
        write_report(accepted, out / "preflight.json")
        print(f"[pipeline] preflight skipped — accepting all {len(pairs)} candidates")
    else:
        all_results = preflight(
            candidates=pairs,
            smoke_duration_sec=args.smoke_duration,
            workspace_root=out / "preflight_workspace",
            min_edges=args.min_edges,
            drop_on_crash=not args.keep_crashing,
        )
        write_report(all_results, out / "preflight.json")
        accepted = [r for r in all_results if r.accepted]
        print(f"[pipeline] preflight: {len(accepted)}/{len(all_results)} accepted")
        for r in all_results:
            if not r.accepted:
                print(f"  REJECT {Path(r.driver_path).name}: {r.rejection_reason}")
        if not accepted:
            print("[pipeline] no drivers survived preflight; aborting", file=sys.stderr)
            return 1

    # ----------------- O2: Coverage-aware selection -----------------
    if project_root is None:
        print(
            "[pipeline] WARNING: --project-root not given; coverage "
            "data unavailable — selection will fall through to all "
            "preflight survivors with uniform weights",
            file=sys.stderr,
        )
        coverages: List[DriverCoverage] = [
            DriverCoverage(
                driver_path=Path(r.driver_path),
                reached_funcs=frozenset({f"__fallback__:{Path(r.driver_path).stem}"}),
                edges_15s=r.edges_seen,
                has_real_data=False,
            )
            for r in accepted
        ]
        require_data = False
    else:
        coverages = []
        for r in accepted:
            drv_src = Path(r.driver_path)
            report = _resolve_coverage_report(project_root, drv_src)
            cov = DriverCoverage.from_oss_fuzz_report(
                drv_src, report, edges_15s=r.edges_seen,
            )
            coverages.append(cov)
        require_data = True

    sel = select_top_k(
        coverages,
        k=args.top_k,
        require_coverage_data=require_data,
    )
    print(f"[pipeline] selection: {len(sel.steps)} drivers (covered "
          f"{sel.total_funcs_covered} unique functions)")
    for step in sel.steps:
        print(f"  {step.driver.driver_path.name}: "
              f"+{step.marginal_funcs} funcs (cum={step.cumulative_funcs})")
    if sel.skipped_no_data:
        print(f"  [skipped {len(sel.skipped_no_data)} without coverage data]")
    if not sel.steps:
        print("[pipeline] no drivers selected; aborting", file=sys.stderr)
        return 1

    # Persist selection report
    (out / "selection.json").write_text(json.dumps({
        "n_selected": len(sel.steps),
        "total_funcs_covered": sel.total_funcs_covered,
        "n_skipped_no_data": len(sel.skipped_no_data),
        "steps": [
            {
                "driver": str(s.driver.driver_path),
                "marginal_funcs": s.marginal_funcs,
                "cumulative_funcs": s.cumulative_funcs,
                "edges_15s": s.driver.edges_15s,
                "has_real_data": s.driver.has_real_data,
            }
            for s in sel.steps
        ],
    }, indent=2))

    # ----------------- O3: CDF emit (or uniform) -----------------
    selected_paths = [s.driver.driver_path for s in sel.steps]
    selected_weights = [float(s.marginal_funcs) for s in sel.steps]
    mode = DispatchMode(args.mode)
    drv = SynthesizedDriver.from_paths(
        selected_paths,
        mode=mode,
        position=SelectorPosition(args.position),
        weights=selected_weights if mode == DispatchMode.CDF else None,
    )
    synth_dir = drv.save(out)
    if args.libs or args.includes or args.target_name != "synthesized_fuzzer":
        snippet = drv.emit_oss_fuzz_build_snippet(
            target_name=args.target_name,
            extra_libs=args.libs or "",
            extra_includes=args.includes or "",
        )
        (out / "oss_fuzz_build_snippet.sh").write_text(snippet)
    print(f"[pipeline] merged {drv.driver_count} sub-drivers → {synth_dir}")
    print(f"  mode={drv.mode.value}, position={drv.position.value}, "
          f"selector_bytes={drv.selector_bytes}, "
          f"lang={'C++' if drv.is_cpp else 'C'}")

    # ----------------- O4: Corpus + dict union -----------------
    if args.skip_corpus:
        print("[pipeline] corpus union skipped")
    else:
        # Sort selected paths back to drv.drivers order — `from_paths`
        # may reorder by filename. Build dict path list aligned to that.
        if args.dict:
            user_dicts = {Path(d) for d in args.dict}
            # Match dict-to-driver on exact stem only. The previous
            # ``startswith(driver_id)`` fallback paired ``10.dict`` with
            # driver_id ``"1"`` (any string-prefix match), silently
            # misrouting dictionaries between sub-drivers.
            dict_paths: Optional[List[Optional[Path]]] = [
                next(
                    (p for p in user_dicts
                     if p.stem == d.driver_path.stem
                     or p.stem == d.driver_id),
                    None,
                )
                for d in drv.drivers
            ]
        else:
            dict_paths = None
        stats = union_corpus(
            synth=drv,
            output_dir=out,
            project_root=project_root,
            dict_paths=dict_paths,
        )
        print(f"[pipeline] corpus union: {stats.n_seeds_tagged} seeds "
              f"from {stats.n_drivers_with_corpus} sub-drivers"
              + (f", {stats.n_dicts_merged} dicts merged" if stats.n_dicts_merged else "")
              + f" → {stats.output_corpus_dir}")

    # ----------------- summary -----------------
    print(f"[pipeline] done. artifacts under {out}/")
    print(f"  synthesized/  — multi-TU sub-drivers + entry.{drv.entry_suffix}")
    print(f"  corpus_merged/ — tagged seed corpus" if not args.skip_corpus else "")
    print(f"  oss_fuzz_build_snippet.sh — append to OSS-Fuzz project build.sh")
    print(f"  preflight.json, selection.json — telemetry")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    p = argparse.ArgumentParser(prog="python -m tools.merge_drivers")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ------ merge ------
    pm = sub.add_parser("merge", help="emit synthesized harness")
    pm.add_argument("--inputs", nargs="+", required=True,
                    help=".fuzz_target source files to merge")
    pm.add_argument("--output", required=True)
    pm.add_argument("--target-name", default="synthesized_fuzzer")
    pm.add_argument("--libs", default="")
    pm.add_argument("--includes", default="")
    pm.add_argument("--mode", choices=["uniform", "cdf"], default="uniform",
                    help="dispatch mode (cdf needs weights — use pipeline)")
    pm.add_argument("--position", choices=["head", "tail"], default="tail",
                    help="selector position in input (default tail)")
    pm.set_defaults(func=_cmd_merge)

    # ------ preflight ------
    pp = sub.add_parser("preflight", help="smoke-fuzz built binaries")
    pp.add_argument("--pair", action="append", required=True, type=_parse_pair,
                    metavar="SRC=BIN",
                    help="SRC=BIN: source path = built fuzzer binary path")
    pp.add_argument("--smoke-duration", type=int, default=15)
    pp.add_argument("--min-edges", type=int, default=1)
    pp.add_argument("--keep-crashing", action="store_true")
    pp.add_argument("--workspace", default=None)
    pp.add_argument("--output", required=True)
    pp.add_argument("--print-accepted-sources", action="store_true")
    pp.set_defaults(func=_cmd_preflight)

    # ------ pipeline ------
    pl = sub.add_parser(
        "pipeline",
        help="O1→O2→O3→O4 end-to-end: preflight + select + merge + corpus",
        epilog=(
            "Coverage data source: O2 reads per-driver reached functions "
            "from results/output-<proj>-project/code-coverage-reports/"
            "<id>.fuzz_target/linux/summary.json. These are produced by "
            "LogicFuzz's main pipeline (run_logicfuzz.py) when it "
            "evaluates each driver — no separate coverage build needed. "
            "If a driver has no summary.json, it is skipped (printed "
            "under 'skipped without coverage data'); re-run the LogicFuzz "
            "evaluation for that driver to produce it."
        ),
    )
    pl.add_argument("--pair", action="append", required=True, type=_parse_pair,
                    metavar="SRC=BIN",
                    help="SRC=BIN: source path = built fuzzer binary path")
    pl.add_argument("--project", default=None,
                    help="OSS-Fuzz project name (informational only)")
    pl.add_argument("--project-root", default=None,
                    help="results/output-<proj>-project/ root for "
                         "coverage reports + corpus discovery")
    pl.add_argument("--output", required=True,
                    help="dir for synthesized/, corpus_merged/, "
                         "preflight.json, selection.json, build snippet")
    pl.add_argument("--top-k", type=int, default=None,
                    help="cap on selected drivers (default: no cap; "
                         "greedy stops naturally at zero marginal gain)")
    pl.add_argument("--mode", choices=["uniform", "cdf"], default="cdf")
    pl.add_argument("--position", choices=["head", "tail"], default="tail")
    pl.add_argument("--smoke-duration", type=int, default=15)
    pl.add_argument("--min-edges", type=int, default=1)
    pl.add_argument("--keep-crashing", action="store_true")
    pl.add_argument("--skip-preflight", action="store_true",
                    help="skip O1 (use when binaries known-good)")
    pl.add_argument("--skip-corpus", action="store_true",
                    help="skip O4 corpus union")
    pl.add_argument("--target-name", default="synthesized_fuzzer")
    pl.add_argument("--libs", default="")
    pl.add_argument("--includes", default="")
    pl.add_argument("--dict", action="append", default=[],
                    help="optional dictionary file(s) to include in union; "
                         "stem is matched to sub-driver id")
    pl.set_defaults(func=_cmd_pipeline)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
