"""CLI for ``python -m tools.merge_drivers``.

Subcommands:

  ``merge``       emit synthesized/ + entry + build snippet (no preflight,
                  no coverage selection — just compile-validate + dispatcher).
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
from tools.merge_drivers.corpus import union_corpus  # noqa: E402
import tools.merge_drivers.pipeline as _pipeline  # noqa: E402


def _parse_pair(spec: str) -> tuple[Path, Path]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"--pair expects SRC=BIN, got {spec!r}"
        )
    src, _, binary = spec.partition("=")
    return Path(src), Path(binary)


def _lang_from_inputs(inputs: List[Path]) -> Optional[str]:
    """Infer stock_lang from the first input's extension; None if ambiguous."""
    for p in inputs:
        ext = p.suffix.lower()
        if ext in (".cc", ".cpp", ".cxx"):
            return "cpp"
        if ext in (".c",):
            return "c"
    return None


def _cmd_merge(args: argparse.Namespace) -> int:
    """Thin adapter: gather inputs, call run_merge_pipeline, print summary."""
    inputs = [Path(p) for p in args.inputs]
    missing = [p for p in inputs if not p.exists()]
    if missing:
        print(f"error: missing inputs: {missing}", file=sys.stderr)
        return 2

    out = Path(args.output)

    # Derive stock_lang: explicit --lang flag, then file extension, then None.
    lang_arg = getattr(args, "lang", None)
    if lang_arg:
        stock_lang: Optional[str] = lang_arg.lower()
    else:
        stock_lang = _lang_from_inputs(inputs)

    # Derive iquote_dirs from --includes (space- or comma-separated, or list).
    includes = getattr(args, "includes", None) or ""
    if isinstance(includes, list):
        iquote_dirs: List[str] = [s for s in includes if s]
    else:
        # Accept space/comma-separated string from argparse default
        iquote_dirs = [s.strip() for s in includes.replace(",", " ").split() if s.strip()]

    project = getattr(args, "project", None) or ""

    result = _pipeline.run_merge_pipeline(
        inputs,
        project=project,
        stock_lang=stock_lang,
        iquote_dirs=iquote_dirs,
        out_dir=out,
        trial_verdicts=None,      # CLI has no per-trial triage
        preflight_dir=None,       # merge subcommand: no binaries
        cov_reports_dir=None,
        model_name=None,
        cdf=(getattr(args, "mode", "uniform") == "cdf"),
    )

    if result is None:
        print(
            "[merge] run_merge_pipeline returned None — not enough surviving "
            "drivers (need ≥2 after gates). Check logs for details.",
            file=sys.stderr,
        )
        return 1

    print(f"[merge] synthesized harness → {result}")
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


def _cmd_pipeline(args: argparse.Namespace) -> int:
    """Thin adapter: O1 preflight (explicit pairs) → run_merge_pipeline → O4 corpus.

    O1 (preflight with explicit src=binary pairs) and O4 (corpus union) are kept
    as leaf-primitive calls because run_merge_pipeline resolves binaries via a
    preflight_dir directory rather than explicit pairs, and does not perform corpus
    union. Everything else (orphan filter, compile-validate, dominance filter,
    synthesis) is handled by run_merge_pipeline.
    """
    pairs: List[tuple[Path, Path]] = args.pair
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    project_root = Path(args.project_root) if args.project_root else None

    # ----------------- O1: Pre-flight -----------------
    # Run preflight with explicit src=binary pairs. Survivors are passed to
    # run_merge_pipeline via a preflight_dir populated with symlinks.
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

    # Build a preflight_dir with symlinks so run_merge_pipeline can resolve
    # binaries for any additional internal preflight it may do.
    preflight_dir = out / "preflight_bins"
    preflight_dir.mkdir(parents=True, exist_ok=True)
    for r in accepted:
        src_path = Path(r.driver_path)
        bin_path = Path(r.fuzzer_binary)
        link = preflight_dir / src_path.stem
        if not link.exists() and bin_path.exists():
            try:
                link.symlink_to(bin_path.resolve())
            except OSError:
                pass

    # Surviving source paths from preflight
    surviving_sources = [Path(r.driver_path) for r in accepted]

    # Coverage reports dir for dominance filter
    cov_reports_dir: Optional[Path] = None
    if project_root is not None:
        cov_dir = project_root / "code-coverage-reports"
        if cov_dir.exists():
            cov_reports_dir = cov_dir

    # Derive stock_lang and iquote_dirs
    lang_arg = getattr(args, "lang", None)
    if lang_arg:
        stock_lang: Optional[str] = lang_arg.lower()
    else:
        stock_lang = _lang_from_inputs(surviving_sources)

    includes = getattr(args, "includes", None) or ""
    if isinstance(includes, list):
        iquote_dirs: List[str] = [s for s in includes if s]
    else:
        iquote_dirs = [s.strip() for s in includes.replace(",", " ").split() if s.strip()]

    project = getattr(args, "project", None) or ""

    # ----------------- O2+O3: run_merge_pipeline (gates + synthesis) -----------------
    result = _pipeline.run_merge_pipeline(
        surviving_sources,
        project=project,
        stock_lang=stock_lang,
        iquote_dirs=iquote_dirs,
        out_dir=out,
        trial_verdicts=None,          # CLI has no per-trial triage
        preflight_dir=preflight_dir,
        cov_reports_dir=cov_reports_dir,
        model_name=None,
        cdf=(getattr(args, "mode", "cdf") == "cdf"),
    )

    if result is None:
        print(
            "[pipeline] run_merge_pipeline returned None — not enough surviving "
            "drivers (need ≥2 after all gates). Check logs for details.",
            file=sys.stderr,
        )
        return 1

    print(f"[pipeline] merged harness → {result}")

    # ----------------- O4: Corpus + dict union -----------------
    # Reload the synthesized driver to get driver metadata for corpus union.
    # run_merge_pipeline writes the synthesized/ dir; we reconstruct the SynthesizedDriver
    # from the saved artifacts.
    if args.skip_corpus:
        print("[pipeline] corpus union skipped")
    else:
        try:
            # Re-load the synthesized driver from the saved artifacts so we can
            # call union_corpus with accurate driver metadata.
            synth_dir = out / "synthesized"
            _mode = DispatchMode(getattr(args, "mode", "cdf"))
            _pos = SelectorPosition(getattr(args, "position", "tail"))
            # Collect the synthesized TU sources
            _synth_sources = sorted(synth_dir.glob("*.c")) + sorted(synth_dir.glob("*.cc"))
            if _synth_sources:
                drv = SynthesizedDriver.from_paths(
                    _synth_sources, mode=_mode, position=_pos, weights=None)

                if args.dict:
                    user_dicts = {Path(d) for d in args.dict}
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
            else:
                print("[pipeline] corpus union skipped — no synthesized TU sources found")
        except Exception as _e:
            print(f"[pipeline] corpus union failed ({_e}); "
                  f"merge artifacts are still usable", file=sys.stderr)

    # ----------------- summary -----------------
    print(f"[pipeline] done. artifacts under {out}/")
    print(f"  synthesized/  — multi-TU sub-drivers + entry")
    if not args.skip_corpus:
        print(f"  corpus_merged/ — tagged seed corpus")
    print(f"  oss_fuzz_build_snippet.sh — append to OSS-Fuzz project build.sh")
    print(f"  preflight.json — preflight telemetry")
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
    pm.add_argument("--project", default=None,
                    help="OSS-Fuzz project name; when absent compile-gate fail-opens")
    pm.add_argument("--lang", default=None, choices=["c", "cpp"],
                    help="force stock-target language (c or cpp); "
                         "defaults to input file extension")
    pm.add_argument("--target-name", default="synthesized_fuzzer")
    pm.add_argument("--libs", default=None)
    pm.add_argument("--includes", default=None)
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
    pl.add_argument("--lang", default=None, choices=["c", "cpp"],
                    help="force stock-target language (c or cpp); "
                         "defaults to input file extension")
    pl.add_argument("--project-root", default=None,
                    help="results/output-<proj>-project/ root for "
                         "coverage reports + corpus discovery")
    pl.add_argument("--output", required=True,
                    help="dir for synthesized/, corpus_merged/, "
                         "preflight.json, build snippet")
    pl.add_argument("--top-k", type=int, default=None,
                    help="cap on selected drivers (default: no cap; "
                         "greedy stops naturally at zero marginal gain); "
                         "note: selection is now via run_merge_pipeline's "
                         "dominance-filter (kept for forward compat)")
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
    pl.add_argument("--libs", default=None)
    pl.add_argument("--includes", default=None)
    pl.add_argument("--dict", action="append", default=[],
                    help="optional dictionary file(s) to include in union; "
                         "stem is matched to sub-driver id")
    pl.set_defaults(func=_cmd_pipeline)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
