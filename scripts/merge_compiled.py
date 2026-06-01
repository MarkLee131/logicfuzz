"""Merge the COMPILED, PREFLIGHT-CLEAN drivers into one harness (99.fuzz_target).

Two filters, in order:
1. Compiled = has a coverage report (the pipeline only produces those for
   drivers that built). Non-compiling drivers break the merged build.
2. Preflight = host-runnable binary preserved under preflight_bins/ that does
   NOT die-on-empty (immediate SEGV with 0 edges). A merged harness runs every
   sub-driver in one process, so one dead driver poisons the whole campaign
   (observed: a c-ares driver SEGV'd in free() → fuzzer exited after ~4 execs →
   the merged coverage A/B was nullified). Preflight drops only truly-dead
   drivers; a driver that explores edges but crashes on a degenerate seed is
   kept (it crashes-and-continues under -ignore_crashes=1). Skipped when no
   preserved binaries exist (then we merge all compiled, as before).

Usage: python scripts/merge_compiled.py <project>
"""
import sys
import glob
from pathlib import Path

from tools.merge_drivers.merge import (
    SynthesizedDriver, DispatchMode, SelectorPosition)


def _preflight_drop(proj, srcs):
    """Drop drivers whose preserved binary is dead-on-empty / no-progress.

    Returns the surviving sources. No-op (returns srcs) when fewer than 2
    preserved binaries are resolvable — same fail-open policy as
    run_single_fuzz._preflight_filter_candidates.
    """
    base = Path(f'results/output-{proj}-project')
    bindir = base / 'preflight_bins'
    if not bindir.is_dir():
        return srcs
    pairs = []
    for s in srcs:
        b = bindir / s.stem
        if b.is_file():
            pairs.append((s, b))
    if len(pairs) < 2:
        return srcs
    try:
        from tools.merge_drivers.preflight import preflight
    except ImportError:
        return srcs
    results = preflight(pairs, smoke_duration_sec=8, drop_on_crash=True)
    # Drop only genuine dead-on-empty / no-progress; keep "binary_broken"
    # (couldn't-vet) and healthy drivers.
    dropped = {r.driver_path for r in results
               if not r.accepted
               and r.rejection_reason.startswith(('dead_on_empty', 'no_progress'))}
    kept = [s for s in srcs if str(s) not in dropped]
    if dropped:
        print(f'preflight dropped {len(dropped)} driver(s): '
              f'{sorted(Path(p).stem for p in dropped)}')
    return kept if len(kept) >= 2 else srcs


def main():
    proj = sys.argv[1]
    ft = Path(f'results/output-{proj}-project/fuzz_targets')
    compiled = {
        Path(s).parts[-3].split('.')[0]
        for s in glob.glob(
            f'results/output-{proj}-project/code-coverage-reports/*/linux/summary.json')
    }
    srcs = [p for p in sorted(ft.glob('[0-9][0-9].fuzz_target'))
            if p.stem in compiled]
    if len(srcs) < 2:
        srcs = sorted(ft.glob('[0-9][0-9].fuzz_target'))  # fallback: all
    srcs = _preflight_drop(proj, srcs)
    drv = SynthesizedDriver.from_paths(
        srcs, mode=DispatchMode.UNIFORM, position=SelectorPosition.TAIL,
        weights=None)
    out = Path(f'results/output-{proj}-project/merged')
    out.mkdir(parents=True, exist_ok=True)
    synth = drv.save(out)
    subs = sorted(p for p in synth.glob('*.c') if not p.name.startswith('entry'))
    comb = "/* merged */\n"
    for p in subs:
        comb += f"\n/* {p.name} */\n" + p.read_text() + "\n"
    comb += "\n/* dispatcher */\n" + (synth / 'entry.c').read_text()
    (ft / '99.fuzz_target').write_text(comb)
    print(f'merged {len(srcs)} compiled drivers -> 99.fuzz_target ({len(comb)} bytes)')


if __name__ == '__main__':
    main()
