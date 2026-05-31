"""Merge the COMPILED drivers of a project's output into one harness (99.fuzz_target).

Compiled = has a coverage report (the pipeline only produces those for drivers
that built). Non-compiling drivers break the merged build, so we exclude them.

Usage: python scripts/merge_compiled.py <project>
"""
import sys
import glob
from pathlib import Path

from tools.merge_drivers.merge import (
    SynthesizedDriver, DispatchMode, SelectorPosition)


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
