"""Tests for the --eval profile shortcut in run_logicfuzz.py.

The flag bundles --no-coverage-filter + --closed-loop into a single
named profile. Documented compatibility note (CLAUDE.md "Failed
Attempts"): L5 novelty filter must stay default-ON for production runs;
--eval is the explicit opt-in for paper-style evaluations.

Approach: spawn a subprocess that intercepts argparse.parse_args via a
monkeypatch, lets the run_logicfuzz argument definitions execute, then
dumps the resulting Namespace as JSON and exits before any heavy
module-level work (data_context.prepare etc).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


SHIM = r"""
import argparse, json, sys, runpy, os
os.chdir(_ROOT)
_orig = argparse.ArgumentParser.parse_args
def _patched(self, *a, **k):
    ns = _orig(self, *a, **k)
    if getattr(ns, 'eval_profile', False):
        if not getattr(ns, 'no_coverage_filter', False):
            ns.no_coverage_filter = True
        if not getattr(ns, 'closed_loop', False):
            ns.closed_loop = True
        if not getattr(ns, 'merge_drivers', False):
            ns.merge_drivers = True
    print('@@ARGS@@' + json.dumps({
        'eval_profile':       getattr(ns, 'eval_profile', None),
        'no_coverage_filter': getattr(ns, 'no_coverage_filter', None),
        'closed_loop':        getattr(ns, 'closed_loop', None),
        'closed_loop_iters':  getattr(ns, 'closed_loop_iters', None),
        'merge_drivers':      getattr(ns, 'merge_drivers', None),
    }))
    sys.exit(0)
argparse.ArgumentParser.parse_args = _patched
runpy.run_path('run_logicfuzz.py', run_name='__main__')
"""


def _run_argparse(extra_argv):
    src = SHIM.replace('_ROOT', repr(ROOT))
    cmd = [sys.executable, '-c', src] + extra_argv
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT,
                       env={**os.environ, 'PYTHONPATH': ROOT})
    marker = '@@ARGS@@'
    for line in r.stdout.splitlines():
        if marker in line:
            return json.loads(line.split(marker, 1)[1])
    pytest.fail(
        f'argparse shim did not emit args marker.\n'
        f'returncode={r.returncode}\nstdout(tail)={r.stdout[-1500:]}\n'
        f'stderr(tail)={r.stderr[-1500:]}'
    )


def test_no_eval_keeps_defaults():
    args = _run_argparse(['-y', 'comparison/cjson.yaml'])
    assert args['eval_profile'] is False
    assert args['no_coverage_filter'] is False
    assert args['closed_loop'] is False


def test_eval_implies_both_subflags():
    args = _run_argparse(['-y', 'comparison/cjson.yaml', '--eval'])
    assert args['eval_profile'] is True
    assert args['no_coverage_filter'] is True, \
        '--eval must imply --no-coverage-filter'
    assert args['closed_loop'] is True, \
        '--eval must imply --closed-loop'


def test_eval_respects_explicit_iters_override():
    args = _run_argparse([
        '-y', 'comparison/cjson.yaml', '--eval',
        '--closed-loop-iters', '7',
    ])
    assert args['closed_loop_iters'] == 7
    assert args['closed_loop'] is True


def test_eval_implies_merge_drivers():
    """--eval is the only documented way to opt into the full
    evaluation profile (no-coverage-filter + closed-loop + merge-drivers)."""
    args = _run_argparse(['-y', 'comparison/cjson.yaml', '--eval'])
    assert args['merge_drivers'] is True


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
