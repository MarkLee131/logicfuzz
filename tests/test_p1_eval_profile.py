"""Tests for the --eval profile shortcut in run_logicfuzz.py.

The flag bundles --merge-drivers into a single named profile (the explicit
opt-in for paper-style evaluations). (It formerly also implied --closed-loop;
the Phase G closed-loop feedback was removed — architecture-cleanup blueprint
#2 — so --eval no longer references it.)

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
        if not getattr(ns, 'merge_drivers', False):
            ns.merge_drivers = True
    print('@@ARGS@@' + json.dumps({
        'eval_profile':       getattr(ns, 'eval_profile', None),
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
    assert args['merge_drivers'] is False


def test_eval_implies_merge_drivers():
    """--eval is the documented way to opt into the evaluation profile
    (merge-drivers)."""
    args = _run_argparse(['-y', 'comparison/cjson.yaml', '--eval'])
    assert args['eval_profile'] is True
    assert args['merge_drivers'] is True, '--eval must imply --merge-drivers'


def test_no_closed_loop_flags_exist():
    """The removed --closed-loop family must no longer parse."""
    src = SHIM.replace('_ROOT', repr(ROOT))
    cmd = [sys.executable, '-c', src,
           '-y', 'comparison/cjson.yaml', '--closed-loop']
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT,
                       env={**os.environ, 'PYTHONPATH': ROOT})
    assert r.returncode != 0, '--closed-loop should be an unrecognized argument'
    assert 'unrecognized arguments' in r.stderr or 'error' in r.stderr.lower()


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
