"""Tests for the per-project driver-count budget cap.

Background
----------
Earlier in the pipeline, several arbitrary numeric caps independently
truncated the L4 viability output (5 / 12 / 24 — see CLAUDE.md "Failed
Attempts"). They were *not* viability filters; they were just pretending
to be. A separate "user must pass -n N" expectation was also broken
because N (the count of viable sequences) is not knowable until the
viability analysis finishes.

Resolution chosen (matches PromeFuzz CCS'25 per-project driver count):

  - Single budget cap, default ``filter_top_k = 10``.
  - L4 greedy max-coverage outputs at most 10 sequences (or fewer if the
    greedy self-terminates because no candidate adds new APIs).
  - Skeleton emission and the trial axis both derive their count from
    ``len(skeleton_drivers)`` — never an independent cap.
  - ``--num-samples`` defaults to ``None`` (auto), resolved at runtime
    in ``_fuzzing_pipelines`` to ``len(skeleton_drivers)`` so every
    viable Z3 skeleton gets one trial. User can still override
    (``-n 1`` for a fast smoke).

This test pins down the budget-cap default and the auto-resolve so a
future refactor can't silently re-introduce the old hardcoded ceilings.
"""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def test_filter_top_k_default_is_budget_cap_10():
    """The single budget knob is set to 10 (PromeFuzz parity)."""
    from src.context.data_context import FuzzingContext

    sig = inspect.signature(FuzzingContext.prepare)
    default = sig.parameters['filter_top_k'].default
    assert default == 10, (
        f'filter_top_k default changed from 10 to {default} — that\'s the '
        f'per-project driver budget; document the new value here if you '
        f'genuinely meant to raise/lower it')


def test_num_samples_default_is_none_for_auto_resolve():
    """The CLI default must be None so _fuzzing_pipelines can resolve to
    len(skeleton_drivers) at runtime. Setting a numeric default here
    would silently re-introduce the brutal cap on the trial axis."""
    src = r"""
import argparse, json, sys, runpy, os
os.chdir(_ROOT)
_orig = argparse.ArgumentParser.parse_args
def _patched(self, *a, **k):
    ns = _orig(self, *a, **k)
    print('@@DEFAULT@@' + json.dumps({'num_samples': ns.num_samples}))
    sys.exit(0)
argparse.ArgumentParser.parse_args = _patched
runpy.run_path('run_logicfuzz.py', run_name='__main__')
""".replace('_ROOT', repr(ROOT))
    r = subprocess.run(
        [sys.executable, '-c', src, '-y', 'comparison/cjson.yaml'],
        capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, 'PYTHONPATH': ROOT})
    marker = '@@DEFAULT@@'
    payload = next((ln for ln in r.stdout.splitlines() if marker in ln), None)
    if payload is None:
        pytest.fail(
            f'argparse shim did not emit marker.\n'
            f'returncode={r.returncode}\nstdout(tail)={r.stdout[-1500:]}\n'
            f'stderr(tail)={r.stderr[-1500:]}'
        )
    args = json.loads(payload.split(marker, 1)[1])
    assert args['num_samples'] is None, (
        '--num-samples must default to None so it can auto-resolve to '
        'the post-viability driver count. A fixed default reintroduces '
        'the brutal trial-axis cap.')


def test_num_samples_explicit_override_still_accepted():
    """User passing -n 1 (e.g. for fast smoke) must still go through."""
    src = r"""
import argparse, json, sys, runpy, os
os.chdir(_ROOT)
_orig = argparse.ArgumentParser.parse_args
def _patched(self, *a, **k):
    ns = _orig(self, *a, **k)
    print('@@N@@' + json.dumps({'num_samples': ns.num_samples}))
    sys.exit(0)
argparse.ArgumentParser.parse_args = _patched
runpy.run_path('run_logicfuzz.py', run_name='__main__')
""".replace('_ROOT', repr(ROOT))
    r = subprocess.run(
        [sys.executable, '-c', src,
         '-y', 'comparison/cjson.yaml', '-n', '1'],
        capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, 'PYTHONPATH': ROOT})
    marker = '@@N@@'
    payload = next((ln for ln in r.stdout.splitlines() if marker in ln), None)
    assert payload is not None, f'no marker; stderr={r.stderr[-800:]}'
    assert json.loads(payload.split(marker, 1)[1])['num_samples'] == 1


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
