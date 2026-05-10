"""Tests for the --merge-drivers integration in run_single_fuzz.py.

Background
----------
``tools/merge_drivers`` ships as a standalone CLI; the integration in
run_single_fuzz._maybe_merge_drivers calls only its building blocks
(SynthesizedDriver.from_paths + save + emit_oss_fuzz_build_snippet) so
the eval pipeline can opt in via ``--merge-drivers`` / ``--eval``.

The minimum-viable contract these tests pin down:

  - Skip cleanly if fewer than 2 trials compiled (nothing to merge).
  - Emit ``synthesized/`` + ``oss_fuzz_build_snippet.sh`` under
    ``<work_dirs.base>/merged/`` when ≥ 2 trials compiled.
  - Skip trials whose source file was deleted (workflow cleanup).
  - Never raise on tools.merge_drivers import failure (lazy + guarded).
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest  # type: ignore[import-not-found]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


C_DRIVER_SOURCE = '''#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
'''


class _FakeWorkDirs:
    """Mirrors the WorkDirs surface that _maybe_merge_drivers reads."""

    def __init__(self, base: Path):
        self.base = str(base)
        self.fuzz_targets = str(base / 'fuzz_targets')
        Path(self.fuzz_targets).mkdir(parents=True, exist_ok=True)


def _fake_trial(trial: int, compiles: bool) -> object:
    """Stand-in for results.TrialResult that satisfies the helper's
    attribute access (`.trial`, `.best_result.compiles`)."""
    return types.SimpleNamespace(
        trial=trial,
        best_result=types.SimpleNamespace(compiles=compiles),
    )


def _write_driver(work_dirs: _FakeWorkDirs, trial: int) -> Path:
    p = Path(work_dirs.fuzz_targets) / f'{trial:02d}.fuzz_target'
    p.write_text(C_DRIVER_SOURCE)
    return p


@pytest.fixture
def fake_benchmark():
    return types.SimpleNamespace(language='c', target_name='fuzz_target')


def test_skips_when_fewer_than_two_successful_trials(tmp_path, fake_benchmark):
    """One success isn't enough to merge; helper must short-circuit."""
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    _write_driver(wd, 1)
    out = _maybe_merge_drivers(
        fake_benchmark, wd, [_fake_trial(1, compiles=True)])
    assert out is None
    assert not (tmp_path / 'merged').exists()


def test_skips_when_zero_trials(tmp_path, fake_benchmark):
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    out = _maybe_merge_drivers(fake_benchmark, wd, [])
    assert out is None


def test_emits_synthesized_dir_and_snippet_for_two_successes(
        tmp_path, fake_benchmark):
    """Happy path: two successful trials → a merged harness on disk."""
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    _write_driver(wd, 1)
    _write_driver(wd, 2)
    out = _maybe_merge_drivers(
        fake_benchmark, wd,
        [_fake_trial(1, compiles=True), _fake_trial(2, compiles=True)])
    assert out is not None, '≥2 successful trials must produce a merged harness'
    out_path = Path(out)
    assert out_path == tmp_path / 'merged'
    # Layout contract: synthesized/ holds entry + per-trial source,
    # plus an oss_fuzz_build_snippet.sh at the merged-dir root.
    assert (out_path / 'oss_fuzz_build_snippet.sh').exists()
    synth = out_path / 'synthesized'
    assert synth.is_dir()
    entries = list(synth.iterdir())
    assert any(e.name.startswith('entry.') for e in entries), \
        'dispatcher entry.{c,cpp} must be emitted'
    # Two sub-drivers, multi-TU layout (each in its own file)
    sub_drivers = [e for e in entries if not e.name.startswith('entry.')]
    assert len(sub_drivers) == 2, \
        f'expected 2 sub-driver files, got {[e.name for e in sub_drivers]}'


def test_excludes_trials_whose_source_file_is_missing(
        tmp_path, fake_benchmark):
    """If workflow cleanup removed a .fuzz_target, that trial must be
    silently dropped — not crashed on, not pretend-included."""
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    _write_driver(wd, 1)
    _write_driver(wd, 2)
    # Trial 3 reports compiles=True but its source was deleted.
    trials = [
        _fake_trial(1, compiles=True),
        _fake_trial(2, compiles=True),
        _fake_trial(3, compiles=True),
    ]
    out = _maybe_merge_drivers(fake_benchmark, wd, trials)
    assert out is not None
    # Only 2 sub-drivers should have been merged.
    synth = Path(out) / 'synthesized'
    sub_drivers = [e for e in synth.iterdir()
                   if not e.name.startswith('entry.')]
    assert len(sub_drivers) == 2


def test_excludes_failed_trials(tmp_path, fake_benchmark):
    """Trials with compiles=False must not be picked even if their
    source still exists on disk."""
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    _write_driver(wd, 1)
    _write_driver(wd, 2)
    _write_driver(wd, 3)
    trials = [
        _fake_trial(1, compiles=True),
        _fake_trial(2, compiles=False),  # failed — must drop
        _fake_trial(3, compiles=True),
    ]
    out = _maybe_merge_drivers(fake_benchmark, wd, trials)
    assert out is not None
    synth = Path(out) / 'synthesized'
    sub_drivers = [e for e in synth.iterdir()
                   if not e.name.startswith('entry.')]
    assert len(sub_drivers) == 2


def test_does_not_raise_when_tools_merge_drivers_unavailable(
        tmp_path, fake_benchmark, monkeypatch):
    """If tools.merge_drivers can't be imported, log and return None —
    the main run must never blow up because of this opt-in stage."""
    from run_single_fuzz import _maybe_merge_drivers
    wd = _FakeWorkDirs(tmp_path)
    _write_driver(wd, 1)
    _write_driver(wd, 2)

    # Force ImportError on the lazy import inside the helper.
    import builtins
    real_import = builtins.__import__

    def fail_on_merge_drivers(name, *a, **k):
        if name.startswith('tools.merge_drivers'):
            raise ImportError(f'simulated absence of {name}')
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, '__import__', fail_on_merge_drivers)
    out = _maybe_merge_drivers(
        fake_benchmark, wd,
        [_fake_trial(1, compiles=True), _fake_trial(2, compiles=True)])
    assert out is None


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
