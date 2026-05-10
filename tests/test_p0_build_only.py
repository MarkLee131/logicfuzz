"""Regression tests for the P0-1 fix in experiment/evaluator.py:build_only.

Background — see CLAUDE.md "Failed Attempts / Lessons" and the project
notes on the cjson run that motivated this:

  Reused gcr.io/oss-fuzz/cjson as ... (no rebuild)
  Build result: success=False, binary_exists=False, errors=0

Two coupled defects:

  1. builder_runner.build_target_local had a "fast-path retag" that
     returned True without compiling, so the binary never appeared.
  2. evaluator.build_only only extracted errors when build_target_local
     returned False, so when (1) fired, errors=[] and the fixer was
     handed a build failure with no diagnostic to triage.

Defect (1) is fixed in builder_runner.py; the tests here pin down
defect (2) — that build_only must produce *some* error payload whenever
the overall build did not produce a binary, regardless of what
build_target_local returned. Without this, the fixer goes blind.
"""
from __future__ import annotations

import os
import sys
import types
from unittest import mock

import pytest

# Ensure repo root is importable (run from any cwd)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


PROJECT_NAME = 'proj-build'


def _make_evaluator(tmp_path, build_log: str):
    """Build a minimal Evaluator stub backed by tmp_path on disk.

    We avoid pulling in the real Benchmark / WorkDirs / BuilderRunner
    constructors (they pull google.cloud.storage, FuzzedDataProvider,
    etc.) by stubbing only the surface that build_only actually reads.

    build_only computes its log_path as:
        os.path.join(work_dirs.run_logs, f'{project_name}-build.log')
    so we mirror that exact name here.
    """
    from experiment.evaluator import Evaluator

    runs_dir = tmp_path / 'run_logs'
    runs_dir.mkdir()
    log_file = runs_dir / f'{PROJECT_NAME}-build.log'
    log_file.write_text(build_log)

    fake_benchmark = types.SimpleNamespace(
        target_name='fuzz_target',
        target_path='/src/fuzz_target.cc',
        language='c++',
        id='proj',
        project='proj',
    )
    fake_work_dirs = types.SimpleNamespace(
        run_logs=str(runs_dir),
        # build_only does not touch other attrs, but Evaluator.__init__ reads
        # them in some branches we don't hit.
        status=str(tmp_path / 'status'),
    )

    # Sidestep Evaluator.__init__ (it just stores fields).
    ev = object.__new__(Evaluator)
    ev.builder_runner = mock.MagicMock()
    ev.benchmark = fake_benchmark
    ev.work_dirs = fake_work_dirs
    return ev, log_file


def test_build_only_extracts_errors_when_binary_missing_despite_true_return(tmp_path):
    """The cjson regression: builder returned True, binary absent → no errors.

    After the fix, build_only must classify this as failure AND surface
    a diagnostic (either parsed errors or a tail-of-log fallback) so the
    fixer has something to triage.
    """
    log_text = (
        "Step 1/12 : FROM gcr.io/oss-fuzz-base/base-builder\n"
        "Reused gcr.io/oss-fuzz/proj as gcr.io/oss-fuzz/proj-build (no rebuild)\n"
        "[some build noise without an explicit 'error:' marker]\n"
    )
    ev, _log_file = _make_evaluator(tmp_path, log_text)

    # Builder returns True (the original bug) but binary does NOT exist.
    ev.builder_runner.build_target_local.return_value = True

    with mock.patch('experiment.evaluator.builder_runner'
                    '.get_build_artifact_dir',
                    return_value=str(tmp_path / 'never-exists')):
        result = ev.build_only(PROJECT_NAME)

    assert result['success'] is False, \
        "binary missing must demote to overall success=False"
    assert result['binary_exists'] is False
    assert result['errors'], (
        "P0-1 regression: errors must not be empty when no binary was produced "
        "— the fixer needs something to triage")
    # Tail-of-log fallback is acceptable; it just must mention the failure.
    joined = '\n'.join(result['errors']).lower()
    assert ('did not produce a binary' in joined
            or 'error' in joined), (
        "diagnostic should reference the binary-missing failure")


def test_build_only_succeeds_when_binary_exists(tmp_path):
    """Sanity: the happy path still works."""
    ev, _ = _make_evaluator(tmp_path, "compile ok\n")
    ev.builder_runner.build_target_local.return_value = True

    fake_outdir = tmp_path / 'out'
    fake_outdir.mkdir()
    (fake_outdir / 'fuzz_target').write_text('binary')

    with mock.patch('experiment.evaluator.builder_runner'
                    '.get_build_artifact_dir',
                    return_value=str(fake_outdir)):
        result = ev.build_only(PROJECT_NAME)

    assert result['success'] is True
    assert result['binary_exists'] is True
    assert result['errors'] == [], "no errors should be extracted on success"


def test_build_only_extracts_errors_from_log_on_compile_failure(tmp_path):
    """Pre-existing path: builder returned False → parse error: lines."""
    log_text = (
        "Compiling fuzz_target.cc\n"
        "fuzz_target.cc:25: error: 'cJSON_ParseWithOpts' was not declared\n"
        "/usr/bin/ld: undefined reference to `cJSON_FreeMemory'\n"
        "make: *** [fuzz_target] Error 1\n"
    )
    ev, _ = _make_evaluator(tmp_path, log_text)
    ev.builder_runner.build_target_local.return_value = False

    with mock.patch('experiment.evaluator.builder_runner'
                    '.get_build_artifact_dir',
                    return_value=str(tmp_path / 'never-exists')):
        result = ev.build_only(PROJECT_NAME)

    assert result['success'] is False
    assert result['binary_exists'] is False
    # The two diagnostic lines should be picked up by the simple matcher.
    joined = '\n'.join(result['errors'])
    assert 'cJSON_ParseWithOpts' in joined
    assert 'cJSON_FreeMemory' in joined


def test_build_only_emits_fallback_when_log_is_empty(tmp_path):
    """No log content + no binary → still emit a one-line diagnostic."""
    ev, _ = _make_evaluator(tmp_path, "")  # empty log
    ev.builder_runner.build_target_local.return_value = True

    with mock.patch('experiment.evaluator.builder_runner'
                    '.get_build_artifact_dir',
                    return_value=str(tmp_path / 'never-exists')):
        result = ev.build_only(PROJECT_NAME)

    assert result['success'] is False
    assert len(result['errors']) >= 1, \
        "must emit at least one record so triage classifies as OTHER, not None"


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
