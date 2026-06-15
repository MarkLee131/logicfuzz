"""Wiring tests: the leaking spawn sites force-remove their container in a
``finally`` so it fires on success, timeout, AND exception.

These exercise the REAL wired functions (not the utility — that has its own
tests) with subprocess mocked, asserting the named-cleanup call happens on the
error path (the path that historically leaked).
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from experiment import container_cleanup  # noqa: E402
from tools.merge_drivers import compile_validate  # noqa: E402


def _capture_cleanup(monkeypatch):
    """Record every force_remove_named_container(name) call."""
    removed = []
    monkeypatch.setattr(container_cleanup, "force_remove_named_container",
                        lambda name, **k: removed.append(name) or 1)
    return removed


def test_compile_validate_cleans_named_container_on_timeout(monkeypatch, tmp_path):
    removed = _capture_cleanup(monkeypatch)

    def _raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)

    monkeypatch.setattr(compile_validate.subprocess, "run", _raise_timeout)

    staging = tmp_path / "cands"
    staging.mkdir()
    out = compile_validate._run_container_validation(
        image="gcr.io/oss-fuzz/lcms", candidates_dir=staging,
        project="lcms", timeout_sec=5)

    assert out is None  # fails open
    # the container was force-removed BY NAME despite the timeout (the leak path)
    assert len(removed) == 1, removed
    assert removed[0].startswith("lf-compileval-"), removed


def test_compile_validate_cleans_named_container_on_success(monkeypatch, tmp_path):
    removed = _capture_cleanup(monkeypatch)

    class _Proc:
        stdout = "VALIDATE_DONE\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(compile_validate.subprocess, "run",
                        lambda *a, **k: _Proc())

    staging = tmp_path / "cands"
    staging.mkdir()
    compile_validate._run_container_validation(
        image="gcr.io/oss-fuzz/lcms", candidates_dir=staging,
        project="lcms", timeout_sec=5)

    assert len(removed) == 1, removed
    assert removed[0].startswith("lf-compileval-"), removed


def test_compile_validate_uses_unique_name_each_call(monkeypatch, tmp_path):
    removed = _capture_cleanup(monkeypatch)
    monkeypatch.setattr(compile_validate.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(
                            subprocess.TimeoutExpired("docker", 1)))
    staging = tmp_path / "c"
    staging.mkdir()
    for _ in range(2):
        compile_validate._run_container_validation(
            "gcr.io/oss-fuzz/lcms", staging, "lcms", 5)
    assert len(removed) == 2 and removed[0] != removed[1], removed
