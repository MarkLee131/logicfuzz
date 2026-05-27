"""P1 — preservation of per-trial fuzzer binaries for the merge preflight.

The eval-tail merge preflight (run_single_fuzz._preflight_filter_candidates)
can only smoke-test a candidate driver if a host-runnable libFuzzer binary is
resolvable under ``<base>/preflight_bins/<NN>``. The per-trial OSS-Fuzz binary
is built in Docker's ``/out`` mount and wiped at the next build, so the
execution node must copy it out while it still exists.

These tests pin the contract that ``_preserve_preflight_binary``:
  * copies ``build/out/<project>/<target>`` → ``<base>/preflight_bins/<NN>``
    with the exact zero-padded stem the resolver derives from
    ``<NN>.fuzz_target``;
  * is a silent no-op when no binary was produced;
  * never raises (preservation must not break the main run);
  * produces a path that ``_resolve_candidate_binary`` actually resolves
    (round-trip with the merge layer).
"""
import os
from pathlib import Path

import run_single_fuzz as rsf
from experiment import builder_runner as builder_runner_lib
from experiment import oss_fuzz_checkout
from src.workflow.nodes import execution as ex


class _WD:
    """Minimal WorkDirs stand-in exposing only ``.base``."""

    def __init__(self, base):
        self.base = str(base)


def _make_fake_build_out(oss_fuzz_dir: Path, project: str, target: str) -> Path:
    """Create a fake OSS-Fuzz build artifact at build/out/<project>/<target>."""
    outdir = oss_fuzz_dir / "build" / "out" / project
    outdir.mkdir(parents=True, exist_ok=True)
    binary = outdir / target
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    return binary


def test_preserves_binary_with_resolver_matching_stem(monkeypatch, tmp_path):
    """Binary is copied to <base>/preflight_bins/<NN> and the merge resolver
    finds it via the <NN>.fuzz_target stem."""
    oss_fuzz_dir = tmp_path / "oss-fuzz"
    monkeypatch.setattr(oss_fuzz_checkout, "OSS_FUZZ_DIR", str(oss_fuzz_dir))

    project = "cjson-7"
    target = "cjson_fuzzer"
    _make_fake_build_out(oss_fuzz_dir, project, target)

    base = tmp_path / "results"
    base.mkdir()
    wd = _WD(base)

    ex._preserve_preflight_binary(wd, project, target, trial=7)

    preserved = base / "preflight_bins" / "07"
    assert preserved.is_file(), "binary not preserved at expected stem path"
    assert preserved.read_bytes() == b"#!/bin/sh\nexit 0\n"
    # Executable bit set so preflight can run it as a subprocess.
    assert os.access(preserved, os.X_OK)

    # Round-trip: the merge resolver derives stem "07" from "07.fuzz_target"
    # and must resolve exactly the file we just wrote.
    src = Path("/some/where/07.fuzz_target")
    resolved = rsf._resolve_candidate_binary(src, wd)
    assert resolved is not None
    assert resolved == preserved


def test_noop_when_no_binary(monkeypatch, tmp_path):
    """No build artifact → silent no-op, no preflight_bins dir created."""
    oss_fuzz_dir = tmp_path / "oss-fuzz"
    monkeypatch.setattr(oss_fuzz_checkout, "OSS_FUZZ_DIR", str(oss_fuzz_dir))

    base = tmp_path / "results"
    base.mkdir()
    wd = _WD(base)

    # build/out/<project>/<target> does not exist.
    ex._preserve_preflight_binary(wd, "cjson-3", "cjson_fuzzer", trial=3)

    assert not (base / "preflight_bins" / "03").exists()


def test_never_raises_on_failure(monkeypatch, tmp_path):
    """Any internal failure is swallowed — preservation must not break a run."""
    def boom(*_a, **_k):
        raise RuntimeError("artifact dir lookup blew up")

    monkeypatch.setattr(builder_runner_lib, "get_build_artifact_dir", boom)

    base = tmp_path / "results"
    base.mkdir()
    # Should not raise.
    ex._preserve_preflight_binary(_WD(base), "cjson-1", "cjson_fuzzer", trial=1)
    assert not (base / "preflight_bins").exists()
