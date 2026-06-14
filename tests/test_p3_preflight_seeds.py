"""Regression test for merge-preflight seed routing.

The merged-coverage A/B exposed that the preflight smoke-test ran every
candidate against a single hardcoded EMPTY seed, so parser-entry drivers got 0
edges on random bytes and were culled as `no_progress` (50/58 lcms). The fix
routes the project's real format-matching seeds into the smoke corpus via the
existing seed_corpus_for_driver. These tests verify the routing decision
without running an actual fuzzer binary (the smoke run is stubbed).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import importlib

# NB: tools/merge_drivers/__init__ rebinds the name ``preflight`` to the
# function, so ``import ... as P`` yields the function; import_module returns the
# actual MODULE from sys.modules (what we need to monkeypatch _run_smoke_cmd).
P = importlib.import_module("tools.merge_drivers.preflight")


def _stub_smoke_run(monkeypatch):
    """Stub the actual binary execution so _smoke_one doesn't need a fuzzer."""
    def fake_run(cmd, log_file, timeout):
        Path(log_file).write_text("#1\tINITED exec/s: 0 rss: 1Mb\n")
        return (0, False)  # (exit_code, timed_out)
    monkeypatch.setattr(P, "_run_smoke_cmd", fake_run)


def test_preflight_routes_real_seeds_when_gated(monkeypatch, tmp_path):
    _stub_smoke_run(monkeypatch)
    calls = []

    def fake_seed(project, corpus_dir, driver_path, max_seeds=64):
        calls.append((project, str(corpus_dir), str(driver_path)))
        (Path(corpus_dir) / "projseed_x.icc").write_bytes(b"\x00" * 36 + b"acsp")
        return 1

    import scripts.seed_discovery as SD
    monkeypatch.setattr(SD, "seed_corpus_for_driver", fake_seed)

    drv = tmp_path / "01.fuzz_target"
    drv.write_text("cmsOpenProfileFromMem(ctx, data, size);")
    binary = tmp_path / "01"
    binary.write_bytes(b"")
    ws = tmp_path / "ws"

    P._smoke_one(drv, binary, 1, ws, project="lcms", route_seeds=True)

    assert calls and calls[0][0] == "lcms"          # seed routing invoked
    assert (ws / "corpus" / "projseed_x.icc").exists()  # real seed routed in
    assert not (ws / "corpus" / "empty").exists()    # empty fallback NOT used


def test_preflight_empty_fallback_when_no_seeds(monkeypatch, tmp_path):
    _stub_smoke_run(monkeypatch)

    import scripts.seed_discovery as SD
    monkeypatch.setattr(SD, "seed_corpus_for_driver",
                        lambda *a, **k: 0)  # no seeds matched

    drv = tmp_path / "01.fuzz_target"
    drv.write_text("x")
    binary = tmp_path / "01"
    binary.write_bytes(b"")
    ws = tmp_path / "ws"

    P._smoke_one(drv, binary, 1, ws, project="lcms", route_seeds=True)
    assert (ws / "corpus" / "empty").exists()        # fallback fired (libFuzzer needs >=1)


def test_preflight_gate_off_uses_empty(monkeypatch, tmp_path):
    _stub_smoke_run(monkeypatch)
    calls = []
    import scripts.seed_discovery as SD
    monkeypatch.setattr(SD, "seed_corpus_for_driver",
                        lambda *a, **k: calls.append(1) or 0)

    drv = tmp_path / "01.fuzz_target"
    drv.write_text("cmsOpenProfileFromMem(...)")
    binary = tmp_path / "01"
    binary.write_bytes(b"")
    ws = tmp_path / "ws"

    # route_seeds=False (kill-switch) OR empty project -> never route, empty seed.
    P._smoke_one(drv, binary, 1, ws, project="lcms", route_seeds=False)
    assert not calls                                  # routing skipped
    assert (ws / "corpus" / "empty").exists()
