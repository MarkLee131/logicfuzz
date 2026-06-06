"""P1 — preflight gating in run_single_fuzz._maybe_merge_drivers.

A merged harness runs every sub-driver in one process, so one crashing
auto-driver poisons the whole fused campaign (observed: a driver that passed
NULL to a consumer aborted the union). `_preflight_filter_candidates` must drop
crash / no-progress drivers BEFORE merge — but only on a real verdict, never
for an unrunnable binary (couldn't-vet ≠ reject), and it must fail safe when
too few binaries are resolvable.
"""
import importlib
from pathlib import Path

import run_single_fuzz as rsf
from tools.merge_drivers.preflight import PreflightResult

# The package __init__ binds the name ``preflight`` to the function, shadowing
# the submodule in the package namespace; fetch the real module to patch it.
pf = importlib.import_module("tools.merge_drivers.preflight")


class _WD:
    def __init__(self, base):
        self.base = str(base)


def _res(path, accepted, reason=""):
    return PreflightResult(
        driver_path=str(path), fuzzer_binary=str(path) + ".bin",
        duration_sec=15, exit_code=0, edges_seen=10, execs_per_sec=100.0,
        crashed=not accepted, accepted=accepted, rejection_reason=reason)


def test_skip_when_too_few_binaries(monkeypatch, tmp_path):
    """<2 resolvable binaries → preflight skipped, all sources kept."""
    srcs = [tmp_path / "01.fuzz_target", tmp_path / "02.fuzz_target"]
    monkeypatch.setattr(rsf, "_resolve_candidate_binary", lambda s, w: None)
    out = rsf._preflight_filter_candidates(srcs, _WD(tmp_path))
    assert out == srcs  # unchanged — can't vet, don't drop


def test_drops_crashing_driver(monkeypatch, tmp_path):
    """A crashing driver (preflight's real ``dead_on_empty`` verdict) is dropped.

    Regression: the filter used to match ``crash_on_empty``, a string preflight
    never emits, so crashers were silently kept and poisoned the merge.
    """
    srcs = [tmp_path / f"{i:02d}.fuzz_target" for i in (1, 2, 3)]
    monkeypatch.setattr(rsf, "_resolve_candidate_binary",
                        lambda s, w: Path(str(s) + ".bin"))

    def fake_preflight(pairs, **kw):
        out = []
        for src, _b in pairs:
            if src.stem == "02":
                out.append(_res(src, False, "dead_on_empty (crash + edges=0 < 1)"))
            else:
                out.append(_res(src, True))
        return out
    monkeypatch.setattr(pf, "preflight", fake_preflight)
    monkeypatch.setattr(pf, "write_report", lambda *a, **k: None)

    out = rsf._preflight_filter_candidates(srcs, _WD(tmp_path))
    assert [s.stem for s in out] == ["01", "03"]  # 02 dropped


def test_keeps_unvettable_binary(monkeypatch, tmp_path):
    """binary_broken/missing is infra, not a driver defect → keep it."""
    srcs = [tmp_path / f"{i:02d}.fuzz_target" for i in (1, 2)]
    monkeypatch.setattr(rsf, "_resolve_candidate_binary",
                        lambda s, w: Path(str(s) + ".bin"))

    def fake_preflight(pairs, **kw):
        return [_res(pairs[0][0], True),
                _res(pairs[1][0], False, "binary_broken (exit=1)")]
    monkeypatch.setattr(pf, "preflight", fake_preflight)
    monkeypatch.setattr(pf, "write_report", lambda *a, **k: None)

    out = rsf._preflight_filter_candidates(srcs, _WD(tmp_path))
    assert [s.stem for s in out] == ["01", "02"]  # broken-to-run kept
