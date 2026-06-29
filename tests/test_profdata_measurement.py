"""Characterization/regression tests for the profdata-first coverage path
(scripts/run_extended_fuzzing.py:_export_coverage_from_profdata, shipped in
ab55eae5). These PIN existing behavior — they PASS against current code. A
failure indicates a real regression or a wrong assumption, not a test to relax."""
import importlib
import json
import types

ext = importlib.import_module("scripts.run_extended_fuzzing")


def _make_fuzzer(target_name="fuzz_target"):
    """A bare ExtendedFuzzer exposing only what the method under test reads."""
    obj = ext.ExtendedFuzzer.__new__(ext.ExtendedFuzzer)
    obj.target_name = target_name
    return obj


def _build_out(tmp_path, target_name="fuzz_target"):
    """Fabricate the build_out dir with the profdata + binary the guard requires."""
    (tmp_path / "dumps").mkdir(parents=True, exist_ok=True)
    (tmp_path / "dumps" / "merged.profdata").write_bytes(b"\x00")
    (tmp_path / target_name).write_bytes(b"\x7fELF")
    return tmp_path


def _totals_json(branches_covered, branches_count, lines_count=10, funcs_count=2):
    pct = (100.0 * branches_covered / branches_count) if branches_count else 0.0
    return json.dumps({"data": [{"totals": {
        "lines": {"count": lines_count, "covered": lines_count, "percent": 100.0},
        "branches": {"count": branches_count, "covered": branches_covered, "percent": pct},
        "functions": {"count": funcs_count, "covered": funcs_count, "percent": 100.0},
    }}]})


def _patch_run(monkeypatch, returncode=0, stdout=""):
    def fake_run(_cmd, *_a, **_k):
        return types.SimpleNamespace(returncode=returncode, stdout=stdout)
    monkeypatch.setattr(ext.subprocess, "run", fake_run)


def test_profdata_returns_coverage_on_valid_totals(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(899, 924))
    cd = _make_fuzzer()._export_coverage_from_profdata(bo)
    assert cd is not None
    assert cd.branches_covered == 899
    assert cd.branches_total == 924


def test_profdata_none_when_profdata_missing(tmp_path, monkeypatch):
    (tmp_path / "fuzz_target").write_bytes(b"\x7fELF")  # binary present, profdata absent
    _patch_run(monkeypatch, 0, _totals_json(1, 1))
    assert _make_fuzzer()._export_coverage_from_profdata(tmp_path) is None


def test_profdata_none_when_binary_missing(tmp_path, monkeypatch):
    (tmp_path / "dumps").mkdir()
    (tmp_path / "dumps" / "merged.profdata").write_bytes(b"\x00")  # profdata present, binary absent
    _patch_run(monkeypatch, 0, _totals_json(1, 1))
    assert _make_fuzzer()._export_coverage_from_profdata(tmp_path) is None


def test_profdata_rejects_empty_totals_garbage(tmp_path, monkeypatch):
    # The deliberate degeneracy gate: an all-zero/un-instrumented profile is rejected.
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(0, 0, lines_count=0))
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None


def test_profdata_keeps_single_source_library(tmp_path, monkeypatch):
    # REGRESSION PIN (run_extended_fuzzing.py:1047-1052): a single-source lib
    # (cJSON.c shape) has small but NON-zero totals and must NOT be rejected.
    # This pins the decision to use empty-totals, NOT an n_files<2 file-count floor.
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(40, 80, lines_count=120))
    cd = _make_fuzzer()._export_coverage_from_profdata(bo)
    assert cd is not None
    assert cd.branches_covered == 40


def test_profdata_none_on_nonzero_returncode(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 1, "")
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None


def test_profdata_none_on_malformed_json(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, "not json{{")
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None
