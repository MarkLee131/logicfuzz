"""Tests for tools.merge_drivers.pipeline and the _maybe_merge_drivers adapter."""
import importlib
import os


def test_pipeline_module_exposes_run_merge_pipeline():
    mod = importlib.import_module("tools.merge_drivers.pipeline")
    assert hasattr(mod, "run_merge_pipeline")
    assert hasattr(mod, "MergeResult") or callable(mod.run_merge_pipeline)


def test_run_single_fuzz_adapter_delegates(monkeypatch):
    # _maybe_merge_drivers must call run_merge_pipeline (no duplicated orchestration)
    import run_single_fuzz
    import tools.merge_drivers.pipeline as pipe
    called = {}
    def fake(candidates, **kw):
        called["candidates"] = list(candidates)
        called["kw"] = kw
        return "/tmp/merged"
    monkeypatch.setattr(pipe, "run_merge_pipeline", fake)

    class _BR:  # minimal best_result
        compiles = True
        cov_pcs = 0
    class _TR:
        trial = 1
        best_result = _BR()
    class _Bench:
        project = "demo"
        file_type = ".c"
    class _WD:
        base = "/tmp/wd"
        fuzz_targets = "/tmp/wd/ft"
        # code_coverage_report is a METHOD on the real WorkDirs (takes a
        # benchmark) — mirror that so the adapter must NOT getattr-and-Path it
        # (that returns a truthy bound method → Path() raises TypeError).
        def code_coverage_report(self, benchmark):
            return f"{self.base}/code-coverage-reports/{benchmark}"
    # 2 compiling, non-crashing trials with on-disk sources
    os.makedirs("/tmp/wd/ft", exist_ok=True)
    for i in (1, 2):
        open(f"/tmp/wd/ft/{i:02d}.fuzz_target", "w").write("int x;")
    trs = []
    for i in (1, 2):
        tr = _TR(); tr.trial = i; trs.append(tr)
    # The adapter calls _pipe._should_quarantine_from_merge directly, so patch
    # the pipeline copy (patching the run_single_fuzz alias has no effect).
    monkeypatch.setattr(pipe, "_should_quarantine_from_merge", lambda br, tr: False)
    out = run_single_fuzz._maybe_merge_drivers(_Bench(), _WD(), trs)
    assert out == "/tmp/merged"
    assert len(called["candidates"]) == 2
