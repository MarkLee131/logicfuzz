# tests/test_pipeline_dominance_stage.py
from pathlib import Path
from tools.merge_drivers import pipeline as pipe


def test_dominance_stage_drops_subset_when_reports_present(tmp_path, monkeypatch):
    # 3 sources; build cov reports so B's set ⊆ A's set → B dropped.
    srcs = []
    for n in ("a", "b", "c"):
        p = tmp_path / f"{n}.fuzz_target"; p.write_text("int x;"); srcs.append(p)
    reports = tmp_path / "reports"
    def _funcs(names):
        return {"data": [{"functions": [{"name": x, "count": 1} for x in names]}]}
    import json
    for n, fs in (("a", ["f1", "f2", "f3"]), ("b", ["f1"]), ("c", ["f9"])):
        d = reports / f"{n}.fuzz_target" / "linux"; d.mkdir(parents=True)
        (d / "summary.json").write_text(json.dumps(_funcs(fs)))
    kept = pipe._apply_dominance(srcs, cov_reports_dir=reports)
    names = sorted(p.stem for p in kept)
    assert names == ["a", "c"]            # b ⊆ a → dropped


def test_dominance_stage_noop_without_reports(tmp_path):
    srcs = [tmp_path / f"{n}.fuzz_target" for n in ("a", "b")]
    for p in srcs:
        p.write_text("int x;")
    kept = pipe._apply_dominance(srcs, cov_reports_dir=tmp_path / "nope")
    assert sorted(p.stem for p in kept) == ["a", "b"]   # keep-all fallback
