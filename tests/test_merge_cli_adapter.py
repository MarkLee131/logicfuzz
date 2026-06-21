"""Tests: CLI subcommands delegate to run_merge_pipeline; dead heuristic removed."""
import tools.merge_drivers.__main__ as cli


def test_cmd_merge_calls_run_merge_pipeline(monkeypatch, tmp_path):
    import tools.merge_drivers.pipeline as pipe
    seen = {}
    monkeypatch.setattr(pipe, "run_merge_pipeline",
                        lambda candidates, **kw: seen.update(kw) or "/out")
    s1 = tmp_path / "01.c"; s1.write_text("int x;")
    s2 = tmp_path / "02.c"; s2.write_text("int y;")
    rc = cli._cmd_merge(type("A", (), {
        "inputs": [str(s1), str(s2)], "output": str(tmp_path / "m"),
        "project": "demo", "mode": "uniform", "position": "tail",
        "libs": None, "includes": None,
    })())
    assert "project" in seen and seen["project"] == "demo"


def test_trial_failed_to_build_removed():
    assert not hasattr(cli, "_trial_failed_to_build")
