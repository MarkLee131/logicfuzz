"""Per-run LLM token meter — process-global accumulator used to compare total
token cost vs PromeFuzz. Fed by state.update_token_usage (all agents) and
Comprehender._invoke; reset/dumped per run in run_logicfuzz.run_experiments.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.utils import token_meter as tm  # noqa: E402


def setup_function(_):
    tm.reset()


def test_accumulates_and_splits_by_agent():
    tm.record(100, 50, 150, "prototyper")
    tm.record(200, 80, 0, "prototyper")          # total auto-derived = 280
    tm.record(30, 10, 40, "comprehender")
    s = tm.snapshot()
    assert s["calls"] == 3
    assert s["prompt_tokens"] == 330
    assert s["completion_tokens"] == 140
    assert s["total_tokens"] == 150 + 280 + 40
    assert s["by_agent"]["prototyper"]["calls"] == 2
    assert s["by_agent"]["comprehender"]["total_tokens"] == 40


def test_zero_usage_is_ignored():
    tm.record(0, 0, 0, "untracked_provider")
    s = tm.snapshot()
    assert s["calls"] == 0
    assert "untracked_provider" not in s["by_agent"]


def test_reset_clears():
    tm.record(10, 10, 20, "x")
    tm.reset()
    assert tm.snapshot() == {
        "calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
        "total_tokens": 0, "by_agent": {},
    }


def test_dump_writes_snapshot(tmp_path):
    tm.record(100, 25, 125, "fixer")
    out = tmp_path / "sub" / "token_summary.json"   # parent created by dump
    snap = tm.dump(str(out))
    assert out.exists()
    on_disk = json.load(open(out))
    assert on_disk["total_tokens"] == 125 == snap["total_tokens"]
