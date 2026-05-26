"""Pin the G5 coverage-gap signal + gap-directed construction.

G5 directs generation at APIs the OSS-Fuzz baseline does NOT cover (the
§10B line_diff=0 problem). These tests pin the gap extraction from a baseline
textcov and that construction builds sequences reaching gap APIs.

See ``docs/generation_stage_redesign.md`` (G5) and
``liberator_adapter/analysis/coverage_gap.py``.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.coverage_gap import (  # noqa: E402
    compute_gap_apis, parse_textcov_covered,
)
from liberator_adapter.analysis.api_semantic_model import reconcile  # noqa: E402
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    construct_sequences,
)


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


_TEXTCOV = """\
lib_covered_a:
  10|  1.2k|{
  11|  1.2k|    return 0;
lib_covered_b:
  20|   55|{
  21|     |    int x = 0;
"""


def test_parse_textcov_covered(tmp_path):
    p = tmp_path / "baseline.covreport"
    p.write_text(_TEXTCOV)
    covered = parse_textcov_covered(p)
    assert covered == {"lib_covered_a", "lib_covered_b"}


def test_gap_from_textcov(tmp_path):
    p = tmp_path / "baseline.covreport"
    p.write_text(_TEXTCOV)
    names = ["lib_covered_a", "lib_covered_b", "lib_gap_x", "lib_gap_y"]
    gap = compute_gap_apis(names, baseline_textcov=p)
    assert gap == {"lib_gap_x", "lib_gap_y"}


def test_gap_from_existing_coverage():
    names = ["a", "b", "c"]
    # a well-covered, b barely, c absent → gap = {b, c}
    gap = compute_gap_apis(names, existing_coverage={"a": 80.0, "b": 1.0},
                           covered_threshold_pct=5.0)
    assert gap == {"b", "c"}


def test_no_baseline_signal_returns_all():
    # No textcov, no coverage dict → don't narrow; everything is a target.
    names = ["a", "b"]
    assert compute_gap_apis(names) == {"a", "b"}


def test_construction_reaches_gap_apis():
    apis = [
        _api("thing_create", [], ret="Thing *"),
        _api("thing_gap_use", [_arg_handle("Thing *")], ret="int"),
        _api("thing_free", [_arg_handle("Thing *")]),
    ]
    model = reconcile(apis)
    gap = {"thing_gap_use"}
    res = construct_sequences(model, gap_apis=gap)
    assert res.metrics["gap_apis_total"] == 1
    assert res.metrics["gap_apis_reached"] == 1
    # some constructed sequence reaches the gap API
    assert any("thing_gap_use" in s for s in res.sequences)


def _arg_handle(t):
    return {"type": t, "is_const": [False], "name": ""}
