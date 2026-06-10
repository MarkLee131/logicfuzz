"""Pin the edge-weighted CDF dispatch piggyback.

Liberator (FSE 2025) probes each driver in a short fuzzing campaign and marks
seed-producing drivers as positive. Our preflight already smoke-fuzzes 15s and
records ``edges_seen`` (drop 0-edge = Liberator negative). This wires that
already-computed signal into the MERGE dispatch: high-interaction sub-drivers
get a larger share of the fuzzer's per-input budget (CDF dispatch), instead of
UNIFORM ``selector % N``. ``run_single_fuzz._edges_weights_for``.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import run_single_fuzz as rsf  # noqa: E402


class _WD:
    def __init__(self, base):
        self.base = str(base)


def _write_preflight(base, edges):
    d = Path(base) / 'merged'
    d.mkdir(parents=True, exist_ok=True)
    results = [{"driver_path": f"/x/{n}", "edges_seen": e}
               for n, e in edges.items()]
    (d / 'preflight.json').write_text(json.dumps({"results": results}))


def test_weights_aligned_to_namesorted_order(tmp_path):
    # from_paths sorts drivers by name, so weights must follow name order.
    _write_preflight(tmp_path, {"03.fuzz_target": 100, "01.fuzz_target": 10})
    srcs = [Path("/x/03.fuzz_target"), Path("/x/01.fuzz_target")]
    assert rsf._edges_weights_for(srcs, _WD(tmp_path)) == [10.0, 100.0]


def test_none_without_preflight_data(tmp_path):
    # No preflight.json → UNIFORM fallback (prior behaviour).
    assert rsf._edges_weights_for([Path("/x/01.fuzz_target")],
                                  _WD(tmp_path)) is None


def test_none_when_all_weights_tie(tmp_path):
    _write_preflight(tmp_path, {"01.fuzz_target": 5, "02.fuzz_target": 5})
    srcs = [Path("/x/01.fuzz_target"), Path("/x/02.fuzz_target")]
    assert rsf._edges_weights_for(srcs, _WD(tmp_path)) is None


def test_missing_driver_gets_median_weight(tmp_path):
    # A candidate with no preflight datum is neutral (median), not penalised.
    _write_preflight(tmp_path, {"01.fuzz_target": 10, "02.fuzz_target": 30})
    srcs = [Path("/x/01.fuzz_target"), Path("/x/02.fuzz_target"),
            Path("/x/03.fuzz_target")]
    assert rsf._edges_weights_for(srcs, _WD(tmp_path)) == [10.0, 30.0, 30.0]
