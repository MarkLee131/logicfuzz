#!/usr/bin/env python3
"""Measure construction breadth (gap_apis_reached / total) for a project, with
whatever LOGICFUZZ_* levers are set in the environment. Runs FuzzingContext.prepare()
(static construction, no LLM fuzzing loop) and prints the g2_construction telemetry.

Usage:
  LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_RESIDUAL_ALLCOVER=1 LOGICFUZZ_API_FLOOR=1 \
    python3 scripts/measure_breadth.py comparison/libpng.yaml
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiment import benchmark as benchmarklib
from experiment import oss_fuzz_checkout
from src.context.data_context import FuzzingContext


def main():
    yaml_path = sys.argv[1]
    benches = benchmarklib.Benchmark.from_yaml(yaml_path)
    b = benches[0]
    oss_fuzz_checkout.clone_oss_fuzz()
    ctx = FuzzingContext.prepare(
        project_name=b.project,
        benchmark=b,
        logger_instance=None,
        llm_client=None,
    )
    _ = ctx.to_dict() if hasattr(ctx, "to_dict") else {}
    # read the freshly-written analysis_summary
    summ = os.path.join("results", b.project, "static_analysis", "analysis_summary.json")
    if os.path.isfile(summ):
        s = json.load(open(summ))
        g2 = s.get("grammar_info", {}).get("g2_construction", {})
        st = s.get("statistics", {})
        # api_coverage = distinct APIs across all constructed sequences (THE breadth metric);
        # gap_apis_reached = only the baseline-uncovered (G5) subset.
        print("PROJECT:", b.project)
        print("total_apis:", st.get("total_apis"))
        print("BREADTH api_coverage:", g2.get("api_coverage"), "/", st.get("total_apis"))
        print("g2:", json.dumps({k: g2.get(k) for k in
              ("n_targets_attempted", "n_sequences", "api_coverage",
               "gap_apis_reached", "gap_apis_total", "avg_length",
               "api_floor_residual_count", "selected")}, indent=1))
    else:
        print("no analysis_summary written at", summ)


if __name__ == "__main__":
    main()
