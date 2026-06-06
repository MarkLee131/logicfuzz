"""T9 probe: is a static call-graph REACHABILITY weight worth adding to L4
ranking? (empirical-before-parametric)

Question: does the current L4 / planner ranking *mis-prioritize* deep-but-
reachable gap APIs — i.e. APIs that (a) the OSS-Fuzz baseline does NOT cover
(the generation target) and (b) sit deep in the use-def dependency graph
(need an upstream producer chain to be reachable)? If those deep gap APIs are
already surfaced early (or are absent for reasons a CFG weight cannot fix),
then T9 buys nothing.

Read-only. CACHED data only (no docker). For each project we use:
  - results/<proj>/apis_llvm.json            (JSONL; full IR API set)
  - results/<proj>/state/api_semantic_model.json  (public API universe + emit order)
  - results/<proj>/state/plan_ledger.json    (actual L4/planner-ordered candidates)
  - the on-disk baseline textcov  (.covreport)  via coverage_gap.locate_baseline_textcov

"dependency_depth" (graph.dependency_depth()) is the reachability proxy:
  depth 0 = root constructor / no handle precondition (trivially reachable);
  depth k = needs a chain of k producer calls before it is callable.

Usage:
  cd <repo> && PYTHONPATH=. python3 scripts/l4_reachability_probe.py
"""
from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from liberator_adapter.analysis.usedef import extract_api_effects, UseDefGraph
from liberator_adapter.analysis.coverage_gap import (
    compute_gap_apis,
    locate_baseline_textcov,
    parse_textcov_covered,
)

PROJECTS = ["c-ares", "lcms", "zlib"]
RESULTS = Path("results")

# A gap API is "deep" (reachability-gated) when its use-def dependency depth is
# at or above this cut. depth>=2 means: at least two producer calls must be
# emitted upstream before the API is even callable — exactly the case a naive
# ranker that ignores reachability could strand.
DEEP_CUT = 2


def _load_jsonl(path: Path) -> List[dict]:
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _build_depth(project: str) -> Dict[str, int]:
    """dependency_depth() over the FULL IR API set (need all producers)."""
    rows = _load_jsonl(RESULTS / project / "apis_llvm.json")
    graph = UseDefGraph(extract_api_effects(rows))
    return graph.dependency_depth()


def _public_universe(project: str) -> List[str]:
    """The curated public API universe, in api_semantic_model emit order.

    This is the set the ranker actually ranks (138/297/95), a subset of the
    1000+ IR symbols. Insertion order is the model's own emit order — one of
    the two ranking signals we test.
    """
    m = json.loads((RESULTS / project / "state" / "api_semantic_model.json").read_text())
    return list(m["apis"].keys())


def _plan_ledger_rank(project: str) -> Tuple[Dict[str, int], int, int]:
    """Earliest-appearance rank of each API across planner-ordered sequences.

    Returns (rank_by_api, n_plans, n_distinct_apis_in_plans). An API absent
    from every emitted candidate sequence has no rank (the ranker never
    surfaces it at all) — that is the strongest form of mis-prioritization.
    """
    pl = json.loads((RESULTS / project / "state" / "plan_ledger.json").read_text())
    plans = pl.get("plans", [])
    rank: Dict[str, int] = {}
    for idx, plan in enumerate(plans):
        for name in plan.get("sequence_names", []):
            if name not in rank:
                rank[name] = idx
    return rank, len(plans), len(rank)


def _gap_apis(project: str, universe: Set[str]) -> Tuple[Set[str], Optional[Path], int]:
    tc = locate_baseline_textcov(project)
    covered = parse_textcov_covered(tc) if tc else set()
    gap = compute_gap_apis(universe, project=project)
    return gap, tc, len(universe & covered)


def _spearman(rank_a: List[float], rank_b: List[float]) -> Optional[float]:
    """Rank correlation between two orderings over the same items."""
    n = len(rank_a)
    if n < 3:
        return None
    d2 = sum((a - b) ** 2 for a, b in zip(rank_a, rank_b))
    return 1 - (6 * d2) / (n * (n * n - 1))


def analyse(project: str) -> dict:
    depth = _build_depth(project)
    universe = _public_universe(project)
    uni_set = set(universe)
    gap, tc, covered_in_uni = _gap_apis(project, uni_set)
    ledger_rank, n_plans, n_in_plans = _plan_ledger_rank(project)

    # Depth restricted to the public universe (what the ranker sees).
    uni_depth = {n: depth.get(n, 0) for n in universe}
    gap_depth = {n: depth.get(n, 0) for n in gap}

    # --- (1) how deep are the gap APIs? ---
    gap_hist = Counter(gap_depth.values())
    deep_gap = {n for n, d in gap_depth.items() if d >= DEEP_CUT}
    shallow_gap = set(gap) - deep_gap

    # Baseline rate: fraction of the WHOLE public universe that is deep — to
    # tell whether gap APIs are *disproportionately* deep (the precondition for
    # a reachability weight to matter).
    uni_deep = {n for n, d in uni_depth.items() if d >= DEEP_CUT}

    # --- (2) does current ranking surface the deep gap APIs? ---
    # Signal A: plan_ledger earliest-appearance rank (the real candidate output)
    deep_in_plans = sorted(n for n in deep_gap if n in ledger_rank)
    deep_absent = sorted(n for n in deep_gap if n not in ledger_rank)
    shallow_in_plans = [n for n in shallow_gap if n in ledger_rank]

    def _mean_rank(names) -> Optional[float]:
        rs = [ledger_rank[n] for n in names if n in ledger_rank]
        return round(statistics.mean(rs), 2) if rs else None

    deep_mean_rank = _mean_rank(deep_gap)
    shallow_mean_rank = _mean_rank(shallow_gap)

    # Signal B: api_semantic_model emit order vs depth (Spearman). A strong
    # NEGATIVE correlation would mean the model already front-loads deep APIs;
    # ~0 means emit order is depth-agnostic (a reachability weight *could*
    # reorder), positive means it actively buries deep APIs.
    emit_pos = {n: i for i, n in enumerate(universe)}
    paired = [(emit_pos[n], uni_depth[n]) for n in universe]
    # Spearman over (emit_rank, depth_rank).
    ds = sorted(set(uni_depth[n] for n in universe))
    depth_rank_map = {d: i for i, d in enumerate(ds)}
    a_ranks = [emit_pos[n] for n in universe]
    b_ranks = [depth_rank_map[uni_depth[n]] for n in universe]
    rho_emit_depth = _spearman(a_ranks, b_ranks)

    return {
        "project": project,
        "textcov": tc.name if tc else None,
        "public_universe": len(universe),
        "covered_public": covered_in_uni,
        "gap_total": len(gap),
        "gap_depth_hist": dict(sorted(gap_hist.items())),
        "deep_cut": DEEP_CUT,
        "deep_gap_n": len(deep_gap),
        "shallow_gap_n": len(shallow_gap),
        "uni_deep_rate": round(len(uni_deep) / max(1, len(universe)), 3),
        "deep_gap_rate": round(len(deep_gap) / max(1, len(gap)), 3),
        "max_depth_universe": max(uni_depth.values()) if uni_depth else 0,
        "n_plans": n_plans,
        "apis_in_plans": n_in_plans,
        "deep_gap_in_plans": len(deep_in_plans),
        "deep_gap_absent_from_plans": len(deep_absent),
        "shallow_gap_in_plans": len(shallow_in_plans),
        "deep_gap_mean_ledger_rank": deep_mean_rank,
        "shallow_gap_mean_ledger_rank": shallow_mean_rank,
        "rho_emit_order_vs_depth": (round(rho_emit_depth, 3)
                                    if rho_emit_depth is not None else None),
        "deep_gap_examples": sorted(deep_gap,
                                    key=lambda n: -uni_depth[n])[:8],
        "deep_absent_examples": deep_absent[:8],
    }


def main() -> None:
    print("=" * 78)
    print("T9 PROBE — does L4 ranking mis-prioritize deep-but-reachable gap APIs?")
    print(f"reachability proxy = use-def dependency_depth();  DEEP = depth >= {DEEP_CUT}")
    print("=" * 78)

    rows = []
    for p in PROJECTS:
        proj_dir = RESULTS / p
        if not proj_dir.exists():
            print(f"\n[{p}] SKIP — no results dir")
            continue
        r = analyse(p)
        rows.append(r)
        print(f"\n### {p}   (baseline textcov: {r['textcov']})")
        print(f"  public universe            : {r['public_universe']} APIs "
              f"(baseline covers {r['covered_public']})")
        print(f"  gap APIs (uncovered)       : {r['gap_total']}")
        print(f"  gap depth histogram        : {r['gap_depth_hist']}   "
              f"(max depth in universe = {r['max_depth_universe']})")
        print(f"  deep gap (depth>={DEEP_CUT})        : {r['deep_gap_n']}  "
              f"(deep-rate {r['deep_gap_rate']}  vs whole-universe deep-rate "
              f"{r['uni_deep_rate']})")
        print(f"  --- does ranking surface them? ---")
        print(f"  plan_ledger sequences      : {r['n_plans']} plans, "
              f"{r['apis_in_plans']} distinct APIs appear")
        print(f"  deep gap APIs in plans     : {r['deep_gap_in_plans']} / "
              f"{r['deep_gap_n']}   (absent: {r['deep_gap_absent_from_plans']})")
        print(f"  mean earliest plan rank    : deep={r['deep_gap_mean_ledger_rank']}  "
              f"shallow={r['shallow_gap_mean_ledger_rank']}  (lower=earlier; "
              f"None=never surfaced)")
        print(f"  Spearman(emit order, depth): {r['rho_emit_order_vs_depth']}  "
              f"(~0 = depth-agnostic order)")
        if r["deep_gap_examples"]:
            print(f"  deep gap examples          : {r['deep_gap_examples']}")
        if r["deep_absent_examples"]:
            print(f"  deep+absent-from-plans     : {r['deep_absent_examples']}")

    # ---- cross-project verdict ----
    print("\n" + "=" * 78)
    print("VERDICT INPUTS")
    print("=" * 78)
    tot_deep = sum(r["deep_gap_n"] for r in rows)
    tot_gap = sum(r["gap_total"] for r in rows)
    tot_deep_absent = sum(r["deep_gap_absent_from_plans"] for r in rows)
    print(f"  total gap APIs across projects : {tot_gap}")
    print(f"  of which DEEP (depth>={DEEP_CUT})       : {tot_deep} "
          f"({round(100*tot_deep/max(1,tot_gap),1)}%)")
    print(f"  deep gap APIs the planner NEVER surfaces : {tot_deep_absent}")
    for r in rows:
        # Is the planner's blind spot reachability-shaped or absent-shaped?
        absent_deep = r["deep_gap_absent_from_plans"]
        absent_shallow = (r["shallow_gap_n"] - r["shallow_gap_in_plans"])
        print(f"  [{r['project']}] absent-from-plans: deep={absent_deep}, "
              f"shallow={absent_shallow}  ->  "
              f"{'reachability-shaped' if absent_deep > absent_shallow else 'NOT reachability-shaped (depth-agnostic gap)'}")


if __name__ == "__main__":
    main()
