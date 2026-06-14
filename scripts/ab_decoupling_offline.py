#!/usr/bin/env python3
"""Offline A/B for the driver decoupling/dedup levers (no docker).

Drives the REAL construction -> coverage-complete selection -> dedup pipeline on
a cached project's APISemanticModel + automaton traces, and reports portfolio
redundancy gates-OFF (baseline) vs gates-ON (decoupled). Measures driver
GENERATION QUALITY (inter-driver overlap); merged-coverage gain is the separate
docker A/B.

Usage: python3 scripts/ab_decoupling_offline.py [project]   # default lcms
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import construct_sequences
from liberator_adapter.analysis.subsystem_clusters import subsystem_clusters
from liberator_adapter.analysis.hole_semantics import value_intents_for_sequence
from liberator_adapter.analysis.driver_dedup import (
    pairwise_dedup_skeletons, subset_eliminate_skeletons)
from liberator_adapter.analysis.portfolio_redundancy import portfolio_redundancy
from liberator_adapter.constraints.coverage_ranker import CoverageRanker

PROJECT = sys.argv[1] if len(sys.argv) > 1 else "lcms"

GATES_ON = {
    "LOGICFUZZ_DENSE_PARTITION": "1",
    "LOGICFUZZ_DEDUP_WORKFLOW_PARTITION": "1",
    "LOGICFUZZ_DIVERSIFY_PRODUCERS": "1",
    "LOGICFUZZ_MARGINAL_DEPTH": "1",
    "LOGICFUZZ_PAIRWISE_DEDUP": "1",
    "LOGICFUZZ_SUBSET_ELIM": "1",
}
DEDUP_GATES = ("LOGICFUZZ_PAIRWISE_DEDUP", "LOGICFUZZ_SUBSET_ELIM",
               "LOGICFUZZ_DENSE_PARTITION", "LOGICFUZZ_DEDUP_WORKFLOW_PARTITION",
               "LOGICFUZZ_DIVERSIFY_PRODUCERS", "LOGICFUZZ_MARGINAL_DEPTH")


def _load(project):
    pa = json.load(open(f"results/{project}/static_analysis/project_apis.json"))
    apis = pa.get("apis") if isinstance(pa, dict) else pa
    model = reconcile(apis)
    acc = []
    tpath = f"results/{project}/automaton/traces.json"
    if os.path.exists(tpath):
        tr = json.load(open(tpath))
        tr = tr if isinstance(tr, list) else tr.get("traces", [])
        for t in tr:
            names = [c.get("api_name") for c in (t.get("api_calls") or [])
                     if c.get("api_name")]
            if len(names) >= 2:
                acc.append(names)
    return apis, model, acc


def _clear():
    for g in DEDUP_GATES:
        os.environ.pop(g, None)


def _run(apis, model, acc, gates_on):
    _clear()
    if gates_on:
        for k, v in GATES_ON.items():
            os.environ[k] = v
    # 1. construction (A-1/A-2a/A-2b/A-3 act here when gated)
    res = construct_sequences(model, project_apis=apis, accepting_paths=acc)
    constructed = res.sequences
    # 2. coverage-complete selection (the marginal selector B-1 adopts)
    clusters = subsystem_clusters(model)
    ranker = CoverageRanker()
    sel = ranker.rank_and_select(constructed, clusters=clusters,
                                 portfolio_mode="complete", portfolio_depth=0.5)
    selected = sel.selected_sequences
    # 3. dedup (B-2/B-3) over the shipped pool, with value-domain fingerprints
    skel = [{"api_sequence": s,
             "value_intents": value_intents_for_sequence(model, s)}
            for s in selected]
    if gates_on:
        skel = subset_eliminate_skeletons(skel, model)
        skel = pairwise_dedup_skeletons(skel, model, tau=0.8)
    shipped = [d["api_sequence"] for d in skel]
    _clear()
    return constructed, selected, shipped


def _fmt(label, seqs):
    r = portfolio_redundancy(seqs)
    return (f"  {label:<26} n={r.get('n_drivers',0):<4} "
            f"union_apis={r.get('union_apis',0):<4} "
            f"sum={r.get('sum_per_driver_apis',0):<5} "
            f"disjoint={r.get('disjointness',0):.3f} "
            f"mean_jaccard={r.get('mean_pairwise_jaccard',0):.3f}")


def main():
    apis, model, acc = _load(PROJECT)
    print(f"\n=== Offline decoupling A/B — {PROJECT} "
          f"({len(model.apis)} APIs, {len(acc)} traces) ===\n")
    c0, s0, sh0 = _run(apis, model, acc, gates_on=False)
    c1, s1, sh1 = _run(apis, model, acc, gates_on=True)
    print("BASELINE (all gates OFF):")
    print(_fmt("constructed pool", c0))
    print(_fmt("selected portfolio", s0))
    print(_fmt("shipped (no dedup)", sh0))
    print("\nTREATMENT (all gates ON):")
    print(_fmt("constructed pool", c1))
    print(_fmt("selected portfolio", s1))
    print(_fmt("shipped (deduped)", sh1))
    r0 = portfolio_redundancy(sh0)
    r1 = portfolio_redundancy(sh1)
    print("\nSHIPPED-PORTFOLIO DELTA (treatment - baseline):")
    print(f"  drivers:           {r0.get('n_drivers',0)} -> {r1.get('n_drivers',0)}")
    print(f"  union_apis:        {r0.get('union_apis',0)} -> {r1.get('union_apis',0)}")
    print(f"  disjointness:      {r0.get('disjointness',0):.3f} -> {r1.get('disjointness',0):.3f}"
          f"  (higher=better)")
    print(f"  mean_pairwise_jac: {r0.get('mean_pairwise_jaccard',0):.3f} -> "
          f"{r1.get('mean_pairwise_jaccard',0):.3f}  (lower=better)")


if __name__ == "__main__":
    main()
