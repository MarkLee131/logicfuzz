#!/usr/bin/env python3
"""Emit a deterministic gates-OFF snapshot of the generation core for one project.

Used by tests/test_golden_characterization.py via a subprocess with
PYTHONHASHSEED=0 so the snapshot is reproducible (the core has set/dict
iteration that otherwise leaks hash order — see the golden test docstring).
Prints the snapshot as JSON to stdout.

Usage: PYTHONHASHSEED=0 python3 scripts/_golden_snapshot.py <project>
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Hermetic: clear every LOGICFUZZ_* gate so the snapshot is the pure gates-OFF
# baseline that behavior-preserving refactors must hold fixed.
for _k in list(os.environ):
    if _k.startswith("LOGICFUZZ_"):
        del os.environ[_k]

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC
from liberator_adapter.analysis.sequence_constructor import construct_sequences
from liberator_adapter.analysis.subsystem_clusters import subsystem_clusters
from liberator_adapter.constraints.coverage_ranker import CoverageRanker

# Force the import-time _OBJCONSTRUCT_FIRST constant OFF (until refactor A1 makes
# it a per-call accessor) so the snapshot is the gates-OFF baseline.
SC._OBJCONSTRUCT_FIRST = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(project):
    pa = json.load(open(
        os.path.join(ROOT, f"results/{project}/static_analysis/project_apis.json")))
    apis = pa.get("apis") if isinstance(pa, dict) else pa
    acc = []
    tpath = os.path.join(ROOT, f"results/{project}/automaton/traces.json")
    if os.path.exists(tpath):
        tr = json.load(open(tpath))
        tr = tr if isinstance(tr, list) else tr.get("traces", [])
        for t in tr:
            names = [c.get("api_name") for c in (t.get("api_calls") or [])
                     if c.get("api_name")]
            if len(names) >= 2:
                acc.append(names)
    return apis, acc


def snapshot(project):
    apis, acc = _load(project)
    model = reconcile(apis)
    constructed = construct_sequences(
        model, project_apis=apis, accepting_paths=acc).sequences
    clusters = subsystem_clusters(model)
    selected = CoverageRanker().rank_and_select(
        constructed, clusters=clusters,
        portfolio_mode="complete", portfolio_depth=0.5).selected_sequences
    return {
        "project": project,
        "n_apis": len(model.apis),
        "n_constructed": len(constructed),
        "constructed": [list(s) for s in constructed],
        "n_selected": len(selected),
        "selected": [list(s) for s in selected],
    }


if __name__ == "__main__":
    print(json.dumps(snapshot(sys.argv[1]), sort_keys=True))
