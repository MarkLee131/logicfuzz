#!/usr/bin/env python3
"""Emit a deterministic gates-OFF snapshot of the generation core for one project.

Used by tests/test_golden_characterization.py via a subprocess pinned to
PYTHONHASHSEED=0 (the core has set/dict iteration that otherwise leaks hash
order — see the golden test docstring + D0 in run_logicfuzz.py).

INPUT IS FROZEN: the snapshot reads the project's APIs + accepting-paths from a
committed fixture (tests/golden/<project>.input.json), NOT from results/<project>/
— because live `--merge-drivers`/NO_CACHE runs regenerate results/ and would
otherwise drift the golden's input out from under it. Capture mode (fixture
absent) seeds the fixture once from results/.

Usage: PYTHONHASHSEED=0 python3 scripts/_golden_snapshot.py <project> <input_fixture_path>
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
# Explicitly disable gates whose DEFAULT flipped to ON so the snapshot always
# characterises the gates-OFF baseline regardless of the current default.
# LOGICFUZZ_VALIDITY_CONTRACT / POPULATE_COLLECTIONS / FUZZ_BUFFERS are now
# unconditional (switches removed 2026-06-20) — no pin needed.
os.environ["LOGICFUZZ_RESIDUAL_ALLCOVER"] = "0"
os.environ["LOGICFUZZ_API_FLOOR"] = "0"

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis import sequence_constructor as SC
from liberator_adapter.analysis.sequence_constructor import construct_sequences
from liberator_adapter.analysis.subsystem_clusters import subsystem_clusters
from liberator_adapter.constraints.coverage_ranker import CoverageRanker

# Force the import-time _OBJCONSTRUCT_FIRST constant OFF (until refactor A1 makes
# it a per-call accessor) so the snapshot is the gates-OFF baseline.
SC._OBJCONSTRUCT_FIRST = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_from_results(project):
    """Capture-mode only: read the live artifacts to seed the frozen fixture."""
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
    return {"apis": apis, "accepting_paths": acc}


def snapshot(project, inp):
    apis = inp["apis"]
    acc = inp.get("accepting_paths") or []
    model = reconcile(apis)
    constructed = construct_sequences(
        model, project_apis=apis, accepting_paths=acc).sequences
    clusters = subsystem_clusters(model)
    selected = CoverageRanker().rank_and_select(
        constructed, clusters=clusters,
        portfolio_depth=0.5).selected_sequences
    return {
        "project": project,
        "n_apis": len(model.apis),
        "n_constructed": len(constructed),
        "constructed": [list(s) for s in constructed],
        "n_selected": len(selected),
        "selected": [list(s) for s in selected],
    }


if __name__ == "__main__":
    project = sys.argv[1]
    fixture_path = sys.argv[2]
    if os.path.exists(fixture_path):
        inp = json.load(open(fixture_path))
    else:
        # capture mode: seed the frozen fixture from the live results once.
        inp = _load_from_results(project)
        os.makedirs(os.path.dirname(fixture_path), exist_ok=True)
        with open(fixture_path, "w") as f:
            json.dump(inp, f, sort_keys=True)
    print(json.dumps(snapshot(project, inp), sort_keys=True))
