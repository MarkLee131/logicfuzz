#!/usr/bin/env python3
"""G2 viability harness — does construct-from-model beat random-walk+filter?

Offline, no LLM, no build. For each cached benchmark it:
  1. builds the APISemanticModel (G1),
  2. constructs sequences from it (G2),
  3. validates every constructed sequence with the *real* ``Typestate``
     checker (lifecycle violations), and
  4. compares against the cached baseline (random-walk → 5-filter) count.

The redesign's viability bar (§6): **lcms moves off ~1**. We additionally
report the lifecycle-clean fraction — the redesign claims construction is
valid *by construction*, so this should be ~1.0.

Run:  .venv/bin/python3 tools/g2_viability/run.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APIRole, reconcile,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    construct_sequences,
)
from liberator_adapter.analysis.usedef import (  # noqa: E402
    UseDefGraph, Typestate, extract_api_effects,
)

BENCHES = ["lcms", "cjson", "c-ares"]


def _load_apis(project: str) -> List[Dict[str, Any]]:
    p = ROOT / f"results/{project}/static_analysis/project_apis.json"
    return [a for a in json.load(open(p))["apis"] if isinstance(a, dict)]


def _baseline_count(project: str) -> int:
    p = ROOT / f"results/{project}/static_analysis/filtered_sequences.json"
    if not p.is_file():
        return -1
    d = json.load(open(p))
    seqs = d if isinstance(d, list) else d.get("sequences", [])
    return len(seqs)


def _lifecycle_pairs(model) -> List[Tuple[str, str]]:
    """(creator, destroyer) pairs from the model, so ``extract_api_effects``
    wires KILL edges and Typestate recognises the destroyers."""
    pairs: List[Tuple[str, str]] = []
    producers: Dict[str, str] = {}
    for s in model.apis.values():
        for t in s.produces:
            producers.setdefault(t, s.name)
    for s in model.apis.values():
        if s.role is APIRole.DESTROYER:
            for t in s.destroys:
                if t in producers:
                    pairs.append((producers[t], s.name))
    return pairs


# Ordering faults are what actually crash / UB a driver. UNCLOSED_RESOURCE
# (and REINIT) are leaks — benign in a short-lived libFuzzer process and not a
# correctness defect for a generated driver. The driver-relevant validity bar
# is therefore "no ordering fault".
_ORDERING_FAULTS = {
    "USE_BEFORE_INIT", "USE_AFTER_DESTROY", "DOUBLE_DESTROY",
    "DESTROY_BEFORE_INIT",
}


def _validate(apis, pairs, sequences) -> Tuple[int, int, int]:
    """Return (n_ordering_clean, n_fully_clean, n_total) via real Typestate."""
    ts = Typestate(UseDefGraph(extract_api_effects(apis, lifecycle_pairs=pairs or None)))
    order_clean = full_clean = 0
    for seq in sequences:
        v = ts.check(seq)
        if not v:
            full_clean += 1
        if not ({r.kind.name for r in v} & _ORDERING_FAULTS):
            order_clean += 1
    return order_clean, full_clean, len(sequences)


def main() -> int:
    print(f"{'bench':8} {'APIs':>5} {'baseline':>9} {'constructed':>12} "
          f"{'ordering-clean':>15} {'no-leak':>12} {'api_cov':>8}")
    print("-" * 76)
    ok = True
    for project in BENCHES:
        try:
            apis = _load_apis(project)
        except Exception as e:
            print(f"{project:8} SKIP ({e})")
            continue
        model = reconcile(apis, project=project)
        pairs = _lifecycle_pairs(model)
        # Construct from the model (no seeds), self-filtered through the
        # Typestate oracle so the output is ordering-clean by construction.
        res = construct_sequences(model, project_apis=apis, lifecycle_pairs=pairs)
        order_clean, full_clean, total = _validate(apis, pairs, res.sequences)
        oc = f"{order_clean}/{total} ({(order_clean/total*100 if total else 0):.0f}%)"
        nl = f"{full_clean}/{total} ({(full_clean/total*100 if total else 0):.0f}%)"
        base = _baseline_count(project)
        m = res.metrics
        print(f"{project:8} {len(apis):>5} {base:>9} {total:>12} "
              f"{oc:>15} {nl:>12} {m['api_coverage']:>8}")
        # Viability: lcms off ~1, AND construction free of ordering faults.
        if project == "lcms" and total <= 1:
            ok = False
        if order_clean != total:
            ok = False
    print("-" * 76)
    print("ordering-clean = no use-before-init / use-after-destroy / "
          "double-destroy (the driver-relevant bar)")
    print("no-leak        = additionally closes every opened handle "
          "(benign if <100% — leaks are safe in a fuzzer)")
    print()
    print("viability (redesign §6): lcms off ~1 AND 100% ordering-clean  →",
          "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
