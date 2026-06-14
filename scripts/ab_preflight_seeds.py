#!/usr/bin/env python3
"""Empirical A/B for the merge-preflight seed routing fix (no LLM, no full eval).

Re-runs the merge preflight on the EXISTING built lcms binaries with seed
routing OFF vs ON (controlled: same binaries, only route_seeds differs). Proves
the fix flips parser-entry drivers from edges=0 (culled as no_progress on random
bytes) to edges>0 (accepted), which is what unblocks merged coverage.

Usage: python3 scripts/ab_preflight_seeds.py [smoke_seconds]
"""
import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

P = importlib.import_module("tools.merge_drivers.preflight")

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = ROOT / "results" / "output-lcms-project"
SMOKE = int(sys.argv[1]) if len(sys.argv) > 1 else 12


def _pairs():
    out = []
    for b in sorted((BASE / "preflight_bins").iterdir(), key=lambda p: p.name):
        src = BASE / "fuzz_targets" / f"{b.name}.fuzz_target"
        if src.exists():
            out.append((src, b))
    return out


def _run(pairs, route):
    res = P.preflight(pairs, smoke_duration_sec=SMOKE, drop_on_crash=True,
                      project="lcms", route_seeds=route)
    acc = [r for r in res if r.accepted]
    edges = sorted((r.edges_seen for r in acc), reverse=True)
    return {
        "candidates": len(res),
        "accepted": len(acc),
        "sum_edges": sum(r.edges_seen for r in acc),
        "max_edges": max(edges) if edges else 0,
        "edges": edges,
    }


def main():
    pairs = _pairs()
    print(f"=== merge-preflight seed A/B (lcms, {len(pairs)} binaries, "
          f"{SMOKE}s smoke) ===")
    off = _run(pairs, route=False)
    print(f"OFF (empty corpus): accepted={off['accepted']}/{off['candidates']} "
          f"sum_edges={off['sum_edges']} max={off['max_edges']}")
    on = _run(pairs, route=True)
    print(f"ON  (real seeds)  : accepted={on['accepted']}/{on['candidates']} "
          f"sum_edges={on['sum_edges']} max={on['max_edges']}")
    print(f"DELTA: accepted {off['accepted']} -> {on['accepted']} "
          f"({on['accepted'] - off['accepted']:+d}); "
          f"sum_edges {off['sum_edges']} -> {on['sum_edges']} "
          f"({on['sum_edges'] - off['sum_edges']:+d})")


if __name__ == "__main__":
    main()
