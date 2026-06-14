"""Layer E: portfolio-redundancy telemetry — the A/B oracle for decoupling.

Pure, deterministic, no LLM. Computes how much the selected drivers overlap in
API-set terms; a *lower* mean pairwise Jaccard and a *higher* disjointness mean
the portfolio is better decoupled (merge gains more marginal coverage).
"""
from __future__ import annotations

import itertools
from typing import Any, Dict, List, Sequence


def portfolio_redundancy(sequences: Sequence[Sequence[str]]) -> Dict[str, Any]:
    """Return redundancy metrics for a list of driver API sequences.

    Keys: n_drivers, union_apis, sum_per_driver_apis, disjointness
    (union/total, 1.0 = fully disjoint), mean_pairwise_jaccard
    (0.0 = no pairwise overlap).
    """
    sets: List[set] = [set(s) for s in sequences if s]
    n = len(sets)
    out: Dict[str, Any] = {"n_drivers": n}
    if n == 0:
        return out
    union: set = set().union(*sets)
    total = sum(len(s) for s in sets)
    out["union_apis"] = len(union)
    out["sum_per_driver_apis"] = total
    out["disjointness"] = (len(union) / total) if total else 1.0
    if n > 1:
        jaccards: List[float] = []
        for a, b in itertools.combinations(sets, 2):
            u = a | b
            jaccards.append(len(a & b) / len(u) if u else 0.0)
        out["mean_pairwise_jaccard"] = sum(jaccards) / len(jaccards)
    else:
        out["mean_pairwise_jaccard"] = 0.0
    return out
