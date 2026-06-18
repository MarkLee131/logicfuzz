"""B-2 / B-3: pairwise dissimilarity gate + subset elimination over the
doc-aware structural fingerprint (Layer C). Deterministic; the only doc/LLM
touch is CONSUMING an existing Stage-B VALID verdict (no new LLM calls).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from liberator_adapter.analysis.driver_fingerprint import (
    sequence_fingerprint, fingerprint_similarity, fingerprint_is_subset)


def _is_valid(sk: Dict[str, Any], valid_seqs: Optional[Set[Tuple[str, ...]]]) -> bool:
    if not valid_seqs:
        return False
    return tuple(sk.get("api_sequence") or []) in valid_seqs


def pairwise_dedup_skeletons(
        skeletons: Sequence[Dict[str, Any]],
        model,
        tau: float = 0.8,
        valid_seqs: Optional[Set[Tuple[str, ...]]] = None) -> List[Dict[str, Any]]:
    """Drop a skeleton whose fingerprint similarity to an already-kept skeleton
    exceeds ``tau`` — UNLESS it is Stage-B VALID-protected. Order-preserving.
    """
    kept: List[Dict[str, Any]] = []
    kept_fps = []
    for sk in skeletons:
        fp = sequence_fingerprint(sk.get("api_sequence") or [], model,
                                  sk.get("value_intents"))
        redundant = any(fingerprint_similarity(fp, kfp) > tau for kfp in kept_fps)
        if redundant and not _is_valid(sk, valid_seqs):
            continue
        kept.append(sk)
        kept_fps.append(fp)
    return kept


def subset_eliminate_skeletons(
        skeletons: Sequence[Dict[str, Any]],
        model,
        valid_seqs: Optional[Set[Tuple[str, ...]]] = None) -> List[Dict[str, Any]]:
    """Drop any skeleton whose fingerprint is a strict same-value-domain subset
    of another's (B-3). Order-preserving; keeps the superset.

    The semantic guard (``valid_seqs``, a set of Comprehender Stage-B VALID
    sequences) is the safety for the drop: a skeleton whose api_sequence is
    VALID is never eliminated even if its fingerprint is a subset of another's.
    """
    fps = [sequence_fingerprint(sk.get("api_sequence") or [], model,
                                sk.get("value_intents")) for sk in skeletons]
    drop = set()
    for i, fi in enumerate(fps):
        if _is_valid(skeletons[i], valid_seqs):
            continue
        for j, fj in enumerate(fps):
            if i != j and fingerprint_is_subset(fi, fj):
                drop.add(i)
                break
    return [sk for k, sk in enumerate(skeletons) if k not in drop]
