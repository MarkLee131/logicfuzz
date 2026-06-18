"""Layer C: doc-aware structural fingerprint of a driver sequence.

A fingerprint is (api_set, root_producers, subchain_shape, value_domain_sig).
The value-domain signature is the keystone of doc/LLM integration: it is a hash
of the G4 ``value_intents`` CONFIG/enum/range intents, so two drivers with the
same APIs but doc-distinct value strategies are NON-redundant. Deterministic;
no LLM.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional, Sequence

# CREATOR->C, MUTATOR->M, CONSUMER->U, DESTROYER->D, UNKNOWN->?
_ROLE_CODE = {"CREATOR": "C", "MUTATOR": "M", "CONSUMER": "U",
              "DESTROYER": "D", "UNKNOWN": "?"}


@dataclass(frozen=True)
class Fingerprint:
    api_set: FrozenSet[str]
    root_producers: FrozenSet[str]
    subchain_shape: str          # ordered role codes, e.g. "CUD"
    value_domain_sig: str        # hash of CONFIG/enum/range intents ("" if none)


def _role_name(model, name: str) -> str:
    sem = model.get(name) if model else None
    role = getattr(sem, "role", None)
    return getattr(role, "name", "UNKNOWN") if role is not None else "UNKNOWN"


def _value_domain_signature(
        value_intents: Optional[Sequence[Dict[str, Any]]]) -> str:
    if not value_intents:
        return ""
    items = []
    for rec in value_intents:
        api = rec.get("api", "")
        for a in rec.get("args", []):
            role = a.get("role", "")
            intent = a.get("intent", "") or ""
            if role == "CONFIG" or intent.startswith(
                    ("FUZZ_DERIVE", "ENUM", "VARY_RANGE")):
                items.append([api, a.get("index"), role, intent])
    if not items:
        return ""
    items.sort(key=lambda t: (str(t[0]), -1 if t[1] is None else t[1], str(t[2])))
    blob = json.dumps(items, sort_keys=True, default=str)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def sequence_fingerprint(
        api_sequence: Sequence[str],
        model,
        value_intents: Optional[Sequence[Dict[str, Any]]] = None) -> Fingerprint:
    api_set = frozenset(a for a in api_sequence if a)
    roots = frozenset(
        a for a in api_sequence if _role_name(model, a) == "CREATOR")
    shape = "".join(_ROLE_CODE.get(_role_name(model, a), "?")
                    for a in api_sequence if a)
    return Fingerprint(api_set, roots, shape,
                       _value_domain_signature(value_intents))


def fingerprint_is_subset(a: Fingerprint, b: Fingerprint) -> bool:
    """True iff ``a`` is a strict, same-value-domain, same-or-fewer-roots subset
    of ``b`` (B-3 subset elimination). A value-distinct or root-distinct subset
    is NOT eliminated.
    """
    return (a.value_domain_sig == b.value_domain_sig
            and a.root_producers <= b.root_producers
            and a.api_set < b.api_set)
