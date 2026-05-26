"""Semantic value-intent for skeleton holes (redesign G4).

A type-correct hole under-constrains the LLM: an ``int`` index hole doesn't
know it should sometimes be in-range (hit the found path) and sometimes
out-of-range (hit not-found / error handling), and a parser's ``const
uint8_t*`` input doesn't know its bytes must form a structure that survives
the front gate to reach deep code (P-gen-8 / P-gen-9).

This module turns the reconciled ``APISemanticModel`` into a per-argument
*value intent* — a structured constraint string — for every API in a
skeleton's sequence. The Prototyper renders it into the hole-filling prompt so
value choices carry intent, not just a type.

Deterministic (no LLM): the intent is a pure function of ``ArgRole`` + type.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from liberator_adapter.analysis.api_semantic_model import (
    ArgRole,
    APISemanticModel,
)

_INT_TYPES = ("int", "size_t", "uint", "long", "short", "unsigned",
              "int8", "int16", "int32", "int64", "char")


def _is_scalar_int(type_str: str) -> bool:
    low = (type_str or "").lower()
    if "*" in low or "[" in low:
        return False
    return any(t in low for t in _INT_TYPES)


def _arg_intent(arg) -> Optional[str]:
    """Value intent for one argument, or ``None`` when nothing to say."""
    role = arg.role
    if role is ArgRole.INPUT_BUFFER:
        return ("STRUCTURED_INPUT: drive these bytes from the fuzzer input. "
                "If the API parses a format, split the input into a "
                "header/prefix + body so the bytes survive front-gate "
                "validation and reach the deep parse path.")
    if role is ArgRole.LENGTH:
        pw = arg.pairs_with
        if pw is not None:
            return f"LENGTH: must equal the byte-length of the buffer at arg{pw}."
        return "LENGTH: must equal the length of the buffer it describes."
    if role is ArgRole.OUTPUT:
        return ("OUTPUT: pass the address of a fresh local; the API writes "
                "through it. Do not pre-fill.")
    if role is ArgRole.HANDLE_IN:
        return ("HANDLE: must be a live handle produced by an earlier creator "
                "in this sequence (never NULL, never freed).")
    if role is ArgRole.NULLABLE_HANDLE:
        return "NULLABLE_HANDLE: may be NULL; exercise both NULL and a live handle."
    if role is ArgRole.CONFIG and _is_scalar_int(arg.type_str):
        # The P-gen-8 index/flag hole: vary across valid and invalid.
        return ("VARY_RANGE: cover both in-range values (drive the success / "
                "found branch) and out-of-range / boundary values (drive the "
                "error-handling / not-found branch).")
    return None


def value_intents_for_sequence(
    model: APISemanticModel,
    api_sequence: Sequence[str],
) -> List[Dict[str, Any]]:
    """Per-API, per-arg value intents for a skeleton's sequence.

    Returns a list of ``{api, role, args: [{index, role, type, intent,
    pairs_with}]}`` records; APIs absent from the model or with no
    intent-bearing args are dropped, so the result is the minimal set the
    Prototyper needs to render.
    """
    out: List[Dict[str, Any]] = []
    for name in api_sequence:
        sem = model.get(name) if model else None
        if sem is None:
            continue
        arg_records: List[Dict[str, Any]] = []
        for arg in sem.args:
            intent = _arg_intent(arg)
            if intent is None:
                continue
            arg_records.append({
                "index": arg.index,
                "role": arg.role.value,
                "type": arg.type_str,
                "pairs_with": arg.pairs_with,
                "intent": intent,
            })
        if arg_records:
            out.append({
                "api": name,
                "role": sem.role.value,
                "args": arg_records,
            })
    return out


def render_value_intents(intents: Sequence[Dict[str, Any]]) -> str:
    """Render value intents as a compact prompt block for the Prototyper."""
    if not intents:
        return ""
    lines = ["Value intent for hole filling (derive values to match these):"]
    for rec in intents:
        lines.append(f"- {rec['api']} [{rec['role']}]:")
        for a in rec["args"]:
            lines.append(f"    arg{a['index']} ({a['type']}): {a['intent']}")
    return "\n".join(lines)


def annotate_skeletons(
    skeleton_drivers: Sequence[Dict[str, Any]],
    model: APISemanticModel,
) -> int:
    """Attach a ``value_intents`` block to each skeleton in place.

    Returns the number of skeletons that received at least one intent. Safe
    on missing/empty inputs (returns 0).
    """
    if not skeleton_drivers or model is None:
        return 0
    n = 0
    for sk in skeleton_drivers:
        seq = sk.get("api_sequence") or []
        intents = value_intents_for_sequence(model, seq)
        sk["value_intents"] = intents
        if intents:
            n += 1
    return n
