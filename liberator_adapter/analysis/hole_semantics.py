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
from liberator_adapter.analysis.named_constants import enum_members_for_type

_INT_TYPES = ("int", "size_t", "uint", "long", "short", "unsigned",
              "int8", "int16", "int32", "int64", "char")


def _is_scalar_int(type_str: str) -> bool:
    low = (type_str or "").lower()
    if "*" in low or "[" in low:
        return False
    return any(t in low for t in _INT_TYPES)


def _format_for_api(api_name: str):
    """Map a parser-entry API to ``(format_label, minimal-valid recipe)`` for
    the G4 format-aware decoder, or ``None`` for an unknown/raw format.

    Recipes are deliberately concrete (byte offsets / magic) so the LLM can
    write the normalizer without guessing the layout. Extend per format.
    """
    low = (api_name or "").lower()
    if "it8" in low or "cgats" in low:
        return ("IT8/CGATS text dataset",
                "ensure the buffer begins with a token the IT8 lexer accepts "
                "(e.g. a header keyword like 'NUMBER_OF_FIELDS' or a leading "
                "'#' comment line) so parsing proceeds past the front gate, "
                "then append the fuzzer bytes as the body")
    if "profile" in low and ("mem" in low or "stream" in low):
        return ("ICC profile (binary)",
                "the buffer must be >=128 bytes; bytes[36..39] must equal the "
                "ASCII magic 'acsp'; bytes[0..3] must be the big-endian total "
                "byte length; the remaining bytes carry the fuzzer payload")
    return None


def _arg_intent(arg, api_name: str = "", vocab=None) -> Optional[str]:
    """Value intent for one argument, or ``None`` when nothing to say.

    ``vocab`` is the optional named-constant vocabulary (T2): when an enum/flag
    CONFIG arg's type is a known true enum, the intent carries the exact legal
    constant set instead of a blind range hint.
    """
    role = arg.role
    if role is ArgRole.INPUT_BUFFER:
        fmt = _format_for_api(api_name)
        if fmt is not None:
            label, recipe = fmt
            # G4 format-aware decoder. The idempotence clause is what lets this
            # COEXIST with the seed layer (scripts/seed_discovery.py): a real
            # seed already has a valid header → passthrough unchanged; a random
            # or libFuzzer-mutated input → normalized so it still clears the
            # front gate and the fuzzer explores the BODY instead of bouncing
            # off the header.
            return (
                f"STRUCTURED_INPUT [{label}]: this arg feeds a {label} parser. "
                f"Write a small IDEMPOTENT decoder that turns the raw fuzzer "
                f"bytes into a minimal-valid {label}: {recipe}. CRITICAL — make "
                f"it idempotent: if the input ALREADY has a valid {label} "
                f"header (a real corpus seed), pass it through UNCHANGED; only "
                f"normalize when the header is missing/invalid. Pass the "
                f"(possibly-normalized) buffer + its length to the API.")
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
    if role is ArgRole.CONFIG:
        # T2: if this CONFIG arg's type is a known true enum, hand the LLM the
        # exact legal constant set so it stops guessing out-of-enum numbers.
        # (Enum/signature typedefs like cmsColorSpaceSignature are not scalar
        # ints by spelling, so this is gated on vocab membership, not type name.)
        members = enum_members_for_type(vocab, arg.type_str) if vocab else []
        if members:
            shown = ", ".join(members[:12])
            more = "" if len(members) <= 12 else f" (+{len(members)-12} more in <library_constants>)"
            return (f"ENUM ({arg.type_str}): pass a LEGAL constant — one of "
                    f"{{{shown}}}{more}. Prefer the value that drives the most "
                    f"code; also try a boundary/invalid value for the error path.")
        if _is_scalar_int(arg.type_str):
            # Plain-int flag/index hole: vary across valid and invalid, and
            # prefer a named constant from the library vocabulary over a raw
            # magic number.
            return ("VARY_RANGE: cover both in-range values (drive the success "
                    "/ found branch) and out-of-range / boundary values (drive "
                    "the error-handling / not-found branch). If a legal named "
                    "constant fits this arg, use one from <library_constants> "
                    "rather than a raw number.")
    return None


def _producer_index(model: APISemanticModel) -> Dict[str, List[str]]:
    """``handle_type -> [api names that produce it]``, from the model's use-def
    ``produces`` sets. Lets T5 name the actual creator for a required handle."""
    idx: Dict[str, List[str]] = {}
    if model is None:
        return idx
    for name, sem in model.apis.items():
        for h in getattr(sem, "produces", ()) or ():
            idx.setdefault(h, []).append(name)
    return idx


def _handle_provenance(sem, name, produced_so_far, prod_idx) -> List[str]:
    """T5: for each handle this API REQUIRES but that isn't produced earlier in
    the sequence (and isn't its own caller-alloc), say which producer to call —
    or, the load-bearing case, that NO producer exists (opaque / direct-entry
    handle) so the binding layer would give up. That tells the LLM to construct
    or NULL it instead of waiting for a creator that never comes (B4 #3)."""
    self_prod = set(getattr(sem, "produces", ()) or ())
    needed = set(getattr(sem, "requires", ()) or ()) - self_prod - produced_so_far
    notes: List[str] = []
    for h in sorted(needed):
        producers = [p for p in prod_idx.get(h, []) if p != name]
        if producers:
            notes.append(f"needs handle {h}: produced by {', '.join(producers[:3])} "
                         f"— ensure one is called earlier in the driver")
        else:
            notes.append(f"needs handle {h}: NO project API produces it "
                         f"(opaque / direct-entry) — construct a zeroed/minimal "
                         f"instance or pass NULL if the API tolerates it; do NOT "
                         f"leave it uninitialized")
    return notes


def value_intents_for_sequence(
    model: APISemanticModel,
    api_sequence: Sequence[str],
    vocab=None,
) -> List[Dict[str, Any]]:
    """Per-API, per-arg value intents for a skeleton's sequence.

    Returns a list of ``{api, role, args: [...], handle_provenance: [...]}``
    records; APIs absent from the model or with nothing to say are dropped, so
    the result is the minimal set the Prototyper needs to render.
    """
    prod_idx = _producer_index(model)
    produced_so_far: set = set()
    out: List[Dict[str, Any]] = []
    for name in api_sequence:
        sem = model.get(name) if model else None
        if sem is None:
            continue
        arg_records: List[Dict[str, Any]] = []
        for arg in sem.args:
            intent = _arg_intent(arg, name, vocab)
            if intent is None:
                continue
            arg_records.append({
                "index": arg.index,
                "role": arg.role.value,
                "type": arg.type_str,
                "pairs_with": arg.pairs_with,
                "intent": intent,
            })
        prov = _handle_provenance(sem, name, produced_so_far, prod_idx)
        produced_so_far |= set(getattr(sem, "produces", ()) or ())
        if arg_records or prov:
            rec: Dict[str, Any] = {
                "api": name,
                "role": sem.role.value,
                "args": arg_records,
            }
            if prov:
                rec["handle_provenance"] = prov
            out.append(rec)
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
        for p in rec.get("handle_provenance", []):
            lines.append(f"    ⚙ {p}")
    return "\n".join(lines)


def annotate_skeletons(
    skeleton_drivers: Sequence[Dict[str, Any]],
    model: APISemanticModel,
    vocab=None,
) -> int:
    """Attach a ``value_intents`` block to each skeleton in place.

    Returns the number of skeletons that received at least one intent. Safe
    on missing/empty inputs (returns 0). ``vocab`` is the optional T2
    named-constant vocabulary used to give enum CONFIG args their legal set.
    """
    if not skeleton_drivers or model is None:
        return 0
    n = 0
    for sk in skeleton_drivers:
        seq = sk.get("api_sequence") or []
        intents = value_intents_for_sequence(model, seq, vocab)
        sk["value_intents"] = intents
        if intents:
            n += 1
    return n
