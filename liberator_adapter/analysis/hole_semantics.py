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

import os
import re
from typing import Any, Dict, List, Optional, Sequence


def _hard_nullguard() -> bool:
    """Escalate the advisory NULL/return contracts + opaque-handle provenance
    into MANDATORY guidance (driver-quality / low-FP).

    Always on: density is default-on, and the ablation (2026-06-07) showed
    density ALONE is harmful (lcms density-only = 0 branches, drivers SEGV;
    combo = 206) — density must never run without the guard. The
    LOGICFUZZ_HARD_NULLGUARD / LOGICFUZZ_DENSE_CONSTRUCT gates were removed."""
    return True

from liberator_adapter.analysis.api_semantic_model import (
    ArgRole,
    APISemanticModel,
)
from liberator_adapter.analysis.named_constants import (
    enum_members_for_type,
    render_constant_vocabulary,
)

_INT_TYPES = ("int", "size_t", "uint", "long", "short", "unsigned",
              "int8", "int16", "int32", "int64", "char")


def _is_scalar_int(type_str: str) -> bool:
    low = (type_str or "").lower()
    if "*" in low or "[" in low:
        return False
    return any(t in low for t in _INT_TYPES)


_FLOAT_TYPES = ("float", "double", "real")


def _is_scalar_float(type_str: str) -> bool:
    low = (type_str or "").lower()
    if "*" in low or "[" in low:
        return False
    return any(t in low for t in _FLOAT_TYPES)


def _fuzzable_holes() -> bool:
    """Tier 1 (opt-in `LOGICFUZZ_FUZZABLE_HOLES`): render fuzzable scalar/enum/
    flag CONFIG holes as 'DERIVE from the fuzz input' directives instead of
    'pick a constant'.

    The depth gap vs PromeFuzz is that we FREEZE the API's tunable parameters
    (gamma=1.0, curve type=1) — a constant arg means the fuzzer's bytes never
    vary that field, so its branches stay unreached. Confirmed: deriving
    cmsBuildParametricToneCurve's type+params from the input took cmsgamma.c
    84→121 branches (+44%) at equal budget. The symbolic layer knows precisely
    which args are tunable DOFs (CONFIG enum/scalar) vs validity-required
    (handles, magic, length) — so it exposes ONLY the DOFs, avoiding the
    fuzz-everything failure (NULL handles / broken magic) a blind LLM hits."""
    # NB: explicit truthy parse — `bool(os.environ.get(...))` treats "0"/"false"
    # as True (any non-empty string), so FUZZABLE_HOLES=0 would ENABLE the
    # feature. 2026-06 review.
    return os.environ.get("LOGICFUZZ_FUZZABLE_HOLES", "").strip().lower() in (
        "1", "true", "yes", "on")


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
        if _fuzzable_holes() and (members or _is_scalar_int(arg.type_str)
                                  or _is_scalar_float(arg.type_str)):
            # Tier 1: a tunable degree-of-freedom, not a validity-fixed value →
            # DERIVE from the fuzz input so the fuzzer sweeps it (not one const).
            # Language-AGNOSTIC: state WHAT (derive, don't hardcode) + the domain;
            # the HOW (C: index data[N]; C++: FuzzedDataProvider) is the harness
            # language's job, supplied by the language-split user prompt — never
            # name FuzzedDataProvider here (it's C++-only; a C driver can't use it).
            if members:
                shown = ", ".join(members[:12])
                more = "" if len(members) <= 12 else f" (+{len(members)-12} in <library_constants>)"
                return (f"FUZZ_DERIVE: do NOT hardcode one value — pick from the "
                        f"LEGAL set {{{shown}}}{more} by indexing a fuzz-input byte "
                        f"into it, so the fuzzer sweeps ALL enum values and reaches "
                        f"each branch.")
            kind = "float" if _is_scalar_float(arg.type_str) else "integral"
            nm = (getattr(arg, "name", "") or "").strip()
            named = f" (parameter '{nm}')" if nm else ""
            # Tier-1 value-domain judgement (the PromeFuzz-style lever): a leaf
            # "derive from data[N]" with NO domain makes the LLM pick arbitrary
            # ranges (chromaticity got data%65536 — out of [0,1] → API rejects →
            # shallow). Invoke the LLM's OWN semantic knowledge of the param's
            # MEANING to choose the VALID range first, THEN derive within it. Same
            # mechanism the enum branch above already proves (give the domain →
            # filled correctly); for scalars the domain is the LLM's knowledge.
            return (f"FUZZ_DERIVE: do NOT hardcode a constant, and do NOT slap an "
                    f"arbitrary modulus on a byte (e.g. `data[i] % 65536`). FIRST "
                    f"decide the range that is SEMANTICALLY VALID for this {kind} "
                    f"parameter{named} of `{api_name}` — reason from what you know "
                    f"about this library and the API's meaning (e.g. a chromaticity "
                    f"/ probability ≈ 0.0..1.0; a gamma ≈ 0.1..5.0; a temperature ≈ "
                    f"1000..25000; a count / index is small; a size is bounded by "
                    f"the input length). THEN derive a value WITHIN that valid range "
                    f"from the fuzz input, so the fuzzer sweeps real + boundary "
                    f"values the API ACCEPTS — not mostly-rejected garbage that "
                    f"bounces off the entry check before reaching deep code.")
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
    hard = _hard_nullguard()
    notes: List[str] = []
    for h in sorted(needed):
        producers = [p for p in prod_idx.get(h, []) if p != name]
        if producers:
            if hard:
                # Factory-chain directive: build the opaque handle for real
                # (PromeFuzz reaches deep APIs this way) — never NULL/garbage it.
                notes.append(f"needs handle {h}: BUILD IT — call {producers[0]}(...) "
                             f"(and any prerequisite it needs) earlier, NULL-check "
                             f"its result, then pass it here. Do NOT pass NULL or an "
                             f"uninitialized value for this handle.")
            else:
                notes.append(f"needs handle {h}: produced by {', '.join(producers[:3])} "
                             f"— ensure one is called earlier in the driver")
        else:
            notes.append(f"needs handle {h}: NO project API produces it "
                         f"(opaque / direct-entry) — construct a zeroed/minimal "
                         f"instance or pass NULL if the API tolerates it; do NOT "
                         f"leave it uninitialized")
    return notes


def _ret_contract_note(name, ret_contracts) -> Optional[str]:
    """T3/T6②: a per-API return-contract note so the driver guards the return.
    Prevents the unchecked-creator-return SEGV that poisons the merged harness."""
    c = (ret_contracts or {}).get(name)
    if not c:
        return None
    hard = _hard_nullguard()
    if c.get("may_return_null"):
        if hard:
            return ("MUST-GUARD: this return MAY be NULL — assign it to a named "
                    "local and `if (!x) return 0;` BEFORE using/freeing/passing "
                    "it. Skipping this guard is a driver bug (SEGV / false positive).")
        return ("⚠ returns NULL on failure → NULL-check this return before "
                "binding/using it")
    if c.get("error_sentinel"):
        if hard:
            return (f"MUST-CHECK: return is an error/status ({c['error_sentinel']}) "
                    f"— branch on it before using the object.")
        return (f"⚠ return is an error/status value ({c['error_sentinel']}) "
                f"→ check it before relying on success")
    return None


def value_intents_for_sequence(
    model: APISemanticModel,
    api_sequence: Sequence[str],
    vocab=None,
    svf_index=None,
    ret_contracts=None,
) -> List[Dict[str, Any]]:
    """Per-API, per-arg value intents for a skeleton's sequence.

    Returns a list of ``{api, role, args: [...], handle_provenance: [...],
    ret_contract: str}`` records; APIs absent from the model or with nothing to
    say are dropped. ``svf_index`` (T1) carries per-param ``set_by``;
    ``ret_contracts`` (T3) carries per-API return NULL/error contracts.
    """
    prod_idx = _producer_index(model)
    produced_so_far: set = set()
    out: List[Dict[str, Any]] = []
    for name in api_sequence:
        sem = model.get(name) if model else None
        if sem is None:
            continue
        api_svf = (svf_index or {}).get(name, {})
        arg_records: List[Dict[str, Any]] = []
        for arg in sem.args:
            intent = _arg_intent(arg, name, vocab)
            set_by = (api_svf.get(arg.index) or {}).get("set_by")
            if intent is None and not set_by:
                continue
            rec_a: Dict[str, Any] = {
                "index": arg.index,
                "role": arg.role.value,
                "type": arg.type_str,
                "pairs_with": arg.pairs_with,
                "intent": intent or "",
            }
            if set_by:
                rec_a["populated_from"] = set_by
            arg_records.append(rec_a)
        prov = _handle_provenance(sem, name, produced_so_far, prod_idx)
        produced_so_far |= set(getattr(sem, "produces", ()) or ())
        ret_note = _ret_contract_note(name, ret_contracts)
        if arg_records or prov or ret_note:
            rec: Dict[str, Any] = {
                "api": name,
                "role": sem.role.value,
                "args": arg_records,
            }
            if prov:
                rec["handle_provenance"] = prov
            if ret_note:
                rec["ret_contract"] = ret_note
            out.append(rec)
    return out


_FUZZABLE_HEADER = (
    "FUZZABLE-HOLE MODE: DERIVE every arg tagged [FUZZ] / FUZZ_DERIVE below from "
    "the fuzz input — never hardcode those — using the harness's input-access "
    "mechanism (C harness: index data[N]; C++ harness: FuzzedDataProvider). Keep "
    "constants ONLY for validity-required values (handles must be real produced "
    "handles; magic/length bytes must stay valid). This is NOT 'fancy input "
    "generation' — it is one byte wired to a tunable parameter so the fuzzer can "
    "reach that parameter's branches; keep calling many APIs as usual.")


def render_value_intents(intents: Sequence[Dict[str, Any]]) -> str:
    """Render value intents as a compact prompt block for the Prototyper."""
    if not intents:
        return ""
    lines = ["Value intent for hole filling (derive values to match these):"]
    if _fuzzable_holes():
        lines.append(_FUZZABLE_HEADER)
    for rec in intents:
        lines.append(f"- {rec['api']} [{rec['role']}]:")
        for a in rec["args"]:
            parts = []
            if a.get("intent"):
                parts.append(a["intent"])
            if a.get("populated_from"):
                srcs = ", ".join(f"arg{i}" for i in a["populated_from"])
                parts.append(f"POPULATED_FROM {srcs}: the API writes this arg "
                             f"using those args — set them to meaningful "
                             f"(non-empty / valid) values so the write is non-trivial.")
            if parts:
                lines.append(f"    arg{a['index']} ({a['type']}): {' | '.join(parts)}")
        if rec.get("ret_contract"):
            lines.append(f"    {rec['ret_contract']}")
        for p in rec.get("handle_provenance", []):
            lines.append(f"    ⚙ {p}")
    return "\n".join(lines)


_KIND_BY_ROLE = {
    "INPUT_BUFFER": "INPUT",
    "LENGTH": "LENGTH",
    "OUTPUT": "OUTPUT",
    "HANDLE_IN": "HANDLE",
    "NULLABLE_HANDLE": "HANDLE?",
}


_INTENT_LABEL_RE = re.compile(r"^[A-Z][A-Z_]*(\s*\([^)]*\))?:\s*")


def _kind_tag(arg_rec: Dict[str, Any]) -> str:
    """The CALLSPEC ``kind`` tag for an arg (light-split of value_intent —
    a scannable tag; the detail stays in the intent payload)."""
    role = arg_rec.get("role", "")
    if role == "CONFIG":
        it = arg_rec.get("intent") or ""
        if it.startswith("FUZZ_DERIVE"):
            return "FUZZ"          # Tier 1: derive from input, don't hardcode
        return "ENUM" if it.startswith("ENUM") else "RANGE"
    return _KIND_BY_ROLE.get(role, role or "?")


def _compact_intent(intent: str) -> str:
    """Drop the leading ``LABEL:`` / ``LABEL (..):`` from an intent — the
    CALLSPEC ``[kind]`` tag already carries the category, so the prose label
    is redundant (HANDLE twice, OUTPUT twice, …)."""
    return _INTENT_LABEL_RE.sub("", intent or "").strip()


def render_callspec(intents: Sequence[Dict[str, Any]],
                    signatures: Optional[Dict[str, str]] = None) -> str:
    """T4: render the per-call CALLSPEC table from the value-intent records.

    One block per call (in order): api + role + return contract + signature,
    then one line per intent-bearing arg `(i, type) [kind] payload`, then the
    handle-provenance (needs/produces). Consolidates what was previously
    scattered across api_understanding / sequence_signatures / project_apis /
    dep_graph / value_intents into a single typed view. Additive; the live
    prompt wiring (and the block cuts) are gated separately.
    """
    if not intents:
        return ""
    signatures = signatures or {}
    lines = ["CALLSPEC — fill each hole so these hold (calls run in this order):"]
    if _fuzzable_holes():
        lines.append(_FUZZABLE_HEADER)
    for i, rec in enumerate(intents, 1):
        api = rec["api"]
        head = f"#{i} {api} [{rec['role']}]"
        lines.append(head)
        if signatures.get(api):
            lines.append(f"    sig: {signatures[api]}")
        if rec.get("ret_contract"):
            lines.append(f"    {rec['ret_contract']}")
        for a in rec.get("args", []):
            seg = f"    arg{a['index']} ({a['type']}) [{_kind_tag(a)}]"
            payload = []
            if a.get("intent"):
                payload.append(_compact_intent(a["intent"]))
            if a.get("pairs_with") is not None:
                payload.append(f"len↔arg{a['pairs_with']}")
            if a.get("populated_from"):
                payload.append("data from arg" + ",arg".join(str(x) for x in a["populated_from"]))
            if payload:
                seg += " — " + " | ".join(payload)
            lines.append(seg)
        for p in rec.get("handle_provenance", []):
            lines.append(f"    ⚙ {p}")
    return "\n".join(lines)


def annotate_skeletons(
    skeleton_drivers: Sequence[Dict[str, Any]],
    model: APISemanticModel,
    vocab=None,
    svf_index=None,
    ret_contracts=None,
) -> int:
    """Attach a ``value_intents`` block to each skeleton in place.

    Returns the number of skeletons that received at least one intent. Safe
    on missing/empty inputs (returns 0). ``vocab`` = T2 named-constant
    vocabulary; ``svf_index`` = T1 ``set_by`` map; ``ret_contracts`` = T3
    per-API return NULL/error contracts.
    """
    if not skeleton_drivers or model is None:
        return 0
    # Render the named-constant vocabulary ONCE; attach to each annotated
    # skeleton so the Prototyper can inject the <library_constants> block the
    # per-arg ENUM/CONFIG intents reference (T2 payoff — previously the block
    # was computed but never rendered into any prompt).
    vocab_block = render_constant_vocabulary(vocab) if vocab else ""
    n = 0
    for sk in skeleton_drivers:
        seq = sk.get("api_sequence") or []
        intents = value_intents_for_sequence(model, seq, vocab, svf_index, ret_contracts)
        sk["value_intents"] = intents
        if intents:
            n += 1
            if vocab_block:
                sk["library_constants"] = vocab_block
    return n
