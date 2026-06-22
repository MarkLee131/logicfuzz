"""APISemanticModel — the single reconciled per-API record (redesign G1).

The generation pipeline (``docs/generation.md``) traces every former
downstream band-aid (Phase A repair, F1–F4, L5 reranks) to one inversion:
roles/arg-semantics were derived from a *single* source (LLVM-IR mod/ref) and
corrected later. This module inverts that: it fuses the three evidence sources
up front into one auditable model.

Reconciliation principle (G1) — each source is authoritative only
for what it can witness:

    | question                         | authority          | supporting |
    |----------------------------------|--------------------|------------|
    | role / intent (creates? frees?)  | doc @brief + name  | IR (tiebreak)
    | memory mechanism (alloc/free)    | IR mod/ref         | —
    | arg = buffer / length / output   | doc @param + type  | IR out-ptr
    | composition (A→B)                | usage (automaton)  | type match

When IR and doc disagree on *role*, **doc wins for role, IR wins for
mechanism** — and the conflict is recorded in ``APISemantics.evidence`` so the
verdict is falsifiable. This single rule dissolves P-gen-1/4/6.

Canonical example (the G1 ship test): ``cmsFreeToneCurveTriple(cmsToneCurve*
Curve[3])`` is a ``cmsToneCurve **`` non-const out-pointer, which IR's
``extract_produced_handles`` reads as *produces a cmsToneCurve* → CREATOR. The
``cmsFree`` name says DESTROYER. The reconciler picks DESTROYER and logs the
IR loser.

Token budget (redesign G1 invariant): this module is **deterministic-only**.
Naming + type-patterns + structured doxygen need no LLM. The batched-LLM
residual is an optional hook (``llm_tiebreak``) that defaults off; with it off
the model adds 0 LLM calls and is cached at
``results/{project}/state/api_semantic_model.json`` for 0-token re-runs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from liberator_adapter.analysis.usedef import (
    extract_api_effects,
    is_handle_type,
    normalize_handle_type,
    _count_pointer_levels,
    _find_buffer_size_positions,
    _get_is_const,
    _is_init_named,
    _strip_one_pointer_level,
)


# =============================================================================
# Vocabulary
# =============================================================================

class APIRole(Enum):
    """What the API *does* to project resources (intent, not mechanism)."""
    CREATOR = "CREATOR"        # produces a fresh handle / resource
    MUTATOR = "MUTATOR"        # takes a handle and configures / advances it
    CONSUMER = "CONSUMER"      # reads a handle, produces no new resource
    DESTROYER = "DESTROYER"    # frees / releases a handle
    UNKNOWN = "UNKNOWN"


class ArgRole(Enum):
    """Per-argument semantic role (redesign §2.1)."""
    INPUT_BUFFER = "INPUT_BUFFER"        # raw bytes the fuzzer should drive
    LENGTH = "LENGTH"                    # length paired with an INPUT_BUFFER
    OUTPUT = "OUTPUT"                    # out-pointer the API writes through
    NULLABLE_HANDLE = "NULLABLE_HANDLE"  # handle that may be NULL
    HANDLE_IN = "HANDLE_IN"              # required upstream handle
    CONFIG = "CONFIG"                    # scalar / enum knob
    UNKNOWN = "UNKNOWN"


class EvidenceSource(Enum):
    """Where a piece of evidence came from — drives the authority ordering."""
    DOC = "DOC"          # doxygen @brief / @param / @return
    NAMING = "NAMING"    # function-name verb stem (_create / _free / ...)
    IR = "IR"            # LLVM-IR mod/ref + use-def
    USAGE = "USAGE"      # automaton accepting paths (composition)
    LLM = "LLM"          # batched LLM role classification (semantic judgement)


# A deterministic role this confident (or higher) is trusted as-is; only
# below it does the LLM classification override. Keeps the symbolic verdict
# authoritative where the rules are sure (per "program-analysis where certain,
# LLM where uncertain"); the LLM repairs the noisy residual (mis-roled
# CONSUMER/CREATOR siblings, signatures the IR/naming can't disambiguate).
_LLM_OVERRIDE_BELOW = 0.7


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True)
class Evidence:
    """One witnessed claim about an API, kept for auditability.

    ``won`` marks whether this claim was the reconciled verdict for ``field``;
    losers are retained so a wrong verdict is debuggable from the artifact
    alone (no re-running of the analysis).
    """
    source: str        # EvidenceSource value
    field: str         # which field this speaks to: "role" | "arg{i}" | ...
    value: str         # the claimed value (role / arg-role name)
    confidence: float
    won: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "field": self.field, "value": self.value,
            "confidence": round(self.confidence, 3), "won": self.won,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(
            source=d["source"], field=d["field"], value=d["value"],
            confidence=float(d.get("confidence", 0.0)),
            won=bool(d.get("won", False)), note=d.get("note", ""),
        )


@dataclass(frozen=True)
class ArgSemantics:
    index: int
    role: ArgRole
    type_str: str = ""
    nullable: bool = False
    pairs_with: Optional[int] = None   # LENGTH ↔ buffer index
    doc_text: Optional[str] = None     # L6b: @param free-text description

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "index": self.index, "role": self.role.value,
            "type_str": self.type_str, "nullable": self.nullable,
            "pairs_with": self.pairs_with,
        }
        if self.doc_text:
            d["doc_text"] = self.doc_text
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ArgSemantics":
        return cls(
            index=int(d["index"]), role=ArgRole(d.get("role", "UNKNOWN")),
            type_str=d.get("type_str", ""), nullable=bool(d.get("nullable", False)),
            pairs_with=d.get("pairs_with"),
            doc_text=d.get("doc_text") or None,
        )


@dataclass(frozen=True)
class APISemantics:
    name: str
    role: APIRole
    role_confidence: float
    args: Tuple[ArgSemantics, ...] = ()
    produces: FrozenSet[str] = frozenset()   # handle types this creates
    requires: FrozenSet[str] = frozenset()   # handle types needed before call
    destroys: FrozenSet[str] = frozenset()   # handle types this frees
    evidence: Tuple[Evidence, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role.value,
            "role_confidence": round(self.role_confidence, 3),
            "args": [a.to_dict() for a in self.args],
            "produces": sorted(self.produces),
            "requires": sorted(self.requires),
            "destroys": sorted(self.destroys),
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "APISemantics":
        return cls(
            name=d["name"],
            role=APIRole(d.get("role", "UNKNOWN")),
            role_confidence=float(d.get("role_confidence", 0.0)),
            args=tuple(ArgSemantics.from_dict(a) for a in d.get("args", [])),
            produces=frozenset(d.get("produces", [])),
            requires=frozenset(d.get("requires", [])),
            destroys=frozenset(d.get("destroys", [])),
            evidence=tuple(Evidence.from_dict(e) for e in d.get("evidence", [])),
        )


@dataclass(frozen=True)
class APISemanticModel:
    """The reconciled model — one ``APISemantics`` per public API."""
    project: str
    apis: Dict[str, APISemantics] = field(default_factory=dict)
    # Project HANDLE-type set (normalized) — the per-facet TYPE authority for
    # "what is a handle", computed once by the IR layer (freed ∪ created-and-
    # consumed). Threaded into the Typestate self-filter so value-structs are not
    # tracked as lifecycle handles. Empty when unknown (no filtering).
    handle_types: FrozenSet[str] = field(default_factory=frozenset)

    def get(self, name: str) -> Optional[APISemantics]:
        return self.apis.get(name)

    def role_of(self, name: str) -> Optional[APIRole]:
        sem = self.apis.get(name)
        return sem.role if sem else None

    def creators(self) -> List[str]:
        return [n for n, s in self.apis.items() if s.role is APIRole.CREATOR]

    def destroyers(self) -> List[str]:
        return [n for n, s in self.apis.items() if s.role is APIRole.DESTROYER]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project": self.project,
            "apis": {n: s.to_dict() for n, s in sorted(self.apis.items())},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "APISemanticModel":
        return cls(
            project=d.get("project", ""),
            apis={
                n: APISemantics.from_dict(s)
                for n, s in (d.get("apis") or {}).items()
            },
        )

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=False)

    @classmethod
    def load(cls, path: Path) -> Optional["APISemanticModel"]:
        path = Path(path)
        if not path.is_file():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except Exception:
            return None


# =============================================================================
# Naming verb stems (the doc/intent bucket that needs no doxygen)
# =============================================================================
#
# Strong stems override IR on role (the redesign's "doc wins for role"); weak
# stems only fill in when IR is silent, because they're ambiguous (a ``parse``
# may create OR consume, ``open`` may or may not return a handle).

_DESTROYER_STRONG: Tuple[str, ...] = (
    "free", "destroy", "delete", "release", "dealloc", "dispose",
    "unref", "deinit", "deinitialize", "uninit", "fini", "finalize",
)
_CREATOR_STRONG: Tuple[str, ...] = (
    "create", "alloc", "_new", "new_", "make",
)
_DESTROYER_WEAK: Tuple[str, ...] = ("close", "cleanup", "clear", "reset")
_CREATOR_WEAK: Tuple[str, ...] = (
    "init", "open", "build", "load", "dup", "clone", "setup", "parse",
)


def _naming_role(name: str) -> Optional[Tuple[APIRole, float, str]]:
    """Role inferred from the function-name verb stem.

    Returns ``(role, confidence, strength)`` where ``strength`` is
    ``"strong"`` (may override IR) or ``"weak"`` (only fills IR silence), or
    ``None`` when no verb stem matches. Destroyer stems are tested first so
    ``deinit`` (contains ``init``) resolves to DESTROYER, not CREATOR.
    """
    low = (name or "").lower()
    if not low:
        return None
    for stem in _DESTROYER_STRONG:
        if stem in low:
            return APIRole.DESTROYER, 0.9, "strong"
    for stem in _CREATOR_STRONG:
        if stem in low:
            return APIRole.CREATOR, 0.85, "strong"
    for stem in _DESTROYER_WEAK:
        if stem in low:
            return APIRole.DESTROYER, 0.6, "weak"
    for stem in _CREATOR_WEAK:
        if stem in low:
            return APIRole.CREATOR, 0.6, "weak"
    return None


# Map a doxygen @brief leading verb to a role. Keyed on lowercase stems found
# at/near the start of the brief description.
_BRIEF_CREATOR_VERBS = (
    "create", "allocate", "alloc", "return a new", "returns a new",
    "construct", "make", "build", "initialize", "initialise", "open", "load",
)
_BRIEF_DESTROYER_VERBS = (
    "free", "frees", "destroy", "destroys", "release", "releases",
    "delete", "deletes", "deallocate", "dispose", "close", "finalize",
)


def _brief_role(brief: str) -> Optional[Tuple[APIRole, float]]:
    if not brief:
        return None
    low = brief.strip().lower()
    head = low[:60]   # the verb is in the lead clause
    for v in _BRIEF_DESTROYER_VERBS:
        if v in head:
            return APIRole.DESTROYER, 0.95
    for v in _BRIEF_CREATOR_VERBS:
        if v in head:
            return APIRole.CREATOR, 0.95
    return None


# =============================================================================
# Evidence collectors (all deterministic)
# =============================================================================

@dataclass
class _IREvidence:
    role: Optional[APIRole]
    role_conf: float
    produces: FrozenSet[str]
    requires: FrozenSet[str]
    kills: FrozenSet[str]
    arg_roles: Dict[int, ArgRole]


def _classify_ir_role(
    produces_h: FrozenSet[str],
    requires_h: FrozenSet[str],
    kills: FrozenSet[str],
    in_sinks: bool,
    in_sources: bool,
    in_inits: bool,
) -> Tuple[Optional[APIRole], float]:
    """Tentative IR role from HANDLE-flow facets (per-facet authority).

    ``produces_h``/``requires_h`` are already filtered to HANDLE types by the
    caller — TYPE owns handle-ness. This is the fix for the conflict where SVF /
    ConditionManager say "creator/mutator" because the API writes through a
    pointer, but the written thing is a non-handle out-buffer (``png_read_image``
    writes ``png_byte*``; ``png_get_sPLT`` writes ``png_splt_t*``): producing a
    non-handle is NOT handle creation, so the ConditionManager ``source``/``init``
    promotion to CREATOR fires ONLY when a real handle is produced (the type veto).
    SVF still owns "is it written/freed" (it set ``produces``/``kills``); naming/
    doc still break ties downstream in the reconciler."""
    if in_sinks or kills:
        return APIRole.DESTROYER, 0.75
    # CREATOR iff it produces a NEW handle — one it does not also require as input
    # (png_create_info_struct produces png_info while requiring png_struct; a
    # source/init that produces a handle also counts). An API that only writes a
    # handle it also requires is an in-place MUTATOR, not a creator.
    new_handles = produces_h - requires_h
    if new_handles or (produces_h and (in_sources or in_inits)):
        return APIRole.CREATOR, 0.7
    if produces_h and requires_h:
        return APIRole.MUTATOR, 0.6
    if requires_h and not produces_h:
        return APIRole.CONSUMER, 0.6
    return None, 0.0


def _compute_handle_types(
    project_apis: Sequence[Dict[str, Any]],
    eff_by_name: Dict[str, Any],
) -> FrozenSet[str]:
    """Project-wide HANDLE (lifecycle-object) type set — the per-facet TYPE
    authority for "is this a handle".

    ``is_handle_type`` only rejects *literal* primitives, so it wrongly accepts
    typedef scalars (``png_byte`` -> unsigned char) and POD value-structs
    (``png_splt_t``, ``png_image``) as handles. A handle is a *managed object*,
    signaled by either:
      1. some API FREES it (an effect ``kill``) — you free handles, not value
         records or scalars; this catches png_struct/png_info, cJSON, cms*,
         ares_*, gzFile; and
      2. a create/init-named API PRODUCES it AND another API CONSUMES it as a
         HANDLE_IN — a passed-between-APIs opaque object. This catches
         ``z_stream`` (deflateInit_ makes it, deflate uses it) even when its free
         is not extracted, WITHOUT re-admitting value-structs (png_splt_t is
         produced by a *get*, never consumed as a handle).
    All keys normalized via ``normalize_handle_type`` for consistent membership.
    """
    freed: set = set()
    created_named: set = set()
    handle_in: set = set()
    for api in project_apis:
        name = api.get("function_name", "")
        if not name:
            continue
        eff = eff_by_name.get(name)
        if eff is not None:
            freed |= {normalize_handle_type(t) for t in eff.kill}
            nr = _naming_role(name)
            if nr is not None and nr[0] is APIRole.CREATOR:
                created_named |= {normalize_handle_type(t) for t in eff.def_}
        args = api.get("arguments", api.get("arguments_info", [])) or []
        for i, r in _ir_arg_roles(api).items():
            if r is ArgRole.HANDLE_IN and i < len(args):
                t = args[i].get("type", args[i].get("type_clang", "")) or ""
                handle_in.add(normalize_handle_type(t))
    return frozenset(freed | (created_named & handle_in))


def collect_ir_evidence(
    project_apis: Sequence[Dict[str, Any]],
    condition_info: Optional[Dict[str, Any]] = None,
    lifecycle_pairs: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[Dict[str, _IREvidence], FrozenSet[str]]:
    """Per-API mechanism evidence from use-def + ConditionManager summary.

    Mechanism (produces/requires/kills handle types) comes straight from the
    shared ``extract_api_effects`` walker. A *tentative* IR role is derived as
    a tiebreak source only; the reconciler lets doc/naming override it.
    """
    condition_info = condition_info or {}
    sources = set(condition_info.get("sources") or [])
    sinks = set(condition_info.get("sinks") or [])
    inits = set(condition_info.get("inits") or [])

    effects = extract_api_effects(
        list(project_apis), lifecycle_pairs=lifecycle_pairs or None
    )
    eff_by_name = {e.name: e for e in effects}
    handle_types = _compute_handle_types(project_apis, eff_by_name)

    out: Dict[str, _IREvidence] = {}
    for api in project_apis:
        name = api.get("function_name", "")
        if not name:
            continue
        eff = eff_by_name.get(name)
        produces = frozenset(eff.def_) if eff else frozenset()
        requires = frozenset(eff.use) if eff else frozenset()
        kills = frozenset(eff.kill) if eff else frozenset()

        # Tentative IR role (tiebreak authority only). Per-facet authority:
        #  • produces_h (STRICT) — only types in the project HANDLE set count as
        #    handle production, so a non-handle out-buffer write (png_read_image →
        #    png_byte*, png_get_sPLT → png_splt_t*) is NOT creation (type veto on
        #    the ConditionManager source/init promotion). SVF still set produces.
        #  • requires_h (LENIENT/structural) — the handle types of HANDLE_IN args
        #    (is_handle_type), NOT eff.use, so a consumer of a handle is still a
        #    CONSUMER even when that handle's create/free isn't in the API set, and
        #    OUTPUT/init args (deflateInit_'s z_stream) are excluded from requires.
        arg_roles = _ir_arg_roles(api)
        _args = api.get("arguments", api.get("arguments_info", [])) or []

        def _atype(i: int) -> str:
            return (_args[i].get("type", _args[i].get("type_clang", "")) or ""
                    if i < len(_args) else "")

        produces_h = frozenset(
            normalize_handle_type(t) for t in produces
            if normalize_handle_type(t) in handle_types)
        requires_h = frozenset(
            normalize_handle_type(_atype(i)) for i, r in arg_roles.items()
            if r is ArgRole.HANDLE_IN and is_handle_type(_atype(i)))
        role, conf = _classify_ir_role(
            produces_h, requires_h, kills,
            name in sinks, name in sources, name in inits)

        out[name] = _IREvidence(
            role=role, role_conf=conf, produces=produces,
            requires=requires, kills=kills,
            arg_roles=arg_roles,
        )
    return out, handle_types


def _ir_arg_roles(api: Dict[str, Any]) -> Dict[int, ArgRole]:
    """Arg roles derivable from type-structure alone (no doc)."""
    args = api.get("arguments", api.get("arguments_info", [])) or []
    roles: Dict[int, ArgRole] = {}
    buf_idx, size_idx = _find_buffer_size_positions(args)
    name_lower = (api.get("function_name", "") or "").lower()
    init_named = _is_init_named(name_lower)
    for i, arg in enumerate(args):
        atype = arg.get("type", arg.get("type_clang", "")) or ""
        if i == buf_idx:
            roles[i] = ArgRole.INPUT_BUFFER
            continue
        if i == size_idx:
            roles[i] = ArgRole.LENGTH
            continue
        levels = _count_pointer_levels(atype)
        if levels >= 2 and not _get_is_const(arg):
            inner = _strip_one_pointer_level(atype)
            if inner and is_handle_type(inner):
                roles[i] = ArgRole.OUTPUT
                continue
        # Caller-allocated-struct init: ``deflateInit_(z_stream*)`` writes/sets
        # up a struct the caller declares. Single-pointer (not the ``T**``
        # out-pointer above), init-named, and not SVF-proven read-only — same
        # gate as the INIT producer channel in usedef. Mark OUTPUT so the hole
        # renderer declares + initializes it rather than seeking a live handle.
        if (levels == 1 and not _get_is_const(arg) and is_handle_type(atype)
                and init_named and arg.get("_svf_writes") is not False):
            roles[i] = ArgRole.OUTPUT
            continue
        if is_handle_type(atype) and levels >= 1:
            roles[i] = ArgRole.HANDLE_IN
            continue
        roles[i] = ArgRole.CONFIG
    return roles


@dataclass
class _DocEvidence:
    role: Optional[APIRole]
    role_conf: float
    role_source: Optional[str]   # EvidenceSource.DOC | NAMING value, or None
    role_strong: bool            # may override IR (strong) vs fill-only (weak)
    arg_roles: Dict[int, ArgRole]
    arg_texts: Dict[int, str] = field(default_factory=dict)  # L6b: @param text


def collect_doc_evidence(
    project_apis: Sequence[Dict[str, Any]],
    doc_signals: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, _DocEvidence]:
    """Per-API intent evidence from structured doxygen + the naming verb.

    ``doc_signals`` is the structured output of
    ``src.knowledge.project_docs.extract_doc_signals`` (``{name: {"brief":..,
    "params": [{"index","role"}], ...}}``). Absent doxygen (the lcms case) is
    fine: the naming verb still carries the role.
    """
    doc_signals = doc_signals or {}
    out: Dict[str, _DocEvidence] = {}
    for api in project_apis:
        name = api.get("function_name", "")
        if not name:
            continue
        sig = doc_signals.get(name) or {}

        # Role: prefer an explicit @brief verb (always strong), else the
        # naming stem (strong stems override IR; weak stems only fill IR
        # silence). Provenance is recorded so the conflict log names the real
        # source (DOC vs NAMING), not whichever confidence tier it landed in.
        role: Optional[APIRole] = None
        conf = 0.0
        role_source: Optional[str] = None
        role_strong = False
        brief_role = _brief_role(sig.get("brief", ""))
        if brief_role is not None:
            role, conf = brief_role
            role_source, role_strong = EvidenceSource.DOC.value, True
        else:
            nm = _naming_role(name)
            if nm is not None:
                role, conf = nm[0], nm[1]
                role_source = EvidenceSource.NAMING.value
                role_strong = (nm[2] == "strong")

        # Arg roles parsed from @param descriptions, keyed by index.
        # L6b: also capture the free-text param description (p["text"]) so
        # hole_semantics can mine a documented value range from it.
        arg_roles: Dict[int, ArgRole] = {}
        arg_texts: Dict[int, str] = {}
        for p in (sig.get("params") or []):
            idx = p.get("index")
            r = p.get("role")
            if isinstance(idx, int):
                if r:
                    try:
                        arg_roles[idx] = ArgRole(r)
                    except ValueError:
                        pass
                t = (p.get("text") or "").strip()
                if t:
                    arg_texts[idx] = t
        out[name] = _DocEvidence(
            role=role, role_conf=conf, role_source=role_source,
            role_strong=role_strong, arg_roles=arg_roles, arg_texts=arg_texts)
    return out


def collect_usage_evidence(
    accepting_paths: Optional[Sequence[Sequence[str]]] = None,
) -> Dict[str, int]:
    """Composition support: how often an API appears as a *non-first* call.

    A purely supporting signal (redesign: usage is authoritative for
    composition, not role). We count appearances *after position 0* — the
    first call in an accepting path is the entry/creator, so following some
    predecessor is what makes the occurrence genuine composition evidence.
    Used only to bump role confidence of APIs the automaton actually
    exercises; never to set a role. Returns ``{api_name: appearance_count}``.
    """
    counts: Dict[str, int] = {}
    for path in (accepting_paths or []):
        for api in path[1:]:   # skip the entry call; count downstream steps
            if api:
                counts[api] = counts.get(api, 0) + 1
    return counts


# =============================================================================
# Reconciliation
# =============================================================================

def _reconcile_role(
    ir: Optional[_IREvidence],
    doc: Optional[_DocEvidence],
    usage_count: int,
    llm_role: Optional[APIRole] = None,
    llm_conf: float = 0.0,
) -> Tuple[APIRole, float, List[Evidence]]:
    """Apply the §2.2 rule: doc/naming win role, IR is the tiebreak.

    Records every candidate as ``Evidence`` (winner ``won=True``) so a wrong
    verdict is auditable straight from the artifact.

    ``llm_role`` (optional) is the batched-LLM classification. It is the
    highest authority but is applied *surgically*: it overrides only when the
    deterministic verdict is UNKNOWN or below ``_LLM_OVERRIDE_BELOW`` — a
    confident rule keeps its verdict (and the LLM claim is logged as a
    non-winning witness). This is the "LLM repairs the uncertain residual"
    boundary, not "LLM replaces the rules".
    """
    log: List[Evidence] = []
    ir_role = ir.role if ir else None
    ir_conf = ir.role_conf if ir else 0.0
    doc_role = doc.role if doc else None
    doc_conf = doc.role_conf if doc else 0.0
    doc_src = (doc.role_source if doc else None) or EvidenceSource.NAMING.value

    # Strength gate (redesign §2.2): a *strong* doc/naming role overrides IR;
    # a *weak* one only fills IR silence. ``role_strong`` is set by
    # ``collect_doc_evidence`` (brief verbs + strong naming stems = strong).
    doc_is_strong = bool(doc and doc.role_strong)

    if doc_role is not None and (doc_is_strong or ir_role is None):
        winner_role, winner_conf = doc_role, doc_conf
        log.append(Evidence(doc_src, "role", doc_role.value, doc_conf, won=True,
                            note="doc/naming authoritative for role"))
        if ir_role is not None:
            log.append(Evidence(EvidenceSource.IR.value, "role", ir_role.value,
                                ir_conf, won=False,
                                note="IR mechanism-derived role overruled"))
    elif ir_role is not None:
        winner_role, winner_conf = ir_role, ir_conf
        log.append(Evidence(EvidenceSource.IR.value, "role", ir_role.value,
                            ir_conf, won=True, note="no doc/naming signal"))
        if doc_role is not None:
            log.append(Evidence(doc_src, "role",
                                doc_role.value, doc_conf, won=False,
                                note="weak naming hint, IR retained"))
    else:
        winner_role, winner_conf = APIRole.UNKNOWN, 0.0

    # LLM override of the uncertain residual.
    if llm_role is not None and llm_role is not APIRole.UNKNOWN:
        if winner_role is APIRole.UNKNOWN or winner_conf < _LLM_OVERRIDE_BELOW:
            # Demote any prior role winner so the flip is auditable.
            log = [Evidence(e.source, e.field, e.value, e.confidence,
                            won=(e.won and e.field != "role"), note=e.note)
                   for e in log]
            winner_role = llm_role
            winner_conf = max(winner_conf, llm_conf, 0.75)
            log.append(Evidence(EvidenceSource.LLM.value, "role", llm_role.value,
                                winner_conf, won=True,
                                note="LLM authoritative (rule uncertain)"))
        else:
            log.append(Evidence(EvidenceSource.LLM.value, "role", llm_role.value,
                                llm_conf, won=False,
                                note="confident rule role retained over LLM"))

    if usage_count > 0 and winner_role is not APIRole.UNKNOWN:
        # Composition support nudges confidence up (capped), never flips role.
        bonus = min(0.1, 0.02 * usage_count)
        log.append(Evidence(EvidenceSource.USAGE.value, "role",
                            winner_role.value, bonus, won=False,
                            note=f"appears in {usage_count} accepting-path step(s)"))
        winner_conf = min(1.0, winner_conf + bonus)

    return winner_role, winner_conf, log


def _output_array_base(type_str: str) -> str:
    """Bare element type name (for producer-set membership), all pointer levels
    and ``const`` stripped: ``"png_color *"`` → ``"png_color"``, ``"cJSON *"`` →
    ``"cjson"``, produced ``"cjson*"`` → ``"cjson"`` — so the two sides match."""
    return type_str.replace("*", "").replace("const", "").strip().lower()


def _reconcile_args(
    api: Dict[str, Any],
    ir: Optional[_IREvidence],
    doc: Optional[_DocEvidence],
    llm_arg: Optional[Dict[int, ArgRole]] = None,
    produced_bases: Optional[FrozenSet[str]] = None,
) -> Tuple[Tuple[ArgSemantics, ...], List[Evidence]]:
    """Arg roles: doc @param > LLM > type-pattern (IR). Pair LENGTH ↔ buffer.

    The LLM arg-role wins over the IR type-pattern (which can't tell a fuzzer
    INPUT_BUFFER from any ``void*``, or a LENGTH from any size_t) but yields to
    an explicit ``@param`` description.
    """
    args = api.get("arguments", api.get("arguments_info", [])) or []
    ir_arg = ir.arg_roles if ir else {}
    doc_arg = doc.arg_roles if doc else {}
    doc_texts: Dict[int, str] = doc.arg_texts if doc else {}  # L6b
    llm_arg = llm_arg or {}
    log: List[Evidence] = []

    resolved: Dict[int, ArgRole] = {}
    for i in range(len(args)):
        if i in doc_arg:
            resolved[i] = doc_arg[i]
            log.append(Evidence(EvidenceSource.DOC.value, f"arg{i}",
                                doc_arg[i].value, 0.9, won=True,
                                note="@param description"))
            if i in ir_arg and ir_arg[i] is not doc_arg[i]:
                log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                    ir_arg[i].value, 0.6, won=False))
        elif i in llm_arg and llm_arg[i] is not ArgRole.UNKNOWN:
            resolved[i] = llm_arg[i]
            log.append(Evidence(EvidenceSource.LLM.value, f"arg{i}",
                                llm_arg[i].value, 0.8, won=True,
                                note="LLM arg classification"))
            if i in ir_arg and ir_arg[i] is not llm_arg[i]:
                log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                    ir_arg[i].value, 0.6, won=False,
                                    note="IR type-pattern overruled by LLM"))
        else:
            resolved[i] = ir_arg.get(i, ArgRole.UNKNOWN)

    # Role-precision: an arg the SVF analyzed and saw ONLY reads on cannot be
    # OUTPUT, even if the LLM said so (e.g. lcms cmsAppendNamedColor's PCS[] /
    # Colorant[] input arrays were labelled OUTPUT → wrong "fresh local, do not
    # pre-fill" hole intent). Veto OUTPUT → IR type-pattern fallback. Strict
    # ``is False`` gate: args without SVF data (None) and genuinely-written
    # out-pointers (True) are untouched.
    # Symmetric SVF role-precision pass (2026-06, Phase 1.5):
    #   * VETO    OUTPUT→fallback when SVF saw read-only access (is False).
    #   * PROMOTE a non-const pointer CONFIG→OUTPUT when SVF PROVED writes
    #     (is True) — the under-labelled caller-alloc / output-array case, the
    #     mirror of the veto. Gated to CONFIG only (NOT HANDLE_IN, which is
    #     commonly in-out) + non-const pointer, so a mutated handle isn't
    #     misclassified as a pure output.
    #   * RECORD a non-winning Evidence when SVF is ABSENT (None) on a pointer
    #     arg whose role SVF could have decided — so the audit chain honestly
    #     shows the verdict rests on type-pattern/LLM, not the strongest
    #     analysis (the "auditable Evidence" claim was silent on SVF-absent).
    # Strict identity gates: only ``is True`` / ``is False`` ever change a role.
    for i in range(len(args)):
        if not isinstance(args[i], dict):
            continue
        svf = args[i].get("_svf_writes")
        atype_i = (args[i].get("type", args[i].get("type_clang", "")) or "")
        is_ptr = "*" in atype_i
        role_i = resolved.get(i, ArgRole.UNKNOWN)
        if role_i is ArgRole.OUTPUT and svf is False:
            fallback = ir_arg.get(i, ArgRole.UNKNOWN)
            if fallback is ArgRole.OUTPUT:
                fallback = ArgRole.UNKNOWN
            resolved[i] = fallback
            log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                fallback.value, 0.7, won=True,
                                note="OUTPUT vetoed: SVF saw read-only access"))
        elif role_i is ArgRole.CONFIG and svf is True and is_ptr \
                and "const" not in atype_i:
            resolved[i] = ArgRole.OUTPUT
            log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                ArgRole.OUTPUT.value, 0.75, won=True,
                                note="OUTPUT confirmed: SVF saw writes"))
        elif role_i is ArgRole.HANDLE_IN and svf is True and is_ptr \
                and "const" not in atype_i \
                and args[i].get("_svf_is_array") is True \
                and _output_array_base(atype_i) not in (produced_bases or frozenset()):
            # A param the IR type-classed as a handle (any struct pointer) that
            # SVF proved is a WRITTEN ARRAY whose element type has NO producer in
            # the project is an OUTPUT value-array, not an in-out handle. Both
            # gates are jointly necessary: ``is_array`` excludes a single in-out
            # handle (is_array=False); "no producer" excludes a managed handle
            # that is merely array-accessed (cJSON's linked nodes, gzFile, which
            # HAVE a creator). png_color (palette) has neither — promoted.
            resolved[i] = ArgRole.OUTPUT
            log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                ArgRole.OUTPUT.value, 0.8, won=True,
                                note="OUTPUT: SVF write to a producer-less value array"))
        elif svf is None and is_ptr and role_i in (
                ArgRole.OUTPUT, ArgRole.CONFIG, ArgRole.HANDLE_IN):
            log.append(Evidence(EvidenceSource.IR.value, f"arg{i}",
                                role_i.value, 0.0, won=False,
                                note="SVF unavailable: role from type-pattern only"))

    # Pair each LENGTH with the nearest preceding INPUT_BUFFER.
    out_args: List[ArgSemantics] = []
    for i, arg in enumerate(args):
        atype = arg.get("type", arg.get("type_clang", "")) or ""
        role = resolved.get(i, ArgRole.UNKNOWN)
        pairs_with: Optional[int] = None
        if role is ArgRole.LENGTH:
            for j in range(i - 1, -1, -1):
                if resolved.get(j) is ArgRole.INPUT_BUFFER:
                    pairs_with = j
                    break
        # §3.0: nullable is EVIDENCE-BASED (IR > doc cue > role/context default),
        # not a pure role guess. doc cue from the @param text (Task 3); ir_nonnull
        # from conditions.json per-arg NON_NULL (Task 9; None until then). A
        # context-typed arg defaults nullable (global-context optional) unless
        # doc/IR override — kills the cmsContext false positive.
        from src.knowledge.project_docs import _param_nullability_from_text
        _doc_null = _param_nullability_from_text(doc_texts.get(i))
        _ir_nonnull = None  # Task 9 wires per-arg NON_NULL from conditions.json
        _role_default = (role in (ArgRole.NULLABLE_HANDLE, ArgRole.OUTPUT)
                         or "context" in atype.lower())
        nullable = _reconcile_arg_nullable(_role_default, _doc_null, _ir_nonnull)
        out_args.append(ArgSemantics(
            index=i, role=role, type_str=atype.strip(),
            nullable=nullable, pairs_with=pairs_with,
            doc_text=doc_texts.get(i) or None,  # L6b: thread @param text
        ))
    return tuple(out_args), log


def _reconcile_arg_nullable(role_default: bool, doc, ir_nonnull) -> bool:
    """Reconcile per-arg nullability by evidence priority:
    IR proof of non-null (assert/deref) > doc @param cue > role/context default.
    ``doc`` is True/False/None; ``ir_nonnull`` is True/None."""
    if ir_nonnull is True:
        return False
    if doc is not None:
        return bool(doc)
    return bool(role_default)


def _parse_llm_roles(
    llm_roles: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Tuple[Optional[APIRole], float, Dict[int, ArgRole]]]:
    """Normalise the Comprehender role payload into typed enums.

    Expected per-API shape (tolerant of missing keys):
    ``{"role": "CREATOR", "confidence": 0.9,
       "args": {0: "INPUT_BUFFER", 1: "LENGTH"}}`` (args may also be a list of
    ``{"index": i, "role": "..."}``).
    """
    out: Dict[str, Tuple[Optional[APIRole], float, Dict[int, ArgRole]]] = {}
    for name, entry in (llm_roles or {}).items():
        if not isinstance(entry, dict):
            continue
        role = None
        try:
            role = APIRole(str(entry.get("role", "")).upper())
        except ValueError:
            role = None
        conf = float(entry.get("confidence", 0.8) or 0.0)
        raw_args = entry.get("args", {})
        arg_roles: Dict[int, ArgRole] = {}
        items = (raw_args.items() if isinstance(raw_args, dict)
                 else [(a.get("index"), a.get("role")) for a in raw_args
                       if isinstance(a, dict)])
        for idx, ar in items:
            if idx is None:
                continue
            try:
                arg_roles[int(idx)] = ArgRole(str(ar).upper())
            except (ValueError, TypeError):
                continue
        out[name] = (role, conf, arg_roles)
    return out


def reconcile(
    project_apis: Sequence[Dict[str, Any]],
    *,
    project: str = "",
    condition_info: Optional[Dict[str, Any]] = None,
    lifecycle_pairs: Optional[List[Tuple[str, str]]] = None,
    doc_signals: Optional[Dict[str, Dict[str, Any]]] = None,
    accepting_paths: Optional[Sequence[Sequence[str]]] = None,
    llm_roles: Optional[Dict[str, Dict[str, Any]]] = None,
    llm_tiebreak: Optional[Any] = None,
) -> APISemanticModel:
    """Fuse IR ⊕ doc ⊕ usage ⊕ LLM into one ``APISemanticModel``.

    Deterministic by default. ``llm_roles`` (the batched Comprehender role
    classification) is folded in as the highest-authority evidence source but
    overrides only the *uncertain residual* (deterministic role UNKNOWN or
    confidence < ``_LLM_OVERRIDE_BELOW``) — confident rule verdicts stand. When
    ``llm_roles`` is None the result is exactly the prior deterministic model
    (zero LLM calls).

    ``llm_tiebreak`` is the older callable hook (model, apis)->model; retained
    for back-compat, runs after the data-driven fold.
    """
    ir_ev, _handle_types = collect_ir_evidence(
        project_apis, condition_info, lifecycle_pairs)
    doc_ev = collect_doc_evidence(project_apis, doc_signals)
    usage = collect_usage_evidence(accepting_paths)
    llm_ev = _parse_llm_roles(llm_roles)

    # Global set of element-type base names that SOME API produces (a creator's
    # return / out-pointer / init). A WRITTEN ARRAY whose element type is in this
    # set is a managed handle (cJSON, gzFile), NOT an output value-array — so the
    # OUTPUT-promotion in _reconcile_args is gated to producer-LESS element types.
    produced_bases: FrozenSet[str] = frozenset(
        _output_array_base(t)
        for ev in ir_ev.values() for t in (ev.produces or frozenset()))

    apis: Dict[str, APISemantics] = {}
    for api in project_apis:
        name = api.get("function_name", "")
        if not name:
            continue
        ir = ir_ev.get(name)
        doc = doc_ev.get(name)
        llm_role, llm_conf, llm_arg = llm_ev.get(name, (None, 0.0, {}))
        # INPUT_BUFFER / LENGTH stay DETERMINISTIC: they are a TYPE pattern (a
        # raw-byte pointer paired with a size), which the IR detector resolves
        # reliably. The LLM over-applies INPUT_BUFFER to any pointer/string arg
        # (it flagged cmsEvalToneCurveFloat, cmsIT8GetProperty as "parser
        # entries"), so we drop its verdict for these two roles and let it
        # speak only to the genuinely-semantic arg roles (OUTPUT / HANDLE_IN /
        # NULLABLE_HANDLE / CONFIG) and to the API role.
        llm_arg = {i: r for i, r in llm_arg.items()
                   if r not in (ArgRole.INPUT_BUFFER, ArgRole.LENGTH)}

        role, role_conf, role_log = _reconcile_role(
            ir, doc, usage.get(name, 0), llm_role=llm_role, llm_conf=llm_conf)
        arg_sems, arg_log = _reconcile_args(
            api, ir, doc, llm_arg=llm_arg, produced_bases=produced_bases)

        # Mechanism: which handle types, from IR; *direction* assigned by the
        # reconciled role. This is the key correction — a DESTROYER's IR
        # "produces" set (the free-array out-pointer mislabel) is re-bucketed
        # as ``destroys`` so the model matches reality.
        ir_produces = ir.produces if ir else frozenset()
        ir_requires = ir.requires if ir else frozenset()
        ir_kills = ir.kills if ir else frozenset()
        if role is APIRole.DESTROYER:
            # A destroyer frees the handle(s) handed to it. Two shapes:
            #   - by-value/in-pointer (``void free(T* t)``): the handle is in
            #     the USE set (``ir_requires``) — this is the common case;
            #   - free-array out-pointer (``free(T* arr[3])``): IR reads it as
            #     a produced handle (``ir_produces``) — the lcms mislabel.
            # Both are what the API destroys; KILL edges (``ir_kills``) too.
            produces: FrozenSet[str] = frozenset()
            destroys = frozenset(ir_kills | ir_produces | ir_requires)
            requires = ir_requires
        elif role is APIRole.CREATOR:
            produces, destroys, requires = ir_produces, ir_kills, ir_requires
        elif role is APIRole.MUTATOR:
            produces, destroys, requires = ir_produces, ir_kills, ir_requires
        else:  # CONSUMER / UNKNOWN
            produces, destroys, requires = frozenset(), ir_kills, ir_requires

        apis[name] = APISemantics(
            name=name, role=role, role_confidence=role_conf,
            args=arg_sems, produces=produces, requires=requires,
            destroys=destroys, evidence=tuple(role_log + arg_log),
        )

    model = APISemanticModel(
        project=project, apis=apis, handle_types=_handle_types)

    if llm_tiebreak is not None:
        # Hook: batched residual over genuine IR↔doc role conflicts only.
        # Left unwired in G1 (deterministic-only); a future phase may pass a
        # callable that takes the model + conflict list and returns overrides.
        try:
            model = llm_tiebreak(model, project_apis) or model
        except Exception:
            pass

    return model
