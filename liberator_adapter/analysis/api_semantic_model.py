"""APISemanticModel — the single reconciled per-API record (redesign G1).

The generation-stage redesign (``docs/generation_stage_redesign.md``) traces
every downstream band-aid (Phase A repair, F1–F4, L5 reranks) to one
inversion: roles/arg-semantics are derived from a *single* source (LLVM-IR
mod/ref) and then corrected later. This module inverts that: it fuses the
three evidence sources up front into one auditable model.

Reconciliation principle (redesign §2.2) — each source is authoritative only
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
    _count_pointer_levels,
    _find_buffer_size_positions,
    _get_is_const,
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index, "role": self.role.value,
            "type_str": self.type_str, "nullable": self.nullable,
            "pairs_with": self.pairs_with,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ArgSemantics":
        return cls(
            index=int(d["index"]), role=ArgRole(d.get("role", "UNKNOWN")),
            type_str=d.get("type_str", ""), nullable=bool(d.get("nullable", False)),
            pairs_with=d.get("pairs_with"),
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


def collect_ir_evidence(
    project_apis: Sequence[Dict[str, Any]],
    condition_info: Optional[Dict[str, Any]] = None,
    lifecycle_pairs: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, _IREvidence]:
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

    out: Dict[str, _IREvidence] = {}
    for api in project_apis:
        name = api.get("function_name", "")
        if not name:
            continue
        eff = eff_by_name.get(name)
        produces = frozenset(eff.def_) if eff else frozenset()
        requires = frozenset(eff.use) if eff else frozenset()
        kills = frozenset(eff.kill) if eff else frozenset()

        # Tentative IR role (tiebreak authority only).
        role: Optional[APIRole] = None
        conf = 0.0
        if name in sinks or kills:
            role, conf = APIRole.DESTROYER, 0.75
        elif name in sources or name in inits or (produces and not requires):
            role, conf = APIRole.CREATOR, 0.7
        elif produces and requires:
            role, conf = APIRole.MUTATOR, 0.6
        elif requires and not produces:
            role, conf = APIRole.CONSUMER, 0.6

        out[name] = _IREvidence(
            role=role, role_conf=conf, produces=produces,
            requires=requires, kills=kills,
            arg_roles=_ir_arg_roles(api),
        )
    return out


def _ir_arg_roles(api: Dict[str, Any]) -> Dict[int, ArgRole]:
    """Arg roles derivable from type-structure alone (no doc)."""
    args = api.get("arguments", api.get("arguments_info", [])) or []
    roles: Dict[int, ArgRole] = {}
    buf_idx, size_idx = _find_buffer_size_positions(args)
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
        arg_roles: Dict[int, ArgRole] = {}
        for p in (sig.get("params") or []):
            idx = p.get("index")
            r = p.get("role")
            if isinstance(idx, int) and r:
                try:
                    arg_roles[idx] = ArgRole(r)
                except ValueError:
                    pass
        out[name] = _DocEvidence(
            role=role, role_conf=conf, role_source=role_source,
            role_strong=role_strong, arg_roles=arg_roles)
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


def _reconcile_args(
    api: Dict[str, Any],
    ir: Optional[_IREvidence],
    doc: Optional[_DocEvidence],
    llm_arg: Optional[Dict[int, ArgRole]] = None,
) -> Tuple[Tuple[ArgSemantics, ...], List[Evidence]]:
    """Arg roles: doc @param > LLM > type-pattern (IR). Pair LENGTH ↔ buffer.

    The LLM arg-role wins over the IR type-pattern (which can't tell a fuzzer
    INPUT_BUFFER from any ``void*``, or a LENGTH from any size_t) but yields to
    an explicit ``@param`` description.
    """
    args = api.get("arguments", api.get("arguments_info", [])) or []
    ir_arg = ir.arg_roles if ir else {}
    doc_arg = doc.arg_roles if doc else {}
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
        nullable = role in (ArgRole.NULLABLE_HANDLE, ArgRole.OUTPUT)
        out_args.append(ArgSemantics(
            index=i, role=role, type_str=atype.strip(),
            nullable=nullable, pairs_with=pairs_with,
        ))
    return tuple(out_args), log


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
    ir_ev = collect_ir_evidence(project_apis, condition_info, lifecycle_pairs)
    doc_ev = collect_doc_evidence(project_apis, doc_signals)
    usage = collect_usage_evidence(accepting_paths)
    llm_ev = _parse_llm_roles(llm_roles)

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
        arg_sems, arg_log = _reconcile_args(api, ir, doc, llm_arg=llm_arg)

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

    model = APISemanticModel(project=project, apis=apis)

    if llm_tiebreak is not None:
        # Hook: batched residual over genuine IR↔doc role conflicts only.
        # Left unwired in G1 (deterministic-only); a future phase may pass a
        # callable that takes the model + conflict list and returns overrides.
        try:
            model = llm_tiebreak(model, project_apis) or model
        except Exception:
            pass

    return model
