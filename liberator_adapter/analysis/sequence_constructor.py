"""Model-driven sequence constructor (redesign G2).

The old path *random-walks* the type-compatible API graph (Step 4 grammar)
and then removes the meaningless majority with five filter layers. The
redesign inverts this: **construct lifecycle-complete sequences directly from
the reconciled ``APISemanticModel``**, so candidates are valid *by
construction* and Z3 stops being a lifecycle gate (it only confirms type /
variable availability).

Construction shape (redesign §2.3):

    creator(produces T) → mutator(T)* → consumer(T) → destroyer(T)

A *target* is an API worth building a sequence around — a direct entry point
(it has an ``INPUT_BUFFER`` arg, i.e. consumes fuzzer bytes), a CONSUMER, or a
MUTATOR. For each target we resolve its ``requires`` transitively through the
model's producers (a dependency-directed build, not a random walk), then close
every handle we opened with a destroyer. The result has no unmatched
init/destroy by construction → ``Typestate.check`` returns no violations.

Two extra seed sources are folded in (both real compositions, not synthesised):
``accepting_paths`` from the project automaton and ``idiom_chains`` from the
Phase B distiller. They are added verbatim (deduped) so known-good usage is
never lost to the constructor's own coverage heuristic.

Deterministic and dependency-light: depends only on ``APISemanticModel`` and
plain lists, so the pipeline (Step 5h) and the offline viability harness share
one implementation.
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from liberator_adapter.analysis.api_semantic_model import (
    APIRole,
    ArgRole,
    APISemantics,
    APISemanticModel,
)


# Ordering faults that actually break a driver (vs benign UNCLOSED_RESOURCE
# leak). A constructed sequence with any of these is dropped by the self-filter.
_ORDERING_FAULTS = frozenset({
    "USE_BEFORE_INIT", "USE_AFTER_DESTROY", "DOUBLE_DESTROY",
    "DESTROY_BEFORE_INIT",
})


# T11 — symbolic error-shape variants (gate LOGICFUZZ_ERROR_VARIANTS). From a
# happy-path lifecycle sequence we derive a few ERROR-SHAPE variants that
# exercise the library's error-handling branches (double-free / idempotent-
# destroy guard, use-after-destroy state check, uninitialised-handle check). The
# variant changes ONLY the call-sequence shape — the LLM still fills the same
# leaf holes. Any crash a variant provokes is triaged by the existing crash-frame
# classifier (driver-bug → pre-ship merge quarantine), so a missing library guard
# never poisons the fused harness, while a present guard is covered for free.
_ERROR_VARIANT_SHAPES = ("DOUBLE_DESTROY", "USE_AFTER_DESTROY", "SKIP_INIT")


def error_shape_variants(
    seq: Sequence[str],
    creator_names: Set[str],
    destroyer_names: Set[str],
    *,
    shapes: Sequence[str] = _ERROR_VARIANT_SHAPES,
) -> List[Tuple[List[str], str]]:
    """Derive error-shape variants of a happy-path sequence.

    Returns ``(variant_sequence, shape_label)`` pairs. Pure + deterministic
    (unit-tested). A variant is produced only when the source sequence has the
    structural ingredient the shape needs (a destroyer for the destroy-shapes, a
    creator for SKIP_INIT); otherwise that shape is skipped. DOUBLE_DESTROY /
    USE_AFTER_DESTROY reuse the SAME bound handle in an illegal order — the shape
    *itself* is the error, independent of any LLM leaf value. SKIP_INIT drops the
    creator so the consumer runs on an unbound handle (LLM-dependent, weaker).
    """
    seq = [a for a in seq if a]
    if len(seq) < 2:
        return []
    destroyers_in = [a for a in seq if a in destroyer_names]
    creators_in = [a for a in seq if a in creator_names]
    out: List[Tuple[List[str], str]] = []

    if "DOUBLE_DESTROY" in shapes and destroyers_in:
        # …, destroy(h), destroy(h) → double-free / idempotent-destroy guard.
        d = destroyers_in[-1]
        out.append((list(seq) + [d], "DOUBLE_DESTROY"))

    if "USE_AFTER_DESTROY" in shapes and destroyers_in and creators_in:
        # create(h), destroy(h), <rest uses h> → use-after-destroy state check.
        d = destroyers_in[-1]
        c = creators_in[0]
        rest = [a for a in seq if a != c and a != d]
        if rest:
            out.append(([c, d] + rest, "USE_AFTER_DESTROY"))

    if "SKIP_INIT" in shapes and creators_in and len(seq) > len(creators_in):
        # drop the first creator → its consumer runs on an uninitialised handle
        # (the handle arg becomes a hole the LLM may NULL — LLM-dependent).
        c = creators_in[0]
        v = list(seq)
        v.remove(c)
        if v:
            out.append((v, "SKIP_INIT"))

    return out


def _scoped_guards() -> bool:
    """B+D gate (LOGICFUZZ_SCOPED_GUARDS, default-OFF).

    When ON: ``construct_sequences`` reorders a constructed ``core`` so its
    dependency components are contiguous (D), and ``skeleton_generator`` renders
    component-scoped NULL guards (B) — an INDEPENDENT param-rich producer no
    longer sits behind a failing input-parser's whole-driver NULL bail. Gate-OFF
    ⇒ byte-identical to the legacy path (the existing regression suite pins
    this)."""
    return os.environ.get("LOGICFUZZ_SCOPED_GUARDS") == "1"


def _dependency_components(
    api_sequence: Sequence[str],
    model: Any,
) -> List[List[str]]:
    """Partition ``api_sequence`` into ordered dependency COMPONENTS.

    A *component* is a maximal contiguous run that shares a data dependency: an
    API stays in the current component iff its ``requires`` intersects the
    handle types PRODUCED EARLIER within that same component; an API that
    consumes none of the current component's handles is INDEPENDENT of the prior
    work and STARTS A NEW component.

    ``model`` only needs a ``.apis`` mapping ``name -> obj`` where ``obj`` has
    ``produces`` / ``requires`` (frozenset-like) attributes — so both an
    ``APISemanticModel`` and the skeleton generator's lightweight signature-
    derived model satisfy it. Names absent from the model contribute no handle
    edges (they're treated as scalar-only → independent), so the partition is
    robust to a partial model.

    Returns ``List[List[str]]`` (components in order; each a contiguous slice of
    the input names, preserving order; the concatenation equals the input — no
    API is dropped or reordered across the slice boundary).
    """
    apis = getattr(model, "apis", {}) or {}

    def _produces(name: str) -> Set[str]:
        sem = apis.get(name)
        return set(getattr(sem, "produces", ()) or ()) if sem is not None else set()

    def _requires(name: str) -> Set[str]:
        sem = apis.get(name)
        return set(getattr(sem, "requires", ()) or ()) if sem is not None else set()

    components: List[List[str]] = []
    cur: List[str] = []
    cur_produced: Set[str] = set()
    for name in api_sequence:
        if not name:
            continue
        if cur and not (_requires(name) & cur_produced):
            # Consumes nothing the current component opened → new component.
            components.append(cur)
            cur = []
            cur_produced = set()
        cur.append(name)
        cur_produced |= _produces(name)
    if cur:
        components.append(cur)
    return components


@dataclass
class ConstructionResult:
    sequences: List[List[str]]
    metrics: Dict[str, Any] = field(default_factory=dict)
    # Workflow-backbone sequences (grafted from the automaton's real per-test
    # accepting paths) that survived the ordering filter — the human-equivalent
    # usage compositions (e.g. profile→transform→dotransform). Callers protect
    # these in the synthesis budget instead of letting gap-COUNT ranking (which
    # rewards long multi-API breadth) bury the focused workflows.
    workflow_sequences: List[List[str]] = field(default_factory=list)


# =============================================================================
# Indexing
# =============================================================================

@dataclass
class _Index:
    producers: Dict[str, List[APISemantics]]   # handle type → APIs producing it
    destroyers: Dict[str, List[APISemantics]]  # handle type → APIs destroying it
    mutators: Dict[str, List[APISemantics]]     # handle type → MUTATORs of it
    entries: List[APISemantics]                 # APIs with an INPUT_BUFFER arg
    consumers: List[APISemantics]               # CONSUMER role
    creators: List[APISemantics]                # CREATOR role
    # Density (LOGICFUZZ_DENSE_CONSTRUCT): handle type → CONSUMERs that read it /
    # pure getters (CONSUMER that requires a handle but produces nothing).
    consumers_by_handle: Dict[str, List[APISemantics]] = field(default_factory=dict)
    getters: Dict[str, List[APISemantics]] = field(default_factory=dict)
    by_name: Dict[str, APISemantics] = field(default_factory=dict)   # co-occurrence lookup
    # Factory-chain recovery (LOGICFUZZ_FACTORY_CHAIN): handle type → CREATORs that
    # produce it but whose ``produces`` set is EMPTY because the handle is a
    # return-by-value opaque typedef (``typedef void* cmsHTRANSFORM``) — the IR
    # desugars the return to ``void *`` so ``extract_produced_handles`` can't see
    # it. Recovered by naming (see ``_recover_opaque_producers``). Empty unless the
    # flag is on → strictly additive, never regresses the default path.
    recovered_producers: Dict[str, List[APISemantics]] = field(default_factory=dict)


# =============================================================================
# Factory-chain recovery (always on)
# =============================================================================
#
# Problem (lcms ``cmsDoTransform``): an opaque handle declared ``typedef void*
# cmsHTRANSFORM`` keeps its typedef name in *argument* positions (so a consumer's
# ``requires`` correctly records ``cmshtransform``), but the *return* type of its
# creator (``cmsCreateTransform``) is desugared to ``void *`` — so the use-def
# walker records no produced handle and ``produces`` is EMPTY. The producer index
# then has no entry for ``cmshtransform`` and ``_build_prefix`` leaves the arg a
# NULL hole → the deep API covers ~0. (29/52 lcms creators are in this state.)
#
# Return-type matching can't recover the link (every such return is ``void``).
# The one robust deterministic signal left is the C handle-object NAMING idiom:
# ``<lib>Create<Name>`` / ``<lib>Open<Name>`` produces the ``<lib>H<NAME>`` handle.
# We map an unproduced opaque (non-pointer) handle type to the CREATORs whose name
# contains the type's stem as a complete camelCase word. This is reused by the
# *existing* recursive ``_build_prefix`` so chaining becomes transitive for free.

def _detect_lib_prefix(names: Sequence[str]) -> str:
    """Most common 2-5 char leading token across API names (the library prefix,
    e.g. ``cms``). Returns ``""`` when no token covers ≥40% of the names."""
    c: Counter = Counter()
    n_names = 0
    for nm in names:
        low = (nm or "").lstrip("_").lower()
        if not low:
            continue
        n_names += 1
        for length in (5, 4, 3, 2):
            if len(low) > length:
                c[low[:length]] += 1
    if not c or not n_names:
        return ""
    best, cnt = c.most_common(1)[0]
    return best if cnt >= 0.4 * n_names else ""


def _opaque_stems(t_norm: str, lib_prefix: str) -> List[str]:
    """Candidate name stems for an opaque handle type (lowercased, normalized).

    ``cmshtransform`` → strip ``cms`` → ``htransform`` → also strip the ``H``
    handle marker → ``{htransform, transform}``. Only stems ≥5 chars are kept so a
    short stem can't spuriously match an unrelated creator. Caller guarantees
    ``t_norm`` is a non-pointer typedef (pointer types are caller-alloc leaves).
    """
    s = t_norm
    if lib_prefix and s.startswith(lib_prefix):
        s = s[len(lib_prefix):]
    out: Set[str] = set()
    if len(s) >= 5:
        out.add(s)
    if s.startswith("h") and len(s) - 1 >= 5:
        out.add(s[1:])
    return [x for x in out if len(x) >= 5]


def _word_in_name(stem: str, name: str) -> bool:
    """True iff ``stem`` (lowercase) occurs in ``name`` as a complete camelCase /
    snake word. Boundary = string edge, an uppercase letter, or a non-alpha char.

    Rejects ``handle`` ⊂ ``...ErrorHandler`` (followed by lowercase ``r``) and
    ``profile`` ⊂ ``Multiprofile`` (preceded by lowercase ``i``) while accepting
    ``Transform`` / ``ProfileFrom`` — the camelCase word test that keeps recovery
    precise."""
    low = name.lower()
    n = len(stem)
    start = 0
    while True:
        i = low.find(stem, start)
        if i < 0:
            return False
        j = i + n
        start_ok = (i == 0) or name[i].isupper() or (not name[i - 1].isalpha())
        end_ok = (j == len(name)) or name[j].isupper() or (not name[j].isalpha())
        if start_ok and end_ok:
            return True
        start = i + 1


def _recover_opaque_producers(
    model: APISemanticModel,
    producers: Dict[str, List[APISemantics]],
    creators: List[APISemantics],
) -> Dict[str, List[APISemantics]]:
    """Map required-but-unproduced opaque (non-pointer typedef) handle types to
    the CREATORs that produce them, recovered by the handle-object naming idiom.

    Only fires for types that (a) some API ``requires``, (b) have NO real producer
    (``produces``-derived), (c) are NON-pointer (a ``*`` means a caller-allocated
    struct/scalar leaf — declare a local, don't factory it), and (d) name-match at
    least one CREATOR. Everything else falls through to the existing hole path, so
    this is purely additive."""
    required: Set[str] = set()
    for sem in model.apis.values():
        required |= set(sem.requires)
    unproduced = [t for t in required if t not in producers and "*" not in t]
    if not unproduced:
        return {}
    lib_prefix = _detect_lib_prefix(list(model.apis.keys()))
    out: Dict[str, List[APISemantics]] = {}
    for t in unproduced:
        stems = _opaque_stems(t, lib_prefix)
        if not stems:
            continue
        matched = [c for c in creators
                   if any(_word_in_name(st, c.name) for st in stems)]
        if matched:
            out[t] = matched
    return out


def _build_index(model: APISemanticModel) -> _Index:
    producers: Dict[str, List[APISemantics]] = {}
    destroyers: Dict[str, List[APISemantics]] = {}
    mutators: Dict[str, List[APISemantics]] = {}
    entries: List[APISemantics] = []
    consumers: List[APISemantics] = []
    creators: List[APISemantics] = []
    consumers_by_handle: Dict[str, List[APISemantics]] = {}
    getters: Dict[str, List[APISemantics]] = {}

    for sem in model.apis.values():
        for t in sem.produces:
            producers.setdefault(t, []).append(sem)
        for t in sem.destroys:
            destroyers.setdefault(t, []).append(sem)
        if sem.role is APIRole.MUTATOR:
            for t in sem.requires:
                mutators.setdefault(t, []).append(sem)
        if sem.role is APIRole.CREATOR:
            creators.append(sem)
        elif sem.role is APIRole.CONSUMER:
            consumers.append(sem)
            for t in sem.requires:
                consumers_by_handle.setdefault(t, []).append(sem)
            if sem.requires and not sem.produces:   # pure read of an open handle
                for t in sem.requires:
                    getters.setdefault(t, []).append(sem)
        if any(a.role is ArgRole.INPUT_BUFFER for a in sem.args):
            entries.append(sem)

    # Factory chain (opaque void*-return producer recovery) is always on: it is
    # monotone — zero effect on libs with no recoverable opaque handles — so the
    # LOGICFUZZ_FACTORY_CHAIN gate was removed.
    recovered = _recover_opaque_producers(model, producers, creators)

    return _Index(producers, destroyers, mutators, entries, consumers, creators,
                  consumers_by_handle, getters,
                  {sem.name: sem for sem in model.apis.values()},
                  recovered_producers=recovered)


def _densify(core_seq: List[str], opened: Set[str], idx: _Index,
             max_extra: int, repeat: bool,
             cooccur: Optional[Dict[str, Set[str]]] = None) -> List[str]:
    """Thicken a thin lifecycle chain toward the PromeFuzz density band (5.6–7.6
    calls) from TWO sources:

    (a) **handle-sharing extenders** — mutators/consumers/getters whose
        ``requires`` ⊆ ``opened`` (valid by construction, no new unmet handle);
    (b) **co-occurrence extenders** — APIs that appear together with this
        sequence's APIs in the library's REAL usage paths (automaton
        accepting-paths / idioms). This is exactly PromeFuzz's call-scope +
        semantic grouping signal: it pulls in the semantically-related,
        multi-handle workflow APIs that (a) misses (e.g. lcms build-tonecurve →
        make-devicelink → close-profile, which span 3 handle types). A
        co-occurrence extender is kept when its handle deps are already open
        (valid) OR are entirely ORPHAN (no in-project producer) — the latter
        becomes a hole the LLM fills (B graceful degradation), and the pre-ship
        quarantine drops any that end up immediate-crash FPs.

    Deterministic symbolic structure on both axes; the LLM still owns leaf
    values. So we reach PromeFuzz's density but keep a lifecycle-valid core +
    only hole what's genuinely unbindable → same density, lower FP."""
    in_seq = set(core_seq)
    cands: Dict[str, APISemantics] = {}
    # (a) handle-sharing extenders
    for t in opened:
        for sem in idx.mutators.get(t, []) + idx.consumers_by_handle.get(t, []):
            if sem.name in in_seq or sem.name in cands:
                continue
            if set(getattr(sem, "requires", ()) or ()) <= opened:
                cands[sem.name] = sem
    # (b) co-occurrence extenders (real usage grouping)
    if cooccur:
        related: Set[str] = set()
        for a in core_seq:
            related |= cooccur.get(a, set())
        for name in sorted(related):
            if name in in_seq or name in cands:
                continue
            sem = idx.by_name.get(name)
            if sem is None:
                continue
            req = set(getattr(sem, "requires", ()) or ())
            if req <= opened or all(not idx.producers.get(h) for h in req):
                cands[name] = sem
    if not cands:
        return list(core_seq)

    def _rank(sem: APISemantics):
        # handle-satisfiable extenders first (valid), then co-occurrence holes
        sat = 0 if set(getattr(sem, "requires", ()) or ()) <= opened else 1
        if sem.role is APIRole.MUTATOR:
            return (sat, 0, sem.name)
        is_getter = bool(getattr(sem, "requires", ())) and not getattr(sem, "produces", ())
        return (sat, 2 if is_getter else 1, sem.name)   # consumer(1) then getter(2)

    ordered = sorted(cands.values(), key=_rank)[:max(0, max_extra)]
    extra = [s.name for s in ordered]
    if repeat:   # PF-style: re-call one CONFIG-bearing consumer/getter in a 2nd state
        for s in ordered:
            if s.role is not APIRole.MUTATOR and any(
                    a.role is ArgRole.CONFIG for a in s.args):
                extra.append(s.name)
                break
    return list(core_seq) + extra


# =============================================================================
# Dependency-directed prefix build
# =============================================================================

def _build_prefix(
    target: APISemantics,
    idx: _Index,
    max_depth: int,
) -> Tuple[List[str], Set[str]]:
    """Build a **coherent, best-effort** creator prefix for ``target``.

    Two principles (learned from the lcms live runs where prefixes were
    incoherent junk that early-returned before the deep API):

    1. **Only chain real CREATORs.** A required handle is produced only by an
       API whose role is CREATOR (``cmsCreateContext``). We do NOT chain
       getters/mutators (``cmsGetToneCurveSegment``) as "producers" — they pull
       in deep prerequisite chains that return NULL and abort the driver before
       it reaches the target. A type with no CREATOR is left UNMET.
    2. **Unmet requires become holes, not failures.** Many "required" pointers
       are caller-populated input structs (``cmsCurveSegment*``) or
       NULL-accepting handles (``cmsContext``) — a human just fills/NULLs them.
       So we never drop the target; an unmet requirement simply isn't in the
       prefix (the renderer/LLM fills that arg).

    Returns ``(prefix_api_names, opened_handle_types)`` — always (never None).
    """
    prefix: List[str] = []
    satisfied: Set[str] = set()
    opened: Set[str] = set()
    in_progress: Set[str] = set()

    def resolve(t: str, depth: int) -> bool:
        if t in satisfied:
            return True
        if depth > max_depth or t in in_progress:
            return False  # too deep or cyclic — leave unmet (hole)
        # Only real CREATORs build a prefix handle; getters/mutators would
        # drag in deep junk chains. No CREATOR ⇒ leave the type unmet.
        cands = [p for p in idx.producers.get(t, []) if p.role is APIRole.CREATOR]
        from_recovery = False
        if not cands and idx.recovered_producers:
            # Factory-chain recovery (LOGICFUZZ_FACTORY_CHAIN): the type is a
            # return-by-value opaque typedef whose creator's ``produces`` was
            # erased by IR desugaring — recover its CREATORs by naming so the
            # SAME recursion below chains them transitively to fuzzer leaves.
            cands = idx.recovered_producers.get(t, [])
            from_recovery = bool(cands)
        if not cands:
            return False

        # Prefer a creator that INGESTS FUZZER BYTES (has an INPUT_BUFFER arg,
        # e.g. cmsOpenProfileFromMem) over an equivalent synthetic creator
        # (cmsCreateBCHSWabstractProfile): both produce the same handle type, but
        # only the byte-parsing one turns fuzz input into the handle's state, so
        # downstream consumers (cmsReadTag → cmstypes.c tag deserializers) reach
        # real depth instead of operating on a fixed in-memory object. Tie-break
        # by fewest prerequisites, then name (deterministic).
        def _creator_key(s: APISemantics) -> Tuple[int, int, str]:
            is_entry = any(a.role is ArgRole.INPUT_BUFFER for a in s.args)
            return (0 if is_entry else 1, len(s.requires), s.name)

        # Recovered opaque factories rank differently. The IR erased the inner
        # handle args of several variants (cmsCreateMultiprofileTransform's profile
        # ARRAY → requires=[]), so "fewest requires" would pick exactly the variant
        # that builds NOTHING and returns NULL. Instead prefer a factory that
        # requires ANOTHER recoverable opaque handle (cmsCreateTransform requires
        # cmshprofile) — that is the genuinely DEEP factory whose dependency we can
        # chain down to a byte-opener (cmsOpenProfileFromMem). Bytes first, then a
        # deep opaque dependency, then the usual fewest-prereq / name tiebreak.
        def _recovered_key(s: APISemantics) -> Tuple[int, int, int, str]:
            is_entry = any(a.role is ArgRole.INPUT_BUFFER for a in s.args)
            deep = any(h in idx.recovered_producers for h in s.requires)
            return (0 if is_entry else 1, 0 if deep else 1,
                    len(s.requires), s.name)

        producer = sorted(
            cands, key=_recovered_key if from_recovery else _creator_key)[0]
        in_progress.add(t)
        for rt in producer.requires:
            resolve(rt, depth + 1)   # best-effort: a sub-req hole is fine
        in_progress.discard(t)
        if producer.name not in prefix:
            prefix.append(producer.name)
        satisfied.add(t)
        # ``t`` is now an open handle. For real producers ``t ∈ produces`` so this
        # is redundant; for a recovered opaque producer ``produces`` is empty, so
        # this is what lets a destroyer close it (cmsDeleteTransform) and density
        # see the handle. Safe either way.
        opened.add(t)
        for pt in producer.produces:
            satisfied.add(pt)
            opened.add(pt)
        return True

    for t in target.requires:
        resolve(t, 0)   # best-effort; unmet requirements stay holes
    return prefix, opened


def _closing_destroyers(opened: Set[str], idx: _Index) -> List[str]:
    """One destroyer per opened handle type (deterministic pick)."""
    out: List[str] = []
    for t in sorted(opened):
        dz = idx.destroyers.get(t)
        if dz:
            name = sorted(dz, key=lambda s: s.name)[0].name
            if name not in out:
                out.append(name)
    return out


# =============================================================================
# Public API
# =============================================================================

def construct_sequences(
    model: APISemanticModel,
    *,
    project_apis: Optional[Sequence[Dict[str, Any]]] = None,
    lifecycle_pairs: Optional[Sequence[Tuple[str, str]]] = None,
    accepting_paths: Optional[Sequence[Sequence[str]]] = None,
    idiom_chains: Optional[Sequence[Sequence[str]]] = None,
    gap_apis: Optional[Set[str]] = None,
    graft_fn: Optional[Any] = None,
    construct_mode: str = "merged",
    max_sequences: int = 300,
    max_prefix_depth: int = 6,
) -> ConstructionResult:
    """Construct lifecycle-complete API sequences from the semantic model.

    Construction reasons over the *model's* ``produces/requires/destroys``.
    When ``project_apis`` is supplied, the result is additionally **self-filtered
    through the shared ``Typestate`` oracle** (the same use-def/KILL walker
    CBFactory's lifecycle check uses): any sequence with an ordering fault
    (use-before-init / use-after-destroy / double-destroy / destroy-before-init)
    is dropped. This guarantees the output is ordering-clean against the
    independent oracle even where the model and raw ``extract_api_effects``
    def/use diverge (observed on freshly-extracted lcms accessors). Omit
    ``project_apis`` to skip the filter (model-only, e.g. unit tests).
    """
    idx = _build_index(model)
    # Density is default-on (the LOGICFUZZ_DENSE_CONSTRUCT gate was removed); the
    # tuning sub-params below stay configurable.
    _dense = True
    # Default 8 → ~7.7 APIs/seq on lcms (PromeFuzz parity 7.6) once co-occurrence
    # is on; lower it (e.g. =4) for thinner drivers / fewer holes.
    _dense_max_extra = int(os.environ.get("LOGICFUZZ_DENSE_MAX_EXTRA", "8"))
    _dense_repeat = os.environ.get(
        "LOGICFUZZ_DENSE_REPEAT_CONSUMER", "").strip().lower() in (
            "1", "true", "yes", "on")  # explicit: "0" must mean off
    n_densified = 0
    # Co-occurrence map for density source (b): which APIs are used TOGETHER in
    # the library's REAL usage paths (automaton accepting-paths + idioms) — the
    # PromeFuzz call-scope/semantic grouping signal, which we already learn.
    # LOGICFUZZ_DENSE_COOCCUR=0 disables just this source (handle-sharing only).
    _cooccur: Dict[str, Set[str]] = {}
    if _dense and os.environ.get("LOGICFUZZ_DENSE_COOCCUR", "1") != "0":
        for _path in list(accepting_paths or []) + list(idiom_chains or []):
            _ps = [a for a in _path if a and a in model.apis]
            for _a in _ps:
                _cooccur.setdefault(_a, set()).update(x for x in _ps if x != _a)

    seqs: List[List[str]] = []
    seen: Set[Tuple[str, ...]] = set()
    source_of: Dict[Tuple[str, ...], str] = {}

    def _add(seq: Sequence[str], source: str = "bottomup") -> None:
        cleaned = [a for a in seq if a and a in model.apis]
        if not cleaned:
            return
        key = tuple(cleaned)
        if key in seen:
            return
        seen.add(key)
        source_of[key] = source
        seqs.append(list(cleaned))

    mode = (construct_mode or "merged").lower()
    do_workflow = mode in ("workflow", "merged")
    do_bottomup = mode in ("bottomup", "merged")

    # 1. WORKFLOW backbone (top-down). The automaton's accepting paths are real
    # usage compositions from the library's own tests — they encode "how the
    # library is actually used" (e.g. lcms profile→transform→dotransform), the
    # domain knowledge a human driver-author has and bottom-up type-walking
    # can't infer. We graft-complete each (prepend creators for handles the
    # path uses but doesn't open — turning a mid-stream trace fragment into a
    # runnable driver) and let the Typestate filter validate. graft_fn is the
    # automaton's graft_creator_prefix; absent it, paths are used verbatim
    # (the filter drops genuine fragments).
    n_seeded = 0
    if do_workflow:
        for p in (accepting_paths or []):
            grafted = None
            if graft_fn is not None:
                try:
                    grafted = graft_fn(list(p))
                except Exception:
                    grafted = None
            _add(grafted or p, source="workflow")
        n_seeded = len(seqs)
    for c in (idiom_chains or []):
        _add(c, source="idiom")
    n_idiom = len(seqs) - n_seeded

    # 2. Type-driven construction around each target. G5: when a coverage gap
    # is supplied, also treat every gap API (incl. creators/mutators the
    # baseline never reaches) as a target, and order gap-touching targets
    # FIRST so they survive the max_sequences / downstream top-K cap. This is
    # what directs generation at baseline-uncovered code.
    gap_apis = gap_apis or set()
    n_attempted = 0
    if do_bottomup:
        targets: List[APISemantics] = []
        seen_targets: Set[str] = set()
        target_pool = list(idx.entries) + list(idx.consumers) \
            + [s for ms in idx.mutators.values() for s in ms]
        if gap_apis:
            # Add gap APIs that aren't already entries/consumers/mutators so we
            # build a reaching sequence for them too.
            target_pool += [model.apis[n] for n in sorted(gap_apis)
                            if n in model.apis]
        # Stable sort: gap-API targets first, then the rest (original order kept).
        target_pool.sort(key=lambda s: 0 if s.name in gap_apis else 1)
        for sem in target_pool:
            if sem.name not in seen_targets:
                seen_targets.add(sem.name)
                targets.append(sem)

        for target in targets:
            n_attempted += 1
            prefix, opened = _build_prefix(target, idx, max_prefix_depth)
            # The target itself opens handles if it is also a producer.
            opened = set(opened) | set(target.produces)
            core = prefix + [target.name]
            if _dense:
                core = _densify(core, opened, idx, _dense_max_extra,
                                _dense_repeat, _cooccur)
                if len(core) > len(prefix) + 1:
                    n_densified += 1
            if _scoped_guards():
                # D — reorder ``core`` so its dependency components are
                # CONTIGUOUS (parser+consumers block first, independent producer
                # blocks after). This is a pure REORDERING (every API kept), so
                # the skeleton's per-component scoped-guard rendering (B) is
                # clean. Gate-OFF leaves ``core`` untouched (byte-identical).
                core = [a for comp in _dependency_components(core, model)
                        for a in comp]
            seq = core + _closing_destroyers(opened, idx)
            _add(seq)

        # 3. create→destroy coverage for creators no target reached.
        covered = {a for s in seqs for a in s}
        for creator in idx.creators:
            if creator.name in covered:
                continue
            prefix, opened = _build_prefix(creator, idx, max_prefix_depth)
            opened = set(opened) | set(creator.produces)
            _add(prefix + [creator.name] + _closing_destroyers(opened, idx))

    if len(seqs) > max_sequences:
        seqs = seqs[:max_sequences]

    # Self-filter through the independent Typestate oracle (when project_apis
    # is available): drop ordering-faulting sequences so the output is
    # ordering-clean by the same walker CBFactory's lifecycle gate uses.
    n_before_filter = len(seqs)
    n_ordering_dropped = 0
    n_orphan_kept = 0   # island-API sequences kept via graceful degradation (B)
    if project_apis:
        try:
            from liberator_adapter.analysis.usedef import (
                UseDefGraph, Typestate, extract_api_effects,
            )
            _ts = Typestate(UseDefGraph(extract_api_effects(
                list(project_apis),
                lifecycle_pairs=list(lifecycle_pairs) if lifecycle_pairs else None,
            )))
            # Graceful degradation (B): a USE_BEFORE_INIT on an ORPHAN handle —
            # one no in-project API produces — is NOT a fixable ordering fault.
            # It is an "island" API (opaque / void* / no producer) that the
            # baselines reach but our construct-from-model used to drop here,
            # walling ~302/452 gap APIs out of every candidate sequence. Keep
            # those sequences: the unchecked render path leaves the orphan handle
            # as a HOLE and the LLM constructs/NULLs it (T5 / CALLSPEC hints).
            # Only a USE_BEFORE_INIT where a producer EXISTS (the prefix should
            # have called it), or any other ordering fault, stays fatal.
            # Kill-switch: LOGICFUZZ_STRICT_ORDERING=1 restores the old behavior.
            import os as _os
            _strict = _os.environ.get(
                "LOGICFUZZ_STRICT_ORDERING", "").strip().lower() in (
                    "1", "true", "yes", "on")  # explicit: "0" must mean off
            kept: List[List[str]] = []
            for s in seqs:
                viols = _ts.check(s)
                fatal = False
                for v in viols:
                    if v.kind.name not in _ORDERING_FAULTS:
                        continue
                    if (not _strict and v.kind.name == "USE_BEFORE_INIT"
                            and not idx.producers.get(v.handle)):
                        n_orphan_kept += 1
                        continue  # orphan handle → keep (LLM fills the hole)
                    fatal = True
                    break
                if fatal:
                    n_ordering_dropped += 1
                else:
                    kept.append(s)
            seqs = kept
        except Exception as _e:
            # First-party analysis (Typestate/UseDefGraph are always importable),
            # so a raise here is a real bug, NOT "oracle unavailable". Keep
            # fail-soft (don't abort construction) but make it VISIBLE — silently
            # swallowing ships ordering-faulty (use-after-destroy / double-destroy)
            # sequences unfiltered, the exact FP-poisoning this filter prevents.
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "Typestate self-filter raised (%s); shipping %d sequences "
                "UNFILTERED — investigate (not 'oracle unavailable')",
                _e, len(seqs))

    # T11: error-shape variants (LOGICFUZZ_ERROR_VARIANTS) — appended AFTER the
    # ordering self-filter so they survive (the shapes are deliberate ordering
    # faults the filter would otherwise drop). Derived from the surviving
    # happy-path sequences; bounded by LOGICFUZZ_ERROR_VARIANTS_MAX.
    n_error_variants = 0
    if os.environ.get("LOGICFUZZ_ERROR_VARIANTS") and seqs:
        _creator_names = {s.name for ns in idx.producers.values() for s in ns}
        _destroyer_names = {s.name for ns in idx.destroyers.values() for s in ns}
        _vbudget = int(os.environ.get("LOGICFUZZ_ERROR_VARIANTS_MAX", "12"))
        # Selectivity (1) — shapes: default to the GUARD-testing shapes a robust
        # library is *designed* to handle (SKIP_INIT = uninitialised-handle check;
        # DOUBLE_DESTROY = idempotent-destroy / double-free guard) → pure coverage
        # win when the guard exists. USE_AFTER_DESTROY is genuine UAF (almost
        # always a crash, rarely a guarded branch), so it is opt-in only.
        _shapes = ["SKIP_INIT", "DOUBLE_DESTROY"]
        if os.environ.get("LOGICFUZZ_ERROR_VARIANTS_AGGRESSIVE"):
            _shapes.append("USE_AFTER_DESTROY")
        # Selectivity (2) — gap-direction: only vary sequences that touch a
        # baseline-UNCOVERED (gap) API, so variants add NEW error-branch coverage
        # instead of re-covering. No gap info → vary all.
        _gap = set(gap_apis) if gap_apis else set()
        _src = [s for s in seqs if (not _gap or (_gap & set(s)))]
        _variants: List[List[str]] = []
        for s in _src:
            if len(_variants) >= _vbudget:
                break
            for vseq, shape in error_shape_variants(
                    s, _creator_names, _destroyer_names, shapes=_shapes):
                key = tuple(vseq)
                if key in seen:
                    continue
                seen.add(key)
                source_of[key] = f"error_variant:{shape}"
                _variants.append(vseq)
                if len(_variants) >= _vbudget:
                    break
        seqs.extend(_variants)
        n_error_variants = len(_variants)

    api_cov = {a for s in seqs for a in s}
    handle_cov = set(idx.producers) | set(idx.destroyers)
    gap_hit = (api_cov & gap_apis) if gap_apis else set()
    metrics = {
        "n_sequences": len(seqs),
        "n_seeded_from_automaton": n_seeded,
        "n_seeded_from_idioms": n_idiom,
        "n_targets_attempted": n_attempted,
        "n_densified": n_densified,
        "n_ordering_dropped": n_ordering_dropped,
        "n_orphan_kept": n_orphan_kept,
        "n_error_variants": n_error_variants,
        "n_before_ordering_filter": n_before_filter,
        "api_coverage": len(api_cov),
        "handle_types": len(handle_cov),
        "avg_length": round(sum(len(s) for s in seqs) / len(seqs), 2) if seqs else 0,
        # G5: how much of the baseline-uncovered API surface we now construct for.
        "gap_apis_total": len(gap_apis),
        "gap_apis_reached": len(gap_hit),
        # Factory-chain recovery: # of opaque handle types whose CREATORs were
        # recovered by naming (0 unless LOGICFUZZ_FACTORY_CHAIN is on).
        "n_factory_recovered": len(idx.recovered_producers),
    }
    workflow_sequences = [s for s in seqs
                          if source_of.get(tuple(s)) == "workflow"]
    metrics["n_workflow_kept"] = len(workflow_sequences)
    return ConstructionResult(sequences=seqs, metrics=metrics,
                              workflow_sequences=workflow_sequences)
