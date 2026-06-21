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
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

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


# =============================================================================
# Phase-3 L1a: object-construction-first gate + root-kind classifier
# =============================================================================

import os as _os
_OBJCONSTRUCT_FIRST: bool = (
    _os.environ.get("LOGICFUZZ_OBJCONSTRUCT_FIRST", "0").strip().lower()
    in ("1", "true", "yes", "on")
)


def _root_kind(sem: "APISemantics") -> str:
    """Classify a CREATOR (or CONSUMER) API by how it obtains its primary handle.

    Returns one of:

    * ``"parser_entry"``  — the API ingests raw fuzzer bytes (has an
      ``INPUT_BUFFER`` arg) and decodes them into a handle / state object.
      Both CREATOR and CONSUMER roles are tagged here (a CONSUMER that parses
      bytes also gates downstream coverage on valid input).

    * ``"caller_alloc"``  — a CREATOR that writes through an OUTPUT pointer
      the *caller* allocates (e.g. ``deflateInit(z_stream*)``).  The caller
      stack-allocates the struct and passes its address; the library initialises
      it in-place.  Identified by: CREATOR role + at least one OUTPUT arg +
      non-empty ``produces``.

    * ``"data_buildable"`` — a CREATOR with no INPUT_BUFFER and no OUTPUT arg;
      it synthesises an object from scalar / enum / config arguments that the
      fuzzer or the LLM can supply directly (e.g. ``cmsCreate_sRGBProfile``).
      This is the "object-construction" class that ``LOGICFUZZ_OBJCONSTRUCT_FIRST``
      promotes to rank ahead of parser-entry chains.

    * ``"other"``         — everything else (MUTATOR, DESTROYER, UNKNOWN, or a
      CONSUMER without an INPUT_BUFFER arg).

    Pure and deterministic — no I/O, no env reads.
    """
    has_buf = any(a.role is ArgRole.INPUT_BUFFER for a in sem.args)
    if has_buf and sem.role in (APIRole.CREATOR, APIRole.CONSUMER):
        return "parser_entry"
    if sem.role is APIRole.CREATOR:
        if any(a.role is ArgRole.OUTPUT for a in sem.args) and sem.produces:
            return "caller_alloc"
        return "data_buildable"
    return "other"


def _exercise_object() -> bool:
    """Gate (default-off): ``LOGICFUZZ_EXERCISE_OBJECT`` extends a construction
    chain FORWARD with the deepest fuzz-data-consuming consumer of each produced
    handle, so a built object is actually RUN on fuzz bytes (e.g. a constructed
    ``cmsHTRANSFORM`` gets ``cmsDoTransform(t, data, …)``) rather than just
    built-then-freed. Addresses the per-driver DEPTH gap: backward ``_build_prefix``
    stops at object construction; this is the missing forward 'exercise' step."""
    return _os.environ.get("LOGICFUZZ_EXERCISE_OBJECT", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _validity_contract() -> bool:
    """Unconditional (graduated 2026-06-20, switch removed): makes construction
    satisfy the Validity Contract — every ``nullable=False`` opaque-handle ARG the model
    knows (not just the lossy IR ``requires``) gets a type-matching producer in the
    prefix. Args with no producer (value-structs/buffers) stay holes for the renderer.
    A/B 2026-06-20 (lcms): preflight-survived 1->14, merged distinct APIs 18->49;
    additive (only binds unbound nullable=False handles), no regression."""
    return True


def _populate_collections() -> bool:
    """Unconditional (graduated 2026-06-20, switch removed): render a CREATOR's
    handle-collection arg (``cmsToneCurve* const []``) as a populated array of
    built producer handles instead of degenerate ``{0}``/NULL, so the deep
    constructor runs (measured +72% edges/driver vs PromeFuzz's build-and-chain
    pattern: 334 vs 194 edges on instrumented lcms).
    lcms 300s-fuzz edges 325→943, cov 0.86%→16.81%."""
    return True


def _fuzz_buffers() -> bool:
    """Unconditional (graduated 2026-06-20, switch removed): render a
    builder's scalar data-buffer arg (``cmsUInt16Number *``) as ``(T*)data`` (raw
    fuzz bytes) with its paired length bound to ``size/sizeof(T)``, instead of the
    degenerate ``nEntries=0`` / single ``{0}``. Makes drivers SEED-INDEPENDENT
    (any bytes build a real object — PromeFuzz's pattern) and deepens them.
    lcms 300s-fuzz edges 325→943, cov 0.86%→16.81%."""
    return True


def _collection_elem_keys(sem) -> List[str]:
    """For a CREATOR with handle-collection args (``cmsToneCurve * *``), the
    element handle-type producer keys (``cmstonecurve*``) — so ``_build_prefix``
    chains a producer of the element (e.g. cmsBuildTabulatedToneCurve16) that
    Lever A then populates the array with. The collection arg has role UNKNOWN
    and is absent from ``requires`` (IR erases the inner handle), so without this
    the deep constructor gets a degenerate ``{0}``. Lever A; caller gates."""
    from liberator_adapter.analysis.usedef import is_handle_type
    out: List[str] = []
    for a in (getattr(sem, "args", ()) or ()):
        t = (getattr(a, "type_str", "") or "").replace("const", "").strip()
        if t.count("*") < 2:
            continue
        base = t.replace("*", "").strip()
        if not base or "char" in base.lower() or not is_handle_type(base):
            continue
        key = (base + "*").lower().replace(" ", "")   # producer key: cmstonecurve*
        if key not in out:
            out.append(key)
    return out


def _recover_init_handles() -> bool:
    """Gate (default-off): ``LOGICFUZZ_RECOVER_INIT_HANDLES`` — recover a void*-
    returning ``*Init``/``*Alloc``/``*New`` initializer as an opaque producer
    EVEN when the IR role heuristic mis-labeled it CONSUMER/MUTATOR (void* return
    erased → produces=[]). Unlocks whole deep subsystems (CIECAM02, gamut/GDB,
    IT8) whose consumers otherwise get a NULL handle → 0 coverage → culled. The
    same-subsystem gate in ``resolve()`` prevents cross-wiring."""
    return _os.environ.get("LOGICFUZZ_RECOVER_INIT_HANDLES", "0").strip().lower() in (
        "1", "true", "yes", "on")


# Strong producer-verb idioms: an API whose subsystem-stripped name STARTS or
# ENDS with one of these allocates/opens a handle. Excludes mutator/accessor
# verbs (Get/Set/Read/Write/Add) which never produce a fresh handle.
_INIT_IDIOM_VERBS = ("init", "alloc", "new", "create", "open", "build", "load",
                     "dup")


def _is_init_idiom_name(name: str, lib_prefix: str) -> bool:
    """True when ``name`` (minus the library prefix) is a producer-verb idiom —
    e.g. ``cmsCIECAM02Init``, ``cmsGBDAlloc``, ``cmsMLUalloc``. Used to recover
    void*-returning initializers the role heuristic missed."""
    core = name
    if lib_prefix and core.lower().startswith(lib_prefix.lower()):
        core = core[len(lib_prefix):]
    low = core.lstrip("_").lower()
    return any(low.startswith(v) or low.endswith(v) for v in _INIT_IDIOM_VERBS)


def _norm_handle(type_str: str) -> str:
    """Normalize a handle type to the index key (lowercase, no spaces/star).

    Strips cv/restrict KEYWORDS (word-boundary) FIRST so a consumer arg
    ``png_struct * __restrict`` keys identically to a producer's ``png_struct*``.
    Without this, libpng handle args (229/295 carry ``__restrict``) keyed as
    ``png_struct*__restrict`` and never matched the producer/handle_types key
    ``png_struct`` → ``repair_sequence_validity`` silently bailed (key-not-in-
    handle_types / no-producer) → NULL handle → dead driver. Sibling of the #19
    ``usedef.normalize_handle_type`` fix, in the function the repair actually uses."""
    from liberator_adapter.analysis.usedef import _strip_type_keywords
    t = _strip_type_keywords(type_str or "")
    return t.strip().lower().replace(" ", "").rstrip("*")


def _producers_for_type(idx, key: str):
    """All known producers of handle type ``key`` — opaque-recovered AND
    by-``produces`` (which is keyed with/without the pointer star). Used to check
    a cross-source alternate exists."""
    out = {}
    for k in (key, key + "*"):
        for p in (getattr(idx, "producers", {}) or {}).get(k, []) or []:
            out[p.name] = p
    for p in (getattr(idx, "recovered_producers", {}) or {}).get(key, []) or []:
        out[p.name] = p
    return list(out.values())


def _is_synthetic_producer(p) -> bool:
    """A data-buildable producer (no INPUT_BUFFER arg) — a stable standalone
    object, the safe cross-source alternate (e.g. cmsCreate_sRGBProfile)."""
    return not any(a.role is ArgRole.INPUT_BUFFER
                   for a in (getattr(p, "args", ()) or ()))


def repair_sequence_validity(
    names: Sequence[str],
    model: Optional["APISemanticModel"] = None,
    *,
    idx: Optional["_Index"] = None,
) -> List[str]:
    """I2a universal repair (LOGICFUZZ_VALIDITY_CONTRACT): ensure every
    ``nullable=False`` opaque-handle arg in ``names`` has an EARLIER same-type
    producer, prepending the cheapest standalone creator when it doesn't.

    ``_build_prefix`` only resolves producers for a constructed chain's ROOT
    target; the DENSIFIED tail and the grammar-FLOOR sequences (random
    type-walks merged at Step 5h) bypass it, so they reach render with NULL
    handles → Task-11 guards them → the consumer never runs → ~0 coverage. This
    is the post-construction net that makes the valid-by-construction contract
    hold for EVERY sequence funnelled to skeleton synthesis, not just G2 roots.

    For each consumer arg that is non-NULL and an opaque handle of family ``F``:
      * if an earlier statement already produces ``F`` → leave it (binding wires
        it; I3 fix);
      * else if the model has a producer of ``F`` → PREPEND the cheapest
        standalone creator (synthetic / no INPUT_BUFFER preferred, then fewest
        own required handles, then name — deterministic);
      * else (genuinely producer-less, e.g. cmsHANDLE) → leave it (the Task-11
        non-NULL guard covers it).

    Pure + deterministic; gated ⇒ gate-off returns ``names`` unchanged
    (byte-identical). ``idx`` may be supplied (tests / reuse); otherwise built
    from ``model``."""
    if not _validity_contract() or not names:
        return list(names)
    if idx is None:
        if model is None:
            return list(names)
        idx = _build_index(model)
    by_name = getattr(idx, "by_name", {}) or {}
    try:
        from liberator_adapter.analysis.validity_contract import _family as _vc_family
    except Exception:
        def _vc_family(_s):  # pragma: no cover - fallback if oracle absent
            return None

    # An OPAQUE HANDLE type = one that some API ``requires`` or ``destroys`` (a
    # lifecycle dependency). Value-structs (cmsCIExyY), strings (char*), version
    # constants (zlibVersion's char*) and scalars are passed by value / filled by
    # the renderer — they are NEVER ``requires``d, so they are correctly excluded.
    # Without this, the repair mis-fires across projects (zlib zlibVersion,
    # c-ares ares_library_initialized) and on lcms value-structs. Mirrors the
    # oracle's ``validity_contract._handle_types``; generic, no project literals.
    handle_types: Set[str] = set()
    for sem in by_name.values():
        for t in (getattr(sem, "requires", ()) or ()):
            handle_types.add(_norm_handle(t))
        for t in (getattr(sem, "destroys", ()) or ()):
            handle_types.add(_norm_handle(t))

    def _is_leaf_creator(p, key: str) -> bool:
        """A creator that yields a LIVE handle from fillable inputs only — the
        only safe prepend. Rejects: (1) INTERNAL APIs (``_cms*`` — won't link);
        (2) creators with a ``nullable=False`` arg that is ITSELF an opaque
        handle needing a producer (e.g. cmsCreateMultiprofileTransform's profile
        array) — prepending one just moves the orphan up a level and the call
        returns NULL anyway. Scalars / strings / value-structs / buffers are
        fillable, so a leaf may still have those."""
        nm = getattr(p, "name", "") or ""
        if nm.startswith("_"):
            return False  # internal symbol, not a public entry point
        for a in (getattr(p, "args", ()) or ()):
            if getattr(a, "nullable", True):
                continue
            ak = _norm_handle(getattr(a, "type_str", "") or "")
            if ak and ak != key and _producers_for_type(idx, ak):
                return False  # needs another handle → not standalone
        return True

    def _pick_producer(key: str) -> Optional[str]:
        # The void* index POOLS wrong-type producers for collapsed opaque handles
        # (lcms: _producers_for_type('cmshprofile') returns cmsCreateExtended*
        # Transform; 'cmshandle' returns math fns like cmsBFDdeltaE). Pick a
        # TYPE-CORRECT producer by NAME family: cmsCreateNULLProfile is family
        # "profile", cmsCreate*Transform is "transform". A family-LESS generic
        # (cmsHANDLE: gamut/IT8/… share one void* typedef) has no type-safe
        # producer determinable here — binding one cross-wires (cmsGBDFree on a
        # profile → heap corruption → crash), so leave it NULL+guarded instead.
        kf = _vc_family(key)
        leaves = [p for p in _producers_for_type(idx, key)
                  if _is_leaf_creator(p, key)]
        if kf is not None:
            # lcms void*-collapsed handles: the by-type pool cross-wires families,
            # so disambiguate by NAME family (cmsCreateNULLProfile=profile, …).
            prods = [p for p in leaves
                     if _vc_family(getattr(p, "name", "") or "") == kf]
        else:
            # No lcms name-family (any OTHER library, e.g. png_struct *). A DISTINCT
            # typed handle's pool is type-correct by construction — every producer
            # indexed under it produces exactly this type, so type-match is safe
            # (this is what makes png_create_read_struct prependable; previously we
            # bailed here and left the handle NULL → dead driver). Guard against a
            # genuine void*-collapsed pool (cmsHANDLE: many families share one
            # typedef) by requiring the candidates' produced types to be
            # UNAMBIGUOUS (all == key); else leave NULL+guarded.
            kn = _norm_handle(key)
            produced = {_norm_handle(pt) for p in leaves
                        for pt in (getattr(p, "produces", ()) or [])}
            prods = leaves if (leaves and produced and produced <= {kn}) else []
        if not prods:
            return None  # no safe standalone leaf → Task-11 guard covers
        prods = sorted(prods, key=lambda p: (
            0 if _is_synthetic_producer(p) else 1,
            len([a for a in (getattr(p, "args", ()) or ())
                 if not getattr(a, "nullable", True)]),  # fewer must-fill args
            getattr(p, "name", "")))
        return getattr(prods[0], "name", None)

    def _mark_produced(nm: str, produced: Set[str]) -> None:
        sem = by_name.get(nm)
        if sem is None:
            return
        for pt in (getattr(sem, "produces", ()) or ()):
            produced.add(_norm_handle(pt))

    result: List[str] = []
    produced: Set[str] = set()
    for nm in names:
        sem = by_name.get(nm)
        if sem is not None:
            for a in (getattr(sem, "args", ()) or ()):
                if getattr(a, "nullable", True):
                    continue  # NULL is legal → no producer needed
                key = _norm_handle(getattr(a, "type_str", "") or "")
                if not key or key in produced:
                    continue
                if key not in handle_types:
                    continue  # not a lifecycle handle (string/value/scalar) →
                    # the renderer fills it; never an I2a producer-prepend case
                if not _producers_for_type(idx, key):
                    continue  # genuinely unconstructable → Task-11 guard
                prod = _pick_producer(key)
                if prod and prod != nm and prod not in result:
                    result.append(prod)
                    produced.add(key)            # this producer satisfies key
                    _mark_produced(prod, produced)
        result.append(nm)
        _mark_produced(nm, produced)
    return result


def count_repairs(
    name_sequences: Sequence[Sequence[str]],
    idx,
    known_names: Optional[Set[str]] = None,
) -> Dict[str, int]:
    """Read-only breadth telemetry over the sequences fed to skeleton synthesis.

    Replays ``repair_sequence_validity`` per name-sequence, tallying how many it
    fires on and how many producer calls it prepends. Pure: same ``idx`` the gate
    builds, so counts match synthesis. ``known_names`` mirrors the gate's
    renderability guard (``None`` counts every repair the pure logic produces).
    """
    n_sequences = n_repaired = n_prepended = 0
    for names in name_sequences:
        names = list(names)
        n_sequences += 1
        fixed = repair_sequence_validity(names, idx=idx)
        if fixed == names:
            continue
        if known_names is not None and not all(n in known_names for n in fixed):
            continue
        n_repaired += 1
        prepended = Counter(fixed) - Counter(names)  # net added producer calls
        n_prepended += sum(prepended.values())
    return {"n_sequences": n_sequences, "n_repaired": n_repaired,
            "n_prepended": n_prepended}


# I2b (Task 8): a required non-handle pointer arg the renderer CAN synthesize
# non-NULL — a string (string-wrapped) or a complete public value-struct
# (stack-alloc {0}, e.g. cmsCIELab / cmsCIEXYZ). Such args are NEVER an I2b
# violation, so a consumer with only fillable required value args is kept.
# lcms value-struct NAME fallback (kept additively so lcms never regresses if its
# DataLayout entry is missing); the GENERAL signal below is the primary path.
_FILLABLE_VALUE_STRUCT = re.compile(
    r"cms(cie|jch|xyy|xyz|viewingconditions|curvesegment|lab|lch)", re.I)


def _is_complete_value_struct(type_str: str) -> bool:
    """True if ``type_str``'s core is a COMPLETE public struct — DataLayout knows
    its full layout and it is not opaque/incomplete — so the renderer can
    stack-allocate it as ``{0}``. Project-agnostic structural replacement for the
    lcms ``_FILLABLE_VALUE_STRUCT`` name list: keeps ``png_color`` / ``struct tm``
    / any library's complete POD value-struct consumer, not just lcms's seven.
    Fail-safe: False when DataLayout is unavailable (→ caller keeps the lcms regex
    fallback / the conservative drop)."""
    from liberator_adapter.analysis.usedef import _strip_type_keywords
    core = _strip_type_keywords(type_str or "").replace("*", "").replace(" ", "")
    if not core:
        return False
    try:
        from liberator_adapter.common import DataLayout
        dl = DataLayout.instance()
        return bool(dl.is_a_struct(core)) and not bool(dl.is_incomplete(core))
    except Exception:  # noqa: BLE001 — DataLayout absent/uninit ⇒ not provably fillable
        return False


def _i2b_unfillable_consumer(sem, idx) -> bool:
    """True iff ``sem`` has a ``nullable=False`` NON-handle required POINTER arg
    that is GENUINELY unfillable: not a handle (no producer of its type), not a
    string (char*), not a complete public value-struct, and not a fuzz-data
    buffer (INPUT_BUFFER/OUTPUT/LENGTH role). Such an arg renders NULL → the
    library asserts/derefs NULL (the FileName-style I2b violation). The layered
    policy drops the consumer (a driver passing NULL there yields no coverage).
    Pure; only consulted under the gate ⇒ gate-off byte-identical."""
    for a in (getattr(sem, "args", ()) or ()):
        if getattr(a, "nullable", True):
            continue  # nullable → NULL is legal
        ts = getattr(a, "type_str", "") or ""
        if "*" not in ts and not re.search(r"cmsH[A-Z]", ts):
            continue  # not a pointer → not an I2b pointer-NULL case
        # a handle (has a real/recovered producer) is I2a, not I2b
        key = _norm_handle(ts)
        if key and _producers_for_type(idx, key):
            continue
        role = getattr(getattr(a, "role", None), "name", None)
        if role in ("INPUT_BUFFER", "OUTPUT", "LENGTH"):
            continue  # fuzz-data / caller-backing buffer (renderer fills)
        low = ts.lower()
        if "char" in low:
            continue  # string → string-wrapped non-NULL
        if _is_complete_value_struct(ts) or _FILLABLE_VALUE_STRUCT.search(ts):
            continue  # complete public value-struct → renderer stack-allocs {0}
        return True   # unfillable required pointer → drop the consumer
    return False


_CROSS_SRC_DENY = ("copy", "clone", "dup", "detach")


def _wants_cross_source(sem, idx) -> bool:
    """True iff ``sem`` is a CREATOR that builds a NEW object from >=2 handles of
    the SAME type T, where T has >=2 producers incl. a synthetic — the
    ``cmsCreateTransform`` cross-profile idiom. CREATOR-scoped (excludes the
    copy/state/mutator/parent-child hazards where the two handles need a specific
    relationship, not two arbitrary instances) + name-deny. Cross-project
    test-locked. Lever ``LOGICFUZZ_CROSS_SOURCE_BIND`` only; pure, no env read."""
    if getattr(sem, "role", None) is not APIRole.CREATOR:
        return False
    nm = (getattr(sem, "name", "") or "").lower()
    if any(k in nm for k in _CROSS_SRC_DENY):
        return False
    counts: Dict[str, int] = {}
    for a in (getattr(sem, "args", ()) or ()):
        t = _norm_handle(a.type_str)
        if t:
            counts[t] = counts.get(t, 0) + 1
    for t, c in counts.items():
        if c < 2:
            continue
        prods = _producers_for_type(idx, t)
        if len(prods) >= 2 and any(_is_synthetic_producer(p) for p in prods):
            return True
    return False


def _cross_source_producer(sem, idx):
    """Name of a synthetic, NO-requires producer of ``sem``'s repeated handle
    type, distinct from ``sem`` — the cross-source alternate (e.g.
    cmsCreate_sRGBProfile for a transform's 2nd profile). None if none exists.
    No-requires keeps the injected call standalone (valid by construction)."""
    counts: Dict[str, int] = {}
    for a in (getattr(sem, "args", ()) or ()):
        t = _norm_handle(a.type_str)
        if t:
            counts[t] = counts.get(t, 0) + 1
    for t, c in counts.items():
        if c < 2:
            continue
        for p in _producers_for_type(idx, t):
            if (p.name != sem.name and _is_synthetic_producer(p)
                    and not (getattr(p, "requires", None) or ())):
                return p.name
    return None


def _inject_cross_source(seq: Sequence[str], model, idx) -> List[str]:
    """For each eligible cross-source CREATOR in ``seq`` (``_wants_cross_source``),
    inject its SYNTHETIC alternate producer (``_cross_source_producer``) once,
    immediately BEFORE the creator, so the creator's two same-type handles can
    later bind to DIFFERENT producers (the cross-profile transform idiom). The
    injected producer is no-requires (standalone) so it stays runnable. Already-
    present / no-alternate ⇒ unchanged. Caller gates on ``_cross_source()``; this
    helper is pure (no env read) so it is byte-identical when not called."""
    out: List[str] = []
    apis = getattr(model, "apis", {}) or {}
    for name in seq:
        sem = apis.get(name)
        if sem is not None and _wants_cross_source(sem, idx):
            xp = _cross_source_producer(sem, idx)
            if xp and xp not in seq and xp not in out:
                out.append(xp)
        out.append(name)
    return out


def _append_exercisers(core: List[str], opened: Set[str], idx) -> List[str]:
    """For each handle the chain PRODUCED, append ONE consumer that exercises it.

    Ranks eligible consumers (``requires`` ⊆ ``opened`` so no NULL hole, not
    already in-chain): fuzz (an ``INPUT_BUFFER`` arg) > plain. Highest rank per
    handle wins; ties keep the first (order-stable). Appends names only."""
    in_core = set(core)
    extra: List[str] = []
    cbh = getattr(idx, "consumers_by_handle", None) or {}
    for h in sorted(opened):
        best = None  # (sem, rank): 1=fuzz, 0=plain
        for c in cbh.get(h, ()):  # consumers whose ``requires`` includes h
            if c.name in in_core or c.name in extra:
                continue
            req = set(getattr(c, "requires", ()) or ())
            if not req <= opened:
                continue  # an unsatisfied handle would NULL-hole the call
            if any(a.role is ArgRole.INPUT_BUFFER
                   for a in getattr(c, "args", ()) or ()):
                rank = 1
            else:
                rank = 0
            if best is None or rank > best[1]:
                best = (c, rank)
                if rank == 1:
                    break  # a fuzz-data consumer is the deepest exercise
        if best is not None:
            extra.append(best[0].name)
            in_core.add(best[0].name)
    return list(core) + extra


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
    """B+D, always-on (gate removed).

    ``construct_sequences`` reorders a constructed ``core`` so its dependency
    components are contiguous (D), and ``skeleton_generator`` renders
    component-scoped NULL guards (B) — an INDEPENDENT param-rich producer no
    longer sits behind a failing input-parser's whole-driver NULL bail."""
    return True


def _dependency_components(
    api_sequence: Sequence[str],
    model: Any,
) -> List[List[str]]:
    """Partition ``api_sequence`` into TRUE data-dependency components.

    Two APIs share a component iff a data dependency connects them transitively:
    a consumer is unioned with the MOST-RECENT PRECEDING producer of each handle
    type it requires (the "last created handle wins" binding the skeleton
    renderer uses). This is deliberately NOT a type-wide union — a second
    INDEPENDENT producer of the same handle type that nothing downstream consumes
    stays in its own component (so an independent ``cmsCreate*`` does not get
    swept into the parser's NULL-guard).

    Fixes the prior greedy single-pass partition, which only saw handles produced
    earlier in the CURRENT contiguous run: a consumer appearing AFTER an
    interleaved independent producer started its own component and (in
    scoped-guard rendering) ran OUTSIDE its real producer's NULL guard
    (use-before-check).

    ``model`` only needs a ``.apis`` mapping ``name -> obj`` with ``produces`` /
    ``requires`` (frozenset-like) — both an ``APISemanticModel`` and the skeleton
    generator's signature-derived model satisfy it. Names absent contribute no
    edges (scalar-only → independent), so the partition is robust to a partial
    model.

    Returns components ordered by their earliest member's position, each
    component's members in their ORIGINAL relative order (so the
    creator→…→destroyer lifecycle order within a component is preserved).
    Concatenating the components REORDERS the sequence so each component is
    contiguous — the intended D-reorder (the old greedy made it a no-op).
    """
    apis = getattr(model, "apis", {}) or {}
    names = [n for n in api_sequence if n]
    n = len(names)
    if n <= 1:
        return [list(names)] if names else []

    def _produces(name: str) -> Set[str]:
        sem = apis.get(name)
        return set(getattr(sem, "produces", ()) or ()) if sem is not None else set()

    def _requires(name: str) -> Set[str]:
        sem = apis.get(name)
        return set(getattr(sem, "requires", ()) or ()) if sem is not None else set()

    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)  # keep earliest position as root

    last_producer = {}
    for i, nm in enumerate(names):
        # requires BEFORE produces: a mutator binds to the PRIOR handle of a
        # type, then becomes that type's most-recent producer.
        for h in _requires(nm):
            p = last_producer.get(h)
            if p is not None:
                _union(p, i)
        for h in _produces(nm):
            last_producer[h] = i

    groups = {}
    for i in range(n):
        groups.setdefault(_find(i), []).append(i)
    ordered = sorted(groups.values(), key=lambda ps: ps[0])
    return [[names[i] for i in ps] for ps in ordered]


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
    # Recovered opaque handle types whose producer bucket spans >1 subsystem (a
    # generic ``void*`` typedef like cmsHANDLE shared by CIECAM02/GDB/IT8/…).
    # Each consumer needs a SUBSYSTEM-SPECIFIC instance, so such a handle must
    # NOT be treated as a freely-shareable open handle by density (that would
    # cross-wire one subsystem's consumer to another's producer). Used only when
    # LOGICFUZZ_RECOVER_INIT_HANDLES is on (keeps gate-off byte-identical).
    generic_opaque_handles: FrozenSet[str] = frozenset()


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


_SUBSYS_VERBS = (
    "Alloc", "Set", "Get", "Dup", "Free", "Create", "Open", "Write", "Read",
    "Delete", "Close", "Build", "Save", "Load", "Init", "Done", "Add", "Insert",
    "Eval", "New", "Compute", "Append", "Reverse", "Join", "Smooth", "Estimate",
    "Detect", "Adapt", "Desaturate", "Link", "Check",
)


def _subsystem_token(name: str, lib_prefix: str) -> str:
    """The SUBSYSTEM noun of an API name. Handles both name shapes:
      * VERB-FIRST (``cmsCreateProfile``/``cmsOpenProfileFromMem`` → ``profile``):
        strip the leading verb, take the following noun.
      * NOUN-FIRST (``cmsDictAlloc``/``cmsDictDup`` → ``dict``; ``cmsIT8Alloc``/
        ``cmsIT8SetDataRowCol`` → ``it8``): cut at the first INTERNAL verb.
    So same-subsystem opaque builders + consumers share a token (binds Dict↔Dict,
    IT8↔IT8, profile-creators together) — NOT ``subsystem_clusters._name_token``,
    which would split IT8Alloc='IT8All' vs IT8Set='IT8Set'."""
    core = name
    if lib_prefix and core.lower().startswith(lib_prefix.lower()):
        core = core[len(lib_prefix):]
    core = core.lstrip("_")
    # 1. strip a LEADING verb (verb-first names key on the following noun).
    for v in _SUBSYS_VERBS:
        if (core.startswith(v) and len(core) > len(v)
                and core[len(v):len(v) + 1].isupper()):
            core = core[len(v):]
            break
    # 2. cut at the first INTERNAL verb (noun-first: IT8SetData → IT8).
    cut = len(core)
    for v in _SUBSYS_VERBS:
        i = core.find(v)
        if 0 < i < cut:
            cut = i
    core = core[:cut] or core
    # 3. take the leading word (all-caps run like IT8, else CamelCase word).
    m = re.match(r'[A-Z0-9]{2,}|[A-Za-z][a-z0-9]*', core)
    return (m.group(0) if m else core).lower()


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

    # Generic opaque-handle fallback: a handle like cmsHANDLE (typedef void*)
    # shared across subsystems has CREATORs (cmsDictAlloc, cmsIT8Alloc) with
    # produces=[] (void* return erased) that the name-stem match above MISSES
    # (they are named for the subsystem, not the handle word). Map such an
    # unrecovered opaque handle to ALL opaque CREATORs (role==CREATOR, no
    # produces); _build_prefix.resolve applies a STRICT same-subsystem gate when
    # the bucket spans >1 subsystem, so it binds Dict↔Dict / IT8↔IT8 and leaves
    # a hole (never cross-connects) when there is no same-subsystem builder.
    opaque_builders = [c for c in creators if not c.produces]
    if _recover_init_handles():
        # LOGICFUZZ_RECOVER_INIT_HANDLES: a void*-returning initializer
        # (cmsCIECAM02Init returns cmsHANDLE=void*) that ALSO takes a config arg
        # is mis-roled CONSUMER/MUTATOR by the IR heuristic (void* return erased
        # → produces=[] → "requires and not produces" = CONSUMER), so it's absent
        # from ``creators`` and its whole subsystem's consumers get a NULL handle
        # → 0 coverage → culled. Recover name-idiom initializers with empty
        # ``produces`` regardless of role. The same-subsystem gate in
        # ``resolve()`` binds each ONLY to a same-subsystem consumer (CIECAM02↔
        # CIECAM02), so a recovered non-producer can never cross-wire.
        creator_names = {c.name for c in opaque_builders}
        for s in model.apis.values():
            if (s.name not in creator_names and not s.produces
                    and _is_init_idiom_name(s.name, lib_prefix)):
                opaque_builders.append(s)
    if opaque_builders:
        for t in unproduced:
            if t not in out:
                out[t] = list(opaque_builders)
    return out


def _has_unsizable_output_buffer(sem) -> bool:
    """True if the API writes through a caller-allocated pointer-ARRAY (``T**``)
    OUTPUT buffer whose length is a runtime value — e.g. ``png_read_image``'s
    ``png_bytepp`` row_pointers (sized by the decoded image height). Such an API
    CANNOT be safely standalone-synthesized: the constructor renders the buffer as
    a size-1 array of UNINITIALIZED pointers, and the callee then writes HEIGHT rows
    through garbage pointers → crash that poisons the merged harness. We exclude it
    from ALL construction; the deep row-loop decode is the LLM's job (it hand-writes
    the height-sized buffer, e.g. libpng driver 92) and ``png_read_png`` covers the
    full one-call decode with no caller row buffer.

    Discriminator is arg-shape + role (project-agnostic): a pointer-to-pointer
    (``>=2`` stars) arg whose role is OUTPUT. A HANDLE_IN ``T**`` (``png_get_tRNS``'s
    ``png_bytep*`` where the lib SETS one pointer to internal data) is NOT flagged,
    nor is a scalar OUTPUT (``int*``)."""
    for a in getattr(sem, "args", ()) or ():
        if (getattr(a, "role", None) is ArgRole.OUTPUT
                and (getattr(a, "type_str", "") or "").replace(" ", "").count("*") >= 2):
            return True
    return False


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
        if _has_unsizable_output_buffer(sem):
            # Exclude from ALL construction (producer/consumer/creator/mutator/
            # densify): a caller-allocated runtime-sized pointer-array OUTPUT buffer
            # (png_read_image's row_pointers) can't be safely synthesized → would
            # render a size-1 garbage-pointer array and crash. Left to the LLM /
            # png_read_png. Also fixes the spurious "produces=[png_byte*]" that made
            # png_read_image look like a producer of the row element type.
            continue
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

    # Recovered opaque handles whose producer bucket spans >1 subsystem token
    # (a generic void* typedef like cmsHANDLE). Density must not freely share
    # these (cross-wiring guard). Cheap; only consulted when the recovery gate
    # is on, so gate-off is byte-identical.
    _lib_prefix = _detect_lib_prefix(list(model.apis.keys()))
    generic_opaque: Set[str] = set()
    for _t, _cands in recovered.items():
        _toks = {_subsystem_token(c.name, _lib_prefix) for c in _cands}
        if len(_toks) > 1:
            generic_opaque.add(_t)

    return _Index(producers, destroyers, mutators, entries, consumers, creators,
                  consumers_by_handle, getters,
                  {sem.name: sem for sem in model.apis.values()},
                  recovered_producers=recovered,
                  generic_opaque_handles=frozenset(generic_opaque))


def _densify(core_seq: List[str], opened: Set[str], idx: _Index,
             max_extra: int, repeat: bool,
             cooccur: Optional[Dict[str, Set[str]]] = None,
             sibling_rank: int = 0) -> List[str]:
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
    # Cross-wiring guard (LOGICFUZZ_RECOVER_INIT_HANDLES): a generic recovered
    # opaque handle (cmsHANDLE, shared by CIECAM02/GDB/IT8/…) is satisfied for
    # the TARGET via a SUBSYSTEM-SPECIFIC producer; another subsystem's consumer
    # of the same generic handle must NOT reuse it (binding by void* type would
    # cross-wire). So exclude such handles from density's free-sharing pool.
    _skip_generic = (idx.generic_opaque_handles
                     if _recover_init_handles() else frozenset())
    # (a) handle-sharing extenders
    for t in opened:
        if t in _skip_generic:
            continue
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
            # Never pull a DESTROYER or CREATOR in as a co-occurrence extender:
            # a co-occurring DESTROYER + the closing destroyer appended at the
            # call site = DOUBLE_DESTROY → the Typestate self-filter SILENTLY
            # drops the WHOLE sequence (lost candidate); a CREATOR opens a handle
            # nothing here closes (UNCLOSED_RESOURCE) and is the prefix's job, not
            # density's. Source (a) can't pull either (it draws from mutators /
            # consumers_by_handle only). 2026-06 (Phase 2.2 review).
            if sem.role is APIRole.DESTROYER or sem.role is APIRole.CREATOR:
                continue
            req = set(getattr(sem, "requires", ()) or ())
            if req <= opened or all(not idx.producers.get(h) for h in req):
                cands[name] = sem
    if not cands:
        return list(core_seq)

    def _rank(sem: APISemantics):
        # handle-satisfiable extenders first (valid), then co-occurrence holes.
        sat = 0 if set(getattr(sem, "requires", ()) or ()) <= opened else 1
        if sem.role is APIRole.MUTATOR:
            return (sat, 0, sem.name)
        is_getter = bool(getattr(sem, "requires", ())) and not getattr(sem, "produces", ())
        return (sat, 2 if is_getter else 1, sem.name)

    _ranked = sorted(cands.values(), key=_rank)
    # A-2a (always-on; was LOGICFUZZ_DENSE_PARTITION): sibling chains sharing this
    # handle set take DISJOINT slices of the ranked candidate pool, so two near-twin
    # chains get DIFFERENT densifier suffixes — raises portfolio breadth and cuts
    # overlap. Deterministic: slice offset = sibling_rank * max_extra, wrap when
    # exhausted. Offline-measured (cjson+lcms): fewer selected drivers covering MORE
    # APIs with far lower pairwise redundancy (lcms 60→54 drivers / 154→213 APIs /
    # mean Jaccard 0.15→0.06; cjson 33→23 / 58→74 / 0.43→0.09).
    if max_extra > 0:
        start = (sibling_rank * max_extra) % max(1, len(_ranked))
        rotated = _ranked[start:] + _ranked[:start]
        ordered = rotated[:max_extra]
    else:
        ordered = []
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
    producer_rank: Optional[Dict[str, int]] = None,
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
    _lib_prefix = _detect_lib_prefix(list(idx.by_name.keys()))

    def resolve(t: str, depth: int, exclude: frozenset = frozenset()) -> bool:
        if t in satisfied:
            return True
        if depth > max_depth or t in in_progress:
            return False  # too deep or cyclic — leave unmet (hole)
        # Only real CREATORs build a prefix handle; getters/mutators would
        # drag in deep junk chains. No CREATOR ⇒ leave the type unmet.
        # ``exclude`` (gated collection-element path only; empty otherwise ⇒
        # byte-identical) drops a producer that is the requesting target itself
        # — a CREATOR that produces the element type it also collects would
        # otherwise satisfy the requirement with itself (self-cycle, no builder).
        cands = [p for p in idx.producers.get(t, [])
                 if p.role is APIRole.CREATOR and p.name not in exclude]
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

        # Over-connection guard: a recovered bucket spanning MORE THAN ONE
        # subsystem (a generic opaque handle like cmsHANDLE shared by Dict/IT8/…)
        # may bind ONLY a creator in the CONSUMER's subsystem. If none, leave the
        # type UNMET (a hole) — never cross-subsystem (the project's type
        # over-connection guardrail). Single-subsystem buckets (the existing
        # cmsHTRANSFORM/cmsHPROFILE name-stem recovery) skip this (no-op).
        if from_recovery and len(cands) > 1:
            _toks = {_subsystem_token(c.name, _lib_prefix) for c in cands}
            if len(_toks) > 1:
                _want = _subsystem_token(target.name, _lib_prefix)
                _same = [c for c in cands
                         if _subsystem_token(c.name, _lib_prefix) == _want]
                if not _same:
                    return False
                cands = _same

        # Prefer a creator that INGESTS FUZZER BYTES (has an INPUT_BUFFER arg,
        # e.g. cmsOpenProfileFromMem) over an equivalent synthetic creator
        # (cmsCreateBCHSWabstractProfile): both produce the same handle type, but
        # only the byte-parsing one turns fuzz input into the handle's state, so
        # downstream consumers (cmsReadTag → cmstypes.c tag deserializers) reach
        # real depth instead of operating on a fixed in-memory object. Tie-break
        # by fewest prerequisites, then name (deterministic).
        #
        # LOGICFUZZ_OBJCONSTRUCT_FIRST: invert the preference — prefer a
        # data-buildable (synthetic) creator over a parser-entry creator.  This
        # promotes object-construction subsystems (cmsCreate_sRGBProfile) ahead
        # of parser-entry chains (cmsOpenProfileFromMem) so the portfolio covers
        # more subsystems rather than deep-diving the ICC parser exclusively.
        _prefer_parser = not _OBJCONSTRUCT_FIRST
        def _creator_key(s: APISemantics) -> Tuple[int, int, str]:
            is_entry = any(a.role is ArgRole.INPUT_BUFFER for a in s.args)
            return (0 if (is_entry == _prefer_parser) else 1,
                    len(s.requires), s.name)

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
            return (0 if (is_entry == _prefer_parser) else 1, 0 if deep else 1,
                    len(s.requires), s.name)

        _sorted_cands = sorted(
            cands, key=_recovered_key if from_recovery else _creator_key)
        # A-1/A-1b: when a handle type has >1 creator, rotate which one each
        # sibling chain uses (deterministic, per-handle round-robin) so the
        # portfolio exercises the full producer set instead of always the single
        # sorted-first one. A-1b: confidence ordering already lives in
        # _creator_key/_recovered_key (role-authored).
        if producer_rank is not None and len(_sorted_cands) > 1:
            _r = producer_rank.get(t, 0)
            producer_rank[t] = _r + 1
            producer = _sorted_cands[_r % len(_sorted_cands)]
        else:
            producer = _sorted_cands[0]
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
    # I2a (LOGICFUZZ_VALIDITY_CONTRACT): the IR ``requires`` is LOSSY — it erases
    # some handle args (cmsCreateMultiprofileTransform's profile array; opaque
    # void* args). Drive resolution from the MODEL's per-arg nullable+type instead:
    # for every ``nullable=False`` arg whose type has a producer, ensure one in the
    # prefix. Value-structs / buffers (no producer) resolve False → stay holes the
    # renderer fills. Additive + gated (gate-off ⇒ byte-identical).
    if _validity_contract():
        for a in (getattr(target, "args", None) or ()):
            if getattr(a, "nullable", True):
                continue  # nullable arg → NULL is legal, no producer needed
            key = _norm_handle(getattr(a, "type_str", "") or "")
            if key and key not in satisfied and _producers_for_type(idx, key):
                resolve(key, 0)
    # Lever A construction side: a CREATOR's handle-collection arg (cmsToneCurve**)
    # is role UNKNOWN / absent from ``requires`` (IR erased the inner handle), so
    # chain a producer of the ELEMENT type too. The render (Lever A) then
    # populates the array with its ret. Gated; inert otherwise.
    if _populate_collections() and target.role is APIRole.CREATOR:
        for ek in _collection_elem_keys(target):
            # Exclude producers that THEMSELVES collect this element (the target,
            # its THR variant, other deep profile/stage constructors) — they are
            # circular/deep; we want a LEAF builder of the element
            # (cmsBuildTabulatedToneCurve16: a curve FROM a fuzz buffer, which
            # Lever B then fills) to chain + populate.
            _circ = frozenset(
                p.name for p in idx.producers.get(ek, [])
                if ek in _collection_elem_keys(p)) | frozenset({target.name})
            resolve(ek, 0, exclude=_circ)
    return prefix, opened


def _enforce_producer_order(seq: Sequence[str], idx: _Index) -> List[str]:
    """I1 (LOGICFUZZ_VALIDITY_CONTRACT): stable-reorder ``seq`` so every producer
    of a handle type is emitted BEFORE any in-sequence consumer/destroyer that
    requires/destroys that type (no use-before-produce / close-before-open).

    ``_build_prefix`` already appends producers ahead of consumers via recursion,
    but later passes (densify / cross-source injection / scoped-guard / error
    variants) can interleave a consumer ahead of its producer. This is a thin
    final net: a stable topological emit that keeps the relative order of every
    other call. Pure; only invoked under the gate ⇒ gate-off byte-identical."""
    names = list(seq)
    if len(names) < 2:
        return names

    # For each statement, the handle types it requires (a producer must precede)
    # and the handle types it produces.
    def _req(nm: str) -> Set[str]:
        sem = idx.by_name.get(nm)
        if sem is None:
            return set()
        # destroyers/consumers both depend on a live handle of the type
        return set(getattr(sem, "requires", ()) or ()) | \
            set(getattr(sem, "destroys", ()) or ())

    def _prod(nm: str) -> Set[str]:
        sem = idx.by_name.get(nm)
        if sem is None:
            return set()
        out = set(getattr(sem, "produces", ()) or ())
        # recovered opaque producers carry their handle type in produces=[]; a
        # CREATOR with no produces still opens its name-stem recovered type, but
        # we only need the explicit-produces signal for ordering here.
        return out

    # Stable topological insertion: build the output incrementally; before
    # emitting a consumer whose required type is produced LATER in the input,
    # first emit those still-pending producers (in their original order).
    remaining = list(names)
    out: List[str] = []
    emitted_types: Set[str] = set()
    guard = 0
    max_iter = len(remaining) * len(remaining) + len(remaining) + 1
    while remaining and guard < max_iter:
        guard += 1
        head = remaining[0]
        needed = _req(head)
        # types this head needs that are NOT yet produced but ARE produced by a
        # later statement still in `remaining`
        pending = {t for t in needed
                   if t not in emitted_types
                   and any(t in _prod(later) for later in remaining[1:])}
        if pending:
            # pull the FIRST later producer of one pending type to the front
            moved = False
            for k in range(1, len(remaining)):
                if _prod(remaining[k]) & pending:
                    prod = remaining.pop(k)
                    remaining.insert(0, prod)
                    moved = True
                    break
            if moved:
                continue  # re-evaluate with the producer now at the head
        # emit head
        out.append(head)
        emitted_types |= _prod(head)
        remaining.pop(0)
    # safety: if the guard tripped (shouldn't for acyclic deps), append the rest
    out.extend(remaining)
    return out


def _closing_destroyers(opened: Set[str], idx: _Index,
                        destroyer_rank: Optional[Dict[str, int]] = None) -> List[str]:
    """One destroyer per opened handle type.

    A-3: when a handle has >1 destroyer, rotate which one each sibling chain
    closes with (deterministic per-handle round-robin). When destroyer_rank is
    None (or a handle has a single destroyer) ⇒ the sorted-first destroyer.
    """
    _rotate = destroyer_rank is not None
    out: List[str] = []
    for t in sorted(opened):
        dz = idx.destroyers.get(t)
        if dz:
            names = [s.name for s in sorted(dz, key=lambda s: s.name)]
            if _rotate and destroyer_rank is not None and len(names) > 1:
                _r = destroyer_rank.get(t, 0)
                destroyer_rank[t] = _r + 1
                name = names[_r % len(names)]
            else:
                name = names[0]
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

    # Mode C — drop guaranteed-NULL-bail sequences. Opt-in (A/B pending): it
    # supersedes the pure-orphan graceful-degradation keep, which the preflight
    # proved produces edges=0 dead drivers (e.g. lcms cmsDictDup) — but the
    # preflight already drops those at merge, so this is primarily a wasted-trial
    # + cleaner-portfolio optimization. Default off keeps the orphan-keep design.
    _drop_unrunnable = os.environ.get(
        "LOGICFUZZ_DROP_UNRUNNABLE", "0").strip().lower() in (
            "1", "true", "yes", "on")
    _n_unrunnable = [0]

    def _runnable(cleaned: Sequence[str]) -> bool:
        """Guaranteed-NULL-bail guard: keep a sequence only if >=1 call actually
        runs against a real input — a fuzz INPUT_BUFFER arg, a CREATOR (incl. an
        opaque produces=[] builder), or a consumer whose every required handle is
        satisfiable (produced in-sequence, or has a real/recovered producer). A
        sequence where EVERY call is an unsatisfied-handle consumer renders the
        handle args NULL → the call returns NULL → the next one bails: an edges=0
        driver. Drop it at construction (frees the portfolio slot for a runnable
        sequence)."""
        produced: Set[str] = set()
        for nm in cleaned:
            sem = idx.by_name.get(nm)
            if sem is None:
                continue
            if any(a.role is ArgRole.INPUT_BUFFER
                   for a in getattr(sem, "args", ()) or ()):
                return True
            if sem.role is APIRole.CREATOR or sem.produces:
                return True
            req = set(getattr(sem, "requires", ()) or ())
            if not any(h not in produced and not idx.producers.get(h)
                       and not idx.recovered_producers.get(h) for h in req):
                return True
            produced |= set(getattr(sem, "produces", ()) or ())
        return False

    def _add(seq: Sequence[str], source: str = "bottomup") -> None:
        cleaned = [a for a in seq if a and a in model.apis]
        if _validity_contract():
            # I2b (Task 8): drop a consumer whose required non-handle value arg
            # the renderer cannot fill non-NULL (and has no producer) — it would
            # render NULL and the library would assert/deref NULL.
            cleaned = [a for a in cleaned
                       if not _i2b_unfillable_consumer(idx.by_name.get(a), idx)]
        if not cleaned:
            return
        # Cross-source profile binding (always-on): inject a synthetic alternate
        # producer before any eligible cross-source CREATOR so its two same-type
        # handles can bind to DIFFERENT producers (cross-profile transform).
        # CREATOR-scoped + name-deny via ``_wants_cross_source`` → a NO-OP on libs
        # without an eligible multi-same-type-handle creator. Chokepoint that sees
        # full sequences incl. prefix-resident creators.
        cleaned = [a for a in _inject_cross_source(cleaned, model, idx)
                   if a in model.apis]
        if _drop_unrunnable and not _runnable(cleaned):
            _n_unrunnable[0] += 1
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
        if _OBJCONSTRUCT_FIRST:
            # LOGICFUZZ_OBJCONSTRUCT_FIRST: prepend data-buildable creators
            # (no INPUT_BUFFER arg) before parser-entry creators so the
            # bottom-up builder visits object-construction subsystems first.
            # Parser-entry targets (idx.entries) follow so they are still
            # covered — breadth is preserved, only visit-order changes.
            _data_buildable = [s for s in idx.creators
                               if not any(a.role is ArgRole.INPUT_BUFFER
                                          for a in s.args)]
            target_pool = _data_buildable + list(idx.entries) + list(idx.consumers) \
                + [s for ms in idx.mutators.values() for s in ms]
        else:
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

        _sibling_rank: Dict[frozenset, int] = {}
        _producer_rank: Dict[str, int] = {}
        _destroyer_rank: Dict[str, int] = {}
        for target in targets:
            n_attempted += 1
            prefix, opened = _build_prefix(target, idx, max_prefix_depth,
                                           producer_rank=_producer_rank)
            # The target itself opens handles if it is also a producer.
            opened = set(opened) | set(target.produces)
            core = prefix + [target.name]
            if _dense:
                _grp = frozenset(opened)
                _rank_i = _sibling_rank.get(_grp, 0)
                _sibling_rank[_grp] = _rank_i + 1
                core = _densify(core, opened, idx, _dense_max_extra,
                                _dense_repeat, _cooccur, sibling_rank=_rank_i)
                if len(core) > len(prefix) + 1:
                    n_densified += 1
            if _exercise_object():
                # Forward 'exercise the object' (per-driver DEPTH): append a
                # fuzz-data consumer for each constructed handle so the object is
                # RUN, not just built+freed. Gate-OFF leaves ``core`` unchanged.
                core = _append_exercisers(core, opened, idx)
            if _scoped_guards():
                # D — reorder ``core`` so its dependency components are
                # CONTIGUOUS (parser+consumers block first, independent producer
                # blocks after). This is a pure REORDERING (every API kept), so
                # the skeleton's per-component scoped-guard rendering (B) is
                # clean. Gate-OFF leaves ``core`` untouched (byte-identical).
                core = [a for comp in _dependency_components(core, model)
                        for a in comp]
            seq = core + _closing_destroyers(opened, idx,
                                             destroyer_rank=_destroyer_rank)
            if _validity_contract():
                seq = _enforce_producer_order(seq, idx)   # I1
            _add(seq)

        # 3. create→destroy coverage for creators no target reached.
        covered = {a for s in seqs for a in s}
        for creator in idx.creators:
            if creator.name in covered:
                continue
            prefix, opened = _build_prefix(creator, idx, max_prefix_depth,
                                           producer_rank=_producer_rank)
            opened = set(opened) | set(creator.produces)
            _core = prefix + [creator.name]
            if _exercise_object():
                # The shallowest chains (pure create→destroy) benefit most from
                # the forward exercise step — these are 'build but never use'.
                _core = _append_exercisers(_core, opened, idx)
            _seq = _core + _closing_destroyers(opened, idx,
                                               destroyer_rank=_destroyer_rank)
            if _validity_contract():
                _seq = _enforce_producer_order(_seq, idx)   # I1
            _add(_seq)

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
        "n_dropped_unrunnable": _n_unrunnable[0],
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
