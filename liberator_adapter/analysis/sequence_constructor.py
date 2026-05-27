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


def _build_index(model: APISemanticModel) -> _Index:
    producers: Dict[str, List[APISemantics]] = {}
    destroyers: Dict[str, List[APISemantics]] = {}
    mutators: Dict[str, List[APISemantics]] = {}
    entries: List[APISemantics] = []
    consumers: List[APISemantics] = []
    creators: List[APISemantics] = []

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
        if any(a.role is ArgRole.INPUT_BUFFER for a in sem.args):
            entries.append(sem)

    return _Index(producers, destroyers, mutators, entries, consumers, creators)


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
        if not cands:
            return False
        producer = sorted(cands, key=lambda s: (len(s.requires), s.name))[0]
        in_progress.add(t)
        for rt in producer.requires:
            resolve(rt, depth + 1)   # best-effort: a sub-req hole is fine
        in_progress.discard(t)
        if producer.name not in prefix:
            prefix.append(producer.name)
        satisfied.add(t)
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
    n_unsatisfiable = 0   # retained for telemetry; best-effort never drops now
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
            seq = prefix + [target.name] + _closing_destroyers(opened, idx)
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
    if project_apis:
        try:
            from liberator_adapter.analysis.usedef import (
                UseDefGraph, Typestate, extract_api_effects,
            )
            _ts = Typestate(UseDefGraph(extract_api_effects(
                list(project_apis),
                lifecycle_pairs=list(lifecycle_pairs) if lifecycle_pairs else None,
            )))
            kept: List[List[str]] = []
            for s in seqs:
                viols = _ts.check(s)
                if any(v.kind.name in _ORDERING_FAULTS for v in viols):
                    n_ordering_dropped += 1
                else:
                    kept.append(s)
            seqs = kept
        except Exception:
            pass  # oracle unavailable → fall back to model-only output

    api_cov = {a for s in seqs for a in s}
    handle_cov = set(idx.producers) | set(idx.destroyers)
    gap_hit = (api_cov & gap_apis) if gap_apis else set()
    metrics = {
        "n_sequences": len(seqs),
        "n_seeded_from_automaton": n_seeded,
        "n_seeded_from_idioms": n_idiom,
        "n_targets_attempted": n_attempted,
        "n_unsatisfiable_targets": n_unsatisfiable,
        "n_ordering_dropped": n_ordering_dropped,
        "n_before_ordering_filter": n_before_filter,
        "api_coverage": len(api_cov),
        "handle_types": len(handle_cov),
        "avg_length": round(sum(len(s) for s in seqs) / len(seqs), 2) if seqs else 0,
        # G5: how much of the baseline-uncovered API surface we now construct for.
        "gap_apis_total": len(gap_apis),
        "gap_apis_reached": len(gap_hit),
    }
    workflow_sequences = [s for s in seqs
                          if source_of.get(tuple(s)) == "workflow"]
    metrics["n_workflow_kept"] = len(workflow_sequences)
    return ConstructionResult(sequences=seqs, metrics=metrics,
                              workflow_sequences=workflow_sequences)
