"""Candidate Repair Engine — Phase A of the 5-stage system redesign.

When the structure-naive L4 random walk emits a sequence that fails Z3
lifecycle validation or RunningContext binding, the legacy behaviour is
"drop and continue". This module changes that to **repair-or-drop**:
each rejected candidate goes through a chain of repair strategies; only
the structurally unrepairable ones are finally dropped.

Strategies (extensible registry; first matching applies):

- **GraftCreatorPrefix**: when a USE-on-T at any position has no prior
  CREATE-on-T, prepend the canonical creator of T from the project
  automaton's `UseDefGraph.roots`. Closes the most common L4 failure
  mode (cjson seq 3/6/9, lcms 8/9 of all rejections).

- (Future) **TopologicalReorder**: when sequence elements are all
  legitimate but in the wrong order, reorder them along the
  CREATE→USE→DELETE partial order.

- (Future) **NullableHandleFill**: when RunningContext rejects an arg
  whose IR type is tagged nullable (cmsContext etc.), inject a NULL
  binding.

- (Future) **SketchFill**: when a CREATE→USE chain has a gap (USE'd
  type isn't anyone's CREATE in the sequence), insert an intermediate
  API from the type-flow graph's shortest path.

Each repair attempt is recorded structurally so downstream phases can
consume the data:

- **Phase B (Distillation)**: learns which "missing pieces" L4 typically
  emits, informs idiom mining.
- **Phase C (CEGAR)**: tracks repair rate as a saturation signal — if
  repair rate stays high across iterations, planner is biased away from
  patterns needing repair.
- **Phase D (Planner)**: avoids generating candidates that would require
  repair in the first place.

The RepairLog is serialized to ``results/<project>/state/repair_log.json``
for inspection and cross-iteration aggregation.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)


class RepairStrategy(Enum):
    """Catalogue of repair strategy identifiers. Extensible."""
    GRAFT_CREATOR_PREFIX = "graft_creator_prefix"
    TOPOLOGICAL_REORDER = "topological_reorder"  # not yet implemented
    NULLABLE_HANDLE_FILL = "nullable_handle_fill"  # not yet implemented
    SKETCH_FILL = "sketch_fill"  # not yet implemented


@dataclass
class RepairAttempt:
    """One repair strategy's application to one candidate.

    The repaired sequence (if any) goes back through the validator chain;
    a successful repair means the validator subsequently accepted it.
    """
    strategy: RepairStrategy
    original_sequence: List[str]
    repaired_sequence: Optional[List[str]] = None
    inserted_apis: List[str] = field(default_factory=list)
    reorder_map: Optional[List[int]] = None
    bound_nullable_args: List[str] = field(default_factory=list)
    success: bool = False
    rejection_reason: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['strategy'] = self.strategy.value
        return d


@dataclass
class CandidateRepairTrace:
    """All repair attempts on a single candidate, in order."""
    candidate_index: int
    original_sequence: List[str]
    attempts: List[RepairAttempt] = field(default_factory=list)
    final_success: bool = False
    final_sequence: Optional[List[str]] = None

    def to_dict(self) -> dict:
        return {
            'candidate_index': self.candidate_index,
            'original_sequence': self.original_sequence,
            'attempts': [a.to_dict() for a in self.attempts],
            'final_success': self.final_success,
            'final_sequence': self.final_sequence,
        }


@dataclass
class RepairLog:
    """Aggregate record of all repair activity in one synthesis batch.

    Persisted as JSON for Phase B/C/D to consume. Counters at the top
    let operators eyeball "is repair carrying weight" without parsing the
    full per-candidate detail.
    """
    candidates_total: int = 0
    candidates_accepted_no_repair: int = 0
    candidates_repaired_success: int = 0
    candidates_unrepairable: int = 0
    by_strategy_success: dict = field(default_factory=dict)
    by_strategy_attempt: dict = field(default_factory=dict)
    traces: List[CandidateRepairTrace] = field(default_factory=list)

    def record(self, trace: CandidateRepairTrace) -> None:
        self.candidates_total += 1
        if trace.final_success:
            if any(a.success for a in trace.attempts):
                self.candidates_repaired_success += 1
            else:
                self.candidates_accepted_no_repair += 1
        else:
            self.candidates_unrepairable += 1
        for a in trace.attempts:
            self.by_strategy_attempt[a.strategy.value] = \
                self.by_strategy_attempt.get(a.strategy.value, 0) + 1
            if a.success:
                self.by_strategy_success[a.strategy.value] = \
                    self.by_strategy_success.get(a.strategy.value, 0) + 1
        self.traces.append(trace)

    def to_dict(self) -> dict:
        return {
            'summary': {
                'candidates_total': self.candidates_total,
                'candidates_accepted_no_repair': self.candidates_accepted_no_repair,
                'candidates_repaired_success': self.candidates_repaired_success,
                'candidates_unrepairable': self.candidates_unrepairable,
                'by_strategy_attempt': self.by_strategy_attempt,
                'by_strategy_success': self.by_strategy_success,
            },
            'traces': [t.to_dict() for t in self.traces],
        }

    def persist(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────────────
# Idiom-aware preference filter (F1, 2026-05-23)
# ─────────────────────────────────────────────────────────────────────
#
# When Phase B idioms are available, the graft strategy uses them to
# prefer "idiom-blessed" root producers over whatever's at the top of
# UseDefGraph.roots(). Concretely, an API is idiom-blessed if it appears
# in an idiom's snippet for any of these kinds:
#
#   cleanup_pair          — the init half (e.g. ``foo_init(...)``)
#   context_null_pass     — the API name (e.g. ``cmsOpenProfileFromMem``)
#   buffer_copy           — sometimes implies a buffer-creator
#   data_offset_parse     — typically the parser entry
#
# On lcms, IR mod/ref tags ``cmsFreeToneCurveTriple`` as CREATE because
# its body internally allocates then frees. Without idioms, ``roots()``
# can rank that ahead of ``cmsCreateContext``. With idioms,
# ``cmsCreateContext`` is preferred because it appears in a
# ``context_null_pass`` snippet.

_API_NAME_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

_PREFERRED_IDIOM_KINDS = frozenset({
    "cleanup_pair",
    "context_null_pass",
    "data_offset_parse",
    "buffer_copy",
})


def extract_idiom_blessed_apis(idioms_payload: Optional[Dict[str, Any]]) -> Set[str]:
    """Return API names mentioned in Phase B idiom snippets.

    Only idioms of "creator-relevant" kinds contribute. Idioms about
    input shape (min_size_guard, null_termination_required, etc.)
    don't influence creator selection — they affect the Prototyper's
    LLVMFuzzerTestOneInput body, not the API sequence.
    """
    blessed: Set[str] = set()
    if not idioms_payload:
        return blessed
    for idiom in (idioms_payload.get('idioms') or []):
        if idiom.get('kind') not in _PREFERRED_IDIOM_KINDS:
            continue
        snippet = str(idiom.get('snippet') or '')
        for m in _API_NAME_RE.finditer(snippet):
            blessed.add(m.group(1))
    return blessed


class RepairEngine:
    """Pluggable chain of repair strategies.

    ``attempt(seq, validator)`` walks the strategy list; the first
    strategy that *changes* the sequence yields a candidate that's
    re-validated. The loop stops at first success or strategy
    exhaustion.

    ``validator`` is a thin callable ``List[str] -> bool`` so the engine
    doesn't depend on the specific factory/Z3/RunningContext stack —
    callers wire whatever validation they want.

    Phase A F1 (2026-05-23): ``idioms_payload`` lets the engine query
    Phase B's distilled idioms when picking among multiple candidate
    root producers in the graft strategy. See ``extract_idiom_blessed_apis``
    for which idiom kinds inform creator choice.
    """

    # ``MAX_GRAFT_RETRIES`` (F2 2026-05-23): per-candidate cap on how
    # many distinct grafted-creator combinations to try before giving
    # up. Top-K=3 in graft_creator_prefix bounds the per-position
    # alternatives, but multi-handle sequences can multiply quickly —
    # cap so a stubborn candidate doesn't burn budget.
    MAX_GRAFT_RETRIES = 4

    def __init__(
        self,
        graft_fn: Optional[Callable[..., Optional[List[str]]]] = None,
        idioms_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        # ``_strategies`` items are generators yielding zero or more
        # ``RepairAttempt`` per candidate. The engine walks each
        # generator until one yields an attempt that revalidates.
        self._strategies: List[Callable[[List[str]],
                                         Iterable[RepairAttempt]]] = []
        self._idiom_blessed: Set[str] = extract_idiom_blessed_apis(idioms_payload)
        if graft_fn is not None:
            self._strategies.append(self._make_graft_strategy(graft_fn))

    def _make_graft_strategy(
        self,
        graft_fn: Callable[..., Optional[List[str]]],
    ) -> Callable[[List[str]], Iterable[RepairAttempt]]:
        """Wrap ``graft_fn`` to yield up to ``MAX_GRAFT_RETRIES`` repair
        attempts per candidate — each with a different set of grafted
        creators.

        Loop:
          1. Try idiom-blessed roots (F1).
          2. If revalidate fails, exclude the chosen creators and ask
             graft again for an alternative.
          3. After the engine's outer loop sees revalidate fail, the
             engine calls the generator again (via ``next``); we then
             yield the next attempt with the failed creators excluded.

        Backward compat: if the underlying ``graft_fn`` doesn't accept
        ``exclude_filter`` (older API), we degrade gracefully —
        yield the single F1-only attempt.
        """
        blessed = self._idiom_blessed
        max_retries = self.MAX_GRAFT_RETRIES

        def _call_graft(
            seq: List[str],
            excluded: Set[str],
        ) -> Optional[List[str]]:
            """Call graft_fn with whatever kwargs it accepts."""
            kwargs: Dict[str, Any] = {}
            if blessed:
                kwargs['prefer_filter'] = lambda name: name in blessed
            if excluded:
                kwargs['exclude_filter'] = lambda name: name in excluded
            if not kwargs:
                return graft_fn(seq)
            try:
                return graft_fn(seq, **kwargs)
            except TypeError:
                # Older API; degrade — drop kwargs incrementally.
                if 'exclude_filter' in kwargs:
                    kwargs.pop('exclude_filter')
                    try:
                        return graft_fn(seq, **kwargs)
                    except TypeError:
                        pass
                return graft_fn(seq)

        def strategy(seq: List[str]) -> Iterable[RepairAttempt]:
            excluded: Set[str] = set()
            previous_inserted: Optional[List[str]] = None
            for retry_idx in range(max_retries):
                grafted = _call_graft(seq, excluded)
                if grafted is None or grafted == seq:
                    return
                inserted = [a for a in grafted if a not in seq]
                if not inserted:
                    return
                # If we already excluded these inserts but graft returned
                # the same answer, the underlying API is ignoring our
                # exclude_filter (legacy graft, or a stuck strategy).
                # Stop retrying — further iterations would be noise.
                if retry_idx > 0 and previous_inserted == inserted:
                    return
                previous_inserted = list(inserted)
                blessed_hits = [a for a in inserted if a in blessed]
                note_parts = []
                if blessed_hits:
                    note_parts.append(f"idiom-blessed: {blessed_hits}")
                if retry_idx > 0:
                    note_parts.append(f"retry #{retry_idx} (excluding {sorted(excluded)})")
                yield RepairAttempt(
                    strategy=RepairStrategy.GRAFT_CREATOR_PREFIX,
                    original_sequence=list(seq),
                    repaired_sequence=list(grafted),
                    inserted_apis=inserted,
                    success=False,  # engine flips after revalidation
                    rejection_reason="; ".join(note_parts),
                )
                # If this attempt didn't succeed, exclude its inserts
                # before the next iteration so we try a different root.
                excluded.update(inserted)
        return strategy

    def attempt(
        self,
        seq: Sequence[str],
        revalidate: Callable[[List[str]], bool],
        candidate_index: int = -1,
    ) -> CandidateRepairTrace:
        """Run strategies until one yields a re-validatable sequence.

        Strategies are now generators yielding zero or more
        ``RepairAttempt`` per candidate (Phase A F2, 2026-05-23). The
        engine walks each generator, revalidates each yielded attempt,
        and stops at the first acceptance.

        ``revalidate`` is the caller's "would this new sequence pass the
        validator stack now?" predicate.
        """
        seq_list = list(seq)
        trace = CandidateRepairTrace(
            candidate_index=candidate_index,
            original_sequence=seq_list,
        )
        for strategy in self._strategies:
            for attempt in strategy(seq_list):
                # ``attempt`` is a fresh RepairAttempt; revalidate, then
                # decide whether to keep looking.
                try:
                    accepted = bool(revalidate(attempt.repaired_sequence or []))
                except Exception as exc:
                    accepted = False
                    extra = (f"revalidate raised "
                             f"{type(exc).__name__}: {exc}")
                    attempt.rejection_reason = (
                        attempt.rejection_reason + " | " + extra
                        if attempt.rejection_reason else extra
                    )
                attempt.success = accepted
                if not accepted and not attempt.rejection_reason:
                    attempt.rejection_reason = "revalidate returned False"
                trace.attempts.append(attempt)
                if accepted:
                    trace.final_success = True
                    trace.final_sequence = attempt.repaired_sequence
                    return trace
            # Strategy exhausted; try next strategy.
        return trace
