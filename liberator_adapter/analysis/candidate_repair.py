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
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional, Sequence

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


class RepairEngine:
    """Pluggable chain of repair strategies.

    ``attempt(seq, validator)`` walks the strategy list; the first
    strategy that *changes* the sequence yields a candidate that's
    re-validated. The loop stops at first success or strategy
    exhaustion.

    ``validator`` is a thin callable ``List[str] -> bool`` so the engine
    doesn't depend on the specific factory/Z3/RunningContext stack —
    callers wire whatever validation they want.
    """

    def __init__(
        self,
        graft_fn: Optional[Callable[[List[str]], Optional[List[str]]]] = None,
    ) -> None:
        self._strategies: List[Callable[[List[str]], Optional[RepairAttempt]]] = []
        if graft_fn is not None:
            self._strategies.append(self._make_graft_strategy(graft_fn))

    def _make_graft_strategy(
        self,
        graft_fn: Callable[[List[str]], Optional[List[str]]],
    ) -> Callable[[List[str]], Optional[RepairAttempt]]:
        def strategy(seq: List[str]) -> Optional[RepairAttempt]:
            grafted = graft_fn(seq)
            if grafted is None or grafted == seq:
                return None
            inserted = [a for a in grafted if a not in seq]
            return RepairAttempt(
                strategy=RepairStrategy.GRAFT_CREATOR_PREFIX,
                original_sequence=list(seq),
                repaired_sequence=list(grafted),
                inserted_apis=inserted,
                success=False,  # caller flips to True after re-validation
            )
        return strategy

    def attempt(
        self,
        seq: Sequence[str],
        revalidate: Callable[[List[str]], bool],
        candidate_index: int = -1,
    ) -> CandidateRepairTrace:
        """Run strategies until one yields a re-validatable sequence.

        ``revalidate`` is the caller's "would this new sequence pass the
        validator stack now?" predicate. Returns ``True`` iff the
        repaired sequence is acceptable; the engine records the result
        on the attempt and stops.
        """
        seq_list = list(seq)
        trace = CandidateRepairTrace(
            candidate_index=candidate_index,
            original_sequence=seq_list,
        )
        for strategy in self._strategies:
            attempt = strategy(seq_list)
            if attempt is None:
                continue
            try:
                accepted = bool(revalidate(attempt.repaired_sequence or []))
            except Exception as exc:
                accepted = False
                attempt.rejection_reason = f"revalidate raised {type(exc).__name__}: {exc}"
            attempt.success = accepted
            if not accepted and not attempt.rejection_reason:
                attempt.rejection_reason = "revalidate returned False"
            trace.attempts.append(attempt)
            if accepted:
                trace.final_success = True
                trace.final_sequence = attempt.repaired_sequence
                return trace
        return trace
