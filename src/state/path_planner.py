"""Path-aware Planner — Phase D of the 5-stage system redesign.

LogicFuzz's candidate generation has historically been L4: type-flow
graph + random walk + greedy max-coverage on API *names*. L4 is
**structure-naive** — it doesn't know which paths the resulting drivers
will actually trigger when fuzzed, and it doesn't know which library
idioms (Phase B) the candidates align with.

The Planner sits between L4 and Z3 skeleton synthesis. It:

1. **Scores each L4 candidate** along several axes (idiom alignment,
   coverage-frontier alignment if frontier data is present, repair
   provenance from past iterations).
2. **Reorders** so the highest-leverage candidates are tried first.
3. **Synthesizes missing candidates**: when a high-confidence idiom
   (e.g. ``context_null_pass`` on lcms) doesn't appear in any L4
   output, emit a synthetic candidate that *does* match it, so the
   prototyper gets the option.

It does **not** drop L4 candidates. L4 is a noisy oracle; the
Planner adds signal, not replacement.

Phase D is the first stage to actively *consume* the multi-iteration
state (CoverageMemory): it idiom-aligns and reranks L4 candidates and
synthesizes missing ones. When the CEGAR loop driver lands (Phase C
completion), Phase D will read the path frontier and plan candidates
targeting it directly.

State produced (for Phase E and operator inspection):
  ``results/<project>/state/plan_ledger.json`` — per-candidate
  rationale, score, and provenance (L4-original vs Planner-synthesized).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


class CandidateOrigin(Enum):
    L4_RANDOM_WALK = "l4_random_walk"
    PLANNER_SYNTHESIZED = "planner_synthesized"


@dataclass
class CandidatePlan:
    """One planned candidate sequence with its rationale.

    The Planner attaches this to every candidate flowing into Z3
    synthesis. Downstream layers (Phase A repair, Phase E shape) see
    the plan and can adjust their behaviour — e.g. shape can pick
    "long+deep" for a candidate whose plan targets a deep-parse path.
    """
    sequence_names: List[str]
    origin: CandidateOrigin
    score: float
    rationale: List[str] = field(default_factory=list)
    matched_idioms: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['origin'] = self.origin.value
        return d


@dataclass
class PlanLedger:
    """All Planner decisions for one iteration."""
    project: str
    candidate_count_in: int = 0
    candidate_count_out: int = 0
    plans: List[CandidatePlan] = field(default_factory=list)
    synthesized_count: int = 0
    reordered: bool = False

    def add(self, plan: CandidatePlan) -> None:
        self.plans.append(plan)

    def to_dict(self) -> dict:
        return {
            'project': self.project,
            'candidate_count_in': self.candidate_count_in,
            'candidate_count_out': self.candidate_count_out,
            'synthesized_count': self.synthesized_count,
            'reordered': self.reordered,
            'plans': [p.to_dict() for p in self.plans],
        }

    def persist(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Idiom → candidate alignment
# ---------------------------------------------------------------------------

_API_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def _api_names_in_snippet(snippet: str) -> Set[str]:
    """Return API names that look like function calls in the snippet."""
    return set(_API_RE.findall(snippet or ""))


def _score_candidate_against_idioms(
    sequence_names: Sequence[str],
    idioms: List[dict],
) -> Tuple[float, List[str], List[str]]:
    """Return (score, rationale, matched_idiom_kinds) for one candidate.

    Scoring weights are calibrated so single-hit "highly actionable"
    idioms (CONTEXT_NULL_PASS, CLEANUP_PAIR) outweigh multiple hits of
    weaker idioms (HEADER_FLAG_DEMUX, DATA_OFFSET_PARSE).
    """
    seq_set = set(sequence_names)
    score = 0.0
    rationale: List[str] = []
    matched_kinds: List[str] = []

    # Per-kind alignment rules. Each rule reads idiom snippets and
    # checks whether the candidate contains the implicated API(s).
    weights = {
        'context_null_pass': 0.6,
        'cleanup_pair': 0.5,
        'min_size_guard': 0.0,        # affects shape, not candidate selection
        'null_termination_required': 0.0,
        'buffer_copy': 0.0,
        'null_terminate_input': 0.0,
        'data_offset_parse': 0.0,
        'header_flag_demux': 0.0,
        'header_body_split': 0.0,
        'size_cap': 0.0,
    }

    for idiom in idioms:
        kind = str(idiom.get('kind') or '')
        if not kind:
            continue
        w = weights.get(kind, 0.0)
        if w == 0.0:
            continue
        snippet_apis = _api_names_in_snippet(idiom.get('snippet', ''))
        hits = snippet_apis & seq_set
        if hits:
            score += w
            rationale.append(
                f"{kind}: candidate contains {sorted(hits)[0]}")
            matched_kinds.append(kind)

    # Diversity bonus: shorter sequences risk missing context; longer
    # sequences over-constrain Z3. Light prior in favour of 5-10 length.
    L = len(sequence_names)
    if 5 <= L <= 10:
        score += 0.1
        rationale.append("length-band 5-10 preferred")

    return score, rationale, matched_kinds


def _idioms_implicating_apis(
    idioms: List[dict],
    kinds: Set[str],
) -> Set[str]:
    """Collect API names mentioned by idioms of the requested kinds.

    Used by ``synthesize_missing`` to surface APIs the planner knows are
    "important per baseline" but absent from L4's pool.
    """
    names: Set[str] = set()
    for idiom in idioms:
        if idiom.get('kind') not in kinds:
            continue
        names |= _api_names_in_snippet(idiom.get('snippet', ''))
    return names


# ---------------------------------------------------------------------------
# Planner entry point
# ---------------------------------------------------------------------------

class PathPlanner:
    """Reorder and optionally augment L4 candidates.

    Inputs:
      - ``target_sequences``: L4's output, list of API-name lists
        (string-only — the planner doesn't need Api objects).
      - ``idioms``: Phase B output. ``{'idioms': [...]}`` shape (the
        dict from ``IdiomLibrary.to_dict()``).
      - ``project_api_names``: full project API set, for synthesis.

    Outputs:
      - Reordered list of sequences (by score descending).
      - PlanLedger with full decision trace.
    """

    def __init__(self, project: str) -> None:
        self.project = project

    def plan(
        self,
        target_sequences: List[List[str]],
        idioms_payload: Optional[Dict[str, Any]] = None,
        project_api_names: Optional[Set[str]] = None,
        max_synth: int = 2,
    ) -> Tuple[List[List[str]], PlanLedger]:
        ledger = PlanLedger(
            project=self.project,
            candidate_count_in=len(target_sequences),
        )
        idioms = (idioms_payload or {}).get('idioms', []) or []

        scored: List[Tuple[float, List[str], CandidatePlan]] = []
        for seq in target_sequences:
            score, rationale, matched = _score_candidate_against_idioms(
                seq, idioms)
            scored.append((score, list(seq), CandidatePlan(
                sequence_names=list(seq),
                origin=CandidateOrigin.L4_RANDOM_WALK,
                score=score,
                rationale=rationale,
                matched_idioms=matched,
            )))

        # Sort descending by score; stable so equal-score keeps L4 order
        # (which already encodes L4's max-coverage greediness).
        original_order = [s[1] for s in scored]
        scored.sort(key=lambda s: -s[0])
        reordered_seqs = [s[1] for s in scored]
        for _, _, plan in scored:
            ledger.add(plan)
        ledger.reordered = reordered_seqs != original_order

        # Synthesize: idioms implicate APIs nobody in L4 reached.
        if project_api_names:
            synthesized = self._synthesize_missing(
                idioms=idioms,
                covered_apis={n for seq in target_sequences for n in seq},
                project_api_names=project_api_names,
                max_synth=max_synth,
            )
            for synth_seq in synthesized:
                reordered_seqs.append(synth_seq)
                plan = CandidatePlan(
                    sequence_names=list(synth_seq),
                    origin=CandidateOrigin.PLANNER_SYNTHESIZED,
                    score=0.0,
                    rationale=["L4 missed an idiom-implicated API"],
                    matched_idioms=[],
                )
                ledger.add(plan)
                ledger.synthesized_count += 1

        ledger.candidate_count_out = len(reordered_seqs)
        return reordered_seqs, ledger

    def _synthesize_missing(
        self,
        idioms: List[dict],
        covered_apis: Set[str],
        project_api_names: Set[str],
        max_synth: int,
    ) -> List[List[str]]:
        """Emit minimal candidate sequences for idioms whose APIs are
        absent from L4's output.

        Conservative: only emits a 1-element sequence (the idiom-named
        API alone). The repair engine will graft a creator prefix if
        needed; the LLM prototyper will flesh out the rest.
        """
        synth: List[List[str]] = []
        idiom_apis = _idioms_implicating_apis(
            idioms,
            kinds={'context_null_pass'},  # most directly actionable
        )
        missing = idiom_apis - covered_apis
        # Only synthesize for APIs that actually exist in the project.
        for name in sorted(missing):
            if name in project_api_names:
                synth.append([name])
                if len(synth) >= max_synth:
                    break
        return synth


def plan_and_persist(
    project: str,
    target_sequences: List[List[str]],
    idioms_payload: Optional[Dict[str, Any]] = None,
    project_api_names: Optional[Set[str]] = None,
    state_dir: Optional[Path] = None,
    max_synth: int = 2,
) -> Tuple[List[List[str]], PlanLedger]:
    """Convenience: run the planner and persist the ledger."""
    planner = PathPlanner(project=project)
    out_seqs, ledger = planner.plan(
        target_sequences=target_sequences,
        idioms_payload=idioms_payload,
        project_api_names=project_api_names,
        max_synth=max_synth,
    )
    if state_dir is None:
        state_dir = Path('results') / project / 'state'
    try:
        ledger.persist(state_dir / 'plan_ledger.json')
        logger.info(
            "Planner: %d in → %d out (synthesized=%d, reordered=%s) for %s",
            ledger.candidate_count_in, ledger.candidate_count_out,
            ledger.synthesized_count, ledger.reordered, project,
        )
    except Exception as exc:
        logger.warning("PlanLedger persist failed (non-critical): %s", exc)
    return out_seqs, ledger
