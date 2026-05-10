"""
L4: Coverage Ranker - Rank and select sequences by coverage potential.

Uses a principled approach without empirical weights:
1. Hierarchical sorting (B): diversity -> entry point position -> length
2. Greedy selection (D): maximize API coverage in selected set

This is the fourth filter in the Progressive Filter Pipeline:
    L0 (Type) -> L1 (Entry Point) -> L2 (Lifecycle) -> L3 (StateMachine) -> L4 (Ranking)

Design principles:
1. No empirical weights - all rules are deterministic and explainable
2. Diversity = coverage potential (more unique APIs = more code paths)
3. Greedy selection maximizes marginal contribution
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class SequenceScore:
    """Score breakdown for a single sequence."""

    sequence: List[str]

    # Primary: API diversity (unique_apis / length)
    diversity_score: float

    # Secondary: Entry point position (lower is better, -1 if no entry point)
    entry_point_position: int

    # Tertiary: Sequence length
    length: int

    # Quaternary (optional, project-adaptive): automaton acceptance.
    # 1.0 = sequence is a fully accepted path through the project's learned
    # protocol automaton; 0.0 = automaton has the sequence labels but breaks
    # on at least one transition; -1.0 = no automaton available (signal off).
    # Defaults keep behavior unchanged when no automaton is provided.
    automaton_acceptance: float = -1.0

    # Metadata
    unique_api_count: int = 0
    has_entry_point: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sequence': self.sequence,
            'diversity_score': round(self.diversity_score, 4),
            'entry_point_position': self.entry_point_position,
            'length': self.length,
            'unique_api_count': self.unique_api_count,
            'has_entry_point': self.has_entry_point,
            'automaton_acceptance': self.automaton_acceptance,
        }


@dataclass
class CoverageRankingResult:
    """Result of coverage ranking and selection."""

    # All sequences with scores, sorted by rank
    ranked_sequences: List[SequenceScore] = field(default_factory=list)

    # Selected top-k sequences (greedy max coverage)
    selected_sequences: List[List[str]] = field(default_factory=list)

    # APIs covered by selected sequences
    total_api_coverage: Set[str] = field(default_factory=set)

    # Selection metadata
    selection_stats: Dict[str, Any] = field(default_factory=dict)

    def get_stats(self) -> Dict[str, Any]:
        return {
            'total_sequences': len(self.ranked_sequences),
            'selected_count': len(self.selected_sequences),
            'api_coverage_count': len(self.total_api_coverage),
            'avg_diversity': (
                sum(s.diversity_score for s in self.ranked_sequences) / len(self.ranked_sequences)
                if self.ranked_sequences else 0
            ),
            **self.selection_stats,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ranked_sequences': [s.to_dict() for s in self.ranked_sequences[:20]],  # Top 20 for brevity
            'selected_sequences': self.selected_sequences,
            'total_api_coverage': list(self.total_api_coverage),
            'stats': self.get_stats(),
        }


# =============================================================================
# Coverage Ranker
# =============================================================================

class CoverageRanker:
    """
    L4 Filter: Rank sequences by coverage potential and select Top-K.

    Ranking approach (no empirical weights):
    1. Primary: API diversity = unique_apis / sequence_length
    2. Secondary: Entry point position (earlier is better)
    3. Tertiary: Sequence length (longer covers more)

    Selection approach:
    - Greedy selection maximizing marginal API coverage
    - Each selected sequence should contribute new API coverage

    Usage:
        ranker = CoverageRanker()
        result = ranker.rank_and_select(
            sequences, entry_point_names, top_k=10
        )
    """

    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        """Initialize Coverage Ranker."""
        self.log = logger_instance or logger

    def rank_and_select(
        self,
        sequences: List[List[str]],
        entry_point_names: Optional[Set[str]] = None,
        top_k: int = 10,
        automaton_acceptance_fn: Optional[Any] = None,
        automaton_graft_fn: Optional[Any] = None,
        automaton_sample_paths: Optional[List[List[str]]] = None,
        automaton_post_extend_fn: Optional[Any] = None,
        post_extend_max_inputs: int = 12,
        length_floor_safe_apis: Optional[Set[str]] = None,
    ) -> CoverageRankingResult:
        """
        Rank sequences and select top-k with maximum coverage.

        Args:
            sequences: List of API name sequences (after L1-L3 filtering).
            entry_point_names: Set of entry point API names (from L1).
            top_k: Number of sequences to select.
            automaton_acceptance_fn: Optional ``Callable[[List[str]], float]``
                returning an acceptance score in ``[0.0, 1.0]`` from the
                project-adaptive automaton.
            automaton_graft_fn: Optional ``Callable[[List[str]], Optional[List[str]]]``
                that returns a creator-prefix-grafted version of an
                unaccepted candidate (or ``None``). Used to *ground*
                candidates whose first call USEs a handle without an
                upstream DEF; reuses the project's existing creator lookup.
            automaton_sample_paths: Optional list of paths sampled directly
                from the merged automaton. These are guaranteed acc=1.0
                accepting paths (often EDSM-merged combinations not in any
                single trace) and are mixed into the candidate pool to
                augment L0–L4 synthesis with project-witnessed protocols.
            length_floor_safe_apis: Optional set of API names that are
                *safe* to appear as a length-1 sequence — typically the
                APIs whose ``APIEffect.use`` is empty (no upstream handle
                required). When supplied, length-1 sequences whose API is
                NOT in this set are dropped before scoring. This is the
                "method B" defensive guard: even if an upstream stage
                accidentally emits ``[ucl_parser_add_chunk]`` (an indirect
                consumer with empty creator-prefix), L4 will not pick it.

        When ``automaton_acceptance_fn`` is supplied the sort key promotes
        acceptance to a *secondary* axis (right after diversity), so
        high-acceptance grafted candidates beat type-only-feasible ones at
        equal diversity. When unset, the secondary axis is the legacy
        entry_point_position so this stays a strict superset of historical
        behaviour.

        Returns:
            CoverageRankingResult with ranked and selected sequences.
        """
        if not sequences and not automaton_sample_paths:
            return CoverageRankingResult()

        entry_points = entry_point_names or set()

        # Step 0: defensive length-floor on the *input* candidate pool.
        # A length-1 sequence is only meaningful when its single API can
        # accept fuzzer data without upstream handle setup (i.e. it's a
        # genuine direct entry point with no USE'd handles). Anything else
        # — typically indirect consumers slipping through L1 because their
        # name happened to land in entry_point_names — would NULL-deref at
        # runtime. We drop such sequences here before scoring.
        if length_floor_safe_apis is not None and sequences:
            kept: List[List[str]] = []
            n_dropped = 0
            for s in sequences:
                if len(s) == 1 and s[0] not in length_floor_safe_apis:
                    n_dropped += 1
                    continue
                kept.append(s)
            if n_dropped:
                self.log.debug(
                    "Length-floor dropped %d/%d length-1 sequences whose API "
                    "is not in the safe direct-EP set",
                    n_dropped, len(sequences),
                )
            sequences = kept

        # Step 1a: candidate pool augmentation.
        # Two augmentations: automaton-sampled paths (high-precision seeds)
        # and creator-grafted versions of unaccepted L0–L4 candidates. We
        # dedupe so we don't double-count an L0–L4 sequence that happens to
        # equal one of the automaton's sampled paths.
        augmented: List[List[str]] = list(sequences)
        seen = {tuple(s) for s in augmented}
        if automaton_sample_paths:
            for p in automaton_sample_paths:
                key = tuple(p)
                if key not in seen:
                    augmented.append(list(p))
                    seen.add(key)
        if automaton_graft_fn is not None and automaton_acceptance_fn is not None:
            for s in list(sequences):
                try:
                    if automaton_acceptance_fn(s) >= 0.999:
                        continue  # already accepted, no graft needed
                    grafted = automaton_graft_fn(s)
                except Exception:
                    grafted = None
                if grafted is None:
                    continue
                key = tuple(grafted)
                if key not in seen:
                    augmented.append(grafted)
                    seen.add(key)

        # Step 1c: Post-DEF extension augmentation (Phase E).
        # For each L0–L4 surviving sequence, ask the automaton/typestate to
        # enumerate downstream consumer chains. This is the missing-tail
        # complement of ``graft_creator_prefix`` (which adds an upstream
        # prefix). Together they let L4 consider both halves of a protocol
        # (constructor… and …downstream) that L0 type generation cut off.
        # Capped at ``post_extend_max_inputs`` source sequences so synthesis
        # cost stays linear in K, not in |sequences|.
        n_post_extend_added = 0
        if automaton_post_extend_fn is not None and sequences:
            sources = list(sequences)[:post_extend_max_inputs]
            for s in sources:
                try:
                    extras = automaton_post_extend_fn(s) or []
                except Exception as exc:
                    self.log.debug("post-extend failed for %s: %s", s, exc)
                    extras = []
                for ext in extras:
                    key = tuple(ext)
                    if key not in seen:
                        augmented.append(list(ext))
                        seen.add(key)
                        n_post_extend_added += 1
        self._post_extend_added = n_post_extend_added

        # Step 1d: Score all (augmented) sequences.
        scored = [
            self._score_sequence(seq, entry_points, automaton_acceptance_fn)
            for seq in augmented
        ]

        # Step 2: Hierarchical sort.
        # When automaton is provided, acceptance becomes the secondary axis
        # right after diversity (high-acceptance wins at equal diversity).
        # When no automaton, secondary stays entry_point_position (legacy).
        if automaton_acceptance_fn is not None:
            sort_key = lambda s: (
                -s.diversity_score,
                -s.automaton_acceptance,
                s.entry_point_position if s.entry_point_position >= 0 else float('inf'),
                -s.length,
            )
        else:
            sort_key = lambda s: (
                -s.diversity_score,
                s.entry_point_position if s.entry_point_position >= 0 else float('inf'),
                -s.length,
            )
        ranked = sorted(scored, key=sort_key)

        # Step 3: Greedy selection for maximum coverage
        selected, coverage, selection_stats = self._greedy_select(ranked, top_k)

        result = CoverageRankingResult(
            ranked_sequences=ranked,
            selected_sequences=selected,
            total_api_coverage=coverage,
            selection_stats=selection_stats,
        )

        self.log.debug(
            f"Coverage Ranking: {len(sequences)} sequences -> "
            f"{len(selected)} selected, {len(coverage)} APIs covered"
        )

        return result

    def _score_sequence(
        self,
        sequence: List[str],
        entry_points: Set[str],
        automaton_acceptance_fn: Optional[Any] = None,
    ) -> SequenceScore:
        """
        Score a single sequence.

        Args:
            sequence: List of API names.
            entry_points: Set of entry point API names.
            automaton_acceptance_fn: Optional fn returning an acceptance score
                in ``[0.0, 1.0]``. If unset, the score field is left at -1.0
                (sentinel = signal disabled).

        Returns:
            SequenceScore with all metrics.
        """
        unique_apis = set(sequence)
        length = len(sequence)

        # Primary: Diversity score
        diversity_score = len(unique_apis) / length if length > 0 else 0

        # Secondary: Entry point position (-1 if no entry point)
        entry_point_position = -1
        has_entry_point = False
        for i, api in enumerate(sequence):
            if api in entry_points:
                entry_point_position = i
                has_entry_point = True
                break

        automaton_acceptance = -1.0
        if automaton_acceptance_fn is not None:
            try:
                v = automaton_acceptance_fn(sequence)
                if isinstance(v, (int, float)):
                    automaton_acceptance = max(0.0, min(1.0, float(v)))
            except Exception:
                automaton_acceptance = -1.0

        return SequenceScore(
            sequence=sequence,
            diversity_score=diversity_score,
            entry_point_position=entry_point_position,
            length=length,
            unique_api_count=len(unique_apis),
            has_entry_point=has_entry_point,
            automaton_acceptance=automaton_acceptance,
        )

    def _greedy_select(
        self,
        ranked_sequences: List[SequenceScore],
        top_k: int
    ) -> Tuple[List[List[str]], Set[str], Dict[str, Any]]:
        """
        Greedy selection maximizing API coverage.

        Instead of just taking top-k by score, we select sequences
        that contribute the most new API coverage.

        Args:
            ranked_sequences: Sequences sorted by score.
            top_k: Maximum number to select.

        Returns:
            Tuple of (selected_sequences, covered_apis, stats).
        """
        selected: List[List[str]] = []
        covered_apis: Set[str] = set()
        marginal_contributions: List[int] = []

        # Pure greedy max-API-coverage. Diversity (per-step new API count)
        # is the *only* objective inside the selection step; ranking already
        # reflects diversity_score / entry_point / acceptance / length, so
        # the order encodes those preferences. Going greedy on top of this
        # ranking gives the budgeted-max-coverage approximation
        # (Khuller/Moss/Naor 1999, ratio 1-1/e).
        for score in ranked_sequences:
            if len(selected) >= top_k:
                break
            seq_apis = set(score.sequence)
            new_apis = seq_apis - covered_apis
            # Accept any sequence that contributes at least one new API; or
            # any of the first three picks unconditionally so we never end
            # up with an empty result on tiny pools.
            if len(new_apis) > 0 or len(selected) < min(3, top_k):
                selected.append(score.sequence)
                covered_apis.update(seq_apis)
                marginal_contributions.append(len(new_apis))

        stats = {
            'greedy_selection': True,
            'marginal_contributions': marginal_contributions,
            'avg_marginal_contribution': (
                sum(marginal_contributions) / len(marginal_contributions)
                if marginal_contributions else 0
            ),
        }

        return selected, covered_apis, stats


# =============================================================================
# Convenience Functions
# =============================================================================

def rank_sequences_by_coverage(
    sequences: List[List[str]],
    entry_point_names: Optional[Set[str]] = None,
    top_k: int = 10,
    logger_instance: Optional[logging.Logger] = None
) -> CoverageRankingResult:
    """
    Convenience function to rank and select sequences.

    Args:
        sequences: List of API name sequences.
        entry_point_names: Set of entry point API names (from L1).
        top_k: Number of sequences to select.
        logger_instance: Optional logger.

    Returns:
        CoverageRankingResult with ranked and selected sequences.
    """
    ranker = CoverageRanker(logger_instance=logger_instance)
    return ranker.rank_and_select(sequences, entry_point_names, top_k)


def select_top_k_sequences(
    sequences: List[List[str]],
    entry_point_analysis: Optional[Dict[str, Any]] = None,
    top_k: int = 10,
    logger_instance: Optional[logging.Logger] = None,
    existing_coverage: Optional[Dict[str, float]] = None,
    important_apis: Optional[Set[str]] = None,
    automaton_artifact: Optional[Any] = None,
    automaton_n_sample_paths: int = 8,
    automaton_post_extend_depth: int = 2,
    automaton_post_extend_branching: int = 4,
    automaton_post_extend_max_inputs: int = 12,
    automaton_post_extend_acceptance_threshold: float = 0.0,
    length_floor_safe_apis: Optional[Set[str]] = None,
    disable_coverage_filter: bool = False,
) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Convenience function matching the filter interface of L1-L3.

    Args:
        sequences: List of API name sequences.
        entry_point_analysis: L1 analysis result (serialized).
        top_k: Number of sequences to select.
        logger_instance: Optional logger.
        existing_coverage: Dict of function_name -> coverage % (0-100).
                          Used for coverage-aware filtering to prioritize
                          sequences targeting uncovered code.
        important_apis: Set of API names that should be kept regardless of coverage.
        automaton_artifact: Optional ``AutomatonArtifact`` from
            ``learn_project_automaton``. When supplied, three signals plug
            into the ranker:
              1. ``acceptance_score`` becomes the secondary sort axis
              2. ``graft_creator_prefix`` augments unaccepted candidates
                 with creator-prefixed grounded versions
              3. ``sample_accepting_paths`` injects high-precision protocol
                 paths into the candidate pool
            All three are signals, none is a hard filter — the underlying
            greedy max-coverage selection still runs.
        automaton_n_sample_paths: How many automaton-sampled paths to
            mix into the candidate pool. Default 8 ≈ ⌊K/2⌋ for K=12; the
            sampler dedupes against L0–L4 to avoid double counting.

    Returns:
        Tuple of (selected_sequences, selection_summary).
    """
    log = logger_instance or logger

    # Extract entry point names from L1 analysis
    entry_point_names = set()
    if entry_point_analysis:
        entry_point_names = set(entry_point_analysis.get('entry_point_names', []))

    # === L5: Coverage-Aware Pre-filtering (if coverage data available) ===
    # Skipped when disable_coverage_filter=True (evaluation mode: maximise
    # total coverage by NOT avoiding APIs the baseline already covers).
    coverage_aware_stats = {}
    if disable_coverage_filter:
        coverage_aware_stats = {'coverage_aware_enabled': False,
                                'reason': 'disabled_for_evaluation'}
        log.info("   ⏭️  L5 Coverage-Aware: SKIPPED (disable_coverage_filter=True)")
    elif existing_coverage:
        try:
            from .coverage_aware_filter import CoverageAwareFilter

            cov_filter = CoverageAwareFilter(
                existing_coverage=existing_coverage,
                important_apis=important_apis,
            )

            # Apply coverage-aware filtering
            cov_result = cov_filter.filter_sequences(
                sequences,
                max_overlap=0.7,  # Allow up to 70% overlap
                min_novelty=0.2,  # Require 20% novelty
            )

            # Use novelty-ranked sequences for further processing
            sequences = cov_result.filtered_sequences
            coverage_aware_stats = {
                'coverage_aware_enabled': True,
                'pre_filter_count': cov_result.stats['input_count'],
                'post_filter_count': cov_result.stats['output_count'],
                'avg_novelty_score': cov_result.stats['avg_novelty'],
                'filtered_by_overlap': cov_result.stats['filtered_out'],
            }

            log.info(
                f"   ✅ L5 Coverage-Aware: {cov_result.stats['input_count']} -> "
                f"{cov_result.stats['output_count']} sequences "
                f"(avg novelty: {cov_result.stats['avg_novelty']:.2f})"
            )

        except ImportError as e:
            log.debug(f"Coverage-aware filter not available: {e}")
            coverage_aware_stats = {'coverage_aware_enabled': False, 'error': str(e)}
        except Exception as e:
            log.warning(f"Coverage-aware filtering failed: {e}")
            coverage_aware_stats = {'coverage_aware_enabled': False, 'error': str(e)}

    ranker = CoverageRanker(logger_instance=logger_instance)
    automaton_acceptance_fn = None
    automaton_graft_fn = None
    automaton_post_extend_fn = None
    automaton_sample_paths: List[List[str]] = []
    automaton_stats: Dict[str, Any] = {'enabled': False}
    if automaton_artifact is not None:
        try:
            automaton_acceptance_fn = automaton_artifact.acceptance_score
            automaton_graft_fn = automaton_artifact.graft_creator_prefix
            automaton_sample_paths = automaton_artifact.sample_accepting_paths(
                n=automaton_n_sample_paths,
            )
            # Phase E: post-parse extension closure. Wraps the artifact's
            # method with the chosen depth/branching/threshold so the ranker
            # only needs a unary callable (sequence -> [extensions]).
            if hasattr(automaton_artifact, "post_parse_extensions"):
                _depth = automaton_post_extend_depth
                _branch = automaton_post_extend_branching
                _thr = automaton_post_extend_acceptance_threshold
                def _post_extend(seq, _art=automaton_artifact,
                                 _d=_depth, _b=_branch, _t=_thr):
                    return _art.post_parse_extensions(
                        seq, depth=_d, branching=_b,
                        acceptance_threshold=_t,
                    )
                automaton_post_extend_fn = _post_extend
            observed = automaton_artifact.observed_apis()
            automaton_stats = {
                'enabled': True,
                'merged_states': automaton_artifact.n_merged_states,
                'observed_apis': len(observed),
                'sample_paths': len(automaton_sample_paths),
                'post_extend_enabled': automaton_post_extend_fn is not None,
            }
        except Exception as exc:
            log.warning("automaton signal unavailable (%s); falling back", exc)
            automaton_acceptance_fn = None
            automaton_graft_fn = None
            automaton_post_extend_fn = None
            automaton_sample_paths = []
            automaton_stats = {'enabled': False, 'error': str(exc)}

    result = ranker.rank_and_select(
        sequences, entry_point_names, top_k,
        automaton_acceptance_fn=automaton_acceptance_fn,
        automaton_graft_fn=automaton_graft_fn,
        automaton_sample_paths=automaton_sample_paths,
        automaton_post_extend_fn=automaton_post_extend_fn,
        post_extend_max_inputs=automaton_post_extend_max_inputs,
        length_floor_safe_apis=length_floor_safe_apis,
    )

    if automaton_post_extend_fn is not None:
        automaton_stats['post_extend_added'] = getattr(
            ranker, '_post_extend_added', 0,
        )

    summary = {
        'input': len(sequences),
        'output': len(result.selected_sequences),
        'api_coverage': len(result.total_api_coverage),
        'stats': result.get_stats(),
        'coverage_aware': coverage_aware_stats,
        'automaton': automaton_stats,
    }

    return result.selected_sequences, summary
