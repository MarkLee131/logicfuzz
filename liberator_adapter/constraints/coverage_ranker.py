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

    # Metadata
    unique_api_count: int
    has_entry_point: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sequence': self.sequence,
            'diversity_score': round(self.diversity_score, 4),
            'entry_point_position': self.entry_point_position,
            'length': self.length,
            'unique_api_count': self.unique_api_count,
            'has_entry_point': self.has_entry_point,
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
        top_k: int = 10
    ) -> CoverageRankingResult:
        """
        Rank sequences and select top-k with maximum coverage.

        Args:
            sequences: List of API name sequences (after L1-L3 filtering).
            entry_point_names: Set of entry point API names (from L1).
            top_k: Number of sequences to select.

        Returns:
            CoverageRankingResult with ranked and selected sequences.
        """
        if not sequences:
            return CoverageRankingResult()

        entry_points = entry_point_names or set()

        # Step 1: Score all sequences
        scored = [self._score_sequence(seq, entry_points) for seq in sequences]

        # Step 2: Hierarchical sort
        # Sort by: diversity (desc), entry_point_position (asc, -1 last), length (desc)
        ranked = sorted(
            scored,
            key=lambda s: (
                -s.diversity_score,  # Higher diversity first
                s.entry_point_position if s.entry_point_position >= 0 else float('inf'),  # Earlier EP first
                -s.length,  # Longer sequence first
            )
        )

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
        entry_points: Set[str]
    ) -> SequenceScore:
        """
        Score a single sequence.

        Args:
            sequence: List of API names.
            entry_points: Set of entry point API names.

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

        return SequenceScore(
            sequence=sequence,
            diversity_score=diversity_score,
            entry_point_position=entry_point_position,
            length=length,
            unique_api_count=len(unique_apis),
            has_entry_point=has_entry_point,
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
        selected = []
        covered_apis: Set[str] = set()
        marginal_contributions = []

        for score in ranked_sequences:
            if len(selected) >= top_k:
                break

            # Calculate marginal contribution
            seq_apis = set(score.sequence)
            new_apis = seq_apis - covered_apis

            # Select if contributes at least 1 new API, or if we haven't selected enough
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

    Returns:
        Tuple of (selected_sequences, selection_summary).
    """
    log = logger_instance or logger

    # Extract entry point names from L1 analysis
    entry_point_names = set()
    if entry_point_analysis:
        entry_point_names = set(entry_point_analysis.get('entry_point_names', []))

    # === L5: Coverage-Aware Pre-filtering (if coverage data available) ===
    coverage_aware_stats = {}
    if existing_coverage:
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
    result = ranker.rank_and_select(sequences, entry_point_names, top_k)

    summary = {
        'input': len(sequences),
        'output': len(result.selected_sequences),
        'api_coverage': len(result.total_api_coverage),
        'stats': result.get_stats(),
        'coverage_aware': coverage_aware_stats,
    }

    return result.selected_sequences, summary
