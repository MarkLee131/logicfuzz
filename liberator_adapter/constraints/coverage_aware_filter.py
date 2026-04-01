"""
Coverage-Aware Sequence Filter (L5)

Filters and ranks sequences based on existing fuzzer coverage data.
Goal: Prioritize sequences that target UNCOVERED code paths.

Key insight:
- APIs with high existing coverage -> low priority (already well-tested)
- APIs with low/zero coverage -> high priority (new coverage potential)
- Important APIs (core functionality) -> always keep regardless of coverage
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class CoverageAwareResult:
    """Result of coverage-aware filtering"""
    filtered_sequences: List[List[str]]
    sequence_scores: List[Tuple[List[str], float]]  # (sequence, novelty_score)
    stats: Dict[str, any]


class CoverageAwareFilter:
    """
    Filter sequences based on existing coverage data from FuzzIntrospector.

    Philosophy:
    - Avoid re-testing what existing fuzzers already cover well
    - But don't completely exclude important/core APIs
    - Balance between novelty and functionality testing
    """

    # APIs that are "important" even if covered - core functionality we want to test
    # These should be determined per-project, but we can have sensible defaults
    DEFAULT_IMPORTANT_PATTERNS = [
        '_parse_',      # Parser functions are security-critical
        '_create',      # Object creation
        '_init',        # Initialization
        '_destroy',     # Cleanup (memory safety)
        '_free',        # Memory management
    ]

    def __init__(
        self,
        existing_coverage: Dict[str, float],
        important_apis: Optional[Set[str]] = None,
        important_patterns: Optional[List[str]] = None,
        high_coverage_threshold: float = 70.0,  # >70% = well-covered
        low_coverage_threshold: float = 30.0,   # <30% = poorly-covered (target these!)
    ):
        """
        Args:
            existing_coverage: Map of function_name -> coverage percentage (0-100)
            important_apis: Explicit set of important API names
            important_patterns: Patterns that mark APIs as important (e.g., '_parse_')
            high_coverage_threshold: APIs above this % are considered well-covered
            low_coverage_threshold: APIs below this % are high-priority targets
        """
        self.existing_coverage = existing_coverage or {}
        self.important_apis = important_apis or set()
        self.important_patterns = important_patterns or self.DEFAULT_IMPORTANT_PATTERNS
        self.high_coverage_threshold = high_coverage_threshold
        self.low_coverage_threshold = low_coverage_threshold

        # Pre-compute coverage categories
        self._categorize_apis()

    def _categorize_apis(self):
        """Categorize APIs by coverage level"""
        self.well_covered_apis = set()
        self.poorly_covered_apis = set()
        self.uncovered_apis = set()

        for api, cov in self.existing_coverage.items():
            if cov >= self.high_coverage_threshold:
                self.well_covered_apis.add(api)
            elif cov <= self.low_coverage_threshold:
                self.poorly_covered_apis.add(api)
                if cov == 0:
                    self.uncovered_apis.add(api)

        logger.info(
            f"Coverage categories: {len(self.well_covered_apis)} well-covered, "
            f"{len(self.poorly_covered_apis)} poorly-covered, "
            f"{len(self.uncovered_apis)} uncovered"
        )

    def _is_important_api(self, api_name: str) -> bool:
        """Check if API is important (should be kept regardless of coverage)"""
        # Explicit important list
        if api_name in self.important_apis:
            return True

        # Pattern matching
        api_lower = api_name.lower()
        for pattern in self.important_patterns:
            if pattern in api_lower:
                return True

        return False

    def calculate_novelty_score(self, sequence: List[str]) -> float:
        """
        Calculate novelty score for a sequence.
        Higher score = more novel (targets uncovered code)

        Score formula:
        - +2.0 for each uncovered API
        - +1.0 for each poorly-covered API
        - +0.5 for each important API (bonus)
        - -0.5 for each well-covered API (penalty)

        Returns normalized score (0-1 range)
        """
        if not sequence:
            return 0.0

        score = 0.0
        for api in sequence:
            cov = self.existing_coverage.get(api, 0)

            if api in self.uncovered_apis or cov == 0:
                score += 2.0  # Big bonus for uncovered
            elif api in self.poorly_covered_apis or cov < self.low_coverage_threshold:
                score += 1.0  # Bonus for poorly covered
            elif api in self.well_covered_apis or cov > self.high_coverage_threshold:
                score -= 0.5  # Penalty for well-covered

            # Bonus for important APIs
            if self._is_important_api(api):
                score += 0.5

        # Normalize by sequence length
        max_possible = len(sequence) * 2.5  # max = 2.0 (uncovered) + 0.5 (important)
        normalized = (score + len(sequence) * 0.5) / max_possible  # Shift to 0-1
        return max(0.0, min(1.0, normalized))

    def calculate_overlap_ratio(self, sequence: List[str]) -> float:
        """
        Calculate overlap ratio with existing well-covered code.

        Returns:
            Ratio of well-covered APIs in sequence (0-1)
        """
        if not sequence:
            return 0.0

        well_covered_count = sum(
            1 for api in sequence
            if api in self.well_covered_apis or
               self.existing_coverage.get(api, 0) > self.high_coverage_threshold
        )
        return well_covered_count / len(sequence)

    def filter_sequences(
        self,
        sequences: List[List[str]],
        max_overlap: float = 0.7,  # Allow up to 70% overlap
        min_novelty: float = 0.2,  # Require at least 20% novelty score
        top_k: Optional[int] = None,
    ) -> CoverageAwareResult:
        """
        Filter sequences based on coverage overlap and novelty.

        Args:
            sequences: List of API sequences
            max_overlap: Maximum allowed overlap with well-covered code
            min_novelty: Minimum required novelty score
            top_k: If set, return only top K sequences by novelty

        Returns:
            CoverageAwareResult with filtered sequences and stats
        """
        scored_sequences = []

        for seq in sequences:
            overlap = self.calculate_overlap_ratio(seq)
            novelty = self.calculate_novelty_score(seq)
            has_important = any(self._is_important_api(api) for api in seq)

            # Keep sequence if:
            # 1. Low overlap with existing coverage, OR
            # 2. Contains important APIs (exception), OR
            # 3. High novelty score
            keep = (
                overlap <= max_overlap or
                has_important or
                novelty >= min_novelty
            )

            if keep:
                scored_sequences.append((seq, novelty, overlap, has_important))

        # Sort by novelty score (descending)
        scored_sequences.sort(key=lambda x: x[1], reverse=True)

        # Apply top_k if specified
        if top_k and len(scored_sequences) > top_k:
            scored_sequences = scored_sequences[:top_k]

        # Extract results
        filtered = [seq for seq, _, _, _ in scored_sequences]
        scores = [(seq, novelty) for seq, novelty, _, _ in scored_sequences]

        # Compute stats
        stats = {
            'input_count': len(sequences),
            'output_count': len(filtered),
            'filtered_out': len(sequences) - len(filtered),
            'avg_novelty': sum(s[1] for s in scores) / len(scores) if scores else 0,
            'kept_by_importance': sum(1 for _, _, _, imp in scored_sequences if imp),
        }

        logger.info(
            f"Coverage-aware filter: {stats['input_count']} -> {stats['output_count']} "
            f"(avg novelty: {stats['avg_novelty']:.2f})"
        )

        return CoverageAwareResult(
            filtered_sequences=filtered,
            sequence_scores=scores,
            stats=stats
        )

    def rank_sequences_by_novelty(
        self,
        sequences: List[List[str]],
    ) -> List[Tuple[List[str], float]]:
        """
        Rank sequences by novelty score without filtering.
        Useful for integration with L4 ranker.

        Returns:
            List of (sequence, novelty_score) sorted by score descending
        """
        scored = [(seq, self.calculate_novelty_score(seq)) for seq in sequences]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored


def get_function_coverage_from_introspector(
    project_name: str,
    introspector_url: str = "http://localhost:8080"
) -> Dict[str, float]:
    """
    Fetch function coverage data from FuzzIntrospector API.

    Returns:
        Dict mapping function_name -> coverage percentage (0-100)
    """
    import requests

    try:
        # Try the function-coverage endpoint
        url = f"{introspector_url}/api/project-summary?project={project_name}"
        resp = requests.get(url, timeout=10)

        if resp.status_code != 200:
            logger.warning(f"Failed to fetch coverage from FI: {resp.status_code}")
            return {}

        data = resp.json()

        # Extract function coverage
        coverage = {}
        for func in data.get('functions', []):
            name = func.get('function_name', '')
            cov = func.get('code_coverage', 0)
            if name:
                coverage[name] = float(cov)

        logger.info(f"Loaded coverage for {len(coverage)} functions from FuzzIntrospector")
        return coverage

    except Exception as e:
        logger.warning(f"Could not fetch FI coverage: {e}")
        return {}


def get_coverage_from_textcov(textcov_path: str) -> Dict[str, float]:
    """
    Parse coverage from textcov report file.

    Returns:
        Dict mapping function_name -> coverage percentage (0-100)
    """
    import os

    if not os.path.exists(textcov_path):
        return {}

    coverage = {}
    try:
        with open(textcov_path, 'r') as f:
            for line in f:
                # Format: "function_name: XX.XX%"
                if ':' in line and '%' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        func_name = parts[0].strip()
                        cov_str = parts[1].strip().rstrip('%')
                        try:
                            coverage[func_name] = float(cov_str)
                        except ValueError:
                            pass
    except Exception as e:
        logger.warning(f"Failed to parse textcov: {e}")

    return coverage
