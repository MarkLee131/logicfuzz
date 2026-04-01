"""
L1: Entry Point Analyzer - Identify APIs that directly consume fuzzer data.

Entry Points are APIs that can directly receive fuzzer input (const uint8_t* data, size_t size)
without requiring complex initialization (like channel/handle setup).

This is the first semantic filter in the Progressive Filter Pipeline:
    L0 (Type) -> L1 (Entry Point) -> L2 (Lifecycle) -> L3 (StateMachine) -> L4 (Ranking)

Design principles:
1. Pure static analysis - no LLM needed
2. Pattern-based identification from API signatures
3. Conservative matching - prefer precision over recall
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

class EntryPointType(Enum):
    """Classification of Entry Point APIs."""

    # Parser: Parse external data into internal structure
    # Examples: ares_dns_parse, cJSON_Parse, xmlReadMemory
    PARSER = "parser"

    # Creator: Create object from external data
    # Examples: ares_create_query, png_create_read_struct
    CREATOR = "creator"

    # Validator: Validate external data format
    # Examples: json_validate, xml_validate_document
    VALIDATOR = "validator"

    # Generic: Matches pattern but unclear category
    GENERIC = "generic"


@dataclass
class EntryPointPattern:
    """Pattern for identifying Entry Point APIs from signatures."""

    # Buffer argument type keywords (any match)
    buffer_type_keywords: Tuple[str, ...] = (
        "unsigned char *",
        "uint8_t *",
        "char *",
        "void *",
        "const unsigned char *",
        "const uint8_t *",
        "const char *",
        "const void *",
    )

    # Size argument type keywords (any match)
    size_type_keywords: Tuple[str, ...] = (
        "int",
        "size_t",
        "unsigned long",
        "long",
        "unsigned int",
        "uint32_t",
        "uint64_t",
    )

    # Expected argument positions
    buffer_arg_index: int = 0
    size_arg_index: int = 1

    # Whether buffer must be const (indicates input data)
    buffer_must_be_const: bool = True

    # Whether this pattern requires a size argument
    requires_size_arg: bool = True


@dataclass
class EntryPointInfo:
    """Information about a single Entry Point API."""

    # API metadata
    function_name: str
    return_type: str
    arguments: List[Dict[str, Any]]

    # Entry point classification
    entry_type: EntryPointType

    # Buffer/size argument info
    buffer_arg_index: int
    buffer_arg_type: str
    size_arg_index: int  # -1 if no size argument
    size_arg_type: Optional[str] = None

    # Matching info
    matched_pattern: Optional[str] = None
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'function_name': self.function_name,
            'return_type': self.return_type,
            'entry_type': self.entry_type.value,
            'buffer_arg_index': self.buffer_arg_index,
            'buffer_arg_type': self.buffer_arg_type,
            'size_arg_index': self.size_arg_index,
            'size_arg_type': self.size_arg_type,
            'confidence': self.confidence,
        }


@dataclass
class EntryPointAnalysis:
    """Result of Entry Point analysis for a project."""

    # All identified Entry Points
    entry_points: List[EntryPointInfo] = field(default_factory=list)

    # Set of Entry Point function names (for fast lookup)
    entry_point_names: Set[str] = field(default_factory=set)

    # APIs that are not Entry Points
    non_entry_points: List[Dict[str, Any]] = field(default_factory=list)

    # Analysis metadata
    total_apis: int = 0
    analysis_version: str = "1.0"

    def __post_init__(self):
        """Ensure entry_point_names is populated."""
        if self.entry_points and not self.entry_point_names:
            self.entry_point_names = {ep.function_name for ep in self.entry_points}

    @property
    def entry_point_count(self) -> int:
        return len(self.entry_points)

    @property
    def entry_point_ratio(self) -> float:
        if self.total_apis == 0:
            return 0.0
        return self.entry_point_count / self.total_apis

    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        type_counts = {}
        for ep in self.entry_points:
            type_name = ep.entry_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            'total_apis': self.total_apis,
            'entry_point_count': self.entry_point_count,
            'entry_point_ratio': round(self.entry_point_ratio, 3),
            'by_type': type_counts,
            'entry_point_names': list(self.entry_point_names),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'entry_points': [ep.to_dict() for ep in self.entry_points],
            'entry_point_names': list(self.entry_point_names),
            'stats': self.get_stats(),
        }


class EntryPointFilterStrategy(Enum):
    """Strategy for filtering sequences by Entry Point presence."""

    # At least one Entry Point anywhere in sequence
    ANY_POSITION = "any"

    # Entry Point must be the first API in sequence
    MUST_BE_FIRST = "first"

    # Entry Point must be within first N positions (default N=3)
    WITHIN_FIRST_N = "within_first_n"


# =============================================================================
# Entry Point Analyzer
# =============================================================================

class EntryPointAnalyzer:
    """
    L1 Filter: Identify Entry Point APIs from project API list.

    Entry Points are APIs that directly consume fuzzer input without
    requiring complex initialization. These are the most valuable
    targets for fuzz driver generation.

    Usage:
        analyzer = EntryPointAnalyzer()
        analysis = analyzer.analyze(project_apis)
        filtered_sequences = analyzer.filter_sequences(
            sequences, analysis, strategy="within_first_n", n=3
        )
    """

    # Default pattern for (buffer, size) APIs
    DEFAULT_PATTERN = EntryPointPattern()

    # Name patterns that suggest parser/creator/validator
    PARSER_NAME_PATTERNS = (
        'parse', 'read', 'load', 'decode', 'deserialize',
        'unmarshal', 'from_', 'import'
    )
    CREATOR_NAME_PATTERNS = (
        'create', 'make', 'build', 'new', 'construct'
    )
    VALIDATOR_NAME_PATTERNS = (
        'valid', 'check', 'verify', 'test'
    )

    def __init__(self,
                 pattern: Optional[EntryPointPattern] = None,
                 logger_instance: Optional[logging.Logger] = None):
        """
        Initialize Entry Point Analyzer.

        Args:
            pattern: Custom pattern for matching. Uses DEFAULT_PATTERN if None.
            logger_instance: Optional logger for debug output.
        """
        self.pattern = pattern or self.DEFAULT_PATTERN
        self.log = logger_instance or logger

    def analyze(self, project_apis: List[Dict[str, Any]]) -> EntryPointAnalysis:
        """
        Analyze project APIs to identify Entry Points.

        Args:
            project_apis: List of API dictionaries with keys:
                - function_name: str
                - return_type: str
                - arguments: List[Dict] with 'type', 'is_const', etc.

        Returns:
            EntryPointAnalysis with identified Entry Points and statistics.
        """
        entry_points = []
        non_entry_points = []

        for api in project_apis:
            ep_info = self._check_entry_point(api)
            if ep_info:
                entry_points.append(ep_info)
            else:
                non_entry_points.append(api)

        analysis = EntryPointAnalysis(
            entry_points=entry_points,
            entry_point_names={ep.function_name for ep in entry_points},
            non_entry_points=non_entry_points,
            total_apis=len(project_apis),
        )

        self.log.debug(
            f"Entry Point Analysis: {analysis.entry_point_count}/{analysis.total_apis} "
            f"({analysis.entry_point_ratio:.1%}) APIs are Entry Points"
        )

        return analysis

    def filter_sequences(self,
                         sequences: List[List[str]],
                         analysis: EntryPointAnalysis,
                         strategy: str = "within_first_n",
                         n: int = 3) -> Tuple[List[List[str]], Dict[str, Any]]:
        """
        Filter sequences to keep only those containing Entry Points.

        Args:
            sequences: List of API name sequences.
            analysis: EntryPointAnalysis from analyze().
            strategy: Filter strategy - "any", "first", or "within_first_n".
            n: For "within_first_n" strategy, Entry Point must be in first n positions.

        Returns:
            Tuple of (filtered_sequences, filter_summary).
        """
        if not sequences:
            return [], {'strategy': strategy, 'input': 0, 'output': 0}

        entry_names = analysis.entry_point_names

        if not entry_names:
            self.log.warning("No Entry Points identified - cannot filter sequences")
            return sequences, {
                'strategy': strategy,
                'input': len(sequences),
                'output': len(sequences),
                'warning': 'no_entry_points_found'
            }

        filtered = []
        for seq in sequences:
            if self._sequence_matches_strategy(seq, entry_names, strategy, n):
                filtered.append(seq)

        summary = {
            'strategy': strategy,
            'n': n if strategy == "within_first_n" else None,
            'input': len(sequences),
            'output': len(filtered),
            'reduction_ratio': round(1 - len(filtered) / len(sequences), 3) if sequences else 0,
            'entry_point_count': len(entry_names),
        }

        self.log.debug(
            f"Entry Point Filter ({strategy}): {len(sequences)} -> {len(filtered)} sequences "
            f"({summary['reduction_ratio']:.1%} reduction)"
        )

        return filtered, summary

    def _check_entry_point(self, api: Dict[str, Any]) -> Optional[EntryPointInfo]:
        """
        Check if an API is an Entry Point.

        Args:
            api: API dictionary with function_name, arguments, etc.

        Returns:
            EntryPointInfo if API is an Entry Point, None otherwise.
        """
        func_name = api.get('function_name', '')
        args = api.get('arguments', [])
        return_type = api.get('return_type', '')

        # Need at least 1 argument for buffer (2 for buffer + size)
        min_args = 2 if self.pattern.requires_size_arg else 1
        if len(args) < min_args:
            return None

        # Check buffer argument
        buffer_idx = self.pattern.buffer_arg_index
        if buffer_idx >= len(args):
            return None

        buffer_arg = args[buffer_idx]
        buffer_type = buffer_arg.get('type', '').lower()

        # Check if buffer type matches
        if not self._type_matches(buffer_type, self.pattern.buffer_type_keywords):
            return None

        # Check const requirement
        if self.pattern.buffer_must_be_const:
            is_const = buffer_arg.get('is_const', [False])
            # is_const is a list, first element indicates if base type is const
            if isinstance(is_const, list):
                is_const = is_const[0] if is_const else False
            if not is_const:
                return None

        # Check size argument (if required)
        size_idx = self.pattern.size_arg_index
        size_type = None

        if self.pattern.requires_size_arg:
            if size_idx >= len(args):
                return None

            size_arg = args[size_idx]
            size_type = size_arg.get('type', '').lower()

            if not self._type_matches(size_type, self.pattern.size_type_keywords):
                return None
        else:
            size_idx = -1

        # Classify entry type based on function name
        entry_type = self._classify_entry_type(func_name)

        return EntryPointInfo(
            function_name=func_name,
            return_type=return_type,
            arguments=args,
            entry_type=entry_type,
            buffer_arg_index=buffer_idx,
            buffer_arg_type=buffer_arg.get('type', ''),
            size_arg_index=size_idx,
            size_arg_type=size_type,
            confidence=1.0,
        )

    def _type_matches(self, actual_type: str, keywords: Tuple[str, ...]) -> bool:
        """Check if actual type matches any keyword."""
        actual_lower = actual_type.lower().strip()
        for keyword in keywords:
            if keyword.lower() in actual_lower:
                return True
        return False

    def _classify_entry_type(self, func_name: str) -> EntryPointType:
        """Classify Entry Point type based on function name patterns."""
        name_lower = func_name.lower()

        if any(p in name_lower for p in self.PARSER_NAME_PATTERNS):
            return EntryPointType.PARSER
        elif any(p in name_lower for p in self.CREATOR_NAME_PATTERNS):
            return EntryPointType.CREATOR
        elif any(p in name_lower for p in self.VALIDATOR_NAME_PATTERNS):
            return EntryPointType.VALIDATOR
        else:
            return EntryPointType.GENERIC

    def _sequence_matches_strategy(self,
                                   seq: List[str],
                                   entry_names: Set[str],
                                   strategy: str,
                                   n: int) -> bool:
        """Check if sequence matches the filter strategy."""
        if not seq:
            return False

        if strategy == "any" or strategy == EntryPointFilterStrategy.ANY_POSITION.value:
            return any(api in entry_names for api in seq)

        elif strategy == "first" or strategy == EntryPointFilterStrategy.MUST_BE_FIRST.value:
            return seq[0] in entry_names

        elif strategy == "within_first_n" or strategy == EntryPointFilterStrategy.WITHIN_FIRST_N.value:
            return any(api in entry_names for api in seq[:n])

        else:
            self.log.warning(f"Unknown filter strategy: {strategy}, using 'any'")
            return any(api in entry_names for api in seq)


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_entry_points(
    project_apis: List[Dict[str, Any]],
    logger_instance: Optional[logging.Logger] = None
) -> EntryPointAnalysis:
    """
    Convenience function to analyze Entry Points.

    Args:
        project_apis: List of API dictionaries.
        logger_instance: Optional logger.

    Returns:
        EntryPointAnalysis result.
    """
    analyzer = EntryPointAnalyzer(logger_instance=logger_instance)
    return analyzer.analyze(project_apis)


def filter_sequences_by_entry_point(
    sequences: List[List[str]],
    analysis: EntryPointAnalysis,
    strategy: str = "within_first_n",
    n: int = 3,
    logger_instance: Optional[logging.Logger] = None
) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Convenience function to filter sequences by Entry Point.

    Args:
        sequences: List of API name sequences.
        analysis: EntryPointAnalysis from analyze_entry_points().
        strategy: Filter strategy - "any", "first", or "within_first_n".
        n: For "within_first_n", Entry Point must be in first n positions.
        logger_instance: Optional logger.

    Returns:
        Tuple of (filtered_sequences, filter_summary).
    """
    analyzer = EntryPointAnalyzer(logger_instance=logger_instance)
    return analyzer.filter_sequences(sequences, analysis, strategy, n)
