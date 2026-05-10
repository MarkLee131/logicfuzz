"""
L1: Entry Point Analyzer - Identify APIs that directly consume fuzzer data.

Entry Points are APIs that can directly receive fuzzer input without requiring
complex initialization (like channel/handle setup).

Supports multiple input type categories:
1. C-style: (const uint8_t* data, size_t size)
2. C++ view types: (string_view input) - self-contained, no size arg needed
3. C++ container refs: (const std::vector<uint8_t>& input)

This is the first semantic filter in the Progressive Filter Pipeline:
    L0 (Type) -> L1 (Entry Point) -> L2 (Lifecycle) -> L3 (StateMachine) -> L4 (Ranking)

Design principles:
1. Pure static analysis - no LLM needed
2. Pattern-based identification from API signatures
3. Extensible type category system - not hardcoded to specific libraries
4. Conservative matching - prefer precision over recall
"""

import logging
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Input Type Category System
# =============================================================================

class InputTypeCategory(Enum):
    """Categories of input types that can consume fuzzer data."""

    # C-style: raw pointer + separate size argument
    # Examples: (const uint8_t* data, size_t size), (const char* buf, int len)
    C_BUFFER_WITH_SIZE = "c_buffer"

    # C++ view types: self-contained (pointer + size in one object)
    # Examples: string_view, span<uint8_t>, StringPiece
    CPP_VIEW = "cpp_view"

    # C++ container references: dynamic containers passed by reference
    # Examples: const std::string&, const std::vector<uint8_t>&
    CPP_CONTAINER_REF = "cpp_container"

    # C-style string: null-terminated, no explicit size
    # Examples: (const char* str) - parser APIs that accept null-terminated input
    C_STRING = "c_string"


@dataclass
class InputTypePatterns:
    """
    Extensible patterns for identifying input types.

    Each pattern category defines type patterns that match fuzzer-consumable input.
    Patterns are substring matches (case-insensitive) against the normalized type string.
    """

    # C-style buffer types (require separate size argument)
    c_buffer_patterns: Tuple[str, ...] = (
        "unsigned char *",
        "uint8_t *",
        "char *",
        "void *",
        "uint8_t*",
        "char*",
    )

    # Size argument types (for C_BUFFER_WITH_SIZE category)
    size_patterns: Tuple[str, ...] = (
        "size_t",
        "int",
        "unsigned long",
        "long",
        "unsigned int",
        "uint32_t",
        "uint64_t",
        "ssize_t",
    )

    # C++ view types (self-contained: contain both data pointer and size)
    # These are generic patterns that match any library's view types
    cpp_view_patterns: Tuple[str, ...] = (
        "string_view",      # std::string_view, absl::string_view
        "stringpiece",      # StringPiece (Google style)
        "span<",            # std::span<uint8_t>, gsl::span
        "array_view",       # Various libraries
        "string_ref",       # llvm::StringRef, etc.
        "byte_view",        # Various libraries
        "bytes_view",       # Various libraries
    )

    # C++ container reference patterns
    cpp_container_patterns: Tuple[str, ...] = (
        "std::string",
        "std::vector",
        "std::array",
        "basic_string",
        "vector<",
        "array<",
    )

    # C-style null-terminated string (no size needed)
    c_string_patterns: Tuple[str, ...] = (
        "const char *",
        "char const *",
        "const char*",
    )

    @classmethod
    def normalize_type(cls, type_str: str) -> str:
        """
        Normalize type string for pattern matching.

        Handles variations like:
        - "const std::string &" vs "std::string const&"
        - Template spacing: "vector< uint8_t >" vs "vector<uint8_t>"
        """
        if not type_str:
            return ""

        # Convert to lowercase
        normalized = type_str.lower()

        # Remove extra whitespace around template brackets
        normalized = re.sub(r'\s*<\s*', '<', normalized)
        normalized = re.sub(r'\s*>\s*', '>', normalized)

        # Normalize pointer/reference spacing
        normalized = re.sub(r'\s*\*\s*', ' *', normalized)
        normalized = re.sub(r'\s*&\s*', ' &', normalized)

        # Collapse multiple spaces
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        return normalized

    def match_category(self, type_str: str, is_const: bool = False) -> Optional[InputTypeCategory]:
        """
        Determine which input category a type belongs to.

        Args:
            type_str: The type string to check
            is_const: Whether the type has const qualifier

        Returns:
            InputTypeCategory if type is a valid input type, None otherwise
        """
        normalized = self.normalize_type(type_str)
        if not normalized:
            return None

        # Check C++ view types first (most specific)
        if any(p.lower() in normalized for p in self.cpp_view_patterns):
            return InputTypeCategory.CPP_VIEW

        # Check C++ container references
        if any(p.lower() in normalized for p in self.cpp_container_patterns):
            # Must be a reference for container input
            if '&' in normalized:
                return InputTypeCategory.CPP_CONTAINER_REF

        # Check C-style buffer (const pointer + typically needs size)
        if any(p.lower() in normalized for p in self.c_buffer_patterns):
            if is_const or 'const' in normalized:
                return InputTypeCategory.C_BUFFER_WITH_SIZE

        # Check C-style null-terminated string (const char* without size)
        if any(p.lower() in normalized for p in self.c_string_patterns):
            return InputTypeCategory.C_STRING

        return None

    def is_size_type(self, type_str: str) -> bool:
        """Check if type is a valid size type."""
        normalized = self.normalize_type(type_str)
        return any(p.lower() in normalized for p in self.size_patterns)


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

    # Indirect: API consumes fuzzer data but also requires a handle produced
    # by another API (e.g. `ucl_parser_add_chunk(parser, data, size)`). These
    # are detected as the *consumer* half of an `IndirectEntryPoint` pair; the
    # creator that produces the handle is tracked separately on the analysis.
    INDIRECT = "indirect"


@dataclass
class EntryPointPattern:
    """
    Pattern configuration for identifying Entry Point APIs.

    Supports multiple input type categories:
    - C_BUFFER_WITH_SIZE: Traditional (const uint8_t*, size_t) pattern
    - CPP_VIEW: C++ view types like string_view (no separate size needed)
    - CPP_CONTAINER_REF: C++ container references like const vector<>&
    - C_STRING: Null-terminated C strings (const char*)
    """

    # Type pattern configuration (extensible)
    type_patterns: InputTypePatterns = field(default_factory=InputTypePatterns)

    # Which input categories to accept
    # Default: accept all categories for maximum coverage
    accepted_categories: Tuple[InputTypeCategory, ...] = (
        InputTypeCategory.C_BUFFER_WITH_SIZE,
        InputTypeCategory.CPP_VIEW,
        InputTypeCategory.CPP_CONTAINER_REF,
        InputTypeCategory.C_STRING,
    )

    # For C_BUFFER_WITH_SIZE: which argument positions to check
    # Default: first two arguments (buffer at 0, size at 1)
    c_buffer_arg_index: int = 0
    c_size_arg_index: int = 1

    # For C++ types: which argument position to check
    # Default: first argument
    cpp_input_arg_index: int = 0

    # Whether C-style buffer must be const (indicates input data).
    # Default was True (strict-const) but the empirical study (2026-05)
    # showed ~5–10% of real OSS-Fuzz entry-point APIs use non-const
    # ``uint8_t *``/``void *`` for input. With the synthesis-side B4
    # safety net (``_create_variable_for_param`` entry-API fallback),
    # admitting these here is the only way to actually exercise that
    # path end-to-end. False means "match the type pattern; admit
    # both const and non-const buffer args". EntryPointInfo.confidence
    # is set lower for non-const matches so L4 still prefers const
    # variants when available.
    c_buffer_must_be_const: bool = False

    # Whether to allow scanning all arguments (not just fixed positions)
    # If True, will check all arguments for matching input types
    scan_all_arguments: bool = True

    # Maximum argument position to scan (prevents false positives from output params)
    max_scan_position: int = 2


@dataclass
class EntryPointInfo:
    """Information about a single Entry Point API."""

    # API metadata
    function_name: str
    return_type: str
    arguments: List[Dict[str, Any]]

    # Entry point classification
    entry_type: EntryPointType

    # Input type category
    input_category: InputTypeCategory

    # Input argument info
    input_arg_index: int
    input_arg_type: str

    # Size argument info (only for C_BUFFER_WITH_SIZE category)
    size_arg_index: int = -1  # -1 if no separate size argument
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
            'input_category': self.input_category.value,
            'input_arg_index': self.input_arg_index,
            'input_arg_type': self.input_arg_type,
            'size_arg_index': self.size_arg_index,
            'size_arg_type': self.size_arg_type,
            'confidence': self.confidence,
        }


@dataclass
class IndirectEntryPoint:
    """A (creator, consumer) pair forming an indirect entry point.

    The consumer is an API whose signature contains a fuzzer-buffer slot but
    whose remaining args require a handle that must be produced upstream.
    The creator is an API in the same project whose return type matches that
    handle. Together they form a usable two-step entry pattern such as
    ``handle = ucl_parser_new(0); ucl_parser_add_chunk(handle, data, size);``.
    """

    consumer: EntryPointInfo
    creator_name: str
    handle_arg_index: int
    handle_arg_type: str
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'consumer': self.consumer.to_dict(),
            'creator_name': self.creator_name,
            'handle_arg_index': self.handle_arg_index,
            'handle_arg_type': self.handle_arg_type,
            'confidence': self.confidence,
        }


@dataclass
class EntryPointAnalysis:
    """Result of Entry Point analysis for a project."""

    # All identified Entry Points (direct + indirect-consumer halves)
    entry_points: List[EntryPointInfo] = field(default_factory=list)

    # Set of Entry Point function names (for fast lookup). Includes the
    # consumer name from each indirect pair so existing callers that ask
    # "is this API an entry point?" keep working.
    entry_point_names: Set[str] = field(default_factory=set)

    # APIs that are not Entry Points
    non_entry_points: List[Dict[str, Any]] = field(default_factory=list)

    # === Indirect entry points (creator → consumer pairs) ===
    indirect_entry_points: List[IndirectEntryPoint] = field(default_factory=list)
    # Names of consumer APIs (subset of entry_point_names)
    indirect_consumer_names: Set[str] = field(default_factory=set)
    # Names of all creator APIs that produce a handle for any indirect consumer
    indirect_creator_names: Set[str] = field(default_factory=set)
    # Map: consumer_name -> list of plausible creator names (sorted, best first)
    indirect_creators_for_consumer: Dict[str, List[str]] = field(default_factory=dict)

    # Analysis metadata
    total_apis: int = 0
    analysis_version: str = "1.1"

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
        """Get analysis statistics. Set-derived lists are sorted for determinism."""
        type_counts = {}
        for ep in self.entry_points:
            type_name = ep.entry_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            'total_apis': self.total_apis,
            'entry_point_count': self.entry_point_count,
            'entry_point_ratio': round(self.entry_point_ratio, 3),
            'by_type': type_counts,
            'entry_point_names': sorted(self.entry_point_names),
            'indirect_pair_count': len(self.indirect_entry_points),
            'indirect_consumer_names': sorted(self.indirect_consumer_names),
            'indirect_creator_names': sorted(self.indirect_creator_names),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary. Set-derived lists are sorted for determinism."""
        return {
            'entry_points': [ep.to_dict() for ep in self.entry_points],
            'entry_point_names': sorted(self.entry_point_names),
            'indirect_entry_points': [p.to_dict() for p in self.indirect_entry_points],
            'indirect_consumer_names': sorted(self.indirect_consumer_names),
            'indirect_creator_names': sorted(self.indirect_creator_names),
            'indirect_creators_for_consumer': dict(self.indirect_creators_for_consumer),
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
        Analyze project APIs to identify Entry Points (direct + indirect).

        Two passes:
        1. Direct: an API whose signature consumes fuzzer input on its own
           (single-step ``LLVMFuzzerTestOneInput(api(data, size))``).
        2. Indirect: an API that consumes fuzzer input *but also* requires a
           handle produced by some other API in the project (two-step:
           ``handle = creator(); consumer(handle, data, size)``).

        Args:
            project_apis: List of API dictionaries with keys:
                - function_name: str
                - return_type: str
                - arguments: List[Dict] with 'type', 'is_const', etc.

        Returns:
            EntryPointAnalysis populated with both direct entry points and
            ``IndirectEntryPoint`` pairs. ``entry_point_names`` is the union
            of direct names and indirect-consumer names so existing callers
            keep working.
        """
        entry_points: List[EntryPointInfo] = []
        non_entry_points: List[Dict[str, Any]] = []
        indirect_consumers: List[Tuple[Dict[str, Any], EntryPointInfo, int, str]] = []

        for api in project_apis:
            ep_info = self._check_entry_point(api)
            if ep_info:
                entry_points.append(ep_info)
                continue
            indirect = self._check_indirect_consumer(api)
            if indirect:
                ep_info, handle_idx, handle_type = indirect
                entry_points.append(ep_info)
                indirect_consumers.append((api, ep_info, handle_idx, handle_type))
            else:
                non_entry_points.append(api)

        # Build the use-def graph and ask it for top-ranked root producers
        # of each consumer's handle. The graph computes ``dependency_depth``
        # internally (see ``UseDefGraph.dependency_depth``), so this single
        # query subsumes our previous hand-written ranker, channel weighting,
        # and iterator filter — all of which are now properties of the same
        # use-def model.
        from liberator_adapter.analysis import UseDefGraph, extract_api_effects
        effects = extract_api_effects(
            project_apis,
            consumed_handle_keys=self._consumed_handle_keys,
            extract_produced_handles=self._extract_produced_handles,
            is_handle_type=self._is_handle_type,
            normalize_handle_type=self._normalize_handle_type,
        )
        graph = UseDefGraph(effects)
        max_creators_per_consumer = 3
        indirect_pairs: List[IndirectEntryPoint] = []
        creators_for_consumer: Dict[str, List[str]] = {}
        for _api, ep_info, handle_idx, handle_type in indirect_consumers:
            handle_key = self._normalize_handle_type(handle_type)
            creators = graph.roots(handle_key, top_k=max_creators_per_consumer)
            if not creators:
                # No producer in the project for this handle. Keep the consumer
                # as an entry-point name (the L0 type DAG may still surface
                # cross-module creators) but skip pair registration.
                continue
            creators_for_consumer[ep_info.function_name] = creators
            for creator_name in creators:
                indirect_pairs.append(IndirectEntryPoint(
                    consumer=ep_info,
                    creator_name=creator_name,
                    handle_arg_index=handle_idx,
                    handle_arg_type=handle_type,
                ))

        analysis = EntryPointAnalysis(
            entry_points=entry_points,
            entry_point_names={ep.function_name for ep in entry_points},
            non_entry_points=non_entry_points,
            indirect_entry_points=indirect_pairs,
            indirect_consumer_names={p.consumer.function_name for p in indirect_pairs},
            indirect_creator_names={p.creator_name for p in indirect_pairs},
            indirect_creators_for_consumer=creators_for_consumer,
            total_apis=len(project_apis),
        )

        self.log.debug(
            f"Entry Point Analysis: {analysis.entry_point_count}/{analysis.total_apis} "
            f"({analysis.entry_point_ratio:.1%}) APIs are Entry Points "
            f"({len(indirect_pairs)} indirect pairs across "
            f"{len(analysis.indirect_consumer_names)} consumers)"
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

        # Indirect-pair lookup: consumer_name -> ranked creator names.
        creators_for_consumer = analysis.indirect_creators_for_consumer
        indirect_consumers = analysis.indirect_consumer_names

        # Strategy match must use *direct-only* names. If an indirect consumer
        # short-circuited the strategy, the bare sequence would be kept without
        # its creator and the resulting driver would deref a NULL handle.
        direct_only_names = entry_names - indirect_consumers

        filtered: List[List[str]] = []
        injected_count = 0
        for seq in sequences:
            if direct_only_names and self._sequence_matches_strategy(
                seq, direct_only_names, strategy, n
            ):
                filtered.append(seq)
                continue
            # Indirect path: a consumer in the prefix is acceptable as long as
            # its creator appears earlier in the same sequence; otherwise we
            # auto-inject the canonical creator at the head (mirrors L2's
            # auto_complete approach).
            patched = self._try_indirect_match(
                seq, indirect_consumers, creators_for_consumer, strategy, n
            )
            if patched is not None:
                if patched is not seq:
                    injected_count += 1
                filtered.append(patched)

        summary = {
            'strategy': strategy,
            'n': n if strategy == "within_first_n" else None,
            'input': len(sequences),
            'output': len(filtered),
            'reduction_ratio': round(1 - len(filtered) / len(sequences), 3) if sequences else 0,
            'entry_point_count': len(entry_names),
            'indirect_pair_count': len(analysis.indirect_entry_points),
            'indirect_creators_injected': injected_count,
        }

        self.log.debug(
            f"Entry Point Filter ({strategy}): {len(sequences)} -> {len(filtered)} sequences "
            f"({summary['reduction_ratio']:.1%} reduction, "
            f"{injected_count} indirect creators auto-injected)"
        )

        return filtered, summary

    def _try_indirect_match(self,
                            seq: List[str],
                            indirect_consumers: Set[str],
                            creators_for_consumer: Dict[str, List[str]],
                            strategy: str,
                            n: int) -> Optional[List[str]]:
        """Accept (and possibly auto-complete) sequences via indirect entries.

        A sequence is accepted if some indirect *consumer* appears within the
        first ``n+1`` positions and either:
          a. one of its registered creators appears earlier in the sequence, or
          b. no such creator is present — in which case we prepend the canonical
             creator (first in the ranked list) at index 0.

        Returns the (possibly patched) sequence, or ``None`` if no indirect
        match could be made.
        """
        if not indirect_consumers or not seq:
            return None
        # The consumer must occur "near the head". Use n+1 because the indirect
        # form unavoidably costs one extra slot for the creator.
        if strategy in ("any", EntryPointFilterStrategy.ANY_POSITION.value):
            window = len(seq)
        elif strategy in ("first", EntryPointFilterStrategy.MUST_BE_FIRST.value):
            # Strict-first does not make sense for indirect (creator must be first);
            # fall back to "creator at 0, consumer at 1".
            window = 2
        else:
            window = max(n + 1, 2)
        for idx in range(min(window, len(seq))):
            consumer_name = seq[idx]
            if consumer_name not in indirect_consumers:
                continue
            creators = creators_for_consumer.get(consumer_name, [])
            if not creators:
                continue
            if any(prev in creators for prev in seq[:idx]):
                return seq  # already well-formed
            # Auto-inject the canonical creator at the head.
            return [creators[0]] + list(seq)
        return None

    def _check_entry_point(self, api: Dict[str, Any]) -> Optional[EntryPointInfo]:
        """
        Check if an API is an Entry Point.

        Checks for multiple input type categories:
        - C_BUFFER_WITH_SIZE: (const uint8_t* data, size_t size)
        - CPP_VIEW: string_view, span<> (no separate size needed)
        - CPP_CONTAINER_REF: const std::vector<>&, const std::string&
        - C_STRING: const char* (null-terminated)

        Args:
            api: API dictionary with function_name, arguments, etc.
                Supports both formats:
                - Standard: arguments[], type, return_type
                - Clang: arguments_info[], type_clang, return_info

        Returns:
            EntryPointInfo if API is an Entry Point, None otherwise.
        """
        func_name = api.get('function_name', '')
        # Support both 'arguments' and 'arguments_info' keys
        args = api.get('arguments', api.get('arguments_info', []))
        # Support both 'return_type' (string) and 'return_info' (dict with type_clang)
        return_info = api.get('return_info', {})
        if isinstance(return_info, dict):
            return_type = return_info.get('type_clang', return_info.get('type', ''))
        else:
            return_type = api.get('return_type', '')

        if not args:
            return None

        type_patterns = self.pattern.type_patterns

        # Determine which argument positions to check
        if self.pattern.scan_all_arguments:
            positions_to_check = range(min(len(args), self.pattern.max_scan_position + 1))
        else:
            positions_to_check = [self.pattern.c_buffer_arg_index, self.pattern.cpp_input_arg_index]
            positions_to_check = [p for p in positions_to_check if p < len(args)]

        # Try to find a matching input argument
        for arg_idx in positions_to_check:
            arg = args[arg_idx]
            # Support both 'type' and 'type_clang' keys
            arg_type = arg.get('type', arg.get('type_clang', ''))
            is_const = self._get_is_const(arg)

            # Determine input category
            category = type_patterns.match_category(arg_type, is_const)

            if category is None:
                continue

            if category not in self.pattern.accepted_categories:
                continue

            # Category-specific validation
            if category == InputTypeCategory.C_BUFFER_WITH_SIZE:
                # Need to find a size argument
                size_info = self._find_size_argument(args, arg_idx)
                if size_info is None:
                    continue
                size_idx, size_type = size_info
            else:
                # C++ view/container types don't need separate size
                size_idx = -1
                size_type = None

            # Additional validation for C buffer: must be const (only when
            # the strict-const policy is active). When admitting non-const,
            # we lower the EntryPointInfo confidence so L4 prefers const
            # alternatives when both exist.
            non_const_buffer = (
                category == InputTypeCategory.C_BUFFER_WITH_SIZE
                and not is_const
            )
            if non_const_buffer and self.pattern.c_buffer_must_be_const:
                continue

            # Reject if any *other* argument (not the buffer, not the size) is
            # handle-shaped. Such APIs require a creator upstream and belong to
            # the indirect entry-point pathway, not the direct one. This guards
            # against e.g. `ucl_parser_add_chunk(parser*, data, size)` being
            # treated as a standalone fuzz target — which would deref a NULL
            # parser.
            has_unrelated_handle = False
            for other_idx, other_arg in enumerate(args):
                if other_idx == arg_idx or other_idx == size_idx:
                    continue
                other_type = other_arg.get('type', other_arg.get('type_clang', ''))
                if self._is_handle_type(other_type):
                    has_unrelated_handle = True
                    break
            if has_unrelated_handle:
                return None

            # Classify entry type based on function name
            entry_type = self._classify_entry_type(func_name)

            # Non-const C buffer entries are real (~5–10% of OSS-Fuzz entry
            # APIs) but lower-precision: the type pattern matches but the
            # const heuristic that worked for const variants is gone. Drop
            # confidence to 0.7 so L4 favours const matches when both exist.
            confidence = 0.7 if non_const_buffer else 1.0
            return EntryPointInfo(
                function_name=func_name,
                return_type=return_type,
                arguments=args,
                entry_type=entry_type,
                input_category=category,
                input_arg_index=arg_idx,
                input_arg_type=arg_type,
                size_arg_index=size_idx,
                size_arg_type=size_type,
                confidence=confidence,
            )

        return None

    # Heuristic: arg types that almost certainly aren't *handles* and so should
    # not register the API as an indirect consumer (avoids treating something
    # like ``my_api(int flags, const uint8_t* data, size_t size)`` as needing
    # an "int producer"). Buffer / size types are filtered separately.
    _NON_HANDLE_PRIMITIVES: Tuple[str, ...] = (
        "int", "long", "short", "char", "size_t", "ssize_t", "bool", "float",
        "double", "void", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "unsigned",
    )

    # Creator name patterns ranked best-first when picking the canonical creator
    # for an indirect entry's handle.
    _CREATOR_PRIORITY_PATTERNS: Tuple[str, ...] = (
        "_new", "_create", "_alloc", "_init", "_open",
    )

    # Production channels for handle delivery. Used to abstract away the C/C++
    # idiomatic differences between "return the handle directly" and "write
    # the handle into a caller-supplied out-pointer". Lower numeric weight =
    # preferred when ranking competing creators.
    _CHANNEL_RETURN: int = 0
    _CHANNEL_OUT_POINTER: int = 1

    def _check_indirect_consumer(
        self, api: Dict[str, Any]
    ) -> Optional[Tuple[EntryPointInfo, int, str]]:
        """Detect APIs that consume fuzzer data *and* require a handle.

        Returns ``(EntryPointInfo, handle_arg_index, handle_arg_type)`` if the
        API has both a buffer-like input slot and at least one handle-typed
        argument that isn't the buffer or its size. Returns ``None`` otherwise.

        We require the API to NOT be a direct entry point; the caller already
        filters that. The buffer search reuses the same matchers as
        ``_check_entry_point`` to keep behaviour consistent.
        """
        args = api.get('arguments', api.get('arguments_info', []))
        if not args:
            return None
        return_info = api.get('return_info', {})
        if isinstance(return_info, dict):
            return_type = return_info.get('type_clang', return_info.get('type', ''))
        else:
            return_type = api.get('return_type', '')

        type_patterns = self.pattern.type_patterns

        # Find a buffer-like argument, plus its size partner if applicable.
        buffer_idx = -1
        buffer_type = ""
        size_idx = -1
        size_type: Optional[str] = None
        category: Optional[InputTypeCategory] = None
        buffer_is_non_const = False
        for arg_idx in range(len(args)):
            arg = args[arg_idx]
            arg_type = arg.get('type', arg.get('type_clang', ''))
            is_const = self._get_is_const(arg)
            cat = type_patterns.match_category(arg_type, is_const)
            if cat is None or cat not in self.pattern.accepted_categories:
                continue
            if cat == InputTypeCategory.C_BUFFER_WITH_SIZE:
                if not is_const:
                    if self.pattern.c_buffer_must_be_const:
                        continue
                    buffer_is_non_const = True
                size_info = self._find_size_argument(args, arg_idx)
                if size_info is None:
                    continue
                size_idx, size_type = size_info
            buffer_idx = arg_idx
            buffer_type = arg_type
            category = cat
            break

        if category is None:
            return None

        # Scan remaining args for a handle-shaped one. A "handle" here is an
        # argument that's neither the buffer nor its size and whose type does
        # not match a primitive scalar — i.e. it must be produced by another
        # API. We pick the first such arg (commonly arg 0).
        handle_idx = -1
        handle_type = ""
        for arg_idx in range(len(args)):
            if arg_idx == buffer_idx or arg_idx == size_idx:
                continue
            arg = args[arg_idx]
            arg_type = arg.get('type', arg.get('type_clang', ''))
            if self._is_handle_type(arg_type):
                handle_idx = arg_idx
                handle_type = arg_type
                break

        if handle_idx < 0:
            return None

        func_name = api.get('function_name', '')
        # Indirect entries are already lower-precision than direct (depend on
        # creator pairing). Penalise non-const buffers further so L4 prefers
        # the const + direct entry over non-const + indirect when both exist.
        base_conf = 0.9
        confidence = base_conf - (0.2 if buffer_is_non_const else 0.0)
        ep_info = EntryPointInfo(
            function_name=func_name,
            return_type=return_type,
            arguments=args,
            entry_type=EntryPointType.INDIRECT,
            input_category=category,
            input_arg_index=buffer_idx,
            input_arg_type=buffer_type,
            size_arg_index=size_idx,
            size_arg_type=size_type,
            confidence=confidence,
        )
        return ep_info, handle_idx, handle_type

    # The four handle-classification primitives below were lifted to
    # ``liberator_adapter/analysis/usedef.py`` as the single source of
    # truth (Aho/Sethi/Ullman §9 — reaching definitions / mod-ref summaries).
    # These wrappers preserve the long-standing private-method signatures
    # used by the rest of EntryPointAnalyzer; the bodies just delegate.

    def _is_handle_type(self, type_str: str) -> bool:
        from liberator_adapter.analysis.usedef import is_handle_type
        return is_handle_type(type_str)

    @staticmethod
    def _normalize_handle_type(type_str: str) -> str:
        from liberator_adapter.analysis.usedef import normalize_handle_type
        return normalize_handle_type(type_str)

    def _extract_produced_handles(
        self, api: Dict[str, Any]
    ) -> List[Tuple[str, int, float]]:
        from liberator_adapter.analysis.usedef import extract_produced_handles
        return extract_produced_handles(api)

    def _consumed_handle_keys(self, api: Dict[str, Any]) -> Set[str]:
        from liberator_adapter.analysis.usedef import consumed_handle_keys
        return consumed_handle_keys(api)

    # NOTE: `_find_buffer_size_positions`, `_count_pointer_levels`,
    # `_strip_one_pointer_level`, `_extract_return_type` were removed in
    # the 2026-05 L1-L5 refactor — they had no callers in this module
    # and the canonical implementations live in
    # `liberator_adapter/analysis/usedef.py`. See
    # `docs/synthesis_refactor_2026_05.md` for the same pattern applied
    # to the synthesis subsystem.

    def _get_is_const(self, arg: Dict[str, Any]) -> bool:
        """Extract const qualifier from argument.

        Supports both formats:
        - Standard: is_const (bool or list)
        - Clang: const (list of bools)
        """
        # Try 'is_const' first (standard format), then 'const' (clang format)
        is_const = arg.get('is_const', arg.get('const', [False]))
        if isinstance(is_const, list):
            return is_const[0] if is_const else False
        return bool(is_const)

    def _find_size_argument(self, args: List[Dict[str, Any]], buffer_idx: int) -> Optional[Tuple[int, str]]:
        """
        Find a size argument for a buffer argument.

        Looks for size argument at expected position or nearby.
        Supports both 'type' and 'type_clang' keys.
        """
        type_patterns = self.pattern.type_patterns

        def get_arg_type(arg: Dict[str, Any]) -> str:
            return arg.get('type', arg.get('type_clang', ''))

        # Check expected position first
        expected_size_idx = self.pattern.c_size_arg_index
        if expected_size_idx < len(args) and expected_size_idx != buffer_idx:
            size_arg = args[expected_size_idx]
            size_type = get_arg_type(size_arg)
            if type_patterns.is_size_type(size_type):
                return (expected_size_idx, size_type)

        # Check argument right after buffer
        next_idx = buffer_idx + 1
        if next_idx < len(args):
            size_arg = args[next_idx]
            size_type = get_arg_type(size_arg)
            if type_patterns.is_size_type(size_type):
                return (next_idx, size_type)

        return None

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
