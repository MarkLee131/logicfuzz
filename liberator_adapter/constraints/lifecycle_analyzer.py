"""
L2: Lifecycle Analyzer - Discover and validate resource lifecycle patterns.

Lifecycle pairs are init-destroy relationships between APIs:
- init API: Creates/allocates a resource (e.g., ares_init, ares_dns_parse)
- destroy API: Frees/destroys the resource (e.g., ares_destroy, ares_free_data)

This is the second semantic filter in the Progressive Filter Pipeline:
    L0 (Type) -> L1 (Entry Point) -> L2 (Lifecycle) -> L3 (StateMachine) -> L4 (Ranking)

Design principles:
1. Pattern-based discovery (name matching + type analysis)
2. Support for shared cleanup APIs (multiple inits -> one destroy)
3. Sequence validation ensures proper resource management
"""

import logging
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple

from liberator_adapter.analysis.usedef import (
    APIEffect, UseDefGraph, Typestate, ViolationKind,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

class LifecycleRole(Enum):
    """Role of an API in resource lifecycle."""

    # Creates/initializes a resource
    INIT = "init"

    # Destroys/frees a resource
    DESTROY = "destroy"

    # Uses but doesn't create or destroy
    USE = "use"

    # Unknown role
    UNKNOWN = "unknown"


class DiscoveryMethod(Enum):
    """How the lifecycle pair was discovered."""

    # Name pattern matching (e.g., xxx_init -> xxx_destroy)
    NAME_PATTERN = "name_pattern"

    # Type-based matching (returns T* -> takes T* and frees)
    TYPE_PATTERN = "type_pattern"

    # Semantic pattern (e.g., all parsers use ares_free_data)
    SEMANTIC_PATTERN = "semantic_pattern"

    # From condition_info sinks
    CONDITION_INFO = "condition_info"

    # Manual/hardcoded rule
    MANUAL = "manual"


@dataclass
class LifecyclePair:
    """A pair of init-destroy APIs for a resource type."""

    # Init API name
    init_api: str

    # Destroy API name
    destroy_api: str

    # Resource type (if known)
    resource_type: Optional[str] = None

    # How this pair was discovered
    discovery_method: DiscoveryMethod = DiscoveryMethod.NAME_PATTERN

    # Confidence score (0.0 - 1.0)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'init_api': self.init_api,
            'destroy_api': self.destroy_api,
            'resource_type': self.resource_type,
            'discovery_method': self.discovery_method.value,
            'confidence': self.confidence,
        }


@dataclass
class LifecycleAnalysis:
    """Result of lifecycle analysis for a project."""

    # All discovered lifecycle pairs
    pairs: List[LifecyclePair] = field(default_factory=list)

    # Mapping: init_api -> list of destroy APIs
    init_to_destroy: Dict[str, List[str]] = field(default_factory=dict)

    # Mapping: destroy_api -> list of init APIs
    destroy_to_init: Dict[str, List[str]] = field(default_factory=dict)

    # Set of all init API names
    init_apis: Set[str] = field(default_factory=set)

    # Set of all destroy API names
    destroy_apis: Set[str] = field(default_factory=set)

    # Analysis metadata
    total_apis: int = 0

    # Cached typestate graph derived from ``pairs`` (built lazily on first
    # ``validate_sequence`` call). Not persisted by ``to_dict`` — it's a
    # pure function of the pair set and reconstructible on demand.
    _typestate_graph: Optional[Any] = field(default=None, repr=False, compare=False)
    _resource_to_inits: Optional[Dict[str, List[str]]] = field(
        default=None, repr=False, compare=False)

    def __post_init__(self):
        """Build lookup dictionaries from pairs."""
        if self.pairs and not self.init_to_destroy:
            self._build_lookups()

    def _build_lookups(self):
        """Build lookup dictionaries from pairs."""
        for pair in self.pairs:
            # init -> destroy mapping
            if pair.init_api not in self.init_to_destroy:
                self.init_to_destroy[pair.init_api] = []
            if pair.destroy_api not in self.init_to_destroy[pair.init_api]:
                self.init_to_destroy[pair.init_api].append(pair.destroy_api)

            # destroy -> init mapping
            if pair.destroy_api not in self.destroy_to_init:
                self.destroy_to_init[pair.destroy_api] = []
            if pair.init_api not in self.destroy_to_init[pair.destroy_api]:
                self.destroy_to_init[pair.destroy_api].append(pair.init_api)

            # Update sets
            self.init_apis.add(pair.init_api)
            self.destroy_apis.add(pair.destroy_api)

    def get_destroy_for_init(self, init_api: str) -> List[str]:
        """Get destroy APIs for an init API."""
        return self.init_to_destroy.get(init_api, [])

    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            'total_apis': self.total_apis,
            'pair_count': len(self.pairs),
            'init_api_count': len(self.init_apis),
            'destroy_api_count': len(self.destroy_apis),
            'by_method': self._count_by_method(),
        }

    def _count_by_method(self) -> Dict[str, int]:
        """Count pairs by discovery method."""
        counts = {}
        for pair in self.pairs:
            method = pair.discovery_method.value
            counts[method] = counts.get(method, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary. Set-derived lists are sorted for determinism."""
        return {
            'pairs': sorted(
                (p.to_dict() for p in self.pairs),
                key=lambda d: (d.get('init_api', ''), d.get('destroy_api', '')),
            ),
            'init_apis': sorted(self.init_apis),
            'destroy_apis': sorted(self.destroy_apis),
            'stats': self.get_stats(),
        }


@dataclass
class LifecycleValidationResult:
    """Result of validating a sequence's lifecycle correctness."""

    # Whether the sequence has valid lifecycle
    is_valid: bool

    # Resources that are opened but not closed
    unclosed_resources: List[str] = field(default_factory=list)

    # Resources that are closed without being opened
    unopened_closes: List[str] = field(default_factory=list)

    # Suggested destroy APIs to add at end
    suggested_cleanup: List[str] = field(default_factory=list)

    # Validation details
    details: Dict[str, Any] = field(default_factory=dict)


class LifecycleFilterStrategy(Enum):
    """Strategy for filtering sequences by lifecycle validity."""

    # Keep only sequences with complete lifecycle (all resources cleaned)
    STRICT = "strict"

    # Keep sequences that can be auto-completed with cleanup
    AUTO_COMPLETE = "auto_complete"

    # Keep all sequences but annotate with needed cleanup
    ANNOTATE_ONLY = "annotate_only"


# =============================================================================
# Lifecycle Analyzer
# =============================================================================

class LifecycleAnalyzer:
    """
    L2 Filter: Discover lifecycle pairs and validate sequences.

    Discovers init-destroy pairs through:
    1. Name pattern matching (xxx_init -> xxx_destroy)
    2. Type-based matching (returns T* -> takes T* and frees)
    3. Semantic patterns (all parsers -> shared free function)
    4. condition_info sinks

    Usage:
        analyzer = LifecycleAnalyzer()
        analysis = analyzer.analyze(project_apis, condition_info)
        filtered, summary = analyzer.filter_sequences(sequences, analysis)
    """

    # Name patterns for init-destroy matching
    INIT_DESTROY_PATTERNS = [
        # (init_regex, destroy_regex)
        (r'^(.+)_init$', r'\1_destroy'),
        (r'^(.+)_init$', r'\1_cleanup'),
        (r'^(.+)_init$', r'\1_fini'),
        (r'^(.+)_create$', r'\1_destroy'),
        (r'^(.+)_create$', r'\1_delete'),
        (r'^(.+)_create$', r'\1_free'),
        (r'^(.+)_new$', r'\1_free'),
        (r'^(.+)_new$', r'\1_delete'),
        (r'^(.+)_open$', r'\1_close'),
        (r'^(.+)_alloc$', r'\1_free'),
        (r'^(.+)_alloc$', r'\1_dealloc'),
        (r'^(.+)_start$', r'\1_stop'),
        (r'^(.+)_begin$', r'\1_end'),
        (r'^(.+)_acquire$', r'\1_release'),
        (r'^(.+)_lock$', r'\1_unlock'),
        (r'^(.+)_ref$', r'\1_unref'),
        (r'^(.+)_dup$', r'\1_free'),
    ]

    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        """Initialize Lifecycle Analyzer."""
        self.log = logger_instance or logger

    def analyze(self,
                project_apis: List[Dict[str, Any]],
                condition_info: Optional[Dict[str, Any]] = None) -> LifecycleAnalysis:
        """
        Analyze project APIs to discover lifecycle pairs.

        Args:
            project_apis: List of API dictionaries.
            condition_info: Optional condition info with sinks/inits.

        Returns:
            LifecycleAnalysis with discovered pairs.
        """
        api_names = set(api['function_name'] for api in project_apis)
        pairs = []

        # Method 1: Name pattern matching
        pattern_pairs = self._discover_by_name_pattern(api_names)
        pairs.extend(pattern_pairs)

        # Method 2: From condition_info sinks
        if condition_info:
            sink_pairs = self._discover_from_sinks(api_names, condition_info)
            pairs.extend(sink_pairs)

        # Method 3: Semantic patterns (project-specific)
        semantic_pairs = self._discover_semantic_patterns(api_names)
        pairs.extend(semantic_pairs)

        # Deduplicate pairs
        pairs = self._deduplicate_pairs(pairs)

        analysis = LifecycleAnalysis(
            pairs=pairs,
            total_apis=len(project_apis),
        )
        analysis._build_lookups()

        self.log.debug(
            f"Lifecycle Analysis: discovered {len(pairs)} pairs "
            f"({len(analysis.init_apis)} init, {len(analysis.destroy_apis)} destroy)"
        )

        return analysis

    def validate_sequence(self,
                          sequence: List[str],
                          analysis: LifecycleAnalysis) -> LifecycleValidationResult:
        """Validate a sequence's lifecycle correctness.

        Delegates the actual walk to ``Typestate.check`` so the typestate
        semantics live in exactly one place (see ``liberator_adapter/
        analysis/usedef.py``). This module owns only the L2 *domain model*
        — how lifecycle pairs become USE/DEF/KILL effects, and how
        ``ViolationRecord``s map back to ``LifecycleValidationResult``.

        Keying difference vs. the legacy walker: open counts are kept per
        *resource type* rather than per *init-API name*. For consistent pair
        sets the two are equivalent — see ``_build_typestate_graph`` below
        for the encoding. ``unclosed_resources`` is reported in terms of the
        init APIs the caller cares about (recovered via the resource→inits
        inverse map cached on the analysis).
        """
        graph = self._ensure_typestate_graph(analysis)
        violations = Typestate(graph).check(sequence)

        unclosed_inits: List[str] = []
        unopened_closes: List[str] = []
        for v in violations:
            if v.kind == ViolationKind.UNCLOSED_RESOURCE:
                # Map resource → an init API that produces it. First pick is
                # deterministic (init_to_destroy is dict-ordered by pair
                # insertion, which mirrors the discovery order).
                init_candidates = (analysis._resource_to_inits or {}).get(
                    v.handle, []
                )
                if init_candidates:
                    unclosed_inits.append(init_candidates[0])
            elif v.kind in (ViolationKind.UNOPENED_CLOSE,
                            ViolationKind.DESTROY_BEFORE_INIT,
                            ViolationKind.DOUBLE_DESTROY):
                unopened_closes.append(v.api_name)

        suggested_cleanup: List[str] = []
        for init_api in unclosed_inits:
            destroy_apis = analysis.get_destroy_for_init(init_api)
            if destroy_apis:
                suggested_cleanup.append(destroy_apis[0])

        is_valid = not unclosed_inits and not unopened_closes

        return LifecycleValidationResult(
            is_valid=is_valid,
            unclosed_resources=unclosed_inits,
            unopened_closes=unopened_closes,
            suggested_cleanup=suggested_cleanup,
            details={
                'sequence_length': len(sequence),
                'init_calls': sum(1 for api in sequence if api in analysis.init_apis),
                'destroy_calls': sum(1 for api in sequence if api in analysis.destroy_apis),
            }
        )

    @staticmethod
    def _ensure_typestate_graph(analysis: LifecycleAnalysis) -> UseDefGraph:
        """Build (and cache on the analysis) a ``UseDefGraph`` for L2 pairs.

        Encoding:
        - init API → ``APIEffect(def_={resource_type})``
        - destroy API → ``APIEffect(kill={resource_type})``
          (``Typestate.check`` raises DESTROY_BEFORE_INIT from KILL alone
          when ``state==UNINITIALIZED ∧ opens==0``; adding USE here would
          falsely flag double-destroy as USE_AFTER_DESTROY too.)

        A single API can appear in multiple pairs (e.g. one destroy paired
        with several inits sharing a resource); the effects merge by set
        union, matching the legacy walker's "any matching init counts".
        """
        if analysis._typestate_graph is not None:
            return analysis._typestate_graph

        accumulated: Dict[str, Dict[str, Set[str]]] = {}
        resource_to_inits: Dict[str, List[str]] = {}

        def _slot(api_name: str) -> Dict[str, Set[str]]:
            return accumulated.setdefault(api_name, {
                'use': set(), 'def_': set(), 'kill': set(),
            })

        for pair in analysis.pairs:
            init_api = pair.init_api
            destroy_api = pair.destroy_api
            resource_type = pair.resource_type or f"resource_{init_api}"
            _slot(init_api)['def_'].add(resource_type)
            _slot(destroy_api)['kill'].add(resource_type)
            # Insertion-order list, deduped.
            inits = resource_to_inits.setdefault(resource_type, [])
            if init_api not in inits:
                inits.append(init_api)

        effects = [
            APIEffect(
                name=name,
                use=frozenset(slot['use']),
                def_=frozenset(slot['def_']),
                kill=frozenset(slot['kill']),
            )
            for name, slot in accumulated.items()
        ]
        graph = UseDefGraph(effects)
        analysis._typestate_graph = graph
        analysis._resource_to_inits = resource_to_inits
        return graph

    def filter_sequences(self,
                         sequences: List[List[str]],
                         analysis: LifecycleAnalysis,
                         strategy: str = "auto_complete") -> Tuple[List[List[str]], Dict[str, Any]]:
        """
        Filter sequences based on lifecycle validity.

        Args:
            sequences: List of API name sequences.
            analysis: LifecycleAnalysis from analyze().
            strategy: Filter strategy - "strict", "auto_complete", or "annotate_only".

        Returns:
            Tuple of (filtered_sequences, filter_summary).
        """
        if not sequences:
            return [], {'strategy': strategy, 'input': 0, 'output': 0}

        filtered = []
        auto_completed = []
        invalid_count = 0

        for seq in sequences:
            validation = self.validate_sequence(seq, analysis)

            if strategy == "strict":
                if validation.is_valid:
                    filtered.append(seq)
                else:
                    invalid_count += 1

            elif strategy == "auto_complete":
                if validation.is_valid:
                    filtered.append(seq)
                elif validation.suggested_cleanup:
                    # Auto-complete by adding cleanup at end
                    completed_seq = seq + validation.suggested_cleanup
                    filtered.append(completed_seq)
                    auto_completed.append(seq)
                else:
                    # Can't auto-complete AND invalid — drop. The previous
                    # behaviour (keep anyway) made `auto_complete` and
                    # `permissive` indistinguishable and let unfix-able
                    # invalid sequences leak through to L4 → downstream
                    # never realised L2 had actually rejected them.
                    invalid_count += 1

            elif strategy == "annotate_only":
                # Keep all sequences
                filtered.append(seq)

        summary = {
            'strategy': strategy,
            'input': len(sequences),
            'output': len(filtered),
            'valid_count': len(sequences) - invalid_count,
            'invalid_count': invalid_count,
            'auto_completed_count': len(auto_completed),
            'pair_count': len(analysis.pairs),
        }

        self.log.debug(
            f"Lifecycle Filter ({strategy}): {len(sequences)} -> {len(filtered)} sequences"
        )

        return filtered, summary

    def _discover_by_name_pattern(self, api_names: Set[str]) -> List[LifecyclePair]:
        """Discover pairs by name pattern matching."""
        pairs = []

        for init_api in api_names:
            for init_re, destroy_re in self.INIT_DESTROY_PATTERNS:
                match = re.match(init_re, init_api, re.IGNORECASE)
                if match:
                    # Construct expected destroy name
                    base = match.group(1)
                    expected_destroy = re.sub(init_re, destroy_re, init_api)

                    if expected_destroy in api_names:
                        pairs.append(LifecyclePair(
                            init_api=init_api,
                            destroy_api=expected_destroy,
                            resource_type=base,
                            discovery_method=DiscoveryMethod.NAME_PATTERN,
                            confidence=0.9,
                        ))

        return pairs

    def _discover_from_sinks(self,
                              api_names: Set[str],
                              condition_info: Dict[str, Any]) -> List[LifecyclePair]:
        """Discover pairs from condition_info sinks."""
        pairs = []
        sinks = set(condition_info.get('sinks', []))

        # For each sink, try to find matching init
        reverse_patterns = [
            (r'^(.+)_destroy$', r'\1_init'),
            (r'^(.+)_destroy$', r'\1_create'),
            (r'^(.+)_delete$', r'\1_create'),
            (r'^(.+)_delete$', r'\1_new'),
            (r'^(.+)_free$', r'\1_new'),
            (r'^(.+)_free$', r'\1_alloc'),
            (r'^(.+)_free$', r'\1_dup'),
            (r'^(.+)_close$', r'\1_open'),
            (r'^(.+)_cleanup$', r'\1_init'),
            (r'^(.+)_fini$', r'\1_init'),
        ]

        for sink in sinks:
            if sink not in api_names:
                continue

            for destroy_re, init_re in reverse_patterns:
                match = re.match(destroy_re, sink, re.IGNORECASE)
                if match:
                    base = match.group(1)
                    expected_init = re.sub(destroy_re, init_re, sink)

                    if expected_init in api_names:
                        pairs.append(LifecyclePair(
                            init_api=expected_init,
                            destroy_api=sink,
                            resource_type=base,
                            discovery_method=DiscoveryMethod.CONDITION_INFO,
                            confidence=0.85,
                        ))

        return pairs

    def _discover_semantic_patterns(self, api_names: Set[str]) -> List[LifecyclePair]:
        """Discover pairs by semantic patterns (project-specific)."""
        pairs = []

        # Find common prefixes to detect project naming convention
        prefixes = self._find_common_prefixes(api_names)

        for prefix in prefixes:
            # Pattern: {prefix}_parse_*_reply -> {prefix}_free_data
            parse_apis = [
                name for name in api_names
                if name.startswith(f'{prefix}_parse_') and name.endswith('_reply')
            ]
            free_data_api = f'{prefix}_free_data'

            if parse_apis and free_data_api in api_names:
                for parse_api in parse_apis:
                    pairs.append(LifecyclePair(
                        init_api=parse_api,
                        destroy_api=free_data_api,
                        resource_type='parsed_data',
                        discovery_method=DiscoveryMethod.SEMANTIC_PATTERN,
                        confidence=0.8,
                    ))

            # Pattern: {prefix}_dns_parse -> {prefix}_dns_record_destroy
            dns_parse = f'{prefix}_dns_parse'
            dns_destroy = f'{prefix}_dns_record_destroy'
            if dns_parse in api_names and dns_destroy in api_names:
                pairs.append(LifecyclePair(
                    init_api=dns_parse,
                    destroy_api=dns_destroy,
                    resource_type='dns_record',
                    discovery_method=DiscoveryMethod.SEMANTIC_PATTERN,
                    confidence=0.9,
                ))

        return pairs

    def _find_common_prefixes(self, api_names: Set[str]) -> List[str]:
        """Find common prefixes in API names."""
        prefix_counts = {}

        for name in api_names:
            parts = name.split('_')
            if len(parts) >= 2:
                prefix = parts[0]
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1

        # Return prefixes that appear in at least 5 APIs
        return [
            prefix for prefix, count in prefix_counts.items()
            if count >= 5
        ]

    def _deduplicate_pairs(self, pairs: List[LifecyclePair]) -> List[LifecyclePair]:
        """Remove duplicate pairs, keeping highest confidence."""
        seen = {}

        for pair in pairs:
            key = (pair.init_api, pair.destroy_api)
            if key not in seen or pair.confidence > seen[key].confidence:
                seen[key] = pair

        return list(seen.values())


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_lifecycle(
    project_apis: List[Dict[str, Any]],
    condition_info: Optional[Dict[str, Any]] = None,
    logger_instance: Optional[logging.Logger] = None
) -> LifecycleAnalysis:
    """
    Convenience function to analyze lifecycle pairs.

    Args:
        project_apis: List of API dictionaries.
        condition_info: Optional condition info with sinks.
        logger_instance: Optional logger.

    Returns:
        LifecycleAnalysis result.
    """
    analyzer = LifecycleAnalyzer(logger_instance=logger_instance)
    return analyzer.analyze(project_apis, condition_info)


def filter_sequences_by_lifecycle(
    sequences: List[List[str]],
    analysis: LifecycleAnalysis,
    strategy: str = "auto_complete",
    logger_instance: Optional[logging.Logger] = None
) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Convenience function to filter sequences by lifecycle.

    Args:
        sequences: List of API name sequences.
        analysis: LifecycleAnalysis from analyze_lifecycle().
        strategy: Filter strategy - "strict", "auto_complete", or "annotate_only".
        logger_instance: Optional logger.

    Returns:
        Tuple of (filtered_sequences, filter_summary).
    """
    analyzer = LifecycleAnalyzer(logger_instance=logger_instance)
    return analyzer.filter_sequences(sequences, analysis, strategy)
