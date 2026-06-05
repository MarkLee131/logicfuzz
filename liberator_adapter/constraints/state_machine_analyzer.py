"""
L3: State Machine Analyzer - Extract and validate API preconditions/postconditions.

State Machine represents resource lifecycle states and transitions:
- UNINITIALIZED -> INITIALIZED (via init API)
- INITIALIZED -> INITIALIZED (via use API)
- INITIALIZED -> DESTROYED (via destroy API)

This is the third semantic filter in the Progressive Filter Pipeline:
    L0 (Type) -> L1 (Entry Point) -> L2 (Lifecycle) -> L3 (StateMachine) -> L4 (Ranking)

Design principles:
1. Derive state constraints from L2 lifecycle pairs
2. Track resource state through API sequence
3. Detect violations: use-before-init, double-free, missing-cleanup
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple

from liberator_adapter.analysis.usedef import (
    APIEffect, UseDefGraph, Typestate, ViolationKind, ViolationRecord,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

class ResourceState(Enum):
    """State of a resource in the state machine."""

    # Resource has not been initialized
    UNINITIALIZED = "uninitialized"

    # Resource has been initialized and is usable
    INITIALIZED = "initialized"

    # Resource has been destroyed/freed
    DESTROYED = "destroyed"


class APIRole(Enum):
    """Role of an API in the state machine."""

    # Creates/initializes a resource: UNINITIALIZED -> INITIALIZED
    INITIALIZER = "initializer"

    # Destroys/frees a resource: INITIALIZED -> DESTROYED
    DESTROYER = "destroyer"

    # Uses a resource (requires INITIALIZED): INITIALIZED -> INITIALIZED
    USER = "user"

    # No effect on resource state
    NEUTRAL = "neutral"


class ViolationType(Enum):
    """Type of state machine violation."""

    # Using a resource before it's initialized
    USE_BEFORE_INIT = "use_before_init"

    # Destroying a resource before it's initialized
    DESTROY_BEFORE_INIT = "destroy_before_init"

    # Destroying a resource that's already destroyed (double-free)
    DOUBLE_DESTROY = "double_destroy"

    # Using a resource after it's been destroyed (use-after-free)
    USE_AFTER_DESTROY = "use_after_destroy"

    # Re-initializing without destroying (resource leak)
    REINIT_WITHOUT_DESTROY = "reinit_without_destroy"


@dataclass
class StateTransition:
    """A state transition in the state machine."""

    api_name: str
    role: APIRole
    resource_type: str
    from_state: ResourceState
    to_state: ResourceState
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'api_name': self.api_name,
            'role': self.role.value,
            'resource_type': self.resource_type,
            'from_state': self.from_state.value,
            'to_state': self.to_state.value,
            'confidence': self.confidence,
        }


@dataclass
class StateConstraint:
    """A precondition or postcondition for an API."""

    api_name: str

    # Preconditions: required resource states before calling
    preconditions: Dict[str, ResourceState] = field(default_factory=dict)

    # Postconditions: resource states after calling
    postconditions: Dict[str, ResourceState] = field(default_factory=dict)

    # API role for each resource type
    roles: Dict[str, APIRole] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'api_name': self.api_name,
            'preconditions': {k: v.value for k, v in self.preconditions.items()},
            'postconditions': {k: v.value for k, v in self.postconditions.items()},
            'roles': {k: v.value for k, v in self.roles.items()},
        }


@dataclass
class StateViolation:
    """A state machine violation detected in a sequence."""

    violation_type: ViolationType
    api_name: str
    resource_type: str
    expected_state: ResourceState
    actual_state: ResourceState
    position: int  # Position in sequence where violation occurred
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'violation_type': self.violation_type.value,
            'api_name': self.api_name,
            'resource_type': self.resource_type,
            'expected_state': self.expected_state.value,
            'actual_state': self.actual_state.value,
            'position': self.position,
            'message': self.message,
        }


@dataclass
class StateMachineAnalysis:
    """Result of state machine analysis for a project."""

    # State transitions for each API
    transitions: List[StateTransition] = field(default_factory=list)

    # State constraints for each API
    constraints: Dict[str, StateConstraint] = field(default_factory=dict)

    # Resource types tracked
    resource_types: Set[str] = field(default_factory=set)

    # API roles mapping: api_name -> {resource_type: role}
    api_roles: Dict[str, Dict[str, APIRole]] = field(default_factory=dict)

    # Analysis metadata
    total_apis: int = 0

    # Cached typestate graph (built lazily on first ``validate_sequence``).
    _typestate_graph: Optional[Any] = field(default=None, repr=False, compare=False)

    def get_constraint(self, api_name: str) -> Optional[StateConstraint]:
        """Get state constraint for an API."""
        return self.constraints.get(api_name)

    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        role_counts = {role.value: 0 for role in APIRole}
        for api_roles in self.api_roles.values():
            for role in api_roles.values():
                role_counts[role.value] += 1

        return {
            'total_apis': self.total_apis,
            'apis_with_constraints': len(self.constraints),
            'resource_types': sorted(self.resource_types),
            'transition_count': len(self.transitions),
            'by_role': role_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary. Set-derived lists are sorted for determinism."""
        return {
            'transitions': sorted(
                (t.to_dict() for t in self.transitions),
                key=lambda d: (d.get('api_name', ''), d.get('resource_type', ''),
                               d.get('from_state', ''), d.get('to_state', '')),
            ),
            'constraints': {k: v.to_dict() for k, v in self.constraints.items()},
            'resource_types': sorted(self.resource_types),
            'stats': self.get_stats(),
        }


@dataclass
class StateMachineValidationResult:
    """Result of validating a sequence against state machine."""

    is_valid: bool
    violations: List[StateViolation] = field(default_factory=list)

    # Final state of each resource after sequence execution
    final_states: Dict[str, ResourceState] = field(default_factory=dict)

    # Suggested fixes
    suggested_fixes: List[str] = field(default_factory=list)

    # Validation details
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_valid': self.is_valid,
            'violations': [v.to_dict() for v in self.violations],
            'final_states': {k: v.value for k, v in self.final_states.items()},
            'suggested_fixes': self.suggested_fixes,
        }


# =============================================================================
# State Machine Analyzer
# =============================================================================

class StateMachineAnalyzer:
    """
    L3 Filter: Extract state machine and validate sequences.

    Derives state constraints from:
    1. L2 lifecycle pairs (init -> INITIALIZED, destroy requires INITIALIZED)
    2. API naming patterns (use_* typically requires INITIALIZED)
    3. Type-based analysis (APIs taking T* may require T initialized)

    Usage:
        analyzer = StateMachineAnalyzer()
        sm_analysis = analyzer.analyze(project_apis, lifecycle_analysis)
        filtered, summary = analyzer.filter_sequences(sequences, sm_analysis)
    """

    # Keywords that suggest "user" APIs (require initialized resource)
    USER_KEYWORDS = (
        '_get', '_set', '_query', '_send', '_recv', '_read', '_write',
        '_process', '_handle', '_execute', '_call', '_invoke', '_use',
        '_search', '_find', '_lookup', '_cancel', '_timeout', '_expand',
        '_gethostbyname', '_gethostbyaddr', '_getnameinfo', '_getaddrinfo',
    )

    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        """Initialize State Machine Analyzer."""
        self.log = logger_instance or logger

    def analyze(
        self,
        project_apis: List[Dict[str, Any]],
        lifecycle_analysis: Optional[Dict[str, Any]] = None
    ) -> StateMachineAnalysis:
        """
        Analyze project APIs to extract state machine.

        Args:
            project_apis: List of API dictionaries.
            lifecycle_analysis: L2 LifecycleAnalysis result (serialized).

        Returns:
            StateMachineAnalysis with transitions and constraints.
        """
        api_names = {api['function_name'] for api in project_apis}
        transitions = []
        constraints = {}
        api_roles = {}
        resource_types = set()

        # Method 1: Derive from L2 lifecycle pairs
        if lifecycle_analysis:
            lc_transitions, lc_constraints = self._derive_from_lifecycle(
                lifecycle_analysis, api_names
            )
            transitions.extend(lc_transitions)
            for api, constraint in lc_constraints.items():
                constraints[api] = constraint
                api_roles[api] = constraint.roles.copy()
                resource_types.update(constraint.roles.keys())

        # Method 2: Infer user APIs from naming patterns
        user_transitions, user_constraints = self._infer_user_apis(
            api_names, resource_types, constraints
        )
        transitions.extend(user_transitions)
        for api, constraint in user_constraints.items():
            if api not in constraints:
                constraints[api] = constraint
                api_roles[api] = constraint.roles.copy()

        # No source/sink-derived transitions: the former
        # _derive_from_condition_info had a no-op body and was removed. Add a
        # real implementation here if such transitions are ever needed.

        analysis = StateMachineAnalysis(
            transitions=transitions,
            constraints=constraints,
            resource_types=resource_types,
            api_roles=api_roles,
            total_apis=len(project_apis),
        )

        self.log.debug(
            f"State Machine Analysis: {len(constraints)} APIs with constraints, "
            f"{len(resource_types)} resource types"
        )

        return analysis

    def validate_sequence(
        self,
        sequence: List[str],
        analysis: StateMachineAnalysis,
        strict: bool = False
    ) -> StateMachineValidationResult:
        """Validate a sequence against the state machine.

        Delegates the walk to ``Typestate.check`` (``liberator_adapter/
        analysis/usedef.py``). This module owns the *domain model* —
        how ``StateConstraint`` preconditions/postconditions become
        USE/DEF/KILL effects, and how ``ViolationRecord``s map back to
        ``StateViolation``s — while the walker itself is shared.

        ``strict`` toggles REINIT_WITHOUT_DESTROY reporting (the legacy
        walker only emitted it under ``strict=True``; we filter it out
        in the translation step when ``strict`` is false).
        """
        graph = self._ensure_typestate_graph(analysis)
        records = Typestate(graph).check(sequence)

        violations: List[StateViolation] = []
        suggested_fixes: List[str] = []
        resource_states: Dict[str, ResourceState] = {
            rt: ResourceState.UNINITIALIZED for rt in analysis.resource_types
        }

        # Pre-compute the resource state trajectory once so the final
        # ``resource_states`` field carries the same information the legacy
        # walker exposed (last-seen state per resource type).
        for api_name in sequence:
            constraint = analysis.get_constraint(api_name)
            if not constraint:
                continue
            for resource_type, new_state in constraint.postconditions.items():
                resource_states[resource_type] = new_state

        for r in records:
            translated = self._translate(r, strict=strict)
            if translated is None:
                continue
            violations.append(translated)
            if translated.violation_type == ViolationType.USE_BEFORE_INIT:
                suggested_fixes.append(
                    f"Add init API for {r.handle} before position {r.position}"
                )

        is_valid = len(violations) == 0
        return StateMachineValidationResult(
            is_valid=is_valid,
            violations=violations,
            final_states=resource_states,
            suggested_fixes=suggested_fixes,
            details={
                'sequence_length': len(sequence),
                'resources_tracked': len(analysis.resource_types),
            }
        )

    @staticmethod
    def _translate(
        record: ViolationRecord, *, strict: bool
    ) -> Optional[StateViolation]:
        """Map a generic ``ViolationRecord`` into the L3 vocabulary.

        Returns ``None`` when the violation isn't part of L3's surface
        (e.g. UNCLOSED_RESOURCE / UNOPENED_CLOSE belong to L2) or when
        REINIT is suppressed because the caller asked for non-strict mode.
        """
        kind_map = {
            ViolationKind.USE_BEFORE_INIT: ViolationType.USE_BEFORE_INIT,
            ViolationKind.DESTROY_BEFORE_INIT: ViolationType.DESTROY_BEFORE_INIT,
            ViolationKind.DOUBLE_DESTROY: ViolationType.DOUBLE_DESTROY,
            ViolationKind.USE_AFTER_DESTROY: ViolationType.USE_AFTER_DESTROY,
            ViolationKind.REINIT_WITHOUT_DESTROY: ViolationType.REINIT_WITHOUT_DESTROY,
        }
        vtype = kind_map.get(record.kind)
        if vtype is None:
            return None
        if vtype == ViolationType.REINIT_WITHOUT_DESTROY and not strict:
            return None
        # The generic walker exposes ResourceLifecycleState; L3's StateViolation
        # carries ResourceState. The two enums share value strings, so the
        # round-trip is lossless when the record's expected/actual are set.
        def _to_resource_state(v) -> ResourceState:
            if v is None:
                return ResourceState.UNINITIALIZED
            return ResourceState(v.value)
        return StateViolation(
            violation_type=vtype,
            api_name=record.api_name,
            resource_type=record.handle,
            expected_state=_to_resource_state(record.expected),
            actual_state=_to_resource_state(record.actual),
            position=record.position,
        )

    @staticmethod
    def _ensure_typestate_graph(analysis: StateMachineAnalysis) -> UseDefGraph:
        """Build (and cache) a ``UseDefGraph`` from L3 constraints.

        Per ``StateConstraint``:
          - postcond ``X → INITIALIZED`` → ``def_`` X
          - postcond ``X → DESTROYED``   → ``kill`` X
            (``Typestate.check`` flags DESTROY_BEFORE_INIT / DOUBLE_DESTROY
            from the KILL alone — no need to also emit a USE, which would
            falsely report USE_AFTER_DESTROY on the second destroy.)
          - precond  ``X = INITIALIZED`` → ``use`` X
        """
        if analysis._typestate_graph is not None:
            return analysis._typestate_graph

        effects: List[APIEffect] = []
        for name, constraint in analysis.constraints.items():
            use: Set[str] = set()
            def_: Set[str] = set()
            kill: Set[str] = set()
            for rt, required in constraint.preconditions.items():
                if required == ResourceState.INITIALIZED:
                    use.add(rt)
            for rt, target in constraint.postconditions.items():
                if target == ResourceState.INITIALIZED:
                    def_.add(rt)
                elif target == ResourceState.DESTROYED:
                    kill.add(rt)
            # If destroy has both a USE-precondition and a KILL postcondition,
            # drop the USE so the second destroy doesn't trigger a spurious
            # USE_AFTER_DESTROY (the KILL alone yields DOUBLE_DESTROY).
            if kill and use & kill:
                use -= kill
            effects.append(APIEffect(
                name=name,
                use=frozenset(use),
                def_=frozenset(def_),
                kill=frozenset(kill),
            ))
        graph = UseDefGraph(effects)
        analysis._typestate_graph = graph
        return graph

    def filter_sequences(
        self,
        sequences: List[List[str]],
        analysis: StateMachineAnalysis,
        strategy: str = "fixable"
    ) -> Tuple[List[List[str]], Dict[str, Any]]:
        """
        Filter sequences based on state machine validity.

        Args:
            sequences: List of API name sequences.
            analysis: StateMachineAnalysis from analyze().
            strategy: Filter strategy - "strict", "fixable", or "permissive".

        Returns:
            Tuple of (filtered_sequences, filter_summary).
        """
        if not sequences:
            return [], {'strategy': strategy, 'input': 0, 'output': 0}

        filtered = []
        valid_count = 0
        fixable_count = 0
        invalid_count = 0

        # Critical violation types that cannot be fixed
        critical_violations = {
            ViolationType.USE_AFTER_DESTROY,
            ViolationType.DOUBLE_DESTROY,
        }

        # Fixable violation types
        fixable_violations = {
            ViolationType.USE_BEFORE_INIT,
            ViolationType.DESTROY_BEFORE_INIT,
        }

        for seq in sequences:
            validation = self.validate_sequence(seq, analysis, strict=False)

            if validation.is_valid:
                filtered.append(seq)
                valid_count += 1

            elif strategy == "fixable":
                # Check if all violations are fixable
                violation_types = {v.violation_type for v in validation.violations}

                if violation_types <= fixable_violations:
                    # All violations are fixable (missing init can be added)
                    filtered.append(seq)
                    fixable_count += 1
                elif not (violation_types & critical_violations):
                    # No critical violations, keep sequence
                    filtered.append(seq)
                    fixable_count += 1
                else:
                    invalid_count += 1

            elif strategy == "permissive":
                # Only filter out sequences with critical violations
                violation_types = {v.violation_type for v in validation.violations}

                if not (violation_types & critical_violations):
                    filtered.append(seq)
                    fixable_count += 1
                else:
                    invalid_count += 1

            else:  # strict
                invalid_count += 1

        summary = {
            'strategy': strategy,
            'input': len(sequences),
            'output': len(filtered),
            'valid_count': valid_count,
            'fixable_count': fixable_count,
            'invalid_count': invalid_count,
            'resource_types': len(analysis.resource_types),
            'apis_with_constraints': len(analysis.constraints),
        }

        self.log.debug(
            f"State Machine Filter ({strategy}): {len(sequences)} -> {len(filtered)} sequences "
            f"({valid_count} valid, {fixable_count} fixable, {invalid_count} invalid)"
        )

        return filtered, summary

    def _derive_from_lifecycle(
        self,
        lifecycle_analysis: Dict[str, Any],
        api_names: Set[str]
    ) -> Tuple[List[StateTransition], Dict[str, StateConstraint]]:
        """Derive state machine from L2 lifecycle analysis."""
        transitions = []
        constraints = {}

        pairs = lifecycle_analysis.get('pairs', [])
        init_apis = set(lifecycle_analysis.get('init_apis', []))
        destroy_apis = set(lifecycle_analysis.get('destroy_apis', []))

        for pair in pairs:
            init_api = pair.get('init_api', '')
            destroy_api = pair.get('destroy_api', '')
            resource_type = pair.get('resource_type') or f"resource_{init_api}"
            confidence = pair.get('confidence', 0.9)

            # Init API: UNINITIALIZED -> INITIALIZED
            if init_api in api_names:
                transitions.append(StateTransition(
                    api_name=init_api,
                    role=APIRole.INITIALIZER,
                    resource_type=resource_type,
                    from_state=ResourceState.UNINITIALIZED,
                    to_state=ResourceState.INITIALIZED,
                    confidence=confidence,
                ))

                if init_api not in constraints:
                    constraints[init_api] = StateConstraint(api_name=init_api)

                constraints[init_api].postconditions[resource_type] = ResourceState.INITIALIZED
                constraints[init_api].roles[resource_type] = APIRole.INITIALIZER

            # Destroy API: INITIALIZED -> DESTROYED
            if destroy_api in api_names:
                transitions.append(StateTransition(
                    api_name=destroy_api,
                    role=APIRole.DESTROYER,
                    resource_type=resource_type,
                    from_state=ResourceState.INITIALIZED,
                    to_state=ResourceState.DESTROYED,
                    confidence=confidence,
                ))

                if destroy_api not in constraints:
                    constraints[destroy_api] = StateConstraint(api_name=destroy_api)

                constraints[destroy_api].preconditions[resource_type] = ResourceState.INITIALIZED
                constraints[destroy_api].postconditions[resource_type] = ResourceState.DESTROYED
                constraints[destroy_api].roles[resource_type] = APIRole.DESTROYER

        return transitions, constraints

    def _infer_user_apis(
        self,
        api_names: Set[str],
        resource_types: Set[str],
        existing_constraints: Dict[str, StateConstraint]
    ) -> Tuple[List[StateTransition], Dict[str, StateConstraint]]:
        """Infer user APIs that require initialized resources."""
        transitions = []
        constraints = {}

        # Skip if no resource types discovered
        if not resource_types:
            return transitions, constraints

        # Find common prefix from resource types to match APIs.
        # Sort both api_names and resource_types so the first-match-wins
        # semantics below are deterministic across Python invocations
        # (set iteration order is hash-randomized).
        prefixes = self._find_common_prefixes(resource_types)
        sorted_resource_types = sorted(resource_types)

        for api_name in sorted(api_names):
            # Skip APIs already in constraints
            if api_name in existing_constraints:
                continue

            # Check if API name contains user keywords
            api_lower = api_name.lower()
            is_user_api = any(kw in api_lower for kw in self.USER_KEYWORDS)

            if is_user_api:
                # Find matching resource type based on prefix
                matching_resource = None
                for prefix in prefixes:
                    if api_name.startswith(prefix):
                        # Find resource type with same prefix
                        for rt in sorted_resource_types:
                            if rt.startswith(prefix) or prefix in rt:
                                matching_resource = rt
                                break
                    if matching_resource:
                        break

                # If no specific match, use first resource type as default
                if not matching_resource and resource_types:
                    # Try to find resource by prefix matching
                    for rt in resource_types:
                        rt_prefix = rt.split('_')[0] if '_' in rt else rt
                        api_prefix = api_name.split('_')[0] if '_' in api_name else ''
                        if rt_prefix == api_prefix:
                            matching_resource = rt
                            break

                if matching_resource:
                    transitions.append(StateTransition(
                        api_name=api_name,
                        role=APIRole.USER,
                        resource_type=matching_resource,
                        from_state=ResourceState.INITIALIZED,
                        to_state=ResourceState.INITIALIZED,
                        confidence=0.6,  # Lower confidence for inferred
                    ))

                    constraints[api_name] = StateConstraint(
                        api_name=api_name,
                        preconditions={matching_resource: ResourceState.INITIALIZED},
                        postconditions={matching_resource: ResourceState.INITIALIZED},
                        roles={matching_resource: APIRole.USER},
                    )

        return transitions, constraints

    def _find_common_prefixes(self, names: Set[str]) -> List[str]:
        """Find common prefixes in names."""
        prefix_counts = {}

        for name in names:
            parts = name.split('_')
            if len(parts) >= 1:
                prefix = parts[0]
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1

        # Return prefixes sorted by frequency
        return sorted(prefix_counts.keys(), key=lambda p: prefix_counts[p], reverse=True)


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_state_machine(
    project_apis: List[Dict[str, Any]],
    lifecycle_analysis: Optional[Dict[str, Any]] = None,
    logger_instance: Optional[logging.Logger] = None
) -> StateMachineAnalysis:
    """
    Convenience function to analyze state machine.

    Args:
        project_apis: List of API dictionaries.
        lifecycle_analysis: L2 LifecycleAnalysis result (serialized).
        logger_instance: Optional logger.

    Returns:
        StateMachineAnalysis result.
    """
    analyzer = StateMachineAnalyzer(logger_instance=logger_instance)
    return analyzer.analyze(project_apis, lifecycle_analysis)


def filter_sequences_by_state_machine(
    sequences: List[List[str]],
    analysis: StateMachineAnalysis,
    strategy: str = "fixable",
    logger_instance: Optional[logging.Logger] = None
) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Convenience function to filter sequences by state machine.

    Args:
        sequences: List of API name sequences.
        analysis: StateMachineAnalysis from analyze_state_machine().
        strategy: Filter strategy - "strict", "fixable", or "permissive".
        logger_instance: Optional logger.

    Returns:
        Tuple of (filtered_sequences, filter_summary).
    """
    analyzer = StateMachineAnalyzer(logger_instance=logger_instance)
    return analyzer.filter_sequences(sequences, analysis, strategy)
