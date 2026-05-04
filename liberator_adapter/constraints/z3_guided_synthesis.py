"""
Z3-Guided Synthesis for LogicFuzz

Transforms Z3 from a post-hoc validator to a core decision participant,
using constraint solving to guide driver generation at each decision point.

Key components:
1. IncrementalZ3Solver - Push/pop based incremental solving
2. Extended constraint types for decision guidance
3. UnsatCoreDiagnoser - Intelligent failure diagnosis
4. Integration points for CBFactory decision guidance

Author: LogicFuzz Team
"""

import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from z3 import Solver, Bool, Int, And, Implies, sat, unsat
Z3_AVAILABLE = True

logger = logging.getLogger(__name__)


# ============================================================
# Extended Constraint Types for Decision Guidance
# ============================================================

class GuidanceConstraintType(Enum):
    """Extended constraint types for Z3-guided decision making"""
    # Original types (from z3_solver.py)
    TYPE_MATCH = "type_match"
    ACCESS_ORDER = "access_order"
    PROVENANCE = "provenance"
    DEPENDENCY = "dependency"
    NULLABILITY = "nullability"
    ARRAY_BOUNDS = "array_bounds"
    RESOURCE_LIFECYCLE = "lifecycle"

    # New types for decision guidance
    VARIABLE_AVAILABILITY = "variable_availability"  # Variable exists and is usable
    RESOURCE_EXISTENCE = "resource_existence"        # Required resource type exists
    PARAMETER_BINDING = "parameter_binding"          # Parameter binds to valid variable
    INIT_COMPLETION = "init_completion"              # Initialization API has been called
    PRODUCER_REQUIRED = "producer_required"          # A producer API is needed


# ============================================================
# Result Types
# ============================================================

class SatisfiabilityStatus(Enum):
    """Result of satisfiability check"""
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class SatisfiabilityResult:
    """Result of a satisfiability check"""
    status: SatisfiabilityStatus
    model: Optional[Dict[str, Any]] = None
    unsat_core: Optional[List[str]] = None

    @property
    def is_sat(self) -> bool:
        return self.status == SatisfiabilityStatus.SAT

    @property
    def is_unsat(self) -> bool:
        return self.status == SatisfiabilityStatus.UNSAT


@dataclass
class CandidateResult:
    """Result of testing a candidate API"""
    api_name: str
    is_feasible: bool
    score: float = 0.0  # Lower is better (complexity score)
    missing_resources: List[str] = field(default_factory=list)
    conflicting_constraints: List[str] = field(default_factory=list)


class DiagnosisType(Enum):
    """Types of constraint failure diagnosis"""
    MISSING_RESOURCE = "missing_resource"
    LIFECYCLE_VIOLATION = "lifecycle_violation"
    TYPE_MISMATCH = "type_mismatch"
    BINDING_CONFLICT = "binding_conflict"
    ORDER_VIOLATION = "order_violation"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    """Suggested recovery actions for constraint failures"""
    ADD_PRODUCER = "add_producer"
    TRY_DIFFERENT_SOURCE = "try_different_source"
    REORDER_APIS = "reorder_apis"
    REMOVE_CONFLICTING = "remove_conflicting"
    BACKTRACK = "backtrack"
    ABORT = "abort"


@dataclass
class UnsatDiagnosis:
    """Diagnosis result for unsatisfiable constraints"""
    diagnosis_type: DiagnosisType
    conflicting_constraints: List[str]
    missing_resources: List[str] = field(default_factory=list)
    suggested_actions: List[RecoveryAction] = field(default_factory=list)
    details: str = ""


@dataclass
class VariableState:
    """State of a variable in the synthesis context"""
    name: str
    type_str: str
    is_initialized: bool = False
    is_consumed: bool = False
    producer_api: Optional[str] = None
    checkpoint_level: int = 0


# ============================================================
# Incremental Z3 Solver
# ============================================================

# ============================================================
# AutomatonAcceptanceGuard — Phase H hard-pruning gate
# ============================================================
#
# Treats automaton acceptance as a *hard* constraint at synthesis time, but
# only when the project automaton has accumulated enough evidence to be
# trusted. Three safety mechanisms keep this from over-pruning:
#
#   1. **Strength gate**: silent no-op unless ``observed_apis ≥ N_min`` and
#      ``n_merged_states ≥ S_min``. Weak automatons (no traces, tiny merge
#      quotient) admit everything.
#   2. **Auto-relaxation**: after ``unsat_relax_count`` consecutive UNSAT
#      verdicts the threshold drops by ``relax_step``. Mirrors how Z3's
#      UnsatCoreDiagnoser informs synthesis recovery — but here recovery is
#      "loosen the soft cut" rather than "find a producer".
#   3. **Float-on-failure**: any exception from the artifact (e.g. mid-merge
#      pickled state, malformed sequence) admits the candidate and logs.
#      Fail-open is the right default for a soft signal promoted to hard.
#
# Reference: Lang/Pearlmutter/Price 1998 §5 — the EDSM merge oracle is
# advisory; here we use the same convention (oracle-says-no → reject the
# *candidate*, not the *automaton*).


class AutomatonAcceptanceGuard:
    """Hard-pruning gate based on project automaton acceptance.

    Wraps an ``AutomatonArtifact`` and exposes ``admits(sequence) -> bool``
    that synthesis loops consult before committing a candidate API. The
    guard is **strong-only**: weak/missing artifacts return ``True``
    unconditionally so projects without learnable typestate behaviour aren't
    starved.

    Stats are exposed via :py:meth:`stats` for telemetry; callers should
    log them after synthesis to size the relax cadence and threshold.
    """

    def __init__(
        self,
        artifact: Optional[Any] = None,
        threshold: float = 0.6,
        min_observed_apis: int = 10,
        min_merged_states: int = 4,
        unsat_relax_count: int = 5,
        relax_step: float = 0.15,
    ) -> None:
        self.artifact = artifact
        self.initial_threshold = float(threshold)
        self.threshold = float(threshold)
        self.min_observed_apis = int(min_observed_apis)
        self.min_merged_states = int(min_merged_states)
        self.unsat_relax_count = int(unsat_relax_count)
        self.relax_step = float(relax_step)
        self._consecutive_reject = 0
        self.n_pruned = 0
        self.n_passed = 0
        self.n_relaxes = 0
        self.n_errors = 0
        self._strong = self._compute_strength()

    def _compute_strength(self) -> bool:
        if self.artifact is None:
            return False
        try:
            n_obs = len(self.artifact.observed_apis())
            n_states = int(self.artifact.n_merged_states)
        except Exception:
            return False
        return (n_obs >= self.min_observed_apis
                and n_states >= self.min_merged_states)

    def is_strong(self) -> bool:
        return self._strong

    def admits(self, candidate_sequence: List[str]) -> bool:
        """``True`` iff guard is weak (always admit) or sequence acceptance
        clears the *current* threshold. Side-effects: increments stats and
        auto-relaxes on consecutive rejects.
        """
        if not self._strong or self.artifact is None:
            self.n_passed += 1
            return True
        try:
            score = float(self.artifact.acceptance_score(candidate_sequence))
        except Exception as exc:
            logger.debug("[AutomatonGuard] acceptance_score raised %s; "
                         "fail-open admit", exc)
            self.n_errors += 1
            self.n_passed += 1
            return True
        if score >= self.threshold:
            self.n_passed += 1
            self._consecutive_reject = 0
            return True
        self.n_pruned += 1
        self._consecutive_reject += 1
        if self._consecutive_reject >= self.unsat_relax_count:
            new_thr = max(0.0, self.threshold - self.relax_step)
            if new_thr < self.threshold:
                self.threshold = new_thr
                self.n_relaxes += 1
                self._consecutive_reject = 0
                logger.info(
                    "[AutomatonGuard] %d consecutive rejects → relax "
                    "threshold to %.3f",
                    self.unsat_relax_count, self.threshold,
                )
        return False

    def stats(self) -> Dict[str, Any]:
        return {
            "strong": self._strong,
            "threshold": round(self.threshold, 4),
            "initial_threshold": round(self.initial_threshold, 4),
            "pruned": self.n_pruned,
            "passed": self.n_passed,
            "relaxes": self.n_relaxes,
            "errors": self.n_errors,
        }


class IncrementalZ3Solver:
    """
    Incremental Z3 solver supporting push/pop for backtracking.

    Maintains constraint state across API additions and supports
    hypothesis testing (check without commit).
    """

    def __init__(self, timeout_ms: int = 1000,
                 automaton_guard: Optional[AutomatonAcceptanceGuard] = None):
        """
        Initialize incremental solver.

        Args:
            timeout_ms: Z3 solving timeout in milliseconds
            automaton_guard: Optional hard-pruning guard from the project
                automaton. When supplied and strong, ``check_candidate``
                rejects candidates whose hypothetical sequence
                (``api_sequence + [candidate]``) fails the guard's
                acceptance threshold *before* invoking Z3. Saves both Z3
                time and propagates an additional symbolic-vs-statistical
                cross-check from the use-def model.
        """
        self.solver = Solver()
        self.solver.set("timeout", timeout_ms)
        self.solver.set("unsat_core", True)

        self.timeout_ms = timeout_ms
        self.checkpoint_level = 0

        # Track state
        self.api_sequence: List[str] = []
        self.variable_state: Dict[str, VariableState] = {}
        self.resource_types: Dict[str, Set[str]] = {}  # type -> set of var names

        # Track constraints by checkpoint level for diagnosis
        self.constraints_by_level: Dict[int, List[Tuple[str, Any]]] = {0: []}

        # Phase H: track api_sequence length per checkpoint so pop() rolls
        # the running sequence back alongside the Z3 solver state. Without
        # this, automaton-guard checks against the running sequence diverge
        # from Z3's actual frame after a backtrack.
        self._sequence_length_by_level: Dict[int, int] = {0: 0}

        # Variable mappings
        self.api_vars: Dict[str, Any] = {}      # api_name -> Bool var
        self.order_vars: Dict[str, Any] = {}    # api_name -> Int var
        self.resource_vars: Dict[str, Any] = {} # type_string -> Bool var (exists)
        self.binding_vars: Dict[str, Any] = {}  # (api, param_pos) -> var

        # Constraint naming for unsat core
        self._constraint_counter = 0

        # Phase H: optional automaton acceptance guard.
        self.automaton_guard = automaton_guard
        self.n_automaton_pruned = 0

    def _next_constraint_name(self, prefix: str = "c") -> str:
        """Generate unique constraint name for unsat core tracking"""
        self._constraint_counter += 1
        return f"{prefix}_{self._constraint_counter}"

    def _get_or_create_api_var(self, api_name: str) -> Any:
        """Get or create API boolean variable (whether API is called)"""
        if api_name not in self.api_vars:
            self.api_vars[api_name] = Bool(f"api_{api_name}")
        return self.api_vars[api_name]

    def _get_or_create_order_var(self, api_name: str) -> Any:
        """Get or create API order variable (call sequence position)"""
        if api_name not in self.order_vars:
            self.order_vars[api_name] = Int(f"order_{api_name}")
        return self.order_vars[api_name]

    def _get_or_create_resource_var(self, type_str: str) -> Any:
        """Get or create resource existence variable"""
        key = self._normalize_type(type_str)
        if key not in self.resource_vars:
            self.resource_vars[key] = Bool(f"resource_{key}")
        return self.resource_vars[key]

    def _normalize_type(self, type_str: str) -> str:
        """Normalize type string for consistent lookup"""
        return type_str.replace(" ", "").replace("const", "").strip()

    def push(self) -> int:
        """
        Create a checkpoint for backtracking.

        Returns:
            Checkpoint level (can be used with pop_to)
        """
        self.solver.push()
        self.checkpoint_level += 1
        self.constraints_by_level[self.checkpoint_level] = []
        # Snapshot api_sequence length so pop() can roll the running sequence
        # back in lockstep with the Z3 frame.
        self._sequence_length_by_level[self.checkpoint_level] = len(self.api_sequence)
        logger.debug(f"[Z3Guided] Push to level {self.checkpoint_level}")
        return self.checkpoint_level

    def pop(self, levels: int = 1):
        """
        Pop back to previous checkpoint.

        Args:
            levels: Number of levels to pop
        """
        for _ in range(min(levels, self.checkpoint_level)):
            self.solver.pop()
            # Clean up constraints at this level
            if self.checkpoint_level in self.constraints_by_level:
                del self.constraints_by_level[self.checkpoint_level]
            # Truncate api_sequence to this checkpoint's snapshot length so
            # the automaton-guard sees the same sequence as the Z3 frame.
            snapshot_len = self._sequence_length_by_level.pop(
                self.checkpoint_level, len(self.api_sequence),
            )
            if len(self.api_sequence) > snapshot_len:
                self.api_sequence = self.api_sequence[:snapshot_len]
            self.checkpoint_level -= 1

        logger.debug(f"[Z3Guided] Popped to level {self.checkpoint_level}")

    def pop_to(self, level: int):
        """Pop to a specific checkpoint level"""
        levels_to_pop = self.checkpoint_level - level
        if levels_to_pop > 0:
            self.pop(levels_to_pop)

    def add_constraint(self, constraint: Any, name: Optional[str] = None,
                       constraint_type: GuidanceConstraintType = GuidanceConstraintType.DEPENDENCY) -> str:
        """
        Add a constraint to the solver.

        Args:
            constraint: Z3 constraint expression
            name: Optional name for the constraint (for unsat core)
            constraint_type: Type of constraint for diagnosis

        Returns:
            Constraint name
        """
        if name is None:
            name = self._next_constraint_name(constraint_type.value)

        # Add with tracking for unsat core
        self.solver.assert_and_track(constraint, Bool(name))

        # Track at current level
        self.constraints_by_level[self.checkpoint_level].append((name, constraint_type))

        return name

    def add_api_called(self, api_name: str, position: int):
        """
        Assert that an API is called at a specific position.

        Args:
            api_name: Name of the API
            position: Position in the call sequence
        """
        api_var = self._get_or_create_api_var(api_name)
        order_var = self._get_or_create_order_var(api_name)

        self.add_constraint(api_var, f"api_called_{api_name}",
                           GuidanceConstraintType.INIT_COMPLETION)
        self.add_constraint(order_var == position, f"api_order_{api_name}_{position}",
                           GuidanceConstraintType.ACCESS_ORDER)

        self.api_sequence.append(api_name)

    def add_resource_produced(self, type_str: str, producer_api: str, var_name: str):
        """
        Assert that a resource of given type is produced.

        Args:
            type_str: Type of resource produced
            producer_api: API that produces the resource
            var_name: Variable name holding the resource
        """
        type_key = self._normalize_type(type_str)
        resource_var = self._get_or_create_resource_var(type_str)
        api_var = self._get_or_create_api_var(producer_api)

        # Resource exists if producer API is called
        self.add_constraint(Implies(api_var, resource_var),
                           f"produces_{producer_api}_{type_key}",
                           GuidanceConstraintType.RESOURCE_EXISTENCE)

        # Track in state
        if type_key not in self.resource_types:
            self.resource_types[type_key] = set()
        self.resource_types[type_key].add(var_name)

        self.variable_state[var_name] = VariableState(
            name=var_name,
            type_str=type_str,
            is_initialized=True,
            producer_api=producer_api,
            checkpoint_level=self.checkpoint_level
        )

    def add_resource_required(self, type_str: str, consumer_api: str):
        """
        Assert that an API requires a resource of given type.

        Args:
            type_str: Type of resource required
            consumer_api: API that consumes the resource
        """
        type_key = self._normalize_type(type_str)
        resource_var = self._get_or_create_resource_var(type_str)
        api_var = self._get_or_create_api_var(consumer_api)

        # If consumer is called, resource must exist
        self.add_constraint(Implies(api_var, resource_var),
                           f"requires_{consumer_api}_{type_key}",
                           GuidanceConstraintType.RESOURCE_EXISTENCE)

    def add_order_constraint(self, before_api: str, after_api: str):
        """
        Assert that one API must be called before another.

        Args:
            before_api: API that must come first
            after_api: API that must come after
        """
        before_order = self._get_or_create_order_var(before_api)
        after_order = self._get_or_create_order_var(after_api)
        before_called = self._get_or_create_api_var(before_api)
        after_called = self._get_or_create_api_var(after_api)

        # If both are called, before must come first
        self.add_constraint(
            Implies(And(before_called, after_called), before_order < after_order),
            f"order_{before_api}_before_{after_api}",
            GuidanceConstraintType.ACCESS_ORDER
        )

    def check(self) -> SatisfiabilityResult:
        """
        Check satisfiability of current constraints.

        Returns:
            SatisfiabilityResult with status, model, or unsat core
        """
        try:
            result = self.solver.check()

            if result == sat:
                model = self.solver.model()
                model_dict = {}
                for var in model:
                    model_dict[str(var)] = str(model[var])
                return SatisfiabilityResult(
                    status=SatisfiabilityStatus.SAT,
                    model=model_dict
                )
            elif result == unsat:
                core = self.solver.unsat_core()
                core_names = [str(c) for c in core]
                return SatisfiabilityResult(
                    status=SatisfiabilityStatus.UNSAT,
                    unsat_core=core_names
                )
            else:
                return SatisfiabilityResult(status=SatisfiabilityStatus.UNKNOWN)

        except Exception as e:
            logger.warning(f"[Z3Guided] Check failed: {e}")
            return SatisfiabilityResult(status=SatisfiabilityStatus.TIMEOUT)

    def check_candidate(self, api_name: str, required_types: List[str],
                       produced_types: List[str]) -> CandidateResult:
        """
        Test if a candidate API is feasible without committing.

        Checks three layers (in order, short-circuit on first reject):
        1. Required resources are actually available (tracked in state)
        2. **Phase H** automaton-acceptance guard (when strong)
        3. Z3 constraints are satisfiable

        Args:
            api_name: Name of candidate API
            required_types: Types this API requires as input
            produced_types: Types this API produces as output

        Returns:
            CandidateResult indicating feasibility
        """
        # First check: are all required resources actually available?
        missing = []
        for req_type in required_types:
            type_key = self._normalize_type(req_type)
            if type_key not in self.resource_types or not self.resource_types[type_key]:
                missing.append(req_type)

        if missing:
            # Resources are missing - API is not feasible
            return CandidateResult(
                api_name=api_name,
                is_feasible=False,
                missing_resources=missing,
                conflicting_constraints=[]
            )

        # Second check (Phase H): automaton-acceptance hard pruning. We
        # fabricate the hypothetical sequence (running sequence ++ candidate)
        # and consult the guard. Strong guards reject sequences whose typestate
        # doesn't match the project's learned protocol — eliminating Z3 calls
        # that would have produced syntactically-valid-but-semantically-wrong
        # candidates. Weak/missing guards admit everything (no-op).
        if self.automaton_guard is not None:
            hypothetical = list(self.api_sequence) + [api_name]
            if not self.automaton_guard.admits(hypothetical):
                self.n_automaton_pruned += 1
                return CandidateResult(
                    api_name=api_name,
                    is_feasible=False,
                    missing_resources=[],
                    conflicting_constraints=[
                        f"automaton_acceptance<{self.automaton_guard.threshold:.3f}"
                    ],
                )

        # Third check: Z3 constraint satisfiability
        # Push a temporary checkpoint
        self.push()

        try:
            api_var = self._get_or_create_api_var(api_name)
            self.solver.add(api_var)  # Assume API is called

            # Add resource requirements
            for req_type in required_types:
                self.add_resource_required(req_type, api_name)

            result = self.check()

            if result.is_sat:
                # Compute complexity score (lower is better)
                # Based on: number of requirements, API name length (heuristic)
                score = len(required_types) * 2 + len(api_name) * 0.01
                return CandidateResult(
                    api_name=api_name,
                    is_feasible=True,
                    score=score
                )
            else:
                return CandidateResult(
                    api_name=api_name,
                    is_feasible=False,
                    missing_resources=[],
                    conflicting_constraints=result.unsat_core or []
                )
        finally:
            # Always pop back
            self.pop()

    def get_available_resources(self) -> Dict[str, Set[str]]:
        """Get currently available resources by type"""
        return dict(self.resource_types)

    def has_resource(self, type_str: str) -> bool:
        """Check if a resource of given type is available"""
        type_key = self._normalize_type(type_str)
        return type_key in self.resource_types and len(self.resource_types[type_key]) > 0

    def reset(self):
        """Reset solver to initial state"""
        self.solver.reset()
        self.solver.set("timeout", self.timeout_ms)
        self.solver.set("unsat_core", True)

        self.checkpoint_level = 0
        self.api_sequence.clear()
        self.variable_state.clear()
        self.resource_types.clear()
        self.constraints_by_level = {0: []}

        self.api_vars.clear()
        self.order_vars.clear()
        self.resource_vars.clear()
        self.binding_vars.clear()
        self._constraint_counter = 0


# ============================================================
# Unsat Core Diagnoser
# ============================================================

class UnsatCoreDiagnoser:
    """
    Analyzes unsat cores to diagnose constraint failures
    and suggest recovery actions.
    """

    def __init__(self, solver: IncrementalZ3Solver):
        self.solver = solver

    def diagnose(self, unsat_core: List[str]) -> UnsatDiagnosis:
        """
        Diagnose the cause of unsatisfiability.

        Args:
            unsat_core: List of constraint names from unsat core

        Returns:
            UnsatDiagnosis with analysis and suggested actions
        """
        if not unsat_core:
            return UnsatDiagnosis(
                diagnosis_type=DiagnosisType.UNKNOWN,
                conflicting_constraints=[],
                suggested_actions=[RecoveryAction.BACKTRACK]
            )

        # Classify constraints
        resource_constraints = []
        lifecycle_constraints = []
        order_constraints = []
        type_constraints = []

        for constraint_name in unsat_core:
            if "resource_" in constraint_name or "requires_" in constraint_name or "produces_" in constraint_name:
                resource_constraints.append(constraint_name)
            elif "lifecycle" in constraint_name or "init_" in constraint_name:
                lifecycle_constraints.append(constraint_name)
            elif "order_" in constraint_name:
                order_constraints.append(constraint_name)
            elif "type_" in constraint_name:
                type_constraints.append(constraint_name)

        # Determine primary diagnosis type
        if resource_constraints:
            # Extract missing resources from constraint names
            missing = self._extract_missing_resources(resource_constraints)
            return UnsatDiagnosis(
                diagnosis_type=DiagnosisType.MISSING_RESOURCE,
                conflicting_constraints=resource_constraints,
                missing_resources=missing,
                suggested_actions=[RecoveryAction.ADD_PRODUCER, RecoveryAction.TRY_DIFFERENT_SOURCE],
                details=f"Missing resources: {', '.join(missing)}"
            )

        if lifecycle_constraints:
            return UnsatDiagnosis(
                diagnosis_type=DiagnosisType.LIFECYCLE_VIOLATION,
                conflicting_constraints=lifecycle_constraints,
                suggested_actions=[RecoveryAction.REORDER_APIS, RecoveryAction.REMOVE_CONFLICTING],
                details="Lifecycle constraint violation detected"
            )

        if order_constraints:
            return UnsatDiagnosis(
                diagnosis_type=DiagnosisType.ORDER_VIOLATION,
                conflicting_constraints=order_constraints,
                suggested_actions=[RecoveryAction.REORDER_APIS],
                details="API ordering constraint violation"
            )

        if type_constraints:
            return UnsatDiagnosis(
                diagnosis_type=DiagnosisType.TYPE_MISMATCH,
                conflicting_constraints=type_constraints,
                suggested_actions=[RecoveryAction.TRY_DIFFERENT_SOURCE],
                details="Type compatibility constraint violation"
            )

        return UnsatDiagnosis(
            diagnosis_type=DiagnosisType.UNKNOWN,
            conflicting_constraints=unsat_core,
            suggested_actions=[RecoveryAction.BACKTRACK],
            details=f"Unclassified constraints: {', '.join(unsat_core[:5])}"
        )

    def _extract_missing_resources(self, resource_constraints: List[str]) -> List[str]:
        """Extract resource type names from constraint names"""
        missing = []
        for constraint in resource_constraints:
            # Format: "requires_{api}_{type}" or "resource_{type}"
            parts = constraint.split("_")
            if len(parts) >= 2:
                if parts[0] == "requires" and len(parts) >= 3:
                    # requires_api_type
                    type_str = "_".join(parts[2:])
                    if type_str not in missing:
                        missing.append(type_str)
                elif parts[0] == "resource":
                    type_str = "_".join(parts[1:])
                    if type_str not in missing:
                        missing.append(type_str)
        return missing

    def suggest_producers(self, missing_type: str,
                          available_producers: Dict[str, List[str]]) -> List[str]:
        """
        Suggest producer APIs for a missing resource type.

        Args:
            missing_type: The type that needs to be produced
            available_producers: Mapping from type to producer API names

        Returns:
            List of suggested producer API names
        """
        type_key = missing_type.replace(" ", "").replace("const", "").strip()

        suggestions = []

        # Direct match
        if type_key in available_producers:
            suggestions.extend(available_producers[type_key])

        # Try without pointer
        if type_key.endswith("*"):
            base_type = type_key[:-1]
            if base_type in available_producers:
                suggestions.extend(available_producers[base_type])

        # Try with pointer
        ptr_type = type_key + "*"
        if ptr_type in available_producers:
            suggestions.extend(available_producers[ptr_type])

        return list(set(suggestions))  # Deduplicate


# ============================================================
# Z3-Guided Synthesis Controller
# ============================================================

class Z3GuidedSynthesisController:
    """
    High-level controller for Z3-guided synthesis.

    Coordinates the incremental solver and diagnoser to guide
    decision making in CBFactory.
    """

    def __init__(self, timeout_ms: int = 1000, strict_mode: bool = True,
                 automaton_artifact: Optional[Any] = None,
                 automaton_threshold: float = 0.6):
        """
        Initialize the synthesis controller.

        Args:
            timeout_ms: Z3 solving timeout
            strict_mode: If True, raise errors on Z3 failures (for debugging)
            automaton_artifact: Optional ``AutomatonArtifact`` to gate
                candidate APIs against the project's learned typestate.
                When supplied and "strong" (≥10 observed APIs, ≥4 merged
                states), Z3 candidates that would push the running sequence
                below ``automaton_threshold`` acceptance score are rejected
                before Z3 is consulted. See ``AutomatonAcceptanceGuard``.
            automaton_threshold: Hard-pruning acceptance floor in [0.0, 1.0].
                Lower = looser; the guard auto-relaxes by 0.15 after 5
                consecutive UNSAT verdicts so an over-eager threshold
                doesn't starve synthesis on novel-but-valid sequences.
        """
        self.automaton_guard: Optional[AutomatonAcceptanceGuard] = None
        if automaton_artifact is not None:
            self.automaton_guard = AutomatonAcceptanceGuard(
                artifact=automaton_artifact,
                threshold=automaton_threshold,
            )
        self.solver = IncrementalZ3Solver(
            timeout_ms=timeout_ms, automaton_guard=self.automaton_guard,
        )
        self.diagnoser = UnsatCoreDiagnoser(self.solver)
        self.strict_mode = strict_mode

        # Cache for API feasibility results
        self._feasibility_cache: Dict[Tuple[str, ...], CandidateResult] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def reset(self):
        """Reset controller state for new synthesis"""
        self.solver.reset()
        self._feasibility_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

    def evaluate_source_apis(self, source_apis: List[Any],
                             get_required_types: callable,
                             get_produced_types: callable) -> List[Tuple[Any, float]]:
        """
        Evaluate and rank source APIs by feasibility and complexity.

        Args:
            source_apis: List of source API objects
            get_required_types: Function to get required types for an API
            get_produced_types: Function to get produced types for an API

        Returns:
            List of (api, score) tuples, sorted by score (lower is better)
        """
        ranked = []

        for api in source_apis:
            api_name = api.function_name if hasattr(api, 'function_name') else str(api)
            required = get_required_types(api)
            produced = get_produced_types(api)

            result = self.solver.check_candidate(api_name, required, produced)

            if result.is_feasible:
                ranked.append((api, result.score))
            else:
                logger.debug(f"[Z3Guided] Source API {api_name} not feasible: "
                            f"missing {result.missing_resources}")

        # Sort by score (lower is better)
        ranked.sort(key=lambda x: x[1])

        return ranked

    def add_api_to_sequence(self, api: Any, position: int,
                            required_types: List[str],
                            produced_types: List[str],
                            var_names: Optional[Dict[str, str]] = None) -> SatisfiabilityResult:
        """
        Add an API to the sequence with incremental constraint checking.

        Args:
            api: API object
            position: Position in sequence
            required_types: Types required by this API
            produced_types: Types produced by this API
            var_names: Optional mapping from type to variable name

        Returns:
            SatisfiabilityResult indicating success
        """
        api_name = api.function_name if hasattr(api, 'function_name') else str(api)

        # Add constraints
        self.solver.add_api_called(api_name, position)

        for req_type in required_types:
            self.solver.add_resource_required(req_type, api_name)

        for prod_type in produced_types:
            var_name = var_names.get(prod_type, f"var_{api_name}_{prod_type}") if var_names else f"var_{api_name}_{prod_type}"
            self.solver.add_resource_produced(prod_type, api_name, var_name)

        # Check incrementally
        result = self.solver.check()

        if not result.is_sat:
            diagnosis = self.diagnoser.diagnose(result.unsat_core or [])
            logger.info(f"[Z3Guided] Adding {api_name} made constraints UNSAT: {diagnosis.details}")

            if self.strict_mode:
                raise Z3GuidedSynthesisError(
                    f"Adding API {api_name} violates constraints: {diagnosis.details}",
                    diagnosis=diagnosis
                )

        return result

    def checkpoint(self) -> int:
        """Create a checkpoint for potential backtracking"""
        return self.solver.push()

    def rollback(self, levels: int = 1):
        """Rollback to previous checkpoint"""
        self.solver.pop(levels)

    def rollback_to(self, level: int):
        """Rollback to specific checkpoint level"""
        self.solver.pop_to(level)

    def get_diagnosis(self, unsat_core: Optional[List[str]] = None) -> UnsatDiagnosis:
        """
        Get diagnosis for current or provided unsat core.

        Args:
            unsat_core: Optional unsat core (uses last check result if None)
        """
        if unsat_core is None:
            result = self.solver.check()
            unsat_core = result.unsat_core if result.is_unsat else []

        return self.diagnoser.diagnose(unsat_core or [])

    def suggest_recovery(self, diagnosis: UnsatDiagnosis,
                         type_to_producers: Dict[str, List[str]]) -> List[str]:
        """
        Suggest recovery actions based on diagnosis.

        Args:
            diagnosis: UnsatDiagnosis from diagnoser
            type_to_producers: Mapping from type to producer API names

        Returns:
            List of suggested API names to try
        """
        suggestions = []

        if diagnosis.diagnosis_type == DiagnosisType.MISSING_RESOURCE:
            for missing_type in diagnosis.missing_resources:
                producers = self.diagnoser.suggest_producers(missing_type, type_to_producers)
                suggestions.extend(producers)

        return list(set(suggestions))  # Deduplicate

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache hit/miss statistics"""
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": self._cache_hits / max(1, self._cache_hits + self._cache_misses)
        }

    def get_automaton_stats(self) -> Optional[Dict[str, Any]]:
        """Phase H: telemetry on automaton-guard prunings. ``None`` when no
        artifact was attached at construction time.
        """
        if self.automaton_guard is None:
            return None
        return self.automaton_guard.stats()


class Z3GuidedSynthesisError(Exception):
    """Exception raised when Z3-guided synthesis encounters a constraint violation"""

    def __init__(self, message: str, diagnosis: Optional[UnsatDiagnosis] = None):
        super().__init__(message)
        self.diagnosis = diagnosis


# ============================================================
# Utility Functions
# ============================================================

def is_z3_guided_available() -> bool:
    """Check if Z3-guided synthesis is available"""
    return Z3_AVAILABLE


def create_guided_controller(
    timeout_ms: int = 1000,
    strict_mode: bool = True,
    automaton_artifact: Optional[Any] = None,
    automaton_threshold: float = 0.6,
) -> Optional[Z3GuidedSynthesisController]:
    """
    Create a Z3-guided synthesis controller.

    Args:
        timeout_ms: Z3 solving timeout
        strict_mode: If True, raise errors on failures
        automaton_artifact: Optional ``AutomatonArtifact`` for Phase H
            hard-pruning. ``None`` (default) preserves legacy behaviour.
        automaton_threshold: Acceptance threshold in [0.0, 1.0].

    Returns:
        Controller instance
    """
    return Z3GuidedSynthesisController(
        timeout_ms=timeout_ms, strict_mode=strict_mode,
        automaton_artifact=automaton_artifact,
        automaton_threshold=automaton_threshold,
    )
