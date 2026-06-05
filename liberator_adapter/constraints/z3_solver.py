"""
Z3 Constraint Solver for LogicFuzz

Provides Z3-based constraint solving functionality for:
1. API sequence feasibility validation
2. Constraint satisfiability checking
3. Dependency graph precise pruning
4. Path constraint validation

Author: LogicFuzz Team
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from z3 import Solver, Bool, Int, And, Not, Implies, sat, unsat
Z3_AVAILABLE = True

from liberator_adapter.common import (
    Api, Access, ValueMetadata, FunctionConditions
)

logger = logging.getLogger(__name__)


class ConstraintType(Enum):
    """Constraint type enumeration"""
    TYPE_MATCH = "type_match"           # Type matching constraint
    ACCESS_ORDER = "access_order"       # Access order constraint (CREATE before DELETE)
    PROVENANCE = "provenance"           # Provenance compatibility constraint
    DEPENDENCY = "dependency"           # Parameter dependency constraint
    NULLABILITY = "nullability"         # Nullability constraint
    ARRAY_BOUNDS = "array_bounds"       # Array bounds constraint
    RESOURCE_LIFECYCLE = "lifecycle"    # Resource lifecycle constraint

    # Extended constraint types for Z3-guided decision making
    VARIABLE_AVAILABILITY = "variable_availability"  # Variable exists and is usable
    RESOURCE_EXISTENCE = "resource_existence"        # Required resource type exists
    PARAMETER_BINDING = "parameter_binding"          # Parameter binds to valid variable
    INIT_COMPLETION = "init_completion"              # Initialization API has been called
    PRODUCER_REQUIRED = "producer_required"          # A producer API is needed for a type


@dataclass
class Z3Constraint:
    """Z3 constraint wrapper class"""
    constraint_type: ConstraintType
    z3_expr: Any  # Z3 expression
    description: str
    source_api: Optional[str] = None
    target_api: Optional[str] = None


class Z3ConstraintBuilder:
    """
    Z3 constraint builder

    Converts LogicFuzz constraint model to Z3 expressions
    """

    def __init__(self):
        self.solver = Solver()
        self.constraints: List[Z3Constraint] = []

        # Variable mappings
        self.api_vars: Dict[str, Any] = {}      # API name -> Z3 variable
        self.type_vars: Dict[str, Any] = {}     # Type name -> Z3 variable
        self.order_vars: Dict[str, Int] = {}    # API order variables

        # Type compatibility cache
        self._type_compat_cache: Dict[Tuple[str, str], bool] = {}

    def reset(self):
        """Reset solver state"""
        self.solver.reset()
        self.constraints.clear()
        self.api_vars.clear()
        self.type_vars.clear()
        self.order_vars.clear()

    def _get_or_create_api_var(self, api_name: str) -> Any:
        """Get or create API's boolean variable (indicates whether API is called)"""
        if api_name not in self.api_vars:
            self.api_vars[api_name] = Bool(f"api_{api_name}")
        return self.api_vars[api_name]

    def _get_or_create_order_var(self, api_name: str) -> Int:
        """Get or create API's order variable (indicates call order)"""
        if api_name not in self.order_vars:
            self.order_vars[api_name] = Int(f"order_{api_name}")
        return self.order_vars[api_name]

    def _get_or_create_type_var(self, type_name: str) -> Int:
        """Get or create type variable (represents type ID)"""
        if type_name not in self.type_vars:
            # Use integer to represent type ID
            self.type_vars[type_name] = Int(f"type_{type_name}")
        return self.type_vars[type_name]

    # ========== Constraint Building Methods ==========

    def add_type_match_constraint(
        self,
        source_api: str,
        target_api: str,
        source_type: str,
        target_type: str
    ) -> Z3Constraint:
        """
        Add type matching constraint

        If target_api depends on source_api's output, types must be compatible.
        When types are incompatible, the constraint is "both APIs cannot be
        called together in this dependency relation" — *not* a contradictory
        ``expr ∧ ¬expr`` pair (which made the whole solver UNSAT regardless
        of the actual sequence).
        """
        # Simplify: compare after removing pointers and spaces
        source_clean = source_type.replace("*", "").replace(" ", "")
        target_clean = target_type.replace("*", "").replace(" ", "")

        if source_clean == target_clean:
            # Compatible types — record an informational equality on the type
            # vars; this is trivially satisfiable.
            source_var = self._get_or_create_type_var(source_type)
            target_var = self._get_or_create_type_var(target_type)
            expr = source_var == target_var
        else:
            # Incompatible types — if both APIs are present in a dep relation,
            # the relation is infeasible. Express as: ¬(src_called ∧ tgt_called).
            src_called = self._get_or_create_api_var(source_api)
            tgt_called = self._get_or_create_api_var(target_api)
            expr = Not(And(src_called, tgt_called))

        constraint = Z3Constraint(
            constraint_type=ConstraintType.TYPE_MATCH,
            z3_expr=expr,
            description=f"Type match: {source_type} -> {target_type}",
            source_api=source_api,
            target_api=target_api
        )
        self.constraints.append(constraint)
        self.solver.add(expr)

        return constraint

    # NOTE: ``add_access_order_constraint`` removed 2026-05-22. It generated
    # cyclic "order_creator < order_user" constraints over the API-name set
    # whenever a single API name appeared in both ``creates`` and ``uses``
    # for the same type (chained-builder APIs like cjson's ``cJSON_Add*``).
    # Replaced by position-indexed lifecycle validation in
    # ``Z3SequenceValidator._check_lifecycle_position_indexed``.

    def add_provenance_constraint(
        self,
        source_api: str,
        target_api: str,
        source_prov: str,
        target_prov: str
    ) -> Z3Constraint:
        """
        Add Provenance compatibility constraint

        Check if source and target provenance are compatible
        """
        source_called = self._get_or_create_api_var(source_api)
        target_called = self._get_or_create_api_var(target_api)

        # Provenance compatibility rules
        compatible = self._check_provenance_compatibility(source_prov, target_prov)

        if compatible:
            expr = Bool(f"prov_compat_{source_api}_{target_api}")
        else:
            # Incompatible: If both APIs are called, it's infeasible
            expr = Not(And(source_called, target_called))

        constraint = Z3Constraint(
            constraint_type=ConstraintType.PROVENANCE,
            z3_expr=expr,
            description=f"Provenance: {source_prov} -> {target_prov}",
            source_api=source_api,
            target_api=target_api
        )
        self.constraints.append(constraint)
        self.solver.add(expr)

        return constraint

    def _check_provenance_compatibility(self, source_prov: str, target_prov: str) -> bool:
        """Check Provenance compatibility"""
        # Rules from provenance_checker.py
        if source_prov == "HEAP_MALLOC" and target_prov == "RETURN_OPAQUE":
            return False
        if source_prov in ["STACK", "GLOBAL"] and target_prov == "HEAP_MALLOC":
            return False
        return True

    def add_dependency_constraint(
        self,
        api_name: str,
        param_idx: int,
        depends_on_param: int,
        condition: str = "length"
    ) -> Z3Constraint:
        """
        Add parameter dependency constraint

        For example: param[i]'s length depends on param[j]
        """
        api_var = self._get_or_create_api_var(api_name)

        # Create parameter variables
        param_var = Int(f"{api_name}_param_{param_idx}")
        dep_var = Int(f"{api_name}_param_{depends_on_param}")

        if condition == "length":
            # Length constraint: param_var's size should be related to dep_var
            expr = Implies(
                api_var,
                And(param_var >= 0, dep_var >= 0, param_var <= dep_var * 1024)
            )
        else:
            # Generic dependency
            expr = Implies(api_var, dep_var >= 0)

        constraint = Z3Constraint(
            constraint_type=ConstraintType.DEPENDENCY,
            z3_expr=expr,
            description=f"Dependency: {api_name}[{param_idx}] depends on [{depends_on_param}]",
            source_api=api_name
        )
        self.constraints.append(constraint)
        self.solver.add(expr)

        return constraint

    # NOTE: ``add_api_sequence_constraint`` and the per-name ``order_X`` /
    # ``api_called_X`` machinery it built on were removed 2026-05-22.
    # Sequence validation now uses position-indexed semantics inside
    # ``Z3SequenceValidator.validate_sequence``; the underlying
    # ``add_access_order_constraint`` + ``_add_lifecycle_constraints``
    # over the *API-name set* generated cyclic order constraints for
    # libraries whose APIs serve both creator and user roles (cjson's
    # ``cJSON_Add*`` family), pathologically rejecting 10/10 sequences
    # on cjson and lcms. See ``docs/z3_skeleton_synthesis_problem_2026_05.md``
    # §3.6 for the empirical root-cause analysis.

    # ========== Solving Methods ==========

    def check_satisfiability(self) -> Tuple[bool, Optional[Dict]]:
        """
        Check if current constraints are satisfiable

        Returns:
            (is_sat, model): Whether satisfiable, and model when satisfied
        """
        result = self.solver.check()

        if result == sat:
            model = self.solver.model()
            model_dict = {}
            for var in model:
                model_dict[str(var)] = model[var]
            return True, model_dict
        elif result == unsat:
            return False, None
        else:  # unknown
            logger.warning("Z3 solver returned unknown")
            return False, None


class Z3SequenceValidator:
    """
    Z3 API sequence validator

    Used to validate whether API call sequences satisfy all constraints
    """

    def __init__(self):
        self.builder = Z3ConstraintBuilder()

    def validate_sequence(
        self,
        api_sequence: List[Api],
        function_conditions: Dict[str, FunctionConditions]
    ) -> Tuple[bool, List[str]]:
        """Validate a fixed API sequence using **position-indexed** lifecycle
        semantics.

        Background: the legacy implementation quantified lifecycle constraints
        over the *API-name set* (``∀c ∈ creates[T], u ∈ uses[T]: order_c <
        order_u``). For libraries with chained-builder APIs that are *both*
        creators and users of the same type (cjson's `cJSON_Add*` family —
        return a fresh node AND mutate the parent), the all-pairs expansion
        generated cyclic order constraints and forced 10/10 sequences UNSAT.

        Position-indexed semantics quantifies over *positions*:
        ``for each j with USE on T: ∃ k < j with CREATE on T``. This matches
        the *intended* meaning ("the creator of this value precedes its
        user") instead of the over-conservative name-level reading
        ("every-creator-API precedes every-user-API").

        Because the sequence is fixed (we're validating a caller-supplied
        ordering, not synthesizing one), the position-indexed check
        collapses to a deterministic left-to-right walk over the sequence
        — no SMT solver call needed for lifecycle. Z3 is retained only for
        the length-dependency family (param-length-depends-on-param) where
        SAT remains meaningful.

        Returns:
            ``(is_valid, violations)`` — ``violations`` is a list of human-
            readable strings tagged by family (``lifecycle:`` /
            ``length_dep:``). Empty when valid.
        """
        violations: List[str] = []

        # ---- 1. Lifecycle (deterministic position-indexed walk) ----
        violations.extend(self._check_lifecycle_position_indexed(
            api_sequence, function_conditions))

        # ---- 2. Length-dependency (still uses Z3) ----
        self.builder.reset()
        for _, api in enumerate(api_sequence):
            if api.function_name not in function_conditions:
                continue
            cond = function_conditions[api.function_name]
            for j, arg_cond in enumerate(cond.argument_at):
                if arg_cond.len_depends_on:
                    try:
                        dep_idx = int(arg_cond.len_depends_on.replace("param_", ""))
                    except ValueError:
                        continue
                    self.builder.add_dependency_constraint(
                        api.function_name, j, dep_idx, "length"
                    )
        # No length constraints emitted → vacuously sat.
        if self.builder.constraints:
            is_sat, _ = self.builder.check_satisfiability()
            if not is_sat:
                violations.append("length_dep: z3 unsat on length constraints")

        return (len(violations) == 0), violations

    def _check_lifecycle_position_indexed(
        self,
        api_sequence: List[Api],
        function_conditions: Dict[str, FunctionConditions],
    ) -> List[str]:
        """Deterministic walk: for each position, verify the lifecycle
        precondition holds against the *prior positions*, not against the
        whole API-name set.

        Semantic rules:
          - USE on T at position j: some k < j must CREATE T.
          - DELETE on T at position j: some k < j must CREATE T (we don't
            forbid USE after DELETE here because the sequence is the
            caller's intent and they may want to test use-after-free).
          - CREATE on T at any position: always permitted.

        These match the intended semantics from §3.6 of
        ``docs/z3_skeleton_synthesis_problem_2026_05.md``.
        """
        violations: List[str] = []

        # Types that come from outside the sequence (fuzzer input, primitive
        # return values, length parameters) rather than from a project-managed
        # creator. Lifecycle preconditions don't apply to them.
        #
        # Heuristic: anything that isn't an LLVM struct/class pointer is
        # treated as primitive. The condition_extractor (Liberator) writes
        # type strings in LLVM IR notation — ``i8*`` for ``char*``,
        # ``%struct.<name>*`` for project-defined record types,
        # ``%class.<name>*`` for C++ classes. The cjson side passed
        # already with the original creatable-types filter (no API there
        # returns ``i8*``), but lcms has c-string-returning APIs
        # (``cmsMLUgetASCII``, etc.) that drag ``i8*`` into ``creatable``,
        # which then forces entry-point APIs like ``cmsOpenProfileFromMem``
        # to fail the "needs prior creator" check on their fuzzer-input
        # buffer arg. That's a false positive — i8* doesn't have an
        # ownership / lifetime contract worth enforcing.
        #
        # Real handles (``%struct.cJSON*``, ``%struct._cms_curve_struct*``,
        # …) keep flowing through the check.
        def _is_lifetime_managed(type_str: str) -> bool:
            if not type_str:
                return False
            ts = type_str.strip()
            return ts.startswith("%struct.") or ts.startswith("%class.")

        # Pre-extract per-position role sets.
        def _role_sets(api: Api) -> Tuple[Set[str], Set[str], Set[str]]:
            """Return (creates, uses, deletes) type-string sets for this API."""
            creates: Set[str] = set()
            uses: Set[str] = set()
            deletes: Set[str] = set()
            cond = function_conditions.get(api.function_name)
            if cond is None:
                return creates, uses, deletes
            # return access → creates only
            for at in cond.return_at.ats:
                if at.access == Access.CREATE:
                    ts = at.type_string or api.return_info.type
                    if ts:
                        creates.add(ts)
            # arg access → uses / deletes (mirrors legacy logic)
            for arg_cond in cond.argument_at:
                for at in arg_cond.ats:
                    ts = at.type_string or ""
                    if not ts:
                        continue
                    if at.access == Access.DELETE:
                        deletes.add(ts)
                    elif at.access in (Access.READ, Access.WRITE):
                        uses.add(ts)
            return creates, uses, deletes

        per_position = [_role_sets(api) for api in api_sequence]

        # "Creatable-in-sequence" filter: a USE/DELETE of type T is only
        # treated as a lifecycle dependency when (a) some API in *this*
        # sequence creates T, AND (b) T is a lifetime-managed type
        # (struct/class pointer). Types nobody creates (integer returns,
        # length parameters) and primitive byte buffers (``i8*`` etc.
        # serve both as fuzzer input and as opaque output buffers, with
        # no useful ownership contract) come from outside the sequence
        # and don't require a creator. This matches the legacy encoding's
        # implicit filter (``set(creates) & set(uses)`` per-sequence)
        # while also handling the lcms case where ``i8*`` is dragged
        # into ``creatable`` by c-string-returning APIs — see
        # ``docs/z3_skeleton_synthesis_problem_2026_05_zh.md`` §6.
        creatable_types: Set[str] = set()
        for creates_at_pos, _, _ in per_position:
            for T in creates_at_pos:
                if _is_lifetime_managed(T):
                    creatable_types.add(T)

        # Track which creatable types have been instantiated at any prior position.
        ever_created: Set[str] = set()
        for j, api in enumerate(api_sequence):
            creates_j, uses_j, deletes_j = per_position[j]

            # Check USE preconditions — need an earlier CREATE on each used
            # type that *can* be created within this sequence.
            for T in uses_j & creatable_types:
                if T not in ever_created:
                    violations.append(
                        f"lifecycle: position {j} ({api.function_name}) "
                        f"uses type {T} but no prior position creates it"
                    )
            # Same precondition for DELETE.
            for T in deletes_j & creatable_types:
                if T not in ever_created:
                    violations.append(
                        f"lifecycle: position {j} ({api.function_name}) "
                        f"deletes type {T} but no prior position creates it"
                    )
            # Roll forward: this position's creates become available downstream.
            ever_created |= creates_j

        return violations

    # NOTE: legacy ``_add_lifecycle_constraints`` (API-name-quantified
    # all-pairs CREATE→USE / CREATE→DELETE / USE→DELETE order constraints)
    # removed 2026-05-22 — see _check_lifecycle_position_indexed above for
    # the position-indexed replacement.


class Z3DependencyPruner:
    """
    Z3 dependency graph pruner

    Uses Z3 constraint solving to precisely prune dependency graph
    """

    def __init__(self):
        pass

    def prune_dependency_edge(
        self,
        source_api: Api,
        target_api: Api,
        source_cond: Optional[FunctionConditions],
        target_cond: Optional[FunctionConditions]
    ) -> Tuple[bool, str]:
        """
        Check if dependency edge should be pruned

        Returns:
            (should_prune, reason): Whether should prune, and reason
        """
        builder = Z3ConstraintBuilder()

        # 1. Type matching check
        source_output_type = source_api.return_info.type
        for arg in target_api.arguments_info:
            target_input_type = arg.type

            # Clean type strings
            source_clean = source_output_type.replace("*", "").replace(" ", "")
            target_clean = target_input_type.replace("*", "").replace(" ", "")

            if source_clean == target_clean:
                # Types match, add constraint
                builder.add_type_match_constraint(
                    source_api.function_name,
                    target_api.function_name,
                    source_output_type,
                    target_input_type
                )

        # 2. Provenance compatibility check
        if source_cond and target_cond:
            source_prov = self._extract_provenance(source_cond.return_at)
            for i, arg_cond in enumerate(target_cond.argument_at):
                target_prov = self._extract_provenance(arg_cond)

                builder.add_provenance_constraint(
                    source_api.function_name,
                    target_api.function_name,
                    source_prov,
                    target_prov
                )

        # 3. Check satisfiability
        is_sat, _ = builder.check_satisfiability()

        if not is_sat:
            return True, "Constraints unsatisfiable"

        return False, "Compatible"

    def _extract_provenance(self, value_metadata: ValueMetadata) -> str:
        """Extract Provenance tag from ValueMetadata"""
        for at in value_metadata.ats:
            if hasattr(at, 'provenance') and at.provenance:
                return at.provenance.tag.value if hasattr(at.provenance, 'tag') else str(at.provenance)
        return "UNKNOWN"


# ========== Convenience Functions ==========

def is_z3_available() -> bool:
    """Check if Z3 is available"""
    return Z3_AVAILABLE


def validate_api_sequence(
    api_sequence: List[Api],
    function_conditions: Dict[str, FunctionConditions]
) -> Tuple[bool, List[str]]:
    """
    Convenience function: Validate API sequence

    Returns:
        (is_valid, violations)
    """
    validator = Z3SequenceValidator()
    return validator.validate_sequence(api_sequence, function_conditions)


