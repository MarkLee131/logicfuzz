"""
Constraint Collector - Constraint Collector

Collects constraints from driver skeleton and attempts to solve them using rules or constraint solvers.

Constraint types:
1. Type constraints: Variable types must match
2. Var-len constraints: Relationship between buffer length and size parameter
3. Lifetime constraints: Variable usage must be within valid lifetime
4. Value range constraints: Parameter values must be within valid range
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleSet, HoleKind, HolePriority,
    BufferSizeHole, ArrayLengthHole, InitValueHole, LoopBoundHole,
    SimpleHole,
)
from liberator_adapter.driver.synthesis.skeleton_generator import (
    DriverSkeleton, SkeletonVariable
)

logger = logging.getLogger(__name__)


# =============================================================================
# Constraint Definitions
# =============================================================================

class ConstraintKind(Enum):
    """Constraint types"""
    TYPE_COMPAT = auto()        # Type compatibility
    VARLEN_RELATION = auto()    # Variable-length relationship
    LIFETIME = auto()           # Lifetime
    VALUE_RANGE = auto()        # Value range
    NOT_NULL = auto()           # Not-null constraint
    DEPENDS_ON = auto()         # Dependency relationship


@dataclass
class Constraint:
    """Base constraint class"""
    kind: ConstraintKind
    description: str
    variables: List[str] = field(default_factory=list)
    is_hard: bool = True  # Hard constraints must be satisfied, soft constraints can be relaxed

    def to_smt(self) -> str:
        """Convert to SMT-LIB format (for Z3)"""
        return f"; {self.description}"


@dataclass
class TypeConstraint(Constraint):
    """Type constraint"""
    kind: ConstraintKind = field(default=ConstraintKind.TYPE_COMPAT, init=False)
    expected_type: str = ""
    actual_type: str = ""

    def to_smt(self) -> str:
        return f"(= (type {self.variables[0]}) {self.expected_type})"


@dataclass
class VarLenConstraint(Constraint):
    """Variable-length constraint"""
    kind: ConstraintKind = field(default=ConstraintKind.VARLEN_RELATION, init=False)
    buffer_var: str = ""
    length_var: str = ""
    relationship: str = ">="  # "==", ">=", "*"

    def to_smt(self) -> str:
        if self.relationship == ">=":
            return f"(>= (len {self.buffer_var}) {self.length_var})"
        elif self.relationship == "==":
            return f"(= (len {self.buffer_var}) {self.length_var})"
        return f"; varlen: {self.buffer_var} {self.relationship} {self.length_var}"


@dataclass
class ValueRangeConstraint(Constraint):
    """Value range constraint"""
    kind: ConstraintKind = field(default=ConstraintKind.VALUE_RANGE, init=False)
    variable: str = ""
    min_value: Optional[int] = None
    max_value: Optional[int] = None

    def to_smt(self) -> str:
        parts = []
        if self.min_value is not None:
            parts.append(f"(>= {self.variable} {self.min_value})")
        if self.max_value is not None:
            parts.append(f"(<= {self.variable} {self.max_value})")
        if len(parts) == 2:
            return f"(and {parts[0]} {parts[1]})"
        elif len(parts) == 1:
            return parts[0]
        return "; no range constraint"


@dataclass
class NotNullConstraint(Constraint):
    """Not-null constraint"""
    kind: ConstraintKind = field(default=ConstraintKind.NOT_NULL, init=False)
    variable: str = ""

    def to_smt(self) -> str:
        return f"(not (= {self.variable} NULL))"


@dataclass
class DependsOnConstraint(Constraint):
    """Dependency constraint"""
    kind: ConstraintKind = field(default=ConstraintKind.DEPENDS_ON, init=False)
    dependent_var: str = ""
    source_var: str = ""

    def to_smt(self) -> str:
        return f"; {self.dependent_var} depends on {self.source_var}"


# =============================================================================
# Constraint Set
# =============================================================================

@dataclass
class ConstraintSet:
    """Constraint set"""
    constraints: List[Constraint] = field(default_factory=list)

    def add(self, constraint: Constraint) -> None:
        self.constraints.append(constraint)

    def get_by_kind(self, kind: ConstraintKind) -> List[Constraint]:
        return [c for c in self.constraints if c.kind == kind]

    def get_for_variable(self, var_name: str) -> List[Constraint]:
        return [c for c in self.constraints if var_name in c.variables]

    def get_hard_constraints(self) -> List[Constraint]:
        return [c for c in self.constraints if c.is_hard]

    def get_soft_constraints(self) -> List[Constraint]:
        return [c for c in self.constraints if not c.is_hard]

    def to_smt_lib(self) -> str:
        """Export to SMT-LIB format"""
        lines = ["; Constraints"]
        for c in self.constraints:
            lines.append(f"(assert {c.to_smt()})")
        return "\n".join(lines)


# =============================================================================
# Constraint Collector
# =============================================================================

class ConstraintCollector:
    """
    Constraint collector

    Collects constraints from skeleton and analysis results
    """

    def __init__(self):
        self.constraints = ConstraintSet()

    def collect_from_skeleton(self, skeleton: DriverSkeleton) -> ConstraintSet:
        """Collect constraints from skeleton"""
        self.constraints = ConstraintSet()

        # 1. Collect type constraints
        self._collect_type_constraints(skeleton)

        # 2. Collect Hole-related constraints
        self._collect_hole_constraints(skeleton)

        # 3. Collect variable dependency constraints
        self._collect_dependency_constraints(skeleton)

        return self.constraints

    def _collect_type_constraints(self, skeleton: DriverSkeleton) -> None:
        """Collect type constraints"""
        for var_name, var in skeleton.variables.items():
            # Pointer types must be initialized to NULL or valid address
            if var.is_pointer:
                constraint = NotNullConstraint(
                    description=f"{var_name} should be valid pointer or NULL",
                    variables=[var_name],
                    variable=var_name,
                    is_hard=False  # Soft constraint, NULL is allowed
                )
                self.constraints.add(constraint)

    def _collect_hole_constraints(self, skeleton: DriverSkeleton) -> None:
        """Collect Hole-related constraints"""
        for hole in skeleton.holes:
            if isinstance(hole, BufferSizeHole):
                constraint = VarLenConstraint(
                    description=f"Buffer size constraint: {hole.name}",
                    variables=[],
                    buffer_var=f"arg{hole.buffer_arg_idx}",
                    length_var=f"arg{hole.length_arg_idx}",
                    relationship=hole.relationship
                )
                self.constraints.add(constraint)

            elif isinstance(hole, ArrayLengthHole):
                constraint = ValueRangeConstraint(
                    description=f"Array length constraint: {hole.name}",
                    variables=[hole.name],
                    variable=hole.name,
                    min_value=1,
                    max_value=hole.max_length
                )
                self.constraints.add(constraint)

            elif isinstance(hole, LoopBoundHole):
                constraint = ValueRangeConstraint(
                    description=f"Loop bound constraint: {hole.name}",
                    variables=[hole.name],
                    variable=hole.name,
                    min_value=1,
                    max_value=10000
                )
                self.constraints.add(constraint)

    def _collect_dependency_constraints(self, skeleton: DriverSkeleton) -> None:
        """Collect dependency constraints"""
        # Infer dependencies from statement order
        defined_vars: Set[str] = set()
        for stmt in skeleton.statements:
            for var in stmt.variables:
                if var not in defined_vars:
                    # Variable needs to be defined before use
                    pass
            defined_vars.update(stmt.variables)


# =============================================================================
# Constraint Solvers
# =============================================================================

class RuleBasedSolver:
    """
    Rule-based constraint solver

    Solves simple constraints with simple rules, does not depend on external solvers
    """

    def __init__(self):
        # Default value mapping
        self.default_sizes = {
            "buffer": 1024,
            "array": 256,
            "string": 512,
            "loop": 100,
        }

    def solve_simple_holes(
        self,
        skeleton: DriverSkeleton,
        constraints: ConstraintSet
    ) -> Dict[str, Any]:
        """
        Solve simple holes with rules

        Returns:
            {hole_name: filled_value}
        """
        solutions = {}

        for hole in skeleton.holes.get_simple_holes():
            if hole.is_filled:
                continue

            solution = self._solve_hole(hole, constraints)
            if solution is not None:
                solutions[hole.name] = solution

        return solutions

    def _solve_hole(self, hole: Hole, constraints: ConstraintSet) -> Optional[Any]:
        """Solve single hole"""
        if hole.kind == HoleKind.BUFFER_SIZE:
            return self._solve_buffer_size(hole, constraints)
        elif hole.kind == HoleKind.ARRAY_LENGTH:
            return self._solve_array_length(hole, constraints)
        elif hole.kind == HoleKind.INIT_VALUE:
            return self._solve_init_value(hole)
        elif hole.kind == HoleKind.LOOP_BOUND:
            return self._solve_loop_bound(hole, constraints)
        elif hole.kind == HoleKind.NULL_CHECK:
            return self._solve_null_check(hole)
        elif hole.kind == HoleKind.TYPE_CAST:
            return self._solve_type_cast(hole)
        return None

    def _solve_buffer_size(
        self,
        hole: Hole,
        constraints: ConstraintSet
    ) -> Optional[str]:
        """Solve buffer size"""
        if isinstance(hole, BufferSizeHole):
            # Use fuzz input size
            return "size"
        return str(self.default_sizes["buffer"])

    def _solve_array_length(
        self,
        hole: Hole,
        constraints: ConstraintSet
    ) -> Optional[int]:
        """Solve array length"""
        if isinstance(hole, ArrayLengthHole):
            # Check if there are range constraints
            hole_constraints = constraints.get_for_variable(hole.name)
            for c in hole_constraints:
                if isinstance(c, ValueRangeConstraint):
                    if c.max_value:
                        return min(self.default_sizes["array"], c.max_value)

            return min(self.default_sizes["array"], hole.max_length)

        return self.default_sizes["array"]

    def _solve_init_value(self, hole: Hole) -> Optional[str]:
        """Solve initialization value"""
        if isinstance(hole, InitValueHole):
            if hole.is_pointer:
                return "NULL"
            # Return default value based on type
            type_defaults = {
                "int": "0",
                "unsigned int": "0",
                "size_t": "0",
                "long": "0L",
                "float": "0.0f",
                "double": "0.0",
                "char": "'\\0'",
            }
            base_type = hole.target_type.replace("const", "").strip()
            return type_defaults.get(base_type, "0")
        return "0"

    def _solve_loop_bound(
        self,
        hole: Hole,
        constraints: ConstraintSet
    ) -> Optional[int]:
        """Solve loop bound"""
        if isinstance(hole, LoopBoundHole):
            return hole.suggested_bound
        return self.default_sizes["loop"]

    def _solve_null_check(self, hole: Hole) -> Optional[str]:
        """Solve NULL check"""
        return "!= NULL"

    def _solve_type_cast(self, hole: Hole) -> Optional[str]:
        """Solve type cast"""
        if isinstance(hole, SimpleHole):
            ctx = hole.context
            if "target_type" in ctx:
                return f"({ctx['target_type']})"
        return ""


# =============================================================================
# Z3 Solver Adapter (Optional)
# =============================================================================

class Z3SolverAdapter:
    """
    Z3 solver adapter

    Converts constraints to Z3-solvable form
    Note: Requires z3-solver package
    """

    def __init__(self):
        self._z3_available = False
        try:
            import z3
            self._z3_available = True
            self._z3 = z3
        except ImportError:
            logger.warning("Z3 not available, using rule-based solver only")

    @property
    def is_available(self) -> bool:
        return self._z3_available

    def solve_numeric_constraints(
        self,
        constraints: List[ValueRangeConstraint]
    ) -> Dict[str, int]:
        """Solve numeric constraints"""
        if not self._z3_available:
            return {}

        z3 = self._z3
        solver = z3.Solver()
        variables = {}

        # Create Z3 variables
        for c in constraints:
            if c.variable not in variables:
                variables[c.variable] = z3.Int(c.variable)

        # Add constraints
        for c in constraints:
            var = variables[c.variable]
            if c.min_value is not None:
                solver.add(var >= c.min_value)
            if c.max_value is not None:
                solver.add(var <= c.max_value)

        # Solve
        if solver.check() == z3.sat:
            model = solver.model()
            return {
                name: model[var].as_long()
                for name, var in variables.items()
                if model[var] is not None
            }

        return {}


# =============================================================================
# Comprehensive Constraint Solver
# =============================================================================

class ConstraintSolver:
    """
    Comprehensive constraint solver

    Combines rule-based solving and Z3 solving
    """

    def __init__(self, use_z3: bool = False):
        self.rule_solver = RuleBasedSolver()
        self.z3_solver = Z3SolverAdapter() if use_z3 else None

    def solve(
        self,
        skeleton: DriverSkeleton,
        constraints: Optional[ConstraintSet] = None
    ) -> Dict[str, Any]:
        """
        Solve simple holes in skeleton

        Returns:
            {hole_name: filled_value}
        """
        if constraints is None:
            collector = ConstraintCollector()
            constraints = collector.collect_from_skeleton(skeleton)

        solutions = {}

        # 1. Try rule-based solving
        rule_solutions = self.rule_solver.solve_simple_holes(skeleton, constraints)
        solutions.update(rule_solutions)

        # 2. Try Z3 solving (numeric constraints)
        if self.z3_solver and self.z3_solver.is_available:
            numeric_constraints = [
                c for c in constraints.get_by_kind(ConstraintKind.VALUE_RANGE)
                if isinstance(c, ValueRangeConstraint)
            ]
            if numeric_constraints:
                z3_solutions = self.z3_solver.solve_numeric_constraints(
                    numeric_constraints
                )
                # Z3 solutions have higher priority
                for name, value in z3_solutions.items():
                    if name in solutions:
                        solutions[name] = value

        return solutions

    def apply_solutions(
        self,
        skeleton: DriverSkeleton,
        solutions: Dict[str, Any]
    ) -> int:
        """
        Apply solutions to skeleton

        Returns:
            Number of filled holes
        """
        filled_count = 0

        for hole_name, value in solutions.items():
            if skeleton.holes.fill(hole_name, value, reason="constraint_solver"):
                filled_count += 1

        return filled_count


# =============================================================================
# Utility Functions
# =============================================================================

def collect_and_solve(skeleton: DriverSkeleton, use_z3: bool = False) -> Tuple[ConstraintSet, Dict[str, Any]]:
    """Convenience function: collect constraints and solve"""
    collector = ConstraintCollector()
    constraints = collector.collect_from_skeleton(skeleton)

    solver = ConstraintSolver(use_z3=use_z3)
    solutions = solver.solve(skeleton, constraints)

    return constraints, solutions
