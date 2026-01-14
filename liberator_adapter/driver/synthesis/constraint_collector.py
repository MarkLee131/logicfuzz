"""
Constraint Collector - 约束收集器

收集Driver骨架中的约束，并尝试用规则或约束求解器解决。

约束类型:
1. 类型约束: 变量类型必须匹配
2. Var-len约束: buffer长度与size参数的关系
3. 生命周期约束: 变量使用必须在有效生命周期内
4. 值域约束: 参数值必须在有效范围内
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
# 约束定义
# =============================================================================

class ConstraintKind(Enum):
    """约束类型"""
    TYPE_COMPAT = auto()        # 类型兼容性
    VARLEN_RELATION = auto()    # 变长关系
    LIFETIME = auto()           # 生命周期
    VALUE_RANGE = auto()        # 值域
    NOT_NULL = auto()           # 非空约束
    DEPENDS_ON = auto()         # 依赖关系


@dataclass
class Constraint:
    """约束基类"""
    kind: ConstraintKind
    description: str
    variables: List[str] = field(default_factory=list)
    is_hard: bool = True  # 硬约束必须满足，软约束可以放松

    def to_smt(self) -> str:
        """转换为SMT-LIB格式（用于Z3）"""
        return f"; {self.description}"


@dataclass
class TypeConstraint(Constraint):
    """类型约束"""
    kind: ConstraintKind = field(default=ConstraintKind.TYPE_COMPAT, init=False)
    expected_type: str = ""
    actual_type: str = ""

    def to_smt(self) -> str:
        return f"(= (type {self.variables[0]}) {self.expected_type})"


@dataclass
class VarLenConstraint(Constraint):
    """变长约束"""
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
    """值域约束"""
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
    """非空约束"""
    kind: ConstraintKind = field(default=ConstraintKind.NOT_NULL, init=False)
    variable: str = ""

    def to_smt(self) -> str:
        return f"(not (= {self.variable} NULL))"


@dataclass
class DependsOnConstraint(Constraint):
    """依赖约束"""
    kind: ConstraintKind = field(default=ConstraintKind.DEPENDS_ON, init=False)
    dependent_var: str = ""
    source_var: str = ""

    def to_smt(self) -> str:
        return f"; {self.dependent_var} depends on {self.source_var}"


# =============================================================================
# 约束集合
# =============================================================================

@dataclass
class ConstraintSet:
    """约束集合"""
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
        """导出为SMT-LIB格式"""
        lines = ["; Constraints"]
        for c in self.constraints:
            lines.append(f"(assert {c.to_smt()})")
        return "\n".join(lines)


# =============================================================================
# 约束收集器
# =============================================================================

class ConstraintCollector:
    """
    约束收集器

    从骨架和分析结果中收集约束
    """

    def __init__(self):
        self.constraints = ConstraintSet()

    def collect_from_skeleton(self, skeleton: DriverSkeleton) -> ConstraintSet:
        """从骨架收集约束"""
        self.constraints = ConstraintSet()

        # 1. 收集类型约束
        self._collect_type_constraints(skeleton)

        # 2. 收集Hole相关约束
        self._collect_hole_constraints(skeleton)

        # 3. 收集变量依赖约束
        self._collect_dependency_constraints(skeleton)

        return self.constraints

    def _collect_type_constraints(self, skeleton: DriverSkeleton) -> None:
        """收集类型约束"""
        for var_name, var in skeleton.variables.items():
            # 指针类型必须初始化为NULL或有效地址
            if var.is_pointer:
                constraint = NotNullConstraint(
                    description=f"{var_name} should be valid pointer or NULL",
                    variables=[var_name],
                    variable=var_name,
                    is_hard=False  # 软约束，NULL是允许的
                )
                self.constraints.add(constraint)

    def _collect_hole_constraints(self, skeleton: DriverSkeleton) -> None:
        """收集Hole相关约束"""
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
        """收集依赖约束"""
        # 从语句顺序推断依赖
        defined_vars: Set[str] = set()
        for stmt in skeleton.statements:
            for var in stmt.variables:
                if var not in defined_vars:
                    # 变量使用前需要定义
                    pass
            defined_vars.update(stmt.variables)


# =============================================================================
# 约束求解器
# =============================================================================

class RuleBasedSolver:
    """
    基于规则的约束求解器

    用简单规则解决简单约束，不依赖外部求解器
    """

    def __init__(self):
        # 默认值映射
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
        用规则解决简单孔

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
        """解决单个孔"""
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
        """解决buffer大小"""
        if isinstance(hole, BufferSizeHole):
            # 使用fuzz输入的size
            return "size"
        return str(self.default_sizes["buffer"])

    def _solve_array_length(
        self,
        hole: Hole,
        constraints: ConstraintSet
    ) -> Optional[int]:
        """解决数组长度"""
        if isinstance(hole, ArrayLengthHole):
            # 检查是否有范围约束
            hole_constraints = constraints.get_for_variable(hole.name)
            for c in hole_constraints:
                if isinstance(c, ValueRangeConstraint):
                    if c.max_value:
                        return min(self.default_sizes["array"], c.max_value)

            return min(self.default_sizes["array"], hole.max_length)

        return self.default_sizes["array"]

    def _solve_init_value(self, hole: Hole) -> Optional[str]:
        """解决初始化值"""
        if isinstance(hole, InitValueHole):
            if hole.is_pointer:
                return "NULL"
            # 根据类型返回默认值
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
        """解决循环边界"""
        if isinstance(hole, LoopBoundHole):
            return hole.suggested_bound
        return self.default_sizes["loop"]

    def _solve_null_check(self, hole: Hole) -> Optional[str]:
        """解决NULL检查"""
        return "!= NULL"

    def _solve_type_cast(self, hole: Hole) -> Optional[str]:
        """解决类型转换"""
        if isinstance(hole, SimpleHole):
            ctx = hole.context
            if "target_type" in ctx:
                return f"({ctx['target_type']})"
        return ""


# =============================================================================
# Z3求解器适配器（可选）
# =============================================================================

class Z3SolverAdapter:
    """
    Z3求解器适配器

    将约束转换为Z3可解的形式
    注意: 需要安装z3-solver包
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
        """解决数值约束"""
        if not self._z3_available:
            return {}

        z3 = self._z3
        solver = z3.Solver()
        variables = {}

        # 创建Z3变量
        for c in constraints:
            if c.variable not in variables:
                variables[c.variable] = z3.Int(c.variable)

        # 添加约束
        for c in constraints:
            var = variables[c.variable]
            if c.min_value is not None:
                solver.add(var >= c.min_value)
            if c.max_value is not None:
                solver.add(var <= c.max_value)

        # 求解
        if solver.check() == z3.sat:
            model = solver.model()
            return {
                name: model[var].as_long()
                for name, var in variables.items()
                if model[var] is not None
            }

        return {}


# =============================================================================
# 综合约束求解器
# =============================================================================

class ConstraintSolver:
    """
    综合约束求解器

    组合规则求解和Z3求解
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
        解决骨架中的简单孔

        Returns:
            {hole_name: filled_value}
        """
        if constraints is None:
            collector = ConstraintCollector()
            constraints = collector.collect_from_skeleton(skeleton)

        solutions = {}

        # 1. 尝试规则求解
        rule_solutions = self.rule_solver.solve_simple_holes(skeleton, constraints)
        solutions.update(rule_solutions)

        # 2. 尝试Z3求解（数值约束）
        if self.z3_solver and self.z3_solver.is_available:
            numeric_constraints = [
                c for c in constraints.get_by_kind(ConstraintKind.VALUE_RANGE)
                if isinstance(c, ValueRangeConstraint)
            ]
            if numeric_constraints:
                z3_solutions = self.z3_solver.solve_numeric_constraints(
                    numeric_constraints
                )
                # Z3解优先级更高
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
        将解应用到骨架

        Returns:
            填充的孔数量
        """
        filled_count = 0

        for hole_name, value in solutions.items():
            if skeleton.holes.fill(hole_name, value, reason="constraint_solver"):
                filled_count += 1

        return filled_count


# =============================================================================
# 工具函数
# =============================================================================

def collect_and_solve(skeleton: DriverSkeleton, use_z3: bool = False) -> Tuple[ConstraintSet, Dict[str, Any]]:
    """便捷函数：收集约束并求解"""
    collector = ConstraintCollector()
    constraints = collector.collect_from_skeleton(skeleton)

    solver = ConstraintSolver(use_z3=use_z3)
    solutions = solver.solve(skeleton, constraints)

    return constraints, solutions
