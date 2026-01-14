"""
Z3 Constraint Solver for LogicFuzz

提供基于 Z3 的约束求解功能，用于：
1. API 序列可行性验证
2. 约束可满足性检查
3. 依赖图精确剪枝
4. 路径约束验证

Author: LogicFuzz Team
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    from z3 import (
        Solver, Bool, Int, BitVec, Array, And, Or, Not, Implies,
        sat, unsat, unknown, IntSort, BitVecSort, ArraySort,
        Function, ForAll, Exists, If, simplify, Context
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    # 提供 stub 以防 Z3 不可用
    Solver = None

from liberator_adapter.common import (
    Api, AccessType, Access, AccessTypeSet, ValueMetadata, FunctionConditions
)

logger = logging.getLogger(__name__)


class ConstraintType(Enum):
    """约束类型枚举"""
    TYPE_MATCH = "type_match"           # 类型匹配约束
    ACCESS_ORDER = "access_order"       # 访问顺序约束 (CREATE before DELETE)
    PROVENANCE = "provenance"           # Provenance 兼容性约束
    DEPENDENCY = "dependency"           # 参数依赖约束
    NULLABILITY = "nullability"         # 可空性约束
    ARRAY_BOUNDS = "array_bounds"       # 数组边界约束
    RESOURCE_LIFECYCLE = "lifecycle"    # 资源生命周期约束


@dataclass
class Z3Constraint:
    """Z3 约束的包装类"""
    constraint_type: ConstraintType
    z3_expr: Any  # Z3 expression
    description: str
    source_api: Optional[str] = None
    target_api: Optional[str] = None


class Z3ConstraintBuilder:
    """
    Z3 约束构建器

    将 LogicFuzz 的约束模型转换为 Z3 表达式
    """

    def __init__(self):
        if not Z3_AVAILABLE:
            raise RuntimeError("Z3 is not available. Please install z3-solver: pip install z3-solver")

        self.solver = Solver()
        self.constraints: List[Z3Constraint] = []

        # 变量映射
        self.api_vars: Dict[str, Any] = {}      # API 名称 -> Z3 变量
        self.type_vars: Dict[str, Any] = {}     # 类型名称 -> Z3 变量
        self.order_vars: Dict[str, Int] = {}    # API 序号变量

        # 类型兼容性缓存
        self._type_compat_cache: Dict[Tuple[str, str], bool] = {}

    def reset(self):
        """重置求解器状态"""
        self.solver.reset()
        self.constraints.clear()
        self.api_vars.clear()
        self.type_vars.clear()
        self.order_vars.clear()

    def _get_or_create_api_var(self, api_name: str) -> Bool:
        """获取或创建 API 的布尔变量（表示 API 是否被调用）"""
        if api_name not in self.api_vars:
            self.api_vars[api_name] = Bool(f"api_{api_name}")
        return self.api_vars[api_name]

    def _get_or_create_order_var(self, api_name: str) -> Int:
        """获取或创建 API 的序号变量（表示调用顺序）"""
        if api_name not in self.order_vars:
            self.order_vars[api_name] = Int(f"order_{api_name}")
        return self.order_vars[api_name]

    def _get_or_create_type_var(self, type_name: str) -> Int:
        """获取或创建类型变量（表示类型 ID）"""
        if type_name not in self.type_vars:
            # 使用整数表示类型 ID
            self.type_vars[type_name] = Int(f"type_{type_name}")
        return self.type_vars[type_name]

    # ========== 约束构建方法 ==========

    def add_type_match_constraint(
        self,
        source_api: str,
        target_api: str,
        source_type: str,
        target_type: str
    ) -> Z3Constraint:
        """
        添加类型匹配约束

        如果 target_api 依赖 source_api 的输出，则类型必须兼容
        """
        source_var = self._get_or_create_type_var(source_type)
        target_var = self._get_or_create_type_var(target_type)

        # 简化：去除指针和空格后比较
        source_clean = source_type.replace("*", "").replace(" ", "")
        target_clean = target_type.replace("*", "").replace(" ", "")

        # 如果类型相同，则添加等价约束
        if source_clean == target_clean:
            expr = source_var == target_var
        else:
            # 类型不同，约束为 False（不兼容）
            expr = Bool(f"type_compat_{source_api}_{target_api}")
            self.solver.add(Not(expr))  # 默认不兼容

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

    def add_access_order_constraint(
        self,
        create_api: str,
        delete_api: str
    ) -> Z3Constraint:
        """
        添加访问顺序约束

        CREATE 必须在 DELETE 之前发生
        """
        create_order = self._get_or_create_order_var(create_api)
        delete_order = self._get_or_create_order_var(delete_api)
        create_called = self._get_or_create_api_var(create_api)
        delete_called = self._get_or_create_api_var(delete_api)

        # 如果 delete 被调用，则 create 必须先被调用且顺序在前
        expr = Implies(
            delete_called,
            And(create_called, create_order < delete_order)
        )

        constraint = Z3Constraint(
            constraint_type=ConstraintType.ACCESS_ORDER,
            z3_expr=expr,
            description=f"Order: {create_api} before {delete_api}",
            source_api=create_api,
            target_api=delete_api
        )
        self.constraints.append(constraint)
        self.solver.add(expr)

        return constraint

    def add_provenance_constraint(
        self,
        source_api: str,
        target_api: str,
        source_prov: str,
        target_prov: str
    ) -> Z3Constraint:
        """
        添加 Provenance 兼容性约束

        检查源和目标的 provenance 是否兼容
        """
        source_called = self._get_or_create_api_var(source_api)
        target_called = self._get_or_create_api_var(target_api)

        # Provenance 兼容性规则
        compatible = self._check_provenance_compatibility(source_prov, target_prov)

        if compatible:
            expr = Bool(f"prov_compat_{source_api}_{target_api}")
            self.solver.add(expr)  # 兼容
        else:
            # 不兼容：如果两个 API 都被调用，则不可行
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
        """检查 Provenance 兼容性"""
        # 规则来自 provenance_checker.py
        if source_prov == "HEAP_MALLOC" and target_prov == "RETURN_OPAQUE":
            return False
        if source_prov in ["STACK", "GLOBAL"] and target_prov == "HEAP_MALLOC":
            return False
        if source_prov == "UNKNOWN" or target_prov == "UNKNOWN":
            return True
        return True

    def add_dependency_constraint(
        self,
        api_name: str,
        param_idx: int,
        depends_on_param: int,
        condition: str = "length"
    ) -> Z3Constraint:
        """
        添加参数依赖约束

        例如：param[i] 的长度依赖于 param[j]
        """
        api_var = self._get_or_create_api_var(api_name)

        # 创建参数变量
        param_var = Int(f"{api_name}_param_{param_idx}")
        dep_var = Int(f"{api_name}_param_{depends_on_param}")

        if condition == "length":
            # 长度约束：param_var 的大小应该与 dep_var 相关
            expr = Implies(
                api_var,
                And(param_var >= 0, dep_var >= 0, param_var <= dep_var * 1024)
            )
        else:
            # 通用依赖
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

    def add_resource_lifecycle_constraint(
        self,
        resource_type: str,
        create_apis: List[str],
        use_apis: List[str],
        delete_apis: List[str]
    ) -> List[Z3Constraint]:
        """
        添加资源生命周期约束

        资源必须先创建，使用，最后销毁
        """
        constraints = []

        # 创建资源存在性变量
        resource_exists = Bool(f"resource_{resource_type}_exists")

        # 任何 create API 可以创建资源
        if create_apis:
            create_exprs = [self._get_or_create_api_var(api) for api in create_apis]
            self.solver.add(Implies(resource_exists, Or(*create_exprs)))

        # 使用 API 需要资源存在
        for use_api in use_apis:
            use_var = self._get_or_create_api_var(use_api)
            expr = Implies(use_var, resource_exists)

            constraint = Z3Constraint(
                constraint_type=ConstraintType.RESOURCE_LIFECYCLE,
                z3_expr=expr,
                description=f"Lifecycle: {use_api} requires {resource_type}",
                source_api=use_api
            )
            constraints.append(constraint)
            self.solver.add(expr)

        # 删除 API 需要资源存在
        for delete_api in delete_apis:
            delete_var = self._get_or_create_api_var(delete_api)
            expr = Implies(delete_var, resource_exists)

            constraint = Z3Constraint(
                constraint_type=ConstraintType.RESOURCE_LIFECYCLE,
                z3_expr=expr,
                description=f"Lifecycle: {delete_api} requires {resource_type}",
                source_api=delete_api
            )
            constraints.append(constraint)
            self.solver.add(expr)

        self.constraints.extend(constraints)
        return constraints

    def add_api_sequence_constraint(
        self,
        api_sequence: List[str]
    ) -> Z3Constraint:
        """
        添加 API 序列顺序约束

        确保序列中的 API 按给定顺序执行
        """
        if len(api_sequence) < 2:
            return None

        order_exprs = []
        for i, api in enumerate(api_sequence):
            order_var = self._get_or_create_order_var(api)
            # 设置序号
            order_exprs.append(order_var == i)
            # 标记 API 被调用
            api_var = self._get_or_create_api_var(api)
            self.solver.add(api_var)

        expr = And(*order_exprs)

        constraint = Z3Constraint(
            constraint_type=ConstraintType.ACCESS_ORDER,
            z3_expr=expr,
            description=f"Sequence: {' -> '.join(api_sequence)}",
        )
        self.constraints.append(constraint)
        self.solver.add(expr)

        return constraint

    # ========== 求解方法 ==========

    def check_satisfiability(self) -> Tuple[bool, Optional[Dict]]:
        """
        检查当前约束是否可满足

        Returns:
            (is_sat, model): 是否可满足，以及满足时的模型
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

    def get_unsat_core(self) -> List[str]:
        """
        获取不可满足的核心约束

        需要先调用 solver.set("unsat_core", True)
        """
        self.solver.set("unsat_core", True)
        result = self.solver.check()

        if result == unsat:
            core = self.solver.unsat_core()
            return [str(c) for c in core]
        return []


class Z3SequenceValidator:
    """
    Z3 API 序列验证器

    用于验证 API 调用序列是否满足所有约束条件
    """

    def __init__(self):
        if not Z3_AVAILABLE:
            raise RuntimeError("Z3 is not available")

        self.builder = Z3ConstraintBuilder()

    def validate_sequence(
        self,
        api_sequence: List[Api],
        function_conditions: Dict[str, FunctionConditions]
    ) -> Tuple[bool, List[str]]:
        """
        验证 API 序列是否可行

        Args:
            api_sequence: API 调用序列
            function_conditions: 函数约束条件映射

        Returns:
            (is_valid, violations): 是否有效，以及违反的约束列表
        """
        self.builder.reset()
        violations = []

        # 1. 添加序列顺序约束
        api_names = [api.function_name for api in api_sequence]
        self.builder.add_api_sequence_constraint(api_names)

        # 2. 添加类型依赖约束
        for i, api in enumerate(api_sequence):
            if api.function_name not in function_conditions:
                continue

            cond = function_conditions[api.function_name]

            # 检查参数依赖
            for j, arg_cond in enumerate(cond.argument_at):
                if arg_cond.len_depends_on:
                    dep_idx = int(arg_cond.len_depends_on.replace("param_", ""))
                    self.builder.add_dependency_constraint(
                        api.function_name, j, dep_idx, "length"
                    )

        # 3. 添加资源生命周期约束
        self._add_lifecycle_constraints(api_sequence, function_conditions)

        # 4. 检查可满足性
        is_sat, model = self.builder.check_satisfiability()

        if not is_sat:
            violations = self.builder.get_unsat_core()

        return is_sat, violations

    def _add_lifecycle_constraints(
        self,
        api_sequence: List[Api],
        function_conditions: Dict[str, FunctionConditions]
    ):
        """添加资源生命周期约束"""
        # 收集 CREATE 和 DELETE 操作
        creates: Dict[str, List[str]] = {}  # type -> [api_names]
        deletes: Dict[str, List[str]] = {}

        for api in api_sequence:
            if api.function_name not in function_conditions:
                continue

            cond = function_conditions[api.function_name]

            # 检查返回值是否有 CREATE
            for at in cond.return_at.ats:
                if at.access == Access.CREATE:
                    type_str = at.type_string or api.return_info.type
                    if type_str not in creates:
                        creates[type_str] = []
                    creates[type_str].append(api.function_name)

            # 检查参数是否有 DELETE
            for arg_cond in cond.argument_at:
                for at in arg_cond.ats:
                    if at.access == Access.DELETE:
                        type_str = at.type_string or ""
                        if type_str not in deletes:
                            deletes[type_str] = []
                        deletes[type_str].append(api.function_name)

        # 添加 CREATE 必须在 DELETE 之前的约束
        for type_str in set(creates.keys()) & set(deletes.keys()):
            for create_api in creates[type_str]:
                for delete_api in deletes[type_str]:
                    self.builder.add_access_order_constraint(create_api, delete_api)


class Z3DependencyPruner:
    """
    Z3 依赖图剪枝器

    使用 Z3 约束求解来精确剪枝依赖图
    """

    def __init__(self):
        if not Z3_AVAILABLE:
            raise RuntimeError("Z3 is not available")

    def prune_dependency_edge(
        self,
        source_api: Api,
        target_api: Api,
        source_cond: Optional[FunctionConditions],
        target_cond: Optional[FunctionConditions]
    ) -> Tuple[bool, str]:
        """
        检查依赖边是否应该被剪枝

        Returns:
            (should_prune, reason): 是否应该剪枝，以及原因
        """
        builder = Z3ConstraintBuilder()

        # 1. 类型匹配检查
        source_output_type = source_api.return_info.type
        for arg in target_api.arguments_info:
            target_input_type = arg.type

            # 清理类型字符串
            source_clean = source_output_type.replace("*", "").replace(" ", "")
            target_clean = target_input_type.replace("*", "").replace(" ", "")

            if source_clean == target_clean:
                # 类型匹配，添加约束
                builder.add_type_match_constraint(
                    source_api.function_name,
                    target_api.function_name,
                    source_output_type,
                    target_input_type
                )

        # 2. Provenance 兼容性检查
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

        # 3. 检查可满足性
        is_sat, _ = builder.check_satisfiability()

        if not is_sat:
            return True, "Constraints unsatisfiable"

        return False, "Compatible"

    def _extract_provenance(self, value_metadata: ValueMetadata) -> str:
        """从 ValueMetadata 中提取 Provenance 标签"""
        for at in value_metadata.ats:
            if hasattr(at, 'provenance') and at.provenance:
                return at.provenance.tag.value if hasattr(at.provenance, 'tag') else str(at.provenance)
        return "UNKNOWN"


# ========== 便捷函数 ==========

def is_z3_available() -> bool:
    """检查 Z3 是否可用"""
    return Z3_AVAILABLE


def validate_api_sequence(
    api_sequence: List[Api],
    function_conditions: Dict[str, FunctionConditions]
) -> Tuple[bool, List[str]]:
    """
    便捷函数：验证 API 序列

    Returns:
        (is_valid, violations)
    """
    if not Z3_AVAILABLE:
        logger.warning("Z3 not available, skipping validation")
        return True, []

    validator = Z3SequenceValidator()
    return validator.validate_sequence(api_sequence, function_conditions)


def should_prune_dependency(
    source_api: Api,
    target_api: Api,
    source_cond: Optional[FunctionConditions] = None,
    target_cond: Optional[FunctionConditions] = None
) -> bool:
    """
    便捷函数：检查依赖边是否应该被剪枝
    """
    if not Z3_AVAILABLE:
        return False

    pruner = Z3DependencyPruner()
    should_prune, _ = pruner.prune_dependency_edge(
        source_api, target_api, source_cond, target_cond
    )
    return should_prune
