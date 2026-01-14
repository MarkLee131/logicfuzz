"""
Hole - 程序合成中的"孔"定义

在混合合成方法中，骨架生成器产生带有"孔"的不完整程序。
孔分为两类:
- SimpleHole: 可通过规则/约束求解器填充
- ComplexHole: 需要LLM语义推理填充

主要用途:
1. 表示Driver生成中的不确定部分
2. 指导填充策略选择
3. 支持增量式Driver构建
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod


# =============================================================================
# Hole类型枚举
# =============================================================================

class HoleKind(Enum):
    """孔的分类"""

    # === SimpleHole (规则/约束可解) ===
    BUFFER_SIZE = auto()        # Buffer大小: 由var-len关系确定
    ARRAY_LENGTH = auto()       # 数组长度: 由size参数确定
    NULL_CHECK = auto()         # NULL检查条件: 基于API返回值语义
    LOOP_BOUND = auto()         # 循环边界: 安全上限
    TYPE_CAST = auto()          # 类型转换: 基于类型兼容性
    INIT_VALUE = auto()         # 初始化值: 0, NULL, 或默认值

    # === ComplexHole (需要LLM) ===
    CALLBACK_IMPL = auto()      # 回调函数实现
    LOOP_CONDITION = auto()     # 循环终止条件
    ERROR_HANDLING = auto()     # 错误处理逻辑
    RESOURCE_CLEANUP = auto()   # 资源清理顺序
    PARAM_CONSTRAINT = auto()   # 参数约束关系
    API_SEQUENCE = auto()       # API调用顺序选择


class HolePriority(Enum):
    """填充优先级"""
    CRITICAL = 1    # 必须填充，否则编译失败
    HIGH = 2        # 影响正确性
    MEDIUM = 3      # 影响覆盖率
    LOW = 4         # 优化项


# =============================================================================
# Hole基类
# =============================================================================

@dataclass
class Hole(ABC):
    """孔的基类"""

    kind: HoleKind
    name: str                       # 孔的标识符 (如 "size_0", "callback_1")
    priority: HolePriority = HolePriority.HIGH
    context: Dict[str, Any] = field(default_factory=dict)  # 上下文信息
    filled_value: Optional[Any] = None  # 填充后的值
    fill_reason: str = ""           # 填充决策的理由

    @property
    def is_filled(self) -> bool:
        return self.filled_value is not None

    @property
    @abstractmethod
    def is_simple(self) -> bool:
        """是否是简单孔（可用规则填充）"""
        pass

    @abstractmethod
    def get_placeholder(self) -> str:
        """获取占位符字符串（用于骨架代码）"""
        pass

    @abstractmethod
    def validate_fill(self, value: Any) -> bool:
        """验证填充值是否合法"""
        pass


# =============================================================================
# SimpleHole - 规则可解的孔
# =============================================================================

@dataclass
class SimpleHole(Hole):
    """简单孔 - 可通过规则或约束求解器填充"""

    # 约束信息
    constraints: List[str] = field(default_factory=list)  # 约束表达式
    valid_range: Optional[tuple] = None  # 有效值范围 (min, max)
    default_value: Optional[Any] = None  # 默认值

    @property
    def is_simple(self) -> bool:
        return True

    def get_placeholder(self) -> str:
        return f"__HOLE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if self.valid_range:
            min_val, max_val = self.valid_range
            if not (min_val <= value <= max_val):
                return False
        return True


@dataclass
class BufferSizeHole(SimpleHole):
    """Buffer大小孔"""

    kind: HoleKind = field(default=HoleKind.BUFFER_SIZE, init=False)
    buffer_arg_idx: int = -1        # 对应的buffer参数索引
    length_arg_idx: int = -1        # 对应的length参数索引
    relationship: str = "=="        # 关系: "==", ">=", "size*count"

    def get_placeholder(self) -> str:
        return f"__BUFSIZE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if not isinstance(value, (int, str)):
            return False
        if isinstance(value, int) and value < 0:
            return False
        return True


@dataclass
class ArrayLengthHole(SimpleHole):
    """数组长度孔"""

    kind: HoleKind = field(default=HoleKind.ARRAY_LENGTH, init=False)
    element_type: str = ""          # 元素类型
    max_length: int = 1024          # 最大长度限制

    def get_placeholder(self) -> str:
        return f"__ARRLEN_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if not isinstance(value, int):
            return False
        return 0 < value <= self.max_length


@dataclass
class InitValueHole(SimpleHole):
    """初始化值孔"""

    kind: HoleKind = field(default=HoleKind.INIT_VALUE, init=False)
    target_type: str = ""           # 目标类型
    is_pointer: bool = False        # 是否是指针类型

    def get_placeholder(self) -> str:
        return f"__INIT_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        # 指针类型接受NULL或地址
        if self.is_pointer:
            return value in [None, "NULL", 0] or isinstance(value, str)
        return True


@dataclass
class LoopBoundHole(SimpleHole):
    """循环边界孔"""

    kind: HoleKind = field(default=HoleKind.LOOP_BOUND, init=False)
    suggested_bound: int = 100      # 建议的边界值

    def get_placeholder(self) -> str:
        return f"__LOOPBOUND_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        return isinstance(value, int) and 0 < value <= 10000


# =============================================================================
# ComplexHole - 需要LLM填充的孔
# =============================================================================

@dataclass
class ComplexHole(Hole):
    """复杂孔 - 需要LLM语义推理填充"""

    # LLM辅助信息
    api_context: Optional[str] = None       # 相关API信息
    code_context: Optional[str] = None      # 周围代码上下文
    semantic_hints: List[str] = field(default_factory=list)  # 语义提示

    @property
    def is_simple(self) -> bool:
        return False

    def get_placeholder(self) -> str:
        return f"__COMPLEX_HOLE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        # 复杂孔通常填充代码字符串
        return isinstance(value, str) and len(value) > 0


@dataclass
class CallbackImplHole(ComplexHole):
    """回调函数实现孔"""

    kind: HoleKind = field(default=HoleKind.CALLBACK_IMPL, init=False)
    callback_signature: str = ""    # 回调函数签名
    callback_type: str = ""         # 回调类型 (comparator, handler, reader等)
    expected_behavior: str = ""     # 期望行为描述

    def get_placeholder(self) -> str:
        return f"__CALLBACK_{self.name}__"


@dataclass
class LoopConditionHole(ComplexHole):
    """循环条件孔"""

    kind: HoleKind = field(default=HoleKind.LOOP_CONDITION, init=False)
    loop_type: str = ""             # 循环类型: iterator, incremental, state_machine
    termination_hint: str = ""      # 终止条件提示
    api_return_type: str = ""       # 相关API返回类型

    def get_placeholder(self) -> str:
        return f"__LOOPCOND_{self.name}__"


@dataclass
class ErrorHandlingHole(ComplexHole):
    """错误处理孔"""

    kind: HoleKind = field(default=HoleKind.ERROR_HANDLING, init=False)
    error_source: str = ""          # 错误来源 (哪个API调用)
    error_type: str = ""            # 错误类型 (NULL, negative, exception)
    cleanup_needed: List[str] = field(default_factory=list)  # 需要清理的资源

    def get_placeholder(self) -> str:
        return f"__ERRHANDLE_{self.name}__"


@dataclass
class ResourceCleanupHole(ComplexHole):
    """资源清理孔"""

    kind: HoleKind = field(default=HoleKind.RESOURCE_CLEANUP, init=False)
    resources: List[str] = field(default_factory=list)  # 需要清理的资源
    cleanup_order: List[str] = field(default_factory=list)  # 建议的清理顺序

    def get_placeholder(self) -> str:
        return f"__CLEANUP_{self.name}__"


@dataclass
class ParamConstraintHole(ComplexHole):
    """参数约束孔"""

    kind: HoleKind = field(default=HoleKind.PARAM_CONSTRAINT, init=False)
    param_name: str = ""            # 参数名
    param_type: str = ""            # 参数类型
    related_params: List[str] = field(default_factory=list)  # 相关参数

    def get_placeholder(self) -> str:
        return f"__PARAMCONST_{self.name}__"


# =============================================================================
# HoleSet - 孔的集合管理
# =============================================================================

@dataclass
class HoleSet:
    """孔的集合，用于管理骨架中的所有孔"""

    holes: Dict[str, Hole] = field(default_factory=dict)

    def add(self, hole: Hole) -> None:
        """添加孔"""
        self.holes[hole.name] = hole

    def get(self, name: str) -> Optional[Hole]:
        """获取孔"""
        return self.holes.get(name)

    def get_unfilled(self) -> List[Hole]:
        """获取未填充的孔"""
        return [h for h in self.holes.values() if not h.is_filled]

    def get_simple_holes(self) -> List[Hole]:
        """获取所有简单孔"""
        return [h for h in self.holes.values() if h.is_simple]

    def get_complex_holes(self) -> List[Hole]:
        """获取所有复杂孔"""
        return [h for h in self.holes.values() if not h.is_simple]

    def get_by_kind(self, kind: HoleKind) -> List[Hole]:
        """按类型获取孔"""
        return [h for h in self.holes.values() if h.kind == kind]

    def get_by_priority(self, priority: HolePriority) -> List[Hole]:
        """按优先级获取孔"""
        return [h for h in self.holes.values() if h.priority == priority]

    def fill(self, name: str, value: Any, reason: str = "") -> bool:
        """填充孔"""
        hole = self.holes.get(name)
        if hole is None:
            return False
        if not hole.validate_fill(value):
            return False
        hole.filled_value = value
        hole.fill_reason = reason
        return True

    def all_filled(self) -> bool:
        """检查是否所有孔都已填充"""
        return all(h.is_filled for h in self.holes.values())

    def get_critical_unfilled(self) -> List[Hole]:
        """获取未填充的关键孔"""
        return [h for h in self.holes.values()
                if not h.is_filled and h.priority == HolePriority.CRITICAL]

    def __len__(self) -> int:
        return len(self.holes)

    def __iter__(self):
        return iter(self.holes.values())


# =============================================================================
# 工具函数
# =============================================================================

def create_buffer_size_hole(name: str, buffer_idx: int, length_idx: int,
                            relationship: str = ">=") -> BufferSizeHole:
    """创建buffer大小孔"""
    return BufferSizeHole(
        name=name,
        buffer_arg_idx=buffer_idx,
        length_arg_idx=length_idx,
        relationship=relationship,
        priority=HolePriority.CRITICAL
    )


def create_callback_hole(name: str, signature: str,
                         callback_type: str) -> CallbackImplHole:
    """创建回调实现孔"""
    return CallbackImplHole(
        name=name,
        callback_signature=signature,
        callback_type=callback_type,
        priority=HolePriority.CRITICAL
    )


def create_loop_condition_hole(name: str, loop_type: str,
                               api_return_type: str) -> LoopConditionHole:
    """创建循环条件孔"""
    return LoopConditionHole(
        name=name,
        loop_type=loop_type,
        api_return_type=api_return_type,
        priority=HolePriority.HIGH
    )


def create_error_handling_hole(name: str, error_source: str,
                               cleanup_needed: List[str]) -> ErrorHandlingHole:
    """创建错误处理孔"""
    return ErrorHandlingHole(
        name=name,
        error_source=error_source,
        cleanup_needed=cleanup_needed,
        priority=HolePriority.HIGH
    )


def classify_hole_for_param(param_type: str, param_name: str,
                            has_varlen_relation: bool,
                            is_callback: bool) -> HoleKind:
    """根据参数特征判断需要哪种类型的孔"""
    if is_callback:
        return HoleKind.CALLBACK_IMPL
    if has_varlen_relation:
        return HoleKind.BUFFER_SIZE
    if "size" in param_name.lower() or "len" in param_name.lower():
        return HoleKind.ARRAY_LENGTH
    if "*" in param_type:
        return HoleKind.INIT_VALUE
    return HoleKind.INIT_VALUE
