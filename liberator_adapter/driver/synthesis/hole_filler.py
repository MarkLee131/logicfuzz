"""
Hole Filler - 孔填充器

分层填充策略:
1. 规则填充: 简单孔用预定义规则
2. 约束求解: 有约束的孔用求解器
3. LLM填充: 复杂孔用LLM语义推理

设计原则:
- 优先使用确定性方法（规则、约束）
- LLM作为兜底方案处理复杂语义
- 填充结果可验证、可解释
"""

import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleSet, HoleKind, HolePriority,
    SimpleHole, ComplexHole,
    BufferSizeHole, ArrayLengthHole, InitValueHole, LoopBoundHole,
    CallbackImplHole, LoopConditionHole, ErrorHandlingHole, ResourceCleanupHole,
)
from liberator_adapter.driver.synthesis.skeleton_generator import DriverSkeleton
from liberator_adapter.driver.synthesis.constraint_collector import (
    ConstraintSet, ConstraintCollector, ConstraintSolver
)

logger = logging.getLogger(__name__)


# =============================================================================
# 填充结果
# =============================================================================

@dataclass
class FillResult:
    """填充结果"""
    hole_name: str
    success: bool
    value: Optional[Any] = None
    method: str = ""        # "rule", "constraint", "llm"
    reason: str = ""
    confidence: float = 1.0  # 置信度 (LLM填充时有意义)


@dataclass
class FillReport:
    """填充报告"""
    results: List[FillResult] = field(default_factory=list)
    total_holes: int = 0
    filled_count: int = 0
    failed_count: int = 0

    def add(self, result: FillResult) -> None:
        self.results.append(result)
        if result.success:
            self.filled_count += 1
        else:
            self.failed_count += 1

    @property
    def success_rate(self) -> float:
        if self.total_holes == 0:
            return 1.0
        return self.filled_count / self.total_holes

    def get_failed(self) -> List[FillResult]:
        return [r for r in self.results if not r.success]

    def get_by_method(self, method: str) -> List[FillResult]:
        return [r for r in self.results if r.method == method]


# =============================================================================
# 填充策略接口
# =============================================================================

class FillStrategy(ABC):
    """填充策略接口"""

    @abstractmethod
    def can_fill(self, hole: Hole) -> bool:
        """检查是否能填充该类型的孔"""
        pass

    @abstractmethod
    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        """填充孔"""
        pass


# =============================================================================
# 规则填充策略
# =============================================================================

class RuleFillStrategy(FillStrategy):
    """基于规则的填充策略"""

    def __init__(self):
        # 规则映射: HoleKind -> 填充函数
        self.rules: Dict[HoleKind, Callable] = {
            HoleKind.BUFFER_SIZE: self._fill_buffer_size,
            HoleKind.ARRAY_LENGTH: self._fill_array_length,
            HoleKind.INIT_VALUE: self._fill_init_value,
            HoleKind.LOOP_BOUND: self._fill_loop_bound,
            HoleKind.NULL_CHECK: self._fill_null_check,
            HoleKind.TYPE_CAST: self._fill_type_cast,
        }

    def can_fill(self, hole: Hole) -> bool:
        return hole.kind in self.rules

    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        if not self.can_fill(hole):
            return FillResult(
                hole_name=hole.name,
                success=False,
                reason="No rule for this hole kind"
            )

        try:
            rule_func = self.rules[hole.kind]
            value = rule_func(hole, context)
            return FillResult(
                hole_name=hole.name,
                success=True,
                value=value,
                method="rule",
                reason=f"Filled by rule for {hole.kind.name}"
            )
        except Exception as e:
            return FillResult(
                hole_name=hole.name,
                success=False,
                reason=f"Rule failed: {e}"
            )

    def _fill_buffer_size(self, hole: Hole, context: Dict) -> str:
        """填充buffer大小"""
        # 默认使用fuzz输入的size
        return "size"

    def _fill_array_length(self, hole: Hole, context: Dict) -> int:
        """填充数组长度"""
        if isinstance(hole, ArrayLengthHole):
            return min(256, hole.max_length)
        return 256

    def _fill_init_value(self, hole: Hole, context: Dict) -> str:
        """填充初始化值"""
        if isinstance(hole, InitValueHole):
            if hole.is_pointer:
                return "NULL"
            type_defaults = {
                "int": "0",
                "unsigned int": "0",
                "size_t": "0",
                "long": "0L",
                "float": "0.0f",
                "double": "0.0",
                "char": "'\\0'",
                "bool": "false",
            }
            base_type = hole.target_type.replace("const", "").strip()
            return type_defaults.get(base_type, "0")
        return "0"

    def _fill_loop_bound(self, hole: Hole, context: Dict) -> int:
        """填充循环边界"""
        if isinstance(hole, LoopBoundHole):
            return hole.suggested_bound
        return 100

    def _fill_null_check(self, hole: Hole, context: Dict) -> str:
        """填充NULL检查"""
        return "!= NULL"

    def _fill_type_cast(self, hole: Hole, context: Dict) -> str:
        """填充类型转换"""
        target_type = context.get("target_type", "void*")
        return f"({target_type})"


# =============================================================================
# 约束求解策略
# =============================================================================

class ConstraintFillStrategy(FillStrategy):
    """基于约束求解的填充策略"""

    def __init__(self, use_z3: bool = False):
        self.solver = ConstraintSolver(use_z3=use_z3)
        self._solutions: Dict[str, Any] = {}

    def precompute(self, skeleton: DriverSkeleton, constraints: ConstraintSet) -> None:
        """预计算约束解"""
        self._solutions = self.solver.solve(skeleton, constraints)

    def can_fill(self, hole: Hole) -> bool:
        # 约束求解主要处理SimpleHole
        return hole.is_simple and hole.name in self._solutions

    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        if hole.name in self._solutions:
            return FillResult(
                hole_name=hole.name,
                success=True,
                value=self._solutions[hole.name],
                method="constraint",
                reason="Solved by constraint solver"
            )
        return FillResult(
            hole_name=hole.name,
            success=False,
            reason="No constraint solution found"
        )


# =============================================================================
# LLM填充策略
# =============================================================================

class LLMClient(ABC):
    """LLM客户端接口"""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """调用LLM完成prompt"""
        pass


class LLMFillStrategy(FillStrategy):
    """基于LLM的填充策略"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

        # Prompt模板
        self.prompts = {
            HoleKind.CALLBACK_IMPL: self._callback_prompt,
            HoleKind.LOOP_CONDITION: self._loop_condition_prompt,
            HoleKind.ERROR_HANDLING: self._error_handling_prompt,
            HoleKind.RESOURCE_CLEANUP: self._cleanup_prompt,
            HoleKind.PARAM_CONSTRAINT: self._param_constraint_prompt,
        }

    def set_llm_client(self, client: LLMClient) -> None:
        self.llm_client = client

    def can_fill(self, hole: Hole) -> bool:
        return (
            not hole.is_simple and
            hole.kind in self.prompts and
            self.llm_client is not None
        )

    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        if not self.can_fill(hole):
            return FillResult(
                hole_name=hole.name,
                success=False,
                reason="LLM not available or unsupported hole kind"
            )

        try:
            prompt_func = self.prompts[hole.kind]
            prompt = prompt_func(hole, context)
            response = self.llm_client.complete(prompt)
            value = self._parse_response(response, hole.kind)

            return FillResult(
                hole_name=hole.name,
                success=True,
                value=value,
                method="llm",
                reason="Generated by LLM",
                confidence=0.8  # LLM填充置信度略低
            )
        except Exception as e:
            return FillResult(
                hole_name=hole.name,
                success=False,
                reason=f"LLM failed: {e}"
            )

    def _callback_prompt(self, hole: Hole, context: Dict) -> str:
        """生成回调实现的prompt"""
        if isinstance(hole, CallbackImplHole):
            return f'''Generate a minimal C callback implementation for fuzzing.

Callback signature: {hole.callback_signature}
Callback type: {hole.callback_type}
Expected behavior: {hole.expected_behavior or "Generic callback stub"}

Requirements:
1. The callback should be safe (no crashes, infinite loops)
2. For comparators: return a simple comparison result
3. For handlers: log or ignore the event
4. For readers: read from fuzz input buffer
5. For writers: write to a discard buffer
6. For allocators: use malloc with size limits

Output ONLY the C function implementation, no explanations.
'''
        return ""

    def _loop_condition_prompt(self, hole: Hole, context: Dict) -> str:
        """生成循环条件的prompt"""
        if isinstance(hole, LoopConditionHole):
            return f'''Generate a loop termination condition for a fuzz driver.

Loop type: {hole.loop_type}
API return type: {hole.api_return_type}
Termination hint: {hole.termination_hint or "None"}

The condition should:
1. Ensure the loop terminates
2. Be based on the API return value or state
3. Work correctly with common patterns (iterator, reader, etc.)

For iterator: check if return is NULL
For incremental: check if return is <= 0
For state machine: check state variable

Output ONLY the C condition expression (e.g., "result != NULL").
'''
        return ""

    def _error_handling_prompt(self, hole: Hole, context: Dict) -> str:
        """生成错误处理代码的prompt"""
        if isinstance(hole, ErrorHandlingHole):
            cleanup_list = ", ".join(hole.cleanup_needed) if hole.cleanup_needed else "none"
            return f'''Generate error handling code for a fuzz driver.

Error source: {hole.error_source}
Error type: {hole.error_type}
Resources to cleanup: {cleanup_list}

The error handling should:
1. Check for the error condition
2. Clean up allocated resources in reverse order
3. Return 0 to indicate fuzzer should continue

Output ONLY the C code block (if statement with cleanup).
'''
        return ""

    def _cleanup_prompt(self, hole: Hole, context: Dict) -> str:
        """生成资源清理代码的prompt"""
        if isinstance(hole, ResourceCleanupHole):
            resources = ", ".join(hole.resources) if hole.resources else "none"
            order = ", ".join(hole.cleanup_order) if hole.cleanup_order else "reverse allocation order"
            return f'''Generate resource cleanup code for a fuzz driver.

Resources to clean: {resources}
Suggested order: {order}

Rules:
1. Free resources in reverse allocation order
2. Check for NULL before freeing
3. Use appropriate cleanup functions (free, close, destroy, etc.)

Output ONLY the C cleanup code statements.
'''
        return ""

    def _param_constraint_prompt(self, hole: Hole, context: Dict) -> str:
        """生成参数约束代码的prompt"""
        if isinstance(hole, ComplexHole):
            return f'''Generate parameter constraint validation for a fuzz driver.

Parameter: {hole.context.get('param_name', 'unknown')}
Type: {hole.context.get('param_type', 'unknown')}

Output a C expression that validates the parameter.
'''
        return ""

    def _parse_response(self, response: str, kind: HoleKind) -> str:
        """解析LLM响应"""
        # 清理响应
        response = response.strip()

        # 移除markdown代码块标记
        if response.startswith("```c"):
            response = response[4:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]

        return response.strip()


# =============================================================================
# 回调Stub模板库
# =============================================================================

class CallbackStubLibrary:
    """预定义的回调stub模板"""

    COMPARATOR = '''
int {name}(const void* a, const void* b) {{
    return memcmp(a, b, 1);
}}
'''

    HANDLER = '''
void {name}(void* user_data) {{
    (void)user_data;
}}
'''

    ERROR_HANDLER = '''
void {name}(int code, const char* msg, void* user_data) {{
    (void)code;
    (void)msg;
    (void)user_data;
}}
'''

    READER = '''
typedef struct {{
    const uint8_t* data;
    size_t size;
    size_t pos;
}} FuzzReaderCtx_{name};

size_t {name}(void* ptr, size_t size, void* stream) {{
    FuzzReaderCtx_{name}* ctx = (FuzzReaderCtx_{name}*)stream;
    size_t avail = ctx->size - ctx->pos;
    size_t to_read = (size < avail) ? size : avail;
    if (to_read > 0) {{
        memcpy(ptr, ctx->data + ctx->pos, to_read);
        ctx->pos += to_read;
    }}
    return to_read;
}}
'''

    WRITER = '''
size_t {name}(const void* ptr, size_t size, void* stream) {{
    (void)ptr;
    (void)stream;
    return size;
}}
'''

    ALLOCATOR = '''
void* {name}(size_t size) {{
    if (size > 1024 * 1024) return NULL;
    return malloc(size);
}}
'''

    DEALLOCATOR = '''
void {name}(void* ptr) {{
    free(ptr);
}}
'''

    VISITOR = '''
int {name}(void* item, void* user_data) {{
    (void)item;
    (void)user_data;
    return 0;
}}
'''

    @classmethod
    def get_stub(cls, callback_type: str, name: str) -> Optional[str]:
        """获取stub模板"""
        templates = {
            "comparator": cls.COMPARATOR,
            "handler": cls.HANDLER,
            "error_handler": cls.ERROR_HANDLER,
            "reader": cls.READER,
            "writer": cls.WRITER,
            "allocator": cls.ALLOCATOR,
            "deallocator": cls.DEALLOCATOR,
            "visitor": cls.VISITOR,
        }
        template = templates.get(callback_type.lower())
        if template:
            return template.format(name=name)
        return None


# =============================================================================
# 模板填充策略
# =============================================================================

class TemplateFillStrategy(FillStrategy):
    """基于模板库的填充策略"""

    def can_fill(self, hole: Hole) -> bool:
        if isinstance(hole, CallbackImplHole):
            return hole.callback_type.lower() in [
                "comparator", "handler", "error_handler",
                "reader", "writer", "allocator", "deallocator", "visitor"
            ]
        return False

    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        if isinstance(hole, CallbackImplHole):
            stub = CallbackStubLibrary.get_stub(
                hole.callback_type,
                f"fuzz_cb_{hole.name}"
            )
            if stub:
                return FillResult(
                    hole_name=hole.name,
                    success=True,
                    value=stub,
                    method="template",
                    reason=f"Used {hole.callback_type} template"
                )

        return FillResult(
            hole_name=hole.name,
            success=False,
            reason="No matching template"
        )


# =============================================================================
# 综合孔填充器
# =============================================================================

class HoleFiller:
    """
    综合孔填充器

    按优先级使用多种策略填充孔:
    1. 规则填充 (最快，确定性)
    2. 模板填充 (针对回调)
    3. 约束求解 (有约束时)
    4. LLM填充 (复杂语义)
    """

    def __init__(self, llm_client: Optional[LLMClient] = None, use_z3: bool = False):
        self.strategies: List[FillStrategy] = [
            RuleFillStrategy(),
            TemplateFillStrategy(),
            ConstraintFillStrategy(use_z3=use_z3),
        ]

        if llm_client:
            self.strategies.append(LLMFillStrategy(llm_client))

        self.llm_strategy: Optional[LLMFillStrategy] = None

    def set_llm_client(self, client: LLMClient) -> None:
        """设置LLM客户端"""
        # 查找或添加LLM策略
        for strategy in self.strategies:
            if isinstance(strategy, LLMFillStrategy):
                strategy.set_llm_client(client)
                self.llm_strategy = strategy
                return

        # 没有找到则添加
        llm_strategy = LLMFillStrategy(client)
        self.strategies.append(llm_strategy)
        self.llm_strategy = llm_strategy

    def fill_all(
        self,
        skeleton: DriverSkeleton,
        constraints: Optional[ConstraintSet] = None
    ) -> FillReport:
        """
        填充骨架中的所有孔

        Args:
            skeleton: Driver骨架
            constraints: 约束集（可选，会自动收集）

        Returns:
            FillReport: 填充报告
        """
        report = FillReport(total_holes=len(skeleton.holes))

        # 收集约束
        if constraints is None:
            collector = ConstraintCollector()
            constraints = collector.collect_from_skeleton(skeleton)

        # 预计算约束解
        for strategy in self.strategies:
            if isinstance(strategy, ConstraintFillStrategy):
                strategy.precompute(skeleton, constraints)

        # 构建填充上下文
        context = self._build_context(skeleton)

        # 按优先级排序孔
        holes = sorted(
            skeleton.holes.get_unfilled(),
            key=lambda h: h.priority.value
        )

        # 逐个填充
        for hole in holes:
            result = self._fill_hole(hole, context)
            report.add(result)

            if result.success:
                skeleton.holes.fill(
                    hole.name,
                    result.value,
                    reason=f"{result.method}: {result.reason}"
                )

        return report

    def _fill_hole(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        """尝试用各种策略填充孔"""
        for strategy in self.strategies:
            if strategy.can_fill(hole):
                result = strategy.fill(hole, context)
                if result.success:
                    return result

        return FillResult(
            hole_name=hole.name,
            success=False,
            reason="No strategy could fill this hole"
        )

    def _build_context(self, skeleton: DriverSkeleton) -> Dict[str, Any]:
        """构建填充上下文"""
        return {
            "driver_name": skeleton.name,
            "target_apis": [api.function_name for api in skeleton.target_apis],
            "variables": list(skeleton.variables.keys()),
            "metadata": skeleton.metadata,
        }


# =============================================================================
# 工具函数
# =============================================================================

def fill_skeleton_holes(
    skeleton: DriverSkeleton,
    llm_client: Optional[LLMClient] = None,
    use_z3: bool = False
) -> FillReport:
    """便捷函数：填充骨架中的孔"""
    filler = HoleFiller(llm_client=llm_client, use_z3=use_z3)
    return filler.fill_all(skeleton)


def apply_fill_report(skeleton: DriverSkeleton, report: FillReport) -> int:
    """将填充报告应用到骨架，返回成功数"""
    count = 0
    for result in report.results:
        if result.success:
            if skeleton.holes.fill(result.hole_name, result.value, result.reason):
                count += 1
    return count
