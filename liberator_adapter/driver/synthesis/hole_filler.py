"""
Hole Filler - Hole filler

Layered filling strategy:
1. Rule filling: Simple holes use predefined rules
2. Constraint solving: Holes with constraints use solvers
3. LLM filling: Complex holes use LLM semantic reasoning

Design principles:
- Prefer deterministic methods (rules, constraints)
- LLM as fallback for complex semantics
- Fill results are verifiable and explainable
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
from liberator_adapter.prompt_loader import get_prompt_manager
from src.llm.adapter import create_llm_adapter

logger = logging.getLogger(__name__)


# =============================================================================
# Fill Results
# =============================================================================

@dataclass
class FillResult:
    """Fill result"""
    hole_name: str
    success: bool
    value: Optional[Any] = None
    method: str = ""        # "rule", "constraint", "llm"
    reason: str = ""
    confidence: float = 1.0  # Confidence (meaningful for LLM filling)


@dataclass
class FillReport:
    """Fill report"""
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
# Fill Strategy Interface
# =============================================================================

class FillStrategy(ABC):
    """Fill strategy interface"""

    @abstractmethod
    def can_fill(self, hole: Hole) -> bool:
        """Check if this type of hole can be filled"""
        pass

    @abstractmethod
    def fill(self, hole: Hole, context: Dict[str, Any]) -> FillResult:
        """Fill hole"""
        pass


# =============================================================================
# Rule Fill Strategy
# =============================================================================

class RuleFillStrategy(FillStrategy):
    """Rule-based fill strategy"""

    def __init__(self):
        # Rule mapping: HoleKind -> fill function
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
        """Fill buffer size"""
        # Default to use fuzz input size
        return "size"

    def _fill_array_length(self, hole: Hole, context: Dict) -> int:
        """Fill array length"""
        if isinstance(hole, ArrayLengthHole):
            return min(256, hole.max_length)
        return 256

    def _fill_init_value(self, hole: Hole, context: Dict) -> str:
        """Fill initialization value"""
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
        """Fill loop bound"""
        if isinstance(hole, LoopBoundHole):
            return hole.suggested_bound
        return 100

    def _fill_null_check(self, hole: Hole, context: Dict) -> str:
        """Fill NULL check"""
        return "!= NULL"

    def _fill_type_cast(self, hole: Hole, context: Dict) -> str:
        """Fill type cast"""
        target_type = context.get("target_type", "void*")
        return f"({target_type})"


# =============================================================================
# Constraint Solving Strategy
# =============================================================================

class ConstraintFillStrategy(FillStrategy):
    """Constraint-solving based fill strategy"""

    def __init__(self, use_z3: bool = False):
        self.solver = ConstraintSolver(use_z3=use_z3)
        self._solutions: Dict[str, Any] = {}

    def precompute(self, skeleton: DriverSkeleton, constraints: ConstraintSet) -> None:
        """Precompute constraint solutions"""
        self._solutions = self.solver.solve(skeleton, constraints)

    def can_fill(self, hole: Hole) -> bool:
        # Constraint solving mainly handles SimpleHole
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
# LLM Fill Strategy
# =============================================================================

class LLMClient(ABC):
    """LLM client interface"""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Call LLM to complete prompt"""
        pass


class LLMFillStrategy(FillStrategy):
    """LLM-based fill strategy"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

        # Prompt templates
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
                confidence=0.8  # LLM fill confidence is slightly lower
            )
        except Exception as e:
            return FillResult(
                hole_name=hole.name,
                success=False,
                reason=f"LLM failed: {e}"
            )

    def _callback_prompt(self, hole: Hole, context: Dict) -> str:
        """Generate callback implementation prompt"""
        if isinstance(hole, CallbackImplHole):
            pm = get_prompt_manager()
            return pm.get_hole_callback_impl_prompt(
                callback_signature=hole.callback_signature,
                callback_type=hole.callback_type,
                expected_behavior=hole.expected_behavior or "Generic callback stub"
            )
        return ""

    def _loop_condition_prompt(self, hole: Hole, context: Dict) -> str:
        """Generate loop condition prompt"""
        if isinstance(hole, LoopConditionHole):
            pm = get_prompt_manager()
            return pm.get_hole_loop_condition_prompt(
                loop_type=hole.loop_type,
                api_return_type=hole.api_return_type,
                termination_hint=hole.termination_hint or "None"
            )
        return ""

    def _error_handling_prompt(self, hole: Hole, context: Dict) -> str:
        """Generate error handling code prompt"""
        if isinstance(hole, ErrorHandlingHole):
            cleanup_list = ", ".join(hole.cleanup_needed) if hole.cleanup_needed else "none"
            pm = get_prompt_manager()
            return pm.get_hole_error_handling_prompt(
                error_source=hole.error_source,
                error_type=hole.error_type,
                cleanup_list=cleanup_list
            )
        return ""

    def _cleanup_prompt(self, hole: Hole, context: Dict) -> str:
        """Generate resource cleanup code prompt"""
        if isinstance(hole, ResourceCleanupHole):
            resources = ", ".join(hole.resources) if hole.resources else "none"
            order = ", ".join(hole.cleanup_order) if hole.cleanup_order else "reverse allocation order"
            pm = get_prompt_manager()
            return pm.get_hole_resource_cleanup_prompt(
                resources=resources,
                cleanup_order=order
            )
        return ""

    def _param_constraint_prompt(self, hole: Hole, context: Dict) -> str:
        """Generate parameter constraint code prompt"""
        if isinstance(hole, ComplexHole):
            pm = get_prompt_manager()
            return pm.get_hole_param_constraint_prompt(
                param_name=hole.context.get('param_name', 'unknown'),
                param_type=hole.context.get('param_type', 'unknown')
            )
        return ""

    def _parse_response(self, response: str, kind: HoleKind) -> str:
        """Parse LLM response"""
        # Clean response
        response = response.strip()

        # Remove markdown code block markers
        if response.startswith("```c"):
            response = response[4:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]

        return response.strip()


# =============================================================================
# Callback Stub Template Library
# =============================================================================

class CallbackStubLibrary:
    """Predefined callback stub templates"""

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
        """Get stub template"""
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
# Template Fill Strategy
# =============================================================================

class TemplateFillStrategy(FillStrategy):
    """Template library-based fill strategy"""

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
# Comprehensive Hole Filler
# =============================================================================

class HoleFiller:
    """
    Comprehensive hole filler

    Uses multiple strategies to fill holes by priority:
    1. Rule filling (fastest, deterministic)
    2. Template filling (for callbacks)
    3. Constraint solving (when constraints exist)
    4. LLM filling (complex semantics)
    """

    def __init__(self, llm_client: Optional[LLMClient] = None, use_z3: bool = False):
        self.strategies: List[FillStrategy] = [
            RuleFillStrategy(),
            TemplateFillStrategy(),
            ConstraintFillStrategy(use_z3=use_z3),
        ]

        if llm_client:
            # Wrap the LLM model in an adapter to provide complete() method
            adapted_client = create_llm_adapter(llm_client)
            self.strategies.append(LLMFillStrategy(adapted_client))

        self.llm_strategy: Optional[LLMFillStrategy] = None

    def set_llm_client(self, client: LLMClient) -> None:
        """Set LLM client"""
        # Wrap the LLM model in an adapter to provide complete() method
        adapted_client = create_llm_adapter(client)
        # Find or add LLM strategy
        for strategy in self.strategies:
            if isinstance(strategy, LLMFillStrategy):
                strategy.set_llm_client(adapted_client)
                self.llm_strategy = strategy
                return

        # If not found, add it
        llm_strategy = LLMFillStrategy(adapted_client)
        self.strategies.append(llm_strategy)
        self.llm_strategy = llm_strategy

    def fill_all(
        self,
        skeleton: DriverSkeleton,
        constraints: Optional[ConstraintSet] = None
    ) -> FillReport:
        """
        Fill all holes in skeleton

        Args:
            skeleton: Driver skeleton
            constraints: Constraint set (optional, will be collected automatically)

        Returns:
            FillReport: Fill report
        """
        report = FillReport(total_holes=len(skeleton.holes))

        # Collect constraints
        if constraints is None:
            collector = ConstraintCollector()
            constraints = collector.collect_from_skeleton(skeleton)

        # Precompute constraint solutions
        for strategy in self.strategies:
            if isinstance(strategy, ConstraintFillStrategy):
                strategy.precompute(skeleton, constraints)

        # Build fill context
        context = self._build_context(skeleton)

        # Sort holes by priority
        holes = sorted(
            skeleton.holes.get_unfilled(),
            key=lambda h: h.priority.value
        )

        # Fill one by one
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
        """Try to fill hole using various strategies"""
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
        """Build fill context"""
        return {
            "driver_name": skeleton.name,
            "target_apis": [api.function_name for api in skeleton.target_apis],
            "variables": list(skeleton.variables.keys()),
            "metadata": skeleton.metadata,
        }


# =============================================================================
# Utility Functions
# =============================================================================

def fill_skeleton_holes(
    skeleton: DriverSkeleton,
    llm_client: Optional[LLMClient] = None,
    use_z3: bool = False
) -> FillReport:
    """Convenience function: fill holes in skeleton"""
    filler = HoleFiller(llm_client=llm_client, use_z3=use_z3)
    return filler.fill_all(skeleton)


def apply_fill_report(skeleton: DriverSkeleton, report: FillReport) -> int:
    """Apply fill report to skeleton, return success count"""
    count = 0
    for result in report.results:
        if result.success:
            if skeleton.holes.fill(result.hole_name, result.value, result.reason):
                count += 1
    return count
