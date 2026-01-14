"""
Synthesis Module - 混合程序合成

基于传统程序合成 + LLM的混合Driver生成方法。

核心组件:
1. hole.py - 孔定义（简单孔/复杂孔）
2. skeleton_generator.py - 骨架生成器
3. constraint_collector.py - 约束收集与求解
4. hole_filler.py - 孔填充器（规则+模板+LLM）

使用示例:
```python
from liberator_adapter.driver.synthesis import (
    SkeletonGenerator, render_skeleton, HoleFiller
)

# 生成骨架
generator = SkeletonGenerator()
skeleton = generator.generate(api_sequence)

# 填充孔
filler = HoleFiller()
report = filler.fill_all(skeleton)

# 渲染代码
code = render_skeleton(skeleton)
```
"""

# Hole definitions
from liberator_adapter.driver.synthesis.hole import (
    Hole,
    HoleKind,
    HolePriority,
    HoleSet,
    SimpleHole,
    ComplexHole,
    BufferSizeHole,
    ArrayLengthHole,
    InitValueHole,
    LoopBoundHole,
    CallbackImplHole,
    LoopConditionHole,
    ErrorHandlingHole,
    ResourceCleanupHole,
    create_buffer_size_hole,
    create_callback_hole,
    create_loop_condition_hole,
    create_error_handling_hole,
)

# Skeleton generation
from liberator_adapter.driver.synthesis.skeleton_generator import (
    DriverSkeleton,
    SkeletonVariable,
    SkeletonStatement,
    SkeletonGenerator,
    SkeletonRenderer,
    StatementKind,
    AllocationType,
    generate_skeleton_for_sequence,
    render_skeleton,
)

# Constraint collection and solving
from liberator_adapter.driver.synthesis.constraint_collector import (
    Constraint,
    ConstraintKind,
    ConstraintSet,
    TypeConstraint,
    VarLenConstraint,
    ValueRangeConstraint,
    NotNullConstraint,
    DependsOnConstraint,
    ConstraintCollector,
    ConstraintSolver,
    RuleBasedSolver,
    Z3SolverAdapter,
    collect_and_solve,
)

# Hole filling
from liberator_adapter.driver.synthesis.hole_filler import (
    FillResult,
    FillReport,
    FillStrategy,
    RuleFillStrategy,
    ConstraintFillStrategy,
    LLMFillStrategy,
    TemplateFillStrategy,
    CallbackStubLibrary,
    HoleFiller,
    LLMClient,
    fill_skeleton_holes,
    apply_fill_report,
)

__all__ = [
    # Holes
    "Hole",
    "HoleKind",
    "HolePriority",
    "HoleSet",
    "SimpleHole",
    "ComplexHole",
    "BufferSizeHole",
    "ArrayLengthHole",
    "InitValueHole",
    "LoopBoundHole",
    "CallbackImplHole",
    "LoopConditionHole",
    "ErrorHandlingHole",
    "ResourceCleanupHole",
    "create_buffer_size_hole",
    "create_callback_hole",
    "create_loop_condition_hole",
    "create_error_handling_hole",
    # Skeleton
    "DriverSkeleton",
    "SkeletonVariable",
    "SkeletonStatement",
    "SkeletonGenerator",
    "SkeletonRenderer",
    "StatementKind",
    "AllocationType",
    "generate_skeleton_for_sequence",
    "render_skeleton",
    # Constraints
    "Constraint",
    "ConstraintKind",
    "ConstraintSet",
    "TypeConstraint",
    "VarLenConstraint",
    "ValueRangeConstraint",
    "NotNullConstraint",
    "DependsOnConstraint",
    "ConstraintCollector",
    "ConstraintSolver",
    "RuleBasedSolver",
    "Z3SolverAdapter",
    "collect_and_solve",
    # Hole filling
    "FillResult",
    "FillReport",
    "FillStrategy",
    "RuleFillStrategy",
    "ConstraintFillStrategy",
    "LLMFillStrategy",
    "TemplateFillStrategy",
    "CallbackStubLibrary",
    "HoleFiller",
    "LLMClient",
    "fill_skeleton_holes",
    "apply_fill_report",
]
