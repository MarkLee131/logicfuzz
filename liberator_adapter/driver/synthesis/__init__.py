"""
Synthesis Module - Hybrid Program Synthesis

Hybrid driver generation method based on traditional program synthesis + LLM.

Core components:
1. hole.py - Hole definitions (simple holes/complex holes)
2. skeleton_generator.py - Skeleton generator
3. constraint_collector.py - Constraint collection and solving
4. hole_filler.py - Hole filler (rules + templates + LLM)

Usage example:
```python
from liberator_adapter.driver.synthesis import (
    SkeletonGenerator, render_skeleton, HoleFiller
)

# Generate skeleton
generator = SkeletonGenerator()
skeleton = generator.generate(api_sequence)

# Fill holes
filler = HoleFiller()
report = filler.fill_all(skeleton)

# Render code
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
