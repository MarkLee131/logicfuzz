"""
Synthesis Module — Skeleton-with-holes program synthesis.

A skeleton has structurally-correct parts (variable declarations,
producer→consumer wiring, API call sequence, paired cleanup) plus
``Hole`` placeholders that the LLM (Prototyper) refines.

Earlier this module also shipped a ``HoleFiller`` (rule / template /
constraint / LLM strategies) that pre-filled "simple" holes
deterministically. The infrastructure was never wired into the live
``CBFactory.create_skeleton_for_sequence`` path; an empirical study
across 70 OSS-Fuzz drivers showed:

  * 54% of hole positions are rule-fillable in principle, but
  * the prompt cost is dominated by the skeleton + context, not the
    response, so pre-filling saves ~3–5% of the API bill, and
  * LLM stochasticity on simple holes occasionally introduces
    coverage-useful tricks (zlib's ``data[0]``-as-size,
    cjson's ``prebuffer=1``).

We therefore deleted the HoleFiller entirely. The narrow exceptions
that ARE worth pre-filling deterministically — RESOURCE_CLEANUP and
LOOP_BOUND — are handled inline in ``SkeletonGenerator.generate``,
not as a separate strategy framework.
"""

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
    CallbackImplHole,
    LoopConditionHole,
    create_buffer_size_hole,
    create_callback_hole,
    create_loop_condition_hole,
)

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
    "CallbackImplHole",
    "LoopConditionHole",
    "create_buffer_size_hole",
    "create_callback_hole",
    "create_loop_condition_hole",
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
]
