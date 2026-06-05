import sys, logging
logger = logging.getLogger("liberator_adapter.constraints")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Conditions        import Conditions
from .ConditionManager import ConditionManager
from .RunningContext    import RunningContext, ConditionUnsat

# Note: the former ``sequence_filter`` module was removed during the L2/L3
# Typestate consolidation. The LLM-driven validator it provided was a parallel
# encoding of the resource-typestate concept now centralised in
# ``liberator_adapter/analysis/usedef.py`` (``Typestate.check``); the LLM
# oracle role is now an extension point of ``analysis/edsm.py``.

# L1: Entry Point Analyzer (Progressive Filter Pipeline)
from .entry_point_analyzer import (
    EntryPointAnalyzer,
    EntryPointAnalysis,
    EntryPointInfo,
    EntryPointType,
    EntryPointPattern,
    EntryPointFilterStrategy,
    analyze_entry_points,
    filter_sequences_by_entry_point,
)

# L2: Lifecycle Analyzer (Progressive Filter Pipeline)
from .lifecycle_analyzer import (
    LifecycleAnalyzer,
    LifecycleAnalysis,
    LifecyclePair,
    LifecycleRole,
    LifecycleValidationResult,
    DiscoveryMethod,
    analyze_lifecycle,
    filter_sequences_by_lifecycle,
)

# L3: State Machine Analyzer (Progressive Filter Pipeline)
from .state_machine_analyzer import (
    StateMachineAnalyzer,
    StateMachineAnalysis,
    StateMachineValidationResult,
    StateTransition,
    StateConstraint,
    StateViolation,
    ResourceState,
    APIRole,
    ViolationType,
    analyze_state_machine,
    filter_sequences_by_state_machine,
)

# L4: Coverage Ranker (Progressive Filter Pipeline)
from .coverage_ranker import (
    CoverageRanker,
    CoverageRankingResult,
    SequenceScore,
    select_top_k_sequences,
)

# L5 (CoverageAwareFilter) deleted in redesign G3 — novelty pre-filter
# replaced by reachability-first ranking in coverage_ranker.

# Special Pattern Analyzers
from .special_patterns import (
    # S1. Var-len variable-length parameter analysis
    VarLenAnalyzer,
    VarLenRelation,
    VarLenAnalysisResult,
    # S2. TLV format analysis
    TLVAnalyzer,
    TLVAnalysisResult,
    StructuredFormat,
    # S3. Loop pattern analysis
    LoopPatternAnalyzer,
    LoopPatternInfo,
    LoopType,
    # S4. Callback function analysis
    CallbackAnalyzer,
    CallbackInfo,
    CallbackAnalysisResult,
    CallbackType,
    # Unified analyzer
    SpecialPatternAnalyzer,
    APIPatternAnalysisResult,
)

# Z3 constraint solving (required)
from .z3_solver import (
    Z3SequenceValidator,
    is_z3_available,
    validate_api_sequence,
    ConstraintType,
)
from .z3_guided_synthesis import (
    Z3GuidedSynthesisController,
    is_z3_guided_available,
    create_guided_controller,
    DiagnosisType,
    RecoveryAction,
)
Z3_AVAILABLE = True  # Z3 is now required
