import sys, logging
logger = logging.getLogger("liberator_adapter.constraints")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Conditions        import Conditions
from .ConditionManager import ConditionManager
from .RunningContext    import RunningContext, ConditionUnsat

# Sequence Filter (LLM-based filtering)
from .sequence_filter import (
    SequenceFilter,           # Basic filter
    LLMLifecycleValidator,    # LLM lifecycle validator
    LLMSequenceFilter,        # LLM sequence filter (main usage)
    APILifecyclePhase,
    APILifecycleInfo,
    FilterResult,
    LifecycleValidationResult,
    LLMClient,                # LLM client protocol
)

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

# Z3 constraint solver (optional, provides stub if Z3 unavailable)
try:
    from .z3_solver import (
        Z3ConstraintBuilder,
        Z3SequenceValidator,
        Z3DependencyPruner,
        is_z3_available,
        validate_api_sequence,
        should_prune_dependency,
        ConstraintType,
        Z3Constraint
    )
except (ImportError, NameError, Exception) as e:
    logger.warning(f"Z3 solver not available: {e}")
    # Provide stub
    is_z3_available = lambda: False  # noqa: E731
    validate_api_sequence = lambda *args, **kwargs: (True, [])  # noqa: E731
    should_prune_dependency = lambda *args, **kwargs: False  # noqa: E731
    Z3ConstraintBuilder = None
    Z3SequenceValidator = None
    Z3DependencyPruner = None
    ConstraintType = None
    Z3Constraint = None
