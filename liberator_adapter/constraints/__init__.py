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

# Z3 constraint solving (optional)
# Provides stubs when Z3 is not installed
try:
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
    Z3_AVAILABLE = is_z3_available()
except (ImportError, RuntimeError) as e:
    logger.debug(f"Z3 not available: {e}")
    Z3_AVAILABLE = False
    is_z3_available = lambda: False  # noqa: E731
    is_z3_guided_available = lambda: False  # noqa: E731
    create_guided_controller = lambda *args, **kwargs: None  # noqa: E731
    validate_api_sequence = lambda *args, **kwargs: (True, [])  # noqa: E731
    Z3SequenceValidator = None
    Z3GuidedSynthesisController = None
    ConstraintType = None
    DiagnosisType = None
    RecoveryAction = None
