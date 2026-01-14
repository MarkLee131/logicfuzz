import sys, logging
logger = logging.getLogger("liberator_adapter.constraints")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Conditions        import Conditions
from .ConditionManager import ConditionManager
from .RunningContext    import RunningContext, ConditionUnsat

# Z3 约束求解器（可选，如果 Z3 不可用则提供 stub）
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
except ImportError as e:
    logger.warning(f"Z3 solver not available: {e}")
    # 提供 stub
    is_z3_available = lambda: False
    validate_api_sequence = lambda *args, **kwargs: (True, [])
    should_prune_dependency = lambda *args, **kwargs: False
    Z3ConstraintBuilder = None
    Z3SequenceValidator = None
    Z3DependencyPruner = None
    ConstraintType = None
    Z3Constraint = None
