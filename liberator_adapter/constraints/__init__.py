import sys, logging
logger = logging.getLogger("liberator_adapter.constraints")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Conditions        import Conditions
from .ConditionManager import ConditionManager
from .RunningContext    import RunningContext, ConditionUnsat
