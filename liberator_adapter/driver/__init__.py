import sys, logging
logger = logging.getLogger("driver")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Driver                import Driver
from .Context               import Context

from . import ir
from . import factory


# for grammar specialization
# from .type.TypeDependencyGraphGenerator import TypeDependencyGraphGenerator