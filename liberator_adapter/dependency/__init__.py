import sys, logging
logger = logging.getLogger("liberator_adapter.dependency")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .DependencyGraphGenerator  import DependencyGraphGenerator
from .DependencyGraph  import DependencyGraph

from .type.TypeDependencyGraphGenerator import TypeDependencyGraphGenerator

