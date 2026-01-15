"""
Hole - "Hole" definition in program synthesis

In hybrid synthesis methods, skeleton generators produce incomplete programs with "holes".
Holes are divided into two categories:
- SimpleHole: Can be filled by rules/constraint solvers
- ComplexHole: Requires LLM semantic reasoning to fill

Main purposes:
1. Represent uncertain parts in driver generation
2. Guide fill strategy selection
3. Support incremental driver construction
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod


# =============================================================================
# Hole Type Enumeration
# =============================================================================

class HoleKind(Enum):
    """Hole classification"""

    # === SimpleHole (solvable by rules/constraints) ===
    BUFFER_SIZE = auto()        # Buffer size: determined by var-len relationship
    ARRAY_LENGTH = auto()       # Array length: determined by size parameter
    NULL_CHECK = auto()         # NULL check condition: based on API return value semantics
    LOOP_BOUND = auto()         # Loop bound: safe upper limit
    TYPE_CAST = auto()          # Type cast: based on type compatibility
    INIT_VALUE = auto()         # Initialization value: 0, NULL, or default value

    # === ComplexHole (requires LLM) ===
    CALLBACK_IMPL = auto()      # Callback function implementation
    LOOP_CONDITION = auto()     # Loop termination condition
    ERROR_HANDLING = auto()     # Error handling logic
    RESOURCE_CLEANUP = auto()   # Resource cleanup order
    PARAM_CONSTRAINT = auto()   # Parameter constraint relationship
    API_SEQUENCE = auto()       # API call order selection


class HolePriority(Enum):
    """Fill priority"""
    CRITICAL = 1    # Must fill, otherwise compilation fails
    HIGH = 2        # Affects correctness
    MEDIUM = 3      # Affects coverage
    LOW = 4         # Optimization item


# =============================================================================
# Hole Base Class
# =============================================================================

@dataclass
class Hole(ABC):
    """Base class for holes"""

    kind: HoleKind
    name: str                       # Hole identifier (e.g., "size_0", "callback_1")
    priority: HolePriority = HolePriority.HIGH
    context: Dict[str, Any] = field(default_factory=dict)  # Context information
    filled_value: Optional[Any] = None  # Filled value
    fill_reason: str = ""           # Reason for fill decision

    @property
    def is_filled(self) -> bool:
        return self.filled_value is not None

    @property
    @abstractmethod
    def is_simple(self) -> bool:
        """Whether this is a simple hole (can be filled by rules)"""
        pass

    @abstractmethod
    def get_placeholder(self) -> str:
        """Get placeholder string (for skeleton code)"""
        pass

    @abstractmethod
    def validate_fill(self, value: Any) -> bool:
        """Validate if fill value is legal"""
        pass


# =============================================================================
# SimpleHole - Holes solvable by rules
# =============================================================================

@dataclass
class SimpleHole(Hole):
    """Simple hole - can be filled by rules or constraint solvers"""

    # Constraint information
    constraints: List[str] = field(default_factory=list)  # Constraint expressions
    valid_range: Optional[tuple] = None  # Valid value range (min, max)
    default_value: Optional[Any] = None  # Default value

    @property
    def is_simple(self) -> bool:
        return True

    def get_placeholder(self) -> str:
        return f"__HOLE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if self.valid_range:
            min_val, max_val = self.valid_range
            if not (min_val <= value <= max_val):
                return False
        return True


@dataclass
class BufferSizeHole(SimpleHole):
    """Buffer size hole"""

    kind: HoleKind = field(default=HoleKind.BUFFER_SIZE, init=False)
    buffer_arg_idx: int = -1        # Corresponding buffer argument index
    length_arg_idx: int = -1        # Corresponding length argument index
    relationship: str = "=="        # Relationship: "==", ">=", "size*count"

    def get_placeholder(self) -> str:
        return f"__BUFSIZE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if not isinstance(value, (int, str)):
            return False
        if isinstance(value, int) and value < 0:
            return False
        return True


@dataclass
class ArrayLengthHole(SimpleHole):
    """Array length hole"""

    kind: HoleKind = field(default=HoleKind.ARRAY_LENGTH, init=False)
    element_type: str = ""          # Element type
    max_length: int = 1024          # Maximum length limit

    def get_placeholder(self) -> str:
        return f"__ARRLEN_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        if not isinstance(value, int):
            return False
        return 0 < value <= self.max_length


@dataclass
class InitValueHole(SimpleHole):
    """Initialization value hole"""

    kind: HoleKind = field(default=HoleKind.INIT_VALUE, init=False)
    target_type: str = ""           # Target type
    is_pointer: bool = False        # Whether it's a pointer type

    def get_placeholder(self) -> str:
        return f"__INIT_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        # Pointer types accept NULL or address
        if self.is_pointer:
            return value in [None, "NULL", 0] or isinstance(value, str)
        return True


@dataclass
class LoopBoundHole(SimpleHole):
    """Loop bound hole"""

    kind: HoleKind = field(default=HoleKind.LOOP_BOUND, init=False)
    suggested_bound: int = 100      # Suggested bound value

    def get_placeholder(self) -> str:
        return f"__LOOPBOUND_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        return isinstance(value, int) and 0 < value <= 10000


# =============================================================================
# ComplexHole - Holes requiring LLM filling
# =============================================================================

@dataclass
class ComplexHole(Hole):
    """Complex hole - requires LLM semantic reasoning to fill"""

    # LLM auxiliary information
    api_context: Optional[str] = None       # Related API information
    code_context: Optional[str] = None      # Surrounding code context
    semantic_hints: List[str] = field(default_factory=list)  # Semantic hints

    @property
    def is_simple(self) -> bool:
        return False

    def get_placeholder(self) -> str:
        return f"__COMPLEX_HOLE_{self.name}__"

    def validate_fill(self, value: Any) -> bool:
        # Complex holes usually fill code strings
        return isinstance(value, str) and len(value) > 0


@dataclass
class CallbackImplHole(ComplexHole):
    """Callback function implementation hole"""

    kind: HoleKind = field(default=HoleKind.CALLBACK_IMPL, init=False)
    callback_signature: str = ""    # Callback function signature
    callback_type: str = ""         # Callback type (comparator, handler, reader, etc.)
    expected_behavior: str = ""     # Expected behavior description

    def get_placeholder(self) -> str:
        return f"__CALLBACK_{self.name}__"


@dataclass
class LoopConditionHole(ComplexHole):
    """Loop condition hole"""

    kind: HoleKind = field(default=HoleKind.LOOP_CONDITION, init=False)
    loop_type: str = ""             # Loop type: iterator, incremental, state_machine
    termination_hint: str = ""      # Termination condition hint
    api_return_type: str = ""       # Related API return type

    def get_placeholder(self) -> str:
        return f"__LOOPCOND_{self.name}__"


@dataclass
class ErrorHandlingHole(ComplexHole):
    """Error handling hole"""

    kind: HoleKind = field(default=HoleKind.ERROR_HANDLING, init=False)
    error_source: str = ""          # Error source (which API call)
    error_type: str = ""            # Error type (NULL, negative, exception)
    cleanup_needed: List[str] = field(default_factory=list)  # Resources that need cleanup

    def get_placeholder(self) -> str:
        return f"__ERRHANDLE_{self.name}__"


@dataclass
class ResourceCleanupHole(ComplexHole):
    """Resource cleanup hole"""

    kind: HoleKind = field(default=HoleKind.RESOURCE_CLEANUP, init=False)
    resources: List[str] = field(default_factory=list)  # Resources that need cleanup
    cleanup_order: List[str] = field(default_factory=list)  # Suggested cleanup order

    def get_placeholder(self) -> str:
        return f"__CLEANUP_{self.name}__"


@dataclass
class ParamConstraintHole(ComplexHole):
    """Parameter constraint hole"""

    kind: HoleKind = field(default=HoleKind.PARAM_CONSTRAINT, init=False)
    param_name: str = ""            # Parameter name
    param_type: str = ""            # Parameter type
    related_params: List[str] = field(default_factory=list)  # Related parameters

    def get_placeholder(self) -> str:
        return f"__PARAMCONST_{self.name}__"


# =============================================================================
# HoleSet - Hole Collection Management
# =============================================================================

@dataclass
class HoleSet:
    """Hole collection, used to manage all holes in a skeleton"""

    holes: Dict[str, Hole] = field(default_factory=dict)

    def add(self, hole: Hole) -> None:
        """Add hole"""
        self.holes[hole.name] = hole

    def get(self, name: str) -> Optional[Hole]:
        """Get hole"""
        return self.holes.get(name)

    def get_unfilled(self) -> List[Hole]:
        """Get unfilled holes"""
        return [h for h in self.holes.values() if not h.is_filled]

    def get_simple_holes(self) -> List[Hole]:
        """Get all simple holes"""
        return [h for h in self.holes.values() if h.is_simple]

    def get_complex_holes(self) -> List[Hole]:
        """Get all complex holes"""
        return [h for h in self.holes.values() if not h.is_simple]

    def get_by_kind(self, kind: HoleKind) -> List[Hole]:
        """Get holes by type"""
        return [h for h in self.holes.values() if h.kind == kind]

    def get_by_priority(self, priority: HolePriority) -> List[Hole]:
        """Get holes by priority"""
        return [h for h in self.holes.values() if h.priority == priority]

    def fill(self, name: str, value: Any, reason: str = "") -> bool:
        """Fill hole"""
        hole = self.holes.get(name)
        if hole is None:
            return False
        if not hole.validate_fill(value):
            return False
        hole.filled_value = value
        hole.fill_reason = reason
        return True

    def all_filled(self) -> bool:
        """Check if all holes are filled"""
        return all(h.is_filled for h in self.holes.values())

    def get_critical_unfilled(self) -> List[Hole]:
        """Get unfilled critical holes"""
        return [h for h in self.holes.values()
                if not h.is_filled and h.priority == HolePriority.CRITICAL]

    def __len__(self) -> int:
        return len(self.holes)

    def __iter__(self):
        return iter(self.holes.values())


# =============================================================================
# Utility Functions
# =============================================================================

def create_buffer_size_hole(name: str, buffer_idx: int, length_idx: int,
                            relationship: str = ">=") -> BufferSizeHole:
    """Create buffer size hole"""
    return BufferSizeHole(
        name=name,
        buffer_arg_idx=buffer_idx,
        length_arg_idx=length_idx,
        relationship=relationship,
        priority=HolePriority.CRITICAL
    )


def create_callback_hole(name: str, signature: str,
                         callback_type: str) -> CallbackImplHole:
    """Create callback implementation hole"""
    return CallbackImplHole(
        name=name,
        callback_signature=signature,
        callback_type=callback_type,
        priority=HolePriority.CRITICAL
    )


def create_loop_condition_hole(name: str, loop_type: str,
                               api_return_type: str) -> LoopConditionHole:
    """Create loop condition hole"""
    return LoopConditionHole(
        name=name,
        loop_type=loop_type,
        api_return_type=api_return_type,
        priority=HolePriority.HIGH
    )


def create_error_handling_hole(name: str, error_source: str,
                               cleanup_needed: List[str]) -> ErrorHandlingHole:
    """Create error handling hole"""
    return ErrorHandlingHole(
        name=name,
        error_source=error_source,
        cleanup_needed=cleanup_needed,
        priority=HolePriority.HIGH
    )


def classify_hole_for_param(param_type: str, param_name: str,
                            has_varlen_relation: bool,
                            is_callback: bool) -> HoleKind:
    """Determine what type of hole is needed based on parameter characteristics"""
    if is_callback:
        return HoleKind.CALLBACK_IMPL
    if has_varlen_relation:
        return HoleKind.BUFFER_SIZE
    if "size" in param_name.lower() or "len" in param_name.lower():
        return HoleKind.ARRAY_LENGTH
    if "*" in param_type:
        return HoleKind.INIT_VALUE
    return HoleKind.INIT_VALUE
