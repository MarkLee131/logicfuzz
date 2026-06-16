"""
Skeleton Generator

Generates driver skeletons using traditional program synthesis techniques.
A skeleton contains:
1. Deterministic parts: API call sequences, variable declarations, control flow structures
2. Holes: Uncertain parts that need to be filled later

Design principles:
- Skeleton covers the overall structure of the driver
- Holes represent parts requiring semantic reasoning
- Supports incremental filling and validation
"""

import logging
import os
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.analysis.constant_usage import legal_constants_for
from liberator_adapter.analysis import header_facts
from liberator_adapter.analysis.sequence_constructor import (
    _dependency_components, _scoped_guards,
)
from liberator_adapter.driver.synthesis.hole import (
    Hole, HoleSet, HolePriority,
    ArrayLengthHole, InitValueHole,
    create_buffer_size_hole, create_callback_hole, create_loop_condition_hole,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Type rendering rules — VALID C BY CONSTRUCTION
# =============================================================================
# The renderer must never emit code that fails to compile. Six classes of
# invalid-C were observed on real lcms skeletons; the helpers below own the
# type/decl decisions that prevent each one at the root (not by name-matching
# the offending API). See the unit tests in tests/test_p1_skeleton_valid_c.py.
#
#   1. ``void name[N]``  — a VOID array (illegal). A ``void``/``void*`` element
#      becomes a ``uint8_t`` byte buffer (passable wherever ``void*`` is).
#   2. opaque/incomplete struct used as a VALUE ARRAY (can't size an incomplete
#      type, e.g. ``cmsToneCurve name[N]``). Only *recognized scalar* element
#      types are rendered as value arrays; everything else stays a pointer.
#   3. struct-by-value initialized with ``0`` / NULL-compared. A non-pointer
#      non-scalar value type is zero-initialized with ``{0}``, never ``= 0``.
#   4. internal opaque struct names (``_cmsContext_struct *``) that aren't
#      visible through the public header → rendered as ``void *`` (the var is
#      only ever NULL-held / passed opaquely here).
#   5. internal (``*_internal.h`` / ``_private`` / ``_impl``) headers are never
#      emitted (``_generate_includes`` filters them).

# Scalar / numeric primitive bare names whose value arrays are guaranteed
# complete (sizeable). Anything outside this set is treated as a (possibly
# incomplete) aggregate and rendered through a pointer instead of a value array.
_SCALAR_VALUE_TYPES: Set[str] = {
    "char", "signed char", "unsigned char",
    "short", "unsigned short", "short int", "unsigned short int",
    "int", "unsigned int", "unsigned",
    "long", "unsigned long", "long int", "unsigned long int",
    "long long", "unsigned long long", "long long int",
    "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "float", "double", "long double",
    "bool", "_Bool", "wchar_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "intmax_t", "uintmax_t",
}

# Substrings that mark a type name as project-internal / forward-declared
# opaque (not visible through the public header). Such single-pointer types
# are rendered as ``void *`` so the driver compiles against the public API.
_INTERNAL_TYPE_MARKERS = ("_struct", "_impl", "_internal", "_private")

# Header basename substrings that are never public — must not be #included.
_INTERNAL_HEADER_MARKERS = (
    "_internal.", "_private.", "_impl.", "_detail.", "_p.h", "internal/")


def _strip_one_pointer(c_type: str) -> str:
    """Remove exactly ONE trailing ``*`` (and surrounding space). Used to get
    an array/element type — ``cmsToneCurve **`` → ``cmsToneCurve *`` (still a
    pointer, safe as an array element) rather than the all-stars-removed
    ``cmsToneCurve`` (an incomplete value type)."""
    t = c_type.rstrip()
    if t.endswith('*'):
        return t[:-1].rstrip()
    return t


def _bare_name(c_type: str) -> str:
    """Lowercase-comparable bare type name: drop qualifiers / struct-union-enum
    keywords / all pointer stars."""
    t = (c_type.replace('const', ' ')
               .replace('volatile', ' ')
               .replace('struct ', ' ')
               .replace('union ', ' ')
               .replace('enum ', ' ')
               .replace('*', ' '))
    return ' '.join(t.split()).strip()


def _is_scalar_value_type(c_type: str) -> bool:
    """True when a VALUE (non-pointer) declaration of ``c_type`` is a complete,
    sizeable scalar — safe to declare as a value array or zero-init with ``0``."""
    bare = _bare_name(c_type)
    return bool(bare) and bare in _SCALAR_VALUE_TYPES


def _is_aggregate_value_type(c_type: str) -> bool:
    """True when a NON-pointer ``c_type`` names a struct/union AGGREGATE that
    must be brace-zero-initialized (``{0}``) — a plain ``= 0`` is illegal for an
    aggregate (bug class 3). Enums / scalar typedefs are NOT aggregates: they
    must keep ``= 0`` (``{0}`` is rejected for a scoped enum under C++)."""
    if '*' in c_type:
        return False
    norm = ' ' + c_type.replace('*', ' ') + ' '
    return (' struct ' in norm) or (' union ' in norm) \
        or norm.lstrip().startswith('struct ') \
        or norm.lstrip().startswith('union ')


def _scalar_init_value(c_type: str, type_init_map: Dict[str, str]) -> str:
    """Choose a VALID zero-initializer for a non-pointer ``c_type``:
    ``{0}`` for a struct/union aggregate, else ``0`` (covers enums, scalar
    typedefs, and known primitives — all legal with ``= 0``)."""
    if _is_aggregate_value_type(c_type):
        return "{0}"
    base_type = c_type.replace('const', '').strip()
    return type_init_map.get(base_type, "0")


def _is_internal_opaque_type(c_type: str) -> bool:
    """True when the type name is a project-internal / forward-declared opaque
    type (e.g. ``_cmsContext_struct``) not visible through the public header."""
    bare = _bare_name(c_type)
    if not bare:
        return False
    # A leading-underscore identifier or a known internal marker substring.
    if bare.startswith('_'):
        return True
    return any(m in bare for m in _INTERNAL_TYPE_MARKERS)


def _public_pointer_type(c_type: str) -> str:
    """Render a single-pointer type for declaration, mapping internal opaque
    struct pointers to ``void *`` (the public typedef is unknown here and the
    var is only held opaquely / NULL-initialized)."""
    if c_type.count('*') == 1 and _is_internal_opaque_type(c_type):
        return "void *"
    return c_type


def _is_handle_collection_type(c_type: str) -> bool:
    """True for an array/double-pointer of a HANDLE type (``cmsToneCurve **`` /
    ``cmsToneCurve * const []`` → ``cmsToneCurve * const *``), the input-collection
    arg a CREATOR reads. Excludes single-pointer (out/handle) and non-handle bases
    (``char **``). Lever A (``LOGICFUZZ_POPULATE_COLLECTIONS``); caller gates."""
    from liberator_adapter.analysis.usedef import is_handle_type
    t = (c_type or "").replace("const", "").strip()
    # Function pointers (callbacks) are NOT handle collections — a ``(`` in the
    # type signals a function type; let the callback path own them.
    if "(" in t:
        return False
    if t.count("*") < 2:
        return False
    base = t.replace("*", "").strip()
    return is_handle_type(base)


# Scalar number typedefs that a builder reads as a fuzz-fillable data buffer
# (lcms convention: ``cmsUInt16Number`` = uint16, ``cmsFloat32Number`` = float).
# ``char`` is excluded (string-wrapped elsewhere); handles/structs are not scalars.
_SCALAR_BUF_RE = __import__("re").compile(
    r"^(cms)?(u?int(8|16|32|64)?number|float(32|64)?number|"
    r"u?int(8|16|32|64)?|float|double|short|long|unsigned\b.*)$",
    __import__("re").IGNORECASE)


def _fuzzable_scalar_buffer_base(c_type: str) -> Optional[str]:
    """If ``c_type`` is a SINGLE pointer to a fuzz-friendly scalar number type
    (``cmsUInt16Number *`` / ``const cmsFloat32Number *``), return the bare base
    type; else None. This is the caller-provided DATA buffer a builder reads —
    rendered as ``(T*)data`` (raw fuzz bytes) by Lever B, NOT NULL. Excludes
    handles (``cmsToneCurve *``), ``void *``, ``char *`` (string), and double
    pointers. Lever B (``LOGICFUZZ_FUZZ_BUFFERS``); caller gates."""
    t = (c_type or "").replace("const", "").strip()
    if t.count("*") != 1:
        return None
    base = t.replace("*", "").strip()
    if not base or "char" in base.lower():
        return None
    return base if _SCALAR_BUF_RE.match(base) else None


def _scalar_buffer_pairs(arg_types: List[str]) -> Dict[int, tuple]:
    """Map a builder's scalar-buffer arg index → ``(base_type, length_arg_idx)``.

    A scalar buffer (``cmsUInt16Number *``) is only safe to fuzz-fill when a
    preceding integer arg gives its element count (the ``func(.., n, T* buf)``
    convention) — bind that length to ``size/sizeof(T)`` so the callee never reads
    past ``data``. The nearest PRECEDING ``int``/``unsigned`` scalar is taken as the
    length; if none exists the buffer is skipped (no safe bound). Lever B."""
    out: Dict[int, tuple] = {}
    for i, t in enumerate(arg_types):
        base = _fuzzable_scalar_buffer_base(t)
        if base is None:
            continue
        len_idx = None
        for j in range(i - 1, -1, -1):
            tj = (arg_types[j] or "").lower()
            if "*" not in tj and ("int" in tj or "unsigned" in tj
                                  or "size" in tj or "number" in tj):
                len_idx = j
                break
        if len_idx is not None:
            out[i] = (base, len_idx)
    return out


def _complete_value_struct(c_type: str) -> Optional[str]:
    """When ``c_type`` is a SINGLE pointer to a complete, non-opaque public
    value struct (``cmsCIELab *``, ``cmsCIEXYZ *`` — a struct whose layout the
    IR knows), return its bare struct name so the renderer can stack-allocate it
    and pass its address. Else ``None``.

    A complete-struct pointer is structurally **not** an opaque handle (handles
    are ``void *`` or forward-declared/incomplete structs such as
    ``cmsToneCurve *``): the caller declares it on the stack, it has no producer.
    The renderer's own "complete" notion is scalar-only, so without this every
    such arg renders ``NULL`` in all branches (HANDLE_IN → NULL, OUTPUT →
    degraded NULL) and the API no-ops / crashes on a NULL struct pointer →
    edges=0 (the lcms color-math subsystem: cmsLab2LCh/cmsDeltaE/cmsD50_XYZ…).

    Gated on DataLayout's IR type table — library-agnostic, no per-library list.
    Returns ``None`` when the layout is unpopulated (no-model / unit path) so the
    caller keeps the prior NULL render; never raises.
    """
    if c_type.count('*') != 1:
        return None                      # T** out-pointers stay OUTPUT-handled
    bare = _bare_name(c_type)
    if not bare or bare == 'void':
        return None
    try:
        from liberator_adapter.common.datalayout import DataLayout
        dl = DataLayout.instance()
        if dl.is_a_struct(bare) and not dl.is_incomplete(bare) \
                and not dl.is_enum_type(bare):
            return bare
    except Exception:
        return None
    return None


def _is_caller_alloc_struct(c_type: str) -> Optional[str]:
    """Looser gate for the OUTPUT-branch fallthrough: a single pointer to a
    struct that DataLayout can SIZE (even if it is NOT recorded in
    ``clang_to_llvm_struct``) is a caller-alloc init struct
    (e.g. ``z_stream *`` when only ``dl.layout["z_stream"]`` is known).

    Returns the bare struct name when the test passes, else ``None``.

    Complements ``_complete_value_struct``, which requires ``is_a_struct``
    (strict — needs a ``clang_to_llvm_struct`` entry). This helper is the
    fallback when the strict gate misses a struct that is nonetheless sizeable.
    Skips void, scalars, and multi-level pointers — only a single-pointer
    aggregate can be caller-stack-allocated. Never raises.
    """
    if c_type.count('*') != 1:
        return None            # T** stays in the OUTPUT array-of-ptrs path
    bare = _bare_name(c_type)
    if not bare or bare == 'void':
        return None
    if _is_scalar_value_type(c_type):
        return None
    try:
        from liberator_adapter.common.datalayout import DataLayout  # lazy: avoid circular import
        dl = DataLayout.instance()
        # Sizeable AND complete: an incomplete/opaque type may carry a
        # pointer-width ``layout`` entry yet must NOT be stack-allocated — it is
        # a handle to be produced by a creator, not a caller-alloc value struct.
        # (``_complete_value_struct`` guards the same way via ``not is_incomplete``.)
        if dl.get_type_size(bare) and not dl.is_incomplete(bare):
            return bare
    except Exception:
        return None
    return None


def _fuzzable_holes_enabled() -> bool:
    """FIX C / FUZZABLE_HOLES gate (default-on; opt-out ``=0``)."""
    return os.environ.get("LOGICFUZZ_FUZZABLE_HOLES", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _is_tunable_scalar(c_type: str) -> bool:
    """True when a NON-pointer CONFIG arg is a tunable scalar/enum/signature
    (a value DOF the fuzzer should sweep: a format/intent/level/flag) — so the
    renderer emits a FUZZABLE value HOLE instead of a fixed ``= 0``.

    Catches plain scalars, IR-known enums, and integer typedefs
    (``cmsUInt32Number``, ``cmsColorSpaceSignature``). A by-value struct CONFIG
    is NOT a scalar (it is handled by the complete-value-struct path); pointers
    never reach here. DataLayout-gated where available, with a name-pattern
    fallback so the no-model/unit path still recognizes integer typedefs.
    """
    if '*' in c_type or '[' in c_type:
        return False
    bare = _bare_name(c_type)
    if not bare:
        return False
    if _is_scalar_value_type(c_type):
        return True
    try:
        from liberator_adapter.common.datalayout import DataLayout
        dl = DataLayout.instance()
        if dl.is_enum_type(bare):
            return True
        if bare in dl.clang_to_llvm_struct and not dl.is_a_struct(bare):
            return True   # typedef'd integer / signature (not an aggregate)
    except Exception:
        pass
    low = bare.lower()
    return any(t in low for t in (
        "int", "uint", "long", "short", "char", "size", "byte",
        "float", "double", "real", "signature", "flag", "bool", "enum"))


def _is_internal_header(header: str) -> bool:
    """True for a non-public (internal/private/impl) header basename."""
    h = header.lower()
    return any(m in h for m in _INTERNAL_HEADER_MARKERS)


# =============================================================================
# Signature-derived model for component partition (B+D, LOGICFUZZ_SCOPED_GUARDS)
# =============================================================================
# ``_dependency_components`` (in sequence_constructor) needs a ``.apis`` mapping
# name → object with ``produces`` / ``requires`` handle-type sets. The skeleton
# renderer only has ``Api`` objects, so we derive that mapping the SAME way the
# wiring layer does (``CBFactory._signature_handle_bindings``): a single-pointer
# RETURN produces that normalized handle type; a single-pointer ARG requires it.
# Pure signature inference, deterministic, no extra inputs.

@dataclass(frozen=True)
class _SigSem:
    produces: frozenset
    requires: frozenset


@dataclass(frozen=True)
class _SigModel:
    apis: Dict[str, _SigSem]


def _build_signature_model(api_sequence: List[Api]) -> _SigModel:
    from liberator_adapter.analysis.usedef import normalize_handle_type
    apis: Dict[str, _SigSem] = {}
    for api in api_sequence:
        produces: Set[str] = set()
        requires: Set[str] = set()
        ri = getattr(api, 'return_info', None)
        rt = getattr(ri, 'type', '') if ri else ''
        if rt and rt not in ('void', '') and rt.count('*') == 1:
            key = normalize_handle_type(rt)
            if key:
                produces.add(key)
        for arg in getattr(api, 'arguments_info', []) or []:
            t = getattr(arg, 'type', '') or ''
            if t.count('*') == 1:
                key = normalize_handle_type(t)
                if key:
                    requires.add(key)
        apis[api.function_name] = _SigSem(frozenset(produces), frozenset(requires))
    return _SigModel(apis)


# =============================================================================
# Producer→consumer wiring is owned by upstream Liberator, NOT this module
# =============================================================================
# Upstream solves cross-API dataflow via
# ``RunningContext.try_to_get_var`` (see
# ``framework/constraints/RunningContext.py:try_to_get_var`` on the
# ``reference/liberator`` branch and the adapter port at
# ``liberator_adapter/constraints/RunningContext.py``). It is category-aware
# (sink / init / setby / source) and runs ``is_compatible_with(cond)``
# semantic checks against a live var pool.
#
# SkeletonGenerator is a *renderer* — it receives a precomputed
# ``arg_bindings`` map from a caller that did the wiring (typically
# ``CBFactory._create_skeleton_from_sequence``). When a binding is
# present for ``(api_name, arg_idx)``, the consumer var's ``init_value``
# is set to the binding text directly (e.g. ``ret_cJSON_Parse``).
# When no binding exists, the variable falls back to NULL/0 — that
# fallback is a degraded path; the wiring layer is upstream's
# responsibility, not ours.


# =============================================================================
# Skeleton IR Definition
# =============================================================================

class StatementKind(Enum):
    """Statement types"""
    BUFFER_DECL = auto()        # Buffer declaration
    BUFFER_INIT = auto()        # Buffer initialization
    API_CALL = auto()           # API call
    ASSIGNMENT = auto()         # Assignment
    IF_CHECK = auto()           # Condition check
    LOOP_START = auto()         # Loop start
    LOOP_END = auto()           # Loop end
    CLEANUP = auto()            # Resource cleanup
    RETURN = auto()             # Return
    COMMENT = auto()            # Comment
    RAW_CODE = auto()           # Raw code


class AllocationType(Enum):
    """Memory allocation types"""
    STACK = auto()      # Stack allocation
    HEAP = auto()       # Heap allocation
    FUZZ_INPUT = auto() # From fuzzer input


@dataclass
class SkeletonVariable:
    """Skeleton variable"""
    name: str
    c_type: str
    allocation: AllocationType = AllocationType.STACK
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[str] = None  # May be a Hole placeholder
    init_value: Optional[str] = None  # May be a Hole placeholder
    source_api: Optional[str] = None  # API that produces this variable (if any)
    # Consumer-arg wiring: when set, the API call passes THIS expression (e.g.
    # ``ret_cmsOpenProfileFromMem``) directly as the argument. The variable's
    # decl-time init snapshots NULL (declarations precede the producer call), so
    # the snapshot must NOT be used as the live argument. 2026-06 review.
    bound_expr: Optional[str] = None
    # Lever A (LOGICFUZZ_POPULATE_COLLECTIONS): when set on an ``is_array`` var, the
    # renderer emits ``name[i] = expr;`` for each expr right before the consuming
    # call (call-time population — decl-time producer rets are NULL, same reason
    # ``bound_expr`` exists). Replaces the degenerate ``{0}`` for handle-collection
    # constructor args so the deep constructor runs.
    prepopulate: Optional[List[str]] = None
    # Lever B (LOGICFUZZ_FUZZ_BUFFERS): when set on a by-value struct var, the
    # renderer emits a size-guarded ``memcpy(&name, data, sizeof(T))`` before the
    # consuming call, so the struct carries fuzz bytes instead of the degenerate
    # ``{0}`` — seed-independent + non-degenerate (PromeFuzz's pattern for value
    # structs like cmsCIExyYTRIPLE primaries).
    fuzz_fill_struct: Optional[str] = None
    # Task 11 (LOGICFUZZ_VALIDITY_CONTRACT): the model marked this HANDLE_IN arg
    # ``nullable=False``. If it is still UNBOUND at render (no ``bound_expr`` → it
    # passes a NULL-initialized var), the renderer wraps the call in
    # ``if (handle) { ... }`` (defense-in-depth) instead of consuming a bare NULL.
    nonnull_handle: bool = False

    def get_declaration(self) -> str:
        """Generate declaration code"""
        if self.is_array and self.array_size:
            return f"{self.c_type} {self.name}[{self.array_size}]"
        elif self.init_value:
            return f"{self.c_type} {self.name} = {self.init_value}"
        else:
            return f"{self.c_type} {self.name}"


@dataclass
class SkeletonStatement:
    """Skeleton statement"""
    kind: StatementKind
    code: str = ""                              # Code string
    holes: List[str] = field(default_factory=list)  # Contained Hole names
    api: Optional[Api] = None                   # Associated API (if API call)
    variables: List[str] = field(default_factory=list)  # Involved variable names
    indent: int = 1                             # Indentation level

    def has_holes(self) -> bool:
        return len(self.holes) > 0


@dataclass
class DriverSkeleton:
    """Driver skeleton"""

    # Basic information
    name: str
    target_apis: List[Api]

    # Structure components
    includes: List[str] = field(default_factory=list)
    variables: Dict[str, SkeletonVariable] = field(default_factory=dict)
    statements: List[SkeletonStatement] = field(default_factory=list)
    cleanup_statements: List[SkeletonStatement] = field(default_factory=list)
    stub_functions: List[str] = field(default_factory=list)

    # Hole management
    holes: HoleSet = field(default_factory=HoleSet)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_variable(self, var: SkeletonVariable) -> None:
        """Add variable"""
        self.variables[var.name] = var

    def add_statement(self, stmt: SkeletonStatement) -> None:
        """Add statement"""
        self.statements.append(stmt)

    def add_cleanup(self, stmt: SkeletonStatement) -> None:
        """Add cleanup statement"""
        self.cleanup_statements.append(stmt)

    def add_hole(self, hole: Hole) -> None:
        """Add hole"""
        self.holes.add(hole)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize skeleton to dictionary for storage and JSON serialization.

        Returns:
            Dictionary containing:
            - name: Driver name
            - code: Rendered code with hole placeholders
            - holes: List of hole definitions
            - api_sequence: List of API names in order
            - metadata: Any additional metadata
        """
        # Render code with holes marked
        try:
            renderer = SkeletonRenderer()
            code = renderer.render_with_holes_marked(self)
        except Exception as _e:
            logger.warning('skeleton render failed (%s); emitting empty code', _e)
            code = ""

        # Serialize holes
        holes_list = []
        for hole in self.holes:
            hole_dict = {
                'name': hole.name,
                'hole_type': hole.kind.name if hasattr(hole.kind, 'name') else str(hole.kind),
                'placeholder': hole.get_placeholder(),
                'is_filled': hole.is_filled,
                'priority': hole.priority.name if hasattr(hole.priority, 'name') else str(hole.priority),
                'is_simple': hole.is_simple,
            }

            # Add type-specific fields
            if hasattr(hole, 'buffer_arg_idx'):
                hole_dict['buffer_arg_idx'] = hole.buffer_arg_idx
                hole_dict['length_arg_idx'] = hole.length_arg_idx
                hole_dict['relationship'] = hole.relationship
            if hasattr(hole, 'callback_signature'):
                hole_dict['callback_signature'] = hole.callback_signature
                hole_dict['callback_type'] = hole.callback_type
            if hasattr(hole, 'loop_type'):
                hole_dict['loop_type'] = hole.loop_type
            if hasattr(hole, 'target_type'):
                hole_dict['target_type'] = hole.target_type

            holes_list.append(hole_dict)

        # API sequence
        api_sequence = [api.function_name for api in self.target_apis] if self.target_apis else []

        return {
            'name': self.name,
            'code': code,
            'holes': holes_list,
            'api_sequence': api_sequence,
            'metadata': dict(self.metadata) if self.metadata else {},
            'includes': list(self.includes) if self.includes else [],
        }


# =============================================================================
# Tag round-trip exerciser (LOGICFUZZ_TAG_ROUNDTRIP, default-off)
# =============================================================================

def _tag_roundtrip() -> bool:
    """Gate (default-off): ``LOGICFUZZ_TAG_ROUNDTRIP`` appends a save->reopen->read
    block on a cmsHPROFILE-producing skeleton to exercise cmstypes.c — the tag-type
    (de)serializers, the single biggest untapped lcms block (95/2270 = 4%). The
    WRITE handlers (Type_X_Write) fire only on cmsSaveProfileToMem of a tag-rich
    profile; the READ handlers (Type_X_Read) only on cmsReadTag of a SAVED+REOPENED
    profile (an in-memory profile returns the live object without deserializing).
    No generated driver did this round-trip (measured)."""
    return os.environ.get("LOGICFUZZ_TAG_ROUNDTRIP", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _validity_contract_enabled() -> bool:
    """Gate (default-off): ``LOGICFUZZ_VALIDITY_CONTRACT``. When on, the renderer
    consumes the model's evidence-based ``nullable`` and wraps an UNBOUND
    ``nullable=False`` handle consume in ``if (handle) { ... }`` (Task 11
    defense-in-depth) instead of passing a bare NULL."""
    return os.environ.get("LOGICFUZZ_VALIDITY_CONTRACT", "0").strip().lower() in (
        "1", "true", "yes", "on")


def _is_profile_producer(source_api: str) -> bool:
    """True for an API that returns a cmsHPROFILE (profile or device-link)."""
    sa = source_api or ""
    return (sa.startswith("cmsCreate") or sa.startswith("cmsOpen")) and (
        "Profile" in sa or "DeviceLink" in sa)


# Fully-guarded, self-contained C block. {prof} = the live profile-handle var.
# Exercises: cmsSaveProfileToMem (write handlers) -> cmsOpenProfileFromMem (parse)
# -> cmsReadTag x14 distinct tag types (read handlers). Memory-safe: bounded
# malloc, every return checked, no fuzz-controlled sizes.
_TAG_ROUNDTRIP_TEMPLATE = """\
/* TAG_ROUNDTRIP: exercise cmstypes (de)serializers via save->reopen->read */
if (({prof}) != NULL) {{
    cmsUInt32Number _rt_n = 0;
    if (cmsSaveProfileToMem(({prof}), NULL, &_rt_n) && _rt_n > 0 && _rt_n < (1u << 22)) {{
        void *_rt_buf = malloc(_rt_n);
        if (_rt_buf != NULL) {{
            if (cmsSaveProfileToMem(({prof}), _rt_buf, &_rt_n)) {{
                cmsHPROFILE _rt_h2 = cmsOpenProfileFromMem(_rt_buf, _rt_n);
                if (_rt_h2 != NULL) {{
                    static const cmsTagSignature _rt_tags[] = {{
                        cmsSigRedTRCTag, cmsSigGreenTRCTag, cmsSigBlueTRCTag,
                        cmsSigRedColorantTag, cmsSigGreenColorantTag, cmsSigBlueColorantTag,
                        cmsSigMediaWhitePointTag, cmsSigProfileDescriptionTag,
                        cmsSigCopyrightTag, cmsSigChromaticAdaptationTag,
                        cmsSigAToB0Tag, cmsSigBToA0Tag, cmsSigGamutTag, cmsSigCharTargetTag }};
                    unsigned _rt_i;
                    for (_rt_i = 0; _rt_i < sizeof(_rt_tags) / sizeof(_rt_tags[0]); _rt_i++)
                        (void) cmsReadTag(_rt_h2, _rt_tags[_rt_i]);
                    cmsCloseProfile(_rt_h2);
                }}
            }}
            free(_rt_buf);
        }}
    }}
}}"""


# =============================================================================
# Skeleton Generator
# =============================================================================

class SkeletonGenerator:
    """
    Skeleton generator

    Generates driver skeleton from API sequence, including:
    1. Variable declarations (with Hole placeholders)
    2. API call sequences
    3. Error checks (with Hole placeholders)
    4. Resource cleanup

    Design principles:
    - Deterministic structure: API call order, variable binding
    - Holes: parameter values, callback implementations, loop conditions
    """

    def __init__(self):
        self._hole_counter = 0

        # Type to initialization value mapping
        self.type_init_map = {
            "int": "0",
            "unsigned int": "0",
            "size_t": "0",
            "long": "0",
            "unsigned long": "0",
            "float": "0.0f",
            "double": "0.0",
            "char": "'\\0'",
            "bool": "false",
            "_Bool": "0",
        }

    def generate(self, api_sequence: List[Api],
                 varlen_relations: Optional[Dict[str, List[Tuple[int, int, str]]]] = None,
                 loop_patterns: Optional[Dict[str, Dict]] = None,
                 callback_infos: Optional[Dict[str, List[Dict]]] = None,
                 driver_name: str = "fuzz_driver",
                 is_cpp: bool = True,
                 arg_bindings: Optional[Dict[Tuple[str, int], str]] = None,
                 dep_model=None,
                 ) -> DriverSkeleton:
        """
        Generate driver skeleton.

        Args:
            api_sequence: API call sequence
            varlen_relations: API var-len relationships {api_name: [(buf_idx, len_idx, rel), ...]}
            loop_patterns: API loop patterns {api_name: {needs_loop, loop_type, ...}}
            callback_infos: API callback information {api_name: [{arg_idx, type, ...}, ...]}
            driver_name: Generated driver name
            is_cpp: If True, generate C++ skeleton with FuzzedDataProvider
            arg_bindings: Optional pre-computed wiring map.
                Key = (api_name, arg_idx), value = the variable / expression
                text the consumer arg should reference (e.g. ``ret_cJSON_Parse``).
                Computed UPSTREAM (typically by ``CBFactory`` driving
                ``RunningContext.try_to_get_var`` over the sequence) — this
                renderer just consumes the decision. When a binding is present,
                the corresponding consumer var's ``init_value`` is set to the
                binding text, replacing the default NULL/0. When absent, the
                arg falls back to NULL/0 (a degraded path).

        Returns:
            DriverSkeleton: Skeleton with holes
        """
        self._hole_counter = 0

        skeleton = DriverSkeleton(
            name=driver_name,
            target_apis=api_sequence
        )

        # 1. Generate includes (with FuzzedDataProvider for C++)
        skeleton.includes = self._generate_includes(api_sequence, is_cpp=is_cpp)

        # 2. Analyze variable requirements (role-aware when dep_model present)
        var_requirements = self._analyze_variable_requirements(
            api_sequence, varlen_relations or {}, dep_model
        )

        # 3. Generate variable declarations
        self._generate_variable_declarations(skeleton, var_requirements)

        # 3.5. C_STRING entry-point wrapper: stateless parsers (cjson,
        # libxml2-style) take const char* but no companion size. The default
        # `(void*)data` cast would feed them a non-null-terminated buffer,
        # which causes UB. Detect this and inject a malloc/copy/null-term
        # prologue that rebinds the entry param to a proper C string.
        self._maybe_inject_c_string_wrapper(skeleton, api_sequence)

        # 3.6. Apply caller-supplied wiring decisions. The producer→consumer
        # dataflow logic lives upstream (RunningContext.try_to_get_var); we
        # just consume the result here.
        if arg_bindings:
            applied = self._apply_arg_bindings(skeleton, var_requirements,
                                               api_sequence, arg_bindings)
            if applied:
                skeleton.metadata['wired_args'] = applied

        # 4. Generate API call sequence. Under LOGICFUZZ_SCOPED_GUARDS (B),
        # group calls into dependency components and emit component-scoped
        # NULL guards (a producer's failure only skips ITS dependents, not the
        # whole driver) so an INDEPENDENT param-rich producer runs regardless of
        # a sibling parser's failure. Gate-OFF keeps the legacy whole-driver
        # ``return 0`` guard (byte-identical).
        if _scoped_guards():
            self._generate_api_calls_scoped(
                skeleton, api_sequence,
                varlen_relations or {},
                loop_patterns or {},
                callback_infos or {},
                dep_model=dep_model,
            )
        else:
            self._generate_api_calls(
                skeleton, api_sequence,
                varlen_relations or {},
                loop_patterns or {},
                callback_infos or {}
            )

        # 4b. Tag round-trip exerciser (LOGICFUZZ_TAG_ROUNDTRIP) — before cleanup
        # so the profile handle is still live.
        self._append_tag_roundtrip(skeleton)

        # 5. Generate cleanup code
        self._generate_cleanup(skeleton, dep_model)

        return skeleton

    def _apply_arg_bindings(
        self,
        skeleton: DriverSkeleton,
        var_requirements: Dict[str, Dict],
        api_sequence: List[Api],
        arg_bindings: Dict[Tuple[str, int], str],
    ) -> int:
        """Override consumer-arg ``init_value`` per the wiring map.

        The map is computed upstream (e.g. CBFactory translating
        ``call.arg_vars`` from ``try_to_instantiate_api_call``). Each
        binding ``(api_name, arg_idx) -> text`` rebinds the corresponding
        skeleton variable's init from the default (NULL / 0 / hole
        placeholder) to ``text``.

        Skips rebinding for FUZZ_INPUT-allocated vars (entry-point fuzz
        stream must keep its raw ``(void*)data`` cast) and for vars
        already pointing at a Hole placeholder (callback impl etc. must
        stay an LLM responsibility).

        Returns the count of args actually rebound (for telemetry).
        """
        applied = 0
        for api in api_sequence:
            api_name = api.function_name
            req = var_requirements.get(api_name)
            if req is None:
                continue
            for arg_info in req.get('args', []):
                idx = arg_info.get('idx', 0)
                key = (api_name, idx)
                if key not in arg_bindings:
                    continue
                wired_text = arg_bindings[key]
                if not wired_text:
                    continue

                var_basename = (arg_info.get('name')
                                or f"arg{idx}")
                var_name = f"{var_basename}_{api_name}"
                var = skeleton.variables.get(var_name)
                if var is None:
                    continue
                if var.allocation == AllocationType.FUZZ_INPUT:
                    continue
                if var.init_value and var.init_value.startswith('__'):
                    continue

                # Wire as a call-site expression, NOT the decl init: setting
                # ``init_value`` rendered ``Type consumer = ret_producer;`` in the
                # DECLARATION block, which runs BEFORE the producer call → the
                # consumer captured NULL (every "wired" arg was NULL at call
                # time). ``bound_expr`` is consumed directly in the API-call arg
                # list (`_generate_single_api_call`) so the LIVE producer return
                # is passed. 2026-06 review.
                var.bound_expr = wired_text
                # NOTE: do NOT set ``var.source_api = wired_text`` here.
                # ``source_api`` drives _generate_cleanup's destroyer pairing
                # and must be a PRODUCING API NAME, not a wired variable name
                # (``ret_cmsOpenProfileFromMem``); the latter made cleanup emit
                # undeclared calls like ``ret_cmsClose(...)`` (bug class 2).
                # Producer-return handles are tagged in
                # _generate_variable_declarations instead. This var is a
                # CONSUMER arg — it owns no resource and needs no cleanup.
                applied += 1
        return applied

    def _maybe_inject_c_string_wrapper(
        self,
        skeleton: DriverSkeleton,
        api_sequence: List[Api],
    ) -> None:
        """If the entry API takes a null-terminated `const char*` (no size
        companion), emit a fuzzer-input → null-terminated-buffer wrapper.

        Implementation: stack-allocated 64KB buffer (no malloc → no leak
        across early-return-on-NULL paths emitted by the API call gen).
        The entry parameter's binding is set via an assignment statement
        AFTER the buffer is filled, avoiding C decl-order use-before-init.
        """
        if not api_sequence:
            return
        entry = api_sequence[0]
        if not entry.arguments_info:
            return

        # Find first pointer-input arg on the entry API.
        target_idx = -1
        target_arg = None
        for idx, arg in enumerate(entry.arguments_info):
            if '*' in arg.type and self._is_input_param(arg):
                target_idx = idx
                target_arg = arg
                break
        if target_arg is None:
            return

        # Only kick in for `const char*` / `char *` (the C_STRING shape).
        # Buffer-with-size APIs already work via varlen_target → (void*)data.
        ttype = target_arg.type.replace(' ', '')
        if 'char*' not in ttype:
            return
        # Skip if there's a paired length arg — that's C_BUFFER_WITH_SIZE,
        # not C_STRING. Check varlen_target was set on the requirements pass:
        var_name = f"{target_arg.name or f'arg{target_idx}'}_{entry.function_name}"
        existing = skeleton.variables.get(var_name)
        if existing and existing.allocation == AllocationType.FUZZ_INPUT:
            # Var-len pair already wired — leave it alone.
            return

        # Stack buffer: 64KB cap is well within libfuzzer's 8MB stack and
        # avoids the malloc/free leak risk under early-return paths the
        # downstream call generator emits on NULL returns.
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.BUFFER_DECL,
            code="char __lf_str_buf[65536];",
            indent=1,
        ))
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.BUFFER_INIT,
            code=("size_t __lf_n = size < (sizeof(__lf_str_buf) - 1) "
                  "? size : (sizeof(__lf_str_buf) - 1);"),
            indent=1,
        ))
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.BUFFER_INIT,
            code="memcpy(__lf_str_buf, data, __lf_n);",
            indent=1,
        ))
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.BUFFER_INIT,
            code="__lf_str_buf[__lf_n] = '\\0';",
            indent=1,
        ))

        # Rebind the entry param to the buffer via assignment. Make sure
        # the param's variable exists and stays initialised to NULL at
        # decl-time (otherwise we'd reference __lf_str_buf before it's
        # declared in C).
        c_type = target_arg.type
        if existing is None:
            skeleton.add_variable(SkeletonVariable(
                name=var_name,
                c_type=c_type,
                is_pointer=True,
                init_value="NULL",
            ))
        else:
            existing.init_value = "NULL"
            existing.allocation = AllocationType.STACK
            existing.is_pointer = True

        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.ASSIGNMENT,
            code=f"{var_name} = __lf_str_buf;",
            indent=1,
        ))

    def _generate_includes(self, apis: List[Api], is_cpp: bool = True) -> List[str]:
        """Generate include list

        Args:
            apis: List of APIs (for future header detection)
            is_cpp: If True, include C++ headers like FuzzedDataProvider
        """
        includes = [
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
        ]

        # NOTE: we deliberately do NOT emit ``#include <fuzzer/FuzzedDataProvider.h>``.
        # The deterministic renderer never produces any FuzzedDataProvider usage
        # (the body is plain C: ``(void)data; if (size < 1) return 0; ...``), so the
        # include was always DEAD. It is also C++-only (its header pulls in
        # <algorithm>): in a C project an unfilled skeleton that reaches the merged
        # build carries it into a ``.c`` file → compiled with $CC → "fatal error:
        # 'algorithm' file not found" → the whole merged build dies (observed on
        # lcms driver 06). LLM-filled drivers get it stripped by the prototyper
        # C-fixer, so only bare skeletons detonated. Invariant: includes must match
        # actual usage — if a future renderer emits FDP usage, add the header next
        # to that emission, gated on real use (and on the project being C++).

        # Defense-in-depth (bug class 5): the renderer must only ever emit
        # PUBLIC headers. The deterministic body emits no project header here,
        # but if any internal/private/impl header is ever routed in, drop it —
        # pulling ``*_internal.h`` into the driver fails the build (the header
        # isn't on the public include path / declares non-exported symbols).
        includes = [
            inc for inc in includes
            if not _is_internal_header(inc)
        ]

        return includes

    def _analyze_variable_requirements(
        self,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]],
        dep_model=None,
    ) -> Dict[str, Dict]:
        """
        Analyze variable requirements

        Returns:
            {api_name: {
                'args': [{name, type, is_input, is_output, role, pairs_with,
                          varlen_idx}, ...],
                'return': {type, name}
            }}

        When ``dep_model`` (the reconciled ``APISemanticModel``) is threaded in,
        each arg also carries its reconciled ``role`` (INPUT_BUFFER / LENGTH /
        HANDLE_IN / CONFIG / OUTPUT) + ``pairs_with`` so the renderer can route
        by SEMANTIC ROLE instead of re-guessing from the C type — otherwise a
        real INPUT_BUFFER renders NULL (driver bails every input) and a HANDLE
        renders ``(void*)data`` (garbage handle). ``role`` is None when no model
        is supplied (legacy heuristic path, byte-identical).
        """
        requirements = {}
        _model_apis = getattr(dep_model, 'apis', None) or {}

        for api in apis:
            api_req = {
                'args': [],
                'return': None
            }

            # Get var-len relationships for this API
            api_varlen = varlen_relations.get(api.function_name, [])
            varlen_map = {buf_idx: (len_idx, rel) for buf_idx, len_idx, rel in api_varlen}

            # Reconciled per-arg roles for this API (by arg index), if a model
            # was threaded in.
            _sem = _model_apis.get(api.function_name)
            _arg_sem = {getattr(a, 'index', i): a
                        for i, a in enumerate(getattr(_sem, 'args', ()) or ())} \
                if _sem is not None else {}

            # Lever B (LOGICFUZZ_EXERCISE_DEEP_BUFFER): mark the deep consumer's
            # INPUT data buffer (the first bare ``void*`` CONFIG arg of a
            # _has_deep_input_buffer-matching consumer) so the renderer feeds it
            # fuzz bytes instead of NULL. Gated + guarded; inert when the sub-gate
            # is off (idx == -1 → no arg flagged → byte-identical render).
            _deep_in_idx = -1
            try:
                from liberator_adapter.analysis.sequence_constructor import (
                    _exercise_deep_buffer, _has_deep_input_buffer,
                    _is_bare_void_ptr)
                if (_sem is not None and _exercise_deep_buffer()
                        and _has_deep_input_buffer(_sem)):
                    for _a in getattr(_sem, 'args', ()) or ():
                        if (getattr(getattr(_a, 'role', None), 'value', None)
                                == 'CONFIG'
                                and _is_bare_void_ptr(getattr(_a, 'type_str', ''))):
                            _deep_in_idx = getattr(_a, 'index', -1)
                            break
            except Exception:
                _deep_in_idx = -1

            # Lever B (LOGICFUZZ_FUZZ_BUFFERS): for a builder (CREATOR/MUTATOR),
            # map each scalar data-buffer arg → (base, length_idx) so the renderer
            # feeds it ``(T*)data`` and binds its length to ``size/sizeof(T)``
            # (memory-safe, seed-independent). Inert when off / no safe pair.
            _fuzz_buf: Dict[int, tuple] = {}
            _fuzz_len: Dict[int, str] = {}
            try:
                from liberator_adapter.analysis.sequence_constructor import (
                    _fuzz_buffers)
                _role_val = getattr(getattr(_sem, 'role', None), 'value', None)
                if _fuzz_buffers() and _role_val in ('CREATOR', 'MUTATOR'):
                    _types = [a.type for a in api.arguments_info]
                    for _bi, (_base, _li) in _scalar_buffer_pairs(_types).items():
                        _fuzz_buf[_bi] = _base
                        _fuzz_len[_li] = _base
            except Exception:
                _fuzz_buf, _fuzz_len = {}, {}

            # Analyze parameters
            for idx, arg in enumerate(api.arguments_info):
                _as = _arg_sem.get(idx)
                _role = None
                _pairs = None
                _nullable = True   # default: NULL is legal (no model signal)
                if _as is not None:
                    _r = getattr(_as, 'role', None)
                    _role = getattr(_r, 'value', _r) if _r is not None else None
                    _pairs = getattr(_as, 'pairs_with', None)
                    # Task 11: the model's evidence-based nullability — read it
                    # (was extracted on ArgSemantics but never consumed here) so
                    # the renderer can guard an unbound nullable=False handle.
                    _nullable = bool(getattr(_as, 'nullable', True))
                arg_info = {
                    'name': arg.name or f"arg{idx}",
                    'type': arg.type,
                    'idx': idx,
                    'api_name': api.function_name,           # FIX D: usage lookup
                    'is_input': self._is_input_param(arg),
                    'is_output': self._is_output_param(arg),
                    'is_callback': self._is_callback_param(arg),
                    'varlen_target': varlen_map.get(idx),  # (len_idx, rel) or None
                    'role': _role,                          # ArgRole value or None
                    'nullable': _nullable,                  # Task 11: render-guard
                    'pairs_with': _pairs,                   # LENGTH↔buffer idx or None
                    'deep_fuzz_buffer': (idx == _deep_in_idx),  # Lever B input void*
                    'fuzz_scalar_buffer': _fuzz_buf.get(idx),   # Lever B: (T*)data
                    'buffer_length_sizeof': _fuzz_len.get(idx),  # Lever B: size/sizeof
                }
                api_req['args'].append(arg_info)

            # Analyze return value
            if api.return_info and api.return_info.type not in ['void', '']:
                api_req['return'] = {
                    'type': api.return_info.type,
                    'name': f"ret_{api.function_name}"
                }

            requirements[api.function_name] = api_req

        return requirements

    def _is_input_param(self, arg: Arg) -> bool:
        """Determine if parameter is input"""
        # const pointer or value passing is usually input
        if arg.is_const and any(arg.is_const):
            return True
        if '*' not in arg.type:
            return True
        return False

    def _is_output_param(self, arg: Arg) -> bool:
        """Determine if parameter is output"""
        # Non-const pointer is usually output
        if '*' in arg.type and (not arg.is_const or not any(arg.is_const)):
            return True
        return False

    def _is_callback_param(self, arg: Arg) -> bool:
        """Determine if parameter is callback"""
        type_str = arg.type
        # Function pointer characteristics
        if '(*)' in type_str or '(*' in type_str:
            return True
        # Common callback typedefs
        callback_suffixes = ['_func', '_callback', '_handler', '_t']
        for suffix in callback_suffixes:
            if arg.name and suffix in arg.name.lower():
                return True
            if suffix in type_str.lower():
                return True
        return False

    def _generate_variable_declarations(
        self,
        skeleton: DriverSkeleton,
        var_requirements: Dict[str, Dict]
    ) -> None:
        """Generate variable declarations.

        Tracks the FIRST API in the sequence so ``_create_variable_for_param``
        can apply the entry-point safety net (B4 mitigation): a non-const
        non-char pointer arg on the entry API is rebound to the fuzz-input
        stream rather than a stack array (the wrong default that
        ``_is_input_param``'s overly-strict const check would have produced).
        """
        declared_vars: Set[str] = set()

        # Identify the entry API (first call in the sequence) for the B4
        # safety net. var_requirements is a dict (insertion-ordered in 3.7+)
        # but we iterate over the original sequence to be explicit.
        entry_api_name = (
            skeleton.target_apis[0].function_name
            if skeleton.target_apis else None
        )

        for api_name, req in var_requirements.items():
            is_entry_api = (api_name == entry_api_name)
            # Return value variable
            if req['return']:
                ret_name = req['return']['name']
                if ret_name not in declared_vars:
                    var = self._create_variable_for_type(
                        ret_name, req['return']['type']
                    )
                    # Tag a POINTER return with its PRODUCING API NAME so
                    # _generate_cleanup can pair a destroyer to the handle it
                    # actually declared. (Scalar/void returns are not heap
                    # handles and stay untagged → no spurious cleanup.) The
                    # producing api_name — never a wired variable name — is the
                    # only correct value here (bug class 2: a wired-text
                    # source_api produced calls like ``ret_cmsClose(...)``).
                    if var.is_pointer:
                        var.source_api = api_name
                    skeleton.add_variable(var)
                    declared_vars.add(ret_name)

            # Parameter variables
            for arg_info in req['args']:
                var_name = f"{arg_info['name']}_{api_name}"
                if var_name not in declared_vars:
                    var = self._create_variable_for_param(
                        var_name, arg_info, skeleton,
                        is_entry_api=is_entry_api,
                    )
                    if var:
                        skeleton.add_variable(var)
                        declared_vars.add(var_name)

    def _create_variable_for_type(self, name: str, c_type: str) -> SkeletonVariable:
        """Create variable for type (e.g. a ``ret_<api>`` return holder).

        Renders VALID C by construction:
          * an internal/forward-declared opaque struct pointer
            (``_cmsContext_struct *``) is emitted as ``void *`` — its name is
            not visible through the public header, and the var is only held
            opaquely / NULL-initialized here (bug class 6).
          * a non-pointer non-scalar VALUE type (a by-value struct/union) is
            zero-initialized with ``{0}`` rather than ``= 0`` (illegal for an
            aggregate) and is never NULL-compared (bug class 3).
        """
        is_pointer = '*' in c_type

        if is_pointer:
            render_type = _public_pointer_type(c_type)
            return SkeletonVariable(
                name=name,
                c_type=render_type,
                is_pointer=True,
                init_value="NULL",
            )

        # A struct/union value gets ``{0}`` (``= 0`` is illegal for an
        # aggregate); enums / scalar typedefs / primitives keep ``= 0``.
        init_value = _scalar_init_value(c_type, self.type_init_map)

        return SkeletonVariable(
            name=name,
            c_type=c_type,
            is_pointer=False,
            init_value=init_value,
        )

    def _create_variable_for_param(
        self,
        name: str,
        arg_info: Dict,
        skeleton: DriverSkeleton,
        is_entry_api: bool = False,
    ) -> Optional[SkeletonVariable]:
        """Render one parameter's variable — MODEL-DRIVEN (reconcile-then-construct:
        the APISemanticModel is the single source of truth for arg semantics).

        Structure:
          1. callback → callback hole.
          2. ROLE DISPATCH (authoritative when the model is threaded in): the
             arg's reconciled ArgRole decides the render —
               INPUT_BUFFER → ``(void*)data`` (+ paired-length size hole),
               LENGTH       → ``(type)size``,
               HANDLE_IN    → NULL (producer-wired later by _apply_arg_bindings),
               CONFIG ptr   → NULL,
               OUTPUT ptr   → a by-construction-safe backing buffer.
          3. C-TYPE HEURISTIC FALLBACK (no-model path only — role is None): the
             pre-model "guess input/output from the signature" branches, incl.
             the entry-API ``(void*)data`` B4 net (``is_entry_api``). Kept only
             for direct-generate callers that supply no model; the construct path
             always supplies one, so the model drives every constructed driver.
        """
        c_type = arg_info['type']
        is_pointer = '*' in c_type

        # Callback parameter - create Hole
        if arg_info['is_callback']:
            hole = create_callback_hole(
                name=f"callback_{self._next_hole_id()}",
                signature=c_type,
                callback_type="unknown"
            )
            skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name,
                c_type=c_type,
                init_value=hole.get_placeholder()
            )

        # ---- Lever B: scalar data buffer + its length (LOGICFUZZ_FUZZ_BUFFERS) --
        # A builder's scalar buffer arg (``cmsUInt16Number *``) otherwise renders a
        # single ``{0}`` and its length renders 0 → a 0-entry degenerate object.
        # Render the buffer as ``(T*)data`` (raw fuzz bytes) and bind the length to
        # ``size/sizeof(T)`` capped at 256 → memory-safe (reads within ``data``) and
        # SEED-INDEPENDENT (any bytes build a real object — PromeFuzz's pattern).
        _fb = arg_info.get("fuzz_scalar_buffer")
        if _fb:
            return SkeletonVariable(
                name=name, c_type=f"{_fb} *", is_pointer=True,
                allocation=AllocationType.FUZZ_INPUT,
                bound_expr=f"({_fb}*)data")
        _bl = arg_info.get("buffer_length_sizeof")
        if _bl:
            return SkeletonVariable(
                name=name, c_type=c_type,
                init_value=(f"(unsigned int)((size/sizeof({_bl})) < 256 ? "
                            f"(size/sizeof({_bl})) : 256)"))

        # ---- Lever A: handle-collection arg (LOGICFUZZ_POPULATE_COLLECTIONS) ----
        # A CREATOR's array-of-handles arg (``cmsToneCurve* const []``) otherwise
        # renders the degenerate ``{0}``/NULL → the deep constructor NULL-guards out
        # → 0 edges. When gated AND same-type producers exist in the skeleton,
        # declare a fixed-size array and populate it with their rets (reuse one K×
        # if only one exists — a valid non-NULL array still runs the constructor).
        # Measured +72% edges/driver vs PromeFuzz's build-and-chain pattern.
        try:
            from liberator_adapter.analysis.sequence_constructor import (
                _populate_collections)
            _pc_on = _populate_collections()
        except Exception:
            _pc_on = False
        if _pc_on and _is_handle_collection_type(c_type):
            base = c_type.replace("const", "").replace("*", "").strip()
            prods = [v.name for v in skeleton.variables.values()
                     if v.source_api and v.c_type.replace("*", "").strip() == base]
            if prods:
                K = 3
                fill = (prods * K)[:K]   # reuse one K× when only one producer exists
                return SkeletonVariable(
                    name=name, c_type=f"{base} *", is_array=True, array_size=str(K),
                    prepopulate=fill)

        ttype_norm = c_type.replace(' ', '')
        is_char_star = 'char*' in ttype_norm

        # ---- Complete value-struct pointer (type-structural, role-dominant) --
        # A single pointer to a complete public struct (cmsCIELab *, cmsCIEXYZ *)
        # is NOT an opaque handle: stack-allocate the struct and pass its address
        # so the API has real storage to read/write. Without this it renders NULL
        # in every role branch (the renderer's "complete" set is scalar-only) and
        # the color-math / introspect-struct subsystems no-op on NULL → edges=0.
        # Skipped for char* (string-wrapped elsewhere); a real upstream producer,
        # if any, still overrides via _apply_arg_bindings (bound_expr).
        if not is_char_star:
            _vstruct = _complete_value_struct(c_type)
            if _vstruct is not None:
                # DataLayout proved it's a struct → ``{0}`` is the only valid
                # zero-init (a typedef'd struct name carries no ``struct``
                # keyword, so _scalar_init_value would wrongly pick ``= 0``).
                # Lever B: when gated AND the arg is an INPUT (role CONFIG/UNKNOWN/
                # HANDLE_IN, NOT OUTPUT — the API writes OUTPUT), fill it from fuzz
                # bytes via a guarded memcpy so it's non-degenerate + seed-
                # independent (the cmsCIExyYTRIPLE primaries case) instead of {0}.
                _fill = None
                _r = arg_info.get('role')
                if _r != 'OUTPUT':
                    try:
                        from liberator_adapter.analysis.sequence_constructor import (
                            _fuzz_buffers)
                        if _fuzz_buffers():
                            _fill = _vstruct
                    except Exception:
                        _fill = None
                return SkeletonVariable(
                    name=name, c_type=_vstruct, is_pointer=False,
                    allocation=AllocationType.STACK, init_value="{0}",
                    bound_expr=f"&{name}", fuzz_fill_struct=_fill,
                )

        # ---- Role-first routing (the reconcile-model floor) ----------------
        # When the model is threaded in, route each arg by its SEMANTIC role
        # instead of re-guessing from the C type. The legacy heuristics below
        # still run when role is None (no model) so behaviour is byte-identical.
        # This fixes the role-blind floor that rendered NULL on a real
        # INPUT_BUFFER (driver bails every input → edges=0) and ``(void*)data``
        # on a HANDLE (garbage handle).
        role = arg_info.get('role')
        if role == 'INPUT_BUFFER' and is_pointer and not is_char_star:
            pw = arg_info.get('pairs_with')
            if isinstance(pw, int) and pw >= 0:
                hole = create_buffer_size_hole(
                    name=f"bufsize_{self._next_hole_id()}",
                    buffer_idx=arg_info['idx'], length_idx=pw,
                    relationship=">=")
                skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name, c_type=_public_pointer_type(c_type),
                allocation=AllocationType.FUZZ_INPUT, is_pointer=True,
                init_value="(void*)data")
        if role == 'LENGTH' and not is_pointer:
            # The fuzz buffer this length pairs with renders as ``(void*)data``
            # of length ``size`` → ``size`` is exactly the right length.
            return SkeletonVariable(
                name=name, c_type=c_type, is_pointer=False,
                init_value=f"({c_type})size")
        if role == 'HANDLE_IN' and is_pointer:
            # NEVER the fuzz buffer: the producer→consumer wiring is applied by
            # _apply_arg_bindings (a prior producer's ret_<x>); absent that, a
            # NULL-guarded pointer. Kills the ``(void*)data``-on-handle bug.
            # Task 11: when the model marks this handle nullable=False (gated),
            # flag it so a still-unbound NULL render is wrapped in if(handle){}.
            _nonnull = (not arg_info.get('nullable', True)
                        and _validity_contract_enabled())
            return SkeletonVariable(
                name=name, c_type=_public_pointer_type(c_type),
                is_pointer=True, init_value="NULL", nonnull_handle=_nonnull)
        if arg_info.get('deep_fuzz_buffer') and is_pointer:
            # Lever B (LOGICFUZZ_EXERCISE_DEEP_BUFFER): the deep consumer's INPUT
            # data buffer is a bare ``void*`` (the cmsDoTransform idiom). Feed it
            # fuzz bytes so the exercised object RUNS on data, not NULL. The flag
            # is set upstream ONLY when the sub-gate is on AND the API matched the
            # guarded _has_deep_input_buffer — so this branch is inert by default
            # (gate-off → flag never set → falls through to the NULL branch).
            return SkeletonVariable(
                name=name, c_type=_public_pointer_type(c_type),
                allocation=AllocationType.FUZZ_INPUT, is_pointer=True,
                init_value="(void*)data")
        if role == 'CONFIG' and is_pointer:
            # An optional/config pointer (e.g. cmsCreateContext's plugin /
            # userdata ``void*`` args) — NULL is the safe by-construction default
            # the API tolerates, NOT a garbage uninitialised byte-array (the
            # role-blind output-branch render) and NOT ``(void*)data``. The
            # LLM/binding can override via the value-intent. (A CONFIG SCALAR
            # falls through to the scalar-init path + its FUZZABLE_HOLES intent.)
            # Task 11 (validity contract): the model MIS-ROLES some required
            # handles as CONFIG (cmsWriteTag's cmsHPROFILE, cmsCloseProfile's).
            # A ``nullable=False`` CONFIG pointer is therefore a REQUIRED handle
            # (the nullable flag distinguishes it from a truly-optional void*
            # plugin which is nullable=True) — flag it so a still-unbound NULL
            # render is wrapped in if(handle){} (no SEGV). Gated; off ⇒ unchanged.
            _nonnull = (not arg_info.get('nullable', True)
                        and _validity_contract_enabled())
            return SkeletonVariable(
                name=name, c_type=_public_pointer_type(c_type),
                is_pointer=True, init_value="NULL", nonnull_handle=_nonnull)
        if role == 'CONFIG' and not is_pointer and _is_tunable_scalar(c_type):
            # L3a: header-fact literal fills (highest priority: INIT scalars
            # with a known compile-time constant from the project headers, e.g.
            # ZLIB_VERSION / (int)sizeof(z_stream) for deflateInit_).  Set via
            # header_facts.set_fact_map() by the extraction pipeline.
            _fact = header_facts.literal_for(
                arg_info.get('api_name', ''), arg_info.get('idx', -1))
            if _fact is not None:
                return SkeletonVariable(
                    name=name, c_type=c_type, is_pointer=False,
                    init_value=_fact)
            # FIX D: if the library's OWN call-sites pass a legal constant at this
            # (api, arg) — mined deterministically from usage — render the modal
            # one (TYPE_RGB_8 for cmsCreateTransform's format) so construction
            # SUCCEEDS by construction, no LLM guess, no invalid ``data % 256``.
            # This is the symbolic side supplying the legal value; floor-valid +
            # measurable. Falls through to the FIX C FUZZABLE hole when usage has
            # nothing for this arg.
            _consts = legal_constants_for(
                arg_info.get('api_name', ''), arg_info.get('idx', -1))
            if _consts:
                return SkeletonVariable(
                    name=name, c_type=c_type, is_pointer=False,
                    init_value=_consts[0])
        if (role == 'CONFIG' and not is_pointer
                and _fuzzable_holes_enabled() and _is_tunable_scalar(c_type)):
            # FIX C: a tunable CONFIG scalar/enum (format, intent, level) renders
            # as a FUZZABLE value HOLE, not a fixed ``= 0``. A hole-LESS skeleton
            # makes the LLM key its value rewrite by VARIABLE NAME → dropped by
            # the #1a merge whitelist → floor ``= 0`` (e.g. cmsCreateTransform
            # InputFormat=0 → cmsCreateTransform returns NULL → guard → the whole
            # object-construction chain is dead → edges=0). A ``__INIT_<var>__``
            # hole lets the LLM's valid-constant fill (TYPE_RGB_8) apply
            # PLACEHOLDER-keyed (survives #1a) so construction SUCCEEDS and the
            # consumer (cmsDoTransform(data,…)) runs input-dependently. The
            # hole_semantics FUZZ_DERIVE intent supplies the value domain; an
            # UNFILLED hole degrades to ``0`` in the merge (floor-safe, == prior
            # ``= 0``). Gated on FUZZABLE_HOLES (default-on); opt-out restores the
            # fixed-scalar floor. The hole is var-NAMED so the LLM maps the
            # per-arg intent (``arg1_cmsCreateTransform``) onto the placeholder.
            hole = InitValueHole(name=name, target_type=c_type,
                                 is_pointer=False, default_value=0)
            skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name, c_type=c_type, is_pointer=False,
                init_value=hole.get_placeholder())

        # B4 safety net: entry-API non-const pointer that ISN'T a char*
        # (char* is handled by `_maybe_inject_c_string_wrapper`) — force
        # the fuzz-input bridge so the caller doesn't get a stack array for a
        # buffer-input parameter the const-check missed. ONLY when role is
        # unknown (no model) — otherwise the role branches above own the call.
        if (role is None and is_entry_api and is_pointer and not is_char_star
                and not arg_info['is_input']):
            varlen = arg_info.get('varlen_target')
            if varlen:
                len_idx, rel = varlen
                hole = create_buffer_size_hole(
                    name=f"bufsize_{self._next_hole_id()}",
                    buffer_idx=arg_info['idx'],
                    length_idx=len_idx,
                    relationship=rel,
                )
                skeleton.add_hole(hole)
            return SkeletonVariable(
                name=name,
                c_type=_public_pointer_type(c_type),
                allocation=AllocationType.FUZZ_INPUT,
                is_pointer=True,
                init_value="(void*)data",
            )

        # ---- Legacy C-type heuristic FALLBACK (no-model path only) ---------
        # The model-driven role dispatch above is AUTHORITATIVE. The branches
        # below re-derive input/output from the C type — the render-layer remnant
        # of the pre-model "guess from the signature" approach. They run only
        # when role is None (the no-model direct-generate path), so the model is
        # the single source of truth whenever it is present (the construct path).
        # Input buffer parameter - may need to get from fuzz input
        if role is None and arg_info['is_input'] and is_pointer:
            # Check if there's var-len relationship
            if arg_info.get('varlen_target'):
                len_idx, rel = arg_info['varlen_target']
                hole = create_buffer_size_hole(
                    name=f"bufsize_{self._next_hole_id()}",
                    buffer_idx=arg_info['idx'],
                    length_idx=len_idx,
                    relationship=rel
                )
                skeleton.add_hole(hole)
                return SkeletonVariable(
                    name=name,
                    c_type=_public_pointer_type(c_type),
                    allocation=AllocationType.FUZZ_INPUT,
                    is_pointer=True,
                    init_value="(void*)data"  # Default to use fuzz data
                )

        # Output parameter - need a backing buffer for the API to write into.
        # The element type MUST be complete & sizeable, or the declaration is
        # illegal C. Pick the rendering by what's safe by construction:
        #   * void* / void element  → ``uint8_t name[N]`` byte buffer (a void
        #     array is illegal; uint8_t* converts to void* implicitly). [bug 1]
        #   * ``Type **`` (≥2 stars) → array of pointers ``Type *name[N]`` —
        #     the element (a pointer) is always complete; ``name`` decays to
        #     ``Type **`` matching the param. [bug 4: cmsToneCurve ** ]
        #   * recognized scalar element → value array ``Type name[N]``.
        #   * anything else (a possibly-incomplete aggregate / opaque struct
        #     value) → a single typed pointer ``Type *name = NULL`` (valid,
        #     passable, degraded — the binding/LLM layer fills the real value).
        # OUTPUT is MODEL-DRIVEN when the model is present (role=='OUTPUT'); the
        # is_output heuristic is the no-model fallback. Both need a backing buffer.
        if (role == 'OUTPUT'
                or (role is None and arg_info['is_output'])) and is_pointer:
            star_count = c_type.count('*')
            element = _strip_one_pointer(c_type)  # one level only
            element_bare = _bare_name(element)

            if star_count == 1 and element_bare == 'void':
                buf_element = 'uint8_t'
                value_array = True
            elif star_count >= 2:
                # Array of pointers: element is itself a pointer (complete).
                buf_element = element
                value_array = True
            elif _is_scalar_value_type(element):
                buf_element = element
                value_array = True
            else:
                # L3a: before degrading to a NULL typed pointer, check if
                # ``element`` is a caller-alloc struct (sizable by DataLayout
                # even when not yet in ``clang_to_llvm_struct``).  If so,
                # stack-allocate it and pass its address — identical to the
                # ``_complete_value_struct`` shape above but gated on the
                # LOOSER ``get_type_size`` check.  This recovers
                # ``deflateInit_(z_stream*)``-style init producers that the
                # strict ``is_a_struct`` gate missed.
                _ca = _is_caller_alloc_struct(c_type)
                if _ca is not None:
                    return SkeletonVariable(
                        name=name, c_type=_ca, is_pointer=False,
                        allocation=AllocationType.STACK, init_value="{0}",
                        bound_expr=f"&{name}",
                    )
                value_array = False

            if value_array:
                hole = ArrayLengthHole(
                    name=f"arrlen_{self._next_hole_id()}",
                    priority=HolePriority.HIGH,
                    element_type=buf_element,
                )
                skeleton.add_hole(hole)
                return SkeletonVariable(
                    name=name,
                    c_type=buf_element,
                    is_array=True,
                    array_size=hole.get_placeholder(),
                    allocation=AllocationType.STACK,
                )
            # Degrade an opaque/incomplete out-param to a single typed pointer.
            return SkeletonVariable(
                name=name,
                c_type=_public_pointer_type(c_type),
                is_pointer=True,
                init_value="NULL",
            )

        # Regular parameter
        if is_pointer:
            return SkeletonVariable(
                name=name,
                c_type=_public_pointer_type(c_type),
                is_pointer=True,
                init_value="NULL",
            )

        # A struct/union value gets ``{0}`` (``= 0`` is illegal for an
        # aggregate); enums / scalar typedefs / primitives keep ``= 0``.
        init_value = _scalar_init_value(c_type, self.type_init_map)

        return SkeletonVariable(
            name=name,
            c_type=c_type,
            is_pointer=False,
            init_value=init_value,
        )

    def _generate_api_calls(
        self,
        skeleton: DriverSkeleton,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]],
        loop_patterns: Dict[str, Dict],
        callback_infos: Dict[str, List[Dict]]
    ) -> None:
        """Generate API call sequence"""

        for api in apis:
            # Check if loop is needed
            loop_info = loop_patterns.get(api.function_name, {})
            if loop_info.get('needs_loop'):
                self._generate_loop_call(skeleton, api, loop_info)
            else:
                self._generate_single_call(skeleton, api)

    def _generate_api_calls_scoped(
        self,
        skeleton: DriverSkeleton,
        apis: List[Api],
        varlen_relations: Dict[str, List[Tuple[int, int, str]]],
        loop_patterns: Dict[str, Dict],
        callback_infos: Dict[str, List[Dict]],
        dep_model=None,
    ) -> None:
        """Component-scoped call generation (B, LOGICFUZZ_SCOPED_GUARDS).

        Partition the sequence into dependency components (a parser + the calls
        that consume its handle = one component; an INDEPENDENT producer = a new
        component). For each component whose head producer may return NULL, wrap
        ONLY that component's dependent calls in ``if (head_handle != NULL) {
        ... }`` (B1 nested-if). The NEXT (independent) component renders OUTSIDE
        that ``if`` → it runs regardless of the parser's failure. No
        ``return 0`` whole-driver bail is ever emitted for a producer failure.

        Variable declarations stay function-scoped (emitted earlier), so the
        end-of-function destroyers run for every opened handle regardless of the
        ``if``-nesting, and C decl-before-use is preserved.
        """
        by_name = {api.function_name: api for api in apis}
        # Prefer the reconcile model (the SAME produces/requires the
        # construct-time D-reorder used) when threaded in — eliminates the
        # divergence with the pointer-count _build_signature_model heuristic,
        # which misses value / multi-level / recovered handle types and could
        # split a component → render a consumer OUTSIDE its producer's guard.
        # Falls back to the signature heuristic on the direct-generate path.
        model = dep_model if dep_model is not None else _build_signature_model(apis)
        components = _dependency_components(
            [api.function_name for api in apis], model)

        def _emit(api: Api, indent: int) -> None:
            loop_info = loop_patterns.get(api.function_name, {})
            if loop_info.get('needs_loop'):
                self._generate_loop_call(skeleton, api, loop_info,
                                         indent=indent, emit_null_guard=False)
            else:
                self._generate_single_call(skeleton, api, indent=indent,
                                           emit_null_guard=False)

        for comp in components:
            comp_apis = [by_name[n] for n in comp if n in by_name]
            if not comp_apis:
                continue
            head = comp_apis[0]
            dependents = comp_apis[1:]
            head_returns_ptr = bool(
                head.return_info and '*' in (head.return_info.type or ''))

            # Head call always runs (no guard, no whole-driver bail).
            _emit(head, indent=1)

            if dependents and head_returns_ptr:
                # B1 nested-if: scope the head producer's consumers to its
                # success. The independent NEXT component is a separate `comp`,
                # so it renders OUTSIDE this `if`.
                ret_name = f"ret_{head.function_name}"
                skeleton.add_statement(SkeletonStatement(
                    kind=StatementKind.IF_CHECK,
                    code=f"if ({ret_name} != NULL) {{",
                    variables=[ret_name],
                    indent=1,
                ))
                for dep in dependents:
                    _emit(dep, indent=2)
                skeleton.add_statement(SkeletonStatement(
                    kind=StatementKind.IF_CHECK,
                    code="}",
                    indent=1,
                ))
            else:
                # Head doesn't gate (void/scalar return) — its dependents run
                # at function scope (still no whole-driver bail).
                for dep in dependents:
                    _emit(dep, indent=1)

    def _emit_collection_population(self, skeleton: 'DriverSkeleton',
                                    var_name: str) -> None:
        """Lever A: emit ``var[i] = producer_ret;`` assignments for a prepopulated
        handle array, immediately before the consuming call (call-time population —
        decl-time producer rets are NULL)."""
        var = skeleton.variables.get(var_name)
        if var is None or not getattr(var, "prepopulate", None):
            return
        for i, expr in enumerate(var.prepopulate):
            skeleton.add_statement(SkeletonStatement(
                kind=StatementKind.ASSIGNMENT,
                code=f"{var_name}[{i}] = {expr};",
                variables=[var_name], indent=1))

    def _emit_struct_fuzz_fill(self, skeleton: 'DriverSkeleton',
                               var_name: str) -> None:
        """Lever B: emit a size-guarded ``memcpy(&name, data, sizeof(T))`` for a
        by-value struct var flagged ``fuzz_fill_struct``, immediately before the
        consuming call — fills the struct from fuzz bytes (seed-independent +
        non-degenerate) instead of the degenerate ``{0}``. Memory-safe: the
        ``if (size >= sizeof(T))`` guard never reads past ``data``."""
        var = skeleton.variables.get(var_name)
        t = var and getattr(var, "fuzz_fill_struct", None)
        if not t:
            return
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.ASSIGNMENT,
            code=(f"if (size >= sizeof({t})) "
                  f"memcpy(&{var_name}, data, sizeof({t}));"),
            variables=[var_name], indent=1))

    def _generate_single_call(
        self,
        skeleton: DriverSkeleton,
        api: Api,
        indent: int = 1,
        emit_null_guard: bool = True,
    ) -> None:
        """Generate single API call.

        ``indent`` controls the statement's nesting level (1 = function body;
        the scoped-guard path uses 2 for calls inside a component's
        ``if (producer != NULL) { ... }`` block). ``emit_null_guard`` toggles the
        legacy whole-driver ``if (ret == NULL) return 0;`` error check — the
        scoped-guard path disables it (component-scoped guards replace it) so an
        independent producer's failure never bails the whole driver.
        """

        # Lever A: populate any handle-collection array arg with its producer
        # handles immediately before this call (call-time — decl-time rets are NULL).
        for idx, arg in enumerate(api.arguments_info):
            vn = f"{arg.name or f'arg{idx}'}_{api.function_name}"
            v = skeleton.variables.get(vn)
            if v is not None and getattr(v, "prepopulate", None):
                self._emit_collection_population(skeleton, vn)
            if v is not None and getattr(v, "fuzz_fill_struct", None):
                self._emit_struct_fuzz_fill(skeleton, vn)

        # Build argument list
        args = []
        # Task 11 (defense-in-depth): handle vars the model marked nullable=False
        # that are STILL unbound at render (no producer wired) → pass a NULL var.
        # Collect them so the whole call is wrapped in ``if (handle) { ... }``
        # instead of consuming a bare NULL (the library would assert/deref NULL).
        guard_vars: List[str] = []
        for idx, arg in enumerate(api.arguments_info):
            var_name = f"{arg.name or f'arg{idx}'}_{api.function_name}"
            if var_name in skeleton.variables:
                var = skeleton.variables[var_name]
                if var.bound_expr:
                    # Pass the producer's LIVE return directly — var.name's decl
                    # init snapshots NULL (declarations precede the producer
                    # call). 2026-06 review.
                    args.append(var.bound_expr)
                else:
                    # is_array / is_pointer / scalar all pass the var name.
                    args.append(var.name)
                    if (getattr(var, 'nonnull_handle', False)
                            and var.name not in guard_vars):
                        guard_vars.append(var.name)
            else:
                # Variable not declared, use placeholder
                hole = InitValueHole(
                    name=f"param_{self._next_hole_id()}",
                    target_type=arg.type,
                    is_pointer='*' in arg.type
                )
                skeleton.add_hole(hole)
                args.append(hole.get_placeholder())

        # Build call code
        args_str = ", ".join(args)
        if api.return_info and api.return_info.type not in ['void', '']:
            ret_name = f"ret_{api.function_name}"
            call_code = f"{ret_name} = {api.function_name}({args_str});"
        else:
            call_code = f"{api.function_name}({args_str});"

        # Task 11 defense-in-depth: if this call consumes an unbound
        # nullable=False handle, wrap it (+ its return check) in
        # ``if (h1 && h2) { ... }`` so a NULL handle is never passed in. The
        # call body indents one deeper inside the guard.
        _guarded = bool(guard_vars) and _validity_contract_enabled()
        _body_indent = indent + 1 if _guarded else indent
        if _guarded:
            cond = " && ".join(guard_vars)
            skeleton.add_statement(SkeletonStatement(
                kind=StatementKind.IF_CHECK,
                code=f"if ({cond}) {{",
                variables=list(guard_vars),
                indent=indent,
            ))

        stmt = SkeletonStatement(
            kind=StatementKind.API_CALL,
            code=call_code,
            api=api,
            variables=args,
            indent=_body_indent,
        )
        skeleton.add_statement(stmt)

        # Add error check (if returns pointer). Whole-driver bail; the
        # scoped-guard path (B) suppresses this and wraps dependents instead.
        if emit_null_guard and api.return_info and '*' in api.return_info.type:
            ret_name = f"ret_{api.function_name}"
            check_code = f"if ({ret_name} == NULL) return 0;"
            check_stmt = SkeletonStatement(
                kind=StatementKind.IF_CHECK,
                code=check_code,
                variables=[ret_name],
                indent=_body_indent,
            )
            skeleton.add_statement(check_stmt)

        if _guarded:
            skeleton.add_statement(SkeletonStatement(
                kind=StatementKind.IF_CHECK,
                code="}",
                indent=indent,
            ))

    def _generate_loop_call(
        self,
        skeleton: DriverSkeleton,
        api: Api,
        loop_info: Dict,
        indent: int = 1,
        emit_null_guard: bool = True,
    ) -> None:
        """Generate loop API call.

        LOOP_BOUND is filled deterministically with ``loop_info[max_iterations]``
        (or 100 default) so the LLM doesn't have to guess. LOOP_CONDITION is
        still LLM-only — it requires API-return semantics the rule layer can't
        infer (cf. data study 2026-05). ``indent`` / ``emit_null_guard`` flow
        through to the inner call for the scoped-guard path (B).
        """

        loop_type = loop_info.get('loop_type', 'iterator')

        # LOOP_CONDITION still needs LLM judgement.
        cond_hole = create_loop_condition_hole(
            name=f"loopcond_{self._next_hole_id()}",
            loop_type=loop_type,
            api_return_type=api.return_info.type if api.return_info else ""
        )
        skeleton.add_hole(cond_hole)

        # LOOP_BOUND: deterministic — emit the suggested numeric literal
        # directly. We *don't* register a hole for it; the renderer just sees
        # the int.
        bound_value = int(loop_info.get('max_iterations', 100) or 100)

        loop_start = SkeletonStatement(
            kind=StatementKind.LOOP_START,
            code=(f"int __iter_count = 0;\n"
                  f"while ({cond_hole.get_placeholder()} "
                  f"&& __iter_count++ < {bound_value}) {{"),
            holes=[cond_hole.name],
            indent=indent,
        )
        skeleton.add_statement(loop_start)

        # API call in loop body
        self._generate_single_call(skeleton, api, indent=indent + 1,
                                   emit_null_guard=emit_null_guard)

        # Loop end
        loop_end = SkeletonStatement(
            kind=StatementKind.LOOP_END,
            code="}",
            indent=indent,
        )
        skeleton.add_statement(loop_end)

    def _append_tag_roundtrip(self, skeleton: DriverSkeleton) -> None:
        """LOGICFUZZ_TAG_ROUNDTRIP: append a guarded save->reopen->read block on a
        cmsHPROFILE-producing skeleton to exercise cmstypes.c (de)serializers (the
        4%-covered tag-type handlers). Picks the FIRST profile-handle variable (by
        cmsHPROFILE c_type or a cms(Create|Open)*(Profile|DeviceLink) producer) and
        emits the self-contained, fully-guarded round-trip. Default-off / inert."""
        if not _tag_roundtrip():
            return
        prof = None
        for v in skeleton.variables.values():
            if 'cmsHPROFILE' in (v.c_type or '') or _is_profile_producer(
                    v.source_api or ''):
                prof = v.name
                break
        if not prof:
            return
        skeleton.add_statement(SkeletonStatement(
            kind=StatementKind.RAW_CODE,
            code=_TAG_ROUNDTRIP_TEMPLATE.format(prof=prof)))

    def _generate_cleanup(self, skeleton: DriverSkeleton, dep_model=None) -> None:
        """Emit cleanup statements.

        Cleanup is paired-destroy by construction: every variable that
        was allocated on the heap (alloc==HEAP) gets a matching destroy
        call inferred from the producing API's name (e.g. ``cJSON_Parse``
        ↔ ``cJSON_Delete``). Patterns recognised:

        * ``<prefix>_create_*`` ↔ ``<prefix>_destroy_*``
        * ``<prefix>_new_*``    ↔ ``<prefix>_free_*``
        * ``<prefix>_open_*``   ↔ ``<prefix>_close_*``
        * ``<prefix>_init_*``   ↔ ``<prefix>_deinit_*``
        * Default fallback: ``free(<var>)``

        We emit the statements directly and skip RESOURCE_CLEANUP holes
        for paired-destroyable resources. When no rule fires (e.g. the
        producer name doesn't match a known pattern), we still emit a
        plain ``free(<var>)`` guard rather than a hole — the empirical
        study (2026-05) showed expert OSS-Fuzz drivers use the same
        paired-destroy logic 100% of the time. Skipping the hole means
        the LLM no longer has to guess at trivial teardown.
        """
        cleanup_lines: List[str] = []

        # Walk variables that came from heap-allocated API returns
        # (source_api set ⇒ producer-tracked).
        # Sequence is lifecycle-complete by construction: if its OWN destroyer
        # for a handle is ALREADY a call in the sequence, emitting the paired
        # destroy here too is a DOUBLE-FREE. (Was masked by the NULL-snapshot
        # binding bug — the in-sequence destroyer received NULL; fixing that
        # binding activates this.) Skip any handle whose inferred destroyer is
        # already in the sequence. 2026-06 review.
        seq_api_names = {a.function_name
                         for a in (skeleton.target_apis or [])}
        # Real-API set for destroyer validation: a name-pattern-inferred destroyer
        # that ISN'T a real project API (e.g. cmsCreateContext → 'cmsDestroy') is
        # an undefined symbol → link failure → the driver is dropped by
        # compile-validation (breadth loss). The validator is the MODEL's API
        # universe — only it authoritatively knows which symbols exist. ARM the
        # reality-gate ONLY when a model is present; with no model we cannot
        # validate, so leave it OFF (empty set ⇒ _real_destroy keeps the legacy
        # name-pattern inference, and any truly invalid symbol is still caught
        # downstream by compile-validation). Seeding the gate from seq_api_names
        # ALONE (the model-absent path) would WRONGLY suppress a real paired
        # destroyer that isn't itself in the sequence (e.g. cJSON_Delete for an
        # in-sequence cJSON_Parse) → leak. Production threads dep_model (CBFactory),
        # so the gate is armed there. 2026-06 review.
        _valid_apis: Set[str] = set()
        if dep_model is not None:
            _valid_apis = set(seq_api_names)
            _model_apis = getattr(dep_model, 'apis', None) or {}
            if isinstance(_model_apis, dict):
                _valid_apis |= set(_model_apis.keys())
                for _v in _model_apis.values():
                    _fn = getattr(_v, 'function_name', None) or (
                        _v.get('function_name') if isinstance(_v, dict) else None)
                    if _fn:
                        _valid_apis.add(_fn)
        for var_name, var in skeleton.variables.items():
            if not var.source_api:
                continue
            destroy_call = _real_destroy(var.source_api, var_name, _valid_apis)
            if destroy_call is None:
                continue
            destroyer_name = destroy_call.split("(", 1)[0].strip()
            if destroyer_name in seq_api_names:
                continue  # sequence already destroys this handle — no double-free
            cleanup_lines.append(f"if ({var_name}) {{ {destroy_call}; }}")

        if not cleanup_lines:
            # Nothing to clean up. Don't emit a hole for "no work".
            return

        cleanup_stmt = SkeletonStatement(
            kind=StatementKind.CLEANUP,
            code="\n".join(cleanup_lines),
        )
        skeleton.add_cleanup(cleanup_stmt)

    def _next_hole_id(self) -> int:
        """Get next Hole ID"""
        self._hole_counter += 1
        return self._hole_counter


# =============================================================================
# Skeleton Renderer
# =============================================================================

class SkeletonRenderer:
    """
    Skeleton renderer

    Renders DriverSkeleton to C code string
    """

    def render(self, skeleton: DriverSkeleton) -> str:
        """Render skeleton to C/C++ code.

        Always uses ``#ifdef __cplusplus extern "C"`` guards so the
        emitted code compiles correctly under OSS-Fuzz (clang++ on
        both .c and .cc) without per-target dispatch.
        """
        lines = []

        # 1. Includes
        for inc in skeleton.includes:
            lines.append(inc)
        lines.append("")

        # 2. Stub functions
        for stub in skeleton.stub_functions:
            lines.append(stub)
            lines.append("")

        # 3. Fuzz function signature
        # OSS-Fuzz ALWAYS uses clang++ ($CXX) even for .c files, so we need extern "C"
        # to prevent C++ name mangling. Use #ifdef __cplusplus guard for compatibility.
        lines.append("#ifdef __cplusplus")
        lines.append("extern \"C\" {")
        lines.append("#endif")
        lines.append("")
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")

        # 4. Minimum size check.
        # Emit a placeholder; the actual minimum is resolved post-merge once we
        # know which data[N] indices the LLM/HoleFiller actually used.
        # (See _merge_holes_into_skeleton._fixup_min_size_guard in prototyper.)
        # The previous literal `if (size < 1)` caused immediate heap-buffer-
        # overflow on any driver that read past data[0].
        lines.append("    if (size < __MIN_SIZE__) return 0;")
        lines.append("")

        # 5. Variable declarations
        for var_name, var in skeleton.variables.items():
            decl = var.get_declaration()
            lines.append(f"    {decl};")
        lines.append("")

        # 6. Statements
        for stmt in skeleton.statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        lines.append("")

        # 7. Cleanup
        for stmt in skeleton.cleanup_statements:
            indent = "    " * stmt.indent
            for code_line in stmt.code.split('\n'):
                lines.append(f"{indent}{code_line}")

        # 8. Return
        lines.append("    return 0;")
        lines.append("}")

        # Close extern "C" block
        lines.append("")
        lines.append("#ifdef __cplusplus")
        lines.append("}")
        lines.append("#endif")

        return "\n".join(lines)

    def render_with_holes_marked(self, skeleton: DriverSkeleton) -> str:
        """Render skeleton, marking all Hole positions"""
        code = self.render(skeleton)

        # Add comment for each Hole
        for hole in skeleton.holes:
            placeholder = hole.get_placeholder()
            if placeholder in code:
                comment = f"/* HOLE[{hole.kind.name}]: {hole.name} */"
                code = code.replace(placeholder, f"{placeholder} {comment}")

        return code


# =============================================================================
# Utility Functions
# =============================================================================

def generate_skeleton_for_sequence(
    api_sequence: List[Api],
    varlen_relations: Optional[Dict] = None,
    loop_patterns: Optional[Dict] = None,
    callback_infos: Optional[Dict] = None,
    driver_name: str = "fuzz_driver",
    is_cpp: bool = True
) -> DriverSkeleton:
    """Convenience function: generate skeleton for API sequence

    Args:
        api_sequence: API call sequence
        varlen_relations: Variable-length parameter relationships
        loop_patterns: Loop patterns for APIs
        callback_infos: Callback information
        driver_name: Name for the generated driver
        is_cpp: If True, include C++ headers (FuzzedDataProvider)
    """
    generator = SkeletonGenerator()
    return generator.generate(
        api_sequence,
        varlen_relations,
        loop_patterns,
        callback_infos,
        driver_name,
        is_cpp=is_cpp
    )


def render_skeleton(skeleton: DriverSkeleton, mark_holes: bool = False) -> str:
    """Convenience function: render skeleton

    Args:
        skeleton: Driver skeleton to render
        mark_holes: Whether to mark unfilled holes with comments
    """
    renderer = SkeletonRenderer()
    if mark_holes:
        return renderer.render_with_holes_marked(skeleton)
    return renderer.render(skeleton)


# =============================================================================
# Paired-destroy inference (2026-05 refactor — replaces RESOURCE_CLEANUP hole)
# =============================================================================

# Common API name conventions for producer→destroyer pairing across
# OSS-Fuzz C/C++ projects. Order matters: longer prefixes first so that
# "create_with_options" matches before "create".
_DESTROY_PAIRS = [
    ("_new", "_free"),
    ("_create", "_destroy"),
    ("_alloc", "_free"),
    ("_open", "_close"),
    ("_init", "_deinit"),
    ("_init", "_free"),
    ("_parse", "_free"),
    ("Parse", "Delete"),  # cJSON convention
    ("New", "Free"),
    ("Create", "Destroy"),
    ("Alloc", "Free"),
    ("Open", "Close"),
]


def _infer_paired_destroy(producer_api: str, var_name: str) -> Optional[str]:
    """Given the API name that produced a heap variable, return the
    matching destroy call as a C statement (without the trailing ``;``).

    Returns ``None`` only when no pattern matches AND ``producer_api``
    looks unrelated to allocation (so we don't emit a misleading
    ``free(x)`` for a stack-returned struct).
    """
    if not producer_api:
        return None
    for create_suffix, destroy_suffix in _DESTROY_PAIRS:
        if producer_api.endswith(create_suffix):
            base = producer_api[: -len(create_suffix)]
            destroy_fn = base + destroy_suffix
            return f"{destroy_fn}({var_name})"
        # also handle infix: <api>_<verb>_<rest> patterns where the verb
        # is at a non-tail position, e.g. cJSON_Parse → cJSON_Delete.
        idx = producer_api.find(create_suffix)
        if idx > 0 and idx + len(create_suffix) <= len(producer_api):
            head = producer_api[:idx]
            tail = producer_api[idx + len(create_suffix):]
            if not tail or tail.startswith("_") or tail[0].isupper():
                return f"{head}{destroy_suffix}({var_name})"
    # Fallback: classic libc allocator chain
    if producer_api.endswith("alloc") or producer_api == "malloc":
        return f"free({var_name})"
    # Could not infer — let the LLM (via prompt) decide if needed.
    return None


def _real_destroy(producer_api: str, var_name: str, valid_apis: set):
    """`_infer_paired_destroy` gated by REALITY: the name-pattern heuristic can
    invent a non-existent symbol (``cmsCreateContext`` → ``cms``+``Destroy`` =
    ``cmsDestroy``, which is not an lcms API; the real destroyer is
    ``cmsDeleteContext``). Emitting it makes the TU fail to LINK and the whole
    driver gets dropped by compile-validation — a breadth loss. Return the
    inferred destroy call ONLY when its function name is a real project API; else
    None (skip the destroy — a leak is harmless, LSan is off). An EMPTY
    ``valid_apis`` (no model) preserves the legacy inference (don't suppress)."""
    call = _infer_paired_destroy(producer_api, var_name)
    if call is None:
        return None
    name = call.split("(", 1)[0].strip()
    if name == "free":          # libc free is always valid
        return call
    if valid_apis and name not in valid_apis:
        return None
    return call
