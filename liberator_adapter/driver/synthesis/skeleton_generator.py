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
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from liberator_adapter.common.api import Api, Arg
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

        # 2. Analyze variable requirements
        var_requirements = self._analyze_variable_requirements(
            api_sequence, varlen_relations or {}
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

        # 5. Generate cleanup code
        self._generate_cleanup(skeleton)

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
        varlen_relations: Dict[str, List[Tuple[int, int, str]]]
    ) -> Dict[str, Dict]:
        """
        Analyze variable requirements

        Returns:
            {api_name: {
                'args': [{name, type, is_input, is_output, varlen_idx}, ...],
                'return': {type, name}
            }}
        """
        requirements = {}

        for api in apis:
            api_req = {
                'args': [],
                'return': None
            }

            # Get var-len relationships for this API
            api_varlen = varlen_relations.get(api.function_name, [])
            varlen_map = {buf_idx: (len_idx, rel) for buf_idx, len_idx, rel in api_varlen}

            # Analyze parameters
            for idx, arg in enumerate(api.arguments_info):
                arg_info = {
                    'name': arg.name or f"arg{idx}",
                    'type': arg.type,
                    'idx': idx,
                    'is_input': self._is_input_param(arg),
                    'is_output': self._is_output_param(arg),
                    'is_callback': self._is_callback_param(arg),
                    'varlen_target': varlen_map.get(idx),  # (len_idx, rel) or None
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
        """Create variable for parameter.

        ``is_entry_api`` triggers the B4 safety net: ``_is_input_param``
        misclassifies non-const pointers as "not input" (75% of OSS-Fuzz
        entry-point calls in the 2026-05 study used const pointers, so
        the heuristic was tuned for those). For the *entry* API we
        cannot rely on producer→consumer wiring (no prior call) and the
        fuzz buffer is the only sensible source. So when:
          - the arg is a non-callback pointer
          - on the entry API
          - and not already covered by the C_STRING wrapper (char*)
        force the FUZZ_INPUT branch with ``(void*)data`` regardless of
        what ``is_input``/``is_output`` claim.
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

        # B4 safety net: entry-API non-const pointer that ISN'T a char*
        # (char* is handled by `_maybe_inject_c_string_wrapper`) — force
        # the fuzz-input bridge so the caller doesn't get a stack array
        # for a buffer-input parameter the const-check missed.
        ttype_norm = c_type.replace(' ', '')
        is_char_star = 'char*' in ttype_norm
        if (is_entry_api and is_pointer and not is_char_star
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

        # Input buffer parameter - may need to get from fuzz input
        if arg_info['is_input'] and is_pointer:
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
        if arg_info['is_output'] and is_pointer:
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

        # Build argument list
        args = []
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

        stmt = SkeletonStatement(
            kind=StatementKind.API_CALL,
            code=call_code,
            api=api,
            variables=args,
            indent=indent,
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
                indent=indent,
            )
            skeleton.add_statement(check_stmt)

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

    def _generate_cleanup(self, skeleton: DriverSkeleton) -> None:
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
        for var_name, var in skeleton.variables.items():
            if not var.source_api:
                continue
            destroy_call = _infer_paired_destroy(var.source_api, var_name)
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
