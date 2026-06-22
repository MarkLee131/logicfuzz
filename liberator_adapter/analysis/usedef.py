"""Use-def + typestate engine.

Models every public API as an IR node carrying USE / DEF / KILL effects on an
abstract universe of *handle types*. From this single description three things
fall out for free that the L1/L2/L3 filters previously implemented separately:

- L1 entry point: an API is a *direct* entry point if it has a buffer / view
  input slot (``input_category``) and no required upstream handle. An
  *indirect* entry point is the same plus a USE'd handle that some other API
  in the project DEFs.
- L2 lifecycle: the typestate for a handle ``H`` requires every DEF(H) to be
  followed by a KILL(H) before the sequence ends; missing KILL = unclosed
  resource; KILL with no preceding DEF = unopened close.
- L3 state machine: the same typestate validates the 5 violation classes
  (USE_BEFORE_INIT / DESTROY_BEFORE_INIT / DOUBLE_DESTROY / USE_AFTER_DESTROY
  / REINIT_WITHOUT_DESTROY) as one-step transition checks.

Reference:
- Aho, Sethi, Ullman, *Compilers: Principles, Techniques, and Tools*, Ch.9
  (reaching definitions, def-use chains).
- Strom & Yemini, "Typestate: A Programming Language Concept for Enhancing
  Software Reliability", IEEE TSE 1986.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple


HandleType = str  # canonical, normalized handle type key (e.g. ``"sqlite3*"``)


# =============================================================================
# Canonical handle classification primitives (single source of truth)
# =============================================================================
#
# Historically these lived as private methods on
# ``EntryPointAnalyzer``. They were promoted here during the L1/L2/L3
# consolidation so all use-def + typestate code shares one notion of "what's
# a handle" / "what does this API consume / produce". EPA still re-exports
# them as instance shims for back-compat with callers passing them through
# ``extract_api_effects``.
#
# Reference: Aho/Sethi/Ullman §9 — reaching definitions / mod-ref summaries.

import re as _re

_NON_HANDLE_PRIMITIVES: Tuple[str, ...] = (
    # C / C++ source-level scalar names
    "int", "long", "short", "char", "size_t", "ssize_t", "bool", "float",
    "double", "void", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "unsigned", "signed",
    # LLVM IR scalar type names — when conditions come from LLVM IR
    # mod/ref analysis (the common case in Liberator), arg types are
    # written as ``i8 *`` / ``i32`` / ``i64`` rather than the source-level
    # ``char *`` / ``int``. Without these here, ``is_handle_type("i8*")``
    # returns True and every byte-buffer / scalar input slot looks like
    # an opaque handle that needs lifecycle tracking. That cascades into
    # graft_creator_prefix, post_parse_extensions, L4 ranking, and the
    # comprehender — all of which then misclassify ``i8*`` as a
    # project-managed resource. Adding the LLVM names propagates the
    # same fix as #73's byte-buffer exemption to all consumers of
    # usedef, not just the Z3 lifecycle walker.
    "i1", "i8", "i16", "i32", "i64", "i128",
    "half", "bfloat", "fp128", "ppc_fp128", "x86_fp80",
    "label", "token", "metadata",
)

_CHANNEL_RETURN: int = 0
_CHANNEL_OUT_POINTER: int = 1
# Caller-allocated-struct init: ``foo_init(foo *)`` initializes a struct the
# caller declares on the stack. The struct arrives by single pointer (arity 1),
# not the ``foo **`` out-pointer pattern, so the RETURN / OUT_POINTER channels
# miss it and the type looks unproduced (e.g. zlib ``z_stream`` ← deflateInit_).
_CHANNEL_INIT: int = 2

_CREATOR_PRIORITY_PATTERNS: Tuple[str, ...] = (
    "_new", "_create", "_alloc", "_init", "_open",
)

# Init-naming stems (substring, case-insensitive) used to distinguish a
# caller-alloc *initializer* (CREATOR-like) from a plain *mutator* of the same
# struct: deflate and deflateInit_ both write z_stream's fields, only the latter
# is the creator. Underscore-free so camelCase (``deflateInit_``) matches.
_INIT_NAMING_STEMS: Tuple[str, ...] = (
    "init", "create", "alloc", "setup", "construct", "make", "open", "begin",
)
# Guard: these forms contain an init stem but are NOT initializers (destroyers /
# re-inits), so they must NOT be treated as producers.
_INIT_NAMING_ANTI_STEMS: Tuple[str, ...] = (
    "deinit", "uninit", "reinit", "close", "free", "destroy", "delet",
    "releas", "cleanup", "fini", "dealloc", "dispose", "reset", "term",
)


def _is_init_named(name_lower: str) -> bool:
    """True for caller-alloc initializer names (``deflateInit_``), excluding
    de-init / destroy forms that merely contain an init substring."""
    if any(a in name_lower for a in _INIT_NAMING_ANTI_STEMS):
        return False
    return any(s in name_lower for s in _INIT_NAMING_STEMS)

# Buffer-hint patterns: arg types that signal raw byte / string buffers
# (we don't want to treat these as handle out-pointers when they appear as
# ``T**`` because callers conventionally allocate/own the bytes themselves,
# not the library).
_BUFFER_HINT_PATTERNS: Tuple[str, ...] = (
    "char *", "char*", "uint8_t *", "uint8_t*",
    "unsigned char *", "unsigned char*", "void *", "void*",
)


def _normalize_type_str(type_str: str) -> str:
    """Lowercase, collapse whitespace around pointers / refs / templates."""
    if not type_str:
        return ""
    s = type_str.lower()
    s = _re.sub(r"\s*<\s*", "<", s)
    s = _re.sub(r"\s*>\s*", ">", s)
    s = _re.sub(r"\s*\*\s*", " *", s)
    s = _re.sub(r"\s*&\s*", " &", s)
    s = _re.sub(r"\s+", " ", s).strip()
    return s


def _count_pointer_levels(type_str: str) -> int:
    if not type_str:
        return 0
    return _normalize_type_str(type_str).count("*")


def _strip_one_pointer_level(type_str: str) -> Optional[str]:
    """Return ``type_str`` with one trailing pointer level removed.

    ``"foo **"`` -> ``"foo *"``; ``"foo *"`` -> ``"foo"``. Returns ``None``
    when the type isn't a pointer.
    """
    if not type_str:
        return None
    norm = _normalize_type_str(type_str)
    if "*" not in norm:
        return None
    # Drop exactly ONE '*' token (the normalizer space-separates them), not the
    # whole trailing run: rstrip(' *') would strip every level, turning
    # ``foo ***`` into ``foo *`` instead of ``foo * *``.
    idx = norm.rfind("*")
    return (norm[:idx] + norm[idx + 1:]).rstrip()


def _get_is_const(arg: Dict[str, Any]) -> bool:
    """Bool from either ``is_const`` (standard) or ``const`` (clang) shape."""
    raw = arg.get("is_const", arg.get("const", [False]))
    if isinstance(raw, list):
        return bool(raw[0]) if raw else False
    return bool(raw)


def _extract_return_type(api: Dict[str, Any]) -> str:
    """Return type tolerating both top-level and nested layouts."""
    return_info = api.get("return_info")
    if isinstance(return_info, dict) and return_info:
        rt = return_info.get("type_clang") or return_info.get("type")
        if rt:
            return rt
    return api.get("return_type", "") or ""


_TYPE_KEYWORD_RE = _re.compile(
    r'\b(?:const|volatile|struct|union|class|enum|restrict|__restrict__|__restrict)\b')


def _strip_type_keywords(t: str) -> str:
    """Drop C type qualifier/elaboration KEYWORDS by WORD BOUNDARY. The legacy
    ``.replace("struct ", "")`` was a substring strip that corrupted a type NAME
    embedding the keyword: ``png_struct *`` -> ``png_*`` (and
    ``_cmsContext_struct *`` -> ``_cmscontext_*``), so a creator's ``produces``
    no longer matched the consumer's ``requires`` for ANY library whose handle
    name contains ``struct`` -> orphan NULL handle -> dead driver. Word
    boundaries strip only the real keyword: ``struct png_struct_def *`` ->
    ``png_struct_def *``; ``png_struct *`` -> ``png_struct *`` (name kept)."""
    return ' '.join(_TYPE_KEYWORD_RE.sub(' ', t or '').split())


def is_handle_type(type_str: str) -> bool:
    """A non-primitive opaque type carried as data.

    Accepts pointer / reference types, ``struct`` / ``union`` / ``class``
    declarations, ``_t``-suffixed typedefs, and bare project-defined
    identifiers. Rejects when *every* token in the bare identifier is a
    known scalar primitive (so ``unsigned char`` / ``long long`` aren't
    mis-classified as handles).
    """
    if not type_str:
        return False
    norm = _normalize_type_str(type_str)
    bare = (_strip_type_keywords(norm)
                 .replace("*", "")
                 .replace("&", "")
                 .strip())
    if not bare:
        return False
    tokens = bare.split()
    if tokens and all(tok in _NON_HANDLE_PRIMITIVES for tok in tokens):
        return False
    return True


def normalize_handle_type(type_str: str) -> str:
    """Canonical lookup key for matching consumer handle args to creator returns."""
    if not type_str:
        return ""
    norm = _normalize_type_str(type_str)
    return (_strip_type_keywords(norm)
                .replace(" *", "*")
                .replace(" &", "&")
                .strip()
                .lower())


def _find_buffer_size_positions(
    args: List[Dict[str, Any]],
) -> Tuple[int, int]:
    """Locate a ``(buf, size)`` arg pair if present; ``(-1, -1)`` otherwise.

    Heuristic: a buffer arg is a const pointer to a byte-ish type whose
    successor is integer-sized.
    """
    for i, arg in enumerate(args):
        atype = arg.get("type", arg.get("type_clang", "")) or ""
        norm = _normalize_type_str(atype)
        if not _get_is_const(arg):
            continue
        if not any(p in norm for p in _BUFFER_HINT_PATTERNS):
            continue
        if i + 1 >= len(args):
            continue
        next_arg = args[i + 1]
        nnorm = _normalize_type_str(
            next_arg.get("type", next_arg.get("type_clang", "")) or "")
        nbare = nnorm.replace("const ", "").replace("*", "").strip()
        if nbare in {"size_t", "ssize_t", "int", "long", "unsigned", "uint32_t",
                     "uint64_t", "unsigned long", "unsigned int"}:
            return i, i + 1
    return -1, -1


def consumed_handle_keys(api: Dict[str, Any]) -> Set[HandleType]:
    """Set of normalized handle-type keys this API takes as input.

    Out-pointer slots (``Type **``, non-const) carry a handle outward and
    are excluded; single-pointer / by-value handles (``Type *``, ``Type``)
    are inputs and counted.
    """
    keys: Set[HandleType] = set()
    args = api.get("arguments", api.get("arguments_info", [])) or []
    for arg in args:
        atype = arg.get("type", arg.get("type_clang", "")) or ""
        if not is_handle_type(atype):
            continue
        if (_count_pointer_levels(atype) >= 2 and not _get_is_const(arg)):
            inner = _strip_one_pointer_level(atype)
            if inner is not None and is_handle_type(inner):
                continue  # this slot is an out-pointer DEF, not a USE
        key = normalize_handle_type(atype)
        if key:
            keys.add(key)
    return keys


def extract_produced_handles(
    api: Dict[str, Any],
) -> List[Tuple[HandleType, int, float]]:
    """Enumerate ``(handle_key, channel, confidence)`` tuples this API produces.

    Two delivery channels:
      - **return**: return type is a handle.
      - **out-pointer**: a non-const param with arity ≥ 2 whose stripped
        inner is a handle and isn't a buffer-hint type.
    """
    produced: List[Tuple[HandleType, int, float]] = []

    rt = _extract_return_type(api)
    if is_handle_type(rt):
        key = normalize_handle_type(rt)
        if key:
            produced.append((key, _CHANNEL_RETURN, 1.0))

    args = api.get("arguments", api.get("arguments_info", [])) or []
    buffer_idx, size_idx = _find_buffer_size_positions(args)
    name_lower = (api.get("function_name", "") or "").lower()
    naming_boost = any(pat in name_lower for pat in _CREATOR_PRIORITY_PATTERNS)
    init_named = _is_init_named(name_lower)
    for arg_idx, arg in enumerate(args):
        if arg_idx == buffer_idx or arg_idx == size_idx:
            continue
        arg_type = arg.get("type", arg.get("type_clang", "")) or ""
        if _get_is_const(arg):
            continue
        levels = _count_pointer_levels(arg_type)
        if levels >= 2:
            # Classic out-pointer creator: ``foo **out`` receives a fresh handle.
            inner = _strip_one_pointer_level(arg_type)
            if inner is None or not is_handle_type(inner):
                continue
            key = normalize_handle_type(inner)
            if not key:
                continue
            confidence = 0.95 if naming_boost else 0.7
            produced.append((key, _CHANNEL_OUT_POINTER, confidence))
        elif levels == 1 and init_named and is_handle_type(arg_type):
            # Caller-allocated-struct init: ``foo_init(foo *)`` initializes a
            # struct the caller declares (zlib ``deflateInit_(z_stream*)``). The
            # produced key is the single-pointer struct itself (same normalize
            # the consumers' ``requires`` use, so they wire up). Three safety nets
            # keep this from over-firing:
            #   (a) only init-NAMED APIs reach here (a plain mutator ``deflate``
            #       that also writes z_stream is excluded by naming);
            #   (b) SVF write-through gate (``_svf_writes`` ∈ {True, False, None}):
            #       True = SVF saw it write/init the struct → produce; False = SVF
            #       analyzed it and saw only reads → it's NOT an initializer
            #       (e.g. ``pthread_create(attr*)`` reads the attr), so SKIP;
            #       None = SVF had no data (e.g. ``inflateInit_`` inlined away) →
            #       trust the init-naming;
            #   (c) ``extract_api_effects`` demotes this channel whenever the
            #       type already has a real (return/out-ptr) creator.
            svf_writes = arg.get("_svf_writes")
            if svf_writes is False:
                continue
            key = normalize_handle_type(arg_type)
            if not key:
                continue
            confidence = 0.6 if svf_writes is True else 0.45
            produced.append((key, _CHANNEL_INIT, confidence))
    return produced


def annotate_svf_writes(
    apis: List[Dict[str, Any]],
    conditions: Any,
) -> None:
    """Tag each arg with ``_svf_writes`` ∈ {True, False, None} in place.

    The signal gates the caller-alloc INIT producer channel (see
    ``extract_produced_handles``): an init-named API only counts as producing a
    single-pointer struct if SVF didn't *positively* observe it reading-only.

      True  — SVF saw a write/delete on this param (it initializes the struct).
      False — SVF analyzed the function and this param has accesses, all reads
              (it consumes the struct, doesn't initialize it).
      None  — SVF had no usable access data for this param (function inlined
              away / not in the report) → caller falls back to naming.

    ``conditions`` is the raw conditions.json structure: either a ``list`` of
    per-function dicts (``{function_name, param_0:{access_type_set:[...]}, ...}``)
    or a mapping ``{name: that_dict}``. Anything else → all args tagged None.
    """
    by_name: Dict[str, Dict[str, Any]] = {}
    if isinstance(conditions, list):
        by_name = {e["function_name"]: e for e in conditions
                   if isinstance(e, dict) and "function_name" in e}
    elif isinstance(conditions, dict):
        by_name = {k: v for k, v in conditions.items() if isinstance(v, dict)}

    for api in apis:
        fname = api.get("function_name", "")
        args = api.get("arguments", api.get("arguments_info", [])) or []
        entry = by_name.get(fname)
        for i, arg in enumerate(args):
            verdict: Optional[bool] = None
            is_array: Optional[bool] = None
            if entry is not None:
                pinfo = entry.get(f"param_{i}")
                if isinstance(pinfo, dict):
                    ats = pinfo.get("access_type_set")
                    if ats:  # analyzed AND has accesses
                        verdict = any(a.get("access") in ("write", "delete")
                                      for a in ats)
                    # SVF array verdict — part of the discriminator that
                    # separates a written value-ARRAY output buffer from a single
                    # in-out handle (see api_semantic_model OUTPUT promotion).
                    is_array = pinfo.get("is_array")
            arg["_svf_writes"] = verdict
            arg["_svf_is_array"] = is_array


# =============================================================================
# Effect summary per API
# =============================================================================

class _Channel(Enum):
    """Delivery channel for a produced handle. Metadata only — not in ranking."""
    RETURN = "return"
    OUT_POINTER = "out_pointer"
    INIT = "init"  # caller-allocated struct initialized in-place (foo_init(foo*))


@dataclass(frozen=True)
class HandleProduction:
    """One way an API produces a handle."""
    handle: HandleType
    channel: _Channel
    confidence: float  # in [0, 1]; higher = more credible


@dataclass(frozen=True)
class APIEffect:
    """USE / DEF / KILL summary for one API.

    All sets are over normalized handle-type keys. ``input_category`` is the
    L1 buffer-input categorization (or ``None`` if no buffer slot). ``raw``
    keeps a back-pointer to the original API dict so reporting layers can
    surface arg indices, type strings, etc., without re-deriving them.
    """
    name: str
    use: FrozenSet[HandleType]
    def_: FrozenSet[HandleType]
    kill: FrozenSet[HandleType] = frozenset()
    productions: Tuple[HandleProduction, ...] = ()
    input_category: Optional[str] = None
    handle_arg_index: int = -1
    handle_arg_type: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)


# =============================================================================
# Typestate violation reporting
# =============================================================================

class ResourceLifecycleState(Enum):
    UNINITIALIZED = "uninitialized"
    INITIALIZED = "initialized"
    DESTROYED = "destroyed"


class ViolationKind(Enum):
    USE_BEFORE_INIT = "use_before_init"
    DESTROY_BEFORE_INIT = "destroy_before_init"
    DOUBLE_DESTROY = "double_destroy"
    USE_AFTER_DESTROY = "use_after_destroy"
    REINIT_WITHOUT_DESTROY = "reinit_without_destroy"
    UNCLOSED_RESOURCE = "unclosed_resource"
    UNOPENED_CLOSE = "unopened_close"


@dataclass(frozen=True)
class ViolationRecord:
    kind: ViolationKind
    api_name: str
    handle: HandleType
    position: int
    expected: Optional[ResourceLifecycleState] = None
    actual: Optional[ResourceLifecycleState] = None


# =============================================================================
# Library-wide use-def graph
# =============================================================================

class UseDefGraph:
    """All ``APIEffect``s indexed by handle type, with derived queries."""

    def __init__(self, effects: Iterable[APIEffect]):
        self._effects: Dict[str, APIEffect] = {e.name: e for e in effects if e.name}
        self._producers: Dict[HandleType, List[str]] = {}
        self._consumers: Dict[HandleType, List[str]] = {}
        self._killers: Dict[HandleType, List[str]] = {}
        for e in self._effects.values():
            for h in e.def_:
                self._producers.setdefault(h, []).append(e.name)
            for h in e.use:
                self._consumers.setdefault(h, []).append(e.name)
            for h in e.kill:
                self._killers.setdefault(h, []).append(e.name)
        # Cache the dataflow fixpoint; used by ``roots``.
        self._depth_cache: Optional[Dict[str, int]] = None

    # ---- query ----
    def effect(self, name: str) -> Optional[APIEffect]:
        return self._effects.get(name)

    def all_effects(self) -> Iterable[APIEffect]:
        return self._effects.values()

    def producers(self, h: HandleType) -> List[str]:
        return list(self._producers.get(h, ()))

    def consumers(self, h: HandleType) -> List[str]:
        return list(self._consumers.get(h, ()))

    def killers(self, h: HandleType) -> List[str]:
        return list(self._killers.get(h, ()))

    def dependency_depth(self) -> Dict[str, int]:
        """Bellman-Ford-style relaxation on the use-def graph.

            depth(api) = 0,                        if USE(api) = ∅
                       = 1 + max_{H ∈ USE(api)} min_{p ∈ producers(H)} depth(p)

        Cached per graph instance. Capped at ``len(effects)`` passes so
        pathological cycles (rare; would imply non-acyclic API protocols)
        terminate.
        """
        if self._depth_cache is not None:
            return self._depth_cache
        max_depth = max(8, len(self._effects))
        depth: Dict[str, int] = {name: 0 for name in self._effects}
        changed = True
        passes = 0
        while changed and passes < max_depth:
            changed = False
            passes += 1
            for name, eff in self._effects.items():
                if not eff.use:
                    continue
                worst = 0
                for h in eff.use:
                    producers = self._producers.get(h)
                    if not producers:
                        cost = 1  # cross-module: unknown but non-zero
                    else:
                        cost = 1 + min(depth.get(p, max_depth) for p in producers)
                    if cost > worst:
                        worst = cost
                if worst != depth[name]:
                    depth[name] = worst
                    changed = True
        self._depth_cache = depth
        return depth

    def roots(self, h: HandleType, top_k: int = 3) -> List[str]:
        """Top-K root producers for handle ``h``.

        Sorted by ``(dependency_depth, -confidence, len, name)``: depth-0
        producers (true root constructors) win over forwarders/extractors
        whose USE preconditions themselves require an upstream call.
        """
        producers = self._producers.get(h, [])
        if not producers:
            return []
        depth = self.dependency_depth()
        # Best confidence per producer across channels.
        best_conf: Dict[str, float] = {}
        for p in producers:
            eff = self._effects.get(p)
            if not eff:
                continue
            conf = max((prod.confidence for prod in eff.productions
                        if prod.handle == h), default=0.0)
            best_conf[p] = conf
        ordered = sorted(
            best_conf.items(),
            key=lambda kv: (depth.get(kv[0], 0), -kv[1], len(kv[0]), kv[0]),
        )
        return [name for name, _ in ordered[:top_k]]


# =============================================================================
# Typestate interpreter
# =============================================================================

class Typestate:
    """Resource lifecycle automaton. Stateless; queried via ``check``."""

    def __init__(self, graph: UseDefGraph, handle_types=None):
        self.graph = graph
        # Optional project HANDLE-type allow-list (normalized keys). When set,
        # only these types are tracked as lifecycle handles — value-structs
        # (cmsCIEXYZ, png_splt_t) carried by pointer are NOT handles and must not
        # raise USE_BEFORE_INIT (their "producer" is a const getter, and the
        # renderer fills them as value args). Default None = track every effect
        # type (unchanged behavior for L2/L3 and existing callers).
        self.handle_types = handle_types

    def check(self, sequence: List[str]) -> List[ViolationRecord]:
        """Walk a sequence and return all observed violations.

        State per handle ``H`` tracks open count: each DEF increments,
        each KILL decrements. A USE on a handle whose state is uninitialized
        *and* whose count is 0 is USE_BEFORE_INIT; KILL with count 0 is
        DESTROY_BEFORE_INIT or DOUBLE_DESTROY depending on prior state. We
        also flag REINIT_WITHOUT_DESTROY (DEF when count > 0 of same H).
        """
        # state[H] in {UNINIT, INIT, DESTROYED}; open_counts[H] = N
        state: Dict[HandleType, ResourceLifecycleState] = {}
        opens: Dict[HandleType, int] = {}
        violations: List[ViolationRecord] = []
        ht = self.handle_types

        def _h(types):
            if ht is None:
                return types
            return [t for t in types if normalize_handle_type(t) in ht]

        for pos, name in enumerate(sequence):
            eff = self.graph.effect(name)
            if eff is None:
                continue
            _uses, _kills, _defs = _h(eff.use), _h(eff.kill), _h(eff.def_)
            # Process KILLs before DEFs so an in-place re-init pattern
            # (rare; e.g. ``ucl_parser_destroy(p); p = ucl_parser_new();``)
            # is reported as REINIT only when there's no kill.
            for h in _uses:
                cur = state.get(h, ResourceLifecycleState.UNINITIALIZED)
                if cur == ResourceLifecycleState.UNINITIALIZED and opens.get(h, 0) == 0:
                    violations.append(ViolationRecord(
                        kind=ViolationKind.USE_BEFORE_INIT,
                        api_name=name, handle=h, position=pos,
                        expected=ResourceLifecycleState.INITIALIZED, actual=cur,
                    ))
                elif cur == ResourceLifecycleState.DESTROYED and opens.get(h, 0) == 0:
                    violations.append(ViolationRecord(
                        kind=ViolationKind.USE_AFTER_DESTROY,
                        api_name=name, handle=h, position=pos,
                        expected=ResourceLifecycleState.INITIALIZED, actual=cur,
                    ))
            for h in _kills:
                cur = state.get(h, ResourceLifecycleState.UNINITIALIZED)
                if cur == ResourceLifecycleState.UNINITIALIZED and opens.get(h, 0) == 0:
                    violations.append(ViolationRecord(
                        kind=ViolationKind.DESTROY_BEFORE_INIT,
                        api_name=name, handle=h, position=pos,
                        expected=ResourceLifecycleState.INITIALIZED, actual=cur,
                    ))
                elif cur == ResourceLifecycleState.DESTROYED and opens.get(h, 0) == 0:
                    violations.append(ViolationRecord(
                        kind=ViolationKind.DOUBLE_DESTROY,
                        api_name=name, handle=h, position=pos,
                        expected=ResourceLifecycleState.INITIALIZED, actual=cur,
                    ))
                else:
                    opens[h] = max(0, opens.get(h, 0) - 1)
                    if opens[h] == 0:
                        state[h] = ResourceLifecycleState.DESTROYED
            for h in _defs:
                if opens.get(h, 0) > 0:
                    violations.append(ViolationRecord(
                        kind=ViolationKind.REINIT_WITHOUT_DESTROY,
                        api_name=name, handle=h, position=pos,
                        expected=ResourceLifecycleState.DESTROYED,
                        actual=state.get(h, ResourceLifecycleState.INITIALIZED),
                    ))
                opens[h] = opens.get(h, 0) + 1
                state[h] = ResourceLifecycleState.INITIALIZED
        # Trailing checks: any handle still open is unclosed.
        for h, n in opens.items():
            if n > 0:
                violations.append(ViolationRecord(
                    kind=ViolationKind.UNCLOSED_RESOURCE,
                    api_name="", handle=h, position=len(sequence),
                    actual=ResourceLifecycleState.INITIALIZED,
                ))
        return violations


# =============================================================================
# Effect extraction
# =============================================================================

def extract_api_effects(
    project_apis: List[Dict[str, Any]],
    *,
    lifecycle_pairs: Optional[List[Tuple[str, str]]] = None,
    consumed_handle_keys: Optional[Any] = None,
    extract_produced_handles: Optional[Any] = None,
    normalize_handle_type: Optional[Any] = None,
) -> List[APIEffect]:
    """Build APIEffects from project APIs.

    The primitive callables default to the canonical implementations in this
    module (``consumed_handle_keys`` / ``extract_produced_handles`` /
    ``normalize_handle_type``). Callers may still pass overrides for testing,
    but most production callers should omit them.

    ``lifecycle_pairs`` is a list of ``(init_api_name, destroy_api_name)``
    derived from ``LifecycleAnalyzer``. Each pair contributes a KILL edge on
    the destroy API for the handle types its paired init produces.
    """
    # Resolve to module-level defaults; the parameter shadowing is
    # intentional so the body doesn't have to branch on ``None``.
    _consumed = consumed_handle_keys or globals()["consumed_handle_keys"]
    _produced = extract_produced_handles or globals()["extract_produced_handles"]
    _normalize = normalize_handle_type or globals()["normalize_handle_type"]

    # Value-type (enum/scalar) exclusion. A non-primitive identifier like
    # ``cmsTagSignature`` passes ``is_handle_type`` (it isn't a known scalar),
    # so without this it would be counted as a USE'd/produced handle — making
    # ``cmsReadTag`` falsely "require" a cmstagsignature handle (no producer →
    # USE_BEFORE_INIT → the open→ReadTag→close tag-deserializer path is dropped).
    # A resource handle is carried by a pointer (``*`` in the spelling, or
    # ``flag == 'ref'`` once Liberator collapses ``typedef void* H`` to ``H``);
    # an enum/scalar is passed by value. A type NEVER seen by reference but seen
    # by value is a value type, not a handle. Derived from the API set itself —
    # no project enum list needed (``enum_types.txt`` is often empty).
    _ref_types: Set[str] = set()
    _val_types: Set[str] = set()
    for api in project_apis:
        for arg in (api.get("arguments", api.get("arguments_info", [])) or []):
            atype = arg.get("type", arg.get("type_clang", "")) or ""
            key = _normalize(atype)
            if not key:
                continue
            is_ptr = "*" in atype or (arg.get("flag") or "").lower() == "ref"
            if is_ptr:
                _ref_types.add(key)
            elif (arg.get("flag") or "").lower() in ("val", ""):
                _val_types.add(key)
    _value_types = _val_types - _ref_types

    effects: Dict[str, APIEffect] = {}
    for api in project_apis:
        name = api.get('function_name', '')
        if not name:
            continue
        use_set = frozenset(_consumed(api)) - _value_types
        # Iterator / forwarder exclusion: a production for handle H is dropped
        # when H is also USE'd by the same API (e.g. ``sqlite3_next_stmt(stmt*)
        # → stmt*``). Such an API traverses an existing instance rather than
        # creating one; treating it as a producer would let the dependency-depth
        # fixpoint pick it as a substitute root, which is wrong.
        #
        # Modelled as a graph-construction rule (``produces ∩ consumes = ∅``)
        # so it composes with downstream queries instead of being a special
        # case in the ranker.
        raw_productions = list(_produced(api))
        _chan = {0: _Channel.RETURN, 1: _Channel.OUT_POINTER, 2: _Channel.INIT}
        productions = tuple(
            HandleProduction(
                handle=h, channel=_chan.get(ch, _Channel.OUT_POINTER),
                confidence=float(conf),
            )
            for h, ch, conf in raw_productions
            # produces ∩ consumes = ∅ (iterator/forwarder exclusion) — EXEMPT the
            # INIT channel (ch==2): an in-place initializer legitimately both
            # reads and writes the caller-declared struct it produces.
            if (ch == 2 or h not in use_set) and h not in _value_types
        )
        # A caller-alloc initializer is the ORIGIN of the struct it sets up, not
        # a consumer of a pre-existing one: drop the INIT-produced handle from
        # its USE set so the role reconciler reads it as CREATOR (produces ∧
        # ¬requires, not MUTATOR) and ``_build_prefix`` — which only chains
        # CREATORs — will prepend it (``deflateInit_`` before ``deflate``).
        _init_handles = {p.handle for p in productions if p.channel is _Channel.INIT}
        if _init_handles:
            use_set = use_set - _init_handles
        def_set = frozenset(p.handle for p in productions)
        effects[name] = APIEffect(
            name=name, use=use_set, def_=def_set,
            productions=productions, raw=api,
        )

    # Demote INIT-channel productions for any handle type that already has a
    # real (return / out-pointer) creator: the genuine factory wins, and the
    # init-named API reverts to a plain consumer of an externally-produced
    # handle. This keeps the caller-alloc channel from competing with a proper
    # creator (only fires for types like z_stream that have NO other producer).
    real_produced = {
        p.handle for e in effects.values() for p in e.productions
        if p.channel in (_Channel.RETURN, _Channel.OUT_POINTER)
    }
    if real_produced:
        for nm, e in list(effects.items()):
            kept = tuple(p for p in e.productions
                         if not (p.channel is _Channel.INIT
                                 and p.handle in real_produced))
            if len(kept) != len(e.productions):
                effects[nm] = APIEffect(
                    name=e.name, use=e.use,
                    def_=frozenset(p.handle for p in kept),
                    productions=kept, raw=e.raw,
                )

    # Apply lifecycle pairs as KILL edges on the destroy side. The destroy
    # API's KILL set picks up every handle the paired init API DEFs (handles
    # the common "init and destroy share a handle type" case naturally; if a
    # destroy API legitimately kills multiple handle types — e.g. a unified
    # cleanup — repeated pair entries accumulate them).
    if lifecycle_pairs:
        for init_name, destroy_name in lifecycle_pairs:
            init_eff = effects.get(init_name)
            destroy_eff = effects.get(destroy_name)
            if init_eff is None or destroy_eff is None:
                continue
            new_kill = frozenset(destroy_eff.kill | init_eff.def_)
            if new_kill != destroy_eff.kill:
                effects[destroy_name] = APIEffect(
                    name=destroy_eff.name,
                    use=destroy_eff.use,
                    def_=destroy_eff.def_,
                    kill=new_kill,
                    productions=destroy_eff.productions,
                    input_category=destroy_eff.input_category,
                    handle_arg_index=destroy_eff.handle_arg_index,
                    handle_arg_type=destroy_eff.handle_arg_type,
                    raw=destroy_eff.raw,
                )
    return list(effects.values())


# =============================================================================
# Post-DEF sequence extension (Phase E: Post-Parse Sequence Extension)
# =============================================================================
#
# Many sequences synthesized at L0 stop at parse / get_object (e.g. for libucl,
# the Top-K is dominated by ``[ucl_parser_new, ucl_parser_add_chunk]``). The
# typestate model already gives us everything needed to walk past that
# boundary: a handle DEF'd by a creator is *live* until KILL'd, and any API
# whose USE set is a subset of the live set is a typestate-feasible next step.
#
# Reference: Aho/Sethi/Ullman §9 (reaching definitions) — the live-handle set
# is the analogue of "in-scope reaching defs"; consumers of those handles are
# the legal extensions. Strom/Yemini Typestate 1986 §3 — the typestate
# precondition check is exactly ``USE ⊆ live ∧ no kill-then-use``.


def extend_post_def(
    graph: "UseDefGraph",
    typestate: "Typestate",
    sequence: List[str],
    depth: int = 2,
    branching: int = 4,
) -> List[List[str]]:
    """Extend ``sequence`` with downstream consumer chains.

    For each handle still live (open count > 0) at the end of ``sequence``,
    enumerate APIs whose USE set is satisfied by the live set, append them,
    and recurse up to ``depth``. ``branching`` caps fan-out per recursion
    step. The full extended sequence is validated by ``Typestate.check`` —
    only ``UNCLOSED_RESOURCE`` is tolerated as a trailing artifact, all other
    violations cause the candidate to be dropped.

    Returns full extended sequences (i.e. ``sequence ++ chain``), deduped.
    Returns ``[]`` when no handle is live or no feasible chain exists.

    Determinism: candidate ordering is ``(-graph.dependency_depth(api), api_name)``
    — deeper consumers (further from the root constructor) win, with
    name as the lex tiebreaker. This keeps the same input deterministic
    across runs and biases toward APIs that the dependency-depth fixpoint
    classified as terminal/leaf operations.
    """
    if depth <= 0 or not sequence:
        return []

    # Walk the input sequence to compute the running open count per handle.
    # Same accounting as Typestate.check (kill before def, max(0, n-1) on KILL).
    open_counts: Dict[HandleType, int] = {}
    for name in sequence:
        eff = graph.effect(name)
        if eff is None:
            continue
        for h in eff.kill:
            open_counts[h] = max(0, open_counts.get(h, 0) - 1)
        for h in eff.def_:
            open_counts[h] = open_counts.get(h, 0) + 1

    if not any(n > 0 for n in open_counts.values()):
        return []

    depth_map = graph.dependency_depth()
    seq_set = set(sequence)
    extensions: List[List[str]] = []
    seen: Set[Tuple[str, ...]] = set()

    def _live(counts: Dict[HandleType, int]) -> Set[HandleType]:
        return {h for h, n in counts.items() if n > 0}

    def _candidates(live: Set[HandleType], used: Set[str]) -> List[str]:
        seen_apis: Set[str] = set()
        scored: List[Tuple[str, int]] = []
        for h in live:
            for c in graph.consumers(h):
                if c in seq_set or c in used or c in seen_apis:
                    continue
                eff = graph.effect(c)
                if eff is None:
                    continue
                # USE must be fully covered by currently live handles —
                # otherwise we'd need yet another upstream call (which is
                # what graft_creator_prefix handles for the reverse case).
                if not eff.use.issubset(live):
                    continue
                seen_apis.add(c)
                scored.append((c, depth_map.get(c, 0)))
        scored.sort(key=lambda kv: (-kv[1], kv[0]))
        return [c for c, _ in scored[:branching]]

    def _recurse(prefix: List[str], counts: Dict[HandleType, int],
                 used_in_chain: Set[str], remaining: int) -> None:
        if remaining <= 0:
            return
        live = _live(counts)
        if not live:
            return
        for c in _candidates(live, used_in_chain):
            extended = prefix + [c]
            # Full typestate validation; UNCLOSED_RESOURCE is a tail artifact
            # (handles still open at end), which is acceptable for fuzz
            # drivers — caller's outer scope owns the cleanup.
            violations = typestate.check(extended)
            if any(v.kind != ViolationKind.UNCLOSED_RESOURCE for v in violations):
                continue
            key = tuple(extended)
            if key not in seen:
                seen.add(key)
                extensions.append(extended)
            # Compute new open counts for recursion.
            eff = graph.effect(c)
            new_counts = dict(counts)
            if eff is not None:
                for h in eff.kill:
                    new_counts[h] = max(0, new_counts.get(h, 0) - 1)
                for h in eff.def_:
                    new_counts[h] = new_counts.get(h, 0) + 1
            _recurse(extended, new_counts, used_in_chain | {c}, remaining - 1)

    _recurse(list(sequence), dict(open_counts), set(), depth)
    return extensions
