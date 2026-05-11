"""Static trace extraction with intra-function value-flow tracking.

For each .c / .cpp file under a set of consumer paths, libclang parses the
translation unit, then for every function definition we walk the body in
source order and emit:

    StaticTrace = {
        function_name, file, line,
        api_calls: [CallSite(api_name, line, arg_bindings, return_var_id)]
    }

``arg_bindings[i] = "<call_id>"`` records that argument ``i`` of the call is
a DeclRefExpr to a local variable that was last assigned by the call with
``<call_id>``. ``return_var_id`` records the variable name the call's return
value was assigned to (if any). This is exactly the def-use chain that the
P1+ automaton will need.

The extractor is deliberately simple: intra-function flow only (no
inter-procedural), no SSA, no alias analysis. It catches the common pattern
``handle = init(); use(handle);`` which is what we care about for typestate
inference. Heavier analysis is the job of Liberator's Z3+Provenance modules
once we wire P1.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from clang.cindex import Cursor, CursorKind, Index, TranslationUnit
except ImportError as e:
    raise SystemExit(
        "libclang Python bindings missing. Install with: pip install libclang"
    ) from e

logger = logging.getLogger(__name__)

# Suffix sets we treat as parseable source.
SRC_C_EXTS = {".c"}
SRC_CXX_EXTS = {".cc", ".cpp", ".cxx", ".cppm"}
SRC_EXTS = SRC_C_EXTS | SRC_CXX_EXTS

# C/C++ reserved keywords excluded from the token-based callee fallback
# in ``FunctionBodyWalker._try_extract_callee``. Mostly defensive — a
# well-formed ``identifier(args)`` call won't have a keyword as its
# first identifier token, but cast-style calls like
# ``((cast_t)func)(args)`` or sizeof-expr arguments could otherwise
# trip us up.
_C_RESERVED_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "return", "goto", "sizeof", "typedef",
    "struct", "union", "enum", "static", "extern", "register", "auto",
    "const", "volatile", "restrict", "inline", "void", "char", "short",
    "int", "long", "signed", "unsigned", "float", "double", "_Bool",
    "_Complex", "_Atomic", "_Alignof", "_Alignas", "_Generic",
    "_Thread_local", "_Noreturn",
    # C++ extras
    "class", "namespace", "template", "typename", "new", "delete",
    "this", "operator", "public", "private", "protected", "virtual",
    "friend", "explicit", "mutable", "using", "throw", "try", "catch",
    "nullptr", "true", "false",
})


@dataclass
class CallSite:
    api_name: str
    file: str
    line: int
    call_id: str  # unique per-trace id, "<func>:<line>:<col>"
    arg_bindings: Dict[int, str] = field(default_factory=dict)
    return_var: Optional[str] = None
    n_handle_arg_slots: int = 0   # filled by run_survey using project_apis
    n_bound_handle_args: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api_name": self.api_name,
            "line": self.line,
            "call_id": self.call_id,
            "arg_bindings": self.arg_bindings,
            "return_var": self.return_var,
            "n_handle_arg_slots": self.n_handle_arg_slots,
            "n_bound_handle_args": self.n_bound_handle_args,
        }


@dataclass
class StaticTrace:
    function_name: str
    file: str
    line: int
    api_calls: List[CallSite] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.api_calls)

    @property
    def n_bound_args(self) -> int:
        return sum(len(c.arg_bindings) for c in self.api_calls)

    @property
    def n_total_args(self) -> int:
        # Caller fills in actual arg count; we only track bindings.
        return self.n_bound_args  # placeholder; report carries the real total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file": self.file,
            "line": self.line,
            "api_calls": [c.to_dict() for c in self.api_calls],
        }


@dataclass
class ProjectTraceReport:
    project: str
    consumer_paths: List[str]
    n_files_attempted: int = 0
    n_files_parsed: int = 0
    n_functions_visited: int = 0
    n_traces: int = 0  # functions with >= 2 public API calls
    n_total_calls: int = 0
    n_unique_apis_called: int = 0
    # All-arg metric (denominator = every arg slot, including int/string literals).
    # Useful as a sanity floor.
    n_total_args: int = 0
    n_bound_args: int = 0
    # Handle-arg metric (denominator = arg slots whose declared type is a handle
    # per the public API signature). This is the value-flow metric the design
    # doc's 80% threshold targets.
    n_handle_arg_slots: int = 0
    n_bound_handle_args: int = 0
    api_calls_per_trace_p50: int = 0
    api_calls_per_trace_max: int = 0
    sample_traces: List[StaticTrace] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

    @property
    def binding_hit_rate(self) -> float:
        return (self.n_bound_args / self.n_total_args) if self.n_total_args else 0.0

    @property
    def handle_binding_hit_rate(self) -> float:
        return ((self.n_bound_handle_args / self.n_handle_arg_slots)
                if self.n_handle_arg_slots else 0.0)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["binding_hit_rate"] = round(self.binding_hit_rate, 3)
        d["handle_binding_hit_rate"] = round(self.handle_binding_hit_rate, 3)
        d["sample_traces"] = [t.to_dict() for t in self.sample_traces]
        return d


# =============================================================================
# Per-translation-unit walker
# =============================================================================

class FunctionBodyWalker:
    """Visit one function body, build (var → last-defining-call) flow map,
    emit ordered CallSites for any callee whose name is in ``public_apis``.

    ``handle_arg_idx_map[api_name]`` is the set of arg slot indices whose
    declared type is a handle (opaque pointer / typedef). Used to compute
    the handle-arg binding hit-rate metric.
    """

    def __init__(self,
                 public_apis: Set[str],
                 file_str: str,
                 func_name: str,
                 handle_arg_idx_map: Optional[Dict[str, Set[int]]] = None,
                 global_to_call: Optional[Dict[str, str]] = None):
        self.public_apis = public_apis
        self.file_str = file_str
        self.func_name = func_name
        self.handle_arg_idx_map: Dict[str, Set[int]] = handle_arg_idx_map or {}
        # Local var DEF chain. Keys can be:
        #   "name"           — plain local var
        #   "obj.field"      — struct field accessed via . or ->
        # Values are the call_id (or synthetic id for params/globals/extern DEFs).
        self.var_to_call: Dict[str, str] = {}
        # TU-level globals/statics that have been recorded as defined elsewhere.
        # Read at every var lookup so a `static sqlite3 *g_db = open();` defined
        # in the same file becomes visible to any function using ``g_db``.
        self.global_to_call: Dict[str, str] = global_to_call or {}
        self.calls: List[CallSite] = []
        self.total_args_in_public_calls = 0
        self.total_handle_arg_slots = 0
        self.total_bound_handle_args = 0

    @staticmethod
    def _call_id(file_str: str, line: int, col: int) -> str:
        return f"{Path(file_str).name}:{line}:{col}"

    def _record_var_assignment(self, var_name: str, call_id: str) -> None:
        if var_name:
            self.var_to_call[var_name] = call_id

    def _try_extract_callee(self, call_cursor: Cursor) -> Optional[str]:
        """Return the simple callee name of a CallExpr if recognizable.

        Resolution order (descending fidelity):
          1. ``cursor.spelling`` — method calls and well-resolved
             function calls.
          2. Walk children for the first ``DECL_REF_EXPR`` /
             ``MEMBER_REF_EXPR`` with a non-empty ``spelling``.
          3. Recurse into ``UNEXPOSED_EXPR`` children.
          4. **Token fallback (2026-05 fix)**: when the call sits on
             the right-hand side of a variable initialization with a
             struct-typed target (``struct cJSON *json = cJSON_ParseWithOpts(...)``)
             AND the project header isn't on the parse path, libclang
             leaves both ``spelling`` and ``referenced`` empty on the
             function child. The lexical token stream still carries
             the identifier — first identifier-shaped token at the
             call's location is the callee name. Cheaper than a full
             re-parse with discovered include paths, and accurate for
             the standard ``identifier(args)`` call form.
        """
        # Step 1: direct spelling.
        spelling = call_cursor.spelling
        if spelling:
            return spelling

        # Step 2/3: walk children.
        for child in call_cursor.get_children():
            if child.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
                if child.spelling:
                    return child.spelling
            elif child.kind == CursorKind.UNEXPOSED_EXPR:
                inner = self._try_extract_callee(child)
                if inner:
                    return inner

        # Step 4: token fallback.
        try:
            tokens = list(call_cursor.get_tokens())
        except Exception:
            return None
        for tok in tokens:
            spelling = tok.spelling
            # Identifier tokens carry the function name. The first
            # identifier in the call's token stream is the callee; the
            # opening ``(`` follows directly. We reject obvious keywords
            # to avoid mis-parsing on cast-style calls like
            # ``(funcptr_t)(...)`` where the first token might be ``(``.
            if not spelling or not spelling[0].isalpha() and spelling[0] != '_':
                continue
            if spelling in _C_RESERVED_KEYWORDS:
                continue
            return spelling
        return None

    def _arg_var_name(self, arg_cursor: Cursor) -> Optional[str]:
        """Best-effort name path for a memory location referenced by an arg.

        Recognises::

            varname              -> "varname"
            &varname             -> "varname"
            *varname             -> "varname"
            obj.field            -> "obj.field"
            obj->field           -> "obj.field"
            &obj->field          -> "obj.field"
            (cast)expr           -> recurse on expr
            (parens)expr         -> recurse on expr

        Returning a *path* (not just a leaf name) lets the walker bind
        ``ctx->db`` slots to whatever previously DEF'd ``ctx->db``. Without
        this, the common pattern of a test fixture struct holding the handle
        is invisible and shows as "unbound".
        """
        if arg_cursor is None:
            return None
        kind = arg_cursor.kind
        if kind == CursorKind.DECL_REF_EXPR:
            return arg_cursor.spelling or None
        if kind == CursorKind.MEMBER_REF_EXPR:
            field = arg_cursor.spelling or ""
            # First child is the object expression (obj or *obj).
            children = list(arg_cursor.get_children())
            if children and field:
                base = self._arg_var_name(children[0])
                if base:
                    return f"{base}.{field}"
            return field or None
        # Walk through unary / paren / cast wrappers
        for child in arg_cursor.get_children():
            n = self._arg_var_name(child)
            if n:
                return n
        return None

    def _resolve_var(self, name: Optional[str]) -> Optional[str]:
        """Look up the most recent DEF call_id for a var path.

        Local DEFs win over globals (shadowing). Falls back to the TU-level
        global symbol map populated during the pre-pass.
        """
        if not name:
            return None
        if name in self.var_to_call:
            return self.var_to_call[name]
        # Strip a single leading object qualifier and try again — handles
        # ``self.handle`` / ``this->handle`` style indirection where the outer
        # object isn't itself a tracked symbol.
        if "." in name:
            tail = name.split(".", 1)[1]
            if tail in self.var_to_call:
                return self.var_to_call[tail]
        if name in self.global_to_call:
            return self.global_to_call[name]
        return None

    @staticmethod
    def _is_addr_of(arg_cursor: Cursor) -> bool:
        """True if ``arg_cursor`` is a unary ``&expr`` (out-pointer pattern).

        libclang doesn't expose unary opcode directly via the Python bindings,
        so we read the source tokens of the cursor's extent. Cheap and
        sufficient for our intra-function use.
        """
        try:
            tokens = list(arg_cursor.get_tokens())
        except Exception:
            return False
        if not tokens:
            return False
        return tokens[0].spelling == "&"

    def _process_call(self, cursor: Cursor) -> Optional[CallSite]:
        callee = self._try_extract_callee(cursor)
        if callee is None or callee not in self.public_apis:
            return None
        loc = cursor.location
        call_id = self._call_id(self.file_str, loc.line, loc.column)
        # Iterate the *argument* children only (skip the callee child).
        arg_children: List[Cursor] = list(cursor.get_arguments()) \
            if hasattr(cursor, "get_arguments") else []
        if not arg_children:
            # fallback for older bindings
            arg_children = [c for c in cursor.get_children() if c.kind not in (
                CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR,
            )][1:]
        handle_slots = self.handle_arg_idx_map.get(callee, set())
        bindings: Dict[int, str] = {}
        n_handle_slots_here = 0
        n_bound_handle_here = 0
        for i, arg in enumerate(arg_children):
            self.total_args_in_public_calls += 1
            is_handle_slot = i in handle_slots
            if is_handle_slot:
                n_handle_slots_here += 1
            var = self._arg_var_name(arg)
            if var is None:
                continue
            if self._is_addr_of(arg):
                # Out-pointer: this call DEFs the var. Record so downstream
                # uses of the same var resolve back to this call. Out-pointer
                # slot counts as bound (caller writes the handle here).
                self._record_var_assignment(var, call_id)
                if is_handle_slot:
                    n_bound_handle_here += 1
            else:
                # Read of a previously defined var (local, struct field, or
                # global) → bind this arg slot.
                src = self._resolve_var(var)
                if src is not None:
                    bindings[i] = src
                    if is_handle_slot:
                        n_bound_handle_here += 1
        self.total_handle_arg_slots += n_handle_slots_here
        self.total_bound_handle_args += n_bound_handle_here
        return CallSite(
            api_name=callee,
            file=str(self.file_str),
            line=loc.line,
            call_id=call_id,
            arg_bindings=bindings,
            n_handle_arg_slots=n_handle_slots_here,
            n_bound_handle_args=n_bound_handle_here,
        )

    def _visit_node(self, cursor: Cursor) -> None:
        kind = cursor.kind
        if kind == CursorKind.VAR_DECL:
            # ``T x = call(...);``  — record the binding.
            for child in cursor.get_children():
                if child.kind == CursorKind.CALL_EXPR:
                    cs = self._process_call(child)
                    if cs is not None:
                        self.calls.append(cs)
                        self._record_var_assignment(cursor.spelling, cs.call_id)
                        cs.return_var = cursor.spelling or None
                else:
                    self._visit_node(child)
            return
        if kind == CursorKind.BINARY_OPERATOR:
            # ``x = call(...);`` — try to match
            children = list(cursor.get_children())
            if len(children) == 2:
                lhs, rhs = children
                if rhs.kind == CursorKind.CALL_EXPR:
                    var_name = self._arg_var_name(lhs)
                    cs = self._process_call(rhs)
                    if cs is not None:
                        self.calls.append(cs)
                        if var_name:
                            self._record_var_assignment(var_name, cs.call_id)
                            cs.return_var = var_name
                    # Continue into LHS for nested bindings
                    self._visit_node(lhs)
                    return
        if kind == CursorKind.CALL_EXPR:
            cs = self._process_call(cursor)
            if cs is not None:
                self.calls.append(cs)
            # Walk into args anyway (nested calls)
            for child in cursor.get_children():
                self._visit_node(child)
            return
        for child in cursor.get_children():
            self._visit_node(child)

    def seed_parameter_defs(self, function_cursor: Cursor) -> None:
        """Treat the function's own parameters as DEF sites from the caller's
        scope. Without this we'd miss the very common pattern of a test
        helper that receives an already-opened handle::

            void run_query(sqlite3 *db, const char *sql) {
                sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);  // 'db' is bound
            }
        """
        for child in function_cursor.get_children():
            if child.kind != CursorKind.PARM_DECL:
                continue
            name = child.spelling
            if not name:
                continue
            param_id = f"param:{self.func_name}:{name}"
            self._record_var_assignment(name, param_id)

    def walk(self, body_cursor: Cursor) -> None:
        for child in body_cursor.get_children():
            self._visit_node(child)


# =============================================================================
# Project-level driver
# =============================================================================

def _enumerate_source_files(source_root: Path,
                            relative_paths: List[str]) -> List[Path]:
    """Resolve consumer_case_paths into a flat list of .c/.cpp files."""
    out: List[Path] = []
    for rel in relative_paths:
        target = source_root / rel
        if not target.exists():
            # Try case-insensitive match
            parent = source_root if "/" not in rel else source_root / Path(rel).parent
            tail = Path(rel).name
            if parent.exists():
                for p in parent.iterdir():
                    if p.name.lower() == tail.lower():
                        target = p
                        break
        if not target.exists():
            continue
        if target.is_file():
            if target.suffix.lower() in SRC_EXTS:
                out.append(target)
            continue
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in SRC_EXTS:
                out.append(p)
    return out


def _parse_translation_unit(index: Index,
                            file_path: Path,
                            include_dirs: List[Path],
                            extra_args: List[str]) -> Optional[TranslationUnit]:
    args = []
    for inc in include_dirs:
        args += ["-I", str(inc)]
    args += extra_args
    args += ["-ferror-limit=0"]
    if file_path.suffix.lower() in SRC_CXX_EXTS:
        args += ["-x", "c++", "-std=c++17"]
    else:
        args += ["-x", "c"]
    try:
        return index.parse(
            str(file_path),
            args=args,
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            | TranslationUnit.PARSE_INCOMPLETE
            | TranslationUnit.PARSE_SKIP_FUNCTION_BODIES & 0,
        )
    except Exception as e:
        logger.debug("parse failed for %s: %s", file_path, e)
        return None


def _function_definitions(tu: TranslationUnit) -> List[Cursor]:
    """All FUNCTION_DECL / CXX_METHOD with a body in this TU."""
    out: List[Cursor] = []
    main_file = tu.spelling
    for cursor in tu.cursor.walk_preorder():
        if cursor.kind not in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.FUNCTION_TEMPLATE,
        ):
            continue
        if not cursor.is_definition():
            continue
        loc = cursor.location
        if loc.file is None or loc.file.name != main_file:
            continue  # skip headers brought in by includes
        # Find a COMPOUND_STMT child = the body
        body = None
        for child in cursor.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                body = child
                break
        if body is None:
            continue
        out.append(cursor)
    return out


def _scan_globals(tu: TranslationUnit,
                  public_apis: Set[str]) -> Dict[str, str]:
    """File-scope ``static T *g = call();`` style DEFs.

    Returns ``{var_name → synthetic_call_id}``. The id format mirrors the
    intra-function call_id so downstream consumers can attribute bindings to
    these without special casing.
    """
    out: Dict[str, str] = {}
    main_file = tu.spelling
    for cursor in tu.cursor.walk_preorder():
        if cursor.kind != CursorKind.VAR_DECL:
            continue
        loc = cursor.location
        if loc.file is None or loc.file.name != main_file:
            continue
        # File scope only (not within a function body). Heuristic: the parent
        # via libclang isn't directly accessible; use semantic_parent which
        # for a file-scope decl is the TU.
        try:
            parent = cursor.semantic_parent
        except Exception:
            continue
        if parent is None or parent.kind != CursorKind.TRANSLATION_UNIT:
            continue
        name = cursor.spelling
        if not name:
            continue
        # Look for a CallExpr in the initializer; if its callee is a public
        # API, record the binding.
        for child in cursor.get_children():
            if child.kind != CursorKind.CALL_EXPR:
                continue
            callee = None
            spelling = child.spelling
            if spelling and spelling in public_apis:
                callee = spelling
            else:
                for grand in child.get_children():
                    if grand.kind in (CursorKind.DECL_REF_EXPR,
                                      CursorKind.MEMBER_REF_EXPR):
                        if grand.spelling in public_apis:
                            callee = grand.spelling
                            break
            if callee is None:
                continue
            cloc = child.location
            call_id = f"{Path(main_file).name}:{cloc.line}:{cloc.column}"
            out[name] = call_id
            break
    return out


def extract_project_traces(
    project: str,
    source_root: Path,
    consumer_paths: List[str],
    public_apis: Set[str],
    handle_arg_idx_map: Optional[Dict[str, Set[int]]] = None,
    include_dirs: Optional[List[Path]] = None,
    extra_clang_args: Optional[List[str]] = None,
    sample_size: int = 8,
    file_limit: Optional[int] = None,
) -> ProjectTraceReport:
    include_dirs = include_dirs or []
    extra_clang_args = extra_clang_args or []
    files = _enumerate_source_files(source_root, consumer_paths)
    if file_limit is not None:
        files = files[:file_limit]
    report = ProjectTraceReport(project=project, consumer_paths=consumer_paths)
    report.n_files_attempted = len(files)

    index = Index.create()
    api_seen: Set[str] = set()
    per_trace_lengths: List[int] = []

    for fp in files:
        tu = _parse_translation_unit(index, fp, include_dirs, extra_clang_args)
        if tu is None:
            report.parse_errors.append(f"parse_failed:{fp}")
            continue
        report.n_files_parsed += 1
        # Pre-pass: file-scope globals/statics whose initializers are public
        # API calls (e.g. ``static sqlite3 *g_db = sqlite3_open(...);``).
        # These DEFs are visible to every function in the same TU.
        global_defs = _scan_globals(tu, public_apis)
        for func in _function_definitions(tu):
            report.n_functions_visited += 1
            walker = FunctionBodyWalker(
                public_apis=public_apis,
                file_str=str(fp),
                func_name=func.spelling,
                handle_arg_idx_map=handle_arg_idx_map,
                global_to_call=global_defs,
            )
            walker.seed_parameter_defs(func)
            for child in func.get_children():
                if child.kind == CursorKind.COMPOUND_STMT:
                    walker.walk(child)
                    break
            if len(walker.calls) >= 2:
                trace = StaticTrace(
                    function_name=func.spelling,
                    file=str(fp.relative_to(source_root))
                          if fp.is_relative_to(source_root) else str(fp),
                    line=func.location.line,
                    api_calls=walker.calls,
                )
                report.n_traces += 1
                report.n_total_calls += len(walker.calls)
                report.n_total_args += walker.total_args_in_public_calls
                report.n_bound_args += sum(len(c.arg_bindings) for c in walker.calls)
                report.n_handle_arg_slots += walker.total_handle_arg_slots
                report.n_bound_handle_args += walker.total_bound_handle_args
                api_seen.update(c.api_name for c in walker.calls)
                per_trace_lengths.append(len(walker.calls))
                if len(report.sample_traces) < sample_size:
                    report.sample_traces.append(trace)
    report.n_unique_apis_called = len(api_seen)
    if per_trace_lengths:
        per_trace_lengths.sort()
        report.api_calls_per_trace_p50 = per_trace_lengths[len(per_trace_lengths) // 2]
        report.api_calls_per_trace_max = per_trace_lengths[-1]
    return report
