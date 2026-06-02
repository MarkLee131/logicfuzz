"""Recover typedef'd opaque-handle identity lost to IR/clang canonicalization.

**Root cause this repairs.** Liberator's symbol extractor expands typedefs to
their underlying type (``Type.underlying_typedef_type.spelling`` in
``liberator/tool/misc/extract_included_functions.py``), so an opaque handle
declared as ``typedef void* cmsHPROFILE`` collapses to ``void *`` (and the
LLVM-IR side to ``i8 *``). The handle classifier
(:func:`usedef.is_handle_type`) then rejects every such slot as a non-handle,
so the per-API ``produces`` / ``requires`` / ``destroys`` handle edges are all
empty and the dependency graph for such a library is *empty*. For lcms every
opaque handle is ``void*`` (``cmsHPROFILE`` / ``cmsHTRANSFORM`` / ``cmsHANDLE``
/ ``cmsContext``), so creator->consumer->destroyer chains (e.g.
``cmsOpenProfileFromMem -> cmsReadTag -> cmsCloseProfile`` — the ``cmstypes.c``
tag-deserializer coverage path) can never be constructed.

**The fix.** The project's public headers and ``exported_functions.txt`` keep
the *typedef spelling* (the latter via libclang ``displayname``). We re-type the
collapsed slots back to that spelling, which the dependency resolver CAN
distinguish (``cmsHPROFILE`` != ``cmsHTRANSFORM``), so there is no
void*-over-connection.

**Safety (minimal blast radius).** We only ever *upgrade* a slot whose current
type is a collapsed opaque pointer (bare token in :data:`_COLLAPSED_BARE`) to a
typedef whose bare token is non-primitive. We never downgrade, never touch an
already-specific type, and never touch a byte buffer — the header declares those
as ``const void *`` and they stay ``void *`` (their recovered bare token is
``void``, which fails the upgrade gate). Functions absent from the recovered
signature map are left untouched, and a library with no void*-typedef handles
sees zero changes. Disable at the call site via
``LOGICFUZZ_DISABLE_TYPEDEF_RECOVERY=1``.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Sequence

from liberator_adapter.analysis.usedef import _NON_HANDLE_PRIMITIVES

# Bare tokens of a *collapsed* opaque pointer — the only slots we may upgrade.
# ``void`` (clang canonical) and ``i8`` (LLVM-IR) are the two forms Liberator
# emits for a typedef'd ``void*`` handle.
_COLLAPSED_BARE = {"void", "i8"}

# Storage / qualifier tokens to strip from a header return spelling. Export
# macros (``CMSAPI`` / ``CMSEXPORT`` / ``__declspec`` ...) are dropped
# generically as all-caps identifiers; this set covers the lowercase ones.
_DECOR_TOKENS = {
    "extern", "static", "inline", "__inline", "__inline__",
    "__forceinline", "__cdecl", "__stdcall",
}

# A C function prototype: <return + decorations> <name> ( <args> ) ;
# Non-greedy return, DOTALL so multi-line prototypes match; ``[^;{}]`` on the
# argument list keeps a single declaration from spilling into the next.
_PROTO_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_\s\*\&]*?)\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*;",
    re.DOTALL,
)


def _bare(type_str: str) -> str:
    """Lowercased identifier of a type with pointers/qualifiers stripped."""
    return (type_str.replace("const", " ")
            .replace("volatile", " ")
            .replace("struct", " ")
            .replace("union", " ")
            .replace("*", " ")
            .replace("&", " ")
            .strip().lower())


def _split_top_level(args: str) -> List[str]:
    """Split an argument list on top-level commas (tolerates nested parens)."""
    out: List[str] = []
    depth = 0
    cur = ""
    for ch in args:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [a.strip() for a in out]


def parse_exported_args(path: str) -> Dict[str, List[str]]:
    """``name(type, type, ...)`` lines → ``{name: [arg_type, ...]}``.

    ``exported_functions.txt`` is the one extractor artifact that preserves the
    typedef spelling (libclang ``displayname``), but it carries no return type.
    """
    out: Dict[str, List[str]] = {}
    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        m = re.match(r"([A-Za-z_]\w*)\s*\((.*)\)\s*$", line)
        if not m:
            continue
        fn, args = m.group(1), m.group(2).strip()
        if not args or args == "void":
            out[fn] = []
        else:
            out[fn] = _split_top_level(args)
    return out


def _clean_return(raw: str) -> str:
    """Reduce a header return-spelling-plus-decorations to the bare type."""
    raw = re.sub(r"__attribute__\s*\(\(.*?\)\)", " ", raw, flags=re.DOTALL)
    raw = re.sub(r"__declspec\s*\([^)]*\)", " ", raw)
    toks: List[str] = []
    for t in raw.replace("*", " * ").split():
        if t == "*":
            toks.append("*")
            continue
        if t in _DECOR_TOKENS:
            continue
        # Export macros are conventionally all-caps identifiers (CMSAPI, ...).
        if len(t) > 1 and t.isupper() and t.replace("_", "").isalnum():
            continue
        toks.append(t)
    s = " ".join(toks)
    return re.sub(r"\s*\*\s*", " *", s).strip()


def parse_header_returns(
    header_text: str, known_names: Sequence[str]
) -> Dict[str, str]:
    """Header prototypes → ``{func: return_type}`` for *known* functions only.

    Imprecise matches are harmless: only names in ``known_names`` are kept, and
    the caller only ever upgrades collapsed opaque pointers, so a garbled return
    spelling simply fails the upgrade gate.
    """
    names = set(known_names)
    text = re.sub(r"/\*.*?\*/", " ", header_text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    out: Dict[str, str] = {}
    for m in _PROTO_RE.finditer(text):
        name = m.group(2)
        if name not in names or name in out:
            continue
        ret = _clean_return(m.group(1))
        if ret:
            out[name] = ret
    return out


def build_signature_map(
    known_names: Sequence[str],
    *,
    exported_functions: Optional[str] = None,
    header_paths: Optional[Sequence[str]] = None,
) -> Dict[str, Dict[str, object]]:
    """Merge typedef-preserving sources → ``{func: {'return', 'args'}}``.

    Args come from ``exported_functions.txt`` (authoritative typedef spellings);
    returns come from the public headers (the only source that keeps them).
    """
    args_map: Dict[str, List[str]] = {}
    if exported_functions and os.path.exists(exported_functions):
        args_map = parse_exported_args(exported_functions)

    ret_map: Dict[str, str] = {}
    for h in (header_paths or []):
        if h and os.path.exists(h):
            try:
                with open(h, "r", errors="replace") as fh:
                    ret_map.update(
                        parse_header_returns(fh.read(), known_names))
            except OSError:
                continue

    sig: Dict[str, Dict[str, object]] = {}
    for fn in set(args_map) | set(ret_map):
        sig[fn] = {"return": ret_map.get(fn, ""), "args": args_map.get(fn, [])}
    return sig


def recover_from_extract_metadata(
    project_apis: Sequence[Dict[str, object]],
    extract_metadata: Optional[Dict[str, object]],
) -> int:
    """Resolve the header / exported-functions paths from Liberator's
    ``extract_metadata['local']`` and run :func:`recover_handle_types`.

    Reuses the same ``headers_dir`` / ``public_headers`` / ``exported_functions``
    keys the Step-5g doc-signal extractor already relies on, so the call site in
    ``data_context`` stays a one-liner. Returns the number of slots upgraded
    (0 if metadata or sources are unavailable — always safe).
    """
    local = {}
    if isinstance(extract_metadata, dict):
        local = extract_metadata.get("local", {}) or {}
    if not isinstance(local, dict):
        return 0

    hdr_dir = local.get("headers_dir") or local.get("source_dir")
    public_headers = local.get("public_headers")
    header_paths: List[str] = []
    if (isinstance(hdr_dir, str) and isinstance(public_headers, str)
            and os.path.exists(public_headers)):
        with open(public_headers, "r") as fh:
            header_paths = [
                os.path.join(hdr_dir, ln.strip()) for ln in fh if ln.strip()
            ]

    exported = local.get("exported_functions")
    return recover_handle_types(
        project_apis,
        exported_functions=exported if isinstance(exported, str) else None,
        header_paths=header_paths,
    )


def _upgrade(current: str, recovered: str, primitives: set) -> Optional[str]:
    """Recovered type if it upgrades a collapsed opaque pointer, else ``None``."""
    if not recovered:
        return None
    if _bare(current) not in _COLLAPSED_BARE:
        return None
    rb = _bare(recovered)
    if not rb or rb in primitives:
        return None
    return recovered


def recover_handle_types(
    project_apis: Sequence[Dict[str, object]],
    *,
    exported_functions: Optional[str] = None,
    header_paths: Optional[Sequence[str]] = None,
) -> int:
    """In-place re-type collapsed handle slots; return the number upgraded.

    Mutates each API dict's ``return_type`` and ``arguments[i]['type']`` so the
    downstream ``usedef`` walker (and thus ``APISemanticModel.produces /
    requires``) recovers the handle dependency edges.
    """
    names: List[str] = [
        str(a.get("function_name", "")) for a in project_apis
        if a.get("function_name")
    ]
    sig = build_signature_map(
        names, exported_functions=exported_functions, header_paths=header_paths)
    if not sig:
        return 0

    primitives = set(_NON_HANDLE_PRIMITIVES)
    upgraded = 0
    for api in project_apis:
        fn = api.get("function_name")
        entry = sig.get(str(fn)) if fn else None
        if not entry:
            continue

        ret = str(entry.get("return") or "")
        new_ret = _upgrade(str(api.get("return_type", "")), ret, primitives)
        if new_ret is not None:
            api["return_type"] = new_ret
            upgraded += 1

        arg_types = entry.get("args") or []
        if not isinstance(arg_types, list):
            arg_types = []
        args = api.get("arguments") or []
        if not isinstance(args, list):
            continue
        for i, arg in enumerate(args):
            if i >= len(arg_types):
                break
            new_t = _upgrade(
                str(arg.get("type", "")), str(arg_types[i]), primitives)
            if new_t is not None:
                arg["type"] = new_t
                upgraded += 1

    return upgraded
