"""Constant-usage mining from the library's own call-sites (FIX D).

A CONFIG scalar arg (``cmsCreateTransform``'s ``InputFormat``) is type-correct
but value-blind: the floor renders ``= 0`` and the LLM guesses ``data[0] % 256``
— both INVALID formats, so the API returns NULL → the whole object-construction
chain is dead → edges=0. The library's OWN tests / examples / fuzzers, however,
call the API with the LEGAL constants
(``cmsCreateTransform(hSrc, TYPE_BGR_8, …)``). This module mines those call-sites
so the renderer can fill a CONFIG arg with a constant the library actually uses
— valid by construction, deterministic (no LLM), grounded in real usage (the
reconcile-then-construct way; the symbolic side supplies the legal value, no
guess).

Pure text parse: no clang, no LLM. Best-effort; returns ``{}`` on unreadable
input rather than raising.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Set

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

# A "named constant" arg: a bare identifier that is macro/enum-shaped — has an
# uppercase letter and an underscore (TYPE_BGR_8, INTENT_PERCEPTUAL,
# Z_DEFAULT_COMPRESSION) or is ALL-CAPS (RGB, GRAY). Excludes ordinary locals
# (``hSrc``, ``size``) and numeric literals. A vocab membership check (optional)
# tightens this further.
_CONST_SHAPED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_PER_ARG = 8          # keep the top-N most-used constants per (api, arg)
_MAX_SCAN_BYTES = 4_000_000   # per-file cap (skip giant generated files)


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _looks_like_constant(tok: str) -> bool:
    """True for a macro/enum-shaped identifier (has an uppercase letter; not a
    pure-lowercase local, not a number, not an expression)."""
    if not _CONST_SHAPED.fullmatch(tok):
        return False
    if not any(c.isupper() for c in tok):
        return False           # pure-lowercase local (hSrc is mixed but has no '_'+upper run; see below)
    # Require either an underscore (TYPE_BGR_8) or fully upper (RGB) — this drops
    # camelCase locals like ``hSrc`` / ``cmsHTRANSFORM``-typed vars.
    return ("_" in tok) or tok.isupper()


def _split_top_level_args(s: str) -> List[str]:
    """Split a call's argument string on TOP-LEVEL commas (ignoring commas
    nested in (), [], {}, or string/char literals)."""
    args: List[str] = []
    depth = 0
    cur = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c in "\"'":
            # skip a string/char literal whole
            q = c
            cur.append(c)
            i += 1
            while i < n:
                cur.append(s[i])
                if s[i] == "\\" and i + 1 < n:
                    cur.append(s[i + 1])
                    i += 2
                    continue
                if s[i] == q:
                    break
                i += 1
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur).strip())
    return args


def _match_call_args(text: str, start: int) -> Optional[str]:
    """``text[start]`` is the ``(`` after the call name — return the balanced
    argument substring (without the outer parens), or None if unbalanced."""
    depth = 0
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return None


def mine_constant_usage(
    source_paths: List[str],
    api_names: Set[str],
    vocab: Optional[Dict] = None,
) -> Dict[str, Dict[int, List[str]]]:
    """Scan ``source_paths`` for call-sites of each API in ``api_names`` and
    return the named constants passed at each argument position, ranked by
    frequency (most-used first).

    Returns ``{api_name: {arg_index: [const, ...]}}``. An arg position appears
    only if at least one call-site passed a constant there. When ``vocab`` (the
    named-constant vocabulary) is given, an arg token is kept only if it is a
    known vocab member OR macro/enum-shaped — tightening precision.
    """
    if not api_names:
        return {}
    vocab_members: Set[str] = set()
    if vocab:
        for members in (vocab.get("enums") or {}).values():
            vocab_members.update(members)
        for members in (vocab.get("define_groups") or {}).values():
            vocab_members.update(members)

    # counts[api][arg_idx][const] -> n
    counts: Dict[str, Dict[int, Counter]] = {}
    # Per-API compiled finder: ``\bNAME\s*(``
    finders = {api: re.compile(r"\b" + re.escape(api) + r"\s*\(")
               for api in api_names}

    for path in source_paths or []:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                raw = f.read(_MAX_SCAN_BYTES + 1)
        except Exception:
            continue
        if len(raw) > _MAX_SCAN_BYTES:
            continue
        text = _strip_comments(raw)
        for api, finder in finders.items():
            for m in finder.finditer(text):
                paren = m.end() - 1   # index of the '('
                argstr = _match_call_args(text, paren)
                if argstr is None:
                    continue
                for idx, arg in enumerate(_split_top_level_args(argstr)):
                    tok = arg.strip()
                    if not _looks_like_constant(tok):
                        continue
                    if vocab_members:
                        # STRICT: a real #define/enum member only — drops
                        # variables that happen to be macro-shaped (lcms_sRGB).
                        if tok not in vocab_members:
                            continue
                    counts.setdefault(api, {}).setdefault(idx, Counter())[tok] += 1

    out: Dict[str, Dict[int, List[str]]] = {}
    for api, per_arg in counts.items():
        for idx, ctr in per_arg.items():
            ranked = [c for c, _ in ctr.most_common(_MAX_PER_ARG)]
            if ranked:
                out.setdefault(api, {})[idx] = ranked
    return out


# --------------------------------------------------------------------------
# Process-global usage map (FIX D). The skeleton renderer reads this the same
# way it reads ``DataLayout.instance()`` — set once by ``data_context`` before
# skeleton generation, read-only thereafter (single render process). Empty in
# the unit/no-model path → ``legal_constant_for`` returns None → the renderer
# keeps the FIX C hole. Avoids threading the map through the construct chain.
# --------------------------------------------------------------------------
_USAGE_MAP: Dict[str, Dict[int, List[str]]] = {}


def set_usage_map(m: Optional[Dict[str, Dict[int, List[str]]]]) -> None:
    global _USAGE_MAP
    _USAGE_MAP = m or {}


def legal_constants_for(api_name: str, arg_idx: int) -> List[str]:
    """The legal constants the library's own call-sites pass at
    ``(api_name, arg_idx)`` — most-used first — or ``[]``."""
    try:
        return list(_USAGE_MAP.get(api_name, {}).get(arg_idx, []))
    except Exception:
        return []
