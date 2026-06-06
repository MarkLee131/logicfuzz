"""Named-constant vocabulary extraction from public headers (T2).

A CONFIG scalar arg (an ``int``/``unsigned`` flag/enum/format selector) is
*type-correct* but *value-blind*: the hole renderer used to emit a generic
"VARY_RANGE: cover in-range and out-of-range" string, so the LLM had to GUESS
the legal value set (lcms ``TYPE_RGB_8`` / ``INTENT_PERCEPTUAL``, zlib level
0-9). Guessed constants are often wrong or out-of-enum, silently hitting the
default/error branch instead of deep code.

This module deterministically scans the project's public headers for the legal
value vocabulary — true C enums and prefix-grouped ``#define`` constant
families — so the symbolic side supplies the LEGAL CONSTANTS and the LLM only
has to pick the right one for each arg (the correct division of labor).

Pure text parse: no clang, no LLM. Best-effort and robust to comments /
multi-line enums; returns ``{}``-ish on unreadable input rather than raising.
"""
from __future__ import annotations

import re
from typing import Dict, List

# An enum body: ``enum Name { ... }`` or ``typedef enum [Name] { ... } Alias;``
_ENUM_RE = re.compile(
    r"(?:typedef\s+)?enum\s+(?P<name1>\w+)?\s*\{(?P<body>[^{}]*)\}\s*(?P<name2>\w+)?",
    re.DOTALL,
)
# A simple object-like macro: ``#define NAME value`` (NAME must be UPPER-ish and
# carry a prefix_ segment so it groups; skip function-like macros NAME(...)).
_DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(?!\()", re.MULTILINE,
)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

# A define is part of a vocabulary only if its name has a PREFIX_ segment and the
# group has at least this many members (filters one-off defines / version macros).
_MIN_GROUP = 3
# Cap members per group when rendering, so the prompt stays token-bounded.
_RENDER_CAP = 24


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _prefix_of(name: str) -> str:
    """Leading ``PREFIX_`` segment of a define name, or "" if none.

    ``TYPE_RGB_8`` -> ``TYPE_``; ``INTENT_PERCEPTUAL`` -> ``INTENT_``;
    ``cmsSigRgbData`` -> "" (no underscore family) — those are handled by the
    enum/typedef path or left out.
    """
    i = name.find("_")
    if i <= 0:
        return ""
    return name[: i + 1]


def extract_constant_vocabulary(header_paths: List[str]) -> Dict[str, Dict[str, List[str]]]:
    """Scan ``header_paths`` for the named-constant vocabulary.

    Returns ``{"enums": {enum_name: [members...]},
               "define_groups": {prefix: [full_names...]}}``.
    Enum members and define groups are de-duplicated and capped for rendering.
    """
    enums: Dict[str, List[str]] = {}
    groups: Dict[str, List[str]] = {}
    seen_members: Dict[str, set] = {}

    for path in header_paths or []:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except Exception:
            continue
        text = _strip_comments(raw)

        # True C enums — the members ARE the legal value set.
        for m in _ENUM_RE.finditer(text):
            name = m.group("name2") or m.group("name1")
            if not name:
                continue
            members = []
            for tok in m.group("body").split(","):
                ident = tok.strip().split("=")[0].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", ident):
                    members.append(ident)
            if members:
                bucket = enums.setdefault(name, [])
                s = seen_members.setdefault("enum:" + name, set())
                for mem in members:
                    if mem not in s:
                        s.add(mem)
                        bucket.append(mem)

        # Prefix-grouped object-like #defines — the legal-value families.
        for dm in _DEFINE_RE.finditer(text):
            nm = dm.group(1)
            pfx = _prefix_of(nm)
            if not pfx:
                continue
            bucket = groups.setdefault(pfx, [])
            s = seen_members.setdefault("grp:" + pfx, set())
            if nm not in s:
                s.add(nm)
                bucket.append(nm)

    # Keep only real families (>= _MIN_GROUP members).
    groups = {p: v for p, v in groups.items() if len(v) >= _MIN_GROUP}
    return {"enums": enums, "define_groups": groups}


def enum_members_for_type(vocab: Dict[str, Dict[str, List[str]]], type_str: str) -> List[str]:
    """Exact legal member list if ``type_str`` names a known true enum, else []."""
    if not vocab or not type_str:
        return []
    base = type_str.replace("enum", "").replace("*", "").strip()
    return list(vocab.get("enums", {}).get(base, []))[:_RENDER_CAP]


def render_constant_vocabulary(vocab: Dict[str, Dict[str, List[str]]]) -> str:
    """A compact prompt block listing the legal constant families ONCE, so the
    LLM picks legal named constants for CONFIG args instead of raw numbers.
    Token-bounded: capped members per family, families sorted by size."""
    if not vocab:
        return ""
    enums = vocab.get("enums", {})
    groups = vocab.get("define_groups", {})
    if not enums and not groups:
        return ""
    lines = ["Library constant vocabulary — for CONFIG/flag/format args, use a "
             "LEGAL named constant from here (the one that drives deep code), "
             "never a raw magic number:"]
    for name, members in sorted(enums.items(), key=lambda kv: -len(kv[1]))[:20]:
        shown = members[:_RENDER_CAP]
        more = "" if len(members) <= _RENDER_CAP else f" (+{len(members)-_RENDER_CAP} more)"
        lines.append(f"  enum {name}: {', '.join(shown)}{more}")
    for pfx, members in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:20]:
        shown = members[:_RENDER_CAP]
        more = "" if len(members) <= _RENDER_CAP else f" (+{len(members)-_RENDER_CAP} more)"
        lines.append(f"  {pfx}* family: {', '.join(shown)}{more}")
    return "\n".join(lines)
