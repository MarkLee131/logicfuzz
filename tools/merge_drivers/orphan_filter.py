"""Detect degenerate ORPHAN merge candidates — drivers that call a handle-
consuming API on a handle that is declared ``= NULL`` and NEVER produced.

These are lifecycle-incomplete sequences the constructor's graceful degradation
keeps (consumers with no producer; CLAUDE.md ``LOGICFUZZ_STRICT_ORDERING``). The
library dereferences the NULL handle internally → SEGV (lcms:
``cmsGetColorSpace(NULL)`` reads the ColorSpace field at offset 0x8c). They
COMPILE (so compile-validation keeps them) and slipped past preflight
(crashed=False), then POISON the single-process merged harness AND corrupt the
coverage ``-merge`` replay. Excluding them at merge time removes the crash poison
WITHOUT STRICT_ORDERING's whole-class breadth loss.

Scope is deliberately NARROW (only the never-produced case) to avoid dropping
valid drivers: a handle assigned a producer return (even a possibly-NULL one) is
NOT flagged here — that's a separate (guarded) concern.
"""
from __future__ import annotations

import re
from typing import List, Set

# Creators / context-or-plugin-taking APIs where a NULL first arg is LEGAL
# (cmsCreateContext(NULL,…), cmsBuild*(ctx,…) with ctx=NULL = global context).
_CREATOR_PREFIXES = (
    "cmsCreate", "cmsOpen", "cmsBuild", "cmsAlloc", "cmsDup", "cmsMLUalloc",
    "cmsDictDup", "cmsStageAlloc", "cmsPipelineAlloc", "cmsGBDAlloc",
    "cmsIT8Alloc", "cmsDictAlloc", "cmsGetContext", "cmsCreateContext",
)


def _produced_vars(code: str) -> Set[str]:
    """Vars assigned a NON-NULL value somewhere (``VAR = <not NULL>``)."""
    produced: Set[str] = set()
    for m in re.finditer(r"\b(\w+)\s*=\s*([^;]+);", code):
        rhs = m.group(2).strip()
        if rhs and rhs != "NULL" and not rhs.startswith("NULL"):
            produced.add(m.group(1))
    return produced


def _null_decl_vars(code: str) -> Set[str]:
    """Vars given an explicit ``= NULL`` initializer/assignment."""
    return set(re.findall(r"\b(\w+)\s*=\s*NULL\b", code))


def is_degenerate_orphan(code: str) -> bool:
    """True iff a cms CONSUMER is called with a first (handle) arg that is a
    declared-NULL var never assigned a producer return."""
    produced = _produced_vars(code)
    orphan_handles = {v for v in _null_decl_vars(code) if v not in produced}
    if not orphan_handles:
        return False
    for m in re.finditer(r"\b(cms\w+)\s*\(\s*([^,)]+)", code):
        api, first = m.group(1), m.group(2).strip()
        if any(api.startswith(p) for p in _CREATOR_PREFIXES):
            continue
        # strip a leading cast and address-of, isolate the bare identifier
        fv = re.sub(r"^\([^)]*\)\s*", "", first).lstrip("&").strip()
        if fv in orphan_handles:
            return True
    return False


def filter_orphans(sources: List) -> tuple:
    """Partition ``sources`` (paths) into (kept, dropped) by orphan detection.
    Unreadable sources are KEPT (fail-open — never block on an IO hiccup)."""
    from pathlib import Path
    kept, dropped = [], []
    for s in sources:
        try:
            code = Path(str(s)).read_text(encoding="utf-8", errors="replace")
        except OSError:
            kept.append(s)
            continue
        (dropped if is_degenerate_orphan(code) else kept).append(s)
    return kept, dropped
