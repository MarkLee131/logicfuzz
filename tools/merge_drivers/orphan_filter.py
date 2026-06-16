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

Relationship to preflight: this is a MERGE-TIME HEURISTIC BACKSTOP. The PRIMARY,
project-agnostic orphan-crash detector is preflight — once the stock-binary build
bug was fixed (``_invalidate_stale_cache_dockerfiles``, 2026-06-16) preflight
compiles+runs the ACTUAL driver, so an orphan SEGV trips ``crashed=True`` and the
quarantine drops it on ANY project. This filter is a cheap, source-only second
line that catches the case where an orphan compiles AND happens not to crash in
the 15s preflight window but would still poison the long merged run.

Scope is deliberately NARROW (only the never-produced case) to avoid dropping
valid drivers: a handle assigned a producer return (even a possibly-NULL one), OR
written through an out-param (``&handle``), is NOT flagged here. Creator/consumer
recognition is project-agnostic (generic creator name tokens, not just ``cms*``)
so it is not vacuously inert off lcms; every ambiguity is resolved toward KEEPING
the driver (errs to false-negative, never false-positive).
"""
from __future__ import annotations

import re
from typing import List, Set

# lcms creators / context-or-plugin-taking APIs where a NULL first arg is LEGAL
# (cmsCreateContext(NULL,…), cmsBuild*(ctx,…) with ctx=NULL = global context).
_CREATOR_PREFIXES = (
    "cmsCreate", "cmsOpen", "cmsBuild", "cmsAlloc", "cmsDup", "cmsMLUalloc",
    "cmsDictDup", "cmsStageAlloc", "cmsPipelineAlloc", "cmsGBDAlloc",
    "cmsIT8Alloc", "cmsDictAlloc", "cmsGetContext", "cmsCreateContext",
)

# Project-agnostic creator name tokens (substring, case-insensitive). A function
# whose name contains one of these is treated as a creator (its return/out-param
# is the produced handle), so a NULL first arg to it is LEGAL — NOT an orphan
# consume. Being generous here only ever yields a false-NEGATIVE (keep a driver),
# the safe direction.
_CREATOR_TOKENS = (
    "create", "alloc", "new", "open", "build", "dup", "clone",
    "init", "make", "begin", "acquire", "obtain",
)

# C control-flow keywords that look like calls (``if(``, ``while(``…) — never APIs.
_C_KEYWORDS = frozenset((
    "if", "for", "while", "switch", "return", "sizeof", "else", "do",
    "case", "default", "goto",
))

# A C call site: identifier '(' first-arg-up-to-comma-or-close.
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(\s*([^,)]*)")


def _is_creator(api: str) -> bool:
    if any(api.startswith(p) for p in _CREATOR_PREFIXES):
        return True
    low = api.lower()
    return any(tok in low for tok in _CREATOR_TOKENS)


def _produced_vars(code: str) -> Set[str]:
    """Vars that receive a real handle: a NON-NULL direct assignment
    (``VAR = <not NULL>``) OR an out-param write (``&VAR`` passed to a callee)."""
    produced: Set[str] = set()
    for m in re.finditer(r"\b(\w+)\s*=\s*([^;]+);", code):
        rhs = m.group(2).strip()
        # Skip comparisons: the regex captures the first '=' of '=='; a real
        # assignment's rhs never starts with '='. (``!=``/``<=``/``>=`` can't
        # match at the var boundary at all — a non-'=' char sits before the '='.)
        if not rhs or rhs.startswith("="):
            continue
        if rhs == "NULL" or rhs.startswith("NULL"):
            continue
        produced.add(m.group(1))
    # Out-param production: &VAR handed to a callee that writes through it
    # (lcms cmsPipelineUnlinkStage(pipe, cmsAT_END, &unlinked)).
    for m in re.finditer(r"&\s*(\w+)\b", code):
        produced.add(m.group(1))
    return produced


def _null_decl_vars(code: str) -> Set[str]:
    """Vars given an explicit ``= NULL`` initializer/assignment."""
    return set(re.findall(r"\b(\w+)\s*=\s*NULL\b", code))


def is_degenerate_orphan(code: str) -> bool:
    """True iff a non-creator CONSUMER is called with a first (handle) arg that
    is a declared-NULL var never produced (no assignment, no out-param write)."""
    produced = _produced_vars(code)
    orphan_handles = {v for v in _null_decl_vars(code) if v not in produced}
    if not orphan_handles:
        return False
    for m in _CALL_RE.finditer(code):
        api, first = m.group(1), m.group(2).strip()
        if api in _C_KEYWORDS or _is_creator(api):
            continue
        # strip a leading cast, isolate the bare first arg
        fv = re.sub(r"^\([^)]*\)\s*", "", first).strip()
        # &VAR here is an OUT-PARAM write (the callee produces it), not a consume
        if fv.startswith("&"):
            continue
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
