"""Pure helpers that keep generated drivers C++-compilation-clean.

OSS-Fuzz compiles C fuzz targets with $CXX (clang++) + ``extern "C"``, so a driver
that is valid under $CC can still fail under $CXX. These helpers have no heavy
dependencies so they are importable + testable in isolation (the agents package has
a circular import that makes importing ``src.agents.prototyper`` standalone fail).
"""
from __future__ import annotations


def balance_extern_c(code: str) -> str:
    """Ensure a guarded ``extern "C" {`` block is closed.

    Some LLMs (e.g. DeepSeek) emit the guarded open
    (``#ifdef __cplusplus`` / ``extern "C" {`` / ``#endif``) but drop the matching
    guarded close. Under $CC the block is ``#ifdef``'d out (harmless); under $CXX the
    ``extern "C" {`` is never closed → ``expected '}'``. This appends the closing
    ``#ifdef __cplusplus`` / ``}`` / ``#endif`` when an unmatched open exists.

    Idempotent: a no-op when already balanced or when no ``extern "C"`` is present.
    """
    if 'extern "C" {' not in code:
        return code
    opens = code.count('extern "C" {')
    # A guarded close is a ``}`` line immediately preceded by ``#ifdef __cplusplus``.
    lines = code.splitlines()
    closes = sum(
        1 for i, ln in enumerate(lines)
        if ln.strip() == '}' and i >= 1 and lines[i - 1].strip() == '#ifdef __cplusplus'
    )
    if closes >= opens:
        return code
    return code.rstrip('\n') + '\n\n#ifdef __cplusplus\n}\n#endif\n'
