"""Sanitizer environment for fuzzing subprocesses.

LeakSanitizer does not work in the ptrace-restricted container/host used here:
``StopTheWorld`` fails, LSan raises "LeakSanitizer has encountered a fatal error"
during its atexit check, and libFuzzer records the (empty) current unit as a
``crash-da39a3ee...`` artifact — marking EVERY driver crashed and, in fork-mode
long runs, aborting each child at batch boundaries. The libFuzzer
``-detect_leaks=0`` CLI flag does NOT suppress the runtime's atexit LSan check;
only ``ASAN_OPTIONS=detect_leaks=0`` (the runtime switch) does.

This module centralises that so preflight (host subprocess) and extended fuzzing
(in-container ``-e``) share one source of truth.
"""
from __future__ import annotations

import os
from typing import Dict, Mapping, Optional


def asan_options_value(existing: str = "") -> str:
    """Return an ASAN_OPTIONS string that forces ``detect_leaks=0`` while
    preserving every other ``key=value`` already present (and de-duplicating /
    overriding any pre-existing ``detect_leaks``)."""
    pairs = []
    seen = set()
    for tok in (existing or "").split(":"):
        tok = tok.strip()
        if not tok:
            continue
        key = tok.split("=", 1)[0]
        if key == "detect_leaks":
            # Drop any existing detect_leaks; we force it below.
            continue
        if key in seen:
            continue
        seen.add(key)
        pairs.append(tok)
    pairs.append("detect_leaks=0")
    return ":".join(pairs)


def fuzzing_subprocess_env(
    base: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """A copy of ``base`` (default ``os.environ``) with ASAN_OPTIONS forced to
    include ``detect_leaks=0``. Does not mutate the input."""
    src = os.environ if base is None else base
    env = dict(src)
    env["ASAN_OPTIONS"] = asan_options_value(env.get("ASAN_OPTIONS", ""))
    return env
