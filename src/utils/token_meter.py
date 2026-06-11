"""Process-global LLM token meter — a per-RUN total across all in-process
trials + the comprehender, so we can compare LLM token cost vs PromeFuzz.

Trials run in a ThreadPool (``run_single_fuzz._fuzzing_pipelines``), i.e. all in
ONE process, so a single thread-safe accumulator captures every LLM call. It is
fed at the two chokepoints every LLM call passes through:
  - ``state.update_token_usage`` (all LangGraph agents: prototyper/fixer/crash…)
  - ``Comprehender._invoke`` (the non-LangGraph knowledge stage).
``run_logicfuzz`` resets it at run start and dumps ``token_summary.json`` at the
end. Reconcile is 0-LLM (deterministic) so it contributes nothing.
"""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict

_lock = threading.Lock()


def _fresh() -> Dict[str, Any]:
    return {
        "calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "by_agent": defaultdict(
            lambda: {"calls": 0, "prompt_tokens": 0,
                     "completion_tokens": 0, "total_tokens": 0}),
    }


_stats = _fresh()


def record(prompt_tokens: int, completion_tokens: int,
           total_tokens: int = 0, agent: str = "") -> None:
    """Accumulate one LLM call's usage. No-op if both token counts are 0
    (so untracked providers don't inflate the call count)."""
    p = int(prompt_tokens or 0)
    c = int(completion_tokens or 0)
    if p == 0 and c == 0:
        return
    t = int(total_tokens or 0) or (p + c)
    with _lock:
        _stats["calls"] += 1
        _stats["prompt_tokens"] += p
        _stats["completion_tokens"] += c
        _stats["total_tokens"] += t
        a = _stats["by_agent"][agent or "unknown"]
        a["calls"] += 1
        a["prompt_tokens"] += p
        a["completion_tokens"] += c
        a["total_tokens"] += t


def snapshot() -> Dict[str, Any]:
    with _lock:
        return {
            "calls": _stats["calls"],
            "prompt_tokens": _stats["prompt_tokens"],
            "completion_tokens": _stats["completion_tokens"],
            "total_tokens": _stats["total_tokens"],
            "by_agent": {k: dict(v) for k, v in _stats["by_agent"].items()},
        }


def reset() -> None:
    global _stats
    with _lock:
        _stats = _fresh()


def dump(path: Any) -> Dict[str, Any]:
    """Write the snapshot to ``path`` (best-effort) and return it."""
    snap = snapshot()
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
    except Exception:
        pass
    return snap
