"""Process-global LLM interaction trace — a per-RUN ledger of every LLM call's
prompt, response, and token usage across all in-process trials + the
comprehender. Companion to ``token_meter`` (which records only the counts).

Trials run in a ThreadPool (``run_single_fuzz._fuzzing_pipelines``), i.e. all in
ONE process, so a single thread-safe appender captures every LLM call.
``run_experiments`` calls ``configure(path)`` at run start (per benchmark); the
ledger is written incrementally as JSONL — one JSON object per LLM call — so a
crash mid-run still leaves a partial, valid trace.

Fed at the two live content-bearing chokepoints every LLM call passes through:
  - ``ToolCallingMixin.run_tool_calling_loop`` (all LangGraph agents:
    prototyper/fixer/crash_analyzer/crash_feasibility).
  - ``Comprehender._invoke`` (the non-LangGraph knowledge stage).
Reconcile is 0-LLM (deterministic) so it contributes nothing.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_path: Optional[Path] = None


def configure(path: Any) -> None:
    """Point the ledger at ``path`` (a JSONL file) and truncate it for a fresh
    run. Best-effort: disables tracing on failure (never breaks a run)."""
    global _path
    with _lock:
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            # Truncate any stale ledger from a previous run of this project.
            p.write_text("", encoding="utf-8")
            _path = p
        except Exception:
            _path = None


def reset() -> None:
    """Disable tracing (no path configured)."""
    global _path
    with _lock:
        _path = None


def is_active() -> bool:
    return _path is not None


def record(agent: str = "",
           trial: Optional[int] = None,
           llm_round: int = 0,
           system: Optional[str] = None,
           user: Optional[str] = None,
           response: Optional[str] = None,
           tool_calls: Optional[List[Dict[str, Any]]] = None,
           tokens: Optional[Dict[str, Any]] = None,
           model: str = "",
           extra: Optional[Dict[str, Any]] = None) -> None:
    """Append one LLM interaction to the per-run ledger.

    No-op if tracing is not configured. Never raises — telemetry must not break
    a real run. ``system``/``user`` are the prompt halves (omit on follow-up
    ReAct rounds to avoid re-dumping the system prompt); ``response`` is the
    LLM's text; ``tokens`` is the usage dict; ``tool_calls`` summarises any
    requested tool calls.
    """
    if _path is None:
        return
    entry: Dict[str, Any] = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "agent": agent or "unknown",
        "trial": trial,
        "round": llm_round,
        "model": model,
        "tokens": tokens or {},
    }
    if system is not None or user is not None:
        entry["prompt"] = {"system": system or "", "user": user or ""}
    if response is not None:
        entry["response"] = response
    if tool_calls:
        entry["tool_calls"] = tool_calls
    if extra:
        entry.update(extra)
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        if _path is None:
            return
        try:
            with open(_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
