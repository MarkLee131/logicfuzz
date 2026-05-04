"""LLM equivalence oracle for EDSM state-merge candidates.

Given two PTA states reached via different prefixes, ask the LLM whether
they represent the same library state. The oracle returns yes / no /
uncertain and EDSM uses that as one extra evidence signal in
``edsm._score_merge``. See ``docs/automaton.md`` §6 (design contracts)
and §9.2 (oracle proposal throttling, future work).

Design constraints:
- Cheap model (default ``gpt-4o-mini``); each query is small (≤ ~600 tokens).
- Disk cache by (library, state_a_history, state_b_history) hash so re-runs
  on the same project pay zero LLM cost.
- Conservative: ambiguous parses → ``None`` so EDSM falls back to evidence.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from liberator_adapter.analysis.edsm import EDSMContext, OracleVerdict
from liberator_adapter.analysis.pta import PTANode

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------- prompt

_SYSTEM_PROMPT = """You are an oracle for an automaton-learning system. You will be given two abstract states from a candidate fuzzing-protocol automaton for a C/C++ library, expressed as the API-call histories that lead to them.

Decide whether the two states represent the *same* library state — meaning a downstream API would behave identically if called from either. Answer in JSON:

    {"verdict": "yes" | "no" | "uncertain", "reason": "<one short sentence>"}

Rules:
- "yes" only if you are confident the histories produce identical library state.
- "no" if you are confident they produce different state (e.g. one has prepared a statement, the other has not).
- "uncertain" if you cannot tell from the histories alone.
- Output JSON only — no prose around it.
"""


_USER_TEMPLATE = """Library: {library_name}
Library purpose: {library_purpose}

State A — reached after this API call sequence:
{history_a}

State B — reached after this API call sequence:
{history_b}

Common observed handle typestate vector at both states (verified by the
analyzer; do not contradict): {state_vector}

Are A and B the same library state?"""


# ----------------------------------------------------------------------- cache

@dataclass
class _CacheKey:
    library_name: str
    history_a: Tuple[str, ...]
    history_b: Tuple[str, ...]
    state_vector: Tuple[str, ...]

    def hash(self) -> str:
        h = hashlib.sha256()
        h.update(self.library_name.encode())
        for piece in (self.history_a, self.history_b, self.state_vector):
            for s in piece:
                h.update(b"\0")
                h.update(s.encode())
            h.update(b"||")
        return h.hexdigest()[:16]


class _OracleCache:
    def __init__(self, cache_path: Optional[Path]):
        self.path = cache_path
        self.data: Dict[str, Dict[str, str]] = {}
        if cache_path and cache_path.exists():
            try:
                self.data = json.loads(cache_path.read_text())
            except Exception as exc:
                logger.warning("oracle cache load failed: %s", exc)

    def get(self, key: _CacheKey) -> Optional[Tuple[OracleVerdict, str]]:
        e = self.data.get(key.hash())
        if not e:
            return None
        v = e.get("verdict")
        verdict: OracleVerdict
        if v == "yes":
            verdict = True
        elif v == "no":
            verdict = False
        else:
            verdict = None
        return verdict, e.get("reason", "")

    def put(self, key: _CacheKey, verdict: OracleVerdict, reason: str) -> None:
        v = {True: "yes", False: "no", None: "uncertain"}[verdict]
        self.data[key.hash()] = {"verdict": v, "reason": reason}
        if self.path:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True))
            except Exception as exc:
                logger.warning("oracle cache write failed: %s", exc)


# ----------------------------------------------------------------------- llm wiring

def _format_history(pta_node: PTANode, ctx: EDSMContext, max_steps: int = 8) -> str:
    """Walk parent links back to the root, emit '<call_id>: api_name' per step."""
    chain: List[str] = []
    cur: Optional[PTANode] = pta_node
    while cur is not None and cur.incoming_edge_label is not None:
        api, _bp = cur.incoming_edge_label
        chain.append(api)
        if cur.parent_id is None:
            break
        cur = ctx.pta.nodes.get(cur.parent_id)
    chain.reverse()
    if not chain:
        return "(initial state — no calls yet)"
    if len(chain) > max_steps:
        head = chain[: max_steps // 2]
        tail = chain[-max_steps // 2:]
        chain = head + ["..."] + tail
    return "  -> ".join(chain)


def _format_state_vector(state) -> str:
    if not state:
        return "(no handles open)"
    return ", ".join(f"{h}={s.value}" for h, s in sorted(state))


_FENCED_JSON_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def _parse_response(text: str) -> Tuple[OracleVerdict, str]:
    if not text:
        return None, "empty"
    m = _FENCED_JSON_RE.search(text)
    payload = m.group(0) if m else text
    try:
        obj = json.loads(payload)
    except Exception:
        return None, "unparseable"
    v = (obj.get("verdict") or "").lower().strip()
    reason = (obj.get("reason") or "").strip()
    if v == "yes":
        return True, reason
    if v == "no":
        return False, reason
    return None, reason


# ----------------------------------------------------------------------- public

class LLMEquivalenceOracle:
    """Callable oracle for EDSM. Initialise once, pass ``oracle.query`` to
    ``edsm.merge(oracle=...)``.
    """

    def __init__(self,
                 library_name: str,
                 library_purpose: str = "",
                 model_name: str = "gpt-4o-mini",
                 cache_path: Optional[Path] = None,
                 disable_llm: bool = False):
        self.library_name = library_name
        self.library_purpose = library_purpose
        self.model_name = model_name
        self.disable_llm = disable_llm
        self._cache = _OracleCache(cache_path)
        self._chat_model = None
        self._n_calls = 0
        self._n_cache_hits = 0
        self._n_yes = self._n_no = self._n_uncertain = 0

    def _get_model(self):
        if self._chat_model is not None:
            return self._chat_model
        if self.disable_llm:
            return None
        try:
            from src.llm.models import get_chat_model
            self._chat_model = get_chat_model(self.model_name, temperature=0.0)
        except Exception as exc:
            logger.warning("LLM oracle unavailable (%s); running in deferred-only mode.", exc)
            self._chat_model = None
        return self._chat_model

    def query(self, a: PTANode, b: PTANode, ctx: EDSMContext) -> OracleVerdict:
        history_a = tuple(_format_history(a, ctx).split(" -> "))
        history_b = tuple(_format_history(b, ctx).split(" -> "))
        state_vec = tuple(f"{h}={s.value}" for h, s in sorted(a.state))
        key = _CacheKey(self.library_name, history_a, history_b, state_vec)
        cached = self._cache.get(key)
        if cached is not None:
            self._n_cache_hits += 1
            verdict, _ = cached
            self._tally(verdict)
            return verdict
        model = self._get_model()
        if model is None:
            return None
        user = _USER_TEMPLATE.format(
            library_name=self.library_name,
            library_purpose=self.library_purpose or "(unknown)",
            history_a=_format_history(a, ctx),
            history_b=_format_history(b, ctx),
            state_vector=_format_state_vector(a.state),
        )
        try:
            from langchain_core.messages import SystemMessage, HumanMessage
            response = model.invoke([
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=user),
            ])
            content = getattr(response, "content", "") or ""
            if isinstance(content, list):
                content = "".join(p.get("text", "") if isinstance(p, dict) else str(p)
                                  for p in content)
            verdict, reason = _parse_response(content)
        except Exception as exc:
            logger.warning("LLM oracle call failed: %s", exc)
            return None
        self._cache.put(key, verdict, reason)
        self._n_calls += 1
        self._tally(verdict)
        return verdict

    def _tally(self, verdict: OracleVerdict) -> None:
        if verdict is True:
            self._n_yes += 1
        elif verdict is False:
            self._n_no += 1
        else:
            self._n_uncertain += 1

    def stats(self) -> Dict[str, int]:
        return {
            "llm_calls": self._n_calls,
            "cache_hits": self._n_cache_hits,
            "yes": self._n_yes,
            "no": self._n_no,
            "uncertain": self._n_uncertain,
        }
