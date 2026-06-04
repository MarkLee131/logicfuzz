"""Knowledge-driven comprehender.

Two-stage design (see docs/knowledge_layer.md):

1. ``LibraryComprehension``: per-API usage notes + a one-paragraph library
   purpose. Layered fallback per API:

      a. Deterministic synthesis from ConditionManager role
         (SOURCE / SINK / INIT / SETBY) plus L2 lifecycle pairing.
      b. Batched LLM call for the remainder, signature-only.

   Only APIs that appear in the top-K filtered sequences are comprehended.
   This is the load-bearing token-saving step.

2. ``SequenceSemantics``: per-sequence semantic verdict. The L0–L3 filters
   already prove type / lifecycle / state-machine validity; this stage answers
   "is the *combination* meaningful?" e.g. ``parser_get_object`` after
   ``parser_new`` but before any ``add_chunk``. Returns a status, optional
   repaired sequence, and invariants the prototyper should respect.

The comprehender is fail-soft: any LLM failure leaves the deterministic
fallback in place rather than blocking ``FuzzingContext.prepare()``.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from src.knowledge.cache import KnowledgeCache
from src.utils.prompt_loader import get_prompt_manager

logger = logging.getLogger(__name__)

# Cheap, fast model for comprehension. Override per project via prepare(model=...).
DEFAULT_COMPREHENDER_MODEL = "gpt-4o-mini"

# Batch size for comprehender-A (signatures per LLM call).
API_BATCH_SIZE = 10

# System prompt for the role-classification authority (classify_roles).
_ROLE_SYSTEM_PROMPT = """You are a C/C++ API analyst for fuzz-driver generation. \
For each function signature, classify its semantic ROLE and each ARGUMENT's role. \
Output ONLY a JSON object, no prose.

ROLE — what the function does to library resources:
- CREATOR: produces a fresh handle/object/resource (returns it or fills an out-pointer), often FROM input bytes (a parser/loader/open).
- MUTATOR: takes an existing handle and configures / advances / writes into it.
- CONSUMER: reads a handle or input data and returns a value/result, creating no new owned resource.
- DESTROYER: frees / closes / releases a handle.

ARG role — per parameter, by 0-based position:
- INPUT_BUFFER: raw input bytes the fuzzer should drive (e.g. a const void*/const char*/const uint8_t* blob to be parsed).
- LENGTH: the size/count of an INPUT_BUFFER.
- OUTPUT: an out-pointer the function writes its result through.
- HANDLE_IN: a required pre-existing handle/object obtained from another call.
- NULLABLE_HANDLE: an optional handle that may be NULL (e.g. a context/allocator/thread arg).
- CONFIG: a scalar / enum / flag knob.

Guidance: a top-level PARSER ENTRY reads INPUT_BUFFER (usually with a LENGTH) and \
needs no prior handle except possibly a NULLABLE_HANDLE context — these are the \
highest-value fuzz entry points. A function that takes a real HANDLE_IN and writes a \
buffer into it is a MUTATOR, not a parser entry. Be decisive; use UNKNOWN only when \
genuinely ambiguous.

Output JSON shape (include EVERY function from the input):
{"func_name": {"role": "CREATOR", "confidence": 0.0-1.0,
  "args": [{"index": 0, "role": "INPUT_BUFFER"}, {"index": 1, "role": "LENGTH"}]}}
"""


@dataclass
class LibraryComprehension:
    """Output of comprehender-A. Mutable so crash-learner (B) can append later."""
    purpose: str = ""
    functions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"purpose": self.purpose, "functions": dict(self.functions)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LibraryComprehension":
        return cls(
            purpose=data.get("purpose", ""),
            functions=dict(data.get("functions", {})),
        )


@dataclass
class SequenceSemantics:
    """Output of comprehender-B for a single candidate sequence."""
    sequence: List[str]
    semantic_status: str = "VALID"   # VALID | SUBOPTIMAL | INVALID
    diagnosis: str = ""
    repair_action: str = "NONE"      # NONE | INSERT | REORDER | REPLACE | DROP
    patched_sequence: Optional[List[str]] = None
    repair_rationale: str = ""
    invariants_for_prototyper: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": list(self.sequence),
            "semantic_status": self.semantic_status,
            "diagnosis": self.diagnosis,
            "repair": {
                "action": self.repair_action,
                "patched_sequence": list(self.patched_sequence) if self.patched_sequence else None,
                "rationale": self.repair_rationale,
            },
            "invariants_for_prototyper": list(self.invariants_for_prototyper),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SequenceSemantics":
        repair = data.get("repair") or {}
        return cls(
            sequence=list(data.get("sequence", [])),
            semantic_status=data.get("semantic_status", "VALID"),
            diagnosis=data.get("diagnosis", ""),
            repair_action=repair.get("action", "NONE"),
            patched_sequence=(list(repair["patched_sequence"])
                              if repair.get("patched_sequence") else None),
            repair_rationale=repair.get("rationale", ""),
            invariants_for_prototyper=list(data.get("invariants_for_prototyper", [])),
        )


_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def _extract_json_block(text: str) -> Optional[Any]:
    """Pull a fenced JSON object/array out of an LLM response. Tolerant.

    Fallback search (no markdown fence) uses **balanced bracket scanning**
    rather than a regex. The 2026-05 review caught that the earlier
    greedy ``re.search(r"\\{.*\\}")`` could span across multiple JSON
    blocks, capturing arbitrary prose between them. Balanced scan stops
    at the first complete object/array.
    """
    if not text:
        return None
    m = _FENCED_JSON_RE.search(text)
    payload = m.group(1) if m else text.strip()
    # If still wrapped in extra prose, find the first complete {...} or
    # [...] via balanced bracket scanning (handles nested braces; the
    # earlier ``re.search(r"\{.*\}", ..., DOTALL)`` would have captured
    # everything from the first ``{`` to the LAST ``}`` in the text,
    # which is wrong when multiple JSON blocks share the response).
    if not payload.lstrip().startswith(("{", "[")):
        payload = _first_balanced_json(payload)
        if payload is None:
            return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        logger.warning("LLM returned non-JSON: %s", exc)
        return None


def _first_balanced_json(text: str) -> Optional[str]:
    """Find the first complete JSON object or array via bracket counting.

    Quote-aware so braces inside strings don't break the count. Returns
    the substring spanning the first complete top-level ``{...}`` or
    ``[...]``, or ``None`` if no balanced span exists.
    """
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch not in "{[":
            i += 1
            continue
        opener = ch
        closer = "}" if opener == "{" else "]"
        depth = 0
        j = i
        in_str = False
        escape = False
        while j < n:
            c = text[j]
            if in_str:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    return text[i:j + 1]
            j += 1
        # Unbalanced — give up
        return None
    return None


def _format_signature(api: Dict[str, Any]) -> str:
    rt = api.get("return_type") or "void"
    name = api.get("function_name", "?")
    args = api.get("arguments") or []
    parts = []
    for arg in args:
        if isinstance(arg, dict):
            t = arg.get("type") or "?"
            n = arg.get("name") or ""
            parts.append(f"{t} {n}".strip())
        else:
            parts.append(str(arg))
    return f"{rt} {name}({', '.join(parts)});"


def _condition_role(name: str, condition_info: Dict[str, Any]) -> Optional[str]:
    if not condition_info:
        return None
    if name in (condition_info.get("inits") or []):
        return "INIT"
    if name in (condition_info.get("sources") or []):
        return "SOURCE"
    if name in (condition_info.get("sinks") or []):
        return "SINK"
    return None


def _lifecycle_pair(name: str,
                    lifecycle_analysis: Dict[str, Any]) -> Optional[str]:
    """Return paired init/destroy partner if known, else None."""
    if not lifecycle_analysis:
        return None
    pairs = lifecycle_analysis.get("pairs") or lifecycle_analysis.get("lifecycle_pairs") or []
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        init = pair.get("init") or pair.get("init_api")
        destroy = pair.get("destroy") or pair.get("destroy_api")
        if name == init and destroy:
            return f"pairs with destroy API `{destroy}`"
        if name == destroy and init:
            return f"pairs with init API `{init}`"
    return None


# Minimum useful doxygen length. Below this, the comment is usually a
# single-word stub like "Initialize" or "Free buffer" that the
# deterministic role-based usage already captures. T1 review: under 40
# chars carries almost no signal the LLM can act on.
_DOXYGEN_MIN_USEFUL_CHARS = 40


def _doc_derived_usage(api: Dict[str, Any], docstring: str) -> Optional[str]:
    """Compose a usage line from a doxygen docstring + the API signature.

    Returns ``None`` for short / vacuous docstrings so the call site
    falls through to the LLM (which can do better than 5 words of
    description). T1 prior: when we have a substantive doc, the LLM
    is largely redundant for this API.
    """
    if not docstring or len(docstring.strip()) < _DOXYGEN_MIN_USEFUL_CHARS:
        return None
    sig = _format_signature(api)
    text = docstring.strip()
    # Cap doc length so a verbose doxygen block doesn't blow the
    # Prototyper prompt budget downstream.
    if len(text) > 600:
        text = text[:600].rsplit(" ", 1)[0] + "..."
    return f"{text} (doxygen) — signature: {sig}"


# APISemanticModel role (redesign G1) → deterministic usage text. The model
# is the authority for role (it reconciles IR ⊕ doc ⊕ naming); ConditionManager's
# IR-only SOURCE/SINK/INIT is the fallback when the model is unavailable.
_MODEL_ROLE_USAGE = {
    "CREATOR": "Produces fresh data / handle; safe to call without prior state.",
    "DESTROYER": "Consumes a previously produced object; releases ownership.",
    "MUTATOR": "Configures or advances a library object; needs an upstream handle.",
    "CONSUMER": "Reads a previously produced object; needs an upstream handle.",
}


def _deterministic_usage(api: Dict[str, Any],
                         condition_info: Dict[str, Any],
                         lifecycle_analysis: Dict[str, Any],
                         api_roles: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Synthesize a usage line from static facts. Returns None if we know nothing.

    ``api_roles`` (name → ``APIRole`` value) is the reconciled
    ``APISemanticModel`` verdict; when present it is the role authority and
    ConditionManager (``_condition_role``) is demoted to fallback.
    """
    name = api.get("function_name", "")
    pair = _lifecycle_pair(name, lifecycle_analysis)

    parts = []
    model_role = (api_roles or {}).get(name)
    role_text = _MODEL_ROLE_USAGE.get(model_role) if model_role else None
    if role_text:
        parts.append(role_text)
    else:
        role = _condition_role(name, condition_info)
        if role == "INIT":
            parts.append("Initializes a library object; call before any consumer API.")
        elif role == "SOURCE":
            parts.append("Produces fresh data / handle; safe to call without prior state.")
        elif role == "SINK":
            parts.append("Consumes a previously produced object; releases ownership.")

    if not parts and not pair:
        return None
    if pair:
        parts.append(pair + ".")
    return " ".join(parts) if parts else None


def _automaton_is_strong(acceptance_fn: Any) -> bool:
    """Best-effort strength check for the automaton behind ``acceptance_fn``.

    ``acceptance_fn`` is typically ``AutomatonArtifact.acceptance_score``,
    a bound method. We pull the artifact off the bound method and consult
    ``AutomatonAcceptanceGuard`` for its strength verdict — same policy
    the L4 ranker uses to decide whether to trust the automaton signal.

    Defensive fallback: any failure (unbound function, missing artifact,
    guard ctor exception) → return ``True`` so we DON'T silently disable
    the prefilter for a callable we just can't introspect. The downstream
    LLM call is the safety net.
    """
    try:
        artifact = getattr(acceptance_fn, "__self__", None)
        if artifact is None:
            return True
        from liberator_adapter.constraints.z3_guided_synthesis import (
            AutomatonAcceptanceGuard,
        )
        guard = AutomatonAcceptanceGuard(artifact=artifact)
        return guard.is_strong()
    except Exception:
        return True


def _build_static_facts(condition_info: Dict[str, Any],
                        lifecycle_analysis: Dict[str, Any]) -> str:
    lines: List[str] = []
    if condition_info:
        counts = condition_info.get("counts", {})
        if counts:
            lines.append(
                f"Roles: {counts.get('inits', 0)} init, "
                f"{counts.get('sources', 0)} source, "
                f"{counts.get('sinks', 0)} sink APIs."
            )
    if lifecycle_analysis:
        pairs = (lifecycle_analysis.get("pairs")
                 or lifecycle_analysis.get("lifecycle_pairs") or [])
        if pairs:
            shown = []
            for pair in pairs[:8]:
                if not isinstance(pair, dict):
                    continue
                init = pair.get("init") or pair.get("init_api")
                destroy = pair.get("destroy") or pair.get("destroy_api")
                if init and destroy:
                    shown.append(f"  {init} ↔ {destroy}")
            if shown:
                lines.append("Verified init/destroy pairs:")
                lines.extend(shown)
    return "\n".join(lines) if lines else "(no additional static facts)"


class Comprehender:
    """Orchestrates comprehender-A and comprehender-B."""

    def __init__(self,
                 project_name: str,
                 model_name: str = DEFAULT_COMPREHENDER_MODEL,
                 cache: Optional[KnowledgeCache] = None):
        self.project_name = project_name
        self.model_name = model_name
        self.cache = cache or KnowledgeCache(project_name)
        self.prompts = get_prompt_manager()
        self._chat_model = None  # lazy

    # ------------------------------------------------------------------ LLM
    def _get_model(self):
        if self._chat_model is not None:
            return self._chat_model
        try:
            from src.llm.models import get_chat_model
            self._chat_model = get_chat_model(self.model_name, temperature=0.2)
        except Exception as exc:
            logger.warning(
                "Comprehender LLM unavailable (%s); will run deterministic-only.",
                exc,
            )
            self._chat_model = None
        return self._chat_model

    def _invoke(self, system_prompt: str, user_prompt: str) -> str:
        model = self._get_model()
        if model is None:
            return ""
        try:
            from langchain_core.messages import SystemMessage, HumanMessage
            response = model.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
            ])
            content = getattr(response, "content", "") or ""
            if isinstance(content, list):
                # Some providers return content as a list of parts.
                content = "".join(part.get("text", "") if isinstance(part, dict) else str(part)
                                  for part in content)
            return content
        except Exception as exc:
            logger.warning("Comprehender LLM call failed: %s", exc)
            return ""

    # ---------------------------------------------------------------- A.purpose
    def comprehend_purpose(self,
                           library_name: str,
                           doc_excerpts: str = "") -> str:
        cached = self.cache.load_purpose()
        if cached:
            logger.info("Comprehender: purpose loaded from cache")
            return cached
        system = self.prompts.get_system_prompt("comprehender_purpose")
        user = self.prompts.build_user_prompt(
            "comprehender_purpose",
            library_name=library_name,
            doc_excerpts=doc_excerpts or "(no documentation available)",
        )
        purpose = self._invoke(system, user).strip()
        if not purpose:
            # LLM returned nothing (transient failure, rate limit, or
            # provider down). Synthesize a generic fallback so callers
            # still see *some* purpose, but DO NOT cache it — the next
            # run will retry the LLM rather than reading the generic
            # template forever. 2026-05 review (C4).
            return (
                f"{library_name}: a C/C++ library; usage inferred from API "
                f"signatures and OSS-Fuzz harness patterns."
            )
        self.cache.save_purpose(purpose)
        return purpose

    # ------------------------------------------------------------ A.role
    def classify_roles(self,
                       api_names: Sequence[str],
                       project_apis: Sequence[Dict[str, Any]],
                       purpose: str = "",
                       api_docstrings: Optional[Dict[str, str]] = None,
                       usage_context: Optional[Dict[str, str]] = None,
                       det_verdicts: Optional[Dict[str, str]] = None,
                       handle_types: Optional[Sequence[str]] = None,
                       ) -> Dict[str, Dict[str, Any]]:
        """Batched-LLM role + arg-role classification (the role authority).

        Returns ``{api_name: {"role": str, "confidence": float,
        "args": [{"index": i, "role": str}, ...]}}`` for ``APISemanticModel.
        reconcile(llm_roles=...)`` to fold in. Cached on disk and merged, so a
        rerun re-classifies only new APIs. Degrades to ``{}`` with no LLM
        (reconcile then stays purely deterministic).

        This is the "LLM as semantic judgement" layer: role (CREATOR vs CONSUMER
        vs MUTATOR vs DESTROYER) is exactly the call the deterministic IR+naming
        model gets noisily wrong on sibling APIs. The symbolic layer still owns
        lifecycle ordering, dependency wiring, INPUT_BUFFER detection, and
        synthesis.

        The LLM ADJUDICATES with evidence rather than cold-guessing the
        signature. Optional context (all sourced from analysis we already run):
        ``api_docstrings`` (doxygen @brief/@param/@return), ``usage_context``
        (the API's real call neighbours from the automaton traces),
        ``det_verdicts`` (the deterministic rule verdict + conflicting claims),
        and ``handle_types`` (the project's opaque-handle type catalogue, so a
        handle arg isn't mistaken for a data buffer). Cache is name-keyed, so
        clear ``api_roles.json`` when the context inputs change materially.
        """
        api_docstrings = api_docstrings or {}
        usage_context = usage_context or {}
        det_verdicts = det_verdicts or {}
        catalogue = ", ".join(sorted(handle_types or [])[:48]) or "(none detected)"
        cached = self.cache.load_api_roles()
        roles: Dict[str, Dict[str, Any]] = {}
        api_lookup = {a.get("function_name", ""): a for a in project_apis}
        need_llm: List[Dict[str, Any]] = []
        for name in api_names:
            if not name or name in roles:
                continue
            if name in cached and isinstance(cached[name], dict):
                roles[name] = cached[name]
                continue
            api = api_lookup.get(name)
            if api is not None:
                need_llm.append(api)

        for batch_start in range(0, len(need_llm), API_BATCH_SIZE):
            batch = need_llm[batch_start:batch_start + API_BATCH_SIZE]
            blocks: List[str] = []
            for a in batch:
                nm = a.get("function_name", "")
                lines = [f"### {nm}", f"signature: {_format_signature(a)}"]
                if api_docstrings.get(nm):
                    lines.append(f"doc: {api_docstrings[nm]}")
                if usage_context.get(nm):
                    lines.append(f"real usage: {usage_context[nm]}")
                if det_verdicts.get(nm):
                    lines.append(f"rule verdict: {det_verdicts[nm]}")
                blocks.append("\n".join(lines))
            user = (
                f"Library: {self.project_name} — {purpose or '(purpose unknown)'}\n\n"
                f"Opaque handle types in this library (a parameter of one of these "
                f"types is HANDLE_IN / NULLABLE_HANDLE, NOT a data INPUT_BUFFER): "
                f"{catalogue}\n\n"
                f"Classify each function below. Weigh the doc, the real usage, and "
                f"the rule verdict; adjudicate conflicts and keep the rule's role "
                f"when it already looks right.\n\n"
                + "\n\n".join(blocks))
            raw = self._invoke(_ROLE_SYSTEM_PROMPT, user)
            parsed = _extract_json_block(raw)
            if not isinstance(parsed, dict):
                logger.warning(
                    "Comprehender-role: unparsable response for batch at %d "
                    "(%d APIs left unclassified → deterministic fallback)",
                    batch_start, len(batch))
                continue
            for api in batch:
                name = api.get("function_name", "")
                entry = parsed.get(name)
                if name and isinstance(entry, dict) and entry.get("role"):
                    roles[name] = entry

        if roles:
            merged = dict(cached)
            merged.update(roles)
            self.cache.save_api_roles(merged)
        return roles

    # ---------------------------------------------------------------- A.usage
    def comprehend_apis(self,
                        api_names: Sequence[str],
                        project_apis: Sequence[Dict[str, Any]],
                        purpose: str,
                        condition_info: Optional[Dict[str, Any]] = None,
                        lifecycle_analysis: Optional[Dict[str, Any]] = None,
                        api_docstrings: Optional[Dict[str, str]] = None,
                        api_roles: Optional[Dict[str, str]] = None,
                        ) -> Dict[str, str]:
        """Per-API usage with cache → deterministic → doxygen → LLM layering.

        ``api_docstrings`` (T1 prior, opt-in): map of API name →
        doxygen description extracted by
        ``src.knowledge.project_docs.extract_doxygen_comments``. When
        an API has a substantive docstring we use it directly and
        skip the LLM batch for that API — the doc is ground truth
        the LLM can only paraphrase. Short / vacuous docstrings fall
        through to the LLM unchanged.
        """
        condition_info = condition_info or {}
        lifecycle_analysis = lifecycle_analysis or {}
        api_docstrings = api_docstrings or {}
        cached_usages = self.cache.load_api_usages()
        usages: Dict[str, str] = {}
        api_lookup = {a.get("function_name", ""): a for a in project_apis}

        # Layer 1: cache hit → reuse
        # Layer 2: deterministic synthesis from static facts
        # Layer 3: doxygen-derived usage (T1 prior, opt-in)
        # Layer 4: LLM batched fallback for the remainder
        n_doc_used = 0
        need_llm: List[Dict[str, Any]] = []
        for name in api_names:
            if not name or name in usages:
                continue
            if name in cached_usages and cached_usages[name].strip():
                usages[name] = cached_usages[name]
                continue
            api = api_lookup.get(name)
            if api is None:
                continue
            det = _deterministic_usage(api, condition_info, lifecycle_analysis,
                                       api_roles)
            if det:
                usages[name] = det
                continue
            doc = api_docstrings.get(name, "")
            doc_usage = _doc_derived_usage(api, doc)
            if doc_usage:
                usages[name] = doc_usage
                n_doc_used += 1
                continue
            need_llm.append(api)

        if n_doc_used:
            logger.info(
                "Comprehender-A: %d APIs resolved from doxygen "
                "(LLM saved on these)", n_doc_used,
            )

        if need_llm:
            self._llm_fill_api_usages(
                need_llm,
                purpose=purpose,
                condition_info=condition_info,
                lifecycle_analysis=lifecycle_analysis,
                out=usages,
            )

        # Persist (merging with prior cache so concurrent runs don't lose data)
        merged = dict(cached_usages)
        merged.update(usages)
        self.cache.save_api_usages(merged)
        return usages

    def _llm_fill_api_usages(self,
                             apis: List[Dict[str, Any]],
                             purpose: str,
                             condition_info: Dict[str, Any],
                             lifecycle_analysis: Dict[str, Any],
                             out: Dict[str, str]) -> None:
        system = self.prompts.get_system_prompt("comprehender_api_usage")
        static_facts = _build_static_facts(condition_info, lifecycle_analysis)
        for batch_start in range(0, len(apis), API_BATCH_SIZE):
            batch = apis[batch_start:batch_start + API_BATCH_SIZE]
            sigs = "\n".join(_format_signature(a) for a in batch)
            user = self.prompts.build_user_prompt(
                "comprehender_api_usage",
                library_name=self.project_name,
                library_purpose=purpose or "(unknown)",
                static_facts=static_facts,
                api_signatures=sigs,
            )
            raw = self._invoke(system, user)
            parsed = _extract_json_block(raw)
            if not isinstance(parsed, dict):
                # Batch parse failed (LLM error / malformed JSON / network).
                # Previously this just `continue`d, leaving every API in
                # the batch without a usage — Prototyper then saw
                # "(no usage available)" for all of them and lost the
                # static-fact signal we had cheaply. Now we synthesize a
                # signature-only fallback per API so downstream agents
                # at least see the API shape. 2026-05 review (C5).
                logger.warning(
                    "Comprehender-A: unparsable response for batch starting at %d; "
                    "writing signature-only fallback for %d APIs",
                    batch_start, len(batch),
                )
                for api in batch:
                    name = api.get("function_name", "")
                    if name and name not in out:
                        out[name] = (
                            f"signature: {_format_signature(api)}"
                            " (usage detail unavailable; LLM call failed)"
                        )
                continue
            for api in batch:
                name = api.get("function_name", "")
                if not name:
                    continue
                value = parsed.get(name)
                if isinstance(value, str) and value.strip():
                    out[name] = value.strip()
                elif name not in out:
                    # LLM parsed but didn't return an entry for this API.
                    # Signature-only fallback (same rationale as the
                    # batch-fail branch above). 2026-05 review (C5).
                    out[name] = (
                        f"signature: {_format_signature(api)}"
                        " (usage detail unavailable; LLM omitted this entry)"
                    )

    # ---------------------------------------------------------------- B.sequence
    def comprehend_sequences(self,
                             sequences: Sequence[Sequence[str]],
                             api_usages: Dict[str, str],
                             purpose: str,
                             allowed_apis: Sequence[str],
                             condition_info: Optional[Dict[str, Any]] = None,
                             lifecycle_analysis: Optional[Dict[str, Any]] = None,
                             automaton_acceptance_fn: Optional[Any] = None,
                             ) -> List[SequenceSemantics]:
        """Per-sequence semantic verdict. Cache-aware.

        When ``automaton_acceptance_fn`` is supplied (a callable returning a
        score in ``[0.0, 1.0]`` from the project-adaptive automaton), it is
        used as a *positive-only* prefilter:

        - **acceptance == 1.0** → emit VALID with no diagnosis, skip LLM
        - **acceptance < 1.0** → defer to LLM (we cannot conclude INVALID
          from non-acceptance because the automaton's training corpus is
          inevitably incomplete; a sequence not seen in tests may still be
          a perfectly valid direct entry point or a novel-but-correct
          combination. Conservative bias: absence of evidence ≠ evidence
          of absence.)

        Cuts LLM calls roughly proportional to the fraction of candidate
        sequences that hit canonical project protocols. Empirically ~30–50%
        on libucl-shaped projects.
        """
        condition_info = condition_info or {}
        lifecycle_analysis = lifecycle_analysis or {}
        cached = self.cache.load_sequence_semantics()
        results: List[SequenceSemantics] = []
        new_cache: Dict[str, Dict[str, Any]] = {}
        system = self.prompts.get_system_prompt("comprehender_sequence")
        static_facts = _build_static_facts(condition_info, lifecycle_analysis)
        allowed_text = ", ".join(sorted({a for a in allowed_apis if a}))
        n_prefilter_valid = 0
        n_llm_calls = 0

        for seq in sequences:
            seq_list = [s for s in seq if s]
            if not seq_list:
                continue
            key = self.cache.sequence_key(seq_list)
            if key in cached:
                results.append(SequenceSemantics.from_dict(cached[key]))
                new_cache[key] = cached[key]
                continue

            # Positive-only automaton prefilter: emit VALID without an LLM
            # call when the sequence walks fully through the learned protocol
            # automaton. Anything less than full acceptance defers to LLM —
            # the automaton's training corpus is inevitably incomplete and
            # an unobserved sequence is not the same as an invalid one.
            #
            # Strength gate (2026-05 Comprehender+Closed-loop review, Q2):
            # only trust the positive prefilter when the underlying automaton
            # has accumulated enough evidence to be strong (matches the
            # L4-side ``AutomatonAcceptanceGuard.is_strong()`` policy).
            # Weak automatons can produce false-positive acc=1.0 on short
            # sequences whose APIs happen to have been observed early.
            if (automaton_acceptance_fn is not None
                    and _automaton_is_strong(automaton_acceptance_fn)):
                try:
                    acc = automaton_acceptance_fn(seq_list)
                except Exception:
                    acc = -1.0
                if acc >= 0.999:
                    semantics = SequenceSemantics(
                        sequence=seq_list,
                        semantic_status="VALID",
                        diagnosis="",
                    )
                    n_prefilter_valid += 1
                    results.append(semantics)
                    new_cache[key] = semantics.to_dict()
                    continue
                # else fall through to LLM
            usages_block = "\n".join(
                f"  {name}: {api_usages.get(name, '(no usage available)')}"
                for name in seq_list
            )
            user = self.prompts.build_user_prompt(
                "comprehender_sequence",
                library_name=self.project_name,
                library_purpose=purpose or "(unknown)",
                sequence=" -> ".join(seq_list),
                api_usages=usages_block,
                static_facts=static_facts,
                allowed_apis=allowed_text or "(none)",
            )
            raw = self._invoke(system, user)
            n_llm_calls += 1
            parsed = _extract_json_block(raw)
            if not isinstance(parsed, dict):
                # Fail-soft: treat as VALID with no annotations.
                semantics = SequenceSemantics(sequence=seq_list)
            else:
                parsed["sequence"] = seq_list
                semantics = SequenceSemantics.from_dict(parsed)
                # Defensive: drop patched_sequence if it contains unknown APIs.
                if semantics.patched_sequence:
                    allowed_set = set(allowed_apis)
                    if not all(a in allowed_set for a in semantics.patched_sequence):
                        logger.warning(
                            "Comprehender-B: discarding patched_sequence with "
                            "out-of-pool APIs for %s",
                            seq_list,
                        )
                        semantics.patched_sequence = None
                        semantics.repair_action = "NONE"
            results.append(semantics)
            new_cache[key] = semantics.to_dict()

        if automaton_acceptance_fn is not None:
            logger.info(
                "Comprehender-B prefilter: prefilter_VALID=%d, LLM_calls=%d",
                n_prefilter_valid, n_llm_calls,
            )

        # Persist merged cache
        merged = dict(cached)
        merged.update(new_cache)
        self.cache.save_sequence_semantics(merged)
        return results
