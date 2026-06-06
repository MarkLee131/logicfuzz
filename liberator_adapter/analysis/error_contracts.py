"""Per-API RETURN error/NULL contracts (T3 / T6②).

Why this module exists
----------------------
Generated drivers that bind a creator's return into a handle *without*
NULL-checking it will SEGV the moment the creator fails on adversarial input —
and a single SEGV poisons the whole merged multi-task harness (see
``MEMORY.md`` "Generated drivers miss NULL-checks on creator returns"). The fix
belongs in *generation*: the hole prompt must tell the model "this creator may
return NULL — guard it". To say that, we need a per-API return contract.

What it produces
----------------
``extract_error_contracts(project)`` →

    { api_name: {
        "may_return_null": bool,      # pointer return with no proof of non-null
        "error_sentinel":  str|None,  # e.g. "0 on success, negative on error"
        "source":          "doc"|"ir" # where the verdict came from
    } }

Two deterministic, best-effort sources (no LLM, no new heavy deps):

  - **doc** — ``@return`` / ``@retval`` free text mined for failure phrasing.
    "returns NULL on error / on failure / on out-of-memory" → may_return_null;
    "returns 0 on success, negative on error" → error_sentinel. The doc verdict
    wins when present (it is intent-level ground truth). Text comes either from
    a caller-supplied ``doc_signals`` map (structured ``{returns: ...}`` from
    ``project_docs.extract_doc_signals``) or from the cached plain-string
    ``api_docstrings`` in ``results/<proj>/comprehension/docs_priors.json``.

  - **ir** — ``results/<proj>/conditions.json``. Each record's ``return`` entry
    has an ``access_type_set``; the top-level element (``parent == 0``) that
    *is* the returned value. When that element is a pointer
    (``type_string`` ends in ``*``) and its provenance does not *prove*
    non-nullness, the return is a may_return_null candidate. None of the
    provenances Liberator emits for returns (UNKNOWN / GLOBAL / STACK /
    PARAM_BORROWED / HEAP_CUSTOM) prove non-null — a freshly-``create``-d heap
    pointer is exactly the OOM-can-fail case we care about — so every pointer
    return is conservatively flagged. Scalar (non-pointer) returns are *not*
    flagged from IR alone (no NULL semantics, and we can't read the sentinel
    from access types).

Everything is wrapped in best-effort guards: a missing file, malformed JSON,
or unexpected shape yields ``{}`` (or skips that record), never an exception.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

logger = logging.getLogger(__name__)

# Repo-root-relative default; callers may override for tests / alt layouts.
_DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parents[2] / "results"


# --------------------------------------------------------------- doc mining
#
# Phrases that say "the return can be a failure value". Matched against the
# lower-cased @return / @retval text. Kept conservative: we want failure
# *contracts*, not every mention of the word "null".

# NULL-return cues → may_return_null = True.
_NULL_RETURN_CUES = (
    "null on error",
    "null on failure",
    "null if",
    "null pointer on",
    "null on out-of-memory",
    "null on out of memory",
    "returns null",
    "return null",
    "nullptr on",
    "0 (null) on",
    "null on allocation failure",
)

# Sentinel cues → error_sentinel = <verbatim return text>. These describe a
# *scalar* failure code (0 / negative / -1) rather than a NULL pointer.
_SENTINEL_CUES = (
    "on success",
    "on error",
    "on failure",
    "negative on",
    "nonzero on",
    "non-zero on",
    "returns 0",
    "return 0",
    "-1 on",
    "zero on success",
    "an error code",
    "error code",
)


def _doc_return_verdict(returns_text: str) -> Optional[Dict[str, Any]]:
    """Map a single ``@return`` text blob to a contract, or ``None``.

    NULL phrasing dominates (it directly drives the NULL-check note). A
    scalar-sentinel phrasing is captured into ``error_sentinel`` verbatim so
    the prompt can echo the developer's own success/failure convention.
    """
    low = (returns_text or "").strip().lower()
    if not low:
        return None

    may_null = any(cue in low for cue in _NULL_RETURN_CUES)

    sentinel: Optional[str] = None
    if any(cue in low for cue in _SENTINEL_CUES):
        # Keep the original (un-lowered, collapsed-whitespace) text — it is the
        # developer's own wording, more useful in a prompt than a paraphrase.
        sentinel = re.sub(r"\s+", " ", (returns_text or "").strip())

    if not may_null and not sentinel:
        return None
    return {
        "may_return_null": bool(may_null),
        "error_sentinel": sentinel,
        "source": "doc",
    }


def _returns_text_from_signal(value: Any) -> str:
    """Pull ``@return`` text out of a doc-signal value.

    Accepts both shapes we see in the wild:
      - structured ``{"brief":..., "params":[...], "returns": "..."}``
        (``project_docs.extract_doc_signals``)
      - a plain docstring string (cached ``api_docstrings``); we scan it for an
        inline ``@return`` / ``@retval`` / ``\\return`` tag.
    """
    if isinstance(value, Mapping):
        return str(value.get("returns") or "")
    if isinstance(value, str):
        m = re.search(r"[\\@](?:returns?|retval)\b[ \t]*(.+)",
                      value, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        # No explicit tag, but a bare "returns NULL on ..." sentence still
        # carries the contract — let the cue matcher see the whole string.
        return value
    return ""


def _contracts_from_docs(
    doc_signals: Mapping[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """Doc-sourced contracts from a ``{api: signal}`` map (best-effort)."""
    out: Dict[str, Dict[str, Any]] = {}
    if not doc_signals:
        return out
    for api, value in doc_signals.items():
        if not api:
            continue
        try:
            rtext = _returns_text_from_signal(value)
            verdict = _doc_return_verdict(rtext)
        except Exception:  # pragma: no cover - defensive
            verdict = None
        if verdict is not None:
            out[str(api)] = verdict
    return out


def _load_cached_docstrings(
    results_root: Path, project: str
) -> Dict[str, Any]:
    """Load ``api_docstrings`` from the cached ``docs_priors.json``, or {}."""
    path = results_root / project / "comprehension" / "docs_priors.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError) as exc:
        logger.debug("docs_priors load failed for %s: %s", project, exc)
        return {}
    if not isinstance(data, dict):
        return {}
    ad = data.get("api_docstrings")
    return ad if isinstance(ad, dict) else {}


# ---------------------------------------------------------------- ir mining
#
# A return whose top-level access element (parent == 0) is a pointer is a
# may_return_null candidate: none of Liberator's return provenances prove
# non-nullness, and the failure mode we guard against (creator OOM → NULL) is
# precisely a freshly-created heap pointer.

# Provenances that would *prove* a non-null pointer return. Liberator currently
# emits none of these for returns, so the set is empty — but naming it makes
# the "no proof of non-null" intent explicit and gives a future-proof hook if
# a NON_NULL / GUARANTEED provenance is ever added upstream.
_NON_NULL_PROVENANCES = frozenset({"NON_NULL", "GUARANTEED_NON_NULL"})


def _is_pointer_type(type_string: str) -> bool:
    return bool(type_string) and type_string.rstrip().endswith("*")


def _return_element(return_rec: Any) -> Optional[Dict[str, Any]]:
    """The access element that *is* the returned value (``parent == 0``)."""
    if not isinstance(return_rec, Mapping):
        return None
    ats = return_rec.get("access_type_set")
    if not isinstance(ats, list):
        return None
    for elem in ats:
        if isinstance(elem, Mapping) and elem.get("parent") == 0:
            return elem
    return None


def _ir_verdict(return_rec: Any) -> Optional[Dict[str, Any]]:
    """may_return_null contract from a record's ``return`` entry, or ``None``."""
    elem = _return_element(return_rec)
    if elem is None:
        return None
    if not _is_pointer_type(str(elem.get("type_string") or "")):
        return None
    prov = elem.get("provenance")
    if prov in _NON_NULL_PROVENANCES:
        return None
    return {
        "may_return_null": True,
        "error_sentinel": None,
        "source": "ir",
    }


def _contracts_from_conditions(
    results_root: Path, project: str
) -> Dict[str, Dict[str, Any]]:
    """IR-sourced contracts from ``results/<proj>/conditions.json`` (best-effort)."""
    path = results_root / project / "conditions.json"
    if not path.is_file():
        return {}
    try:
        records = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError) as exc:
        logger.debug("conditions.json load failed for %s: %s", project, exc)
        return {}
    if not isinstance(records, list):
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        name = rec.get("function_name")
        if not name:
            continue
        try:
            verdict = _ir_verdict(rec.get("return"))
        except Exception:  # pragma: no cover - defensive
            verdict = None
        if verdict is not None:
            out[str(name)] = verdict
    return out


# ------------------------------------------------------------------- public
def extract_error_contracts(
    project: str,
    results_root: Optional[Path] = None,
    doc_signals: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Per-API return error/NULL contracts for ``project`` (best-effort).

    Args:
      project:      project name (the ``results/<project>/`` subdir).
      results_root: override the ``results/`` root (defaults to repo layout).
      doc_signals:  optional ``{api: signal}`` map of structured doc signals
                    (from ``project_docs.extract_doc_signals``). When omitted,
                    the cached ``api_docstrings`` from ``docs_priors.json`` are
                    used instead.

    Returns ``{api: {"may_return_null", "error_sentinel", "source"}}``.
    Doc verdicts take precedence over IR verdicts for the same API (doc is
    intent-level ground truth; IR is a structural over-approximation). Returns
    ``{}`` on any failure.
    """
    try:
        root = Path(results_root) if results_root is not None \
            else _DEFAULT_RESULTS_ROOT

        # IR floor first, then let doc verdicts override per-API.
        contracts: Dict[str, Dict[str, Any]] = _contracts_from_conditions(
            root, project)

        signals: Mapping[str, Any] = doc_signals if doc_signals is not None \
            else _load_cached_docstrings(root, project)
        doc_contracts = _contracts_from_docs(signals)
        contracts.update(doc_contracts)  # doc wins on conflict

        return contracts
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        logger.debug("extract_error_contracts failed for %s: %s", project, exc)
        return {}
