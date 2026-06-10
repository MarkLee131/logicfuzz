"""T7 — cross-project driver retrieval (gated `LOGICFUZZ_CROSS_PROJECT`).

When a target library is *resource-thin* (few/no own OSS-Fuzz drivers, doxygen, or
tests) generation has little library-specific usage to learn from. This retrieves
structurally-similar fuzz drivers from a corpus of OTHER projects' drivers and
injects them as compressed CALLSPEC-style hints.

Design (user-decided — see CLAUDE.md Open TODOs / audit B1-①):
  - **corpus** = all OSS-Fuzz drivers (scale-up: via the FuzzIntrospector API,
    offline-indexed once; MVP here = local `extracted_fuzz_drivers/<proj>/*.c`).
  - **prefer same-project drivers first**; go cross-project only when own is thin.
  - **retrieval = structure-signature primary** (deterministic, one-time index:
    API set / lifecycle-role hints / entry-type hints / call bigrams). If
    structure-sig precision proves insufficient (residual project-local helpers),
    the cross-naming fallback is an **OpenAI `text-embedding-3-large`** re-rank —
    NOT wired here; build only when structure-sig is shown lacking.
  - **selection = scope + relevance threshold** (score ≥ τ), NOT top-N; fall back
    to the single best for resource-thin libs; an LLM later picks 1–2 of the k.
  - **injection = compressed** (driver API sequence + role/entry hints), not raw.

This module is the deterministic structure-signature core — pure & unit-tested.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

# Repo root (this file = <root>/liberator_adapter/analysis/cross_project_retrieval.py).
_ROOT = Path(__file__).resolve().parents[2]
_DEDUP_KEEP = _ROOT / "results" / "xproj_index" / "dedup_keep.json"

# Lifecycle / entry role hints by name token (deterministic, language-agnostic).
_ENTRY_TOK = ("parse", "open", "load", "decode", "read", "begin", "scan",
              "frommem", "frommemory", "fromfile", "frombuffer", "frommem")
_CREATE_TOK = ("create", "new", "init", "alloc", "open", "make", "build")
_DESTROY_TOK = ("free", "destroy", "delete", "close", "release", "end",
                "cleanup", "dispose", "fini")
# C keywords / libfuzzer boilerplate that look like calls but aren't library APIs.
_NOT_API = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "static_cast",
    "reinterpret_cast", "const_cast", "dynamic_cast", "assert", "sizeof",
    "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize", "main", "memcpy", "memset",
    "malloc", "free", "calloc", "realloc", "printf", "fprintf", "sizeof",
})
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def extract_api_calls(source: str) -> List[str]:
    """Ordered list of called identifiers that look like library APIs.

    Precision filters (the structure-sig precision the design flags as the
    embedding-fallback trigger): strip comments first (else license-block words
    like ``Copyright (c)`` register as calls), then drop ALL-CAPS macros
    (``KEEP_FUZZING``), leading-underscore builtins/guards (``__AFL_LOOP``), and
    the boilerplate set. Residual project-local helpers (e.g. ``ProcessFile``)
    are the known precision ceiling → the embedding fallback exists for that.
    """
    src = _COMMENT_RE.sub(" ", source or "")
    out: List[str] = []
    for m in _CALL_RE.finditer(src):
        name = m.group(1)
        if name in _NOT_API:
            continue
        if name.startswith("__"):           # compiler builtins / include guards
            continue
        if name.isupper():                  # MACROS / constants (KEEP_FUZZING)
            continue
        out.append(name)
    return out


def _has_tok(name: str, toks: Sequence[str]) -> bool:
    low = name.lower()
    return any(t in low for t in toks)


@dataclass(frozen=True)
class DriverSignature:
    """Structural fingerprint of a driver — the retrieval key."""
    project: str
    name: str
    api_set: frozenset = field(default_factory=frozenset)
    entry_hints: frozenset = field(default_factory=frozenset)
    create_hints: frozenset = field(default_factory=frozenset)
    destroy_hints: frozenset = field(default_factory=frozenset)
    bigrams: frozenset = field(default_factory=frozenset)
    api_sequence: Tuple[str, ...] = ()


def signature_of(api_calls: Sequence[str], project: str = "",
                 name: str = "") -> DriverSignature:
    apis = [a for a in api_calls if a]
    aset = frozenset(apis)
    bigr = frozenset(zip(apis, apis[1:])) if len(apis) > 1 else frozenset()
    return DriverSignature(
        project=project, name=name, api_set=aset,
        entry_hints=frozenset(a for a in aset if _has_tok(a, _ENTRY_TOK)),
        create_hints=frozenset(a for a in aset if _has_tok(a, _CREATE_TOK)),
        destroy_hints=frozenset(a for a in aset if _has_tok(a, _DESTROY_TOK)),
        bigrams=bigr, api_sequence=tuple(apis))


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def overlap(a: DriverSignature, b: DriverSignature) -> float:
    """Weighted structural similarity in [0,1]. API-set dominates; role/entry
    hints catch same-shape-different-names; bigrams reward shared call order."""
    role_a = a.entry_hints | a.create_hints | a.destroy_hints
    role_b = b.entry_hints | b.create_hints | b.destroy_hints
    return (0.60 * _jaccard(a.api_set, b.api_set)
            + 0.25 * _jaccard(role_a, role_b)
            + 0.15 * _jaccard(a.bigrams, b.bigrams))


def is_resource_thin(own_driver_count: int, has_docs: bool,
                     has_tests: bool) -> bool:
    """Trigger: go cross-project only when the target's OWN material is thin —
    no own drivers, OR a single driver with no docs and no tests."""
    if own_driver_count <= 0:
        return True
    if own_driver_count <= 1 and not has_docs and not has_tests:
        return True
    return False


# Embedding fallback (cross-naming residual, when structure-sig is insufficient):
# OpenAI ``text-embedding-3-large`` re-rank of the candidates. Not built here —
# add a single embed-and-cosine pass when the structure-sig precision is shown
# lacking by a coverage A/B.


def retrieve(
    target: DriverSignature,
    corpus: Sequence[DriverSignature],
    *,
    tau: float = 0.15,
    budget: int = 5,
    prefer_project: Optional[str] = None,
) -> List[DriverSignature]:
    """Scope+threshold retrieval. Same-project drivers come FIRST (user rule),
    then cross-project hits with score ≥ ``tau``, up to ``budget`` total. Falls back
    to the single best cross-project hit when none clears τ (resource-thin
    safety net). A driver identical to the target (same project+name) is skipped.
    """
    prefer = prefer_project or target.project
    scored: List[Tuple[float, DriverSignature]] = []
    same: List[DriverSignature] = []
    for c in corpus:
        if c.project == target.project and c.name == target.name:
            continue
        if prefer and c.project == prefer:
            same.append(c)
            continue
        scored.append((overlap(target, c), c))
    scored.sort(key=lambda x: (-x[0], x[1].project, x[1].name))

    out: List[DriverSignature] = list(same[:budget])
    for score, c in scored:
        if len(out) >= budget:
            break
        if score >= tau:
            out.append(c)
    if not out and scored:                      # resource-thin fallback: best-1
        out = [scored[0][1]]
    return out[:budget]


def render_hints(hits: Sequence[DriverSignature], *, max_apis: int = 12) -> str:
    """Compressed CALLSPEC-style block — driver API order + role/entry markers,
    not raw source. Empty string for no hits."""
    if not hits:
        return ""
    lines = ["<cross_project_examples> (structurally-similar drivers from other "
             "OSS-Fuzz projects — adapt the SHAPE, not the literal API names)"]
    for h in hits:
        seq = " → ".join(h.api_sequence[:max_apis])
        if len(h.api_sequence) > max_apis:
            seq += " …"
        entry = ", ".join(sorted(h.entry_hints)) or "—"
        lines.append(f"  [{h.project}/{h.name}] entry={entry}")
        lines.append(f"    seq: {seq}")
    lines.append("</cross_project_examples>")
    return "\n".join(lines)


def _load_dedup_keep() -> Optional[Set[Tuple[str, str]]]:
    """Deduped corpus keep-list as a set of ``(project, filename)`` pairs.

    Built by ``scripts/dedup_xproj_index.py`` (drops vendored near-copies via
    source-embedding cosine + libFuzzer-selftest noise — 4757→2217). Returns
    None when the file is absent → no filtering (use the whole corpus, the
    pre-dedup behaviour). Matching by (project, filename) is robust to how
    ``root`` is passed (relative vs absolute)."""
    try:
        data = json.loads(_DEDUP_KEEP.read_text())
    except (OSError, ValueError):
        return None
    keep = {(Path(p).parent.name, Path(p).name) for p in (data.get("keep_paths") or [])}
    return keep or None


def load_corpus(root: Path,
                exts: Sequence[str] = (".c", ".cc", ".cpp", ".cxx", ".c++")
                ) -> List[DriverSignature]:
    """Build signatures for every driver under ``root/<project>/*.{c,cc,cpp,cxx,c++}``.
    (Bucket ``human_written_targets`` extension histogram: .cpp 1840 / .cc 1496 /
    .c 1363 / .cxx 56 / .c++ 2 — the default set must cover .cxx/.c++ or 58 C++
    harnesses silently drop. ``.suffix.lower()`` folds ``.C`` onto ``.c``.)
    Best-effort: unreadable files skipped. Returns [] if root absent.
    When ``results/xproj_index/dedup_keep.json`` exists, the corpus is restricted
    to the deduped keep-list (vendored near-copies + libFuzzer-selftest noise
    removed, 4757→2217); absent → the whole corpus (pre-dedup behaviour)."""
    out: List[DriverSignature] = []
    root = Path(root)
    if not root.is_dir():
        return out
    keep = _load_dedup_keep()
    for proj_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for f in sorted(proj_dir.iterdir()):
            if f.suffix.lower() not in exts or not f.is_file():
                continue
            if keep is not None and (proj_dir.name, f.name) not in keep:
                continue
            try:
                src = f.read_text(errors="replace")
            except OSError:
                continue
            out.append(signature_of(extract_api_calls(src),
                                    project=proj_dir.name, name=f.stem))
    return out


def retrieve_hints_for_apis(
    target_apis: Sequence[str],
    *,
    project: str,
    corpus_root: Path,
    tau: float = 0.15,
    budget: int = 5,
) -> str:
    """End-to-end convenience for the gated wiring: build the target signature
    from its API surface, load the local corpus, apply the resource-thin trigger
    (rich own project → its OWN drivers only as examples; thin → allow
    cross-project), retrieve (same-project first), render hints. Best-effort → ''
    on any failure."""
    try:
        corpus = load_corpus(corpus_root)
        if not corpus:
            return ""
        own = [c for c in corpus if c.project == project]
        # has_docs/has_tests not cheaply known here → own-driver count is the
        # signal; conservative (cross-project only when own is genuinely thin).
        thin = is_resource_thin(len(own), has_docs=False, has_tests=False)
        use = corpus if thin else (own or corpus)
        tgt = signature_of(list(target_apis), project=project, name="__target__")
        hits = retrieve(tgt, use, tau=tau, budget=budget,
                        prefer_project=project)
        return render_hints(hits)
    except Exception:
        return ""
