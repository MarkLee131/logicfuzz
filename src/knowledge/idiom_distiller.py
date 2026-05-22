"""Idiom Distiller — Phase B of the 5-stage system redesign.

When ``existing_driver_knowledge`` is populated, the baseline fuzz
driver(s) already encode a lot of hard-won knowledge about how to
turn fuzzer input into a valid call sequence: minimum-size guards,
null-termination tricks, header/body splits, cleanup pairing, etc.
The legacy pipeline drops the whole baseline source into the
Prototyper prompt as a ``<reference_drivers>`` block — useful, but
unstructured. The LLM may or may not pick up on the deep idioms.

This module extracts **structured, actionable idioms** from baseline
driver source. The first layer (this commit) is deterministic pattern
matching on the C source — fast, free, no LLM tokens, and the
idioms it surfaces are concrete enough that the Prototyper can be
told *exactly* what to include. A second LLM-driven layer can be
added later for richer multi-stage patterns.

Distilled idioms feed:

- **Prototyper**: as a high-priority ``<library_idioms>`` block in the
  prompt — turns "look at this for inspiration" into "you MUST include
  the min-size guard / null-terminator / cleanup pattern shown here".
- **Phase D (Planner)** [future]: pick idioms aligned to target paths.
- **Phase A (Repair Engine)** [future]: graft can prefer creators that
  match library idioms.

The idiom set is persisted as JSON to
``results/<project>/state/idioms.json`` for inspection and cross-run
reuse.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class IdiomKind(Enum):
    """Category of pattern extracted from a baseline driver.

    L1 (deterministic regex / AST-light pattern matching):
    """
    MIN_SIZE_GUARD = "min_size_guard"
    """``if (size < N) return 0;`` — early-exit on too-small inputs."""

    SIZE_CAP = "size_cap"
    """``if (size > N) size = N;`` — truncate oversized inputs."""

    NULL_TERMINATE_INPUT = "null_terminate_input"
    """Copy data into a buffer and append ``\\0`` — required by APIs
    that take ``const char*`` and call ``strlen``."""

    BUFFER_COPY = "buffer_copy"
    """Allocate a local buffer and ``memcpy`` from ``data`` —
    pre-condition for in-place mutation or signature-strict APIs."""

    HEADER_BODY_SPLIT = "header_body_split"
    """Extract a fixed-prefix header from ``data``, treat the rest as
    body. Enables multi-stage parsers."""

    CLEANUP_PAIR = "cleanup_pair"
    """``X_create(...)`` / ``X_destroy(...)`` matched pairs at function
    body bookends."""

    CONTEXT_NULL_PASS = "context_null_pass"
    """Pass ``NULL`` for an optional context parameter — the
    ``cmsContext`` family in lcms is the canonical example."""

    NULL_TERMINATION_REQUIRED = "null_termination_required"
    """``if (data[size - 1] != '\\0') return 0;`` — the API expects
    the input to already be null-terminated; the driver bails
    instead of attempting to fix it."""

    HEADER_FLAG_DEMUX = "header_flag_demux"
    """First N bytes of ``data`` are interpreted as on/off flags or
    enum selectors, multiplexing fuzz target sub-arms."""

    DATA_OFFSET_PARSE = "data_offset_parse"
    """``parse(data + offset, ...)`` — skip a fixed prefix when
    handing data to the API. Often paired with HEADER_FLAG_DEMUX."""

    # Future LLM-tier idioms (placeholder for Phase B-L2):
    # MULTI_STAGE_PARSE = "multi_stage_parse"
    # EDGE_CASE_TRICK   = "edge_case_trick"


@dataclass
class Idiom:
    """One distilled pattern."""
    kind: IdiomKind
    snippet: str
    """Canonical example code (verbatim from the source or
    normalised)."""
    rationale: str
    """One-line "why does the baseline driver do this" — used as
    the actionable hint in the Prototyper prompt."""
    source_driver: str
    """Which baseline driver this came from."""
    confidence: float = 1.0
    """Pattern-match confidence in [0, 1]. Deterministic L1 patterns
    are 1.0 by construction; LLM L2 idioms get lower default."""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['kind'] = self.kind.value
        return d


@dataclass
class IdiomLibrary:
    """All idioms distilled for one project, plus run metadata."""
    project: str
    idioms: List[Idiom] = field(default_factory=list)
    distillation_method: str = "deterministic_l1"

    def add(self, idiom: Idiom) -> None:
        # Dedupe by (kind, snippet) — same pattern from multiple
        # drivers gets reported once with the first source kept.
        for existing in self.idioms:
            if existing.kind == idiom.kind and existing.snippet == idiom.snippet:
                return
        self.idioms.append(idiom)

    def by_kind(self, kind: IdiomKind) -> List[Idiom]:
        return [i for i in self.idioms if i.kind == kind]

    def to_dict(self) -> dict:
        return {
            'project': self.project,
            'distillation_method': self.distillation_method,
            'idiom_count': len(self.idioms),
            'by_kind_count': {
                k.value: len(self.by_kind(k)) for k in IdiomKind
                if self.by_kind(k)
            },
            'idioms': [i.to_dict() for i in self.idioms],
        }

    def persist(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# L1 deterministic pattern matchers
# ---------------------------------------------------------------------------

# Each matcher returns a list of (snippet, rationale) tuples; the
# distiller wraps them as Idioms with the right kind + source.

_RE_MIN_SIZE = re.compile(
    # ``if (size < N) return 0;`` / ``if (size <= N) ...``  /
    # ``if (size <= offset) ...`` / ``if (size < sizeof(...)) ...``
    r'if\s*\(\s*size\s*<=?\s*(\d+|\w+|sizeof\s*\([^)]+\))\s*\)\s*\n?\s*return\s+\d+\s*;',
    re.IGNORECASE,
)
_RE_NULL_TERM_REQUIRED = re.compile(
    r"if\s*\(\s*data\s*\[\s*size\s*-\s*1\s*\]\s*!=\s*['\"]?\\?0['\"]?\s*\)\s*\n?\s*return\s+\d+\s*;",
)
_RE_DATA_OFFSET = re.compile(
    # ``(...cast?) data + offset`` or ``data + N``
    r"(?:\([^)]+\)\s*)?data\s*\+\s*(\w+)\b",
)
_RE_HEADER_FLAG_DEMUX = re.compile(
    # ``data[0] == '1'`` / ``data[0] != '0'`` / ``data[N] & 1`` style
    r"data\s*\[\s*\d+\s*\]\s*(?:==|!=|&|\|)\s*[\d'\"]",
)
_RE_SIZE_CAP_CLAMP = re.compile(
    r'if\s*\(\s*size\s*>\s*(\d+)\s*\)\s*\n?\s*size\s*=\s*\1\s*;',
    re.IGNORECASE,
)
_RE_SIZE_CAP_STDMIN = re.compile(
    r'size\s*=\s*std::min\s*\(\s*size\s*,\s*\w+\s*\)\s*;',
    re.IGNORECASE,
)
_RE_NULL_TERMINATE = re.compile(
    # Patterns: buf[size] = '\0';  or  memcpy(buf, data, size); buf[size] = 0;
    r"(?:\w+\s*\[\s*size\s*\]\s*=\s*['\"]?\\?0['\"]?\s*;"
    r"|\w+\s*\[\s*size\s*\]\s*=\s*0\s*;)",
)
_RE_BUFFER_COPY = re.compile(
    r"memcpy\s*\(\s*(\w+)\s*,\s*data\s*,\s*size\s*\)\s*;",
)
_RE_HEADER_SPLIT = re.compile(
    # data += N; size -= N; — fixed-size header skip
    r"data\s*\+=\s*(\d+|sizeof\s*\([^)]+\))\s*;\s*\n?\s*size\s*-=\s*\1\s*;",
)


def _find_cleanup_pairs(source: str) -> List[tuple]:
    """Find ``X_create(...)`` / ``X_destroy(...)`` matched pairs.

    Conservative: only treats them as a pair when both appear within
    the same function body. Returns ``[(create_call, destroy_call)]``.
    """
    pairs = []
    # Look for canonical create/init * destroy/free pairs.
    # Pattern: <prefix>_(new|create|alloc|init|open)  ↔  <prefix>_(delete|destroy|free|close)
    create_re = re.compile(
        r'\b(\w+_(?:new|create|alloc|init|open|parse))\s*\(',
        re.IGNORECASE,
    )
    destroy_re = re.compile(
        r'\b(\w+_(?:delete|destroy|free|close|cleanup|fini))\s*\(',
        re.IGNORECASE,
    )
    creates = set(m.group(1) for m in create_re.finditer(source))
    destroys = set(m.group(1) for m in destroy_re.finditer(source))
    for c in sorted(creates):
        # Try to match by prefix swap.
        for suffix in ("delete", "destroy", "free", "close", "cleanup", "fini"):
            for create_suffix in ("new", "create", "alloc", "init", "open", "parse"):
                if c.lower().endswith("_" + create_suffix):
                    base = c[:-len(create_suffix) - 1]
                    candidate = f"{base}_{suffix}"
                    if candidate in destroys or candidate.lower() in {d.lower() for d in destroys}:
                        pairs.append((c, candidate))
                        break
            else:
                continue
            break
    return pairs


def _find_null_context_pass(source: str, context_type_hints: tuple) -> List[str]:
    """Find call sites that pass NULL for a known optional-context param.

    ``context_type_hints`` lists library-specific function-name prefixes
    whose 0th arg is the optional context. For now we just look for
    explicit ``foo(NULL, ...)`` patterns where the function name starts
    with one of those prefixes; future versions can plug in the IR-side
    nullable-handle tag.
    """
    hits = []
    for prefix in context_type_hints:
        pattern = re.compile(
            rf'\b({re.escape(prefix)}\w*)\s*\(\s*NULL\s*[,\)]',
            re.IGNORECASE,
        )
        for m in pattern.finditer(source):
            hits.append(m.group(0).rstrip(', '))
    return hits


# ---------------------------------------------------------------------------
# Distiller entry point
# ---------------------------------------------------------------------------

# Library-specific hints for the CONTEXT_NULL_PASS pattern. Operator
# can extend this; future Phase B-L2 will infer it from IR nullable tags.
_CONTEXT_HINTS_BY_PROJECT: Dict[str, tuple] = {
    "lcms": ("cms",),
    "lcms2": ("cms",),
    "cjson": (),
    "c-ares": ("ares_",),
    "libucl": ("ucl_",),
}


def distill_idioms(
    project: str,
    driver_sources: List[Dict[str, str]],
) -> IdiomLibrary:
    """Run L1 deterministic distillation on a project's baseline drivers.

    ``driver_sources`` shape mirrors ``existing_driver_knowledge.driver_sources``:
    each entry has ``{'path': <abs path>, 'source': <full C text>}``.
    """
    lib = IdiomLibrary(project=project)
    context_hints = _CONTEXT_HINTS_BY_PROJECT.get(project, ())

    for entry in driver_sources:
        src = entry.get('source', '') or ''
        path = entry.get('path', '<unknown>')
        if not src:
            continue
        src_name = Path(path).name if path else '<unknown>'

        for m in _RE_MIN_SIZE.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.MIN_SIZE_GUARD,
                snippet=m.group(0).strip(),
                rationale=(
                    "Skip too-small inputs — fuzzer often produces "
                    "0-or-1-byte payloads that don't form valid library "
                    "input; the early return saves a guaranteed parse "
                    "failure path and lets the fuzzer corpus stay "
                    "structurally interesting."
                ),
                source_driver=src_name,
            ))

        for m in _RE_SIZE_CAP_CLAMP.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.SIZE_CAP,
                snippet=m.group(0).strip(),
                rationale=(
                    "Cap input size — protects against pathological "
                    "huge inputs that explode timeouts. Baseline driver "
                    "uses this explicit clamp; reproduce the same cap."
                ),
                source_driver=src_name,
            ))
        for m in _RE_SIZE_CAP_STDMIN.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.SIZE_CAP,
                snippet=m.group(0).strip(),
                rationale=(
                    "Cap input size (std::min variant). Same intent: "
                    "bound runaway sizes."
                ),
                source_driver=src_name,
            ))

        for m in _RE_NULL_TERMINATE.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.NULL_TERMINATE_INPUT,
                snippet=m.group(0).strip(),
                rationale=(
                    "Null-terminate the input buffer — APIs that take "
                    "``const char*`` and call ``strlen()`` will read past "
                    "the fuzzer-provided size without this. Required for "
                    "any string-parsing API (cjson, libxml2, libucl, …)."
                ),
                source_driver=src_name,
            ))

        for m in _RE_BUFFER_COPY.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.BUFFER_COPY,
                snippet=m.group(0).strip(),
                rationale=(
                    "Copy fuzzer input into a local buffer before the "
                    "library touches it. Needed when the library mutates "
                    "in-place, or when its signature wants a non-const "
                    "buffer."
                ),
                source_driver=src_name,
            ))

        for m in _RE_HEADER_SPLIT.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.HEADER_BODY_SPLIT,
                snippet=m.group(0).strip(),
                rationale=(
                    "Use the first N bytes as a header (e.g. selecting "
                    "a mode / format / fuzz target sub-arm), the rest "
                    "as body. Lets one fuzz target multiplex multiple "
                    "library entry points from a single corpus."
                ),
                source_driver=src_name,
            ))

        for m in _RE_NULL_TERM_REQUIRED.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.NULL_TERMINATION_REQUIRED,
                snippet=m.group(0).strip(),
                rationale=(
                    "API requires a null-terminated input; the baseline "
                    "bails when fuzzer didn't already provide one rather "
                    "than appending '\\0' itself. Reproduce the same "
                    "guard — otherwise un-terminated fuzzer payloads "
                    "either crash deep in the API or get silently "
                    "rejected with no driver-side signal."
                ),
                source_driver=src_name,
            ))

        for m in _RE_HEADER_FLAG_DEMUX.finditer(src):
            lib.add(Idiom(
                kind=IdiomKind.HEADER_FLAG_DEMUX,
                snippet=m.group(0).strip(),
                rationale=(
                    "Use specific bytes of the input as on/off flags or "
                    "enum selectors to multiplex multiple fuzz arms in "
                    "one driver. Each arm exercises a different code "
                    "path; the fuzzer is encouraged to explore all of "
                    "them by mutating these flag bytes."
                ),
                source_driver=src_name,
            ))

        # Find data+offset patterns but only count them as DATA_OFFSET_PARSE
        # if they're using a non-literal offset (signal of structured split).
        for m in _RE_DATA_OFFSET.finditer(src):
            offset_expr = m.group(1)
            # Skip obvious noise (e.g. ``data + i`` inside a loop body).
            if offset_expr in {'i', 'j', 'k', 'index', 'pos', 'idx'}:
                continue
            lib.add(Idiom(
                kind=IdiomKind.DATA_OFFSET_PARSE,
                snippet=m.group(0).strip(),
                rationale=(
                    f"Skip the first {offset_expr} bytes of the fuzzer "
                    "input before handing the rest to the library. The "
                    "skipped prefix is typically a HEADER_FLAG_DEMUX; "
                    "preserve both halves together."
                ),
                source_driver=src_name,
            ))

        for create, destroy in _find_cleanup_pairs(src):
            lib.add(Idiom(
                kind=IdiomKind.CLEANUP_PAIR,
                snippet=f"{create}(...)  →  {destroy}(...);",
                rationale=(
                    f"Every ``{create}`` call must be paired with "
                    f"``{destroy}`` to avoid leaks; the baseline driver "
                    f"does this — reproduce the pattern."
                ),
                source_driver=src_name,
            ))

        for hit in _find_null_context_pass(src, context_hints):
            lib.add(Idiom(
                kind=IdiomKind.CONTEXT_NULL_PASS,
                snippet=hit + ", ...)",
                rationale=(
                    "This API's first arg is an optional context handle; "
                    "passing NULL selects the library default and avoids "
                    "needing a context-creator in the sequence. The "
                    "baseline driver does this — propagate the pattern."
                ),
                source_driver=src_name,
            ))

    return lib


def distill_and_persist(
    project: str,
    driver_sources: List[Dict[str, str]],
    state_dir: Optional[Path] = None,
) -> IdiomLibrary:
    """Convenience: distill + persist to ``results/<project>/state/idioms.json``."""
    lib = distill_idioms(project, driver_sources)
    if state_dir is None:
        state_dir = Path('results') / project / 'state'
    out = state_dir / 'idioms.json'
    try:
        lib.persist(out)
        logger.info(
            "Distilled %d idioms for %s (%s) → %s",
            len(lib.idioms), project,
            ", ".join(f"{k.value}={len(lib.by_kind(k))}"
                      for k in IdiomKind if lib.by_kind(k)) or "none",
            out,
        )
    except Exception as exc:
        logger.warning(
            "Idiom persistence failed for %s (non-critical): %s",
            project, exc,
        )
    return lib
