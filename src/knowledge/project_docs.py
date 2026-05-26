"""T1 knowledge layer: README + Doxygen extraction.

Two ground-truth sources we previously ignored:

  - **README** of the target project: 1-3 paragraphs describing
    "what this library does" — replaces the LLM-from-project-name
    fabrication in ``Comprehender.comprehend_purpose``.
  - **Doxygen comments** (``/** ... */`` blocks) above public API
    declarations in project headers: per-API semantics
    (ownership, lifecycle, "caller must free with X") that the
    Comprehender currently invents from the signature alone.

Both extractors are best-effort: they return empty results when the
source isn't present or the format is unrecognised, never raising.
The caller decides whether to use the prior (CLI flags
``--use-readme-purpose`` / ``--use-doxygen-priors``).

Design notes (see ``docs/knowledge_layer_design_proposal_2026_05.md``):

  - README parsing is intentionally simple: strip code fences /
    badges / markdown formatting, take the first non-boilerplate
    paragraph of 3-15 lines. We don't try to render rST — a
    library that ships a substantive rST README will produce a
    reasonable "purpose-ish" excerpt under this stripper anyway.
  - Doxygen extraction uses libclang ``cursor.brief_comment`` /
    ``cursor.raw_comment`` — already in the static_trace toolchain.
    No new dependency.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------- README
_README_CANDIDATES = (
    "README.md",
    "README.MD",
    "README",
    "README.rst",
    "README.txt",
    "Readme.md",
    "readme.md",
    "readme",
)

# Lines that almost never carry purpose information; skipped during paragraph
# selection. Conservative — only obvious chaff.
_README_SKIP_PATTERNS = (
    re.compile(r"^\s*#"),                     # markdown headings (lone #)
    re.compile(r"^\s*\[!\["),                  # badge lines [![...]]
    re.compile(r"^\s*!\["),                    # image lines
    re.compile(r"^\s*<"),                      # HTML tag lines
    re.compile(r"^\s*-{3,}\s*$"),              # rule
    re.compile(r"^\s*={3,}\s*$"),              # rule
    re.compile(r"^\s*\|"),                     # table rows
    re.compile(r"^\s*(\*|-|\+|\d+\.)\s"),     # list bullets
    re.compile(r"^\s*```"),                    # code fence
    re.compile(r"^\s*    \S"),                 # code-indented lines
)

_README_MARKDOWN_INLINE = (
    (re.compile(r"\[([^\]]+)\]\([^)]+\)"), r"\1"),      # [text](url) → text
    (re.compile(r"`([^`]+)`"), r"\1"),                   # `code` → code
    (re.compile(r"\*\*([^*]+)\*\*"), r"\1"),             # **bold** → bold
    (re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)"), r"\1"),    # *italic* → italic
    (re.compile(r"_([^_]+)_"), r"\1"),                   # _italic_ → italic
)


def _strip_inline_markdown(text: str) -> str:
    for pat, repl in _README_MARKDOWN_INLINE:
        text = pat.sub(repl, text)
    return text.strip()


def _find_readme(src_root: Path) -> Optional[Path]:
    """Locate a README file under ``src_root``. First-match wins."""
    if not src_root or not src_root.exists():
        return None
    for name in _README_CANDIDATES:
        candidate = src_root / name
        if candidate.is_file():
            return candidate
    return None


def _is_purpose_paragraph(lines: Sequence[str]) -> bool:
    """Heuristic: a paragraph is "purpose-like" if it's 3-15 lines,
    starts with prose (not a header / bullet / badge), and contains
    a noun verb-able-ish word like ``library``, ``parser``, ``provides``,
    ``implements``, ``supports``, ``decodes``, ``encodes``, ``handles``,
    ``a``/``an``/``the``.
    """
    if not lines:
        return False
    if len(lines) > 15:
        return False
    joined = " ".join(lines).lower()
    if len(joined) < 50:
        return False
    purpose_hints = (
        "library", "parser", "implements", "provides", "supports",
        "decodes", "encodes", "handles", "is a ", "is an ", " a ", " an ",
        " the ", "format", "protocol", "codec", "compress", "json", "xml",
        "image", "audio", "video",
    )
    return any(hint in joined for hint in purpose_hints)


def extract_readme_purpose(src_root: Path,
                           max_chars: int = 1500) -> Optional[str]:
    """Extract a short "purpose paragraph" from a project's README.

    Returns ``None`` when no README is found, or when no paragraph
    matches the purpose heuristic.

    Output is plain prose, suitable to drop into the Comprehender's
    ``doc_excerpts`` field as-is.
    """
    readme = _find_readme(src_root)
    if readme is None:
        logger.debug("No README found under %s", src_root)
        return None

    try:
        raw = readme.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Could not read %s: %s", readme, exc)
        return None

    # Split into paragraphs (blank-line-delimited)
    paragraphs: List[List[str]] = []
    current: List[str] = []
    in_code = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if not stripped:
            if current:
                paragraphs.append(current)
                current = []
            continue
        if any(pat.match(line) for pat in _README_SKIP_PATTERNS):
            # Heading / badge / bullet — flush current paragraph,
            # don't start a new one with this line.
            if current:
                paragraphs.append(current)
                current = []
            continue
        current.append(stripped)
    if current:
        paragraphs.append(current)

    # First paragraph that looks like a purpose statement.
    for para in paragraphs:
        if _is_purpose_paragraph(para):
            text = _strip_inline_markdown(" ".join(para))
            if len(text) > max_chars:
                text = text[:max_chars].rsplit(" ", 1)[0] + "..."
            logger.info(
                "Extracted README purpose from %s (%d chars)",
                readme.name, len(text),
            )
            return text

    logger.debug("README %s has no purpose-like paragraph", readme.name)
    return None


# ---------------------------------------------------------------- Doxygen
_DOXY_HEADER_RE = re.compile(r"^\s*/\*+\s*$")
_DOXY_LINE_RE = re.compile(r"^\s*\*\s?(.*)$")
_DOXY_TRAILING_RE = re.compile(r"^\s*\*+/\s*$")
_DOXY_TAG_RE = re.compile(r"^\s*@\w+\b")
_DOXY_PARAM_RE = re.compile(r"\\param\b|@param\b")


def _normalize_doxygen(raw: Optional[str]) -> str:
    """Convert a raw libclang doxygen blob into a single-paragraph string.

    libclang returns the comment with ``/** ... */`` markers and
    per-line ``*`` prefixes still intact. We strip those, drop empty
    lines, and keep only the descriptive text (no ``@param``,
    ``@returns`` tag bodies — those are useful but verbose and we
    already have signatures elsewhere).
    """
    if not raw:
        return ""
    out_lines: List[str] = []
    seen_descriptive = False
    for line in raw.splitlines():
        if _DOXY_HEADER_RE.match(line) or _DOXY_TRAILING_RE.match(line):
            continue
        m = _DOXY_LINE_RE.match(line)
        body = m.group(1) if m else line.strip()
        body = body.strip()
        if not body:
            continue
        if _DOXY_TAG_RE.match(body) or _DOXY_PARAM_RE.search(body):
            # Stop accumulating once we hit the parameter/return tag block —
            # everything before that is the descriptive lead, which is what
            # the Comprehender wants.
            break
        out_lines.append(body)
        seen_descriptive = True
    if not seen_descriptive:
        return ""
    return " ".join(out_lines).strip()


def extract_doxygen_comments(
    headers_dir: Optional[Path],
    public_headers: Sequence[str],
    api_names: Sequence[str],
) -> Dict[str, str]:
    """Map ``api_name`` → its doxygen description (where present).

    libclang walks each header, looking for ``FUNCTION_DECL`` cursors
    whose ``spelling`` is in ``api_names``. The cursor's
    ``brief_comment`` (preferred) or ``raw_comment`` is normalised
    into a single descriptive paragraph.

    Empty dict on libclang unavailability or any walk failure —
    caller falls back to the LLM-from-signature path.
    """
    if not headers_dir or not public_headers or not api_names:
        return {}

    try:
        from clang.cindex import Cursor, CursorKind, Index, TranslationUnit
    except ImportError:
        logger.warning(
            "libclang Python bindings not available; doxygen extraction skipped"
        )
        return {}

    api_set: Set[str] = {n for n in api_names if n}
    if not api_set:
        return {}

    headers_root = Path(headers_dir)
    if not headers_root.is_dir():
        logger.debug("headers_dir %s is not a directory", headers_dir)
        return {}

    # Resolve each public_headers entry against headers_root. The
    # public_headers list is the same source LFBackendDriver uses for
    # ``#include <...>`` so the names should resolve directly.
    header_paths: List[Path] = []
    for name in public_headers:
        candidate = headers_root / name
        if candidate.is_file():
            header_paths.append(candidate)

    if not header_paths:
        logger.debug(
            "No resolvable header paths under %s for %d header names",
            headers_dir, len(public_headers),
        )
        return {}

    index = Index.create()
    out: Dict[str, str] = {}
    parse_args = [
        "-I", str(headers_root),
        "-x", "c++",                # libclang accepts both for header parsing
        "-std=c++17",
        "-ferror-limit=0",
        "-fparse-all-comments",     # include non-doxygen /* ... */ too
    ]

    def _walk(cursor: 'Cursor') -> None:
        try:
            kind = cursor.kind
        except Exception:
            return
        if kind in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD):
            name = cursor.spelling
            if name and name in api_set and name not in out:
                # Prefer brief_comment (the descriptive lead) over
                # raw_comment (full block including tags).
                doc = ""
                try:
                    doc = (cursor.brief_comment or "").strip()
                except Exception:
                    doc = ""
                if not doc:
                    try:
                        doc = _normalize_doxygen(cursor.raw_comment)
                    except Exception:
                        doc = ""
                if doc:
                    out[name] = doc
        for child in cursor.get_children():
            _walk(child)

    for hp in header_paths:
        try:
            tu = index.parse(
                str(hp),
                args=parse_args,
                options=(
                    TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                    | TranslationUnit.PARSE_INCOMPLETE
                ),
            )
        except Exception as exc:
            logger.debug("libclang parse failed for %s: %s", hp, exc)
            continue
        if tu is None:
            continue
        try:
            _walk(tu.cursor)
        except Exception as exc:
            logger.debug("doxygen walk failed for %s: %s", hp, exc)
            continue

    logger.info(
        "Doxygen extraction: %d/%d APIs documented (across %d headers)",
        len(out), len(api_set), len(header_paths),
    )
    return out


# ------------------------------------------------ Structured doc signals (G1)
#
# ``extract_doxygen_comments`` deliberately *drops* @param / @returns tag
# bodies — fine for the free-text Comprehender, useless for the redesign's
# APISemanticModel, which needs per-arg roles. ``extract_doc_signals`` keeps
# the tags and emits a structured per-API record consumed by
# ``liberator_adapter.analysis.api_semantic_model.collect_doc_evidence``.
# Deterministic (no LLM); empty on libclang unavailability.

_DOXY_BRIEF_TAG_RE = re.compile(r"[\\@]brief\s+(.*)", re.IGNORECASE)
_DOXY_PARAM_TAG_RE = re.compile(
    r"[\\@]param(?:\s*\[[^\]]*\])?\s+(\w+)\s+(.*)", re.IGNORECASE)
_DOXY_RETURN_TAG_RE = re.compile(r"[\\@](?:return|returns|retval)\s+(.*)",
                                 re.IGNORECASE)

# @param description → ArgRole value string. Order matters: LENGTH and OUTPUT
# cues are checked before the generic BUFFER cue so "size of the buffer" reads
# as LENGTH, not INPUT_BUFFER.
_PARAM_LENGTH_CUES = ("length", "size", "number of bytes", "num bytes",
                      "byte count", "count of", "n_bytes", "nbytes", "len of",
                      "size in bytes", "size of")
_PARAM_OUTPUT_CUES = ("output", "result is", "receives", "filled in",
                      "will be set", "will receive", "out parameter",
                      "pointer to store", "on success contains", "[out]")
_PARAM_BUFFER_CUES = ("input buffer", "the input", "raw bytes", "the data",
                      "input data", "data buffer", "byte buffer", "the bytes",
                      "buffer to", "pointer to the data")
_PARAM_HANDLE_CUES = ("handle", "context", "the object", "instance",
                      "previously created", "returned by")


def _param_role_from_text(text: str) -> Optional[str]:
    """Map a @param description to an ``ArgRole`` value string, or ``None``."""
    low = (text or "").lower()
    if not low:
        return None
    if any(c in low for c in _PARAM_LENGTH_CUES):
        return "LENGTH"
    if any(c in low for c in _PARAM_OUTPUT_CUES):
        return "OUTPUT"
    if any(c in low for c in _PARAM_BUFFER_CUES):
        return "INPUT_BUFFER"
    if any(c in low for c in _PARAM_HANDLE_CUES):
        return "HANDLE_IN"
    return None


def _parse_doxygen_structured(raw: Optional[str]) -> Dict[str, Any]:
    """Split a raw doxygen block into brief + ordered @param + return.

    Keeps tag bodies (unlike ``_normalize_doxygen``). ``params`` is ordered by
    appearance, each ``{"index", "name", "text", "role"}`` — ``index`` is the
    ordinal position, which conventionally matches the signature arg order.
    """
    if not raw:
        return {}
    # Strip /** */ framing and per-line '*' prefixes, but keep tags.
    lines: List[str] = []
    for line in raw.splitlines():
        if _DOXY_HEADER_RE.match(line) or _DOXY_TRAILING_RE.match(line):
            continue
        m = _DOXY_LINE_RE.match(line)
        lines.append((m.group(1) if m else line.strip()).strip())
    blob = "\n".join(l for l in lines if l)
    if not blob:
        return {}

    params: List[Dict[str, Any]] = []
    for ordinal, m in enumerate(_DOXY_PARAM_TAG_RE.finditer(blob)):
        pname, ptext = m.group(1), m.group(2).strip()
        params.append({
            "index": ordinal, "name": pname, "text": ptext,
            "role": _param_role_from_text(ptext),
        })

    brief = ""
    bm = _DOXY_BRIEF_TAG_RE.search(blob)
    if bm:
        brief = bm.group(1).strip()
    else:
        # No explicit @brief: the lead text before the first tag is the brief.
        lead: List[str] = []
        for l in blob.splitlines():
            if _DOXY_TAG_RE.match(l) or _DOXY_PARAM_RE.search(l):
                break
            lead.append(l)
        brief = " ".join(lead).strip()

    rm = _DOXY_RETURN_TAG_RE.search(blob)
    returns = rm.group(1).strip() if rm else ""

    out: Dict[str, Any] = {}
    if brief:
        out["brief"] = brief
    if params:
        out["params"] = params
    if returns:
        out["returns"] = returns
    return out


def extract_doc_signals(
    headers_dir: Optional[Path],
    public_headers: Sequence[str],
    api_names: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    """Map ``api_name`` → structured doc signal ``{brief, params, returns}``.

    Same libclang walk as ``extract_doxygen_comments`` but retains @param /
    @return tags so the APISemanticModel can read per-arg roles. Empty dict on
    any failure (caller's naming + type-pattern evidence still carries role).
    """
    if not headers_dir or not public_headers or not api_names:
        return {}
    try:
        from clang.cindex import Cursor, CursorKind, Index, TranslationUnit
    except ImportError:
        logger.warning(
            "libclang bindings unavailable; structured doc extraction skipped")
        return {}

    api_set: Set[str] = {n for n in api_names if n}
    headers_root = Path(headers_dir)
    if not api_set or not headers_root.is_dir():
        return {}

    header_paths = [headers_root / n for n in public_headers
                    if (headers_root / n).is_file()]
    if not header_paths:
        return {}

    index = Index.create()
    out: Dict[str, Dict[str, Any]] = {}
    parse_args = ["-I", str(headers_root), "-x", "c++", "-std=c++17",
                  "-ferror-limit=0", "-fparse-all-comments"]

    def _walk(cursor: 'Cursor') -> None:
        try:
            kind = cursor.kind
        except Exception:
            return
        if kind in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD):
            name = cursor.spelling
            if name and name in api_set and name not in out:
                try:
                    sig = _parse_doxygen_structured(cursor.raw_comment)
                except Exception:
                    sig = {}
                if sig:
                    out[name] = sig
        for child in cursor.get_children():
            _walk(child)

    for hp in header_paths:
        try:
            tu = index.parse(
                str(hp), args=parse_args,
                options=(TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                         | TranslationUnit.PARSE_INCOMPLETE))
        except Exception as exc:
            logger.debug("libclang parse failed for %s: %s", hp, exc)
            continue
        if tu is None:
            continue
        try:
            _walk(tu.cursor)
        except Exception as exc:
            logger.debug("structured doc walk failed for %s: %s", hp, exc)
            continue

    logger.info("Structured doc signals: %d/%d APIs (across %d headers)",
                len(out), len(api_set), len(header_paths))
    return out
