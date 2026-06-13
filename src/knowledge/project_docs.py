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


# ------------------------------------------- Markdown / prose API docs (parity)
#
# ``extract_doxygen_comments`` / ``extract_doc_signals`` only see ``/** ... */``
# blocks in the HEADERS. Many libraries document their public API in a prose
# reference under ``doc/`` or ``docs/`` (libucl's ``doc/api.md`` — 506 lines of
# per-function reference) INSTEAD OF, or in addition to, header comments. A
# baseline that ingests such files (PromeFuzz's ``document_paths``) then has a
# semantic edge we'd be throwing away. This extractor mines those files for the
# SAME structured per-API record ``{brief, params, returns}`` as
# ``extract_doc_signals`` so a markdown reference feeds the Comprehender +
# APISemanticModel exactly like a doxygen block would. Deterministic (no LLM);
# best-effort; never raises. The caller merges header doxygen FIRST and lets the
# markdown fill only the APIs the headers leave undocumented (doc-rich libraries
# stay byte-identical).

_DOC_DIR_CANDIDATES = ("doc", "docs", "Documentation", "documentation", "man")
_DOC_FILE_GLOBS = ("*.md", "*.markdown", "*.mdown", "*.mkd", "*.rst")
_DOC_ROOT_FILES = ("API.md", "api.md", "APIS.md", "apis.md",
                   "API.rst", "api.rst", "API.markdown")
_DOC_MAX_FILES = 64
_DOC_MAX_BYTES = 2_000_000

_MD_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_RST_UNDERLINE_RE = re.compile(r"^\s*([=~`'\"^\-_*+#:.])\1{2,}\s*$")
_CODE_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_RETURN_SENTENCE_RE = re.compile(r"[^.\n]*\breturns?\b[^.\n]*\.", re.IGNORECASE)
_LIST_PREFIX_RE = re.compile(r"^\s*([*+\-]|\d+\.)\s")

# C declaration keywords that are never the parameter NAME (so the name is the
# last identifier in an arg decl that isn't one of these).
_TYPE_KEYWORDS = {
    "const", "unsigned", "signed", "struct", "union", "enum", "void", "char",
    "short", "int", "long", "float", "double", "size_t", "ssize_t", "bool",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
    "int32_t", "int64_t", "restrict", "volatile", "static", "inline",
}

# Doc-safe inline-markdown strip: links / inline-code / bold only. Unlike
# ``_strip_inline_markdown`` (tuned for README prose) it does NOT apply the
# ``_italic_`` / ``*italic*`` rules — technical API docs use ``_`` and ``*``
# literally (``ucl_parser_new``, ``*ptr``) far more than as emphasis, and the
# italic rules would corrupt every underscored identifier.
_DOC_INLINE_MARKDOWN = (
    (re.compile(r"\[([^\]]+)\]\([^)]+\)"), r"\1"),     # [text](url) → text
    (re.compile(r"`([^`]+)`"), r"\1"),                  # `code` → code
    (re.compile(r"\*\*([^*]+)\*\*"), r"\1"),            # **bold** → bold
)


def _strip_doc_markdown(text: str) -> str:
    for pat, repl in _DOC_INLINE_MARKDOWN:
        text = pat.sub(repl, text)
    return text.strip()


def _split_call_args(s: str) -> List[str]:
    """Split a C arg-list string on top-level commas (paren/bracket aware)."""
    args: List[str] = []
    depth = 0
    cur: List[str] = []
    for c in s:
        if c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if cur:
        args.append("".join(cur).strip())
    return args


def _heading_to_api(title: str, api_set: Set[str]) -> Optional[str]:
    """If a heading names exactly one API in ``api_set``, return it.

    Handles ``ucl_parser_new``, ``ucl_parser_new()``, ``` `ucl_parser_new` ```,
    and ``[ucl_parser_new](#anchor)`` heading forms.
    """
    t = _strip_doc_markdown(title)
    t = re.sub(r"\(.*?\)", "", t)            # drop a trailing (args) group
    for tok in _IDENT_RE.findall(t):
        if tok in api_set:
            return tok
    return None


def _params_from_signature(sig_line: str, api_name: str) -> List[Dict[str, Any]]:
    """Parse ordered params from a ``ret api_name(a, b, c)`` signature line."""
    i = sig_line.find(api_name)
    if i < 0:
        return []
    p = sig_line.find("(", i)
    if p < 0:
        return []
    depth = 0
    end = -1
    for j in range(p, len(sig_line)):
        if sig_line[j] == "(":
            depth += 1
        elif sig_line[j] == ")":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end < 0:
        return []
    params: List[Dict[str, Any]] = []
    for raw in _split_call_args(sig_line[p + 1:end]):
        a = raw.strip()
        if not a or a in ("void", "...", "void)"):
            continue
        toks = _IDENT_RE.findall(a.replace("*", " ").replace("[", " ").replace("]", " "))
        name = ""
        for tok in reversed(toks):
            if tok not in _TYPE_KEYWORDS:
                name = tok
                break
        params.append({
            "index": len(params), "name": name, "text": a,
            "role": _param_role_from_text(a),
        })
    return params


def _record_from_body(body: List[str], api_name: str) -> Dict[str, Any]:
    """Build a ``{brief, params, returns}`` record from one API section body."""
    prose: List[str] = []
    code: List[str] = []
    in_code = False
    for line in body:
        if _CODE_FENCE_RE.match(line):
            in_code = not in_code
            continue
        (code if in_code else prose).append(line)

    sig_line = ""
    for cl in code:
        if api_name in cl and "(" in cl:
            sig_line = cl.strip()
            break
    params = _params_from_signature(sig_line, api_name) if sig_line else []

    # brief: first prose paragraph (stop at blank line / list / sub-heading).
    brief_parts: List[str] = []
    for line in prose:
        s = line.strip()
        if not s:
            if brief_parts:
                break
            continue
        if _LIST_PREFIX_RE.match(line) or _MD_HEADING_RE.match(line) \
                or _RST_UNDERLINE_RE.match(line) or s.startswith(("|", ">")):
            if brief_parts:
                break
            continue
        brief_parts.append(s)
    brief = _strip_doc_markdown(" ".join(brief_parts)).strip()
    if len(brief) > 400:
        brief = brief[:400].rsplit(" ", 1)[0] + "..."

    prose_blob = " ".join(l.strip() for l in prose if l.strip())
    rm = _RETURN_SENTENCE_RE.search(prose_blob)
    returns = _strip_doc_markdown(rm.group(0).strip()) if rm else ""

    rec: Dict[str, Any] = {}
    if brief:
        rec["brief"] = brief
    if params:
        rec["params"] = params
    if returns:
        rec["returns"] = returns
    return rec


def _collect_headings(lines: List[str]) -> List[tuple]:
    """Return ``(line_idx, level, raw_title)`` for markdown ATX + rST headings.

    rST underlined headings (a text line followed by a rule line) are assigned
    a synthetic level below any ATX heading so the section-end logic (next
    heading with ``level <= mine``) still bounds them sensibly.
    """
    heads: List[tuple] = []
    n = len(lines)
    for idx, line in enumerate(lines):
        m = _MD_HEADING_RE.match(line)
        if m:
            heads.append((idx, len(m.group(1)), m.group(2)))
            continue
        # rST: a non-blank title line whose NEXT line is a rule of >= its length
        if idx + 1 < n and line.strip() and not _CODE_FENCE_RE.match(line):
            nxt = lines[idx + 1]
            if _RST_UNDERLINE_RE.match(nxt) and len(nxt.strip()) >= len(line.strip()):
                heads.append((idx, 3, line.strip()))   # synthetic level 3
    return heads


def _parse_api_doc_file(text: str, api_set: Set[str],
                        out: Dict[str, Dict[str, Any]]) -> None:
    """Parse one markdown/rST file, adding per-API records to ``out`` in place.

    First documented occurrence of an API wins (``out`` is not overwritten), so
    a table-of-contents heading that names the API but carries no body is
    skipped in favour of the real section (which yields a non-empty record).
    """
    lines = text.splitlines()
    heads = _collect_headings(lines)
    for h_i, (start, level, title) in enumerate(heads):
        api = _heading_to_api(title, api_set)
        if not api or api in out:
            continue
        end = len(lines)
        for (s2, l2, _title2) in heads[h_i + 1:]:
            if l2 <= level:
                end = s2
                break
        rec = _record_from_body(lines[start + 1:end], api)
        if rec:                       # skip empty (TOC) occurrences
            out[api] = rec


def extract_markdown_api_docs(
    src_root: Optional[Path],
    api_names: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    """Map ``api_name`` → structured doc signal ``{brief, params, returns}``
    mined from prose API docs under ``src_root`` (``doc/``, ``docs/``, a
    top-level ``api.md``, …).

    Same record shape as ``extract_doc_signals`` so the caller can merge the two
    (header doxygen first, markdown fills the rest). Empty dict when no doc files
    are found or none name a known API.
    """
    if not src_root or not api_names:
        return {}
    root = Path(src_root)
    if not root.is_dir():
        return {}
    api_set: Set[str] = {n for n in api_names if n}
    if not api_set:
        return {}

    files: List[Path] = []
    seen: Set[Path] = set()
    for d in _DOC_DIR_CANDIDATES:
        dd = root / d
        if dd.is_dir():
            for g in _DOC_FILE_GLOBS:
                for p in sorted(dd.rglob(g)):
                    if p.is_file() and p not in seen:
                        files.append(p)
                        seen.add(p)
                        if len(files) >= _DOC_MAX_FILES:
                            break
    for fn in _DOC_ROOT_FILES:
        p = root / fn
        if p.is_file() and p not in seen:
            files.append(p)
            seen.add(p)
    if not files:
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for p in files:
        try:
            if p.stat().st_size > _DOC_MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            _parse_api_doc_file(text, api_set, out)
        except Exception as exc:        # never let a malformed doc break prepare()
            logger.debug("markdown API-doc parse failed for %s: %s", p, exc)
            continue

    logger.info("Markdown API docs: %d/%d APIs documented (across %d files)",
                len(out), len(api_set), len(files))
    return out
