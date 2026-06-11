"""T10 — generalized format-entry inference (deterministic, no LLM).

A parser-entry API (``cmsOpenProfileFromMem``, ``png_image_begin_read…``) early-
returns on random bytes at its magic/length/version front gate, so a driver that
calls it covers ~nothing until a *front-gate-passing* input reaches it. Real
seeds (routed by ``seed_discovery``) are the best source; this module covers the
gap: when **no real seed ships**, synthesize a minimal front-gate-passing seed
from a FORMAT SPEC inferred deterministically from one of three sources, in
preference order:

1. a sampled real seed's prefix (most reliable — it *is* a valid header),
2. a small registry of well-known binary magics (icc/png/jpeg/…),
3. ``#define``'d magic / signature / fourcc constants scanned from the project
   headers — the generalization to formats the registry doesn't hardcode.

Scope (honest): this is deterministic *constant* inference, NOT full IR symbolic
execution — ``conditions.json``/SVF carry no branch-predicate operands, so we
cannot in general recover an arbitrary parser's validation from the IR. A
synthesized seed is a *better-than-random starting point* (passes the leading
magic gate; the fuzzer mutates from there), not a guaranteed-deep input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FormatSpec:
    """A minimal description of a format's front gate."""
    label: str
    magic: bytes
    offset: int = 0
    min_length: int = 0
    source: str = "registry"     # registry | seed_sample | header_define

    def __post_init__(self) -> None:
        # min_length must at least span the magic at its offset.
        need = self.offset + len(self.magic)
        if self.min_length < need:
            self.min_length = need


# Well-known binary magics sufficient to clear the leading gate. Keyed by the
# ``seed_discovery`` format family. Text formats (json/it8/xml) have no reliable
# binary magic and are forgiving of random bytes, so they are intentionally
# absent (synthesis would not help). min_length leaves room past the magic for
# the parser's immediate header reads.
_REGISTRY = {
    "icc": FormatSpec("icc", b"acsp", 36, 132, "registry"),       # 'acsp'@36, 128B header
    "image": FormatSpec("image", b"\x89PNG\r\n\x1a\n", 0, 16, "registry"),
    "pdf": FormatSpec("pdf", b"%PDF-1.4", 0, 16, "registry"),
    "archive": FormatSpec("archive", b"PK\x03\x04", 0, 16, "registry"),
    "font": FormatSpec("font", b"\x00\x01\x00\x00", 0, 16, "registry"),
}

# A #define whose NAME looks like a format signature.
_MAGIC_NAME = re.compile(
    r"#\s*define\s+(\w*(?:MAGIC|SIGNATURE|SIGNATUR|FOURCC|FILE_?ID)\w*)\s+(.+?)\s*(?:/\*|//|$)",
    re.IGNORECASE,
)
_STR_LIT = re.compile(r'"((?:[^"\\]|\\.){2,16})"')
_HEX_LIT = re.compile(r"0x([0-9A-Fa-f]{4,16})")


def _bytes_from_hex(hexstr: str) -> bytes:
    if len(hexstr) % 2:
        hexstr = "0" + hexstr
    return bytes.fromhex(hexstr)


def magic_defines_from_text(header_text: str) -> List[FormatSpec]:
    """Scan one header's text for ``#define <…MAGIC…> "abcd" | 0x…`` lines.

    Returns a FormatSpec per recognised define (offset 0 — a #define magic
    almost always names the *leading* signature). Deterministic; tolerant of
    unparsable values (skipped).
    """
    specs: List[FormatSpec] = []
    for m in _MAGIC_NAME.finditer(header_text or ""):
        name, value = m.group(1), m.group(2).strip()
        magic: Optional[bytes] = None
        sm = _STR_LIT.search(value)
        if sm:
            try:
                magic = sm.group(1).encode("latin-1", "ignore").decode(
                    "unicode_escape").encode("latin-1", "ignore")
            except Exception:
                magic = sm.group(1).encode("latin-1", "ignore")
        else:
            hm = _HEX_LIT.search(value)
            if hm:
                magic = _bytes_from_hex(hm.group(1))
        if magic:
            specs.append(FormatSpec(label=name.lower(), magic=magic,
                                    offset=0, source="header_define"))
    return specs


def spec_from_seed_sample(data: bytes, label: str = "seed") -> Optional[FormatSpec]:
    """Build a spec from a real seed's leading bytes (its prefix IS the gate)."""
    if not data:
        return None
    magic = bytes(data[:min(8, len(data))])
    return FormatSpec(label=label, magic=magic, offset=0,
                      min_length=len(data) if len(data) <= 256 else 256,
                      source="seed_sample")


def infer_spec(
    family: Optional[str] = None,
    *,
    seed_sample: Optional[bytes] = None,
    header_texts: Optional[List[str]] = None,
) -> Optional[FormatSpec]:
    """Infer a FormatSpec, preferring seed_sample > registry > header_define."""
    if seed_sample:
        s = spec_from_seed_sample(seed_sample, label=family or "seed")
        if s:
            return s
    if family and family in _REGISTRY:
        return _REGISTRY[family]
    for txt in header_texts or []:
        defs = magic_defines_from_text(txt)
        if defs:
            return defs[0]
    return None


def synthesize_minimal_seed(spec: FormatSpec) -> bytes:
    """A minimal front-gate-passing seed: the magic at its offset, zero-padded
    to ``min_length``."""
    buf = bytearray(spec.min_length)
    buf[spec.offset:spec.offset + len(spec.magic)] = spec.magic
    return bytes(buf)


def synthesize_seed_corpus(spec: FormatSpec, k: int = 6) -> List[bytes]:
    """``k`` deterministic gate-passing seeds (not just one zero-body seed).

    A single all-zero body (``synthesize_minimal_seed``) gives libFuzzer almost
    nothing to mutate structurally. This emits the minimal seed PLUS variants
    whose post-magic body carries distinct fixed byte patterns, so the fuzzer
    starts from structurally-varied inputs that already clear the magic gate.
    Fully deterministic (no RNG) for reproducibility; only the body past the
    magic is varied (the gate-passing prefix is preserved in every variant)."""
    base = bytes(synthesize_minimal_seed(spec))
    body = spec.offset + len(spec.magic)
    out: List[bytes] = [base]
    for pat in (0xFF, 0xAA, 0x55, 0x01):
        if len(out) >= k:
            break
        v = bytearray(base)
        for i in range(body, len(v)):
            v[i] = pat
        out.append(bytes(v))
    # One variant with a plausible big-endian length field right after the magic
    # (many binary formats carry a size/version word there).
    if len(out) < k and len(base) >= body + 4:
        v = bytearray(base)
        v[body:body + 4] = len(base).to_bytes(4, "big")
        out.append(bytes(v))
    return out[:k]


def format_recipe_text(spec: FormatSpec) -> str:
    """Human recipe for the hole / prompt: how to clear this front gate."""
    hexm = spec.magic.hex()
    printable = spec.magic.decode("latin-1", "replace")
    return (f"buffer must be >= {spec.min_length} bytes and carry magic "
            f"{printable!r} (0x{hexm}) at offset {spec.offset} "
            f"[inferred:{spec.source}]")
