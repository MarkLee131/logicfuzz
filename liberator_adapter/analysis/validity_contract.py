"""Validity Contract validator — the construction gate AND the regression oracle.

Read-only. Checks four invariants against the APISemanticModel's per-arg
``{nullable, type_str}``:

  I1  producer-before-consumer (no use-before-produce / close-before-open)
  I2a every ``nullable=False`` HANDLE arg has a producer (no orphan NULL handle)
  I2b every ``nullable=False`` non-handle required arg is non-NULL
  I3  handle arg bound to a producer of the SAME handle family (no void* confusion)

Args the model marks ``nullable=True`` (OUTPUT, NULLABLE_HANDLE like cmsContext)
are EXEMPT — NULL is legal for them. ``check_sequence`` operates on a normalized
``[Call]`` view; ``from_rendered_c`` adapts a rendered ``*.fuzz_target`` into that
view (the oracle path over existing drivers).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ArgBinding:
    producer: Optional[str]      # producing api name, or None
    produced_at: Optional[int]   # stmt index of the producer, or None
    is_null: bool                # bound to NULL at the call site


@dataclass
class Call:
    api: str
    args: List[ArgBinding]


@dataclass
class ContractReport:
    counts: Dict[str, int] = field(
        default_factory=lambda: {"I1": 0, "I2a": 0, "I2b": 0, "I3": 0})
    detail: List[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(self.counts.values())


_HANDLE_FAMILIES = ("transform", "profile", "tonecurve", "pipeline", "stage",
                    "context", "it8")


def _family(s: str) -> Optional[str]:
    t = (s or "").lower()
    # The _HANDLE_FAMILIES allow-list is an lcms-specific heuristic for
    # disambiguating lcms's void*-collapsed opaque handles (cmsHPROFILE vs
    # cmsHTRANSFORM share one void* typedef). Apply it ONLY to lcms-style
    # names/types (must contain "cms"); otherwise a NON-lcms type or name that
    # merely shares a substring spuriously matches (EVP_PIPELINE->pipeline,
    # png_context->context, GLTFStage->stage, it8_data->it8, my_transform_t->
    # transform) and CBFactory.produced_by_family then CROSS-WIRES two unrelated
    # handle types. Non-lcms -> None -> the type-exact binding path handles it.
    if "cms" not in t:
        return None
    if "hprofile" in t:
        return "profile"
    if "htransform" in t:
        return "transform"
    for fam in _HANDLE_FAMILIES:
        if fam in t:
            return fam
    return None


def _normalize_type(type_str: str) -> str:
    """Canonicalize a C type to the model's `requires`/`produces` key form:
    lowercase, drop ``struct``/``const``, strip whitespace.
    ``cmsHPROFILE`` -> ``cmshprofile``; ``cmsPipeline *`` -> ``cmspipeline*``;
    ``_cmsContext_struct *`` -> ``_cmscontext_*``."""
    t = (type_str or "").lower()
    t = t.replace("struct", "").replace("const", "")
    return re.sub(r"\s+", "", t)


def _handle_types(model: Dict) -> set:
    """The set of normalized HANDLE types = every type some API ``requires``
    (a lifecycle dependency). Value-structs / buffers are config args, never
    required, so they are correctly excluded. Generic across projects."""
    out = set()
    for m in model.values():
        if isinstance(m, dict):
            for r in (m.get("requires") or ()):
                out.add(_normalize_type(r))
    return out


# Transparent value structs (driver stack-allocates + fills; NOT produced by a
# creator) and numeric/byte buffers — a NULL one is an I2b (fill) violation, NOT an
# I2a (orphan handle / needs producer). Distinguishing them routes the right repair.
_TRANSPARENT_VALUE = re.compile(
    r"cms(cie|jch|xyy|xyz|viewingconditions|curvesegment|lab|lch)", re.I)
_BUFFER_OR_SCALAR = re.compile(
    r"cms(u?int|float|bool|s15|u8)\w*number|\b(char|void|file|tm|wchar_t)\b", re.I)


def _is_opaque_handle(type_str: str, handle_types: set) -> bool:
    """An OPAQUE handle (produced by a creator) — `requires`-listed AND not a
    transparent value-struct / numeric buffer."""
    if _normalize_type(type_str) not in handle_types:
        return False
    return not (_TRANSPARENT_VALUE.search(type_str or "")
                or _BUFFER_OR_SCALAR.search(type_str or ""))


def _is_pointer_type(type_str: str) -> bool:
    t = type_str or ""
    return "*" in t or bool(re.search(r"cmsH[A-Z]", t))


def _producer_family(api: str) -> str:
    return _family(api) or "other"


def check_sequence(calls: List[Call], model: Dict) -> ContractReport:
    """Validate a normalized call sequence against the contract."""
    rep = ContractReport()
    handle_types = _handle_types(model)
    for i, call in enumerate(calls):
        margs = (model.get(call.api) or {}).get("args") or []
        for j, b in enumerate(call.args):
            ma = next((a for a in margs if a.get("index") == j), None)
            if ma is None or ma.get("nullable", True):
                continue  # unknown arg or legally-nullable -> exempt
            ts = ma.get("type_str", "")
            if _is_opaque_handle(ts, handle_types):
                if b.producer is None or b.is_null:
                    rep.counts["I2a"] += 1
                    rep.detail.append(f"{call.api} arg{j}: orphan non-NULL handle ({ts})")
                elif b.produced_at is not None and b.produced_at > i:
                    rep.counts["I1"] += 1
                    rep.detail.append(f"{call.api} arg{j}: use-before-produce")
                else:
                    pf = _producer_family(b.producer)
                    af = _family(ts)
                    if af and pf != "other" and pf != af:
                        rep.counts["I3"] += 1
                        rep.detail.append(f"{call.api} arg{j}: type-confusion {pf}->{af}")
            elif _is_pointer_type(ts) and b.is_null:
                # a required non-NULL value-struct / string / buffer left NULL
                rep.counts["I2b"] += 1
                rep.detail.append(f"{call.api} arg{j}: non-NULL pointer = NULL ({ts})")
    return rep


# --------------------------------------------------------------------------- #
# Rendered-C adapter (the oracle path over existing *.fuzz_target drivers).
# --------------------------------------------------------------------------- #

_CALL_RE = re.compile(r"(?:(\w+)\s*=\s*)?\b(cms[A-Za-z0-9_]+)\s*\(([^;]*)\)\s*;")


def _body(src: str) -> str:
    m = re.search(r"LLVMFuzzerTestOneInput[^{]*\{(.*)\n\}", src, re.S)
    return m.group(1) if m else src


def _first_ident(expr: str) -> Optional[str]:
    e = re.sub(r"^\([^)]*\)\s*", "", expr.strip())  # strip a leading cast
    e = e.lstrip("&").strip()
    m = re.match(r"([A-Za-z_]\w*)", e)
    return m.group(1) if m else None


def _split_args(argstr: str) -> List[str]:
    parts, depth, cur = [], 0, ""
    for ch in argstr:
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def from_rendered_c(src: str, model: Dict) -> ContractReport:
    """Parse a rendered driver into a ``[Call]`` view and validate it."""
    lines = _body(src).split("\n")
    null_decl = set()
    for ln in lines:
        m = re.match(r"\s*[\w\s\*]+?\b(\w+)\s*=\s*NULL\s*;", ln)
        if m:
            null_decl.add(m.group(1))

    # Collect calls in order; producer position is the CALL-LIST index (NOT the
    # line index) so it shares the index space with ``check_sequence``'s ``i``.
    produced_at: Dict[str, int] = {}
    producer_of: Dict[str, str] = {}
    raw_calls = []  # (api, [arg_expr]) in call order
    for ln in lines:
        cm = _CALL_RE.search(ln)
        if not cm:
            continue
        lhs, api, argstr = cm.group(1), cm.group(2), cm.group(3)
        pos = len(raw_calls)
        raw_calls.append((api, _split_args(argstr)))
        if lhs and lhs.startswith("ret_"):
            producer_of[lhs] = api
            produced_at[lhs] = pos  # call position, not line

    calls: List[Call] = []
    for (api, arg_exprs) in raw_calls:
        bindings: List[ArgBinding] = []
        for raw in arg_exprs:
            var = _first_ident(raw)
            pidx = produced_at.get(var) if var else None
            is_null = raw.strip() == "NULL" or (var in null_decl and pidx is None)
            bindings.append(ArgBinding(
                producer=producer_of.get(var) if (var and pidx is not None) else None,
                produced_at=pidx,
                is_null=is_null,
            ))
        calls.append(Call(api, bindings))
    return check_sequence(calls, model)
