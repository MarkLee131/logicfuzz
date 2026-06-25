"""Plan-conformance check — the architecture-cleanup #4 guard.

Given a symbolic PLAN (the ordered lifecycle API sequence the planner produced)
and an LLM-authored driver's C source, decide whether the driver CONFORMS — i.e.
it kept the lifecycle *backbone* and *depth* and did NOT revert to a shallow
parser-entry driver (the validated A-design failure mode, see
docs/.../project_llm_reverts_objconstruct_to_parser). The spec-guided render
layer's freedom is bounded by this check: non-conformant ⇒ regenerate.

Design (empirically grounded on the libpng validation drivers): the LLM
LEGITIMATELY drops incoherent planned APIs (write-side setters, deprecated
re-initializers, mutually-exclusive one-shots) — good drivers kept only 44–100%
of their plan, so KEPT-FRACTION IS A NOISY SIGNAL and must not gate. Conformance
gates on the lifecycle BACKBONE instead:

  conformant  ⇔  a planned creator is called  AND  a planned terminal
                 (deep consumer — the deepest lifecycle API) is called.

The terminal-consumer presence cleanly separates good drivers (call it) from the
A-design failures — shallow drivers (created the handle, bailed) and parser-entry
reverts (swapped the planned chain for an unplanned one-shot) both LACK the
planned terminal. Kept-fraction is reported + an advisory note below ``min_kept``,
never a blocker. Robust to comments (an API named in prose is not counted).

Pure analysis, zero side effects — safe to call anywhere. NOT yet wired into the
pipeline (wiring is REPLACE #4, gated behind LOGICFUZZ_LLM_REWRITE + A/B).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

_CREATE_RE = re.compile(r"create|_new\b|_alloc|_init\b|_open|_begin", re.I)
_DESTROY_RE = re.compile(r"destroy|_free\b|_close|_delete|_release|_end\b|_finish", re.I)
# deep "consumer" verbs: the API that actually exercises the built object
_TERMINAL_RE = re.compile(r"read|decode|parse|process|run|render|image|convert|transform|update|write|do_", re.I)


def _strip_comments(src: str) -> str:
    """Remove // line and /* */ block comments so an API mentioned in prose
    (e.g. ``png_info_init_3 (deliberately omitted)``) is not counted as a call."""
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


_WRAPPER_PREFIX_RE = re.compile(r"^(?:OSS_FUZZ_)+")


def _canon(name: str) -> str:
    """Canonicalize an API name by stripping the OSS-Fuzz introspector wrapper
    prefix. Plan names reach the gate as ``OSS_FUZZ_png_*`` (the harness wrapper
    symbols), but the LLM authors the real library names ``png_*`` — comparing
    them literally is a 0%-match false reject (the libpng A/B bug)."""
    return _WRAPPER_PREFIX_RE.sub("", name)


def _calls(code: str, api: str) -> bool:
    # Prefix-agnostic: match whether the driver wrote the real name or the
    # OSS_FUZZ_ wrapper, against a canonicalized plan name.
    name = _canon(api)
    return re.search(rf"\b(?:OSS_FUZZ_)?{re.escape(name)}\s*\(", code) is not None


@dataclass
class Conformance:
    conformant: bool
    kept_frac: float
    called: List[str]
    dropped: List[str]
    has_creator: bool
    has_terminal: bool
    has_destroyer: bool
    reasons: List[str] = field(default_factory=list)


def analyze_conformance(
    planned: Sequence[str],
    driver_src: str,
    *,
    creators: Optional[Sequence[str]] = None,
    terminals: Optional[Sequence[str]] = None,
    destroyers: Optional[Sequence[str]] = None,
    min_kept: float = 0.5,
) -> Conformance:
    """Check an authored driver against its plan. ``creators``/``terminals``/
    ``destroyers`` are optional role hints (the planner knows them); when omitted
    they are inferred — terminals from the plan's lifecycle ORDER (the last
    non-destroyer planned API, which is the deepest consumer) plus naming, and
    creators/destroyers from naming. ``min_kept`` is intentionally low: the gate
    is the backbone, not exact reproduction."""
    planned = [_canon(a) for a in planned]
    code = _strip_comments(driver_src)
    called = [a for a in planned if _calls(code, a)]
    dropped = [a for a in planned if a not in called]
    kept = len(called) / max(1, len(planned))

    inferred_destroy = [a for a in planned if _DESTROY_RE.search(a)]
    inferred_create = [a for a in planned if _CREATE_RE.search(a) and a not in inferred_destroy]
    # terminal by plan ORDER: deepest = last planned API that is neither a
    # creator nor a destroyer (the lifecycle consumer just before teardown).
    non_teardown = [a for a in planned if a not in inferred_destroy]
    order_terminal = [non_teardown[-1]] if non_teardown else []
    name_terminal = [a for a in planned
                     if _TERMINAL_RE.search(a) and a not in inferred_create and a not in inferred_destroy]

    creators = [_canon(a) for a in creators] if creators is not None else inferred_create
    destroyers = [_canon(a) for a in destroyers] if destroyers is not None else inferred_destroy
    # A weak explicit terminal hint (e.g. the planner's last-non-destroyer, which
    # can be a utility like png_malloc_default) must not block a genuinely deep
    # driver: union the hint with the name-inferred decode terminals so a real
    # decode consumer (read/decode/image/...) present in the plan still counts.
    if terminals is not None:
        terminals = sorted(set(_canon(a) for a in terminals) | set(name_terminal))
    else:
        terminals = sorted(set(order_terminal) | set(name_terminal))

    has_creator = any(_calls(code, a) for a in creators) if creators else True
    has_terminal = any(_calls(code, a) for a in terminals) if terminals else (kept >= min_kept)
    has_destroyer = any(_calls(code, a) for a in destroyers) if destroyers else True

    # CONFORMANCE GATE = backbone presence (creator + terminal deep-consumer).
    # Empirically (libpng validation drivers), kept-fraction is a NOISY signal —
    # a legitimately-minimal good driver drops most setters (kept 44–67%) yet
    # spans create→…→terminal. The terminal-consumer presence cleanly separates
    # good (has it) from the A-design failures (shallow / parser-revert lack it).
    # kept-fraction is therefore ADVISORY only (``min_kept`` adds a note, never
    # blocks on its own).
    reasons: List[str] = []
    if not has_creator:
        reasons.append("no planned creator called")
    if not has_terminal:
        reasons.append("no planned terminal/deep consumer called (shallow or parser-revert)")
    if kept < min_kept:
        reasons.append(f"advisory: low plan coverage (kept {kept:.0%} < {min_kept:.0%}) — review")

    conformant = has_creator and has_terminal and len(called) >= 2
    return Conformance(
        conformant=conformant, kept_frac=kept, called=called, dropped=dropped,
        has_creator=has_creator, has_terminal=has_terminal, has_destroyer=has_destroyer,
        reasons=reasons,
    )
