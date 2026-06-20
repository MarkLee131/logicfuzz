"""Merge-gate LLM repair — recover non-compiling drivers the compile-validation
gate would otherwise silently drop.

Gives each TU the gate excluded ONE single-shot LLM rewrite, then RE-VALIDATES
through the SAME ``validate_compilable`` gate, keeping it only if it now compiles.
Fail-closed re-validation preserves the merge A≡B contract: a kept TU compiles
under the identical coverage-build flags. Single-shot (no container bash); injects
``llm_query``/``revalidate`` for docker-free unit testing; repaired TU keeps the
original extension so the merge-target language is unchanged.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


def _extract_fuzz_target(response: str) -> str:
    """Pull the corrected driver from a ``<fuzz_target>`` block, stripping a stray
    markdown fence. Inlined (not ``src.agents.utils.parse_tag``) to avoid a
    circular ``src.agents`` import. Falls back to a bare code block when the tag is
    omitted, guarded by requiring ``LLVMFuzzerTestOneInput`` so prose isn't taken.
    """
    m = re.search(r"<fuzz_target>(.*?)</fuzz_target>", response or "", re.DOTALL)
    code = ""
    if m:
        code = m.group(1).strip()
        fence = re.match(r"^```(?:c|cpp|c\+\+)?\s*\n(.*?)```$", code, re.DOTALL)
        if fence:
            code = fence.group(1).strip()
    else:
        for fm in re.finditer(r"```(?:c|cpp|c\+\+)?\s*\n(.*?)```",
                              response or "", re.DOTALL):
            block = fm.group(1).strip()
            if "LLVMFuzzerTestOneInput" in block:
                code = block
                break
    return code


def build_repair_prompt(source_code: str, error_tail: str, lang: str,
                        known_apis: Optional[List[dict]] = None) -> str:
    """Build a single-shot repair prompt (failing source + compiler diagnostic +
    merge-target language + triage guidance) asking for a corrected
    ``<fuzz_target>``. Pure; ``lang`` is 'c'/'cpp' (the language the MERGED build
    compiles this TU as — the LLM must not re-introduce the other's syntax).
    """
    lang_name = "C++" if str(lang).lower() in ("cpp", "c++", "cxx", "cc") else "C"
    try:
        from src.utils.compilation_error_triage import (
            triage_build_errors, get_fix_guidance)
        guidance = get_fix_guidance(
            triage_build_errors([error_tail], known_apis)).strip()
    except Exception:  # noqa: BLE001 — guidance is best-effort, prompt still valid
        guidance = ""

    forbidden = "C-only" if lang_name == "C++" else "C++-only"
    code_fence = "cpp" if lang_name == "C++" else "c"
    guidance_block = (f"## Fix guidance\n{guidance}\n\n") if guidance else ""
    return (
        f"The following libFuzzer driver FAILS to compile under the OSS-Fuzz "
        f"build flags. Fix it so it compiles cleanly as **{lang_name}** "
        f"(this translation unit is built with the {lang_name} compiler — do NOT "
        f"use {forbidden} constructs).\n\n"
        f"## Compiler error\n```\n{error_tail.strip()}\n```\n\n"
        f"{guidance_block}"
        f"## Driver source\n```{code_fence}\n"
        f"{source_code}\n```\n\n"
        f"## Rules\n"
        f"- Make the SMALLEST change that fixes the compile error; keep the same "
        f"APIs and fuzzing behavior.\n"
        f"- Do NOT invent functions; do NOT add internal/private headers.\n"
        f"- Keep `LLVMFuzzerTestOneInput` as the entry point.\n"
        f"- Output ONLY the complete corrected driver, wrapped in a single "
        f"`<fuzz_target>...</fuzz_target>` block.\n"
    )


def _default_revalidate(sources, project, iquote_dirs=None):
    from tools.merge_drivers.compile_validate import validate_compilable
    return validate_compilable(
        list(sources), project, iquote_dirs=iquote_dirs)


def repair_candidates(
    excluded: Sequence[Tuple[Path, str]],
    project: str,
    llm_query: Callable[[str], str],
    out_dir: Path,
    iquote_dirs: Optional[Sequence[str]] = None,
    known_apis: Optional[List[dict]] = None,
    revalidate: Optional[Callable] = None,
) -> Tuple[List[Tuple[Path, Path]], List[Tuple[Path, str]]]:
    """Single-shot-repair each excluded TU, then batch re-validate the rewrites.

    Args:
        excluded:    [(source_path, error_tail)] from ``validate_compilable``.
        project:     OSS-Fuzz project (for the re-validation container).
        llm_query:   callable prompt→completion.
        out_dir:     where repaired sources are written (persisted, auditable).
        iquote_dirs: passed to re-validation so includes resolve as in the merge.
        known_apis:  optional triage fake-definition hint.
        revalidate:  callable(sources, project, iquote_dirs=...) → (valid,
                     excluded); defaults to the real ``validate_compilable``.

    Returns (recovered, still_excluded). Fail-closed: a TU is in ``recovered``
    ([(orig_src, repaired_path)]) ONLY if its rewrite re-validated; everything
    else stays in ``still_excluded`` as [(orig_src, reason)].
    """
    revalidate = revalidate or _default_revalidate
    from tools.merge_drivers.compile_validate import _merge_target_lang

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    still_excluded: List[Tuple[Path, str]] = []
    # repaired_path -> original_src, to map re-validation verdicts back.
    repaired_to_orig: dict = {}

    for src, error_tail in excluded:
        src = Path(src)
        try:
            source_code = src.read_text()
        except Exception as exc:  # noqa: BLE001
            still_excluded.append((src, f"repair: unreadable source ({exc})"))
            continue
        lang = _merge_target_lang(src)
        prompt = build_repair_prompt(source_code, error_tail or "", lang,
                                     known_apis)
        try:
            completion = llm_query(prompt) or ""
        except Exception as exc:  # noqa: BLE001 — a failed call drops the TU
            still_excluded.append((src, f"repair: LLM call failed ({exc})"))
            continue
        code = _extract_fuzz_target(completion)
        if not code:
            still_excluded.append((src, "repair: no <fuzz_target> in LLM output"))
            continue
        # Keep the original extension so the merge-target language is unchanged.
        repaired = out_dir / f"{src.stem}.repaired{src.suffix}"
        repaired.write_text(code)
        repaired_to_orig[repaired] = src

    recovered: List[Tuple[Path, Path]] = []
    if repaired_to_orig:
        rewrites = list(repaired_to_orig.keys())
        try:
            valid, _gate_excluded = revalidate(
                rewrites, project, iquote_dirs=iquote_dirs)
        except Exception as exc:  # noqa: BLE001 — infra failure: fail-closed
            # (drop all rewrites; never ship an un-revalidated TU).
            logger.warning("merge-repair: re-validation failed (%s); dropping "
                           "all %d rewrites", exc, len(rewrites))
            for rp, orig in repaired_to_orig.items():
                still_excluded.append((orig, f"repair: re-validation failed ({exc})"))
            return recovered, still_excluded
        valid_set = {Path(v) for v in valid}
        for rp, orig in repaired_to_orig.items():
            if rp in valid_set:
                recovered.append((orig, rp))
            else:
                still_excluded.append(
                    (orig, "repair: rewrite still fails compile gate"))

    return recovered, still_excluded
