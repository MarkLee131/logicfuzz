"""Coverage-gap signal (redesign G5).

The generation-stage redesign (G1–G4) made driver synthesis *valid by
construction* — but a valid driver is worthless if it only re-covers what the
existing OSS-Fuzz baseline already covers (measured: cjson drivers added
`line_diff=0.00%`; the lcms baseline `cms_gdb_fuzzer` touches just 5 of 297
public APIs, leaving 98% of the surface uncovered). Value comes from reaching
code the baseline misses.

G5 turns that into a *positive* signal: extract the set of **gap APIs** — APIs
the baseline does NOT cover — and direct construction (G2) and ranking (G3)
*toward* them. This is the principled successor to the deleted L5 novelty
filter: L5's target (novelty vs baseline) was right, but it was a hard
*post-filter* that just dropped candidates; G5 instead *builds and ranks toward*
the gap, so we actively manufacture sequences that exercise untouched code.

Two gap sources, best-effort, unioned:
  1. The OSS-Fuzz baseline **textcov** report (per-function coverage; the same
     artifact the §10B baseline-regression check reads). Authoritative.
  2. A ``{function_name: coverage_percent}`` dict from the cloud Fuzz
     Introspector (``_fetch_oss_fuzz_function_coverage``), when available.

Deterministic; no LLM.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

# A function block header in an llvm-cov textcov report: ``func_name:`` alone.
_FUNC_HDR_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*):\s*$')


def parse_textcov_covered(path: Path) -> Set[str]:
    """Return the set of function names the baseline textcov *covered*.

    A function appears as a ``name:`` block header in the report only when the
    baseline fuzzer reached it, so the set of headers is the covered set.
    """
    covered: Set[str] = set()
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                m = _FUNC_HDR_RE.match(line)
                if m:
                    covered.add(m.group(1))
    except OSError:
        pass
    return covered


def locate_baseline_textcov(project: str) -> Optional[Path]:
    """Best-effort search for the project's baseline OSS-Fuzz textcov report.

    Looks in the per-driver coverage-report dirs (where the §10B reference is
    copied) and the canonical ``textcov_reports`` cache. Returns the largest
    ``.covreport`` found (the baseline fuzzer's report), or ``None``.
    """
    roots = [
        Path(f"results/output-{project}-project/code-coverage-reports"),
        Path(f"results/{project}/textcov_reports"),
        Path(f"results/{project}"),
    ]
    candidates: list[Path] = []
    for r in roots:
        if r.exists():
            candidates.extend(r.rglob("*.covreport"))
    if not candidates:
        return None
    # The baseline report is the richest; pick the largest file.
    return max(candidates, key=lambda p: p.stat().st_size if p.is_file() else 0)


def compute_gap_apis(
    api_names: Iterable[str],
    *,
    project: Optional[str] = None,
    baseline_textcov: Optional[Path] = None,
    existing_coverage: Optional[Dict[str, float]] = None,
    covered_threshold_pct: float = 5.0,
) -> Set[str]:
    """APIs the baseline does NOT meaningfully cover — the generation target.

    ``gap = api_names − covered``, where ``covered`` is the union of:
      - functions present in the baseline textcov (header set), and
      - functions with ``existing_coverage[fn] >= covered_threshold_pct``.

    Returns the full ``api_names`` set when no baseline signal is available
    (no gap info ⇒ treat everything as worth targeting — never *narrows*
    generation on missing data).
    """
    api_set = {n for n in api_names if n}
    if not api_set:
        return set()

    covered: Set[str] = set()
    path = baseline_textcov
    if path is None and project:
        path = locate_baseline_textcov(project)
    if path is not None:
        covered |= parse_textcov_covered(path)
    if existing_coverage:
        covered |= {
            fn for fn, pct in existing_coverage.items()
            if pct is not None and pct >= covered_threshold_pct
        }

    if not covered:
        # No baseline signal — don't narrow; everything is a candidate target.
        return set(api_set)
    return api_set - covered
