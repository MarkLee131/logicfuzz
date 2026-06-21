"""O2 — coverage-aware subset selection for merged harness.

Given preflight-survivors and per-driver reached function sets (from
existing OSS-Fuzz coverage reports — we do *not* re-run coverage builds),
pick the Top-K drivers maximizing the union of reachable functions.

This is classical Maximum Coverage (NP-hard), greedy approximation by
Khuller/Moss/Naor 1999, ratio (1 − 1/e). At each step we pick the
driver with the largest marginal gain on the running union.

Note on relation to ``liberator_adapter/constraints/coverage_ranker.py``:
that module's ``_greedy_select`` iterates input-order and deduplicates;
it relies on the caller having pre-sorted by a fixed score. That is *not*
the same algorithm as classical max-coverage greedy and does not enjoy
the (1−1/e) bound. The two coexist because they serve different
purposes: ranker selects API *sequences* (where pre-sort encodes
diversity / entry-point / acceptance preferences), this module selects
*drivers* purely on union coverage.

Data source: ``results/output-{project}-project/code-coverage-reports/
<id>.fuzz_target/linux/summary.json`` produced by LogicFuzz's existing
OSS-Fuzz coverage build. We trust the recorded set of executed
functions as the empirical reachable set per driver. This is more
faithful than the static reachability prediction used during driver
synthesis.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, List, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class DriverCoverage:
    """Per-driver reached function set, plus preflight signals."""

    driver_path: Path
    reached_funcs: FrozenSet[str]
    edges_15s: int = 0  # from preflight; tie-break only
    has_real_data: bool = True  # False if reached_funcs is a fallback singleton

    @classmethod
    def from_oss_fuzz_report(
        cls,
        driver_path: Path,
        report_dir: Optional[Path],
        edges_15s: int = 0,
    ) -> "DriverCoverage":
        """Load reached-functions from an LLVM ``summary.json`` if present.

        ``report_dir`` should be the directory containing
        ``linux/summary.json`` (LogicFuzz writes it under
        ``code-coverage-reports/<id>.fuzz_target/``). When absent or
        unparsable, we fall back to a unique singleton so the driver
        is still routable but not double-counted.
        """
        summary_path: Optional[Path] = None
        if report_dir:
            for candidate in (
                report_dir / "linux" / "summary.json",
                report_dir / "summary.json",
            ):
                if candidate.exists():
                    summary_path = candidate
                    break

        if summary_path is None:
            logger.warning(
                "no coverage report for %s; using fallback singleton",
                driver_path.name,
            )
            return cls(
                driver_path=driver_path,
                reached_funcs=frozenset({f"__fallback__:{driver_path.stem}"}),
                edges_15s=edges_15s,
                has_real_data=False,
            )

        try:
            data = json.loads(summary_path.read_text())
            funcs = frozenset(
                f["name"]
                for f in data["data"][0]["functions"]
                if f.get("count", 0) > 0
            )
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            logger.warning("failed to parse %s: %s; using fallback", summary_path, e)
            return cls(
                driver_path=driver_path,
                reached_funcs=frozenset({f"__fallback__:{driver_path.stem}"}),
                edges_15s=edges_15s,
                has_real_data=False,
            )

        return cls(
            driver_path=driver_path,
            reached_funcs=funcs,
            edges_15s=edges_15s,
            has_real_data=True,
        )


@dataclass
class SelectionStep:
    """One greedy step's record for downstream weight assignment / debug."""

    driver: DriverCoverage
    marginal_funcs: int      # |reached_funcs(d) \ union_so_far|
    cumulative_funcs: int    # |union after this pick|


@dataclass
class SelectionResult:
    """Output of ``select_top_k``."""

    steps: List[SelectionStep] = field(default_factory=list)
    skipped_no_data: List[DriverCoverage] = field(default_factory=list)

    @property
    def selected_drivers(self) -> List[DriverCoverage]:
        return [s.driver for s in self.steps]

    @property
    def total_funcs_covered(self) -> int:
        return self.steps[-1].cumulative_funcs if self.steps else 0


@dataclass
class DominanceResult:
    """Output of ``dominance_filter``: the kept (shipped) drivers and the
    fully-dominated ones removed (each dropped driver's reached set is a subset
    of some kept driver, so the union is unchanged)."""

    kept: List[DriverCoverage] = field(default_factory=list)
    dropped: List[DriverCoverage] = field(default_factory=list)


def dominance_filter(coverages: Sequence[DriverCoverage]) -> DominanceResult:
    """Keep every driver whose measured reached-function set is NOT fully
    contained in another KEPT driver; drop only fully-dominated drivers.

    Guarantee: the union of ``reached_funcs`` over ``kept`` equals the union over
    ``coverages`` — a dropped driver adds nothing the kept set does not already
    cover. So this cannot remove any distinct reached function (no breadth loss).

    - A driver with ``has_real_data == False`` is ALWAYS kept (its fallback
      singleton is unique, never a subset of a real set).
    - Exact duplicates (mutually-contained sets): the one with higher
      ``edges_15s``, then lexicographically smaller ``driver_path.name``, is
      kept; the other is dropped.
    - An empty-coverage real driver (``reached_funcs == frozenset()``) is
      dominated by every non-empty kept driver and is dropped — correct, since
      it contributes nothing to the union (and the guarantee still holds).
    - Deterministic and order-independent: real candidates are processed
      largest-set-first (edges, then name as tie-breaks) and the kept order
      (incl. no-data drivers, sorted by name) does not depend on input order,
      so a dominator is always seen before any driver it dominates.
    """
    real = [c for c in coverages if c.has_real_data]
    nodata = sorted(
        (c for c in coverages if not c.has_real_data),
        key=lambda c: c.driver_path.name,
    )

    order = sorted(
        real,
        key=lambda c: (-len(c.reached_funcs), -c.edges_15s, c.driver_path.name),
    )
    kept: List[DriverCoverage] = []
    dropped: List[DriverCoverage] = []
    for c in order:
        if any(c.reached_funcs <= k.reached_funcs for k in kept):
            dropped.append(c)
        else:
            kept.append(c)

    kept.extend(nodata)  # no-data drivers are never dominated
    return DominanceResult(kept=kept, dropped=dropped)


def select_top_k(
    coverages: Sequence[DriverCoverage],
    k: Optional[int] = None,
    require_coverage_data: bool = True,
) -> SelectionResult:
    """Classical max-coverage greedy.

    Args:
        coverages: candidate drivers with their reached-function sets.
        k: cap on the number of selected drivers; ``None`` means "no cap"
           (algorithm still terminates when no driver adds marginal
           coverage).
        require_coverage_data: if True (default), drivers with
           ``has_real_data == False`` are excluded entirely from
           selection — including them would force the greedy to pick
           them as "novel" contributors of the singleton fallback set,
           which is meaningless. If False, fallback drivers are kept and
           may be selected (typically only when no real-data driver
           remains).

    Returns:
        ``SelectionResult`` with per-step marginal contributions, in
        selection order. The order is the *greedy order* (largest
        marginal first), which O3 directly reuses for CDF weight
        assignment.

        Termination: the greedy stops when (a) all drivers are picked,
        (b) ``k`` reached, or (c) the best remaining marginal gain is 0.
    """
    if k is None:
        k = len(coverages)

    pool = [c for c in coverages if c.has_real_data or not require_coverage_data]
    skipped = [c for c in coverages if c not in pool]

    selected: List[SelectionStep] = []
    covered: set[str] = set()

    while pool and len(selected) < k:
        # Pick driver with max marginal contribution. Tie-break by
        # edges_15s (more responsive driver in smoke run wins) then by
        # path stability (lexicographic) so the result is deterministic.
        best_idx = -1
        best_gain = -1
        best_edges = -1
        best_name = ""
        for i, cov in enumerate(pool):
            gain = len(cov.reached_funcs - covered)
            if (
                gain > best_gain
                or (gain == best_gain and cov.edges_15s > best_edges)
                or (
                    gain == best_gain
                    and cov.edges_15s == best_edges
                    and cov.driver_path.name < best_name
                )
            ):
                best_idx = i
                best_gain = gain
                best_edges = cov.edges_15s
                best_name = cov.driver_path.name

        if best_gain <= 0:
            # No driver adds new functions — stop. (Khuller stop condition.)
            break

        chosen = pool.pop(best_idx)
        covered |= chosen.reached_funcs
        selected.append(SelectionStep(
            driver=chosen,
            marginal_funcs=best_gain,
            cumulative_funcs=len(covered),
        ))

    return SelectionResult(steps=selected, skipped_no_data=skipped)
