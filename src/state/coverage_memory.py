"""Coverage Memory — Phase C foundation of the 5-stage system redesign.

LogicFuzz's evaluation signal historically lived at **per-trial** level
(§10B v1/v2 baseline-regression alerts fired inside execution.py). The
multi-trial × merge design means the right unit of evaluation is the
**merged driver across all trials**, evaluated after merge — not the
individual trial drivers.

This module is the persistent state layer for that post-merge view:
each project's run produces a series of ``IterationSnapshot``s, kept
in ``results/<project>/state/coverage_memory.json``. Each snapshot
records:

- which trials produced drivers
- per-trial coverage profile (already available from execution.py)
- whether the trial's skeleton was repaired by Phase A (provenance)
- the merged driver path + how many of the trials made it in
- post-merge aggregate coverage and ratio vs OSS-Fuzz baseline

Downstream consumers (Phase D Planner, Phase E Adaptive Shape) read
the memory to decide the next iteration's candidate plan — what paths
to target, what shapes to prefer, when to stop.

Single-iteration snapshots are useful immediately: they make the
"are we doing better than last run?" question answerable across
sessions. Cross-iteration saturation detection requires ≥2 snapshots
and lands when the CEGAR loop driver does.

JSON shape is forward-compatible: adding fields is fine, removing or
renaming requires a migration. ``coverage_memory.json`` carries a
``schema_version`` field so consumers can fail loudly on mismatch.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, cast

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


@dataclass
class TrialOutcome:
    """One trial's outcome — input to PostMergeEvaluator."""
    trial_id: int
    api_sequence: List[str]
    """Names of APIs in the synthesized driver (post-repair if applicable)."""
    final_coverage_pct: Optional[float] = None
    """Driver's PC% on the OSS-Fuzz benchmark; None if not measured."""
    final_line_diff_pct: Optional[float] = None
    """Lines covered beyond baseline / total lines; None if no baseline."""
    crashes_found: int = 0
    success: bool = True
    """False if build/run failed entirely."""
    skeleton_repair_applied: bool = False
    """True iff Phase A repaired this trial's skeleton."""
    skeleton_repair_inserted: List[str] = field(default_factory=list)
    """APIs the repair engine grafted in. Empty if not repaired."""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IterationSnapshot:
    """One full iteration of the LogicFuzz pipeline.

    Currently every ``--eval`` run produces exactly one snapshot
    (iteration_idx=0). When the CEGAR loop driver lands, subsequent
    iterations append.
    """
    iteration_idx: int
    timestamp: str
    """ISO-8601 UTC timestamp at snapshot creation."""
    trial_count: int
    trial_results: List[TrialOutcome] = field(default_factory=list)
    merged_driver_path: Optional[str] = None
    merged_driver_count: int = 0
    """How many trials' drivers were successfully merged."""

    # Computed when baseline OSS-Fuzz coverage is available
    aggregate_max_coverage_pct: Optional[float] = None
    """Best single-trial coverage in this iteration."""
    baseline_line_count: Optional[int] = None
    """Total project lines, from OSS-Fuzz summary."""
    baseline_covered_lines: Optional[int] = None
    """Lines the baseline OSS-Fuzz drivers cover (union)."""
    baseline_coverage_pct: Optional[float] = None
    """``baseline_covered_lines / baseline_line_count``."""
    coverage_ratio_to_baseline: Optional[float] = None
    """``aggregate_max_coverage_pct / baseline_coverage_pct`` —
    headline number for "are we doing as well as hand-written?"."""
    aggregate_line_diff_pct: Optional[float] = None
    """Lines our trials cover that baseline doesn't / total. Direct
    "are we finding new paths" indicator."""

    # Phase A telemetry (Phase B telemetry lives in idioms.json)
    repair_summary: Dict[str, int] = field(default_factory=dict)
    """e.g. ``{'candidates_total': 10, 'repaired_success': 2, ...}``"""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['trial_results'] = [tr.to_dict() for tr in self.trial_results]
        return d


@dataclass
class CoverageMemory:
    """Per-project persistent coverage memory across iterations."""
    project: str
    snapshots: List[IterationSnapshot] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def append(self, snap: IterationSnapshot) -> None:
        self.snapshots.append(snap)

    def latest(self) -> Optional[IterationSnapshot]:
        return self.snapshots[-1] if self.snapshots else None

    def latest_ratio(self) -> Optional[float]:
        s = self.latest()
        return s.coverage_ratio_to_baseline if s else None

    def is_saturated(self, lookback: int = 2,
                     ratio_delta: float = 0.01) -> bool:
        """``ratio_to_baseline`` changed less than ``ratio_delta`` over
        the last ``lookback`` snapshots → saturated.

        Returns False when there isn't enough history.
        """
        if len(self.snapshots) < lookback + 1:
            return False
        recent = [s.coverage_ratio_to_baseline for s in self.snapshots[-(lookback + 1):]]
        if any(r is None for r in recent):
            return False
        # All non-None per the guard above; cast keeps the type checker honest.
        recent_f = cast(List[float], recent)
        for prev, cur in zip(recent_f, recent_f[1:]):
            if abs(cur - prev) >= ratio_delta:
                return False
        return True

    def to_dict(self) -> dict:
        return {
            'project': self.project,
            'schema_version': self.schema_version,
            'iteration_count': len(self.snapshots),
            'latest_ratio_to_baseline': self.latest_ratio(),
            'snapshots': [s.to_dict() for s in self.snapshots],
        }

    def persist(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load_or_create(cls, project: str, path: Path) -> 'CoverageMemory':
        if not path.exists():
            return cls(project=project)
        try:
            with path.open(encoding='utf-8') as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("CoverageMemory load failed (%s); starting fresh", e)
            return cls(project=project)
        if raw.get('schema_version') != SCHEMA_VERSION:
            logger.warning(
                "CoverageMemory schema_version mismatch (file=%s, code=%s); "
                "starting fresh", raw.get('schema_version'), SCHEMA_VERSION,
            )
            return cls(project=project)
        snaps = []
        for s in raw.get('snapshots', []):
            trs = [TrialOutcome(**t) for t in s.pop('trial_results', [])]
            snaps.append(IterationSnapshot(trial_results=trs, **s))
        return cls(project=project, snapshots=snaps)


def make_snapshot(
    iteration_idx: int,
    trial_results: List[TrialOutcome],
    merged_driver_path: Optional[str] = None,
    merged_driver_count: int = 0,
    baseline_line_count: Optional[int] = None,
    baseline_covered_lines: Optional[int] = None,
    repair_summary: Optional[Dict[str, int]] = None,
) -> IterationSnapshot:
    """Build a snapshot, computing the derived ratio fields.

    Aggregate convention: ``aggregate_max_coverage_pct`` is the best
    single trial. ``aggregate_line_diff_pct`` is the best line_diff —
    not summed across trials (over-counts shared lines). The right
    aggregate when fuzzing data is available is a union over per-trial
    covered-lines sets; this MVP uses max as a conservative proxy.
    """
    successful = [t for t in trial_results if t.success]
    aggregate_max = max(
        (t.final_coverage_pct or 0.0 for t in successful), default=0.0,
    ) if successful else None
    aggregate_diff = max(
        (t.final_line_diff_pct or 0.0 for t in successful), default=0.0,
    ) if successful else None

    baseline_pct = None
    ratio = None
    if (baseline_line_count is not None
            and baseline_covered_lines is not None
            and baseline_line_count > 0):
        baseline_pct = baseline_covered_lines / baseline_line_count
        if aggregate_max is not None and baseline_pct > 0:
            ratio = aggregate_max / baseline_pct

    return IterationSnapshot(
        iteration_idx=iteration_idx,
        timestamp=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        trial_count=len(trial_results),
        trial_results=trial_results,
        merged_driver_path=merged_driver_path,
        merged_driver_count=merged_driver_count,
        aggregate_max_coverage_pct=aggregate_max,
        baseline_line_count=baseline_line_count,
        baseline_covered_lines=baseline_covered_lines,
        baseline_coverage_pct=baseline_pct,
        coverage_ratio_to_baseline=ratio,
        aggregate_line_diff_pct=aggregate_diff,
        repair_summary=repair_summary or {},
    )


def harvest_trial_outcomes(trial_results: List) -> List[TrialOutcome]:
    """Convert the legacy ``src.results.TrialResult`` objects from a
    ``_fuzzing_pipelines`` run into Phase C ``TrialOutcome`` records.

    The legacy class carries full ``result_history``; we summarise to
    the fields the CoverageMemory consumer needs: coverage, line_diff,
    success, crashes. Defensive against partial trials (missing
    best_result, no run_result, etc.) — failure becomes ``success=False``
    not a raised exception.
    """
    outcomes: List[TrialOutcome] = []
    for tr in trial_results or []:
        if tr is None:
            continue
        trial_id = getattr(tr, 'trial', -1)
        api_sequence: List[str] = []
        coverage_pct: Optional[float] = None
        line_diff_pct: Optional[float] = None
        crashes = 0
        success = False
        try:
            best = getattr(tr, 'best_result', None) or \
                getattr(tr, 'best_analysis_result', None)
            if best is not None:
                run = getattr(best, 'run_result', None) or best
                # Pull whichever fields are present.
                cov = getattr(run, 'coverage', None)
                if cov is not None and isinstance(cov, (int, float)):
                    coverage_pct = float(cov)
                cdiff = getattr(run, 'line_coverage_diff', None)
                if cdiff is not None and isinstance(cdiff, (int, float)):
                    line_diff_pct = float(cdiff)
                if getattr(run, 'crashes', False):
                    crashes = 1
                success = bool(getattr(run, 'compiles', False))
        except Exception:
            success = False

        outcomes.append(TrialOutcome(
            trial_id=int(trial_id) if trial_id is not None else -1,
            api_sequence=api_sequence,
            final_coverage_pct=coverage_pct,
            final_line_diff_pct=line_diff_pct,
            crashes_found=crashes,
            success=success,
        ))
    return outcomes


def load_baseline_line_counts(
    project: str, log: Optional[logging.Logger] = None,
) -> Optional[Dict[str, int]]:
    """Best-effort: fetch baseline OSS-Fuzz line counts via existing
    ``experiment.evaluator`` helpers. Returns
    ``{'covered': N, 'total': M}`` or None on failure (e.g. no network,
    bucket auth, or project not in OSS-Fuzz).
    """
    try:
        from experiment.evaluator import (
            load_existing_coverage_summary,
            compute_total_lines_without_fuzz_targets,
        )
    except Exception:
        return None
    try:
        summary = load_existing_coverage_summary(project)
        if not summary:
            return None
        totals = summary['data'][0]['totals']['lines']
        covered = int(totals.get('covered', 0))
        total = int(totals.get('count', 0))
        if total <= 0:
            return None
        # ``compute_total_lines_without_fuzz_targets`` excludes the
        # fuzz-target files themselves; use it when possible.
        try:
            adj_total = compute_total_lines_without_fuzz_targets(
                summary, '__placeholder__')
            if isinstance(adj_total, int) and adj_total > 0:
                total = adj_total
        except Exception:
            pass
        return {'covered': covered, 'total': total}
    except Exception as exc:
        if log is not None:
            log.debug("baseline line-count fetch failed: %s", exc)
        return None


def persist_snapshot(
    project: str,
    snapshot: IterationSnapshot,
    state_dir: Optional[Path] = None,
) -> CoverageMemory:
    """Convenience: load existing memory, append snapshot, persist.

    Returns the updated CoverageMemory so callers can inspect saturation
    / latest ratio without re-loading.
    """
    if state_dir is None:
        state_dir = Path('results') / project / 'state'
    path = state_dir / 'coverage_memory.json'
    mem = CoverageMemory.load_or_create(project, path)
    mem.append(snapshot)
    try:
        mem.persist(path)
        logger.info(
            "CoverageMemory: iter %d, %d trials, ratio=%s → %s",
            snapshot.iteration_idx, snapshot.trial_count,
            f"{snapshot.coverage_ratio_to_baseline:.2f}"
                if snapshot.coverage_ratio_to_baseline is not None else "n/a",
            path,
        )
    except Exception as exc:
        logger.warning("CoverageMemory persist failed (non-critical): %s", exc)
    return mem
