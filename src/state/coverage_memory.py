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

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, cast

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


@dataclass
class TrialOutcome:
    """One trial's outcome — input to PostMergeEvaluator."""
    trial_id: int
    api_sequence: List[str]
    """Names of APIs in the synthesized driver."""
    final_coverage_pct: Optional[float] = None
    """Driver's PC% on the OSS-Fuzz benchmark; None if not measured."""
    final_line_diff_pct: Optional[float] = None
    """Lines covered beyond baseline / total lines; None if no baseline."""
    crashes_found: int = 0
    success: bool = True
    """False if build/run failed entirely."""

    # T12 — dynamic value feedback. The concrete leaf values the LLM chose for
    # this skeleton's holes, captured at hole-fill time (prototyper) into a side
    # file and attached at snapshot time, so the NEXT run can pin proven values
    # instead of re-guessing. Matched across runs by ``skeleton_key`` — a hash of
    # the API SEQUENCE (content), NOT the positional ``cbfactory_skeleton_{i}``
    # name (which can denote a different sequence next run). ``skeleton_name`` is
    # kept for human/debug only. All default-empty → forward-compatible with old
    # JSON (``TrialOutcome(**t)`` supplies the defaults).
    skeleton_name: Optional[str] = None
    skeleton_key: Optional[str] = None
    hole_values: Dict[str, str] = field(default_factory=dict)

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
        except Exception as _e:
            logger.debug('trial %s outcome extraction failed (%s); not-success',
                         trial_id, _e)
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


# ===================================================================
# T12 — dynamic value feedback (the "read" side of Phase C)
# ===================================================================
# coverage_memory.json was write-only. These helpers close the loop: capture a
# trial's filled hole values (side file), then on a LATER run read back the
# values that reached the highest coverage for a given skeleton and pin them into
# that skeleton's holes — so the LLM starts from a proven value instead of
# re-guessing. Cross-RUN (the snapshot is persisted post-merge); gated upstream
# by LOGICFUZZ_VALUE_FEEDBACK. All best-effort: a failure never breaks a run.

def _hole_values_dir(project: str, state_dir: Optional[Path]) -> Path:
    if state_dir is None:
        state_dir = Path('results') / project / 'state'
    return state_dir / 'hole_values'


def sequence_key(api_sequence: Sequence[str]) -> str:
    """Stable content key for a skeleton = hash of its API sequence.

    Matching proven hole values across runs by the positional name
    (``cbfactory_skeleton_{i}``) is WRONG — index ``i`` can denote a different
    sequence next run, mis-pinning values onto an unrelated API chain. Keying by
    the sequence content makes a pin apply iff the SAME API chain recurs.
    Returns '' for an empty sequence (never matches).
    """
    names = [a for a in (api_sequence or []) if a]
    if not names:
        return ''
    return hashlib.sha1('→'.join(names).encode('utf-8')).hexdigest()[:16]


def record_trial_hole_values(
    project: str,
    trial_id: int,
    skeleton_name: Optional[str],
    api_sequence: Sequence[str],
    hole_values: Dict[str, str],
    state_dir: Optional[Path] = None,
) -> None:
    """Capture one trial's filled hole values to a side file (last-write-wins).

    Written by the prototyper at hole-fill time so the post-merge snapshot can
    attach them without threading values through the state→Result→harvest path.
    Keyed by the API-sequence content hash (``sequence_key``), not the positional
    name. No-op when there are no hole values; never raises.
    """
    if not hole_values:
        return
    try:
        d = _hole_values_dir(project, state_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / f'trial_{int(trial_id)}.json').write_text(
            json.dumps({'skeleton_name': skeleton_name,
                        'skeleton_key': sequence_key(api_sequence),
                        'hole_values': dict(hole_values)}),
            encoding='utf-8')
    except Exception as exc:  # capture must never break the run
        logger.debug("record_trial_hole_values skipped: %s", exc)


def load_trial_hole_values(
    project: str, trial_id: int, state_dir: Optional[Path] = None,
) -> dict:
    """Read back ``{'skeleton_name', 'skeleton_key', 'hole_values'}``; {} if absent."""
    try:
        p = _hole_values_dir(project, state_dir) / f'trial_{int(trial_id)}.json'
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding='utf-8')) or {}
    except Exception as _e:
        logger.debug('hole-values read failed (trial %s): %s', trial_id, _e)
        return {}


def proven_hole_values(memory: CoverageMemory, skeleton_key: str) -> Dict[str, str]:
    """The hole→value map from the highest-coverage prior trial whose
    ``skeleton_key`` matches and that recorded hole values. {} if none.

    Selection: among all snapshots' successful trials with the SAME sequence
    content key and a non-empty ``hole_values``, pick the greatest
    ``final_coverage_pct`` (None coverage treated as 0). Ties keep the first
    (earliest) — deterministic.
    """
    if not skeleton_key:
        return {}
    best_cov = -1.0
    best: Dict[str, str] = {}
    for snap in memory.snapshots:
        for t in snap.trial_results:
            if (t.success and t.hole_values
                    and t.skeleton_key == skeleton_key):
                cov = t.final_coverage_pct or 0.0
                if cov > best_cov:
                    best_cov = cov
                    best = dict(t.hole_values)
    return best


def attach_proven_holes(skeleton_drivers: List[dict],
                        memory: CoverageMemory) -> int:
    """For each skeleton, attach ``skeleton['proven_holes']`` = the proven
    hole→value map from ``memory``, matched by the skeleton's API-sequence
    content key (``sequence_key(sk['api_sequence'])``). Returns how many
    skeletons got a non-empty map. The prototyper renders these as
    'reuse-unless-you-have-a-reason' hints in the hole prompt.
    """
    n = 0
    for sk in skeleton_drivers or []:
        key = sequence_key(sk.get('api_sequence', []))
        proven = proven_hole_values(memory, key)
        if proven:
            sk['proven_holes'] = proven
            n += 1
    return n
