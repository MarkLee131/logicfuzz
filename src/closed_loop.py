"""Phase G: closed-loop CBFactory feedback driver.

Runs N feedback iterations on top of an initial driver-synthesis pass.
Each iteration:

1. Materializes "evidence sequences" from the prior round's drivers. By
   default every driver's ``api_sequence`` contributes a positive trace —
   the driver was emitted by CBFactory under the type / lifecycle /
   state-machine / Z3-acceptance constraints, so it represents a working
   protocol the project's static analysis already endorsed. When
   ``preflight_runner`` is wired, only drivers passing a libFuzzer smoke
   test contribute traces.
2. Feeds the evidence into the project automaton via
   :py:meth:`AutomatonArtifact.update_with_traces` (incremental EDSM).
3. Calls the caller-supplied ``resynthesize_fn`` to produce a fresh
   driver batch under the updated automaton. The synthesis path
   currently consumes the artifact via CBFactory's Phase H
   ``AutomatonAcceptanceGuard`` (hard-pruning candidates below the
   acceptance threshold). Other L4 signals the artifact carries —
   ``acceptance_score`` as primary sort axis (G3), ``sample_accepting_paths``
   pool injection, ``graft_creator_prefix``, ``post_parse_extensions`` —
   are NOT re-applied here; doing so would make consecutive iters
   produce identical deterministic top-K (no novelty → automaton
   saturates instantly → defeats the multi-iter feedback design). The
   random-walk path inside CBFactory provides the per-iter diversity
   that keeps the automaton evolving. If a future refactor introduces a
   "weighted random sample from L4 top-K + sample_paths injection"
   strategy, the 4 signals can be re-applied without breaking the
   diversity property.
4. Records per-iteration deltas (Δmerged_states, Δtraces, n_drivers
   synthesized, automaton strength).
5. Early-stops when ``|Δmerged_states| ≤ early_stop_delta`` for two
   consecutive iterations — the automaton has saturated.

This is the runtime side of A2DG (automaton-augmented driver
generation). The static side is :py:func:`learn_project_automaton`
(one-shot from project tests). Together they form the design-doc
Phase 3 closed loop.

Reference:
- Lang/Pearlmutter/Price 1998 §6 (incremental EDSM updates).
- Khuller/Moss/Naor 1999 (budgeted max-coverage; the (1−1/e)-greedy
  used by L4 in the initial pass, not re-applied per-iter — see the
  Step 3 note above).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# A user-supplied function that, given a list of (driver_id, source_path,
# fuzzer_binary), returns the subset of driver_ids that passed preflight.
# When ``None``, every driver is considered "passed" (most permissive
# evidence collection).
PreflightRunner = Callable[
    [List[tuple]], List[int]
]


@dataclass
class IterationRecord:
    """Per-iteration trajectory entry.

    The earlier schema carried ``guard_pruned`` / ``guard_passed`` fields,
    but the closed-loop has no handle to the production CBFactory's
    ``Z3GuidedSynthesisController.automaton_guard`` (it's instantiated
    per-CBFactory-call inside the caller's ``resynthesize_fn``). The
    probe guard we created here was never fed candidates, so the metrics
    were always 0. Dropped in the 2026-05 Comprehender+Closed-loop
    review — better to omit the field than report a misleading constant.
    """

    iteration: int
    n_evidence_traces: int
    n_added_pta_nodes: int
    delta_merged_states: int  # negative = compressed (good)
    n_drivers_synthesized: int
    n_drivers_passed_preflight: int
    automaton_strong: bool
    guard_threshold: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iteration": self.iteration,
            "n_evidence_traces": self.n_evidence_traces,
            "n_added_pta_nodes": self.n_added_pta_nodes,
            "delta_merged_states": self.delta_merged_states,
            "n_drivers_synthesized": self.n_drivers_synthesized,
            "n_drivers_passed_preflight": self.n_drivers_passed_preflight,
            "automaton_strong": self.automaton_strong,
            "guard_threshold": round(self.guard_threshold, 4),
        }


@dataclass
class ClosedLoopResult:
    project: str
    n_iters: int
    iterations: List[IterationRecord] = field(default_factory=list)
    final_drivers: List[Dict[str, Any]] = field(default_factory=list)
    early_stopped: bool = False
    early_stop_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project": self.project,
            "n_iters_requested": self.n_iters,
            "n_iters_run": len(self.iterations),
            "early_stopped": self.early_stopped,
            "early_stop_reason": self.early_stop_reason,
            "iterations": [r.to_dict() for r in self.iterations],
            "n_final_drivers": len(self.final_drivers),
        }


def _extract_evidence_sequences(
    drivers: List[Dict[str, Any]],
    passed_ids: Optional[set] = None,
    *,
    min_length: int = 2,
) -> List[List[str]]:
    """Pull api_sequences out of CBFactory driver records.

    When ``passed_ids`` is provided, only include drivers whose
    ``i`` is in the set (preflight-gated). When ``None``, take all
    drivers (synthesis-only gate).
    """
    out: List[List[str]] = []
    for i, d in enumerate(drivers):
        if passed_ids is not None and i not in passed_ids:
            continue
        seq = d.get("api_sequence") or []
        if isinstance(seq, list) and len(seq) >= min_length:
            out.append([str(x) for x in seq])
    return out


def run_closed_loop(
    *,
    project: str,
    automaton_artifact: Any,
    initial_drivers: List[Dict[str, Any]],
    resynthesize_fn: Callable[[Any, int], List[Dict[str, Any]]],
    n_iters: int = 3,
    early_stop_delta: int = 0,
    early_stop_consecutive: int = 2,
    preflight_runner: Optional[PreflightRunner] = None,
    target_drivers_per_iter: Optional[int] = None,
    persist_dir: Optional[Path] = None,
    log: Optional[logging.Logger] = None,
) -> ClosedLoopResult:
    """Run N feedback iterations.

    Args:
        project: project name (for logging / artifact persistence).
        automaton_artifact: the ``AutomatonArtifact`` produced by the
            initial pipeline pass. Mutated in place across iterations.
        initial_drivers: drivers from iter 0 (the seed evidence).
        resynthesize_fn: callable ``(artifact, num_drivers) -> drivers``.
            Wraps the project's CBFactory invocation; the runner doesn't
            assume a particular shape so callers can plug in any
            synthesis path that respects Phase H (artifact-aware).
        n_iters: number of feedback iterations after iter 0.
        early_stop_delta: automaton is "saturated" when |Δmerged_states|
            ≤ this (default 0 = exactly no compression delta).
        early_stop_consecutive: stop after this many consecutive
            saturated iterations.
        preflight_runner: optional smoke-tester. When supplied, only
            preflight-passing drivers contribute evidence.
        target_drivers_per_iter: K passed to ``resynthesize_fn``. Defaults
            to ``len(initial_drivers)``.
        persist_dir: optional directory to dump per-iteration trajectory.
        log: logger (defaults to module-level).

    Returns:
        ``ClosedLoopResult`` with per-iteration records + final driver set.
    """
    log = log or logger
    if target_drivers_per_iter is None:
        target_drivers_per_iter = max(1, len(initial_drivers))

    result = ClosedLoopResult(project=project, n_iters=n_iters)
    drivers_so_far = list(initial_drivers)
    saturated_streak = 0

    for it in range(1, n_iters + 1):
        # 1. Determine which drivers from prior round contribute evidence.
        passed_ids: Optional[set] = None
        if preflight_runner is not None and drivers_so_far:
            try:
                cands = [
                    (i, d.get("source_path", ""), d.get("fuzzer_binary", ""))
                    for i, d in enumerate(drivers_so_far)
                ]
                passed_ids = set(preflight_runner(cands))
                log.info(
                    "[closed-loop iter %d] preflight passed %d / %d",
                    it, len(passed_ids), len(drivers_so_far),
                )
            except Exception as exc:
                log.warning(
                    "[closed-loop iter %d] preflight runner failed (%s); "
                    "falling back to synthesis-only gating", it, exc,
                )
                passed_ids = None

        evidence = _extract_evidence_sequences(drivers_so_far, passed_ids)
        if not evidence:
            log.warning(
                "[closed-loop iter %d] no evidence sequences; stopping early",
                it,
            )
            result.early_stopped = True
            result.early_stop_reason = "no_evidence"
            break

        # 2. Update automaton with the evidence (incremental EDSM).
        prev_merged = int(automaton_artifact.n_merged_states)
        delta = automaton_artifact.update_with_traces(
            evidence, source_label=f"closed_loop_iter_{it}",
        )

        # 3. Re-synthesize. Caller's resynthesize_fn picks up the mutated
        # artifact (Phase H acceptance guard reflects new strength).
        try:
            new_drivers = resynthesize_fn(
                automaton_artifact, target_drivers_per_iter,
            ) or []
        except Exception as exc:
            log.error(
                "[closed-loop iter %d] resynthesize_fn raised: %s", it, exc,
            )
            new_drivers = []

        # 4. Optional preflight on new drivers (sets passed_ids for the
        # NEXT iteration's evidence gating).
        n_passed_new = 0
        if preflight_runner is not None and new_drivers:
            try:
                cands = [
                    (i, d.get("source_path", ""), d.get("fuzzer_binary", ""))
                    for i, d in enumerate(new_drivers)
                ]
                passed_set = preflight_runner(cands)
                n_passed_new = len(passed_set)
            except Exception:
                n_passed_new = 0
        else:
            # Treat all synthesized drivers as "passed" when no preflight.
            n_passed_new = len(new_drivers)

        # 5. Record metrics. The guard probe gives us a *snapshot* of
        # how the production guard would currently classify the
        # artifact (strong / threshold); per-iteration prune/pass
        # counts live inside the CBFactory the caller spawned, which we
        # don't have a handle to. See IterationRecord docstring for the
        # rationale behind dropping the unreachable counters.
        guard_strong = False
        guard_threshold = 0.0
        try:
            from liberator_adapter.constraints.z3_guided_synthesis import (
                AutomatonAcceptanceGuard,
            )
            probe = AutomatonAcceptanceGuard(artifact=automaton_artifact)
            guard_strong = probe.is_strong()
            guard_threshold = probe.threshold
        except Exception:
            pass

        record = IterationRecord(
            iteration=it,
            n_evidence_traces=len(evidence),
            n_added_pta_nodes=int(delta.get("added_nodes", 0)),
            delta_merged_states=(
                int(automaton_artifact.n_merged_states) - prev_merged
            ),
            n_drivers_synthesized=len(new_drivers),
            n_drivers_passed_preflight=n_passed_new,
            automaton_strong=guard_strong,
            guard_threshold=guard_threshold,
        )
        result.iterations.append(record)
        log.info(
            "[closed-loop iter %d] evidence=%d nodes+%d Δmerged=%+d "
            "drivers=%d passed=%d guard_strong=%s",
            it, record.n_evidence_traces, record.n_added_pta_nodes,
            record.delta_merged_states, record.n_drivers_synthesized,
            record.n_drivers_passed_preflight, record.automaton_strong,
        )

        # Per-iteration persist. The earlier code only persisted at the
        # final return statement; an interrupted run lost the entire
        # trajectory. Now we flush after every iteration so a long
        # closed-loop can be partially recovered. 2026-05 review (CL5).
        if persist_dir is not None:
            try:
                persist_dir.mkdir(parents=True, exist_ok=True)
                import json as _json
                (persist_dir / "closed_loop_trajectory.json").write_text(
                    _json.dumps(result.to_dict(), indent=2),
                )
            except Exception as exc:
                log.warning("[closed-loop iter %d] persist failed: %s", it, exc)

        # 6. Early-stop check.
        if abs(record.delta_merged_states) <= early_stop_delta:
            saturated_streak += 1
        else:
            saturated_streak = 0
        if saturated_streak >= early_stop_consecutive:
            result.early_stopped = True
            result.early_stop_reason = (
                f"automaton_saturated_{saturated_streak}_consecutive_iters"
            )
            log.info(
                "[closed-loop iter %d] automaton saturated; stopping early",
                it,
            )
            # Still keep the new drivers from this iteration.
            drivers_so_far = drivers_so_far + new_drivers
            break

        # 7. Roll forward.
        drivers_so_far = drivers_so_far + new_drivers

    result.final_drivers = drivers_so_far

    if persist_dir is not None:
        try:
            persist_dir.mkdir(parents=True, exist_ok=True)
            import json
            (persist_dir / "closed_loop_trajectory.json").write_text(
                json.dumps(result.to_dict(), indent=2),
            )
        except Exception as exc:
            log.warning("[closed-loop] persist failed: %s", exc)

    return result
