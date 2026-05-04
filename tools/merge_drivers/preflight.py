"""O1 — pre-flight smoke test for candidate fuzz drivers.

Each candidate is run through libFuzzer for a short window
(``smoke_duration_sec``, default 15 s). We drop drivers that:

  * crash on the empty corpus (``crash_on_empty``),
  * fail to gain any coverage edges in the smoke window (``edges == 0``),
  * exit non-zero before the duration elapses (``exit_code != 0``
    without a crash file — usually means the binary is broken).

Surviving drivers are returned with ``edges_15s`` and ``execs_per_sec``
so the caller (``__main__.py``) can sort + cap before passing to
``SynthesizedDriver.from_paths``.

Important — what this module does NOT do:

  * It does NOT build the fuzzer binaries. Caller must pass paths to
    *already-built* libFuzzer binaries (one per candidate driver). For
    LogicFuzz this means using OSS-Fuzz ``infra/helper.py build_fuzzers``
    upstream of preflight.
  * It does NOT measure source-line coverage — only edge coverage from
    libFuzzer's own ``cov:`` line. Source-cov takes a separate
    ``coverage`` build, which is too expensive at 15 s × N drivers.

Theory anchor: cheap rejection on a 15 s smoke is a Pareto-dominant
filter — drivers that don't progress in 15 s fundamentally won't
contribute to a 24 h fused campaign either, and they pollute the
shared corpus / dispatcher's discriminator slot.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PreflightResult:
    """Smoke-fuzz result for one candidate driver."""

    driver_path: str  # path to the source ``.fuzz_target`` (for downstream merge)
    fuzzer_binary: str  # path to the built libFuzzer binary
    duration_sec: int
    exit_code: int
    edges_seen: int
    execs_per_sec: float
    crashed: bool
    crash_artifact: Optional[str] = None
    stderr_tail: str = ""
    # Set by the caller (preflight()), not the runner
    accepted: bool = False
    rejection_reason: str = ""


def _parse_libfuzzer_log(log_text: str) -> tuple[int, float]:
    """Return ``(max_edges_seen, execs_per_sec)`` from a libFuzzer log."""
    max_edges = 0
    execs = 0.0
    for line in log_text.splitlines():
        m = re.search(r'\bcov:\s*(\d+)', line)
        if m:
            try:
                max_edges = max(max_edges, int(m.group(1)))
            except ValueError:
                pass
        m = re.search(r'stat::average_exec_per_sec:\s*([\d.]+)', line)
        if m:
            try:
                execs = float(m.group(1))
            except ValueError:
                pass
    return max_edges, execs


def _smoke_one(
    driver_path: Path,
    fuzzer_binary: Path,
    duration_sec: int,
    workspace: Path,
) -> PreflightResult:
    """Run one fuzzer binary for ``duration_sec`` seconds and parse output."""
    workspace.mkdir(parents=True, exist_ok=True)
    corpus_dir = workspace / "corpus"
    crashes_dir = workspace / "crashes"
    log_file = workspace / "stderr.log"
    corpus_dir.mkdir(exist_ok=True)
    crashes_dir.mkdir(exist_ok=True)

    # Single empty seed — libFuzzer needs ≥1 entry to start
    (corpus_dir / "empty").write_bytes(b"")

    cmd = [
        str(fuzzer_binary),
        str(corpus_dir),
        f"-max_total_time={duration_sec}",
        "-print_final_stats=1",
        "-detect_leaks=0",
        f"-artifact_prefix={crashes_dir}/",
        # Don't fork — we want a clean exit code if the binary itself dies
    ]
    try:
        with open(log_file, "wb") as out:
            proc = subprocess.run(
                cmd,
                stdout=out,
                stderr=subprocess.STDOUT,
                timeout=duration_sec + 30,
                check=False,
            )
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        exit_code = -1
        timed_out = True

    log_text = log_file.read_text(encoding="utf-8", errors="replace")
    edges, execs = _parse_libfuzzer_log(log_text)

    crashes = sorted(crashes_dir.glob("crash-*"))
    timeouts = sorted(crashes_dir.glob("timeout-*"))
    crash_artifact = str(crashes[0]) if crashes else (
        str(timeouts[0]) if timeouts else None
    )

    # libFuzzer exits 77 on a found crash, 0 on duration completion.
    # If it exited non-zero with no crash file and we didn't time out,
    # the binary is broken (segfault before fuzzing started, missing
    # symbol, etc.).
    crashed = bool(crash_artifact) or (exit_code == 77)

    tail = log_text[-2000:] if len(log_text) > 2000 else log_text
    return PreflightResult(
        driver_path=str(driver_path),
        fuzzer_binary=str(fuzzer_binary),
        duration_sec=duration_sec if not timed_out else duration_sec + 30,
        exit_code=exit_code,
        edges_seen=edges,
        execs_per_sec=execs,
        crashed=crashed,
        crash_artifact=crash_artifact,
        stderr_tail=tail,
    )


def preflight(
    candidates: List[tuple[Path, Path]],
    smoke_duration_sec: int = 15,
    workspace_root: Optional[Path] = None,
    min_edges: int = 1,
    drop_on_crash: bool = True,
) -> List[PreflightResult]:
    """Smoke-test a list of (driver_source, fuzzer_binary) pairs.

    Args:
        candidates: list of ``(driver_source_path, fuzzer_binary_path)``.
            ``driver_source_path`` is what gets passed downstream to
            ``SynthesizedDriver.from_paths``; ``fuzzer_binary_path`` is
            the actual libFuzzer binary we run for the smoke test.
        smoke_duration_sec: per-driver smoke window. Default 15.
        workspace_root: where to put per-driver corpus / crashes / logs.
            One temp dir is created if ``None``.
        min_edges: minimum ``cov:`` reported edges to accept the driver.
            Default 1 (any edge at all). Set to e.g. 10 to require some
            forward progress.
        drop_on_crash: if True (default), reject drivers whose smoke run
            produced a crash artifact. Set False if your goal is to
            *find* crashes during preflight (rare, but supported).

    Returns:
        ``List[PreflightResult]`` in the same order as ``candidates``,
        with ``accepted`` / ``rejection_reason`` populated.
    """
    if workspace_root is None:
        workspace_root = Path(tempfile.mkdtemp(prefix="merge_drivers_preflight_"))
    workspace_root.mkdir(parents=True, exist_ok=True)

    results: List[PreflightResult] = []
    for i, (drv_src, drv_bin) in enumerate(candidates):
        ws = workspace_root / f"d{i:03d}_{drv_src.stem}"
        logger.info(
            "[preflight %d/%d] %s (%ds)",
            i + 1, len(candidates), drv_src.name, smoke_duration_sec,
        )
        try:
            res = _smoke_one(drv_src, drv_bin, smoke_duration_sec, ws)
        except FileNotFoundError as e:
            res = PreflightResult(
                driver_path=str(drv_src),
                fuzzer_binary=str(drv_bin),
                duration_sec=0,
                exit_code=-1,
                edges_seen=0,
                execs_per_sec=0.0,
                crashed=False,
                stderr_tail=f"FileNotFoundError: {e}",
            )

        # Decide acceptance
        if not drv_bin.exists():
            res.accepted = False
            res.rejection_reason = f"binary_missing ({drv_bin})"
        elif drop_on_crash and res.crashed:
            res.accepted = False
            res.rejection_reason = (
                f"crash_on_empty (artifact={res.crash_artifact})"
            )
        elif res.exit_code not in (0, 77, -1) and not res.crashed:
            # -1 = our timeout fallback; 0/77 = clean libFuzzer exit
            res.accepted = False
            res.rejection_reason = f"binary_broken (exit={res.exit_code})"
        elif res.edges_seen < min_edges:
            res.accepted = False
            res.rejection_reason = (
                f"no_progress (edges={res.edges_seen} < {min_edges})"
            )
        else:
            res.accepted = True
            res.rejection_reason = ""

        logger.info(
            "[preflight] %s → %s (edges=%d, ex/s=%.0f, %s)",
            drv_src.name,
            "ACCEPT" if res.accepted else "REJECT",
            res.edges_seen,
            res.execs_per_sec,
            res.rejection_reason or "ok",
        )
        results.append(res)

    return results


def write_report(results: List[PreflightResult], path: Path) -> None:
    """Persist a preflight run as JSON for batch evaluation aggregation."""
    payload = {
        "n_candidates": len(results),
        "n_accepted": sum(1 for r in results if r.accepted),
        "n_rejected": sum(1 for r in results if not r.accepted),
        "results": [asdict(r) for r in results],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
