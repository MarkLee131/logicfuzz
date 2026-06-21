"""Merge orchestration pipeline — the SSOT for multi-task harness assembly.

``run_merge_pipeline`` is the public entry point.  ``run_single_fuzz._maybe_merge_drivers``
is a thin adapter that reads from ``Benchmark``/``WorkDirs`` objects and calls this.
The CLI (``tools/merge_drivers/__main__.py``) can also call this directly (Task 3
will wire dominance_filter; for now it is behavior-preserving / unused here).

All helpers that were formerly in ``run_single_fuzz.py`` (lines 512-887) live here
so neither the production path nor the CLI path needs to duplicate orchestration.
"""

import json
import os
from pathlib import Path
from typing import List, Optional

import logger


# ---------------------------------------------------------------------------
# Quarantine helpers (binary-free, triage-based)
# ---------------------------------------------------------------------------

def _is_immediate_crash_fp(br) -> bool:
  """Pre-ship quarantine criterion: a compiled driver that crashed in-container
  with ~0 coverage is an immediate-SEGV false positive (unchecked creator return
  / garbage opaque arg — the class density can introduce on handle-ful drivers).
  It poisons the single-process fused merge harness and contributes no coverage.
  A crasher that made real progress (cov>0) is a normal fuzz target — keep it."""
  if not getattr(br, 'crashes', False):
    return False
  cov_pcs = getattr(br, 'cov_pcs', 0) or 0
  cov_frac = getattr(br, 'coverage', 0.0) or 0.0
  return cov_pcs == 0 and cov_frac <= 0.001


def _should_quarantine_from_merge(br, tr) -> bool:
  """Drop a compiled driver from the merge iff it's a driver-FP crasher — it
  crashed AND its triage did NOT confirm a real (feasible) library bug. This
  covers BOTH cov==0 immediate-crash FPs AND cov>0 deterministic driver-FP
  crashers: a DRIVER-bug crasher that covers a few edges before aborting (e.g.
  libpng driver 116's ``png_color`` output array sized [1] for an API that writes
  up to 256 entries → stack-overflow on ~every input) still poisons the fused
  harness and throttles throughput. A confirmed real library bug is NEVER dropped
  (``_trial_confirms_real_bug``)."""
  return getattr(br, 'crashes', False) and not _trial_confirms_real_bug(tr)


def _trial_confirms_real_bug(tr) -> bool:
  """True iff this trial's crash triage CONFIRMED a real (feasible) bug — a
  library-frame crash kept by lean, or an LLM-feasible verdict. Such a driver is
  KEPT in the merge even at 0 coverage (a genuine library crash may abort before
  accumulating edges); only driver-FP / unverified immediate crashes are
  quarantined. Relies on the verdict reaching ``TrialResult.is_semantic_error``
  (the analysis-result fix in adapters.py). ``is_semantic_error`` is False both
  for a real bug AND for 'no verdict', so we require an actual analysis result —
  a no-verdict immediate crash stays quarantined (the safe default)."""
  return (getattr(tr, 'best_analysis_result', None) is not None
          and not getattr(tr, 'is_semantic_error', True))


# ---------------------------------------------------------------------------
# Binary resolution + preflight helpers
# ---------------------------------------------------------------------------

def _resolve_candidate_binary(src, preflight_dir: Optional[Path]):
  """Best-effort: find a host-runnable libFuzzer binary for a driver source.

  Per-trial OSS-Fuzz binaries are built in Docker and cleaned up, so this
  returns one only when the eval preserved a host-runnable build under
  ``preflight_dir/<NN>`` (the preservation hook). Returns None when no
  runnable binary exists — preflight then can't vet this driver (it is kept,
  not dropped).
  """
  if preflight_dir is None:
    return None
  stem = Path(src).stem  # e.g. "06" from "06.fuzz_target"
  base = Path(preflight_dir)
  for cand in (base / stem, base / f'{stem}.bin', base / f'{stem}_fuzzer'):
    if cand.is_file():
      return cand
  return None


def _is_degenerate_binary_set(hashes) -> bool:
  """True when preflight binaries collapse to a tiny set of distinct hashes — the
  stock-binary build-cache bug signature (instrumented vs not, ± a few sanitizer
  variants). It makes the no_progress edge signal a PHANTOM (verified: lcms 63→2
  hashes, c-ares 29→2, both the stock fuzzer). Real per-driver builds (zlib 18→18,
  libucl 13→13) are NOT degenerate, so their no_progress gate stays trustworthy.

  Threshold is RATIO-based (``distinct <= max(2, total//10)``), not a flat ``<=2``:
  a partial collapse (e.g. 3 distinct among 60 — a handful of sanitizer variants of
  the same stock binary) is still a phantom signal, and a flat ``<=2`` would miss
  it. The ``max(2, …)`` floor preserves the original behaviour for small sets
  (c-ares 29→2 still degenerate; zlib 18→18 / libucl 13→13 still real).
  Cross-project-safe."""
  hashes = list(hashes or [])
  if len(hashes) < 5:
    return False
  return len(set(hashes)) <= max(2, len(hashes) // 10)


def _binaries_degenerate(pairs) -> bool:
  """Hash the preflight binaries and test for the stock-binary collapse."""
  import hashlib
  hashes = []
  for _src, b in pairs:
    try:
      hashes.append(hashlib.md5(Path(str(b)).read_bytes()).hexdigest())
    except OSError:
      continue
  return _is_degenerate_binary_set(hashes)


def _should_drop_no_progress(env_val) -> bool:
  """Decide whether to drop ``no_progress`` drivers from a MERGE.

  DEFAULT = False (KEEP). ``no_progress`` (15s solo edge-growth = 0) is the WRONG
  selector for a MERGED harness: a driver that doesn't GROW in a 15s solo smoke
  run still contributes its construction/exercise edges to the UNION, and a deep
  build+exercise driver (the point of the depth levers) is exactly the kind that
  reads as no_progress solo yet adds union breadth. PromeFuzz filters on COMPILE,
  not 15s runtime growth (Fix 1a principle).

  This used to be ``drop = not _binaries_degenerate(pairs)`` — keep only when the
  preflight binaries collapsed (stock-binary build bug). That mis-fired once the
  build bug was FIXED: real (non-degenerate) binaries RE-ENABLED the gate and it
  culled 10/13 merge-valuable drivers (lcms 16→6 merged, 1411 vs 2289 edges,
  2026-06-16). The realness of the binary does NOT make 15s-solo-growth a valid
  merge selector. Only the explicit env override forces the drop (A/B control).
  Crashers (``dead_on_empty``) are dropped UNCONDITIONALLY elsewhere. Binary
  degeneracy is still detected + LOGGED at the call site as a build-health warning.
  """
  v = (env_val or '').strip().lower()
  return v in ('1', 'true', 'yes', 'on')


def _preflight_rejection_set(results, drop_no_progress: bool):
  """Compute the set of driver_paths to reject from preflight results.

  Always drops crashers (``dead_on_empty``). Drops ``no_progress`` (15s edge-
  growth = 0) ONLY when ``drop_no_progress`` — by default these are KEPT, since
  a deterministic build+exercise driver contributes its construction edges to the
  merged UNION regardless of 15s growth, and the lcms preflight binary was the
  stock cms_gdb_fuzzer (phantom signal). Accepted drivers are never rejected.
  """
  reasons = ('dead_on_empty',) + (('no_progress',) if drop_no_progress else ())
  return {r.driver_path for r in results
          if not r.accepted and r.rejection_reason.startswith(reasons)}


def _preflight_filter_candidates(sources, *, project: str = "",
                                 preflight_dir: Optional[Path] = None,
                                 out_dir: Optional[Path] = None):
  """Smoke-test candidate drivers and drop crash / no-progress ones.

  Returns the surviving source paths. Drops a driver ONLY on a crash or
  zero-edge verdict from a runnable binary; a driver whose binary can't be
  resolved/run is kept (couldn't vet ≠ reject). If fewer than 2 binaries are
  resolvable, preflight is skipped entirely and all sources are returned
  unchanged (logged), preserving prior behaviour.

  *project*: OSS-Fuzz project name threaded into ``preflight()`` so each
  smoke run can execute inside the base-runner container (avoids host glibc
  version mismatches for binaries built against a newer glibc, e.g. 2.38).
  Defaults to ``""`` (legacy host-run behaviour).
  """
  pairs = []
  for src in sources:
    b = _resolve_candidate_binary(src, preflight_dir)
    if b is not None:
      pairs.append((Path(src), b))
  if len(pairs) < 2:
    logger.info(
        f'merge_drivers: preflight skipped — only {len(pairs)} of '
        f'{len(sources)} candidates have a host-runnable binary '
        f'(per-trial binaries are cleaned, so few remain host-runnable). '
        f'Merging the unvetted set.', trial=0)
    return sources
  try:
    from tools.merge_drivers.preflight import preflight, write_report
  except ImportError as exc:
    logger.warning(f'merge_drivers: preflight unavailable ({exc}); '
                   f'merging unvetted', trial=0)
    return sources

  # Route real format-matching seeds into the preflight smoke corpus so
  # parser-entry drivers aren't culled as no_progress on random bytes (the
  # seed-starvation gate). Kill-switch reproduces the legacy empty-corpus gate.
  _route_seeds = os.environ.get("LOGICFUZZ_PREFLIGHT_SEEDS", "1").strip().lower() \
      not in ("0", "false", "no", "off")
  results = preflight(pairs, smoke_duration_sec=15, drop_on_crash=True,
                      project=project, route_seeds=_route_seeds)
  try:
    if out_dir is not None:
      write_report(results, Path(out_dir) / 'preflight.json')
  except Exception:
    pass
  # Drop crashers ALWAYS; KEEP no_progress by default. The 15s solo edge-GROWTH
  # gate is the WRONG selector for a MERGE — a deep build+exercise driver that is
  # flat solo still adds UNION edges (PromeFuzz filters on compile, not 15s growth,
  # Fix 1a). The old `drop = not degenerate` rule mis-fired once the stock-binary
  # build bug was fixed: real binaries re-enabled the gate → culled 10/13
  # merge-valuable drivers (lcms 16→6, 1411 vs 2289 edges, 2026-06-16). Env
  # override LOGICFUZZ_DROP_NO_PROGRESS in {0,1} forces it (A/B). Degeneracy is now
  # a build-HEALTH warning only (it should be impossible post-fix).
  _drop_np = _should_drop_no_progress(
      os.environ.get('LOGICFUZZ_DROP_NO_PROGRESS', ''))
  if _binaries_degenerate(pairs):
    logger.info('merge_drivers: ⚠ preflight binaries DEGENERATE (stock-binary '
                'build bug recurred? expected distinct per-driver builds)',
                trial=0)
  rejected = _preflight_rejection_set(results, drop_no_progress=_drop_np)
  if rejected:
    logger.info(
        f'merge_drivers: preflight dropped {len(rejected)} crashing/'
        f'no-progress driver(s): '
        f'{sorted(Path(p).name for p in rejected)}', trial=0)
  return [s for s in sources if str(s) not in rejected]


# ---------------------------------------------------------------------------
# Language + include-dir helpers (previously tied to Benchmark type)
# ---------------------------------------------------------------------------

def _stock_target_lang(benchmark):
  """Compile language ('c'/'cpp') from the STOCK fuzz target, not the yaml
  ``language`` field (that is the *library* language). None ⇒ merge content-sniffs."""
  try:
    if getattr(benchmark, 'is_cpp_target', False):
      return 'cpp'
    if getattr(benchmark, 'is_c_target', False):
      return 'c'
  except Exception:  # noqa: BLE001 — never block the merge on language probing
    pass
  return None


def _iquote_dirs_for_target(benchmark) -> List[str]:
  """In-image ``-iquote`` dirs so a RELOCATED synthesized driver resolves the
  stock fuzzer's relative include (``#include "../cJSON.h"``) — which resolves
  relative to the including file's directory, not -I/CWD.

  Derived from the benchmark's ``target_path`` (the stock fuzzer's in-image path,
  e.g. ``/src/cjson/fuzzing/cjson_read_fuzzer.c``): the fuzzer's own directory
  (handles ``../X.h``) plus the project root (handles ``X.h``). This reconstructs
  the exact quote-search base the per-driver build has, so the driver's original
  oss-fuzz include resolves identically from ``$SRC/synthesized`` / ``/candidates``.
  Empty when target_path is absent or not an absolute in-image path."""
  tp = (getattr(benchmark, 'target_path', '') or '').strip()
  if not tp.startswith('/'):
    return []
  fuzzer_dir = os.path.dirname(tp)        # e.g. /src/cjson/fuzzing
  proj_root = os.path.dirname(fuzzer_dir)  # e.g. /src/cjson
  dirs: List[str] = []
  for d in (fuzzer_dir, proj_root):
    if d and d not in dirs and d not in ('/', '/src'):
      dirs.append(d)
  return dirs


# ---------------------------------------------------------------------------
# Edge-weighted CDF dispatch helpers
# ---------------------------------------------------------------------------

def _edges_weights_for(sources, out_dir: Optional[Path]):
  """Per-driver dispatch weights from preflight's edges_15s.

  Liberator's "a driver that produces seeds (interacts with the library) is
  high-value" signal — our preflight already smoke-fuzzes each driver 15s and
  records ``edges_seen`` (written to ``merged/preflight.json``). We feed that as
  CDF dispatch weights so the merged fuzzer spends MORE of its per-input budget
  on high-interaction sub-drivers (instead of UNIFORM ``selector % N``). Returns
  ``None`` when there's no edge data (→ uniform dispatch, prior behaviour), or
  when all weights tie. Drivers without data get the MEDIAN weight (neutral, not
  penalised). Weights are aligned to the merge's name-sorted driver order
  (``SynthesizedDriver.from_paths`` sorts by ``path.name``)."""
  if out_dir is None:
    return None
  try:
    payload = json.loads((Path(out_dir) / 'preflight.json').read_text())
    results = payload.get('results') or []
  except (OSError, ValueError):
    return None
  edges_by_name = {Path(r['driver_path']).name: float(r.get('edges_seen') or 0)
                   for r in results if r.get('driver_path')}
  known = sorted(edges_by_name[Path(s).name] for s in sources
                 if Path(s).name in edges_by_name)
  if not known:
    return None
  median = known[len(known) // 2]
  default = median if median > 0 else 1.0
  ordered = sorted(sources, key=lambda p: Path(p).name)  # match from_paths
  weights = [max(edges_by_name.get(Path(s).name, default), 1.0) for s in ordered]
  if len(set(weights)) <= 1:
    return None
  return weights


# ---------------------------------------------------------------------------
# Compile-validation gate
# ---------------------------------------------------------------------------

def _compile_validate_candidates(sources, *, project: str,
                                 stock_lang: Optional[str],
                                 iquote_dirs: List[str],
                                 out_dir: Optional[Path] = None,
                                 model_name: Optional[str] = None):
  """Drop merge candidates that don't COMPILE under the OSS-Fuzz build flags.

  Compiles each candidate TU inside the project's real OSS-Fuzz container with
  ``$CC $CFLAGS -fsyntax-only`` (plus the coverage-build flags — the stricter
  measurement build), in ONE container, once. A TU that fails is EXCLUDED from
  the merge instead of being silently ``|| continue``-skipped + weak-stubbed
  into a no-op slot (which loses the driver and reads 0 coverage on it).

  Fails OPEN: on any infra problem (docker unavailable, no project image,
  container hiccup) it returns the sources unchanged and logs the gap — it must
  never BLOCK a merge, only PRUNE known-bad TUs (the weak-stub net still backs
  it up). A run can opt out via ``LOGICFUZZ_SKIP_COMPILE_VALIDATE=1``.

  Opt-in merge-gate LLM repair (``LOGICFUZZ_MERGE_REPAIR=1`` + ``model_name``):
  give each excluded TU ONE single-shot LLM rewrite, RE-VALIDATE through this same
  gate, keep only if it now compiles (fail-closed → A≡B preserved).
  """
  # Explicit truthy parse — a bare `if os.environ.get(...)` treats "0"/"false"
  # as set, so SKIP_COMPILE_VALIDATE=0 would SKIP the A≡B gate. 2026-06 review.
  if os.environ.get('LOGICFUZZ_SKIP_COMPILE_VALIDATE', '').strip().lower() in (
          '1', 'true', 'yes', 'on'):
    logger.info('merge_drivers: compile-validation skipped '
                '(LOGICFUZZ_SKIP_COMPILE_VALIDATE set)', trial=0)
    return sources
  if not project:
    logger.warning('merge_drivers: no project; skipping '
                   'compile-validation (merging unvetted)', trial=0)
    return sources
  try:
    from tools.merge_drivers.compile_validate import validate_compilable
  except ImportError as exc:
    logger.warning(f'merge_drivers: compile-validation unavailable ({exc}); '
                   f'merging unvetted', trial=0)
    return sources

  valid, excluded = validate_compilable(
      [Path(s) for s in sources], project, iquote_dirs=iquote_dirs, lang=stock_lang)

  # Merge-gate LLM repair (opt-in: LOGICFUZZ_MERGE_REPAIR=1): one single-shot
  # rewrite per excluded TU, re-validated through this same gate. Fail-closed —
  # a still-failing rewrite is dropped, so A≡B holds (kept TUs compile under cov).
  repaired_recovered = 0
  _do_repair = os.environ.get('LOGICFUZZ_MERGE_REPAIR', '').strip().lower() in (
      '1', 'true', 'yes', 'on')
  if excluded and _do_repair and model_name and out_dir is not None:
    try:
      from tools.merge_drivers.llm_repair import repair_candidates
      from src.llm.adapter import create_llm_adapter
      _adapter = create_llm_adapter(model_name)
      if _adapter is None:
        raise RuntimeError('no LLM adapter')

      def _revalidate(srcs, proj, iquote_dirs=None):
        return validate_compilable(list(srcs), proj, iquote_dirs=iquote_dirs,
                                   lang=stock_lang)

      recovered, excluded = repair_candidates(
          excluded, project, _adapter.query,
          out_dir=Path(out_dir) / 'repaired',
          iquote_dirs=iquote_dirs, revalidate=_revalidate)
      for _orig, _repaired in recovered:
        valid.append(_repaired)
      repaired_recovered = len(recovered)
      if repaired_recovered:
        logger.info(
            f'merge_drivers: LLM-repair RECOVERED {repaired_recovered} '
            f'previously-excluded driver(s) (re-validated under cov flags): '
            f'{sorted(Path(o).name for o, _ in recovered)}', trial=0)
    except Exception as _re:  # never block the merge on the repair path
      logger.warning(f'merge_drivers: LLM-repair skipped ({_re}); keeping the '
                     f'original excluded set', trial=0)

  if excluded:
    # Visible, not silent: log every excluded driver + the first error line so
    # the loss is auditable (and confirm it drops the known-invalid ones).
    for src, reason in excluded:
      first = (reason or '').strip().splitlines()
      head = first[0] if first else 'compile error'
      logger.info(
          f'merge_drivers: EXCLUDED non-compiling driver {Path(src).name} '
          f'— {head}', trial=0)
    logger.info(
        f'merge_drivers: compile-validation dropped {len(excluded)} of '
        f'{len(sources)} candidate(s) that fail to build under the OSS-Fuzz '
        f'coverage flags (would have been weak-stubbed no-ops): '
        f'{sorted(Path(s).name for s, _ in excluded)}', trial=0)
    # Persist a machine-readable record alongside the merged output.
    if out_dir is not None:
      try:
        rep = {'project': project,
               'valid': sorted(Path(s).name for s in valid),
               'repaired_recovered': repaired_recovered,
               'excluded': [{'driver': Path(s).name,
                             'reason': (r or '').strip()[:1000]}
                            for s, r in excluded]}
        rep_dir = Path(out_dir)
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / 'compile_validation.json').write_text(
            json.dumps(rep, indent=2))
      except Exception:  # noqa: BLE001 — reporting is best-effort
        pass
  else:
    logger.info(
        f'merge_drivers: compile-validation — all {len(sources)} candidate(s) '
        f'compile under the OSS-Fuzz flags', trial=0)
  return valid


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------

def run_merge_pipeline(
    candidates: List[Path],
    *,
    project: str,
    stock_lang: Optional[str],
    iquote_dirs: List[str],
    out_dir: Path,
    trial_verdicts: Optional[dict] = None,
    preflight_dir: Optional[Path] = None,
    cov_reports_dir: Optional[Path] = None,
    model_name: Optional[str] = None,
    cdf: bool = False,
) -> Optional[str]:
  """Synthesize a multi-task harness from compiled driver sources.

  This is the SSOT for merge orchestration.  ``run_single_fuzz._maybe_merge_drivers``
  is a thin adapter; the CLI ``tools/merge_drivers/__main__.py`` can call this directly.

  Parameters
  ----------
  candidates:
      Paths to ``NN.fuzz_target`` sources (already filtered to compiling,
      non-crashed drivers by the caller, or raw — the quarantine + preflight
      + compile-validate stages below do further pruning).
  project:
      OSS-Fuzz project name (e.g. ``"lcms"``).
  stock_lang:
      ``'c'`` or ``'cpp'`` from the stock fuzz target extension; ``None`` to
      content-sniff (legacy fallback).
  iquote_dirs:
      In-image ``-iquote`` dirs for the compile-validate gate and snippet.
  out_dir:
      Where to write ``synthesized/``, ``oss_fuzz_build_snippet.sh``, etc.
  trial_verdicts:
      Maps ``Path → bool`` (``True`` = quarantine).  When ``None``, the
      quarantine stage is skipped (CLI path has no per-trial verdicts).
  preflight_dir:
      Directory containing host-runnable per-driver binaries; ``None`` skips
      preflight.
  cov_reports_dir:
      Reserved for future per-driver coverage reports (unused now).
  model_name:
      LLM model identifier for ``LOGICFUZZ_MERGE_REPAIR`` (opt-in).
  cdf:
      Use edge-weighted CDF dispatch instead of UNIFORM.  ``False`` by default
      (UNIFORM is the seed-routing-compatible default).

  Returns
  -------
  str
      Path to the ``out_dir`` on success.
  None
      When fewer than 2 candidates survive all gates, or on any infra error
      (fail-open — never raises into the main run).
  """
  out_dir = Path(out_dir)

  # --- Quarantine (binary-free, triage-based) ---
  # When trial_verdicts is provided, drop confirmed driver-FP crashers.
  successful_sources: List[Path] = []
  quarantined = 0
  if trial_verdicts is not None:
    for src in candidates:
      src = Path(src)
      if trial_verdicts.get(src):
        quarantined += 1
        logger.info(
            f'merge: quarantined {src.name} (driver-FP crash) '
            f'— would poison the fused harness', trial=0)
        continue
      successful_sources.append(src)
    if quarantined:
      logger.info(f'merge: pre-ship quarantine dropped {quarantined} '
                  f'immediate-crash FP driver(s)', trial=0)
  else:
    successful_sources = [Path(s) for s in candidates]

  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'successful trial(s); need ≥2 to merge)', trial=0)
    return None

  # --- Preflight (O1): vet candidates before merging ---
  successful_sources = _preflight_filter_candidates(
      successful_sources,
      project=project,
      preflight_dir=preflight_dir,
      out_dir=out_dir,
  )
  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'candidate(s) survived preflight; need ≥2 to merge)', trial=0)
    return None

  # --- Orphan filter: drop lifecycle-incomplete crashers preflight missed ---
  try:
    from tools.merge_drivers.orphan_filter import filter_orphans
    _kept, _orphans = filter_orphans(successful_sources)
    if _orphans:
      logger.info(
          f'merge_drivers: orphan filter dropped {len(_orphans)} '
          f'lifecycle-incomplete (getter-on-NULL) driver(s): '
          f'{[str(o).split("/")[-1] for o in _orphans]}', trial=0)
      successful_sources = _kept
  except Exception as _ofe:  # never block a merge on the filter
    logger.warning(f'merge_drivers: orphan filter skipped ({_ofe})', trial=0)
  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'candidate(s) survived orphan filter; need ≥2 to merge)', trial=0)
    return None

  # --- Compile-validation: keep the MERGED harness VALID (A≡B) ---
  successful_sources = _compile_validate_candidates(
      successful_sources,
      project=project,
      stock_lang=stock_lang,
      iquote_dirs=iquote_dirs,
      out_dir=out_dir,
      model_name=model_name,
  )
  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'candidate(s) survived compile-validation; need ≥2 to merge)',
        trial=0)
    return None

  try:
    from tools.merge_drivers.merge import (
        DispatchMode, SelectorPosition, SynthesizedDriver)
  except ImportError as exc:
    logger.warning(
        f'merge_drivers: tools.merge_drivers unavailable ({exc}); '
        f'skipping', trial=0)
    return None

  try:
    # Dispatch mode. DEFAULT = UNIFORM (``selector % N``, PromeFuzz's mode) — the
    # ONLY mode whose tail selector can be SEED-TAGGED, so real format seeds
    # (.icc/.it8) reliably reach their parser sub-driver at run time
    # (run_extended_fuzzing._parse_merged_dispatch tags UNIFORM, NOT CDF). The
    # edge-weighted CDF dispatch (opt-in LOGICFUZZ_CDF_DISPATCH=1) gives
    # high-interaction sub-drivers a larger budget share BUT makes the selector
    # un-taggable → real seeds route ~1/N at random → the parser is rarely hit →
    # merged coverage collapses + becomes a routing LOTTERY (measured: same
    # drivers, CDF=416 br/7.89%@0s vs UNIFORM seed-routed control=1708/25.84%@0s).
    # For seed-dependent parser drivers, correct seed routing dominates budget
    # weighting, so UNIFORM is the right default.
    _w = _edges_weights_for(successful_sources, out_dir) if cdf else None
    drv = SynthesizedDriver.from_paths(
        successful_sources,
        mode=DispatchMode.CDF if _w else DispatchMode.UNIFORM,
        position=SelectorPosition.TAIL,
        weights=_w,
        lang=stock_lang,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    drv.save(out_dir)
    snippet_path = out_dir / 'oss_fuzz_build_snippet.sh'
    # Relocated synthesized drivers keep the stock fuzzer's relative include
    # idiom (``#include "../cJSON.h"``), which resolves relative to the driver's
    # own directory. Give the compile the stock fuzzer's directory (and the
    # project root) as -iquote bases so that include resolves from $SRC/synthesized
    # exactly as it does in the per-driver build at target_path.
    snippet_path.write_text(drv.emit_oss_fuzz_build_snippet(
        target_name='merged_fuzzer',
        iquote_dirs=iquote_dirs))
    logger.info(
        f'merge_drivers: synthesized {drv.driver_count} drivers '
        f'(lang={"C++" if drv.is_cpp else "C"}, '
        f'selector_bytes={drv.selector_bytes}) → {out_dir}',
        trial=0)
    return str(out_dir)
  except Exception as exc:  # noqa: BLE001 — never break the main run
    logger.warning(
        f'merge_drivers: synthesis failed ({type(exc).__name__}: {exc}); '
        f'main run unaffected', trial=0)
    return None
