#!/usr/bin/env python3
"""Run an experiment with one function-under-test."""

import argparse
import dataclasses
import logging
import os
from multiprocessing import pool
from typing import List, Optional

import logger
from src.workflow import FuzzingWorkflow
from experiment import builder_runner as builder_runner_lib
from experiment import evaluator as exp_evaluator
from experiment import oss_fuzz_checkout, textcov
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from src.llm import models
from results import BenchmarkResult, TrialResult

# WARN: Avoid high value for NUM_EVA for local experiments.
# NUM_EVA controls the number of fuzz targets to evaluate in parallel by each
# experiment, while {run_logicfuzz.NUM_EXP, default 2} experiments will
# run in parallel.
NUM_EVA = int(os.getenv('LLM_NUM_EVA', '6'))

# Default LLM hyper-parameters.
# #182 shows Gemini returns NUM_SAMPLES independent responses via repeated
#  queries, which generally performs better than top-k responses from one
#  query [1].
# WARN: Avoid large NUM_SAMPLES in highly parallelized local experiments.
# It controls the number of LLM responses per prompt, which may exceed your
# LLM's limit on query-per-second.
# Trial cap dropped from 5 → 2 (override with -n) to halve LLM cost on
# repeated runs; the L4 ranker already prunes to 12 sequences so the gain
# from extra trials past 2 is marginal in our empirical runs.
NUM_SAMPLES = 2
MAX_TOKENS: int = 409600
RUN_TIMEOUT: int = 60
TEMPERATURE: float = 0.4

# Default results directory (matches main branch behavior)
# Each benchmark gets its own directory: results/output-{project}-{function}/
RESULTS_DIR = './results'

@dataclasses.dataclass
class AggregatedResult:
  """Aggregated evaluation result."""
  build_success_count: int = 0
  build_success_rate: float = 0.0
  crash_rate: float = 0.0
  found_bug: int = 0
  max_coverage: float = 0.0
  max_line_coverage_diff: float = 0.0
  max_coverage_sample: str = ''
  max_coverage_diff_sample: str = ''
  max_coverage_diff_report: str = ''
  full_textcov_diff: textcov.Textcov = dataclasses.field(
      default_factory=textcov.Textcov)

  def __str__(self):
    return (
        f'build success rate: {self.build_success_rate}, '
        f'crash rate: {self.crash_rate}, '
        f'found bug: {self.found_bug}, '
        f'max coverage: {self.max_coverage}, '
        f'max line coverage diff: {self.max_line_coverage_diff}\n'
        f'max coverage sample: {self.max_coverage_sample}\n'
        f'max coverage diff sample: {self.max_coverage_diff_sample}\n'
        f'max coverage diff report: {self.max_coverage_diff_report or "None"}')

  @classmethod
  def from_benchmark_result(
      cls, benchmark_result: BenchmarkResult) -> 'AggregatedResult':
    """Aggregates experiment history results of all samples."""

    return AggregatedResult(
        build_success_count=benchmark_result.build_success_count,
        build_success_rate=benchmark_result.build_success_rate,
        crash_rate=benchmark_result.crash_rate,
        max_coverage=benchmark_result.coverage,
        max_line_coverage_diff=benchmark_result.line_coverage_diff,
        max_coverage_sample=benchmark_result.max_coverage_sample,
        max_coverage_diff_sample=benchmark_result.max_coverage_diff_sample,
        max_coverage_diff_report=benchmark_result.line_coverage_report,
        full_textcov_diff=benchmark_result.textcov_diff)


def aggregate_results(target_stats: list[tuple[int, exp_evaluator.Result]],
                      generated_targets: list[str]) -> AggregatedResult:
  """Aggregates experiment status and results of a targets."""
  build_success_count = sum([int(stat.compiles) for _, stat in target_stats])
  build_success_rate = build_success_count / len(target_stats)
  crash_rate = sum([int(stat.crashes) for _, stat in target_stats
                   ]) / len(target_stats)
  found_bug = sum([
      int(stat.crashes and not stat.is_semantic_error)
      for _, stat in target_stats
  ])
  max_coverage = max([stat.coverage for _, stat in target_stats])
  max_line_coverage_diff = max(
      [stat.line_coverage_diff for _, stat in target_stats])

  max_coverage_sample = ''
  max_coverage_diff_sample = ''
  max_coverage_diff_report = ''

  all_textcov = textcov.Textcov()
  for i, stat in target_stats:
    if stat.coverage == max_coverage:
      max_coverage_sample = generated_targets[i]

    if stat.line_coverage_diff == max_line_coverage_diff:
      max_coverage_diff_sample = generated_targets[i]
      max_coverage_diff_report = stat.coverage_report_path

    if isinstance(stat.textcov_diff, textcov.Textcov):
      all_textcov.merge(stat.textcov_diff)

  return AggregatedResult(build_success_count, build_success_rate, crash_rate,
                          found_bug, max_coverage, max_line_coverage_diff,
                          max_coverage_sample, max_coverage_diff_sample,
                          max_coverage_diff_report, all_textcov)

def check_targets(
    benchmark: Benchmark,
    work_dirs: WorkDirs,
    generated_targets: List[str],
    cloud_experiment_name: str = '',
    cloud_experiment_bucket: str = '',
    run_timeout: int = RUN_TIMEOUT,
    fixer_model_name: str = models.DEFAULT_MODEL,
) -> Optional[AggregatedResult]:
  """Builds all targets in the fixed target directory."""
  target_stats = []

  if cloud_experiment_name:
    builder_runner = builder_runner_lib.CloudBuilderRunner(
        benchmark,
        work_dirs,
        run_timeout,
        fixer_model_name,
        experiment_name=cloud_experiment_name,
        experiment_bucket=cloud_experiment_bucket,
    )
  else:
    builder_runner = builder_runner_lib.BuilderRunner(benchmark, work_dirs,
                                                      run_timeout,
                                                      fixer_model_name)

  evaluator = exp_evaluator.Evaluator(builder_runner, benchmark, work_dirs)

  with pool.ThreadPool(NUM_EVA) as p:
    for i, target_stat in enumerate(
        p.map(evaluator.check_target, generated_targets)):
      if target_stat is None:
        logging.error('This should never happen: Error evaluating target: %s',
                      generated_targets[i])
        target_stat = exp_evaluator.Result()

      target_stats.append((i, target_stat))

  if len(target_stats) > 0:
    return aggregate_results(target_stats, generated_targets)

  logging.info('No targets to check.')
  return None

def prepare(oss_fuzz_dir: str) -> None:
  """Prepares the experiment environment."""
  oss_fuzz_checkout.clone_oss_fuzz(oss_fuzz_dir)
  oss_fuzz_checkout.postprocess_oss_fuzz()

def _prepare_shared_data_for_benchmark(benchmark: Benchmark, args: argparse.Namespace,
                                        model_name: str = None) -> dict:
  """
  Extract shared data using Liberator project-level modeling.

  This function uses ProjectDriverGenerator to model the entire project,
  extract all APIs, and generate API sequences for driver generation.

  Args:
      benchmark: Benchmark containing project info (project-level mode)
      args: Command line arguments
      model_name: LLM model name for driver knowledge extraction

  Returns:
      Dictionary with shared data:
      - project_apis: All APIs extracted from project
      - api_sequences: API call sequences from grammar
      - dependency_graph: Type dependency graph
      - grammar_info: Grammar metadata
      - header_info: Header file information
      - existing_fuzzer_headers: Headers from existing fuzzers
      - existing_driver_knowledge: Knowledge extracted from existing OSS-Fuzz drivers
  """
  from src.context.data_context import FuzzingContext
  from src.llm.adapter import create_llm_adapter

  project_name = benchmark.project

  try:
    # Phase G closed-loop knobs (only active when --closed-loop is also set)
    # ``num_synthesis_drivers`` was removed: per CLAUDE.md, --num-samples is
    # auto-resolved to ``len(skeleton_drivers)`` at runtime — one trial per
    # Z3-validated skeleton. The old hardcoded knob was dead-arg-passed for
    # months until --use-doxygen-priors first triggered a strict-kwarg path
    # in prepare() that surfaced the latent TypeError. Cleared here.
    closed_loop_iters = (
        getattr(args, 'closed_loop_iters', 0)
        if (args and getattr(args, 'closed_loop', False)) else 0
    )
    closed_loop_early_stop = (
        getattr(args, 'closed_loop_early_stop', 0) if args else 0
    )

    # Create LLM adapter for driver knowledge extraction (optional)
    llm_client = None
    if model_name:
      try:
        llm_client = create_llm_adapter(model_name)
        logger.info(f'✅ Created LLM adapter ({model_name}) for driver knowledge extraction', trial=0)
      except Exception as e:
        logger.warning(f'⚠️ Could not create LLM adapter: {e}. Driver knowledge extraction will be limited.', trial=0)

    context = FuzzingContext.prepare(
      project_name=project_name,
      benchmark=benchmark,  # Pass benchmark for Clang/LLVM extraction
      logger_instance=None,  # Use standard logging - no trial concept here
      llm_client=llm_client,  # Pass LLM for driver knowledge extraction
      closed_loop_iters=closed_loop_iters,
      closed_loop_early_stop=closed_loop_early_stop,
      # Doc priors (doxygen + readme) are always on — see prepare() (B1-③).
    )
    return context.to_dict()
  except (ValueError, RuntimeError) as e:
    # Re-raise with clear message - caller decides how to handle
    logger.error(f'❌ Failed to prepare project-level fuzzing context: {e}', trial=0)
    raise


# Removed: _extract_existing_fuzzer_headers_helper
# Now handled inside FuzzingContext.prepare()


def _fuzzing_pipeline(benchmark: Benchmark, model_name: str,
                      args: argparse.Namespace, work_dirs: WorkDirs,
                      trial: int, shared_data: dict = None) -> TrialResult:
  """Runs the LangGraph-based fuzzing workflow for one trial."""
  trial_logger = logger.get_trial_logger(trial=trial, level=logging.DEBUG)
  trial_logger.info('Trial Starts')
  
  # Log shared data usage
  if shared_data:
    trial_logger.info(f'Using shared data prepared at timestamp {shared_data.get("timestamp", "unknown")}')
  else:
    trial_logger.warning('No shared data provided - will query FI independently (inefficient!)')
  
  # Note: signal-based timeout is disabled because signal.signal() only works in main thread
  # ThreadPool workers run in separate threads, so signal.SIGALRM cannot be used here
  # If timeout protection is needed, consider using multiprocessing.Pool instead of ThreadPool
  TRIAL_TIMEOUT = getattr(args, 'trial_timeout', 7200)  # 2 hours default
  trial_logger.info(f'⏰ Trial timeout configured: {TRIAL_TIMEOUT} seconds ({TRIAL_TIMEOUT/3600:.1f} hours)')
  trial_logger.info('⏰ Note: signal-based timeout disabled (running in ThreadPool, not main thread)')
  
  try:
    # Use the LangGraph-based agent system
    trial_logger.info('Using LangGraph-based agent workflow')
    
    args.work_dirs = work_dirs
    
    # Create and run the LangGraph workflow
    trial_logger.info('🔧 Creating FuzzingWorkflow instance...')
    workflow = FuzzingWorkflow(model_name, args, shared_data=shared_data)
    trial_logger.info('✅ FuzzingWorkflow instance created')
    
    # Run the full supervisor-based workflow
    trial_logger.info('🚀 Starting workflow.run()...')
    trial_logger.info(f'   Benchmark: {benchmark.id}')
    trial_logger.info(f'   Trial: {trial}')
    trial_logger.info(f'   Workflow type: full')
    if shared_data:
      trial_logger.info(f'   Using shared data: YES (timestamp {shared_data.get("timestamp", "?")})')
    else:
      trial_logger.info(f'   Using shared data: NO (will query FI)')
    
    import time
    workflow_start_time = time.time()
    
    try:
      final_state = workflow.run(
          benchmark=benchmark,
          trial=trial,
      )
      workflow_end_time = time.time()
      workflow_duration = workflow_end_time - workflow_start_time
      trial_logger.info(f'✅ workflow.run() completed in {workflow_duration:.2f} seconds')
    except Exception as e:
      workflow_end_time = time.time()
      workflow_duration = workflow_end_time - workflow_start_time
      trial_logger.error(f'❌ workflow.run() failed after {workflow_duration:.2f} seconds: {e}')
      raise
    
    trial_logger.info('🔄 Converting state to result_history...')
    from src.workflow.adapters import StateAdapter

    result_history = StateAdapter.state_to_result_history(final_state)
    trial_logger.info(f'✅ Converted to result_history ({len(result_history)} results)')
    
    trial_logger.info('🎉 LangGraph workflow completed successfully')
    
    # Get the best result for saving files
    # The last result should be the most complete one (RunResult or AnalysisResult)
    trial_logger.info('📍 Getting best result from result_history...')
    best_result = result_history[-1] if result_history else None
    trial_logger.info(f'📍 Best result: {type(best_result).__name__ if best_result else "None"}')
    
    # Save fuzz target and build script to disk (matching WritingStage behavior)
    if best_result and best_result.fuzz_target_source:
      trial_logger.info('📍 Writing fuzz target to disk...')
      write_start = time.time()
      trial_logger.write_fuzz_target(best_result)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Fuzz target written in {write_duration:.3f}s to {work_dirs.fuzz_targets}')
    else:
      trial_logger.info('📍 No fuzz target to write')
      
    if best_result and best_result.build_script_source:
      trial_logger.info('📍 Writing build script to disk...')
      write_start = time.time()
      trial_logger.write_build_script(best_result)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Build script written in {write_duration:.3f}s to {work_dirs.fuzz_targets}')
    else:
      trial_logger.info('📍 No build script to write')
    
    # Convert agent_messages to chat_history format
    trial_logger.info('📍 Converting agent_messages to chat_history...')
    if best_result and 'agent_messages' in final_state:
      chat_history = {}
      for agent_name, messages in final_state['agent_messages'].items():
        # Convert message list to string format
        history_str = '\n'.join([
            f"{msg.get('role', 'unknown').upper()}: {msg.get('content', '')}"
            for msg in messages
        ])
        chat_history[agent_name] = history_str
      best_result.chat_history = chat_history
      trial_logger.info(f'📍 Converted {len(chat_history)} agent message histories')
    else:
      trial_logger.info('📍 No agent_messages to convert')
    
    # Save chat history
    if best_result and best_result.chat_history:
      trial_logger.info('📍 Writing chat history to disk...')
      write_start = time.time()
      trial_logger.write_chat_history(best_result, cycle_count=0)
      write_duration = time.time() - write_start
      trial_logger.info(f'📍 Chat history written in {write_duration:.3f}s to {work_dirs.status}')
    else:
      trial_logger.info('📍 No chat history to write')
    
    # Save token usage to best_result
    if best_result and 'token_usage' in final_state:
      trial_logger.info('📍 Saving token usage to best_result...')
      best_result.token_usage = final_state['token_usage']
      trial_logger.info('📍 Token usage saved')
    
    # Create trial result to match expected return format
    trial_logger.info('📍 Creating TrialResult...')
    trial_result = TrialResult(benchmark=benchmark,
                               trial=trial,
                               work_dirs=work_dirs,
                               result_history=result_history)
    trial_logger.info('📍 TrialResult created')
    
    trial_logger.info('📍 Writing trial result to disk...')
    write_start = time.time()
    trial_logger.write_result(
        result_status_dir=trial_result.best_result.work_dirs.status,
        result=trial_result,
        finished=True)
    write_duration = time.time() - write_start
    trial_logger.info(f'📍 Trial result written in {write_duration:.3f}s')

    # Dump build-attempt telemetry alongside the trial result.
    # See state.py:build_attempts — used to derive per-error-class fixer
    # success curves so retry budgets can be calibrated from data instead
    # of priors. Failure here is non-fatal.
    #
    # We dump even when `attempts` is empty so missing-telemetry trials
    # are visible (vs. "trial never reached the dump path"). The
    # aggregator can then distinguish "no build attempts captured"
    # from "no trial at all" and surface the gap.
    try:
        attempts = (final_state.get("build_attempts", [])
                    if final_state else [])
        import json as _json
        status_dir = trial_result.best_result.work_dirs.status
        attempts_path = os.path.join(
            status_dir, f'{trial:02d}', 'build_attempts.json')
        os.makedirs(os.path.dirname(attempts_path), exist_ok=True)
        with open(attempts_path, 'w') as f:
            _json.dump(
                {
                    "trial": trial,
                    "attempts": attempts,
                    "final_outcome": (
                        "compile_succeeded"
                        if any(a.get("compile_success") for a in attempts)
                        else ("compile_failed" if attempts
                              else "no_build_attempts_recorded")),
                },
                f, indent=2)
        trial_logger.info(
            f'📊 build_attempts telemetry written: {len(attempts)} record(s) '
            f'→ {attempts_path}')
    except Exception as _telem_exc:
        trial_logger.debug(
            f'build_attempts telemetry dump skipped: {_telem_exc}')

    trial_logger.info('✅ _fuzzing_pipeline completed, returning trial_result')
    return trial_result
    
  except TimeoutError as e:
    trial_logger.error(f'⏰ Trial timed out: {e}')
    trial_logger.error('⏰ Returning empty result due to timeout')
    # Return a minimal failed result
    return TrialResult(
        benchmark=benchmark,
        trial=trial,
        work_dirs=work_dirs,
        result_history=[]
    )
  finally:
    # Note: signal.alarm(0) removed because we disabled signal-based timeout
    trial_logger.info('⏰ Trial cleanup complete')

def _fuzzing_pipelines(benchmark: Benchmark, model_name: str,
                       args: argparse.Namespace,
                       work_dirs: WorkDirs) -> BenchmarkResult:
  """Runs all trial experiments in their pipelines."""
  import time
  
  # Use trial=0 for global/non-trial-specific logs
  logger.info(f'📍 [_fuzzing_pipelines] Starting with {args.num_samples} trial(s)', trial=0)
  logger.info(f'📍 [_fuzzing_pipelines] ThreadPool size: {NUM_EVA}', trial=0)
  
  # ============================================================
  # OPTIMIZATION: Pre-fetch shared data (only once for all trials)
  # ============================================================
  logger.info('📍 [_fuzzing_pipelines] Pre-fetching shared data...', trial=0)
  shared_data_start = time.time()
  
  try:
    shared_data = _prepare_shared_data_for_benchmark(benchmark, args, model_name)
  except ValueError as e:
    # Data preparation failed due to bad input - this is terminal
    logger.error(
      f'❌ Cannot prepare fuzzing context: {e}\n'
      f'This is a DATA problem. Check your benchmark configuration.',
      trial=0
    )
    # Return empty result - no trials can proceed without data
    return BenchmarkResult(
      benchmark=benchmark,
      work_dirs=work_dirs,
      trial_results=[]
    )
  except RuntimeError as e:
    # Infrastructure failure - also terminal
    logger.error(
      f'❌ Infrastructure failure during data preparation: {e}\n'
      f'Check Clang/LLVM extractor availability and the cloud FI coverage endpoint.',
      trial=0
    )
    return BenchmarkResult(
      benchmark=benchmark,
      work_dirs=work_dirs,
      trial_results=[]
    )
  
  shared_data_duration = time.time() - shared_data_start

  # Resolve --num-samples=auto. Until viability analysis runs (L0–L5 + L4
  # greedy max-coverage), we cannot know how many sequences survive — so
  # there's no honest CLI default. Default to "one trial per Z3-validated
  # skeleton" so every survivor gets at least one LLM pass. Falls back to
  # 1 when the synthesis pool is empty (still better than crashing on
  # ``range(1, None+1)``).
  #
  # NOTE: the local variable inside ``_synthesize_skeletons_per_sequence``
  # is called ``synthesized_drivers``, but the value is stored on
  # ``FuzzingContext`` / ``shared_data`` under the key ``skeleton_drivers``
  # (see ``src/context/data_context.py`` lines 65, 1222). Reading the
  # wrong key here used to silently cap every project at a single trial.
  if args.num_samples is None:
    n_skeletons = len(shared_data.get('skeleton_drivers', []) or [])
    args.num_samples = n_skeletons if n_skeletons > 0 else 1
    logger.info(
        f'📍 [_fuzzing_pipelines] --num-samples auto-resolved to '
        f'{args.num_samples} (= len(skeleton_drivers), one trial per '
        f'Z3-validated skeleton)',
        trial=0)

  logger.info(
      f'📍 [_fuzzing_pipelines] Shared data prepared in {shared_data_duration:.2f}s '
      f'(will be reused by all {args.num_samples} trials)',
      trial=0
  )
  
  # Create a pool of worker processes
  logger.info('📍 [_fuzzing_pipelines] Creating ThreadPool...', trial=0)
  pool_start = time.time()
  
  with pool.ThreadPool(processes=NUM_EVA) as p:
    pool_create_duration = time.time() - pool_start
    logger.info(f'📍 [_fuzzing_pipelines] ThreadPool created in {pool_create_duration:.2f}s', trial=0)
    
    # Initialize thread-local storage in each worker before processing
    # IMPORTANT: Pass shared_data to each trial
    task_args = [(benchmark, model_name, args, work_dirs, trial, shared_data)
                 for trial in range(1, args.num_samples + 1)]
    logger.info(f'📍 [_fuzzing_pipelines] Starting {len(task_args)} trial(s) via starmap...', trial=0)
    
    starmap_start = time.time()
    trial_results = p.starmap(_fuzzing_pipeline, task_args)
    starmap_duration = time.time() - starmap_start
    logger.info(f'📍 [_fuzzing_pipelines] All trials completed in {starmap_duration:.2f}s', trial=0)
    
    # Calculate efficiency metrics
    if args.num_samples > 1:
      time_saved = shared_data_duration * (args.num_samples - 1)
      logger.info(
          f'📊 [_fuzzing_pipelines] Shared data optimization: '
          f'saved ~{time_saved:.1f}s by avoiding {args.num_samples - 1} redundant queries',
          trial=0
      )
    
    logger.info('📍 [_fuzzing_pipelines] Exiting ThreadPool context (will wait for cleanup)...', trial=0)

  cleanup_duration = time.time() - starmap_start - starmap_duration
  logger.info(f'📍 [_fuzzing_pipelines] ThreadPool cleanup completed in {cleanup_duration:.2f}s', trial=0)

  # Optional: merge successful trials into a single multi-task harness
  # (--merge-drivers flag in run_logicfuzz; design rationale in
  # docs/contributions_and_related_work.md §3 "Harness merge").
  merged_path: Optional[str] = None
  if getattr(args, 'merge_drivers', False):
    merged_path = _maybe_merge_drivers(benchmark, work_dirs, trial_results)

  # Phase C foundation — persist a post-merge IterationSnapshot. The
  # snapshot is the evaluation unit Phase D Planner / Phase E Adaptive
  # Shape will read from. Failing softly (best-effort telemetry; no
  # workflow blocking).
  try:
    _persist_phase_c_snapshot(
        benchmark=benchmark,
        trial_results=trial_results,
        merged_path=merged_path,
    )
  except Exception as exc:
    logger.warning(
        f"Phase C snapshot persist failed (non-critical): {exc}",
        trial=0)

  logger.info('📍 [_fuzzing_pipelines] Creating BenchmarkResult...', trial=0)
  result = BenchmarkResult(benchmark=benchmark,
                          work_dirs=work_dirs,
                          trial_results=trial_results)
  logger.info('📍 [_fuzzing_pipelines] BenchmarkResult created, returning', trial=0)
  return result


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


def _resolve_candidate_binary(src, work_dirs):
  """Best-effort: find a host-runnable libFuzzer binary for a driver source.

  Per-trial OSS-Fuzz binaries are built in Docker and cleaned up, so this
  returns one only when the eval preserved a host-runnable build under
  ``<base>/preflight_bins/<NN>`` (the preservation hook). Returns None when no
  runnable binary exists — preflight then can't vet this driver (it is kept,
  not dropped).
  """
  from pathlib import Path
  stem = src.stem  # e.g. "06" from "06.fuzz_target"
  base = Path(work_dirs.base) / 'preflight_bins'
  for cand in (base / stem, base / f'{stem}.bin', base / f'{stem}_fuzzer'):
    if cand.is_file():
      return cand
  return None


def _preflight_filter_candidates(sources, work_dirs):
  """Smoke-test candidate drivers and drop crash / no-progress ones.

  Returns the surviving source paths. Drops a driver ONLY on a crash or
  zero-edge verdict from a runnable binary; a driver whose binary can't be
  resolved/run is kept (couldn't vet ≠ reject). If fewer than 2 binaries are
  resolvable, preflight is skipped entirely and all sources are returned
  unchanged (logged), preserving prior behaviour.
  """
  from pathlib import Path
  pairs = []
  for src in sources:
    b = _resolve_candidate_binary(src, work_dirs)
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

  results = preflight(pairs, smoke_duration_sec=15, drop_on_crash=True)
  try:
    write_report(results, Path(work_dirs.base) / 'merged' / 'preflight.json')
  except Exception:
    pass
  # Drop ONLY genuine crash / no-progress; keep "couldn't vet" (binary missing
  # or broken-to-run, which is infra, not a driver defect).
  # NB: preflight emits ``dead_on_empty (...)`` for a crash-on-empty (see
  # preflight.py:219) — matching ``crash_on_empty`` here was dead code, so
  # crashing drivers were never dropped and poisoned the merged harness.
  rejected = {r.driver_path for r in results
              if not r.accepted
              and r.rejection_reason.startswith(('dead_on_empty', 'no_progress'))}
  if rejected:
    logger.info(
        f'merge_drivers: preflight dropped {len(rejected)} crashing/'
        f'no-progress driver(s): '
        f'{sorted(Path(p).name for p in rejected)}', trial=0)
  return [s for s in sources if str(s) not in rejected]


def _compile_validate_candidates(sources, benchmark, work_dirs):
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
  """
  from pathlib import Path
  if os.environ.get('LOGICFUZZ_SKIP_COMPILE_VALIDATE'):
    logger.info('merge_drivers: compile-validation skipped '
                '(LOGICFUZZ_SKIP_COMPILE_VALIDATE set)', trial=0)
    return sources
  project = getattr(benchmark, 'project', None)
  if not project:
    logger.warning('merge_drivers: no benchmark.project; skipping '
                   'compile-validation (merging unvetted)', trial=0)
    return sources
  try:
    from tools.merge_drivers.compile_validate import validate_compilable
  except ImportError as exc:
    logger.warning(f'merge_drivers: compile-validation unavailable ({exc}); '
                   f'merging unvetted', trial=0)
    return sources

  valid, excluded = validate_compilable([Path(s) for s in sources], project)
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
    try:
      import json
      rep = {'project': project,
             'valid': sorted(Path(s).name for s in valid),
             'excluded': [{'driver': Path(s).name,
                           'reason': (r or '').strip()[:1000]}
                          for s, r in excluded]}
      rep_dir = Path(work_dirs.base) / 'merged'
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


def _maybe_merge_drivers(benchmark: Benchmark,
                         work_dirs: WorkDirs,
                         trial_results: List) -> Optional[str]:
  """Synthesize a multi-task harness from successful trials.

  Minimum-viable integration of tools.merge_drivers (--merge-drivers /
  --eval). Output: ``<work_dirs.base>/merged/`` with:
    - synthesized/entry.{c,cpp}    dispatcher
    - synthesized/<id>.{c,cpp}     renamed sub-driver i
    - oss_fuzz_build_snippet.sh    append to OSS-Fuzz project build.sh

  **Preflight is now wired** (``_preflight_filter_candidates``): candidates are
  smoke-fuzzed and crashing / no-progress drivers are dropped BEFORE merge, so
  one bad auto-driver can't poison the fused campaign (the failure that
  motivated this). It activates when host-runnable binaries are resolvable
  under ``<base>/preflight_bins/`` (preservation hook); per-trial OSS-Fuzz
  binaries are still cleaned up, so when none are resolvable preflight logs the
  gap and proceeds with the unvetted set rather than blocking the merge. A
  driver is dropped only on a real crash/no-progress verdict, never for a
  missing/unrunnable binary.

  Still skipped vs the standalone `pipeline` subcommand:
    - **coverage-aware Top-K selection**: needs binaries
      to gather per-driver edge counts. Without it we use uniform
      dispatch (PromeFuzz §5.2 fallback when coverage signal is
      unavailable). Future enhancement: read from per-driver coverage
      reports under work_dirs.code_coverage_report (the run_target_local
      path produces these and they survive cleanup).

  Returns the output directory on success, None if there were fewer
  than 2 successful trials (nothing meaningful to merge).
  """
  from pathlib import Path
  successful_sources: List[Path] = []
  quarantined = 0
  for tr in trial_results:
    if not tr or not getattr(tr, 'best_result', None):
      continue
    br = tr.best_result
    if not getattr(br, 'compiles', False):
      continue
    # Pre-ship quarantine (binary-free, complements preflight). A driver that
    # crashed in-container with ~0 coverage is an immediate-SEGV false positive
    # (unchecked creator return / garbage opaque arg — the class density can add
    # on handle-ful drivers). In the single-process fused harness it crashes
    # before any sub-driver runs → poisons the whole campaign, and it
    # contributes no coverage anyway. A crasher that made real progress (cov>0)
    # is a normal fuzz target (-ignore_crashes=1 carries it) — keep it.
    # BUT never drop a crash the triage CONFIRMED feasible (a real library bug
    # can abort at 0 coverage): gate the quarantine on the crash verdict so the
    # low-FP classifier's "real bug" decision is honored, not just coverage.
    if _is_immediate_crash_fp(br) and not _trial_confirms_real_bug(tr):
      quarantined += 1
      logger.info(
          f'merge: quarantined trial {tr.trial:02d} (immediate-crash FP, '
          f'cov_pcs=0) — would poison the fused harness', trial=0)
      continue
    src = Path(work_dirs.fuzz_targets) / f'{tr.trial:02d}.fuzz_target'
    if src.exists():
      successful_sources.append(src)
  if quarantined:
    logger.info(f'merge: pre-ship quarantine dropped {quarantined} '
                f'immediate-crash FP driver(s)', trial=0)

  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'successful trial(s); need ≥2 to merge)', trial=0)
    return None

  # === Preflight (O1): vet candidates before merging ===
  # A merged harness runs all sub-drivers in ONE process, so a single
  # crashing/zero-progress driver poisons the whole fused campaign (observed:
  # an auto-driver that passed NULL to a consumer aborted the union). We smoke
  # each candidate and drop the bad ones first. Preflight needs *host-runnable*
  # libFuzzer binaries (tools.merge_drivers.preflight runs them as
  # subprocesses); the per-trial OSS-Fuzz binaries are built in Docker and
  # cleaned up, so they're only available when the eval kept a host-runnable
  # build (resolver below). When none are resolvable we DON'T silently merge
  # everything blind — we log the gap and proceed with the unvetted set
  # (preserving prior behaviour), and a crash will surface in the merged run.
  # Only crash / no-progress verdicts drop a driver; a missing/unrunnable
  # binary is treated as "couldn't vet", never as a reason to drop.
  successful_sources = _preflight_filter_candidates(successful_sources, work_dirs)
  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'candidate(s) survived preflight; need ≥2 to merge)', trial=0)
    return None

  # === Compile-validation: keep the MERGED harness VALID ===
  # First principle: the merge must ship only sub-drivers that COMPILE under the
  # real OSS-Fuzz build flags. Preflight (above) only drops crash/no-progress —
  # and only for drivers that HAD a host-runnable binary; a COMPILE-INVALID
  # driver never built one, so "couldn't vet" kept it. Those invalid TUs then
  # get ``|| continue``-skipped in the merged build and weak-stubbed into silent
  # no-op slots — the portfolio loses them and coverage replay reads 0 on them
  # (the address-build vs coverage-build divergence). We compile each candidate
  # in the project's OSS-Fuzz container under the COVERAGE-build flags
  # (-fsyntax-only, one container) and EXCLUDE every TU that fails, so both the
  # address build and the coverage build compile the identical valid set. The
  # ``|| continue`` + weak stub stay as a now-rarely-firing SAFETY NET.
  successful_sources = _compile_validate_candidates(
      successful_sources, benchmark, work_dirs)
  if len(successful_sources) < 2:
    logger.info(
        f'merge_drivers: skipping (only {len(successful_sources)} '
        f'candidate(s) survived compile-validation; need ≥2 to merge)',
        trial=0)
    return None

  try:
    # Import lazily so a missing tools.merge_drivers package doesn't
    # break the main run; the flag is opt-in and a clean error is
    # better than a hard import failure at module-load.
    from tools.merge_drivers.merge import (
        DispatchMode, SelectorPosition, SynthesizedDriver)
  except ImportError as exc:
    logger.warning(
        f'merge_drivers: tools.merge_drivers unavailable ({exc}); '
        f'skipping', trial=0)
    return None

  try:
    drv = SynthesizedDriver.from_paths(
        successful_sources,
        mode=DispatchMode.UNIFORM,
        position=SelectorPosition.TAIL,
        weights=None,
    )
    out_dir = Path(work_dirs.base) / 'merged'
    out_dir.mkdir(parents=True, exist_ok=True)
    drv.save(out_dir)
    snippet_path = out_dir / 'oss_fuzz_build_snippet.sh'
    snippet_path.write_text(drv.emit_oss_fuzz_build_snippet(
        target_name='merged_fuzzer'))
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


def _persist_phase_c_snapshot(
    benchmark: Benchmark,
    trial_results: List,
    merged_path: Optional[str],
) -> None:
  """Phase C foundation — write an ``IterationSnapshot`` to
  ``results/<project>/state/coverage_memory.json`` summarising this
  run's trials, the merge outcome, and the ratio-to-baseline derived
  from OSS-Fuzz's published coverage.

  Single-iteration snapshots are the current MVP; appending across
  iterations is what the future CEGAR loop driver will do. Phase D
  Planner / Phase E Adaptive Shape consume the latest snapshot for
  candidate-plan decisions.

  Best-effort: failures here become a warning, never block the run.
  """
  from pathlib import Path
  from src.state.coverage_memory import (
      harvest_trial_outcomes,
      load_baseline_line_counts,
      make_snapshot,
      persist_snapshot,
  )

  project = getattr(benchmark, 'project', None) or 'unknown'
  state_dir = Path('results') / project / 'state'

  outcomes = harvest_trial_outcomes(trial_results)
  # T12: attach the hole values captured by the prototyper (side files) so the
  # snapshot records which leaf values reached coverage — read back next run via
  # coverage_memory.attach_proven_holes. Gated; best-effort.
  if os.environ.get('LOGICFUZZ_VALUE_FEEDBACK'):
    from src.state.coverage_memory import load_trial_hole_values
    for _o in outcomes:
      _hv = load_trial_hole_values(project, _o.trial_id, state_dir=state_dir)
      if _hv:
        _o.skeleton_name = _hv.get('skeleton_name')
        _o.skeleton_key = _hv.get('skeleton_key')
        _o.hole_values = _hv.get('hole_values') or {}
  baseline = load_baseline_line_counts(project, log=logger)

  merged_count = 0
  if merged_path:
    merged_dir = Path(merged_path) / 'synthesized'
    if merged_dir.exists():
      merged_count = len([p for p in merged_dir.iterdir()
                         if p.is_file() and p.name != 'entry.c'
                         and p.name != 'entry.cpp'])

  snap = make_snapshot(
      iteration_idx=0,  # MVP: single-iter; CEGAR loop will bump this
      trial_results=outcomes,
      merged_driver_path=merged_path,
      merged_driver_count=merged_count,
      baseline_line_count=(baseline['total'] if baseline else None),
      baseline_covered_lines=(baseline['covered'] if baseline else None),
  )
  persist_snapshot(project, snap, state_dir=state_dir)


def run(benchmark: Benchmark, model_name: str, args: argparse.Namespace,
        work_dirs: WorkDirs) -> Optional[AggregatedResult]:
  """Generates code via LLM, and evaluates them."""
  # Note: cloud_setup() removed - LangChain handles initialization internally

  # Save the benchmark in the WorkDir base. This is saved to the working
  # directory, and should not be deleted in future executions. As such,
  # from here on, do not erase all WorkDir contents.
  Benchmark.to_yaml([benchmark],
                    outdir=work_dirs.base,
                    out_basename='benchmark.yaml')

  return AggregatedResult.from_benchmark_result(
      _fuzzing_pipelines(benchmark, model_name, args, work_dirs))
