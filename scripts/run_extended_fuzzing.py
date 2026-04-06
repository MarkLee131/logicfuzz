#!/usr/bin/env python3
"""
Extended fuzzing script for evaluating generated fuzz drivers.

This script runs a generated fuzz driver for extended periods and collects
metrics like coverage, crashes, and corpus growth.

Usage:
    python scripts/run_extended_fuzzing.py \
        --project cjson \
        --fuzz-target results/output-cjson-project/fuzz_targets/01.fuzz_target \
        --duration 3600 \
        --output-dir results/extended_fuzzing/cjson

Features:
    - Long-duration fuzzing (hours/days)
    - Periodic coverage snapshots with actual coverage measurement
    - Coverage diff tracking between snapshots
    - Crash collection with metadata
    - Corpus statistics
    - Comparison with baseline (existing OSS-Fuzz driver)
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from experiment import oss_fuzz_checkout

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CrashInfo:
    """Information about a crash."""
    crash_file: str
    crash_hash: str
    timestamp: float
    crash_type: str  # e.g., "heap-buffer-overflow", "null-deref"
    stack_trace: str
    input_size: int
    reproducer_path: str


@dataclass
class CoverageData:
    """Coverage data at a point in time."""
    line_coverage_percent: float
    branch_coverage_percent: float
    function_coverage_percent: float
    lines_covered: int
    lines_total: int
    branches_covered: int
    branches_total: int
    functions_covered: int
    functions_total: int
    edge_coverage: int  # From libFuzzer


@dataclass
class FuzzingSnapshot:
    """Snapshot of fuzzing state at a point in time."""
    timestamp: float
    elapsed_seconds: int
    corpus_size: int
    total_executions: int
    exec_per_sec: float
    coverage: CoverageData
    coverage_diff_from_prev: float  # Line coverage diff from previous snapshot
    coverage_diff_from_start: float  # Line coverage diff from start
    crashes_found: int
    new_crashes_this_interval: int
    timeouts_found: int
    ooms_found: int
    log_snapshot_path: str  # Path to log snapshot for this interval


@dataclass
class ExtendedFuzzingResult:
    """Results from extended fuzzing run."""
    project: str
    fuzz_target_path: str
    duration_seconds: int
    start_time: str
    end_time: str

    # Final coverage
    final_coverage: Optional[CoverageData] = None
    final_corpus_size: int = 0

    # Coverage progression
    initial_coverage_percent: float = 0.0
    final_coverage_percent: float = 0.0
    total_coverage_gain: float = 0.0

    # Crashes
    total_crashes: int = 0
    unique_crashes: int = 0
    crash_infos: List[CrashInfo] = field(default_factory=list)

    # Snapshots for time-series analysis
    snapshots: List[FuzzingSnapshot] = field(default_factory=list)

    # Paths
    corpus_dir: str = ''
    crashes_dir: str = ''
    coverage_report_dir: str = ''

    error: Optional[str] = None


class ExtendedFuzzer:
    """Run fuzz driver for extended periods and collect metrics."""

    def __init__(
        self,
        project: str,
        fuzz_target_path: str,
        output_dir: str,
        duration: int = 3600,
        snapshot_interval: int = 300,
        sanitizer: str = "address",
        fuzzer_name: Optional[str] = None,
        skip_build: bool = False,
        use_existing_build_dir: Optional[str] = None
    ):
        self.project = project
        self.fuzz_target_path = Path(fuzz_target_path)
        self.output_dir = Path(output_dir)
        self.duration = duration
        self.snapshot_interval = snapshot_interval
        self.sanitizer = sanitizer
        self.fuzzer_name = fuzzer_name
        self.skip_build = skip_build
        self.use_existing_build_dir = use_existing_build_dir

        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir = self.output_dir / "corpus"
        self.crashes_dir = self.output_dir / "crashes"
        self.logs_dir = self.output_dir / "logs"
        self.snapshots_dir = self.output_dir / "snapshots"
        self.coverage_dir = self.output_dir / "coverage"

        for d in [self.corpus_dir, self.crashes_dir, self.logs_dir,
                  self.snapshots_dir, self.coverage_dir]:
            d.mkdir(exist_ok=True)

        # Create seed corpus if empty (LibFuzzer needs at least one input)
        self._ensure_seed_corpus()

        self.snapshots: List[FuzzingSnapshot] = []
        self.crash_infos: List[CrashInfo] = []
        self.seen_crash_hashes: set = set()
        self.container_name = f"extended_fuzz_{project}_{int(time.time())}"
        self.generated_project_name = None
        self.initial_coverage: Optional[CoverageData] = None
        self.prev_coverage: Optional[CoverageData] = None
        self._fuzzer_log_handle = None

    def _ensure_seed_corpus(self):
        """Ensure corpus has at least one seed file for LibFuzzer to start."""
        corpus_files = list(self.corpus_dir.glob("*"))
        if not corpus_files:
            # Create minimal seed inputs for common fuzzing scenarios
            seeds = [
                b"",                    # Empty input
                b"{}",                  # Empty JSON object
                b"[]",                  # Empty JSON array
                b'{"a":1}',             # Simple JSON
                b"null",                # JSON null
                b'"test"',              # JSON string
                b"123",                 # JSON number
                b"true",                # JSON boolean
            ]
            for i, seed in enumerate(seeds):
                seed_file = self.corpus_dir / f"seed_{i:03d}"
                with open(seed_file, 'wb') as f:
                    f.write(seed)
            logger.info(f"Created {len(seeds)} seed corpus files in {self.corpus_dir}")

    def _read_fuzz_target(self) -> str:
        """Read fuzz target source code."""
        with open(self.fuzz_target_path, 'r') as f:
            return f.read()

    def _get_oss_fuzz_dir(self) -> Path:
        """Get OSS-Fuzz directory."""
        # Try to use existing OSS-Fuzz checkout
        oss_fuzz_dir = Path(PROJECT_ROOT) / "oss-fuzz"
        if oss_fuzz_dir.exists():
            return oss_fuzz_dir

        # Fallback to global temp dir
        if oss_fuzz_checkout.GLOBAL_TEMP_DIR:
            return Path(oss_fuzz_checkout.GLOBAL_TEMP_DIR)

        # Clone if needed
        oss_fuzz_checkout.clone_oss_fuzz()
        return Path(oss_fuzz_checkout.OSS_FUZZ_DIR)

    def _setup_oss_fuzz_project(self) -> bool:
        """Setup OSS-Fuzz project with our fuzz target."""
        logger.info(f"Setting up OSS-Fuzz project for {self.project}...")

        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()

            # Create a unique project name for this run
            timestamp = int(time.time())
            self.generated_project_name = f"{self.project}-ext-{timestamp}"

            # Copy the original project
            src_project = oss_fuzz_dir / "projects" / self.project
            dst_project = oss_fuzz_dir / "projects" / self.generated_project_name

            if not src_project.exists():
                logger.error(f"Project {self.project} not found in OSS-Fuzz")
                return False

            shutil.copytree(src_project, dst_project)

            # Copy our fuzz target to the project
            target_basename = self.fuzz_target_path.name
            shutil.copy(self.fuzz_target_path, dst_project / target_basename)

            # Determine the target name in the build
            if self.fuzzer_name:
                target_name = self.fuzzer_name
            else:
                # Try to infer from the file
                target_name = self.fuzz_target_path.stem
                # Handle files like "01.fuzz_target" or "02.fuzz_target"
                # stem gives "01" or "02", which are not good fuzzer names
                if target_name.isdigit() or target_name in ('01', '02', '03', '04', '05'):
                    target_name = f"{self.project}_fuzzer"
                elif target_name.startswith(('01.', '02.', '03.')):
                    target_name = f"{self.project}_fuzzer"

            self.target_name = target_name
            logger.info(f"Using target name: {self.target_name}")

            # Update Dockerfile to copy our target
            dockerfile = dst_project / "Dockerfile"
            with open(dockerfile, 'a') as f:
                f.write(f'\nCOPY {target_basename} /src/{target_basename}\n')

            # Modify build.sh to include our target
            # This ensures our fuzz target gets compiled
            build_sh = dst_project / "build.sh"
            if build_sh.exists():
                with open(build_sh, 'r') as f:
                    build_content = f.read()

                # Add compilation for our target at the end
                target_ext = self.fuzz_target_path.suffix
                if target_ext in ['.c', '.cc', '.cpp', '.cxx']:
                    compile_cmd = f'''
# Compile extended fuzzing target
$CXX $CXXFLAGS -c /src/{target_basename} -o /tmp/ext_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE /tmp/ext_fuzzer.o -o $OUT/{self.target_name} ${{LDFLAGS:-}}
'''
                    # Try to find library link flags from existing build.sh
                    # Look for patterns like -lcjson, -lz, etc.
                    import re
                    lib_matches = re.findall(r'-l\w+', build_content)
                    if lib_matches:
                        libs = ' '.join(set(lib_matches))
                        compile_cmd = compile_cmd.replace('${LDFLAGS:-}', f'${{LDFLAGS:-}} {libs}')

                    with open(build_sh, 'a') as f:
                        f.write(compile_cmd)

            logger.info(f"Created project {self.generated_project_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to setup project: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def _build_docker_image(self) -> bool:
        """Build OSS-Fuzz project image."""
        logger.info(f"Building Docker image for {self.generated_project_name}...")

        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()
            helper_py = oss_fuzz_dir / "infra" / "helper.py"

            # Check if base image already exists (from previous logicfuzz runs)
            # This can save significant build time
            base_image_name = f"gcr.io/oss-fuzz/{self.project}"
            check_cmd = ["docker", "images", "-q", base_image_name]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True)
            has_cached_image = bool(check_result.stdout.strip())

            # Always build the project image to include our custom Dockerfile changes
            # (COPY of our fuzz target). Even with a cached base image, we need to rebuild
            # to pick up the modified Dockerfile.
            if has_cached_image:
                logger.info(f"Found cached base image for {self.project}, rebuilding with custom fuzz target...")
            else:
                logger.info(f"No cached image found, building from scratch (this may take 15-30 minutes)...")

            # Build the project image (required to pick up Dockerfile changes with our fuzz target)
            # Use --no-pull to avoid interactive prompt in non-interactive mode
            build_cmd = [
                "python3", str(helper_py),
                "build_image", "--no-pull", self.generated_project_name
            ]
            logger.info(f"Running: {' '.join(build_cmd)}")
            # Increase timeout for full image build (30 minutes)
            result = subprocess.run(build_cmd, capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                logger.error(f"Failed to build image: {result.stderr[:1000]}")
                return False

            # Build fuzzers with the specified sanitizer
            build_fuzzers_cmd = [
                "python3", str(helper_py),
                "build_fuzzers", "--sanitizer", self.sanitizer,
                self.generated_project_name
            ]
            logger.info(f"Running: {' '.join(build_fuzzers_cmd)}")
            # Increase timeout for fuzzer build (20 minutes)
            result = subprocess.run(build_fuzzers_cmd, capture_output=True, text=True, timeout=1200)
            if result.returncode != 0:
                logger.error(f"Failed to build fuzzers: {result.stderr[:1000]}")
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.error("Build timed out (try running with cached images or increase timeout)")
            return False
        except Exception as e:
            logger.error(f"Build failed: {e}")
            return False

    def _build_coverage_image(self) -> bool:
        """Build with coverage sanitizer for coverage measurement."""
        logger.info(f"Building coverage image for {self.generated_project_name}...")

        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()
            helper_py = oss_fuzz_dir / "infra" / "helper.py"

            build_fuzzers_cmd = [
                "python3", str(helper_py),
                "build_fuzzers", "--sanitizer", "coverage",
                self.generated_project_name
            ]
            # Increase timeout for coverage build (20 minutes)
            result = subprocess.run(build_fuzzers_cmd, capture_output=True, text=True, timeout=1200)
            if result.returncode != 0:
                logger.warning(f"Failed to build coverage image: {result.stderr[:500]}")
                return False

            return True
        except subprocess.TimeoutExpired:
            logger.warning("Coverage build timed out")
            return False
        except Exception as e:
            logger.warning(f"Coverage build failed: {e}")
            return False

    def _run_fuzzer(self) -> subprocess.Popen:
        """Start fuzzer process."""
        oss_fuzz_dir = self._get_oss_fuzz_dir()
        helper_py = oss_fuzz_dir / "infra" / "helper.py"

        # Use absolute paths for corpus and crash dirs
        corpus_dir_abs = str(self.corpus_dir.resolve())
        crashes_dir_abs = str(self.crashes_dir.resolve())

        run_cmd = [
            "python3", str(helper_py),
            "run_fuzzer",
            "--corpus-dir", corpus_dir_abs,
            self.generated_project_name,
            self.target_name,
            "--",
            f"-max_total_time={self.duration}",
            "-print_final_stats=1",
            "-detect_leaks=0",
            f"-artifact_prefix={crashes_dir_abs}/",
            # Continue fuzzing after crashes (standard practice for 24h evaluation)
            # -fork=1: Run in forked process, auto-restart on crash
            # -ignore_crashes=1: Save crash but continue fuzzing
            "-fork=1",
            "-ignore_crashes=1",
            "-ignore_timeouts=1",
            "-ignore_ooms=1",
        ]

        logger.info(f"Starting fuzzer: {' '.join(run_cmd)}")
        logger.info(f"Corpus directory: {corpus_dir_abs} (files: {len(list(self.corpus_dir.glob('*')))})")

        log_file = self.logs_dir / "fuzzer.log"
        log_file_handle = open(log_file, 'w')

        proc = subprocess.Popen(
            run_cmd,
            stdout=log_file_handle,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(oss_fuzz_dir)
        )

        # Store file handle for cleanup
        self._fuzzer_log_handle = log_file_handle

        # Give fuzzer time to start and check for immediate failure
        time.sleep(2)
        if proc.poll() is not None:
            # Fuzzer exited immediately, read log for error
            log_file_handle.flush()
            try:
                with open(log_file, 'r') as f:
                    error_log = f.read()
                logger.error(f"Fuzzer exited immediately with code {proc.returncode}")
                logger.error(f"Fuzzer log:\n{error_log[:2000]}")
            except Exception as e:
                logger.error(f"Could not read fuzzer log: {e}")

        return proc

    def _parse_fuzzer_stats(self, log_path: Path) -> Dict[str, Any]:
        """Parse fuzzer log for statistics."""
        stats = {
            'corpus_size': 0,
            'total_executions': 0,
            'exec_per_sec': 0.0,
            'edge_coverage': 0,
        }

        if not log_path.exists():
            return stats

        try:
            with open(log_path, 'r') as f:
                content = f.read()

            # Parse libFuzzer stats
            for line in content.split('\n'):
                if 'stat::number_of_executed_units:' in line:
                    stats['total_executions'] = int(line.split(':')[-1].strip())
                elif 'stat::average_exec_per_sec:' in line:
                    stats['exec_per_sec'] = float(line.split(':')[-1].strip())
                elif 'stat::new_units_added:' in line:
                    stats['corpus_size'] = int(line.split(':')[-1].strip())
                elif 'cov:' in line:
                    # Parse coverage from progress lines like "#1234 NEW cov: 567"
                    match = re.search(r'cov:\s*(\d+)', line)
                    if match:
                        stats['edge_coverage'] = max(
                            stats['edge_coverage'],
                            int(match.group(1))
                        )

        except Exception as e:
            logger.warning(f"Failed to parse stats: {e}")

        return stats

    def _measure_coverage(self) -> Optional[CoverageData]:
        """Measure actual code coverage using OSS-Fuzz coverage infrastructure."""
        logger.info("Measuring code coverage...")

        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()
            helper_py = oss_fuzz_dir / "infra" / "helper.py"

            # Use absolute path for corpus dir
            corpus_dir_abs = str(self.corpus_dir.resolve())

            # Check if corpus directory has files
            corpus_files = list(self.corpus_dir.glob("*"))
            if not corpus_files:
                logger.warning("Corpus directory is empty, skipping coverage measurement")
                return None

            # Run coverage measurement
            coverage_cmd = [
                "python3", str(helper_py),
                "coverage",
                "--corpus-dir", corpus_dir_abs,
                "--fuzz-target", self.target_name,
                "--no-serve",
                "--port", "",
                self.generated_project_name
            ]

            result = subprocess.run(
                coverage_cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(oss_fuzz_dir)
            )

            if result.returncode != 0:
                logger.warning(f"Coverage measurement failed: {result.stderr}")
                return None

            # Parse coverage from summary.json
            if not self.generated_project_name:
                logger.warning("No generated project name")
                return None
            build_out = oss_fuzz_dir / "build" / "out" / self.generated_project_name
            summary_file = build_out / "report" / "linux" / "summary.json"

            if not summary_file.exists():
                logger.warning(f"Coverage summary not found: {summary_file}")
                return None

            with open(summary_file) as f:
                summary = json.load(f)

            # Extract coverage data
            totals = summary.get('data', [{}])[0].get('totals', {})
            lines = totals.get('lines', {})
            branches = totals.get('branches', {})
            functions = totals.get('functions', {})

            coverage_data = CoverageData(
                line_coverage_percent=lines.get('percent', 0.0),
                branch_coverage_percent=branches.get('percent', 0.0),
                function_coverage_percent=functions.get('percent', 0.0),
                lines_covered=lines.get('covered', 0),
                lines_total=lines.get('count', 0),
                branches_covered=branches.get('covered', 0),
                branches_total=branches.get('count', 0),
                functions_covered=functions.get('covered', 0),
                functions_total=functions.get('count', 0),
                edge_coverage=0  # Will be filled from libFuzzer stats
            )

            # Copy coverage report to output dir
            coverage_report = build_out / "report"
            if coverage_report.exists():
                snapshot_coverage_dir = self.coverage_dir / f"snapshot_{len(self.snapshots):03d}"
                shutil.copytree(coverage_report, snapshot_coverage_dir, dirs_exist_ok=True)

            return coverage_data

        except Exception as e:
            logger.warning(f"Coverage measurement error: {e}")
            return None

    def _process_crashes(self) -> Tuple[int, int]:
        """Process crash files and extract metadata.

        Returns:
            Tuple of (total_crashes, new_crashes_this_interval)
        """
        crash_files = list(self.crashes_dir.glob("crash-*"))
        new_crashes = 0

        for crash_file in crash_files:
            # Calculate hash of crash input
            with open(crash_file, 'rb') as f:
                crash_data = f.read()
            crash_hash = hashlib.sha256(crash_data).hexdigest()[:16]

            if crash_hash in self.seen_crash_hashes:
                continue

            self.seen_crash_hashes.add(crash_hash)
            new_crashes += 1

            # Try to extract crash type from log
            crash_type = "unknown"
            stack_trace = ""

            log_file = self.logs_dir / "fuzzer.log"
            if log_file.exists():
                try:
                    with open(log_file, 'r') as f:
                        log_content = f.read()

                    # Look for crash type patterns
                    crash_patterns = [
                        (r'ERROR: AddressSanitizer: ([\w-]+)', 'asan'),
                        (r'ERROR: UndefinedBehaviorSanitizer: ([\w-]+)', 'ubsan'),
                        (r'ERROR: MemorySanitizer: ([\w-]+)', 'msan'),
                    ]

                    for pattern, _ in crash_patterns:
                        match = re.search(pattern, log_content)
                        if match:
                            crash_type = match.group(1)
                            break

                    # Extract stack trace (first 20 lines after ERROR)
                    stack_match = re.search(r'(ERROR:.*?(?:\n.*?){0,20})', log_content, re.DOTALL)
                    if stack_match:
                        stack_trace = stack_match.group(1)

                except Exception as e:
                    logger.warning(f"Failed to parse crash info: {e}")

            # Create crash info
            crash_info = CrashInfo(
                crash_file=str(crash_file),
                crash_hash=crash_hash,
                timestamp=time.time(),
                crash_type=crash_type,
                stack_trace=stack_trace[:2000],  # Limit size
                input_size=len(crash_data),
                reproducer_path=str(crash_file)
            )
            self.crash_infos.append(crash_info)

            # Save crash metadata
            metadata_file = crash_file.with_suffix('.json')
            with open(metadata_file, 'w') as f:
                json.dump(asdict(crash_info), f, indent=2)

            logger.info(f"New crash: {crash_hash} ({crash_type}, {len(crash_data)} bytes)")

        return len(crash_files), new_crashes

    def _save_log_snapshot(self, elapsed: int) -> str:
        """Save a snapshot of the current fuzzer log."""
        log_file = self.logs_dir / "fuzzer.log"
        if not log_file.exists():
            return ""

        snapshot_path = self.snapshots_dir / f"log_snapshot_{elapsed:06d}s.log"

        # Copy the current log (or just the tail for large logs)
        try:
            with open(log_file, 'r') as f:
                content = f.read()

            # Keep last 100KB if log is too large
            max_size = 100 * 1024
            if len(content) > max_size:
                content = f"... (truncated, showing last {max_size} bytes)\n" + content[-max_size:]

            with open(snapshot_path, 'w') as f:
                f.write(content)

            return str(snapshot_path)
        except Exception as e:
            logger.warning(f"Failed to save log snapshot: {e}")
            return ""

    def _take_snapshot(self, elapsed: int, measure_full_coverage: bool = False) -> FuzzingSnapshot:
        """Take a snapshot of current fuzzing state."""
        stats = self._parse_fuzzer_stats(self.logs_dir / "fuzzer.log")
        total_crashes, new_crashes = self._process_crashes()
        corpus_files = len(list(self.corpus_dir.glob("*")))

        # Measure coverage
        coverage_data = None
        if measure_full_coverage:
            coverage_data = self._measure_coverage()

        if coverage_data is None:
            # Use edge coverage from libFuzzer as fallback
            coverage_data = CoverageData(
                line_coverage_percent=0.0,
                branch_coverage_percent=0.0,
                function_coverage_percent=0.0,
                lines_covered=0,
                lines_total=0,
                branches_covered=0,
                branches_total=0,
                functions_covered=0,
                functions_total=0,
                edge_coverage=stats['edge_coverage']
            )
        else:
            coverage_data.edge_coverage = stats['edge_coverage']

        # Calculate coverage diff
        coverage_diff_from_prev = 0.0
        coverage_diff_from_start = 0.0

        if self.initial_coverage is None:
            self.initial_coverage = coverage_data
        else:
            coverage_diff_from_start = (
                coverage_data.line_coverage_percent -
                self.initial_coverage.line_coverage_percent
            )

        if self.prev_coverage is not None:
            coverage_diff_from_prev = (
                coverage_data.line_coverage_percent -
                self.prev_coverage.line_coverage_percent
            )

        self.prev_coverage = coverage_data

        # Save log snapshot
        log_snapshot_path = self._save_log_snapshot(elapsed)

        snapshot = FuzzingSnapshot(
            timestamp=time.time(),
            elapsed_seconds=elapsed,
            corpus_size=corpus_files,
            total_executions=stats['total_executions'],
            exec_per_sec=stats['exec_per_sec'],
            coverage=coverage_data,
            coverage_diff_from_prev=coverage_diff_from_prev,
            coverage_diff_from_start=coverage_diff_from_start,
            crashes_found=total_crashes,
            new_crashes_this_interval=new_crashes,
            timeouts_found=0,  # TODO: parse from log
            ooms_found=0,  # TODO: parse from log
            log_snapshot_path=log_snapshot_path
        )

        self.snapshots.append(snapshot)
        logger.info(
            f"Snapshot @ {elapsed}s: corpus={corpus_files}, "
            f"execs={stats['total_executions']}, coverage={coverage_data.line_coverage_percent:.2f}%, "
            f"crashes={total_crashes} (+{new_crashes})"
        )

        return snapshot

    def _cleanup(self):
        """Cleanup generated project and resources."""
        # Close fuzzer log file handle if open
        if hasattr(self, '_fuzzer_log_handle') and self._fuzzer_log_handle:
            try:
                self._fuzzer_log_handle.close()
            except Exception:
                pass

        if self.generated_project_name:
            try:
                oss_fuzz_dir = self._get_oss_fuzz_dir()
                project_dir = oss_fuzz_dir / "projects" / self.generated_project_name
                if project_dir.exists():
                    shutil.rmtree(project_dir)
                    logger.info(f"Cleaned up project {self.generated_project_name}")
            except Exception as e:
                logger.warning(f"Failed to cleanup: {e}")

    def run(self) -> ExtendedFuzzingResult:
        """Run extended fuzzing and collect results."""
        start_time = datetime.now()
        logger.info(f"Starting extended fuzzing for {self.project}")
        logger.info(f"Duration: {self.duration}s, Snapshot interval: {self.snapshot_interval}s")

        result = ExtendedFuzzingResult(
            project=self.project,
            fuzz_target_path=str(self.fuzz_target_path),
            duration_seconds=self.duration,
            start_time=start_time.isoformat(),
            end_time="",
            corpus_dir=str(self.corpus_dir),
            crashes_dir=str(self.crashes_dir),
            coverage_report_dir=str(self.coverage_dir),
        )

        try:
            # Check for existing build directory (fastest path)
            has_coverage_build = False
            if self.use_existing_build_dir:
                logger.info(f"Using existing build directory: {self.use_existing_build_dir}")
                self.build_out_dir = Path(self.use_existing_build_dir)
                if not self.build_out_dir.exists():
                    result.error = f"Build directory not found: {self.use_existing_build_dir}"
                    return result
                # Set target name from existing fuzzers
                fuzzers = list(self.build_out_dir.glob("*_fuzzer")) + list(self.build_out_dir.glob("*_fuzz"))
                if fuzzers and not self.fuzzer_name:
                    self.target_name = fuzzers[0].name
                    logger.info(f"Using existing fuzzer: {self.target_name}")
            else:
                # Setup and build
                if not self._setup_oss_fuzz_project():
                    result.error = "Failed to setup OSS-Fuzz project"
                    return result

                if not self._build_docker_image():
                    result.error = "Failed to build Docker image"
                    return result

                # Build coverage image for coverage measurement
                has_coverage_build = self._build_coverage_image()
            if not has_coverage_build:
                logger.warning("Coverage build failed, will use edge coverage only")

            # Start fuzzer
            proc = self._run_fuzzer()

            # Take initial snapshot
            time.sleep(5)  # Let fuzzer start
            self._take_snapshot(0, measure_full_coverage=has_coverage_build)
            result.initial_coverage_percent = (
                self.initial_coverage.line_coverage_percent if self.initial_coverage else 0.0
            )

            # Take snapshots periodically
            start = time.time()
            last_snapshot = start

            while proc.poll() is None:
                elapsed = int(time.time() - start)

                # Take snapshot at intervals
                if time.time() - last_snapshot >= self.snapshot_interval:
                    # Full coverage measurement every 3rd snapshot to save time
                    full_coverage = has_coverage_build and (len(self.snapshots) % 3 == 0)
                    self._take_snapshot(elapsed, measure_full_coverage=full_coverage)
                    last_snapshot = time.time()

                # Check if duration exceeded
                if elapsed >= self.duration:
                    logger.info("Duration reached, stopping fuzzer...")
                    proc.terminate()
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    break

                time.sleep(10)  # Check every 10 seconds

            # Final snapshot with full coverage
            self._take_snapshot(int(time.time() - start), measure_full_coverage=has_coverage_build)

            # Collect results
            result.snapshots = self.snapshots
            result.final_corpus_size = len(list(self.corpus_dir.glob("*")))
            result.total_crashes = len(list(self.crashes_dir.glob("crash-*")))
            result.unique_crashes = len(self.crash_infos)
            result.crash_infos = self.crash_infos

            if self.snapshots:
                result.final_coverage = self.snapshots[-1].coverage
                result.final_coverage_percent = self.snapshots[-1].coverage.line_coverage_percent
                result.total_coverage_gain = (
                    result.final_coverage_percent - result.initial_coverage_percent
                )

        except Exception as e:
            logger.error(f"Fuzzing failed: {e}")
            import traceback
            traceback.print_exc()
            result.error = str(e)

        finally:
            self._cleanup()

        result.end_time = datetime.now().isoformat()

        # Save results
        self._save_results(result)

        return result

    def _save_results(self, result: ExtendedFuzzingResult):
        """Save results to JSON file."""
        results_file = self.output_dir / "results.json"

        # Convert to dict, handling dataclasses
        def to_serializable(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            elif isinstance(obj, list):
                return [to_serializable(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: to_serializable(v) for k, v in obj.items()}
            return obj

        result_dict = to_serializable(result)

        with open(results_file, 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)

        logger.info(f"Results saved to {results_file}")

        # Also save a summary CSV for easy plotting
        self._save_summary_csv(result)

    def _save_summary_csv(self, result: ExtendedFuzzingResult):
        """Save time-series data as CSV for easy plotting."""
        csv_file = self.output_dir / "coverage_timeline.csv"

        with open(csv_file, 'w') as f:
            f.write("elapsed_seconds,corpus_size,total_executions,exec_per_sec,"
                    "line_coverage_percent,edge_coverage,coverage_diff_from_start,"
                    "total_crashes,new_crashes\n")

            for snap in result.snapshots:
                cov = snap.coverage
                f.write(f"{snap.elapsed_seconds},{snap.corpus_size},"
                        f"{snap.total_executions},{snap.exec_per_sec:.2f},"
                        f"{cov.line_coverage_percent:.4f},{cov.edge_coverage},"
                        f"{snap.coverage_diff_from_start:.4f},"
                        f"{snap.crashes_found},{snap.new_crashes_this_interval}\n")

        logger.info(f"Coverage timeline saved to {csv_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Run extended fuzzing on generated fuzz drivers"
    )
    parser.add_argument(
        "--project", "-p",
        required=True,
        help="Project name (e.g., cjson)"
    )
    parser.add_argument(
        "--fuzz-target", "-f",
        required=True,
        help="Path to generated fuzz target file"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=3600,
        help="Fuzzing duration in seconds (default: 3600 = 1 hour)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for results (default: results/extended_fuzzing/{project})"
    )
    parser.add_argument(
        "--snapshot-interval", "-s",
        type=int,
        default=300,
        help="Interval between snapshots in seconds (default: 300 = 5 minutes)"
    )
    parser.add_argument(
        "--sanitizer",
        choices=["address", "undefined", "memory"],
        default="address",
        help="Sanitizer to use for fuzzing (default: address)"
    )
    parser.add_argument(
        "--fuzzer-name",
        default=None,
        help="Name of the fuzzer binary (default: inferred from target file)"
    )
    parser.add_argument(
        "--use-existing-build",
        default=None,
        help="Path to existing OSS-Fuzz build output directory (skips Docker build)"
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Docker build and use pre-existing images (faster if images exist)"
    )

    args = parser.parse_args()

    # Set default output directory
    if args.output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_dir = f"results/extended_fuzzing/{args.project}/{timestamp}"

    # Validate fuzz target exists
    if not os.path.exists(args.fuzz_target):
        logger.error(f"Fuzz target not found: {args.fuzz_target}")
        sys.exit(1)

    # Run extended fuzzing
    fuzzer = ExtendedFuzzer(
        project=args.project,
        fuzz_target_path=args.fuzz_target,
        output_dir=args.output_dir,
        duration=args.duration,
        snapshot_interval=args.snapshot_interval,
        sanitizer=args.sanitizer,
        fuzzer_name=args.fuzzer_name,
        skip_build=args.skip_build,
        use_existing_build_dir=args.use_existing_build
    )

    result = fuzzer.run()

    # Print summary
    print("\n" + "=" * 70)
    print("EXTENDED FUZZING SUMMARY")
    print("=" * 70)
    print(f"Project: {result.project}")
    print(f"Duration: {result.duration_seconds}s")
    print(f"Final corpus size: {result.final_corpus_size}")
    print(f"Total crashes: {result.total_crashes}")
    print(f"Unique crashes: {result.unique_crashes}")
    print("-" * 70)
    print("COVERAGE:")
    print(f"  Initial: {result.initial_coverage_percent:.2f}%")
    print(f"  Final:   {result.final_coverage_percent:.2f}%")
    print(f"  Gain:    {result.total_coverage_gain:+.2f}%")
    if result.final_coverage:
        print(f"  Lines:   {result.final_coverage.lines_covered}/{result.final_coverage.lines_total}")
        print(f"  Edges:   {result.final_coverage.edge_coverage}")
    print("-" * 70)
    print(f"Results saved to: {args.output_dir}")

    if result.crash_infos:
        print("\nCRASHES:")
        for crash in result.crash_infos[:5]:  # Show first 5
            print(f"  - {crash.crash_hash}: {crash.crash_type} ({crash.input_size} bytes)")
        if len(result.crash_infos) > 5:
            print(f"  ... and {len(result.crash_infos) - 5} more")

    if result.error:
        print(f"\nError: {result.error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
