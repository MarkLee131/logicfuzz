#!/usr/bin/env python3
"""
Extended fuzzing script v2 - Uses existing LogicFuzz infrastructure directly.

This script takes a fuzz target file and runs it for extended periods (e.g., 24 hours),
collecting coverage metrics at intervals.

Usage:
    python scripts/run_extended_fuzzing_v2.py \
        --project sqlite3 \
        --fuzz-target results/output-sqlite3-project/fuzz_targets/05.fuzz_target \
        --duration 86400 \
        --output-dir results/extended_fuzzing/sqlite3_05 \
        --snapshot-interval 3600
"""
import argparse
import json
import logging
import os
import re
import shutil
import subprocess as sp
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add project root to path
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from experiment import container_cleanup, oss_fuzz_checkout

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CoverageMetrics:
    line_coverage_percent: float = 0.0
    branch_coverage_percent: float = 0.0
    function_coverage_percent: float = 0.0
    lines_covered: int = 0
    lines_total: int = 0
    branches_covered: int = 0
    branches_total: int = 0
    functions_covered: int = 0
    functions_total: int = 0
    edge_coverage: int = 0


@dataclass
class FuzzingSnapshot:
    timestamp: float
    elapsed_seconds: int
    corpus_size: int
    total_executions: int
    exec_per_sec: float
    coverage: CoverageMetrics
    coverage_diff_from_prev: float
    coverage_diff_from_start: float
    crashes_found: int
    new_crashes_this_interval: int
    log_snapshot_path: str = ""


@dataclass
class ExtendedFuzzingResult:
    project: str
    fuzz_target_path: str
    duration_seconds: int
    start_time: str
    end_time: str = ""
    final_coverage: CoverageMetrics = field(default_factory=CoverageMetrics)
    final_corpus_size: int = 0
    initial_coverage_percent: float = 0.0
    final_coverage_percent: float = 0.0
    total_coverage_gain: float = 0.0
    total_crashes: int = 0
    unique_crashes: int = 0
    crash_infos: List[Dict] = field(default_factory=list)
    snapshots: List[FuzzingSnapshot] = field(default_factory=list)
    corpus_dir: str = ""
    crashes_dir: str = ""
    coverage_report_dir: str = ""
    error: Optional[str] = None
    generated_project: str = ""


class ExtendedFuzzingRunner:
    """Runs extended fuzzing using LogicFuzz's existing infrastructure."""

    # Regex patterns for parsing libFuzzer output
    LIBFUZZER_COV_REGEX = re.compile(r'.*cov: (\d+)')
    LIBFUZZER_EXEC_REGEX = re.compile(r'.*exec/s:\s*(\d+)')
    LIBFUZZER_UNITS_REGEX = re.compile(r'.*units:\s*(\d+)')

    def __init__(
        self,
        project: str,
        fuzz_target_path: str,
        duration_seconds: int,
        output_dir: str,
        snapshot_interval: int = 3600,
        target_name: str = "ossfuzz",  # Default target name from LogicFuzz builds
    ):
        self.project = project
        self.fuzz_target_path = Path(fuzz_target_path).resolve()
        self.duration_seconds = duration_seconds
        self.output_dir = Path(output_dir).resolve()
        self.snapshot_interval = snapshot_interval
        self.target_name = target_name

        # Generated project name (OSS-Fuzz style)
        self.generated_project = f"{project}-ext-{int(time.time())}"

        # Setup directories
        self.corpus_dir = self.output_dir / "corpus"
        self.crashes_dir = self.output_dir / "crashes"
        self.logs_dir = self.output_dir / "logs"
        self.snapshots_dir = self.output_dir / "snapshots"
        self.coverage_dir = self.output_dir / "coverage"

        # Initialize result
        self.result = ExtendedFuzzingResult(
            project=project,
            fuzz_target_path=str(self.fuzz_target_path),
            duration_seconds=duration_seconds,
            start_time=datetime.now().isoformat(),
            corpus_dir=str(self.corpus_dir),
            crashes_dir=str(self.crashes_dir),
            coverage_report_dir=str(self.coverage_dir),
            generated_project=self.generated_project,
        )

        # State tracking
        self.fuzzer_process: Optional[sp.Popen] = None
        self.start_time: float = 0
        self.previous_coverage: float = 0.0
        self.initial_coverage: float = 0.0

    def setup(self) -> bool:
        """Setup directories and OSS-Fuzz project."""
        logger.info("Setting up extended fuzzing environment...")

        # Create directories
        for d in [self.output_dir, self.corpus_dir, self.crashes_dir,
                  self.logs_dir, self.snapshots_dir, self.coverage_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Ensure OSS-Fuzz checkout exists
        if not os.path.exists(oss_fuzz_checkout.OSS_FUZZ_DIR):
            logger.error("OSS-Fuzz directory not found: %s", oss_fuzz_checkout.OSS_FUZZ_DIR)
            return False

        # Copy base project and create extended project
        if not self._setup_oss_fuzz_project():
            return False

        # Create initial seed corpus
        self._create_seed_corpus()

        return True

    def _setup_oss_fuzz_project(self) -> bool:
        """Setup OSS-Fuzz project with our custom fuzz target."""
        oss_fuzz_dir = Path(oss_fuzz_checkout.OSS_FUZZ_DIR)
        projects_dir = oss_fuzz_dir / "projects"
        base_project_dir = projects_dir / self.project
        generated_project_dir = projects_dir / self.generated_project

        if not base_project_dir.exists():
            logger.error("Base project not found: %s", base_project_dir)
            return False

        # Copy base project
        if generated_project_dir.exists():
            shutil.rmtree(generated_project_dir)
        shutil.copytree(base_project_dir, generated_project_dir)

        # Read fuzz target source
        with open(self.fuzz_target_path, 'r') as f:
            fuzz_target_source = f.read()

        # Preprocess fuzz target to fix include paths
        fuzz_target_source = self._preprocess_fuzz_target(fuzz_target_source)

        # Determine target path in container based on project
        target_filename = f"{self.target_name}.c"  # Use .c extension
        container_target_path = self._get_container_target_path()

        # Write our custom fuzz target to the project directory
        fuzz_target_dest = generated_project_dir / target_filename
        with open(fuzz_target_dest, 'w') as f:
            f.write(fuzz_target_source)

        # Modify Dockerfile to COPY our target into the container
        dockerfile = generated_project_dir / "Dockerfile"
        if dockerfile.exists():
            with open(dockerfile, 'a') as f:
                f.write(f"\n# LogicFuzz custom target\n")
                f.write(f"COPY {target_filename} {container_target_path}\n")

        logger.info("Created OSS-Fuzz project: %s", self.generated_project)
        logger.info("Target will be placed at: %s", container_target_path)
        return True

    def _get_container_target_path(self) -> str:
        """Get the path where the fuzz target should be placed in the container."""
        # Project-specific paths based on OSS-Fuzz structure
        # These must match what build.sh compiles!
        target_paths = {
            "sqlite3": "/src/sqlite3/test/ossfuzz.c",
            "re2": "/src/re2/re2/fuzzing/re2_fuzzer.cc",  # Fixed: re2's fuzzer is in re2/fuzzing/
            "c-ares": "/src/c-ares/test/ares-test-fuzz.c",
            "cjson": "/src/cJSON/fuzzing/cjson_read_fuzzer.c",
        }
        return target_paths.get(self.project, f"/src/{self.project}/{self.target_name}.c")

    def _preprocess_fuzz_target(self, source: str) -> str:
        """Preprocess fuzz target to fix include paths for Docker build."""
        # Fix absolute Docker paths to relative paths that work during OSS-Fuzz build
        if self.project == "sqlite3":
            # Replace /src/sqlite3/bld/sqlite3.h with just sqlite3.h (found via -I.)
            source = re.sub(
                r'#include\s*[<"]/?src/sqlite3/bld/sqlite3\.h[>"]',
                '#include "sqlite3.h"',
                source
            )
            # Also handle variations
            source = re.sub(
                r'#include\s*[<"]sqlite3/bld/sqlite3\.h[>"]',
                '#include "sqlite3.h"',
                source
            )
        elif self.project == "re2":
            # Fix re2 include paths
            source = re.sub(
                r'#include\s*[<"]/?src/re2/',
                '#include "re2/',
                source
            )
        elif self.project == "c-ares":
            # Fix c-ares include paths
            source = re.sub(
                r'#include\s*[<"]/?src/c-ares/',
                '#include "',
                source
            )
        return source

    def _modify_build_script(self, build_sh: Path, target_filename: str):
        """Modify build.sh to compile our custom fuzz target."""
        with open(build_sh, 'r') as f:
            content = f.read()

        # Project-specific compilation commands
        if self.project == "sqlite3":
            compile_cmd = f"""
# Build LogicFuzz custom target (sqlite3)
# Stay in bld directory where sqlite3.o was built
$CC $CFLAGS -I. -c $SRC/{self.generated_project}/{target_filename} -o $SRC/{self.generated_project}/custom_target.o 2>/dev/null || true
if [ -f "$SRC/{self.generated_project}/custom_target.o" ]; then
    $CXX $CXXFLAGS $SRC/{self.generated_project}/custom_target.o -o $OUT/{self.target_name} $LIB_FUZZING_ENGINE ./sqlite3.o
else
    # Fallback: compile as C++ directly
    $CXX $CXXFLAGS -I. $LIB_FUZZING_ENGINE $SRC/{self.generated_project}/{target_filename} ./sqlite3.o -o $OUT/{self.target_name}
fi
"""
        elif self.project == "re2":
            compile_cmd = f"""
# Build LogicFuzz custom target (re2)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \\
    $SRC/{self.generated_project}/{target_filename} \\
    -I$SRC/re2 \\
    $SRC/re2/obj/libre2.a \\
    -o $OUT/{self.target_name}
"""
        elif self.project == "c-ares":
            compile_cmd = f"""
# Build LogicFuzz custom target (c-ares)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \\
    $SRC/{self.generated_project}/{target_filename} \\
    -I$SRC/c-ares/include -I$SRC/c-ares \\
    $SRC/c-ares/.libs/libcares.a \\
    -o $OUT/{self.target_name}
"""
        else:
            # Generic fallback
            compile_cmd = f"""
# Build LogicFuzz custom target (generic)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \\
    $SRC/{self.generated_project}/{target_filename} \\
    -I$SRC/{self.project} -I$SRC/{self.project}/src -I$SRC/{self.project}/include \\
    $(find $SRC/{self.project} -name "*.a" 2>/dev/null | head -5 | tr '\\n' ' ') \\
    -o $OUT/{self.target_name} 2>/dev/null || \\
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \\
    $SRC/{self.generated_project}/{target_filename} \\
    $(pkg-config --cflags --libs {self.project} 2>/dev/null || echo "") \\
    -o $OUT/{self.target_name}
"""
        with open(build_sh, 'w') as f:
            f.write(content + "\n" + compile_cmd)

    def _create_seed_corpus(self):
        """Seed the corpus — real project inputs first, synthetic as fallback.

        Parser entry points (ICC/IT8/image/…) reject random bytes at the
        header check, so continuous fuzzing needs valid seeds (the project's
        own ``*.icc``/``*.it8``/``*_seed_corpus.zip`` samples) to reach deep
        code. See ``scripts/seed_discovery.py``.
        """
        import shutil as _shutil
        n_real = 0
        try:
            from scripts.seed_discovery import discover_project_seeds
            for i, src in enumerate(discover_project_seeds(self.project)):
                dst = self.corpus_dir / f"projseed_{i:04d}_{src.name}"
                if not dst.exists():
                    try:
                        _shutil.copy(src, dst)
                        n_real += 1
                    except OSError:
                        continue
        except Exception as exc:
            logger.debug("project seed discovery skipped: %s", exc)
        if n_real:
            logger.info("Seeded corpus with %d REAL project inputs", n_real)
            return
        seeds = [b"", b"{}", b"[]", b'{"a":1}', b"null", b'"test"', b"123", b"true"]
        for i, seed in enumerate(seeds):
            seed_path = self.corpus_dir / f"seed_{i:04d}"
            with open(seed_path, 'wb') as f:
                f.write(seed)
        logger.info("No real seeds found; created %d synthetic seed files", len(seeds))

    def build(self) -> bool:
        """Build the fuzz target with address sanitizer."""
        logger.info("Building fuzz target...")
        oss_fuzz_dir = oss_fuzz_checkout.OSS_FUZZ_DIR

        # Build docker image
        build_log = self.logs_dir / "build_image.log"
        cmd = [
            "docker", "build", "-t", f"gcr.io/oss-fuzz/{self.generated_project}",
            str(Path(oss_fuzz_dir) / "projects" / self.generated_project)
        ]
        with open(build_log, 'w') as f:
            result = sp.run(cmd, cwd=oss_fuzz_dir, stdout=f, stderr=sp.STDOUT)
            if result.returncode != 0:
                logger.error("Failed to build Docker image. See %s", build_log)
                return False

        # Build fuzzers
        build_log = self.logs_dir / "build_fuzzers.log"
        outdir = Path(oss_fuzz_dir) / "build" / "out" / self.generated_project
        workdir = Path(oss_fuzz_dir) / "build" / "work" / self.generated_project
        outdir.mkdir(parents=True, exist_ok=True)
        workdir.mkdir(parents=True, exist_ok=True)

        # NAME channel: unique --name so a killed client can't orphan it.
        build_ctr = container_cleanup.make_container_name('v2build')
        cmd = [
            "docker", "run", "--rm", "--name", build_ctr,
            "--privileged", "--shm-size=2g",
            "--platform", "linux/amd64", "-i",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", "SANITIZER=address",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={self.generated_project}",
            "-e", "FUZZING_LANGUAGE=c++",
            "-v", f"{outdir}:/out",
            "-v", f"{workdir}:/work",
            "--entrypoint", "/bin/bash",
            f"gcr.io/oss-fuzz/{self.generated_project}",
            "-c", "rm -rf /out/* /work/* && compile && chmod 777 -R /out/*"
        ]
        with open(build_log, 'w') as f:
            try:
                result = sp.run(cmd, cwd=oss_fuzz_dir, stdout=f, stderr=sp.STDOUT)
            finally:
                container_cleanup.force_remove_named_container(build_ctr)
            if result.returncode != 0:
                logger.error("Failed to build fuzzers. See %s", build_log)
                return False

        # Verify fuzzer was built
        fuzzer_path = outdir / self.target_name
        if not fuzzer_path.exists():
            # Try to find any fuzzer
            fuzzers = list(outdir.glob("*_fuzzer")) + list(outdir.glob("*fuzzer"))
            if fuzzers:
                self.target_name = fuzzers[0].name
                logger.info("Using fuzzer: %s", self.target_name)
            else:
                logger.error("No fuzzer found in %s", outdir)
                return False

        logger.info("Successfully built fuzzer: %s", self.target_name)
        return True

    def run_fuzzing(self) -> bool:
        """Run fuzzing for the specified duration with periodic snapshots."""
        logger.info("Starting fuzzing for %d seconds...", self.duration_seconds)
        self.start_time = time.time()
        oss_fuzz_dir = oss_fuzz_checkout.OSS_FUZZ_DIR

        # Run fuzzer
        # Note: artifact_prefix must be a path inside the container
        # OSS-Fuzz mounts /tmp/ossfuzz_corpus, but we can use the /out directory
        fuzzer_log = self.logs_dir / "fuzzer.log"
        cmd = [
            "python3", "infra/helper.py", "run_fuzzer",
            # LSan can't run under the ptrace-restricted runner (fatal error at
            # exit → false crash artifact); the -detect_leaks=0 flag doesn't
            # suppress the runtime atexit check, this env var does.
            "-e", "ASAN_OPTIONS=detect_leaks=0",
            "--corpus-dir", str(self.corpus_dir),
            self.generated_project, self.target_name,
            "--",
            f"-max_total_time={self.duration_seconds}",
            "-print_final_stats=1",
            "-detect_leaks=0",
        ]

        logger.info("Running: %s", " ".join(cmd))
        # NAME channel: name the helper.py run_fuzzer container so it can be
        # force-removed (helper.py drops --rm when this env is set; the long-
        # running Popen would otherwise orphan it on kill).
        self._fuzz_ctr = container_cleanup.make_container_name('v2fuzz')
        fuzz_env = dict(os.environ,
                        OSS_FUZZ_SAVE_CONTAINERS_NAME=self._fuzz_ctr)
        with open(fuzzer_log, 'w') as f:
            self.fuzzer_process = sp.Popen(
                cmd, cwd=oss_fuzz_dir,
                stdout=f, stderr=sp.STDOUT,
                stdin=sp.DEVNULL,
                env=fuzz_env,
            )

        # Take periodic snapshots
        next_snapshot = self.start_time + self.snapshot_interval
        last_snapshot_time = self.start_time

        while True:
            # Check if fuzzer is still running
            poll_result = self.fuzzer_process.poll()
            if poll_result is not None:
                logger.info("Fuzzer process exited with code: %d", poll_result)
                break

            current_time = time.time()
            elapsed = int(current_time - self.start_time)

            # Take snapshot at intervals
            if current_time >= next_snapshot:
                logger.info("Taking snapshot at %d seconds...", elapsed)
                self._take_snapshot(elapsed, fuzzer_log)
                next_snapshot = current_time + self.snapshot_interval
                last_snapshot_time = current_time

            # Check if duration exceeded
            if elapsed >= self.duration_seconds:
                logger.info("Duration reached, waiting for fuzzer to finish...")
                try:
                    self.fuzzer_process.wait(timeout=60)
                except sp.TimeoutExpired:
                    logger.warning("Fuzzer didn't stop gracefully, terminating...")
                    self.fuzzer_process.terminate()
                    self.fuzzer_process.wait(timeout=10)
                break

            time.sleep(10)  # Check every 10 seconds

        # Force-remove the named fuzzer container (NAME channel): helper.py
        # dropped --rm because we set OSS_FUZZ_SAVE_CONTAINERS_NAME, and a
        # terminated long-running fuzzer would otherwise orphan it.
        container_cleanup.force_remove_named_container(
            getattr(self, '_fuzz_ctr', ''))

        # Take final snapshot
        elapsed = int(time.time() - self.start_time)
        self._take_snapshot(elapsed, fuzzer_log, is_final=True)

        return True

    def _take_snapshot(self, elapsed_seconds: int, fuzzer_log: Path, is_final: bool = False):
        """Take a snapshot of current fuzzing state."""
        # Count corpus files
        corpus_size = len(list(self.corpus_dir.glob("*")))

        # Count crashes - crashes are written to /out directory in container
        # which maps to the build output dir
        oss_fuzz_out = Path(oss_fuzz_checkout.OSS_FUZZ_DIR) / "build" / "out" / self.generated_project
        crashes = list(oss_fuzz_out.glob("crash-*")) + list(self.crashes_dir.glob("crash-*"))
        crash_count = len(crashes)

        # Parse recent log output for exec/s and coverage
        exec_per_sec = 0.0
        edge_coverage = 0
        total_executions = 0

        try:
            with open(fuzzer_log, 'r') as f:
                lines = f.readlines()[-100:]  # Last 100 lines
                for line in reversed(lines):
                    if 'exec/s:' in line:
                        match = self.LIBFUZZER_EXEC_REGEX.search(line)
                        if match:
                            exec_per_sec = float(match.group(1))
                    if 'cov:' in line:
                        match = self.LIBFUZZER_COV_REGEX.search(line)
                        if match:
                            edge_coverage = int(match.group(1))
                    if 'units:' in line:
                        match = self.LIBFUZZER_UNITS_REGEX.search(line)
                        if match:
                            total_executions = int(match.group(1))
                    if exec_per_sec > 0 and edge_coverage > 0:
                        break
        except Exception as e:
            logger.warning("Failed to parse fuzzer log: %s", e)

        # Create coverage metrics (edge coverage only for now)
        coverage = CoverageMetrics(edge_coverage=edge_coverage)

        # Calculate coverage diff
        coverage_diff_from_prev = edge_coverage - self.previous_coverage
        coverage_diff_from_start = edge_coverage - self.initial_coverage

        if self.initial_coverage == 0:
            self.initial_coverage = edge_coverage

        self.previous_coverage = edge_coverage

        # Save log snapshot
        snapshot_log = self.snapshots_dir / f"log_snapshot_{elapsed_seconds:06d}s.log"
        try:
            with open(fuzzer_log, 'r') as src:
                with open(snapshot_log, 'w') as dst:
                    dst.write(src.read())
        except Exception as e:
            logger.warning("Failed to save log snapshot: %s", e)

        # Calculate new crashes since last snapshot
        prev_crashes = sum(1 for s in self.result.snapshots for _ in range(s.new_crashes_this_interval))
        new_crashes = max(0, crash_count - prev_crashes)

        snapshot = FuzzingSnapshot(
            timestamp=time.time(),
            elapsed_seconds=elapsed_seconds,
            corpus_size=corpus_size,
            total_executions=total_executions,
            exec_per_sec=exec_per_sec,
            coverage=coverage,
            coverage_diff_from_prev=coverage_diff_from_prev,
            coverage_diff_from_start=coverage_diff_from_start,
            crashes_found=crash_count,
            new_crashes_this_interval=new_crashes,
            log_snapshot_path=str(snapshot_log),
        )
        self.result.snapshots.append(snapshot)

        logger.info(
            "Snapshot [%ds]: corpus=%d, exec/s=%.1f, edge_cov=%d, crashes=%d",
            elapsed_seconds, corpus_size, exec_per_sec, edge_coverage, crash_count
        )

    def collect_coverage(self) -> bool:
        """Build with coverage sanitizer and collect coverage metrics."""
        logger.info("Collecting coverage metrics...")
        oss_fuzz_dir = oss_fuzz_checkout.OSS_FUZZ_DIR

        # Build with coverage sanitizer
        outdir = Path(oss_fuzz_dir) / "build" / "out" / self.generated_project
        workdir = Path(oss_fuzz_dir) / "build" / "work" / self.generated_project

        build_log = self.logs_dir / "build_coverage.log"
        covbuild_ctr = container_cleanup.make_container_name('v2covbuild')
        cmd = [
            "docker", "run", "--rm", "--name", covbuild_ctr,
            "--privileged", "--shm-size=2g",
            "--platform", "linux/amd64", "-i",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", "SANITIZER=coverage",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={self.generated_project}",
            "-e", "FUZZING_LANGUAGE=c++",
            "-v", f"{outdir}:/out",
            "-v", f"{workdir}:/work",
            "--entrypoint", "/bin/bash",
            f"gcr.io/oss-fuzz/{self.generated_project}",
            "-c", "rm -rf /out/* /work/* && compile && chmod 777 -R /out/*"
        ]
        with open(build_log, 'w') as f:
            try:
                result = sp.run(cmd, cwd=oss_fuzz_dir, stdout=f, stderr=sp.STDOUT)
            finally:
                container_cleanup.force_remove_named_container(covbuild_ctr)
            if result.returncode != 0:
                logger.warning("Failed to build coverage version. See %s", build_log)
                return False

        # Run coverage
        coverage_log = self.logs_dir / "coverage.log"
        cov_ctr = container_cleanup.make_container_name('v2cov')
        cov_env = dict(os.environ, OSS_FUZZ_SAVE_CONTAINERS_NAME=cov_ctr)
        cmd = [
            "python3", "infra/helper.py", "coverage",
            "--corpus-dir", str(self.corpus_dir),
            "--fuzz-target", self.target_name,
            "--no-serve", "--port", "",
            self.generated_project
        ]
        with open(coverage_log, 'w') as f:
            try:
                result = sp.run(cmd, cwd=oss_fuzz_dir, stdout=f, stderr=sp.STDOUT,
                                env=cov_env)
            finally:
                container_cleanup.force_remove_named_container(cov_ctr)
            if result.returncode != 0:
                logger.warning("Failed to collect coverage. See %s", coverage_log)
                return False

        # Copy coverage report
        report_dir = outdir / "report"
        if report_dir.exists():
            shutil.copytree(report_dir, self.coverage_dir / "report", dirs_exist_ok=True)

        # Parse summary.json
        summary_path = outdir / "report" / "linux" / "summary.json"
        if summary_path.exists():
            with open(summary_path, 'r') as f:
                summary = json.load(f)
                totals = summary.get('data', [{}])[0].get('totals', {})

                lines = totals.get('lines', {})
                branches = totals.get('branches', {})
                functions = totals.get('functions', {})

                self.result.final_coverage = CoverageMetrics(
                    line_coverage_percent=lines.get('percent', 0.0),
                    branch_coverage_percent=branches.get('percent', 0.0),
                    function_coverage_percent=functions.get('percent', 0.0),
                    lines_covered=lines.get('covered', 0),
                    lines_total=lines.get('count', 0),
                    branches_covered=branches.get('covered', 0),
                    branches_total=branches.get('count', 0),
                    functions_covered=functions.get('covered', 0),
                    functions_total=functions.get('count', 0),
                )
                logger.info(
                    "Coverage: lines=%.1f%%, branches=%.1f%%, functions=%.1f%%",
                    self.result.final_coverage.line_coverage_percent,
                    self.result.final_coverage.branch_coverage_percent,
                    self.result.final_coverage.function_coverage_percent
                )

        return True

    def finalize(self):
        """Finalize results and save."""
        self.result.end_time = datetime.now().isoformat()
        self.result.final_corpus_size = len(list(self.corpus_dir.glob("*")))

        # Count crashes
        crashes = list(self.crashes_dir.glob("crash-*"))
        self.result.total_crashes = len(crashes)
        self.result.unique_crashes = len(crashes)  # All are unique at file level

        # Calculate coverage gain
        if self.result.snapshots:
            self.result.initial_coverage_percent = self.result.snapshots[0].coverage.edge_coverage
            self.result.final_coverage_percent = self.result.snapshots[-1].coverage.edge_coverage
            self.result.total_coverage_gain = (
                self.result.final_coverage_percent - self.result.initial_coverage_percent
            )

        # Save results
        results_path = self.output_dir / "results.json"
        with open(results_path, 'w') as f:
            json.dump(self._to_dict(self.result), f, indent=2)

        logger.info("Results saved to %s", results_path)
        logger.info("Final corpus size: %d", self.result.final_corpus_size)
        logger.info("Total crashes: %d", self.result.total_crashes)

    def _to_dict(self, obj) -> Dict[str, Any]:
        """Convert dataclass to dict recursively."""
        if hasattr(obj, '__dataclass_fields__'):
            return {k: self._to_dict(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, list):
            return [self._to_dict(v) for v in obj]
        elif isinstance(obj, dict):
            return {k: self._to_dict(v) for k, v in obj.items()}
        else:
            return obj

    def run(self) -> ExtendedFuzzingResult:
        """Run the complete extended fuzzing workflow."""
        try:
            if not self.setup():
                self.result.error = "Setup failed"
                self.finalize()
                return self.result

            if not self.build():
                self.result.error = "Build failed"
                self.finalize()
                return self.result

            if not self.run_fuzzing():
                self.result.error = "Fuzzing failed"
                self.finalize()
                return self.result

            self.collect_coverage()
            self.finalize()

        except Exception as e:
            logger.exception("Extended fuzzing failed with error: %s", e)
            self.result.error = str(e)
            self.finalize()

        return self.result


def main():
    parser = argparse.ArgumentParser(description="Run extended fuzzing on a fuzz target")
    parser.add_argument("--project", required=True, help="Project name (e.g., sqlite3, re2)")
    parser.add_argument("--fuzz-target", required=True, help="Path to fuzz target source file")
    parser.add_argument("--duration", type=int, default=86400, help="Fuzzing duration in seconds (default: 24h)")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--snapshot-interval", type=int, default=3600, help="Snapshot interval in seconds (default: 1h)")
    parser.add_argument("--target-name", default="ossfuzz", help="Fuzzer target name (default: ossfuzz)")

    args = parser.parse_args()

    runner = ExtendedFuzzingRunner(
        project=args.project,
        fuzz_target_path=args.fuzz_target,
        duration_seconds=args.duration,
        output_dir=args.output_dir,
        snapshot_interval=args.snapshot_interval,
        target_name=args.target_name,
    )

    result = runner.run()

    if result.error:
        logger.error("Extended fuzzing failed: %s", result.error)
        sys.exit(1)
    else:
        logger.info("Extended fuzzing completed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
