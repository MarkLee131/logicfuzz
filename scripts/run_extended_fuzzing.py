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
from tools.merge_drivers.merge import SynthesizedDriver  # for --fuzz-target-dir mode

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
        use_existing_build_dir: Optional[str] = None,
        fuzz_target_dir: Optional[str] = None,
        merged_build_libs: str = "",
        merged_build_includes: str = "",
        seed_corpus_dir: Optional[str] = None,
    ):
        self.project = project
        self.fuzz_target_path = Path(fuzz_target_path) if fuzz_target_path else None
        self.fuzz_target_dir = Path(fuzz_target_dir) if fuzz_target_dir else None
        self.output_dir = Path(output_dir)
        self.duration = duration
        self.snapshot_interval = snapshot_interval
        self.sanitizer = sanitizer
        self.fuzzer_name = fuzzer_name
        self.skip_build = skip_build
        self.use_existing_build_dir = use_existing_build_dir
        self.merged_build_libs = merged_build_libs
        self.merged_build_includes = merged_build_includes
        self.seed_corpus_dir = Path(seed_corpus_dir) if seed_corpus_dir else None
        if (self.fuzz_target_path is None) == (self.fuzz_target_dir is None):
            raise ValueError(
                "exactly one of fuzz_target_path / fuzz_target_dir is required"
            )

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
        # Separate project/out dir for the COVERAGE build. `build_fuzzers
        # --sanitizer coverage` writes to build/out/<name>; if that name equals
        # the address build's, the profile-instrumented binary CLOBBERS the
        # libFuzzer (sancov) one and the fuzzer runs blind (corp 1/1b forever).
        self.coverage_project_name = None
        self.initial_coverage: Optional[CoverageData] = None
        self.prev_coverage: Optional[CoverageData] = None
        self._fuzzer_log_handle = None

    def _ensure_seed_corpus(self):
        """Ensure corpus has at least one seed file for LibFuzzer to start."""
        # If caller supplied a pre-tagged seed corpus (e.g. corpus_merged/
        # from tools/merge_drivers pipeline), copy it in first.
        if self.seed_corpus_dir and self.seed_corpus_dir.is_dir():
            n = 0
            for src in self.seed_corpus_dir.iterdir():
                if not src.is_file():
                    continue
                dst = self.corpus_dir / src.name
                if not dst.exists():
                    shutil.copy(src, dst)
                    n += 1
            if n:
                logger.info(
                    f"Copied {n} pre-tagged seeds from {self.seed_corpus_dir}"
                )

        # Seed with the project's REAL inputs (valid ICC profiles, IT8
        # datasets, OSS-Fuzz *_seed_corpus.zip, …). A format parser rejects
        # random bytes at its header check, so without valid seeds our
        # parser-entry drivers barely move coverage. Real seeds drive them
        # straight into deep parse code.
        try:
            from scripts.seed_discovery import discover_project_seeds
            real_seeds = discover_project_seeds(self.project)
            # A MERGED dispatcher harness (tools/merge_drivers) consumes the
            # last `selector_bytes` of every input as `driverIndex` and routes
            # via `switch(driverIndex % n)`, feeding Data[0:Size-selector_bytes]
            # as the body. A raw seed copied verbatim therefore (a) loses its
            # last body byte(s) to the selector and (b) routes to a
            # pseudo-random sub-driver — a real .icc almost never reaches the
            # profile sub-driver. Fix: tag each raw seed with EVERY sub-driver's
            # TAIL selector (one copy per index) so the format-matching
            # sub-driver gets a clean-body copy. Format-agnostic; N is small.
            # LOGICFUZZ_DISABLE_SEED_TAGGING=1 forces verbatim (A/B isolation).
            merged = (None if os.environ.get('LOGICFUZZ_DISABLE_SEED_TAGGING')
                      else self._parse_merged_dispatch())
            n_real = 0
            for i, src in enumerate(real_seeds):
                if merged is not None:
                    sel_bytes, ndrv = merged
                    try:
                        data = src.read_bytes()
                    except OSError:
                        continue
                    for d in range(ndrv):
                        tag = d.to_bytes(sel_bytes, "little")
                        dst = self.corpus_dir / f"projseed_{i:04d}_d{d:02d}_{src.name}"
                        if not dst.exists():
                            try:
                                dst.write_bytes(data + tag)
                                n_real += 1
                            except OSError:
                                continue
                else:
                    dst = self.corpus_dir / f"projseed_{i:04d}_{src.name}"
                    if not dst.exists():
                        try:
                            shutil.copy(src, dst)
                            n_real += 1
                        except OSError:
                            continue
            if n_real:
                _how = (f"selector-tagged for {merged[1]}-way merged dispatch"
                        if merged is not None else "verbatim")
                logger.info(
                    "Seeded corpus with %d REAL project inputs (%s) (continuous "
                    "fuzzing will exercise deep parser paths)", n_real, _how)
        except Exception as exc:
            logger.debug("project seed discovery skipped: %s", exc)

        corpus_files = list(self.corpus_dir.glob("*"))
        if not corpus_files:
            # No caller corpus AND no real project seeds → minimal synthetic
            # fallback so LibFuzzer has a non-empty start (low value; only
            # forgiving parsers like JSON get coverage from these).
            seeds = [
                b"", b"{}", b"[]", b'{"a":1}', b"null", b'"test"', b"123", b"true",
            ]
            for i, seed in enumerate(seeds):
                seed_file = self.corpus_dir / f"seed_{i:03d}"
                with open(seed_file, 'wb') as f:
                    f.write(seed)
            logger.info(f"No real seeds found; created {len(seeds)} synthetic "
                        f"seed files in {self.corpus_dir}")

    def _parse_merged_dispatch(self):
        """Detect a merged dispatcher harness; return (selector_bytes, n) or None.

        Matches the ACTUAL tools/merge_drivers/merge.py UNIFORM/TAIL dispatcher:
            memcpy(&driverIndex, Data + Size - <k>, <k>);
            switch (driverIndex % <n>) {
        Single-driver harnesses (and HEAD/CDF variants) return None → seeds are
        copied verbatim (safe). Only UNIFORM/TAIL — what run_single_fuzz emits —
        is selector-tagged.
        """
        try:
            if not self.fuzz_target_path:
                return None
            src = Path(self.fuzz_target_path)
            if not src.is_file():
                return None
            text = src.read_text(errors="replace")
            import re as _re
            m_n = _re.search(r"switch\s*\(\s*driverIndex\s*%\s*(\d+)\s*\)", text)
            m_tail = _re.search(
                r"memcpy\(&driverIndex,\s*Data\s*\+\s*Size\s*-\s*(\d+)\s*,\s*(\d+)\)",
                text)
            if m_n and m_tail:
                return int(m_tail.group(2)), int(m_n.group(1))
        except Exception:
            pass
        return None

    def _read_fuzz_target(self) -> str:
        """Read fuzz target source code (single-file mode only)."""
        assert self.fuzz_target_path is not None
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
        """Setup OSS-Fuzz project with our fuzz target (single file or merged dir)."""
        logger.info(f"Setting up OSS-Fuzz project for {self.project}...")
        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()
            timestamp = int(time.time())
            self.generated_project_name = f"{self.project}-ext-{timestamp}"
            src_project = oss_fuzz_dir / "projects" / self.project
            dst_project = oss_fuzz_dir / "projects" / self.generated_project_name
            if not src_project.exists():
                logger.error(f"Project {self.project} not found in OSS-Fuzz")
                return False
            shutil.copytree(src_project, dst_project)

            if self.fuzz_target_dir is not None:
                ok = self._setup_merged_dir(dst_project)
            else:
                ok = self._setup_single_file(dst_project)
            if not ok:
                return False

            # Mirror the fully-prepared project (our fuzz target COPY + the
            # build.sh append + Dockerfile changes) into a sibling project used
            # ONLY for the coverage build. This gives the coverage build its own
            # build/out/<name>-cov dir so it never overwrites the libFuzzer
            # (sancov) binary the fuzzer actually runs. ROOT CAUSE of every flat
            # long run: both builds shared build/out/<gen>; the coverage
            # (-fprofile-instr-generate) binary clobbered the sancov one, so
            # libFuzzer got zero edge feedback (corp 1/1b, +0.00% gain forever).
            self.coverage_project_name = f"{self.generated_project_name}-cov"
            cov_project = oss_fuzz_dir / "projects" / self.coverage_project_name
            if cov_project.exists():
                shutil.rmtree(cov_project)
            shutil.copytree(dst_project, cov_project)
            return True
        except Exception as e:
            logger.error(f"Failed to setup project: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def _setup_single_file(self, dst_project: Path) -> bool:
        """Single-file fuzz target — original behavior."""
        assert self.fuzz_target_path is not None
        target_basename = self.fuzz_target_path.name
        shutil.copy(self.fuzz_target_path, dst_project / target_basename)

        if self.fuzzer_name:
            target_name = self.fuzzer_name
        else:
            target_name = self.fuzz_target_path.stem
            if target_name.isdigit() or target_name in ('01', '02', '03', '04', '05'):
                target_name = f"{self.project}_fuzzer"
            elif target_name.startswith(('01.', '02.', '03.')):
                target_name = f"{self.project}_fuzzer"
        self.target_name = target_name
        logger.info(f"Using target name: {self.target_name}")

        dockerfile = dst_project / "Dockerfile"
        with open(dockerfile, 'a') as f:
            f.write(f'\nCOPY {target_basename} /src/{target_basename}\n')

        build_sh = dst_project / "build.sh"
        if build_sh.exists():
            with open(build_sh, 'r') as f:
                build_content = f.read()
            # Our generated drivers carry a ``.fuzz_target`` extension (not
            # ``.c``), and OSS-Fuzz fuzz targets are C/C++ (libFuzzer is C++,
            # our drivers use ``extern "C"`` guards) — so compile ANY source
            # extension with $CXX. (The old gate silently skipped
            # ``.fuzz_target`` ⇒ the binary was never built ⇒ 0 execs ⇒ no
            # coverage.) Also wire the project's headers + its just-built
            # static lib(s): a bare ``$CXX target.o`` can't resolve
            # ``cmsOpenProfileFromMem`` / ``#include "lcms2.h"``. We append
            # AFTER the project's own build.sh, so its lib is already built.
            import re
            extra_l = ' '.join(sorted(set(re.findall(r'-l\w+', build_content))))
            compile_cmd = f'''
# === LogicFuzz extended-fuzzing target (compiled after project build) ===
EXT_INC=""
for d in /src/{self.project}/include /src/{self.project} /src/{self.project}/src /src/include /src; do
  [ -d "$d" ] && EXT_INC="$EXT_INC -I$d"
done
EXT_LIBS=$(find /src/{self.project} -name 'lib*.a' 2>/dev/null | tr '\\n' ' ')
# The driver has a ``.fuzz_target`` extension, so clang can't infer the source
# language and would treat it as a linker input. We must pass ``-x``. Try C
# first ($CC -x c) — C projects (lcms/cjson/c-ares) and their drivers are C,
# and real C drivers use C-only features (e.g. VLAs that C++ rejects) — then
# fall back to C++ for genuinely-C++ drivers. Always LINK with $CXX (the
# libFuzzer engine is C++).
($CC $CFLAGS $EXT_INC -x c -c /src/{target_basename} -o /tmp/ext_fuzzer.o) || \\
($CXX $CXXFLAGS $EXT_INC -x c++ -c /src/{target_basename} -o /tmp/ext_fuzzer.o)
$CXX $CXXFLAGS /tmp/ext_fuzzer.o $EXT_LIBS $LIB_FUZZING_ENGINE {extra_l} -o $OUT/{self.target_name} ${{LDFLAGS:-}}
'''
            with open(build_sh, 'a') as f:
                f.write(compile_cmd)
        logger.info(f"Created project {self.generated_project_name} "
                    f"(target {self.target_name}, compiled with project "
                    f"includes + static libs)")
        return True

    def _setup_merged_dir(self, dst_project: Path) -> bool:
        """Merged synthesized/ directory — emit OSS-Fuzz build snippet.

        Expects ``self.fuzz_target_dir`` to point at a synthesized/
        directory produced by ``tools/merge_drivers`` containing each
        sub-driver TU plus an ``entry.{c,cpp}``.
        """
        assert self.fuzz_target_dir is not None
        if not self.fuzz_target_dir.is_dir():
            logger.error(f"fuzz_target_dir not a directory: {self.fuzz_target_dir}")
            return False

        target_name = self.fuzzer_name or f"{self.project}_synth_fuzzer"
        self.target_name = target_name
        logger.info(f"Using merged target name: {self.target_name}")

        # Copy synthesized/ into the OSS-Fuzz project.
        dst_synth = dst_project / "synthesized"
        if dst_synth.exists():
            shutil.rmtree(dst_synth)
        shutil.copytree(self.fuzz_target_dir, dst_synth)

        # Dockerfile: COPY synthesized into /src/
        dockerfile = dst_project / "Dockerfile"
        with open(dockerfile, 'a') as f:
            f.write("\nCOPY synthesized /src/synthesized\n")

        # Reconstruct a SynthesizedDriver from the on-disk files just
        # to derive is_cpp + a build snippet aligned with what merge.py
        # would emit. We pick up *.c/*.cpp/*.cc/*.cxx but exclude entry
        # — actually entry is part of the same set; the snippet's
        # for-loop compiles every TU including entry, which is correct.
        sources = (
            sorted(self.fuzz_target_dir.glob("*.c"))
            + sorted(self.fuzz_target_dir.glob("*.cpp"))
            + sorted(self.fuzz_target_dir.glob("*.cc"))
            + sorted(self.fuzz_target_dir.glob("*.cxx"))
        )
        if not sources:
            logger.error(f"No C/C++ files in {self.fuzz_target_dir}")
            return False

        # Auto-detect lib link flags from project's existing build.sh
        # (matches single-file behavior).
        build_sh = dst_project / "build.sh"
        extra_libs = self.merged_build_libs
        if build_sh.exists() and not extra_libs:
            import re
            content = build_sh.read_text()
            lib_matches = re.findall(r'-l\w+', content)
            if lib_matches:
                extra_libs = ' '.join(sorted(set(lib_matches)))

        # Drop the entry from the SynthesizedDriver list — emit_oss_fuzz_
        # build_snippet only needs the language/N for snippet shape.
        # We keep entry in the on-disk dir so it gets compiled.
        non_entry_sources = [s for s in sources if s.stem != "entry"]
        if not non_entry_sources:
            logger.error("No sub-driver TUs found beside entry.*")
            return False
        try:
            drv = SynthesizedDriver.from_paths(non_entry_sources)
        except ValueError as e:
            logger.error(f"merged synth driver invalid: {e}")
            return False

        snippet = drv.emit_oss_fuzz_build_snippet(
            target_name=target_name,
            extra_libs=extra_libs,
            extra_includes=self.merged_build_includes,
            synth_dir_var="/src/synthesized",
        )
        with open(build_sh, 'a') as f:
            f.write(snippet)
        logger.info(
            f"Created merged project {self.generated_project_name} "
            f"({drv.driver_count} sub-drivers, "
            f"libs='{extra_libs}', includes='{self.merged_build_includes}')"
        )
        return True

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
                # The real docker/build error is at the TAIL of the combined
                # output (helper.py prints the build to stdout; the leading
                # 1000 chars are just its "Running: ..." banner).
                _tail = ((result.stdout or "") + (result.stderr or ""))[-3000:]
                logger.error(f"Failed to build image (tail):\n{_tail}")
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
                _tail = ((result.stdout or "") + (result.stderr or ""))[-3000:]
                logger.error(f"Failed to build fuzzers (tail):\n{_tail}")
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.error("Build timed out (try running with cached images or increase timeout)")
            return False
        except Exception as e:
            logger.error(f"Build failed: {e}")
            return False

    def _build_coverage_image(self) -> bool:
        """Build the coverage-instrumented binary into its OWN out dir.

        Builds project ``<gen>-cov`` so the profile-instrumented binary lands in
        build/out/<gen>-cov and does NOT clobber the sancov/libFuzzer binary in
        build/out/<gen> that the fuzzer runs. The cov project shares the address
        build's docker image (via ``docker tag``) so we skip a second
        build_image; only ``build_fuzzers --sanitizer coverage`` re-runs.
        """
        assert self.coverage_project_name, "coverage_project_name unset (setup not run)"
        logger.info(f"Building coverage image for {self.coverage_project_name}...")

        try:
            oss_fuzz_dir = self._get_oss_fuzz_dir()
            helper_py = oss_fuzz_dir / "infra" / "helper.py"

            # Reuse the already-built project image under the cov project name.
            tag_cmd = [
                "docker", "tag",
                f"gcr.io/oss-fuzz/{self.generated_project_name}",
                f"gcr.io/oss-fuzz/{self.coverage_project_name}",
            ]
            tag_res = subprocess.run(tag_cmd, capture_output=True, text=True)
            if tag_res.returncode != 0:
                logger.warning(
                    "docker tag for cov image failed (%s); falling back to "
                    "build_image", tag_res.stderr[:300])
                subprocess.run(
                    ["python3", str(helper_py), "build_image", "--no-pull",
                     self.coverage_project_name],
                    capture_output=True, text=True, timeout=1800)

            build_fuzzers_cmd = [
                "python3", str(helper_py),
                "build_fuzzers", "--sanitizer", "coverage",
                self.coverage_project_name
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

        # Mount a FRESH, uniquely-named copy of the corpus — NOT self.corpus_dir
        # directly. Bug: helper.py bind-mounts the host corpus to
        # /tmp/<target>_corpus and base-runner's run_fuzzer rm's/syncs it; on a
        # bind-mounted host dir that races ("rm: Device or resource busy" →
        # "0 files found in corpus" → libFuzzer starts from EMPTY, so the real
        # seeds never reach the fuzzer). A fresh per-run dir has no stale mount
        # holder and a unique name (no cross-run TOCTOU), so the seeds load.
        # We snapshot the new units back into self.corpus_dir after the run.
        import tempfile
        self._run_corpus_dir = Path(tempfile.mkdtemp(
            prefix=f"lf_corpus_{self.target_name}_"))
        n_staged = 0
        for src in self.corpus_dir.glob("*"):
            if src.is_file():
                try:
                    shutil.copy(src, self._run_corpus_dir / src.name)
                    n_staged += 1
                except OSError:
                    continue
        logger.info("Staged %d seeds into fresh run-corpus %s",
                    n_staged, self._run_corpus_dir)
        corpus_dir_abs = str(self._run_corpus_dir.resolve())

        run_cmd = [
            "python3", str(helper_py),
            "run_fuzzer",
            # CRITICAL: set CORPUS_DIR to the in-container mount path. Without
            # it, base-runner's run_fuzzer script defaults CORPUS_DIR to
            # /tmp/<fuzzer>_corpus AND does `rm -rf` + recreate it — which wipes
            # the seeds we bind-mounted there (helper.py mounts host corpus →
            # /tmp/<fuzzer>_corpus but never exports CORPUS_DIR). Result was
            # `corp: 1/1b` / "target rejected all inputs" — seeds never loaded,
            # so a strict-format target (lcms .icc) got ZERO real fuzzing even
            # over 4h/268M execs. Setting CORPUS_DIR makes run_fuzzer take the
            # else-branch (use the dir as-is, no rm).
            "-e", f"CORPUS_DIR=/tmp/{self.target_name}_corpus",
            "--corpus-dir", corpus_dir_abs,
            self.generated_project_name,
            self.target_name,
            "--",
            f"-max_total_time={self.duration}",
            "-print_final_stats=1",
            "-detect_leaks=0",
            # artifact_prefix must be a path that exists INSIDE the runner
            # container — the host crashes dir isn't mounted there, so passing
            # it makes libFuzzer abort ("required directory does not exist")
            # before fuzzing. ``/tmp/`` always exists in base-runner. (Host-side
            # crash collection needs a separate volume mount — tracked apart;
            # the priority here is that the fuzzer actually RUNS so coverage is
            # measurable.) ``crashes_dir_abs`` retained for host-side globbing.
            "-artifact_prefix=/tmp/",
            # Continue fuzzing after crashes (standard practice for 24h evaluation)
            # -ignore_crashes=1: Save crash but continue fuzzing
            "-ignore_crashes=1",
            "-ignore_timeouts=1",
            "-ignore_ooms=1",
            # Raise the RSS ceiling: a merged harness runs N sub-drivers in one
            # process and their cumulative allocations + libFuzzer's own corpus
            # bookkeeping blow past the 2560Mb default in minutes, killing a
            # long run prematurely (observed: c-ares OOM at 2622Mb after ~30s,
            # ending a 4h run early). 8Gb lets a long campaign actually run.
            "-rss_limit_mb=8192",
            # Bound per-input memory so a single pathological input can't OOM
            # the whole run (-malloc_limit defaults to rss_limit; keep it lower).
            "-malloc_limit_mb=3072",
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

            # Pull the post-fuzz corpus (seeds + newly-discovered units) back
            # from the fresh run-corpus dir into self.corpus_dir, so coverage is
            # measured over what the fuzzer actually accumulated — not just the
            # original seeds. (The run-corpus is the bind-mounted dir libFuzzer
            # wrote into; see _run_fuzzer for the mount-race rationale.)
            run_corpus = getattr(self, "_run_corpus_dir", None)
            if run_corpus and Path(run_corpus).is_dir():
                pulled = 0
                for src in Path(run_corpus).glob("*"):
                    if src.is_file():
                        dst = self.corpus_dir / src.name
                        if not dst.exists():
                            try:
                                shutil.copy(src, dst)
                                pulled += 1
                            except OSError:
                                continue
                logger.info("Pulled %d post-fuzz units back from run-corpus",
                            pulled)
            # Defensive: if still empty (e.g. seeding failed entirely), re-seed.
            corpus_files = list(self.corpus_dir.glob("*"))
            if not corpus_files:
                logger.info("Corpus empty after run; re-seeding before coverage")
                self._ensure_seed_corpus()
                corpus_files = list(self.corpus_dir.glob("*"))
            if not corpus_files:
                logger.warning("Corpus directory is empty, skipping coverage measurement")
                return None
            logger.info("Measuring coverage over %d corpus inputs", len(corpus_files))

            # Run coverage measurement
            coverage_cmd = [
                "python3", str(helper_py),
                "coverage",
                "--corpus-dir", corpus_dir_abs,
                "--fuzz-target", self.target_name,
                "--no-serve",
                "--port", "",
                # Measure against the coverage-instrumented build (its own out
                # dir), NOT the address build the fuzzer runs.
                self.coverage_project_name
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
            if not self.coverage_project_name:
                logger.warning("No coverage project name")
                return None
            build_out = oss_fuzz_dir / "build" / "out" / self.coverage_project_name
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

        # Remove the per-run staging corpus (already pulled back into corpus_dir).
        run_corpus = getattr(self, "_run_corpus_dir", None)
        if run_corpus:
            try:
                shutil.rmtree(run_corpus, ignore_errors=True)
            except Exception:
                pass

        for proj in (self.generated_project_name, self.coverage_project_name):
            if not proj:
                continue
            try:
                oss_fuzz_dir = self._get_oss_fuzz_dir()
                project_dir = oss_fuzz_dir / "projects" / proj
                if project_dir.exists():
                    shutil.rmtree(project_dir)
                    logger.info(f"Cleaned up project {proj}")
            except Exception as e:
                logger.warning(f"Failed to cleanup: {e}")

    def run(self) -> ExtendedFuzzingResult:
        """Run extended fuzzing and collect results."""
        start_time = datetime.now()
        logger.info(f"Starting extended fuzzing for {self.project}")
        logger.info(f"Duration: {self.duration}s, Snapshot interval: {self.snapshot_interval}s")

        result = ExtendedFuzzingResult(
            project=self.project,
            fuzz_target_path=str(self.fuzz_target_path or self.fuzz_target_dir),
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
        default=None,
        help="Path to a single fuzz target source file"
    )
    parser.add_argument(
        "--fuzz-target-dir",
        default=None,
        help="Path to a synthesized/ directory produced by "
             "tools/merge_drivers (multi-TU merged harness)"
    )
    parser.add_argument(
        "--seed-corpus-dir",
        default=None,
        help="Optional pre-tagged seed corpus to copy into corpus/ "
             "before fuzzing starts (e.g. corpus_merged/ from "
             "tools/merge_drivers pipeline)"
    )
    parser.add_argument(
        "--merged-libs",
        default="",
        help="(merged-dir mode) extra link libs for the merged harness "
             "build snippet (default: auto-detect -l flags from project's "
             "build.sh)"
    )
    parser.add_argument(
        "--merged-includes",
        default="",
        help="(merged-dir mode) extra -I flags for the merged harness "
             "build snippet"
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

    # Validate fuzz target spec — exactly one of --fuzz-target /
    # --fuzz-target-dir is required.
    if (args.fuzz_target is None) == (args.fuzz_target_dir is None):
        logger.error(
            "exactly one of --fuzz-target / --fuzz-target-dir is required"
        )
        sys.exit(2)
    if args.fuzz_target and not os.path.exists(args.fuzz_target):
        logger.error(f"Fuzz target not found: {args.fuzz_target}")
        sys.exit(1)
    if args.fuzz_target_dir and not os.path.isdir(args.fuzz_target_dir):
        logger.error(f"Fuzz target dir not found: {args.fuzz_target_dir}")
        sys.exit(1)

    # Run extended fuzzing
    fuzzer = ExtendedFuzzer(
        project=args.project,
        fuzz_target_path=args.fuzz_target,
        fuzz_target_dir=args.fuzz_target_dir,
        seed_corpus_dir=args.seed_corpus_dir,
        merged_build_libs=args.merged_libs,
        merged_build_includes=args.merged_includes,
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
