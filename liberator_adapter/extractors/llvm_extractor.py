"""
LLVM API Extractor

Uses Liberator's condition_extractor/bin/extractor to extract apis_llvm.json from bitcode
"""
import hashlib
import os
import logging
import shutil
import subprocess
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark
from liberator_adapter.extractors.base_extractor import BaseAPIExtractor

logger = logging.getLogger(__name__)

# SVF analysis cost splits two ways; the timeout here and the RLIMIT_AS cap
# below target each. TIME-bound libs (libtiff/libvpx) have large bitcode whose
# pointer analysis is super-linear: MEASURED 2026-06 both timed out at 7200s
# with TINY memory (libtiff 4.5GB, libvpx 7.7GB) — they need more WALL-TIME, not
# RAM. The old 600s hard-killed them into clang-only (no conditions.json) even
# though they built fine; raised default 600→1800s. For these set a long cap,
# e.g. LIBERATOR_SVF_TIMEOUT_SECS=14400 (4h) — extraction is one-time + disk-
# cached on success, so only libs that need it pay it, once. (MEMORY-bound libs
# like libucl don't converge — that's the RLIMIT_AS cap below, not this.)
_SVF_TIMEOUT_SECS = int(os.environ.get('LIBERATOR_SVF_TIMEOUT_SECS', '1800'))

# Memory cap (RLIMIT_AS, in GB) for the SVF extractor child. SVF on a non-
# converging bitcode can thrash the whole — SHARED — host. Capping the child's
# virtual address space makes a runaway fail its OWN malloc (→ std::bad_alloc →
# extractor aborts → caught → clang-only fallback) instead of triggering the
# host OOM-killer. VALIDATED 2026-06 on libucl: under a 48GB cap it aborted with
# std::bad_alloc deep in ucl_parse_csexp at ~37GB RSS (virtual > 48GB) —
# graceful clang-only, no host OOM. (libtiff/libvpx are NOT memory-bound —
# 4.5/7.7GB — so the cap never bites them; their wall is the timeout above.)
# 0 = no cap (default; preserves prior behaviour). Set e.g.
# LIBERATOR_SVF_MEM_GB=48 on a shared box so one extraction's virtual footprint
# can't eat a multi-user host. Timeout bounds WALL-TIME; this bounds MEMORY.
_SVF_MEM_GB = int(os.environ.get('LIBERATOR_SVF_MEM_GB', '0'))

# Projects where SVF's flow-sensitive analysis must be disabled because it
# won't converge (libucl has a callback fan-out from -do_indirect_jumps that
# makes SVF spin).  Comma-separated env override: LIBERATOR_SVF_LITE.
_SVF_LITE_PROJECTS: set = set(filter(
    None, os.environ.get("LIBERATOR_SVF_LITE", "libucl").split(",")))

# Per-project SVF resource overrides.  Heavy libs need a bigger one-time
# budget; the result is disk-cached forever after the first success.
# Keys: "timeout_secs" and "mem_gb".  Falls back to module defaults for
# projects not listed here.
_SVF_PROJECT_RESOURCES: dict = {
    "sqlite3": {"timeout_secs": 14400, "mem_gb": 0},    # time-bound amalgamation
    "libucl":  {"timeout_secs": 21600, "mem_gb": 140},  # big flow-sensitive budget
}


def svf_resources_for(project: str) -> dict:
    """Return {"timeout_secs", "mem_gb", "lite"} for *project*.

    Merges module-level defaults with any per-project overrides from
    _SVF_PROJECT_RESOURCES, then sets "lite" from _SVF_LITE_PROJECTS.
    """
    base = {"timeout_secs": _SVF_TIMEOUT_SECS, "mem_gb": _SVF_MEM_GB, "lite": False}
    base.update(_SVF_PROJECT_RESOURCES.get(project, {}))
    base["lite"] = project in _SVF_LITE_PROJECTS
    return base


def build_svf_cmd(
    extractor_bin: str,
    bc: str,
    interface: str,
    output: str,
    minimize: str,
    data_layout: str,
    lite: bool,
) -> list:
    """Build the extractor argv list.

    Includes ``-do_indirect_jumps`` only when *lite* is False (full mode).
    Always ends with ``-data_layout <data_layout>`` so the caller can rely on
    ``cmd[-1] == data_layout``.
    """
    cmd = [
        str(extractor_bin), bc,
        "-interface", interface,
        "-output", output,
        "-minimize_api", minimize,
        "-v", "v0",
        "-t", "json",
    ]
    if not lite:
        cmd.append("-do_indirect_jumps")  # callback fan-out; the libucl blow-up
    cmd += ["-data_layout", data_layout]
    return cmd


# clang>=15-only warning tokens that the base-builder (clang-22) injects into
# CFLAGS; clang-14 rejects them, which trips cmake's CHECK_C_COMPILER_FLAG probes.
_CLANG14_INCOMPATIBLE_FLAGS = ("-Wno-error=vla-cxx-extension",)


def sanitize_extraction_flags(flags, deny=_CLANG14_INCOMPATIBLE_FLAGS):
    """Drop clang-14-incompatible tokens; return (cleaned, stripped[])."""
    kept, stripped = [], []
    for tok in (flags or "").split():
        (stripped if tok in deny else kept).append(tok)
    return " ".join(kept), stripped


def _svf_preexec():
    """preexec_fn for the extractor subprocess: apply RLIMIT_AS (Unix). No-op
    when uncapped or `resource` is unavailable; best-effort (never raises)."""
    if _SVF_MEM_GB <= 0:
        return
    try:
        import resource
        nbytes = _SVF_MEM_GB * 1024 ** 3
        resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
    except Exception:
        pass

# Disk cache for SVF outputs keyed by bitcode hash. SVF is deterministic
# given a fixed binary version + same .bc input, so re-extraction is
# wasted CPU. Override path with LIBERATOR_SVF_CACHE_DIR.
_SVF_CACHE_DIR = Path(os.environ.get(
    'LIBERATOR_SVF_CACHE_DIR',
    str(Path.home() / '.cache' / 'logicfuzz' / 'svf')
))


def _bitcode_fingerprint(bc_path: str, extractor_bin: Path) -> str:
    """Hash the bitcode + extractor binary together so cache invalidates
    when either the input or the analysis tool changes."""
    h = hashlib.sha256()
    for p in (bc_path, str(extractor_bin)):
        if not os.path.exists(p):
            continue
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        h.update(b'\x00')
    return h.hexdigest()[:16]


class LLVMAPIExtractor(BaseAPIExtractor):
    """
    Extract API information using LLVM bitcode
    
    Wraps liberator/condition_extractor/bin/extractor
    """
    
    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None):
        """
        Initialize LLVM API extractor
        
        Args:
            benchmark: Project benchmark object
            container: Optional container tool (if already created)
        """
        super().__init__(benchmark, container, container_name='llvm_extract')
        
        # Liberator tool path: strictly use files under liberator_adapter/liberator
        self.extractor_bin = self.liberator_root / 'condition_extractor' / 'bin' / 'extractor'
    
    # NOTE: extract_apis_llvm (container-based) has been removed.
    # Use extract_apis_llvm_on_host instead, which runs the extractor on the host
    # to avoid complex dependency installation in each container.
    
    def compile_to_bitcode(
        self,
        source_dir: Optional[str] = None,
        output_bc: Optional[str] = None
    ) -> str:
        """
        Compile project to bitcode using wllvm

        Uses clang-14 to compile, ensuring generated bitcode is compatible with host extractor
        (host extractor is built with LLVM 14, doesn't support opaque pointers)
        clang-14 generated bitcode uses typed pointers, compatible with LLVM 14

        Args:
            source_dir: Source code directory (defaults to project_dir)
            output_bc: Output bitcode file path (optional)

        Returns:
            Bitcode file path
        """
        if not source_dir:
            source_dir = self.container.project_dir

        # Ensure wllvm and clang-14 are installed (pre-installed via custom base-builder image)
        self._ensure_wllvm_installed()
        self._ensure_clang14_installed()

        # Compile project: use clang-14 instead of default clang (may be 22+)
        # This way generated bitcode doesn't use opaque pointers, compatible with host extractor
        # Note: Disable sanitizers, as clang-14 doesn't have corresponding runtime libraries
        # We only need bitcode for static analysis, don't need sanitizers
        # Note: libc++-14-dev is pre-installed in logicfuzz/base-builder-llvm14 image
        logger.info("Compiling project with wllvm using clang-14...")

        # Fix A: strip clang-14-incompatible flags the base-builder (clang-22) injects.
        _cf = self.container.execute('echo "$CFLAGS"').stdout.strip()
        _cxf = self.container.execute('echo "$CXXFLAGS"').stdout.strip()
        _cf_clean, _cf_strip = sanitize_extraction_flags(_cf)
        _cxf_clean, _cxf_strip = sanitize_extraction_flags(_cxf)
        self.flags_stripped = sorted(set(_cf_strip) | set(_cxf_strip))
        if self.flags_stripped:
            logger.info("Stripped clang-14-incompatible flags: %s",
                        self.flags_stripped)

        compile_cmd = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            'export CC=wllvm && '
            'export CXX=wllvm++ && '
            'export SANITIZER=none && '
            'export LIB_FUZZING_ENGINE="" && '
            'export FUZZING_ENGINE=none && '
            f'export CFLAGS="{_cf_clean}" && '
            f'export CXXFLAGS="{_cxf_clean}" && '
            'compile 2>&1'
        )
        # Use longer timeout for compile (10 minutes) - complex projects like curl need more time
        compile_result = self.container.execute(compile_cmd, timeout=600)
        # Note: compile script may fail when building fuzz targets (libc++ issues)
        # but the library itself might have been built successfully
        if compile_result.returncode != 0:
            logger.warning(f"Compile script returned error, but library may still exist")
            # Show last 50 lines of compile output for debugging
            output_lines = compile_result.stdout.strip().split('\n')
            last_lines = '\n'.join(output_lines[-50:]) if len(output_lines) > 50 else compile_result.stdout
            logger.info(f"Compile output (last 50 lines):\n{last_lines}")

        # Find library file and extract bitcode
        if not output_bc:
            lib_file = None
            project_name = self.benchmark.project

            # Strategy 1: Search for project-named library (e.g., libcurl.a, libcjson.a)
            # This is the most reliable approach
            project_lib_patterns = [
                f'lib{project_name}*.a',
                f'lib{project_name}*.so',
                f'{project_name}*.a',
                f'{project_name}*.so',
            ]
            search_dirs = [f'/src/{project_name}', source_dir, '/src', '/out', '/work']

            for search_dir in search_dirs:
                for pattern in project_lib_patterns:
                    find_result = self.container.execute(
                        f'find {search_dir} -name "{pattern}" -type f 2>/dev/null | head -1'
                    )
                    if find_result.returncode == 0 and find_result.stdout.strip():
                        lib_file = find_result.stdout.strip()
                        logger.info(f"Found project library: {lib_file}")
                        break
                if lib_file:
                    break

            # Strategy 2: Fall back to any .a file in project-specific directory only
            if not lib_file:
                project_dir = f'/src/{project_name}'
                find_result = self.container.execute(
                    f'find {project_dir} -name "*.a" -type f 2>/dev/null | head -1'
                )
                if find_result.returncode == 0 and find_result.stdout.strip():
                    lib_file = find_result.stdout.strip()
                    logger.info(f"Found library in project dir: {lib_file}")

            if lib_file:
                output_bc = f'{lib_file}.bc'
            else:
                raise RuntimeError(
                    f"Could not find library file for project '{project_name}'. "
                    f"Searched for lib{project_name}*.a/.so in {search_dirs}"
                )

        # Use extract-bc to extract bitcode (using clang-14)
        logger.info(f"Extracting bitcode from: {output_bc.replace('.bc', '')}")
        extract_cmd = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            f'extract-bc -b "{output_bc.replace(".bc", "")}" 2>&1'
        )
        result = self.container.execute(extract_cmd)
        if result.returncode != 0:
            logger.error(f"extract-bc failed. Output: {result.stdout}")
            raise RuntimeError(f"Failed to extract bitcode: {result.stdout or result.stderr}")

        if not self._file_exists_in_container(output_bc):
            logger.error(f"Expected bitcode file not created: {output_bc}")
            # List what files exist in the directory
            dir_path = os.path.dirname(output_bc)
            ls_result = self.container.execute(f'ls -la {dir_path}/*.bc 2>/dev/null || echo "No .bc files found"')
            logger.info(f"BC files in directory: {ls_result.stdout}")
            raise RuntimeError(f"Output file {output_bc} was not created")

        logger.info(f"Successfully created bitcode file: {output_bc}")
        return output_bc

    def _ensure_clang14_installed(self):
        """Ensure clang-14 is installed (should already be pre-installed in custom base-builder image)"""
        result = self.container.execute('test -x /usr/lib/llvm-14/bin/clang && echo ok')
        if result.returncode == 0 and 'ok' in result.stdout:
            return

        # clang-14 not found - this should not happen with our custom base-builder
        raise RuntimeError(
            "clang-14 not found in container. "
            "Please ensure the container is built using 'logicfuzz/base-builder-llvm14' image. "
            "Run 'docker/build_custom_image.sh' to build the custom image, "
            "and use --enable-llvm-extraction flag to use it."
        )

    def _ensure_wllvm_installed(self):
        """Ensure wllvm is installed"""
        result = self.container.execute('which wllvm extract-bc')
        if result.returncode == 0:
            return
        
        logger.info("wllvm not found, installing...")
        install_result = self.container.execute('pip3 install wllvm || pip install wllvm')
        if install_result.returncode != 0:
            raise RuntimeError("Failed to install wllvm")
    
    def extract_apis_llvm_on_host(
        self,
        bc_file: str,
        apis_clang_path: str,
        output_dir: str
    ) -> str:
        """
        Run extractor on host to analyze bitcode (recommended approach)

        This approach avoids configuring complex LLVM/SVF/Z3 dependencies in each container.
        Host extractor only needs to be built once, can be reused for all projects.

        Args:
            bc_file: Bitcode file path in container
            apis_clang_path: apis_clang.json path in container
            output_dir: Local output directory

        Returns:
            Local path to apis_llvm.json
        """
        import tempfile
        import shutil

        # Verify extractor exists on host
        if not self.extractor_bin.exists():
            raise RuntimeError(
                f"Extractor binary not found at {self.extractor_bin}. "
                f"Please build it first: cd liberator_adapter/liberator/condition_extractor && ./bootstrap.sh"
            )

        # Create temporary directory for host-side processing
        temp_dir = tempfile.mkdtemp(prefix='llvm_extract_')
        logger.info(f'Created temp directory for host extraction: {temp_dir}')

        try:
            # 1. Copy bitcode file from container to host
            local_bc_file = os.path.join(temp_dir, 'input.bc')
            self._copy_from_container(bc_file, local_bc_file, required=True)
            logger.info(f'Copied bitcode from container: {bc_file} -> {local_bc_file}')

            # 2. Copy apis_clang.json from container to host
            local_apis_clang = os.path.join(temp_dir, 'apis_clang.json')
            self._copy_from_container(apis_clang_path, local_apis_clang, required=True)
            logger.info(f'Copied apis_clang.json from container')

            # 3. Prepare output file paths
            local_conditions = os.path.join(temp_dir, 'conditions.json')
            local_apis_llvm = os.path.join(temp_dir, 'apis_llvm.json')
            local_data_layout = os.path.join(temp_dir, 'data_layout.txt')
            local_minimized_apis = os.path.join(temp_dir, 'apis_minimized.txt')

            # 3.5 Cache lookup. SVF is deterministic in (bitcode, extractor)
            # so if we've analysed this exact bitcode + extractor binary
            # before, just copy the cached outputs back.
            cache_key = _bitcode_fingerprint(local_bc_file, self.extractor_bin)
            cache_slot = _SVF_CACHE_DIR / cache_key
            cached_conditions = cache_slot / 'conditions.json'
            cached_apis_llvm = cache_slot / 'apis_llvm.json'
            cached_data_layout = cache_slot / 'data_layout.txt'
            if cached_conditions.exists() and cached_data_layout.exists():
                logger.info(
                    'SVF cache HIT for bitcode %s (key=%s); skipping ~%ds '
                    'analysis', os.path.basename(bc_file), cache_key,
                    _SVF_TIMEOUT_SECS,
                )
                shutil.copy(cached_conditions, local_conditions)
                shutil.copy(cached_data_layout, local_data_layout)
                if cached_apis_llvm.exists():
                    shutil.copy(cached_apis_llvm, local_apis_llvm)
            else:
                # 4. Run extractor on host with a hard wall-time cap. SVF's
                # pointer analysis on some libraries (libucl) won't converge
                # in any reasonable resource budget; bound it so the pipeline
                # falls back to clang-only mode rather than swap-thrash.
                env = os.environ.copy()
                env['LIBFUZZ_LOG_PATH'] = temp_dir

                _res = svf_resources_for(self.benchmark.project)
                cmd = build_svf_cmd(
                    self.extractor_bin, local_bc_file,
                    local_apis_clang, local_conditions,
                    local_minimized_apis, local_data_layout,
                    lite=_res["lite"],
                )
                _timeout = _res["timeout_secs"]
                # Per-project mem cap: use the project-specific value when
                # > 0; otherwise fall back to the module-level _SVF_MEM_GB.
                _mem_gb = _res["mem_gb"] if _res["mem_gb"] > 0 else _SVF_MEM_GB
                _preexec = _svf_preexec if _mem_gb > 0 else None

                logger.info(
                    f'Running extractor on host (timeout {_timeout}s, '
                    f'lite={_res["lite"]}): {" ".join(str(a) for a in cmd)}'
                )
                try:
                    result = subprocess.run(
                        cmd, env=env, capture_output=True, text=True,
                        timeout=_timeout,
                        preexec_fn=_preexec,
                    )
                except subprocess.TimeoutExpired:
                    logger.error(
                        'Extractor exceeded %ds wall-time on bitcode %s; '
                        'killing — pipeline will fall back to clang-only mode',
                        _timeout, os.path.basename(bc_file),
                    )
                    raise RuntimeError(
                        f'Extractor timed out after {_timeout}s'
                    )

                if result.returncode != 0:
                    logger.error(f'Extractor stdout: {result.stdout}')
                    logger.error(f'Extractor stderr: {result.stderr}')
                    raise RuntimeError(f'Extractor failed: {result.stderr}')

                logger.info('Extractor completed successfully on host')

                # Populate cache for subsequent runs.
                try:
                    cache_slot.mkdir(parents=True, exist_ok=True)
                    if os.path.exists(local_conditions):
                        shutil.copy(local_conditions, cached_conditions)
                    if os.path.exists(local_data_layout):
                        shutil.copy(local_data_layout, cached_data_layout)
                    if os.path.exists(local_apis_llvm):
                        shutil.copy(local_apis_llvm, cached_apis_llvm)
                    logger.debug('SVF cache MISS → wrote slot %s', cache_slot)
                except OSError as exc:
                    logger.warning('Failed to populate SVF cache: %s', exc)

            # 5. Copy results to output directory
            os.makedirs(output_dir, exist_ok=True)

            final_conditions = os.path.join(output_dir, 'conditions.json')
            final_apis_llvm = os.path.join(output_dir, 'apis_llvm.json')
            final_data_layout = os.path.join(output_dir, 'data_layout.txt')

            if os.path.exists(local_conditions):
                shutil.copy(local_conditions, final_conditions)
                logger.info(f'Copied conditions.json to {final_conditions}')
            else:
                raise RuntimeError('conditions.json was not generated')

            if os.path.exists(local_apis_llvm):
                shutil.copy(local_apis_llvm, final_apis_llvm)
                logger.info(f'Copied apis_llvm.json to {final_apis_llvm}')

            if os.path.exists(local_data_layout):
                shutil.copy(local_data_layout, final_data_layout)
                logger.info(f'Copied data_layout.txt to {final_data_layout}')
            else:
                raise RuntimeError('data_layout.txt was not generated')

            return final_apis_llvm if os.path.exists(final_apis_llvm) else ''

        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f'Cleaned up temp directory: {temp_dir}')

