"""
LLVM API Extractor

Uses Liberator's condition_extractor/bin/extractor to extract apis_llvm.json from bitcode
"""
import os
import logging
import subprocess
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark
from liberator_adapter.extractors.base_extractor import BaseAPIExtractor

logger = logging.getLogger(__name__)


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

        compile_cmd = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            'export CC=wllvm && '
            'export CXX=wllvm++ && '
            'export SANITIZER=none && '
            'export LIB_FUZZING_ENGINE="" && '
            'export FUZZING_ENGINE=none && '
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

            # 4. Run extractor on host
            # Need to set environment variables
            env = os.environ.copy()
            env['LIBFUZZ_LOG_PATH'] = temp_dir

            cmd = [
                str(self.extractor_bin),
                local_bc_file,
                '-interface', local_apis_clang,
                '-output', local_conditions,
                '-minimize_api', local_minimized_apis,
                '-v', 'v0',
                '-t', 'json',
                '-do_indirect_jumps',
                '-data_layout', local_data_layout
            ]

            logger.info(f'Running extractor on host: {" ".join(cmd)}')
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f'Extractor stdout: {result.stdout}')
                logger.error(f'Extractor stderr: {result.stderr}')
                raise RuntimeError(f'Extractor failed: {result.stderr}')

            logger.info('Extractor completed successfully on host')

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

