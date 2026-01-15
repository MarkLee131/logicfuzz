"""
LLVM API 提取器

使用 Liberator 的 condition_extractor/bin/extractor 从 bitcode 提取 apis_llvm.json
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
    使用 LLVM bitcode 提取 API 信息
    
    封装 liberator/condition_extractor/bin/extractor
    """
    
    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None):
        """
        初始化 LLVM API 提取器
        
        Args:
            benchmark: 项目基准对象
            container: 可选的容器工具（如果已创建）
        """
        super().__init__(benchmark, container, container_name='llvm_extract')
        
        # Liberator 工具路径：严格使用 liberator_adapter/liberator 下的文件
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
        使用 wllvm 编译项目到 bitcode

        使用clang-12来编译，以确保生成的bitcode与host上的extractor兼容
        (host的extractor是用LLVM 14构建的，不支持opaque pointers)
        clang-12 生成的bitcode使用typed pointers，与LLVM 14兼容

        Args:
            source_dir: 源代码目录（默认使用 project_dir）
            output_bc: 输出 bitcode 文件路径（可选）

        Returns:
            bitcode 文件路径
        """
        if not source_dir:
            source_dir = self.container.project_dir

        # 确保 wllvm 和 clang-14 已安装（通过自定义base-builder镜像预装）
        self._ensure_wllvm_installed()
        self._ensure_clang14_installed()

        # 编译项目：使用 clang-14 而不是默认的 clang (可能是22+)
        # 这样生成的bitcode不使用opaque pointers，与host的extractor兼容
        # 注意：禁用sanitizers，因为clang-14没有对应的运行时库
        # 我们只需要bitcode用于静态分析，不需要sanitizers
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
        compile_result = self.container.execute(compile_cmd)
        # Note: compile script may fail when building fuzz targets (libc++ issues)
        # but the library itself might have been built successfully
        if compile_result.returncode != 0:
            logger.warning(f"Compile script returned error, but library may still exist")
            logger.debug(f"Compile output: {compile_result.stdout}")

        # 查找库文件并提取 bitcode
        if not output_bc:
            find_result = self.container.execute(
                f'find {source_dir} -name "*.a" -type f | head -1'
            )
            if find_result.returncode == 0 and find_result.stdout.strip():
                lib_file = find_result.stdout.strip()
                output_bc = f'{lib_file}.bc'
            else:
                raise RuntimeError("Could not find library file to extract bitcode from")

        # 使用 extract-bc 提取 bitcode（使用 clang-14）
        extract_cmd = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            f'extract-bc -b "{output_bc.replace(".bc", "")}"'
        )
        result = self.container.execute(extract_cmd)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to extract bitcode: {result.stderr}")

        if not self._file_exists_in_container(output_bc):
            raise RuntimeError(f"Output file {output_bc} was not created")

        logger.info(f"Successfully created bitcode file: {output_bc}")
        return output_bc

    def _ensure_clang14_installed(self):
        """确保 clang-14 已安装（应该已经在自定义base-builder镜像中预装）"""
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
        """确保 wllvm 已安装"""
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
        在Host上运行extractor分析bitcode（推荐方式）

        这种方式避免了在每个容器内配置复杂的LLVM/SVF/Z3依赖。
        Host上的extractor只需构建一次，所有项目都可以复用。

        Args:
            bc_file: 容器内的bitcode文件路径
            apis_clang_path: 容器内的apis_clang.json路径
            output_dir: 本地输出目录

        Returns:
            apis_llvm.json的本地路径
        """
        import tempfile
        import shutil

        # 验证host上的extractor存在
        if not self.extractor_bin.exists():
            raise RuntimeError(
                f"Extractor binary not found at {self.extractor_bin}. "
                f"Please build it first: cd liberator_adapter/liberator/condition_extractor && ./bootstrap.sh"
            )

        # 创建临时目录用于host端处理
        temp_dir = tempfile.mkdtemp(prefix='llvm_extract_')
        logger.info(f'Created temp directory for host extraction: {temp_dir}')

        try:
            # 1. 从容器复制bitcode文件到host
            local_bc_file = os.path.join(temp_dir, 'input.bc')
            self._copy_from_container(bc_file, local_bc_file, required=True)
            logger.info(f'Copied bitcode from container: {bc_file} -> {local_bc_file}')

            # 2. 从容器复制apis_clang.json到host
            local_apis_clang = os.path.join(temp_dir, 'apis_clang.json')
            self._copy_from_container(apis_clang_path, local_apis_clang, required=True)
            logger.info(f'Copied apis_clang.json from container')

            # 3. 准备输出文件路径
            local_conditions = os.path.join(temp_dir, 'conditions.json')
            local_apis_llvm = os.path.join(temp_dir, 'apis_llvm.json')
            local_data_layout = os.path.join(temp_dir, 'data_layout.txt')
            local_minimized_apis = os.path.join(temp_dir, 'apis_minimized.txt')

            # 4. 在host上运行extractor
            # 需要设置环境变量
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

            # 5. 复制结果到output目录
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
            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f'Cleaned up temp directory: {temp_dir}')

