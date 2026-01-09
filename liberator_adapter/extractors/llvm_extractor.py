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
    
    def extract_apis_llvm(
        self,
        bc_file: str,
        apis_clang_path: str,
        output_dir: str = '/tmp/liberator_extract'
    ) -> str:
        """
        从 bitcode 文件提取 apis_llvm.json
        
        Args:
            bc_file: LLVM bitcode 文件路径（容器内路径，如 libz.a.bc）
            apis_clang_path: apis_clang.json 文件路径（容器内路径）
            output_dir: 输出目录（容器内路径）
        
        Returns:
            apis_llvm.json 的路径（容器内路径）
        """
        # 确保输出目录存在
        self._ensure_output_dir(output_dir)
        
        # 设置环境变量（extractor 会使用 LIBFUZZ_LOG_PATH）
        self.container.execute(f'export LIBFUZZ_LOG_PATH={output_dir}')
        
        # 准备输出文件路径
        conditions_path = f'{output_dir}/conditions.json'
        minimized_apis_path = f'{output_dir}/apis_minimized.txt'
        data_layout_path = f'{output_dir}/data_layout.txt'
        apis_llvm_path = f'{output_dir}/apis_llvm.json'
        
        # 构建命令
        # 查找或复制 extractor 到容器内
        extractor_path = self._find_or_copy_extractor()
        
        cmd = (
            f'export LIBFUZZ_LOG_PATH={output_dir} && '
            f'{extractor_path} '
            f'"{bc_file}" '
            f'-interface "{apis_clang_path}" '
            f'-output "{conditions_path}" '
            f'-minimize_api "{minimized_apis_path}" '
            f'-v v0 -t json -do_indirect_jumps '
            f'-data_layout "{data_layout_path}"'
        )
        
        logger.info(f"Extracting apis_llvm.json with command: {cmd}")
        result = self.container.execute(cmd)
        
        if result.returncode != 0:
            error_msg = f"LLVM extraction failed: {result.stderr}"
            logger.error(error_msg)
            logger.error(f"STDOUT: {result.stdout}")
            raise RuntimeError(error_msg)
        
        # 验证输出文件是否存在
        # 注意：extractor 可能将 apis_llvm.json 写入到 LIBFUZZ_LOG_PATH
        if not self._file_exists_in_container(apis_llvm_path):
            # 尝试查找其他可能的位置
            logger.warning(f"apis_llvm.json not found at {apis_llvm_path}, checking alternative locations")
            # extractor 可能直接写入到当前目录或 LIBFUZZ_LOG_PATH
            alt_paths = [
                f'{output_dir}/apis_llvm.json',
                './apis_llvm.json',
                f'{os.path.dirname(bc_file)}/apis_llvm.json',
            ]
            found_path = self._find_file_in_container(alt_paths)
            if found_path:
                logger.info(f"Found apis_llvm.json at {found_path}")
                return found_path
            raise RuntimeError(f"Output file apis_llvm.json was not created in {output_dir}")
        
        logger.info(f"Successfully extracted apis_llvm.json to {apis_llvm_path}")
        return apis_llvm_path
    
    def compile_to_bitcode(
        self,
        source_dir: Optional[str] = None,
        output_bc: Optional[str] = None
    ) -> str:
        """
        使用 wllvm 编译项目到 bitcode
        
        Args:
            source_dir: 源代码目录（默认使用 project_dir）
            output_bc: 输出 bitcode 文件路径（可选）
        
        Returns:
            bitcode 文件路径
        """
        if not source_dir:
            source_dir = self.container.project_dir
        
        # 检查是否已安装 wllvm
        result = self.container.execute('which wllvm')
        if result.returncode != 0:
            logger.warning("wllvm not found, attempting to install...")
            # 尝试安装 wllvm
            install_result = self.container.execute('pip install wllvm || pip3 install wllvm')
            if install_result.returncode != 0:
                raise RuntimeError("Failed to install wllvm. Please install it manually.")
        
        # 设置 wllvm 环境变量
        self.container.execute('export LLVM_COMPILER=clang')
        self.container.execute('export LLVM_COMPILER_PATH=$(which clang | xargs dirname)')
        
        # 编译项目（使用项目的 build.sh）
        logger.info("Compiling project with wllvm...")
        compile_result = self.container.compile()
        if compile_result.returncode != 0:
            raise RuntimeError(f"Failed to compile project: {compile_result.stderr}")
        
        # 提取 bitcode（假设库文件在标准位置）
        # 这需要根据项目结构调整
        if not output_bc:
            # 尝试查找 .a 文件
            find_result = self.container.execute(
                f'find {source_dir} -name "*.a" -type f | head -1'
            )
            if find_result.returncode == 0 and find_result.stdout.strip():
                lib_file = find_result.stdout.strip()
                output_bc = f'{lib_file}.bc'
            else:
                raise RuntimeError("Could not find library file to extract bitcode from")
        
        # 使用 extract-bc 提取 bitcode
        self._execute_with_error_check(
            f'extract-bc -b "{output_bc.replace(".bc", "")}"',
            "Failed to extract bitcode",
            check_output=True,
            output_file=output_bc
        )
        
        logger.info(f"Successfully created bitcode file: {output_bc}")
        return output_bc
    
    def _find_or_copy_extractor(self) -> str:
        """
        查找或复制 extractor 到容器内
        
        Returns:
            容器内的 extractor 路径
        """
        # First, check if extractor already exists and is executable in container.
        container_possible = [
            '/liberator/condition_extractor/bin/extractor',
            '/usr/local/bin/extractor',
            '/tmp/extractor'
        ]
        found_path = self._find_file_in_container(container_possible, check_executable=True)
        if found_path:
            return found_path

        # If host has a prebuilt extractor binary at self.extractor_bin, copy it into container.
        if self.extractor_bin.exists():
            container_extractor_path = '/tmp/extractor'
            try:
                self._copy_file_to_container(
                    self.extractor_bin,
                    container_extractor_path,
                    make_executable=True
                )
                logger.info(f"Copied extractor binary to container: {container_extractor_path}")
                return container_extractor_path
            except Exception as e:
                logger.warning(f"Error copying extractor binary into container: {e}")

        # As a final step, copy the condition_extractor source into container and build it there.
        src_dir = self.liberator_root / 'condition_extractor'
        if not src_dir.exists():
            raise RuntimeError(
                f"Condition extractor source not found at {src_dir}; cannot build extractor."
            )

        container_dest = '/liberator/condition_extractor'
        try:
            # copy source dir into container
            self._copy_dir_to_container(src_dir, container_dest)
            logger.info('Copied condition_extractor sources into container at %s', container_dest)
            
            # Build inside container
            build_cmds = (
                f'cd {container_dest} && mkdir -p build && cd build && cmake .. && make -j$(nproc)'
            )
            build_result = self.container.execute(build_cmds)
            if build_result.returncode != 0:
                logger.error(
                    'Failed to build condition_extractor in container: %s',
                    build_result.stderr
                )
                raise RuntimeError('Building condition_extractor in container failed.')
            
            extractor_path = f'{container_dest}/bin/extractor'
            if self._file_exists_in_container(extractor_path):
                logger.info('Built extractor at %s', extractor_path)
                return extractor_path
            else:
                raise RuntimeError('Extractor binary not found after build in container.')
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f'Failed to copy condition_extractor sources into container: {e}'
            )

