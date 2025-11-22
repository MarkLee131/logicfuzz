"""
LLVM API 提取器

使用 Liberator 的 condition_extractor/bin/extractor 从 bitcode 提取 apis_llvm.json
"""
import os
import logging
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

logger = logging.getLogger(__name__)


class LLVMAPIExtractor:
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
        self.benchmark = benchmark
        self.container = container or ProjectContainerTool(benchmark, name='llvm_extract')
        
        # Liberator 工具路径
        self.liberator_root = Path(__file__).parent.parent.parent / 'liberator'
        self.extractor_bin = self.liberator_root / 'condition_extractor' / 'bin' / 'extractor'
        
        if not self.extractor_bin.exists():
            logger.warning(f"Liberator extractor binary not found at {self.extractor_bin}")
    
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
        self.container.execute(f'mkdir -p {output_dir}')
        
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
            for alt_path in alt_paths:
                if self._file_exists_in_container(alt_path):
                    logger.info(f"Found apis_llvm.json at {alt_path}")
                    return alt_path
            raise RuntimeError(f"Output file apis_llvm.json was not created in {output_dir}")
        
        logger.info(f"Successfully extracted apis_llvm.json to {apis_llvm_path}")
        return apis_llvm_path
    
    def _file_exists_in_container(self, file_path: str) -> bool:
        """检查容器内文件是否存在"""
        result = self.container.execute(f'test -f "{file_path}" && echo "exists" || echo "not_found"')
        return result.stdout.strip() == 'exists'
    
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
        extract_result = self.container.execute(f'extract-bc -b "{output_bc.replace(".bc", "")}"')
        if extract_result.returncode != 0:
            raise RuntimeError(f"Failed to extract bitcode: {extract_result.stderr}")
        
        if not self._file_exists_in_container(output_bc):
            raise RuntimeError(f"Bitcode file {output_bc} was not created")
        
        logger.info(f"Successfully created bitcode file: {output_bc}")
        return output_bc
    
    def _find_or_copy_extractor(self) -> str:
        """
        查找或复制 extractor 到容器内
        
        Returns:
            容器内的 extractor 路径
        """
        # 尝试的路径列表
        possible_paths = [
            '/liberator/condition_extractor/bin/extractor',
            '/tmp/extractor',
            '/usr/local/bin/extractor',
        ]
        
        # 检查 extractor 是否已存在
        for path in possible_paths:
            if self._file_exists_in_container(path):
                # 检查是否可执行
                result = self.container.execute(f'test -x "{path}" && echo "executable" || echo "not_executable"')
                if result.stdout.strip() == 'executable':
                    return path
        
        # 如果不存在，尝试复制到容器内
        container_extractor_path = '/tmp/extractor'
        try:
            import subprocess as sp
            # 使用 docker cp 复制 extractor（需要复制整个目录结构）
            # 先创建目录
            self.container.execute('mkdir -p /tmp/condition_extractor/bin')
            
            # 复制 extractor 二进制文件
            cmd = [
                'docker', 'cp',
                str(self.extractor_bin),
                f'{self.container.container_id}:{container_extractor_path}'
            ]
            result = sp.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                # 设置执行权限
                self.container.execute(f'chmod +x {container_extractor_path}')
                logger.info(f"Copied extractor to container: {container_extractor_path}")
                return container_extractor_path
            else:
                logger.warning(f"Failed to copy extractor: {result.stderr}")
        except Exception as e:
            logger.warning(f"Error copying extractor: {e}")
        
        # 如果复制失败，尝试使用容器内可能已安装的版本
        result = self.container.execute('which extractor || echo "not_found"')
        if 'not_found' not in result.stdout:
            return 'extractor'
        
        # 最后尝试：假设 extractor 在 /liberator（如果容器已挂载）
        return possible_paths[0]
    
    def cleanup(self):
        """清理资源（关闭容器等）"""
        if self.container:
            self.container.terminate()

