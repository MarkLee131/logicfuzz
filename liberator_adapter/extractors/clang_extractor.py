"""
Clang API 提取器

使用 Liberator 的 extract_included_functions.py 从头文件提取 apis_clang.json
"""
import os
import logging
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

logger = logging.getLogger(__name__)


class ClangAPIExtractor:
    """
    使用 Clang Python bindings 从头文件提取 API 信息
    
    封装 liberator/tool/misc/extract_included_functions.py
    """
    
    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None):
        """
        初始化 Clang API 提取器
        
        Args:
            benchmark: 项目基准对象
            container: 可选的容器工具（如果已创建）
        """
        self.benchmark = benchmark
        self.container = container or ProjectContainerTool(benchmark, name='clang_extract')
        
        # Liberator 工具路径（相对于项目根目录）
        self.liberator_root = Path(__file__).parent.parent.parent / 'liberator'
        self.extract_script = self.liberator_root / 'tool' / 'misc' / 'extract_included_functions.py'
        
        if not self.extract_script.exists():
            logger.warning(f"Liberator extract script not found at {self.extract_script}")
    
    def extract_apis_clang(
        self,
        include_dir: str,
        public_headers_file: Optional[str] = None,
        output_dir: str = '/tmp/liberator_extract',
        project_name: Optional[str] = None
    ) -> str:
        """
        提取 apis_clang.json
        
        Args:
            include_dir: 头文件目录（容器内路径）
            public_headers_file: 公共头文件列表（可选，容器内路径）
            output_dir: 输出目录（容器内路径）
            project_name: 项目名称（用于查找 public_headers.txt）
        
        Returns:
            apis_clang.json 的路径（容器内路径）
        """
        # 确保输出目录存在
        self.container.execute(f'mkdir -p {output_dir}')
        
        # 准备输出文件路径
        apis_clang_path = f'{output_dir}/apis_clang.json'
        exported_functions_path = f'{output_dir}/exported_functions.txt'
        incomplete_types_path = f'{output_dir}/incomplete_types.txt'
        enum_types_path = f'{output_dir}/enum_types.txt'
        
        # 构建命令
        # 尝试多种可能的脚本路径
        # 1. 如果 liberator 已挂载到容器内
        # 2. 如果脚本已复制到容器内
        # 3. 使用 docker cp 临时复制（如果前两种都不可用）
        script_path = self._find_or_copy_script()
        
        cmd_parts = [
            f'python3 {script_path}',
            f'-i "{include_dir}"',
            f'-e "{exported_functions_path}"',
            f'-t "{incomplete_types_path}"',
            f'-a "{apis_clang_path}"',
            f'-n "{enum_types_path}"',
        ]
        
        # 添加 public_headers 文件（如果提供）
        if public_headers_file:
            cmd_parts.insert(2, f'-p "{public_headers_file}"')
        elif project_name:
            # 尝试查找项目特定的 public_headers.txt
            project_headers = f'/liberator/targets/{project_name}/public_headers.txt'
            if self._file_exists_in_container(project_headers):
                cmd_parts.insert(2, f'-p "{project_headers}"')
        
        cmd = ' '.join(cmd_parts)
        
        logger.info(f"Extracting apis_clang.json with command: {cmd}")
        result = self.container.execute(cmd)
        
        if result.returncode != 0:
            error_msg = f"Clang extraction failed: {result.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # 验证输出文件是否存在
        if not self._file_exists_in_container(apis_clang_path):
            raise RuntimeError(f"Output file {apis_clang_path} was not created")
        
        logger.info(f"Successfully extracted apis_clang.json to {apis_clang_path}")
        return apis_clang_path
    
    def _file_exists_in_container(self, file_path: str) -> bool:
        """检查容器内文件是否存在"""
        result = self.container.execute(f'test -f "{file_path}" && echo "exists" || echo "not_found"')
        return result.stdout.strip() == 'exists'
    
    def _find_include_dir(self) -> Optional[str]:
        """
        自动查找项目的 include 目录
        
        Returns:
            include 目录路径（容器内），如果找不到则返回 None
        """
        # 常见的 include 目录位置
        possible_paths = [
            f'{self.container.project_dir}/include',
            f'{self.container.project_dir}/../include',
            '/usr/local/include',
            '/usr/include',
        ]
        
        for path in possible_paths:
            result = self.container.execute(f'test -d "{path}" && echo "exists" || echo "not_found"')
            if result.stdout.strip() == 'exists':
                return path
        
        return None
    
    def extract_with_auto_detect(
        self,
        output_dir: str = '/tmp/liberator_extract',
        project_name: Optional[str] = None
    ) -> str:
        """
        自动检测 include 目录并提取
        
        Args:
            output_dir: 输出目录
            project_name: 项目名称
        
        Returns:
            apis_clang.json 的路径
        """
        include_dir = self._find_include_dir()
        if not include_dir:
            raise RuntimeError("Could not find include directory. Please specify include_dir manually.")
        
        logger.info(f"Auto-detected include directory: {include_dir}")
        return self.extract_apis_clang(
            include_dir=include_dir,
            output_dir=output_dir,
            project_name=project_name or self.benchmark.project
        )
    
    def _find_or_copy_script(self) -> str:
        """
        查找或复制 extract_included_functions.py 到容器内
        
        Returns:
            容器内的脚本路径
        """
        # 尝试的路径列表
        possible_paths = [
            '/liberator/tool/misc/extract_included_functions.py',
            '/tmp/extract_included_functions.py',
            '/usr/local/bin/extract_included_functions.py',
        ]
        
        # 检查脚本是否已存在
        for path in possible_paths:
            if self._file_exists_in_container(path):
                return path
        
        # 如果不存在，尝试复制到容器内
        container_script_path = '/tmp/extract_included_functions.py'
        try:
            import subprocess as sp
            # 使用 docker cp 复制脚本
            cmd = [
                'docker', 'cp',
                str(self.extract_script),
                f'{self.container.container_id}:{container_script_path}'
            ]
            result = sp.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                logger.info(f"Copied script to container: {container_script_path}")
                return container_script_path
            else:
                logger.warning(f"Failed to copy script: {result.stderr}")
        except Exception as e:
            logger.warning(f"Error copying script: {e}")
        
        # 如果复制失败，尝试使用容器内可能已安装的版本
        # 检查是否可以通过 python -m 或直接调用
        result = self.container.execute('which extract_included_functions.py || echo "not_found"')
        if 'not_found' not in result.stdout:
            return 'extract_included_functions.py'
        
        # 最后尝试：假设脚本在 /liberator（如果容器已挂载）
        return possible_paths[0]
    
    def cleanup(self):
        """清理资源（关闭容器等）"""
        if self.container:
            self.container.terminate()

