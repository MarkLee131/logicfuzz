"""
Base API Extractor

提供所有 API 提取器的公共基类功能
"""
import logging
import subprocess
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

logger = logging.getLogger(__name__)


class BaseAPIExtractor:
    """
    API 提取器基类
    
    提供公共功能：
    - 容器操作
    - 文件存在性检查
    - 资源清理
    - 错误处理
    """
    
    def __init__(
        self,
        benchmark: Benchmark,
        container: Optional[ProjectContainerTool] = None,
        container_name: Optional[str] = None
    ):
        """
        初始化基类
        
        Args:
            benchmark: 项目基准对象
            container: 可选的容器工具（如果已创建）
            container_name: 容器名称（用于创建新容器）
        """
        self.benchmark = benchmark
        self.container = container or ProjectContainerTool(
            benchmark,
            name=container_name or 'api_extract'
        )
        
        # Liberator 工具路径：严格使用 liberator_adapter/liberator 下的文件
        self.liberator_root = Path(__file__).parent.parent / 'liberator'
        
        if not self.liberator_root.exists():
            raise RuntimeError(
                f"Required liberator directory not found at {self.liberator_root}. "
                "Please ensure liberator_adapter/liberator is present."
            )
    
    def _file_exists_in_container(self, file_path: str) -> bool:
        """
        检查容器内文件是否存在
        
        Args:
            file_path: 文件路径（容器内路径）
        
        Returns:
            文件是否存在
        """
        result = self.container.execute(
            f'test -f "{file_path}" && echo "exists" || echo "not_found"'
        )
        return result.stdout.strip() == 'exists'
    
    def _dir_exists_in_container(self, dir_path: str) -> bool:
        """
        检查容器内目录是否存在
        
        Args:
            dir_path: 目录路径（容器内路径）
        
        Returns:
            目录是否存在
        """
        result = self.container.execute(
            f'test -d "{dir_path}" && echo "exists" || echo "not_found"'
        )
        return result.stdout.strip() == 'exists'
    
    def _ensure_output_dir(self, output_dir: str) -> None:
        """
        确保输出目录存在
        
        Args:
            output_dir: 输出目录路径（容器内路径）
        """
        result = self.container.execute(f'mkdir -p {output_dir}')
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to create output directory {output_dir}: {result.stderr}"
            )
    
    def _copy_file_to_container(
        self,
        host_path: Path,
        container_path: str,
        make_executable: bool = False
    ) -> str:
        """
        复制文件到容器
        
        Args:
            host_path: 主机上的文件路径
            container_path: 容器内的目标路径
            make_executable: 是否设置为可执行
        
        Returns:
            容器内的文件路径
        """
        if not host_path.exists():
            raise FileNotFoundError(f"Source file not found: {host_path}")
        
        try:
            cmd = [
                'docker', 'cp',
                str(host_path),
                f'{self.container.container_id}:{container_path}'
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            if make_executable:
                self.container.execute(f'chmod +x {container_path}')
            
            logger.info(f"Copied file to container: {host_path} -> {container_path}")
            return container_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Failed to copy file to container: {e.stderr}"
            )
    
    def _copy_dir_to_container(
        self,
        host_dir: Path,
        container_dir: str
    ) -> str:
        """
        复制目录到容器
        
        Args:
            host_dir: 主机上的目录路径
            container_dir: 容器内的目标目录路径
        
        Returns:
            容器内的目录路径
        """
        if not host_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {host_dir}")
        
        try:
            cmd = [
                'docker', 'cp',
                str(host_dir),
                f'{self.container.container_id}:{container_dir}'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Copied directory to container: {host_dir} -> {container_dir}")
            return container_dir
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Failed to copy directory to container: {e.stderr}"
            )
    
    def _execute_with_error_check(
        self,
        cmd: str,
        error_msg: str,
        check_output: bool = False,
        output_file: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """
        执行命令并检查错误
        
        Args:
            cmd: 要执行的命令
            error_msg: 错误消息前缀
            check_output: 是否检查输出文件
            output_file: 输出文件路径（如果 check_output=True）
        
        Returns:
            命令执行结果
        
        Raises:
            RuntimeError: 如果命令执行失败或输出文件不存在
        """
        logger.debug(f"Executing command: {cmd}")
        result = self.container.execute(cmd)
        
        if result.returncode != 0:
            full_error = f"{error_msg}: {result.stderr}"
            if result.stdout:
                full_error += f"\nSTDOUT: {result.stdout}"
            logger.error(full_error)
            raise RuntimeError(full_error)
        
        if check_output and output_file:
            if not self._file_exists_in_container(output_file):
                raise RuntimeError(
                    f"{error_msg}: Output file {output_file} was not created"
                )
        
        return result
    
    def _find_file_in_container(
        self,
        search_paths: list[str],
        check_executable: bool = False
    ) -> Optional[str]:
        """
        在容器的多个可能路径中查找文件
        
        Args:
            search_paths: 要搜索的路径列表
            check_executable: 是否检查文件可执行性
        
        Returns:
            找到的文件路径，如果未找到则返回 None
        """
        for path in search_paths:
            if self._file_exists_in_container(path):
                if check_executable:
                    result = self.container.execute(
                        f'test -x "{path}" && echo "executable" || echo "not_executable"'
                    )
                    if result.stdout.strip() != 'executable':
                        continue
                return path
        return None
    
    def cleanup(self):
        """清理资源（关闭容器等）"""
        if self.container:
            self.container.terminate()

