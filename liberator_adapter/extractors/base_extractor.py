"""
Base API Extractor

Provides common base class functionality for all API extractors
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
    Base class for API extractors
    
    Provides common functionality:
    - Container operations
    - File existence checks
    - Resource cleanup
    - Error handling
    """
    
    def __init__(
        self,
        benchmark: Benchmark,
        container: Optional[ProjectContainerTool] = None,
        container_name: Optional[str] = None,
        use_llvm14_builder: bool = False
    ):
        """
        Initialize base class

        Args:
            benchmark: Project benchmark object
            container: Optional container tool (if already created)
            container_name: Container name (for creating new container)
            use_llvm14_builder: Whether to use custom base-builder image with pre-installed LLVM 14
        """
        self.benchmark = benchmark
        self.container = container or ProjectContainerTool(
            benchmark,
            name=container_name or 'api_extract',
            use_llvm14_builder=use_llvm14_builder
        )
        
        # Liberator tool path: strictly use files under liberator_adapter/liberator
        self.liberator_root = Path(__file__).parent.parent / 'liberator'
        
        if not self.liberator_root.exists():
            raise RuntimeError(
                f"Required liberator directory not found at {self.liberator_root}. "
                "Please ensure liberator_adapter/liberator is present."
            )
    
    def _file_exists_in_container(self, file_path: str) -> bool:
        """
        Check if file exists in container
        
        Args:
            file_path: File path (container path)
        
        Returns:
            Whether file exists
        """
        result = self.container.execute(
            f'test -f "{file_path}" && echo "exists" || echo "not_found"'
        )
        return result.stdout.strip() == 'exists'
    
    def _dir_exists_in_container(self, dir_path: str) -> bool:
        """
        Check if directory exists in container
        
        Args:
            dir_path: Directory path (container path)
        
        Returns:
            Whether directory exists
        """
        result = self.container.execute(
            f'test -d "{dir_path}" && echo "exists" || echo "not_found"'
        )
        return result.stdout.strip() == 'exists'
    
    def _ensure_output_dir(self, output_dir: str) -> None:
        """
        Ensure output directory exists
        
        Args:
            output_dir: Output directory path (container path)
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
        Copy file to container
        
        Args:
            host_path: File path on host
            container_path: Target path in container
            make_executable: Whether to make it executable
        
        Returns:
            File path in container
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
        Copy directory to container
        
        Args:
            host_dir: Directory path on host
            container_dir: Target directory path in container
        
        Returns:
            Directory path in container
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
    
    def _copy_from_container(
        self,
        container_path: str,
        local_path: str,
        required: bool = True
    ) -> str:
        """
        Copy file from container to local
        
        Args:
            container_path: File path in container
            local_path: Local target path
            required: If True, raise exception when file doesn't exist; otherwise return empty string
        
        Returns:
            Local file path, or empty string if required=False and copy failed
        """
        try:
            cmd = [
                'docker', 'cp',
                f'{self.container.container_id}:{container_path}',
                local_path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                if required:
                    raise RuntimeError(
                        f"Failed to copy {container_path} from container: {result.stderr}"
                    )
                else:
                    logger.warning(
                        'Failed to copy optional file %s from container: %s',
                        container_path, result.stderr
                    )
                    return ''
            
            logger.debug(f"Copied from container: {container_path} -> {local_path}")
            return local_path
        except subprocess.CalledProcessError as e:
            if required:
                raise RuntimeError(f"Failed to copy from container: {e.stderr}")
            return ''
    
    def _execute_with_error_check(
        self,
        cmd: str,
        error_msg: str,
        check_output: bool = False,
        output_file: Optional[str] = None,
        timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Execute command and check for errors

        Args:
            cmd: Command to execute
            error_msg: Error message prefix
            check_output: Whether to check output file
            output_file: Output file path (if check_output=True)
            timeout: Command execution timeout in seconds (default: 60)

        Returns:
            Command execution result

        Raises:
            RuntimeError: If command execution fails or output file doesn't exist
        """
        logger.debug(f"Executing command: {cmd}")
        result = self.container.execute(cmd, timeout=timeout)
        
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
        Find file in multiple possible paths in container
        
        Args:
            search_paths: List of paths to search
            check_executable: Whether to check file executability
        
        Returns:
            Found file path, or None if not found
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
        """Clean up resources (close container, etc.)"""
        if self.container:
            self.container.terminate()

