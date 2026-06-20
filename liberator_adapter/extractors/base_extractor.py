"""
Base API Extractor

Provides common base class functionality for all API extractors
"""
import logging
import subprocess
from typing import Optional
from pathlib import Path
from enum import Enum

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

logger = logging.getLogger(__name__)


class DegradedReason(str, Enum):
    NONE = "none"
    COMPILE_FAILED = "compile_failed"
    EXTRACT_BC_FAILED = "extract_bc_failed"
    SVF_TIMEOUT = "svf_timeout"
    SVF_OOM = "svf_oom"
    CONDITIONS_EMPTY = "conditions_empty"
    CONDITIONS_MISSING = "conditions_missing"
    HOST_EXTRACTOR_MISSING = "host_extractor_missing"
    CONDITION_MANAGER_ERROR = "condition_manager_error"


def classify_degraded_reason(msg: str) -> str:
    """Map an exception message to the most-specific DegradedReason value string.

    Checks patterns most-specific-first so that e.g. an extract-bc error that
    happens to mention 'compiler' does NOT fall into COMPILE_FAILED.

    Returns a DegradedReason.*.value string, or up to the first 200 chars of
    *msg* when no pattern matches (raw fallback).
    """
    # Most specific first
    if "timed out" in msg or "timeout" in msg:
        return DegradedReason.SVF_TIMEOUT.value
    if "bad_alloc" in msg or "MemoryError" in msg or "out of memory" in msg:
        return DegradedReason.SVF_OOM.value
    if "extract bitcode" in msg or "extract-bc" in msg:
        return DegradedReason.EXTRACT_BC_FAILED.value
    if "conditions.json was not generated" in msg or "conditions.json" in msg:
        return DegradedReason.CONDITIONS_MISSING.value
    if ("Extractor binary not found" in msg
            or "clang-14" in msg
            or "Path to compiler" in msg):
        return DegradedReason.HOST_EXTRACTOR_MISSING.value
    if "Could not find library" in msg or "compile script" in msg:
        return DegradedReason.COMPILE_FAILED.value
    return msg[:200]


def extraction_status_fields(clang_only, reason, recovery=None):
    """Single source of truth for the persisted extraction-status fields.

    recovery: name of the recovery path that produced usable bitcode
    (e.g. "stub_engine"), or None. Only meaningful in full mode."""
    if not clang_only:
        return {"extraction_mode": "full", "degraded_reason": None,
                "bitcode_recovery": recovery}
    if isinstance(reason, DegradedReason):
        reason = reason.value
    return {"extraction_mode": "clang_only",
            "degraded_reason": reason or DegradedReason.COMPILE_FAILED.value,
            "bitcode_recovery": None}


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
    
    
    def cleanup(self):
        """Clean up resources (close container, etc.)"""
        if self.container:
            self.container.terminate()

