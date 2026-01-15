"""
Clang API Extractor

Uses Liberator's extract_included_functions.py to extract apis_clang.json from header files
"""
import logging
from typing import Optional, Tuple
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark
from liberator_adapter.extractors.base_extractor import BaseAPIExtractor

logger = logging.getLogger(__name__)


class ClangAPIExtractor(BaseAPIExtractor):
    """
    Extract API information from header files using Clang Python bindings
    
    Wraps liberator/tool/misc/extract_included_functions.py
    """
    
    # Common clang environment paths in OSS-Fuzz containers
    # OSS-Fuzz uses self-compiled Python, its sys.path doesn't include system dist-packages
    SYSTEM_DIST_PACKAGES = '/usr/lib/python3/dist-packages'
    COMMON_LIBCLANG_PATHS = [
        '/usr/lib/llvm-10/lib/libclang.so.1',
        '/usr/lib/x86_64-linux-gnu/libclang-10.so.1',
        '/usr/lib/llvm-11/lib/libclang.so.1',
        '/usr/lib/llvm-12/lib/libclang.so.1',
    ]
    
    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None,
                 use_llvm14_builder: bool = False):
        """
        Initialize Clang API extractor

        Args:
            benchmark: Project benchmark object
            container: Optional container tool (if already created)
            use_llvm14_builder: Whether to use custom base-builder image with LLVM 14 pre-installed
        """
        super().__init__(benchmark, container, container_name='clang_extract',
                         use_llvm14_builder=use_llvm14_builder)
        
        # Liberator tool path: strictly use files under liberator_adapter/liberator
        self.extract_script = self.liberator_root / 'tool' / 'misc' / 'extract_included_functions.py'

        if not self.extract_script.exists():
            raise RuntimeError(
                f"Required liberator script not found at {self.extract_script}. "
                "Please ensure `liberator_adapter/liberator/tool/misc/extract_included_functions.py` exists."
            )
        
        # Cache clang environment configuration
        self._clang_env_cache: Optional[Tuple[str, str]] = None
    
    def _setup_clang_environment(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Setup clang Python bindings environment
        
        OSS-Fuzz containers usually have python3-clang pre-installed, but since they use
        self-compiled Python, PYTHONPATH and LIBCLANG_PATH environment variables need to be set.
        
        Returns:
            (libclang_path, pythonpath) tuple, or None if not needed
        """
        if self._clang_env_cache is not None:
            return self._clang_env_cache
        
        libclang_path = None
        pythonpath = None
        
        # Strategy 1: Check if python3-clang is installed (usually installed in OSS-Fuzz)
        check_pkg = self.container.execute('dpkg -l python3-clang 2>/dev/null | grep -q "^ii"')
        if check_pkg.returncode == 0:
            logger.info('python3-clang package already installed')
            
            # Check if clang module exists in system dist-packages
            check_module = self.container.execute(f'ls {self.SYSTEM_DIST_PACKAGES}/clang/__init__.py 2>/dev/null')
            if check_module.returncode == 0:
                pythonpath = self.SYSTEM_DIST_PACKAGES
                logger.info(f'Found clang module in {pythonpath}')
            
            # Find libclang library
            libclang_path = self._find_libclang()
            
            # Verify configuration works
            if self._verify_clang_import(libclang_path, pythonpath):
                self._clang_env_cache = (libclang_path, pythonpath)
                return self._clang_env_cache
        
        # Strategy 2: Try standard import (may be installed via pip)
        if self._verify_clang_import(None, None):
            logger.info('clang Python bindings available via standard import')
            self._clang_env_cache = (None, None)
            return self._clang_env_cache
        
        # Strategy 3: Need to install clang bindings
        logger.info('clang Python bindings not found, attempting to install...')
        self._install_clang_bindings()
        
        # Re-detect environment
        libclang_path = self._find_libclang()
        
        # Check dist-packages
        check_module = self.container.execute(f'ls {self.SYSTEM_DIST_PACKAGES}/clang/__init__.py 2>/dev/null')
        if check_module.returncode == 0:
            pythonpath = self.SYSTEM_DIST_PACKAGES
        
        if not self._verify_clang_import(libclang_path, pythonpath):
            self._raise_clang_error(libclang_path)
        
        self._clang_env_cache = (libclang_path, pythonpath)
        return self._clang_env_cache
    
    def _find_libclang(self) -> Optional[str]:
        """Find libclang library path"""
        # First try common paths (faster)
        for path in self.COMMON_LIBCLANG_PATHS:
            check = self.container.execute(f'test -f {path}')
            if check.returncode == 0:
                logger.info(f'Found libclang at: {path}')
                return path
        
        # Fallback to find command
        result = self.container.execute('find /usr -name "libclang*.so*" 2>/dev/null | head -1')
        if result.returncode == 0 and result.stdout.strip():
            path = result.stdout.strip()
            logger.info(f'Found libclang via find: {path}')
            return path
        
        return None
    
    def _verify_clang_import(self, libclang_path: Optional[str], pythonpath: Optional[str]) -> bool:
        """Verify if clang Python bindings are available"""
        cmd_parts = []
        
        if pythonpath:
            cmd_parts.append(f'export PYTHONPATH={pythonpath}:$PYTHONPATH')
        if libclang_path:
            cmd_parts.append(f'export LIBCLANG_PATH={libclang_path}')
        
        cmd_parts.append('python3 -c "import clang.cindex"')
        cmd = ' && '.join(cmd_parts)
        
        result = self.container.execute(f'{cmd} 2>&1')
        return result.returncode == 0
    
    def _install_clang_bindings(self):
        """Install clang Python bindings"""
        # Try apt installation
        logger.info('Trying apt-get install python3-clang...')
        result = self.container.execute('apt-get update && apt-get install -y python3-clang 2>&1')
        if result.returncode == 0:
            logger.info('python3-clang installed successfully via apt')
            return
        
        # Fallback to pip installation
        logger.warning('apt install failed, trying pip...')
        
        # Ensure pip is available
        pip_check = self.container.execute('which pip3 2>&1 || which pip 2>&1')
        if pip_check.returncode != 0:
            self.container.execute('apt-get install -y python3-pip 2>&1')
        
        # Install libclang-dev (required for pip version)
        self.container.execute('apt-get install -y libclang-dev 2>&1')
        
        # 尝试 pip install
        result = self.container.execute('pip3 install clang 2>&1 || pip install clang 2>&1')
        if result.returncode != 0:
            self.container.execute('pip3 install libclang 2>&1 || pip install libclang 2>&1')
    
    def _raise_clang_error(self, libclang_path: Optional[str]):
        """生成详细的错误信息"""
        dpkg_result = self.container.execute('dpkg -l | grep -i clang 2>&1')
        apt_packages = dpkg_result.stdout.strip() if dpkg_result.returncode == 0 else 'Unable to check'
        
        python_path_result = self.container.execute('python3 -c "import sys; print(chr(10).join(sys.path))" 2>&1')
        python_paths = python_path_result.stdout.strip() if python_path_result.returncode == 0 else 'Unable to check'
        
        error_msg = (
            f'Failed to setup clang Python bindings.\n'
            f'\nInstalled APT packages:\n{apt_packages}\n'
            f'\nPython sys.path:\n{python_paths}\n'
            f'\nManual troubleshooting:\n'
            f'1. docker exec -it {self.container.container_id} bash\n'
            f'2. export PYTHONPATH={self.SYSTEM_DIST_PACKAGES}:$PYTHONPATH\n'
        )
        if libclang_path:
            error_msg += f'3. export LIBCLANG_PATH={libclang_path}\n'
        error_msg += f'4. python3 -c "import clang.cindex"\n'
        
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    
    def _build_command_with_env(self, python_cmd: str) -> str:
        """构建带环境变量的命令"""
        libclang_path, pythonpath = self._setup_clang_environment()
        
        cmd_parts = []
        if pythonpath:
            cmd_parts.append(f'export PYTHONPATH={pythonpath}:$PYTHONPATH')
        if libclang_path:
            cmd_parts.append(f'export LIBCLANG_PATH={libclang_path}')
        cmd_parts.append(python_cmd)
        
        return ' && '.join(cmd_parts)
    
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
            public_headers_file: 公共头文件列表（可选，主机路径或容器内路径）
            output_dir: 输出目录（容器内路径）
            project_name: 项目名称（用于查找 public_headers.txt）

        Returns:
            apis_clang.json 的路径（容器内路径）
        """
        # 确保输出目录存在
        self._ensure_output_dir(output_dir)

        # 设置 clang 环境
        self._setup_clang_environment()

        # 准备输出文件路径
        apis_clang_path = f'{output_dir}/apis_clang.json'

        # 复制脚本到容器
        script_path = self._copy_script_to_container()

        # 处理 public_headers_file - 如果是主机路径，复制到容器
        container_public_headers = None
        if public_headers_file:
            from pathlib import Path
            host_path = Path(public_headers_file)
            if host_path.exists():
                # 文件在主机上，需要复制到容器
                container_public_headers = '/tmp/public_headers.txt'
                self._copy_file_to_container(
                    host_path,
                    container_public_headers,
                    make_executable=False
                )
                logger.info(f"Copied public_headers to container: {container_public_headers}")
            elif self._file_exists_in_container(public_headers_file):
                # 文件已在容器内
                container_public_headers = public_headers_file
            else:
                raise FileNotFoundError(
                    f"public_headers_file not found on host or in container: {public_headers_file}"
                )

        # 构建 Python 命令
        python_cmd_parts = [
            f'python3 {script_path}',
            f'-i "{include_dir}"',
            f'-o "{output_dir}"',
        ]

        if container_public_headers:
            python_cmd_parts.append(f'-p "{container_public_headers}"')
        
        python_cmd = ' '.join(python_cmd_parts)
        cmd = self._build_command_with_env(python_cmd)
        
        logger.info(f"Extracting apis_clang.json with command: {cmd}")
        self._execute_with_error_check(
            cmd,
            "Clang extraction failed",
            check_output=True,
            output_file=apis_clang_path
        )
        
        logger.info(f"Successfully extracted apis_clang.json to {apis_clang_path}")
        return apis_clang_path
    
    def _find_include_dir(self) -> Optional[str]:
        """
        自动查找项目的 include 目录
        
        Returns:
            include 目录路径（容器内），如果找不到则返回 None
        """
        # 优先级1: 检查项目目录下的 include
        project_include = f'{self.container.project_dir}/include'
        if self._dir_exists_in_container(project_include):
            return project_include
        
        # 优先级2: 检查项目源码目录中是否有头文件
        find_headers_cmd = f'find "{self.container.project_dir}" -maxdepth 3 -type f -name "*.h" -o -name "*.hpp" | head -1'
        result = self.container.execute(find_headers_cmd)
        if result.returncode == 0 and result.stdout.strip():
            logger.info(f"Found headers in project directory: {self.container.project_dir}")
            return self.container.project_dir
        
        # 优先级3: 检查系统 include 目录
        system_include = '/usr/local/include'
        if self._dir_exists_in_container(system_include):
            logger.warning(f"Using system include directory: {system_include}. This may include many headers.")
            return system_include
        
        return None
    
    def extract_with_auto_detect(
        self,
        output_dir: str = '/tmp/liberator_extract',
        project_name: Optional[str] = None,
        public_headers_file: Optional[str] = None
    ) -> str:
        """
        自动检测 include 目录并提取

        Args:
            output_dir: 输出目录
            project_name: 项目名称
            public_headers_file: 公共头文件列表文件（主机路径或容器内路径），必需。

        Returns:
            apis_clang.json 的路径
        """
        include_dir = self._find_include_dir()
        if not include_dir:
            raise RuntimeError("Could not find include directory. Please specify include_dir manually.")

        logger.info(f"Auto-detected include directory: {include_dir}")

        if not public_headers_file:
            raise ValueError(
                "public_headers_file is required. "
                "Please provide a file listing the header files to analyze."
            )

        # Note: extract_apis_clang now handles host path to container path conversion
        # So we just pass the public_headers_file as-is
        return self.extract_apis_clang(
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            output_dir=output_dir,
            project_name=project_name or self.benchmark.project
        )
    
    def _copy_script_to_container(self) -> str:
        """复制 extract_included_functions.py 到容器"""
        container_script_path = '/tmp/extract_included_functions.py'
        return self._copy_file_to_container(
            self.extract_script,
            container_script_path,
            make_executable=False
        )
