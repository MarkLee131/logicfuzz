"""
Clang API 提取器

使用 Liberator 的 extract_included_functions.py 从头文件提取 apis_clang.json
"""
import logging
from typing import Optional
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark
from liberator_adapter.extractors.base_extractor import BaseAPIExtractor

logger = logging.getLogger(__name__)


class ClangAPIExtractor(BaseAPIExtractor):
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
        super().__init__(benchmark, container, container_name='clang_extract')
        
        # Liberator 工具路径：严格使用 liberator_adapter/liberator 下的文件
        self.extract_script = self.liberator_root / 'tool' / 'misc' / 'extract_included_functions.py'

        if not self.extract_script.exists():
            raise RuntimeError(
                f"Required liberator script not found at {self.extract_script}. "
                "Please ensure `liberator_adapter/liberator/tool/misc/extract_included_functions.py` exists."
            )
    
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
        # TODO: 这里我们当前没提供呢, 后续可以尝试Fuzz introspector API
        # 或者我们的逆拓扑排序 
        # 确保输出目录存在
        self._ensure_output_dir(output_dir)
        
        # 检查 clang Python bindings 是否可用，如果缺失则尝试安装
        # 先查找 libclang 库路径（用于设置环境变量）
        libclang_path_result = self.container.execute('find /usr -name "libclang*.so*" 2>/dev/null | head -1')
        libclang_path = libclang_path_result.stdout.strip() if libclang_path_result.returncode == 0 and libclang_path_result.stdout.strip() else None
        
        # 构建测试命令，如果找到 libclang 则设置环境变量
        test_cmd = 'python3 -c "import clang.cindex" 2>&1'
        if libclang_path:
            test_cmd = f'export LIBCLANG_PATH={libclang_path} && {test_cmd}'
        
        check_clang = self.container.execute(test_cmd)
        if check_clang.returncode != 0:
            logger.info('clang Python bindings not found, attempting to install in container...')
            
            # 首先尝试通过 apt 安装（Debian/Ubuntu）
            logger.info('Trying apt-get install python3-clang...')
            install_result = self.container.execute('apt-get update && apt-get install -y python3-clang 2>&1')
            
            # 验证包是否真的安装了
            verify_pkg_result = self.container.execute('dpkg -l | grep python3-clang 2>&1')
            pkg_installed = verify_pkg_result.returncode == 0 and 'python3-clang' in verify_pkg_result.stdout
            
            if install_result.returncode != 0 or not pkg_installed:
                logger.warning(f'apt-get install python3-clang failed or package not found')
                
                # 检查 pip 是否可用
                pip_check = self.container.execute('which pip3 2>&1 || which pip 2>&1')
                pip_available = pip_check.returncode == 0
                
                if not pip_available:
                    logger.info('pip not found, installing python3-pip...')
                    pip_install_result = self.container.execute('apt-get install -y python3-pip 2>&1')
                    if pip_install_result.returncode == 0:
                        pip_available = True
                        logger.info('python3-pip installed successfully')
                    else:
                        logger.warning('Failed to install python3-pip')
                
                if pip_available:
                    logger.info('Trying apt-get install libclang-dev (required for pip install clang)...')
                    libclang_result = self.container.execute('apt-get install -y libclang-dev 2>&1')
                    if libclang_result.returncode == 0:
                        logger.info('libclang-dev installed, trying pip install clang...')
                        # 尝试通过 pip 安装 clang（需要 libclang-dev）
                        install_result = self.container.execute('pip3 install clang 2>&1 || pip install clang 2>&1')
                        if install_result.returncode != 0:
                            logger.warning(f'pip install clang failed, trying libclang...')
                            # 最后尝试安装 libclang
                            install_result = self.container.execute('pip3 install libclang 2>&1 || pip install libclang 2>&1')
                    else:
                        logger.warning('Failed to install libclang-dev, cannot use pip install')
                else:
                    logger.warning('pip not available, cannot install Python clang bindings via pip')
            else:
                logger.info('python3-clang package installed successfully')
            
            # 重新查找 libclang 路径（安装后可能有变化）
            libclang_path_result = self.container.execute('find /usr -name "libclang*.so*" 2>/dev/null | head -1')
            libclang_path = libclang_path_result.stdout.strip() if libclang_path_result.returncode == 0 and libclang_path_result.stdout.strip() else None
            
            # 查找 clang Python 模块的实际位置
            logger.info('Locating clang Python module...')
            find_clang_module = self.container.execute('find /usr/lib/python3* -name "clang" -type d 2>/dev/null | head -3')
            clang_module_dirs = [d.strip() for d in find_clang_module.stdout.strip().split('\n') if d.strip()] if find_clang_module.returncode == 0 else []
            
            # 尝试不同的导入方式
            import_success = False
            clang_module_parent = None
            
            # 方法1: 标准导入
            if libclang_path:
                verify_cmd = f'export LIBCLANG_PATH={libclang_path} && python3 -c "import clang.cindex" 2>&1'
            else:
                verify_cmd = 'python3 -c "import clang.cindex" 2>&1'
            
            verify_result = self.container.execute(verify_cmd)
            if verify_result.returncode == 0:
                import_success = True
                logger.info('Standard import succeeded')
            else:
                # 方法2: 如果找到模块目录，尝试手动添加到路径
                for module_dir in clang_module_dirs:
                    if module_dir:
                        parent_dir = '/'.join(module_dir.split('/')[:-1])
                        logger.info(f'Trying import with explicit path: {parent_dir}')
                        if libclang_path:
                            test_cmd = f'export LIBCLANG_PATH={libclang_path} && python3 -c "import sys; sys.path.insert(0, \\"{parent_dir}\\"); import clang.cindex" 2>&1'
                        else:
                            test_cmd = f'python3 -c "import sys; sys.path.insert(0, \\"{parent_dir}\\"); import clang.cindex" 2>&1'
                        
                        test_result = self.container.execute(test_cmd)
                        if test_result.returncode == 0:
                            import_success = True
                            clang_module_parent = parent_dir
                            # 更新 verify_result 为成功的结果
                            verify_result = test_result
                            logger.info(f'Import succeeded with path: {parent_dir}')
                            break
                
                if not import_success:
                    # 如果所有方法都失败，使用标准导入的结果
                    logger.warning('All import methods failed')
            
            # 保存模块路径供后续使用
            if clang_module_parent:
                self._clang_module_parent = clang_module_parent
            
            if verify_result.returncode != 0:
                # 收集详细的错误信息
                error_output = verify_result.stdout.strip() or verify_result.stderr.strip() or 'No error message available'
                
                # 检查已安装的包（apt 和 pip）
                dpkg_result = self.container.execute('dpkg -l | grep -i clang 2>&1')
                apt_packages = dpkg_result.stdout.strip() if dpkg_result.returncode == 0 else 'Unable to check'
                
                pip_list_result = self.container.execute('(pip3 list 2>/dev/null || pip list 2>/dev/null) | grep -i clang 2>&1')
                pip_packages = pip_list_result.stdout.strip() if pip_list_result.returncode == 0 and pip_list_result.stdout.strip() else 'None found'
                
                # 检查 Python 模块的实际位置
                check_clang_import = self.container.execute('python3 -c "import sys; import os; paths = sys.path; clang_paths = []; [clang_paths.append(os.path.join(p, \"clang\")) for p in paths if os.path.exists(os.path.join(p, \"clang\"))]; print(\"\\n\".join(clang_paths) if clang_paths else \"No clang module found in sys.path\")" 2>&1')
                clang_module_locations = check_clang_import.stdout.strip() if check_clang_import.returncode == 0 else 'Unable to check'
                
                # 检查 dist-packages 和 site-packages
                check_dist = self.container.execute('ls -la /usr/lib/python3*/dist-packages/clang* 2>&1 | head -5')
                dist_packages_info = check_dist.stdout.strip() if check_dist.returncode == 0 else 'Not found'
                
                check_site = self.container.execute('ls -la /usr/local/lib/python3*/site-packages/clang* 2>&1 | head -5')
                site_packages_info = check_site.stdout.strip() if check_site.returncode == 0 else 'Not found'
                
                # 检查 Python 路径
                python_path_result = self.container.execute('python3 -c "import sys; print(\"\\n\".join(sys.path))" 2>&1')
                python_paths = python_path_result.stdout.strip() if python_path_result.returncode == 0 else 'Unable to check'
                
                error_msg = (
                    f'clang Python bindings installation completed but import still fails.\n'
                    f'Import error: {error_output}\n'
                    f'\nInstallation status:\n'
                    f'  APT packages: {apt_packages}\n'
                    f'  PIP packages: {pip_packages}\n'
                )
                if libclang_path:
                    error_msg += f'  Found libclang at: {libclang_path}\n'
                error_msg += (
                    f'\nPython module locations:\n'
                    f'  sys.path clang modules: {clang_module_locations}\n'
                    f'  dist-packages: {dist_packages_info}\n'
                    f'  site-packages: {site_packages_info}\n'
                    f'\nPython paths:\n{python_paths}\n'
                    f'\nManual troubleshooting steps:\n'
                    f'1. docker exec -it {self.container.container_id} bash\n'
                    f'2. Check Python version: python3 --version\n'
                    f'3. Check module location: python3 -c "import sys; print(sys.path)"\n'
                    f'4. Try: find /usr -name "clang" -type d | grep python\n'
                    f'5. Try: python3 -c "import sys; sys.path.insert(0, \"/usr/lib/python3/dist-packages\"); import clang.cindex"\n'
                )
                if libclang_path:
                    error_msg += f'6. export LIBCLANG_PATH={libclang_path}\n'
                error_msg += f'7. python3 -c "import clang.cindex"\n'
                
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            logger.info('clang Python bindings installed successfully')
        
        # 准备输出文件路径
        apis_clang_path = f'{output_dir}/apis_clang.json'
        exported_functions_path = f'{output_dir}/exported_functions.txt'
        incomplete_types_path = f'{output_dir}/incomplete_types.txt'
        enum_types_path = f'{output_dir}/enum_types.txt'
        
        # 复制脚本到容器的固定位置
        script_path = self._copy_script_to_container()
        
        # 重新查找 libclang 路径（确保使用最新路径）
        libclang_path_result = self.container.execute('find /usr -name "libclang*.so*" 2>/dev/null | head -1')
        libclang_path = libclang_path_result.stdout.strip() if libclang_path_result.returncode == 0 and libclang_path_result.stdout.strip() else None
        
        # 构建命令
        python_cmd_parts = [
            f'python3 {script_path}',
            f'-i "{include_dir}"',
            f'-o "{output_dir}"',
        ]
        
        # 添加 public_headers 文件（如果提供）
        if public_headers_file:
            python_cmd_parts.append(f'-p "{public_headers_file}"')
        
        python_cmd = ' '.join(python_cmd_parts)
        
        # 如果之前找到了需要手动添加路径的模块位置，在命令前添加路径
        cmd_prefix = ''
        if hasattr(self, '_clang_module_parent'):
            cmd_prefix = f'export PYTHONPATH={self._clang_module_parent}:$PYTHONPATH && '
        
        # 如果找到 libclang 库，在命令前设置环境变量
        if libclang_path:
            cmd = f'{cmd_prefix}export LIBCLANG_PATH={libclang_path} && {python_cmd}'
        elif cmd_prefix:
            cmd = f'{cmd_prefix}{python_cmd}'
        else:
            cmd = python_cmd
        
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
        
        # 优先级2: 检查项目源码目录中是否有头文件（可能在项目根目录或src目录）
        # 查找项目目录下的所有 .h 文件
        find_headers_cmd = f'find "{self.container.project_dir}" -maxdepth 3 -type f -name "*.h" -o -name "*.hpp" | head -1'
        result = self.container.execute(find_headers_cmd)
        if result.returncode == 0 and result.stdout.strip():
            # 找到头文件，使用项目目录作为 include 目录
            logger.info(f"Found headers in project directory: {self.container.project_dir}")
            return self.container.project_dir
        
        # 优先级3: 检查系统 include 目录（最后的选择）
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
            public_headers_file: 公共头文件列表文件（容器内路径），必需。
                                文件内容应该是每行一个头文件名（如 cjson.h）
        
        Returns:
            apis_clang.json 的路径
        """
        include_dir = self._find_include_dir()
        if not include_dir:
            raise RuntimeError("Could not find include directory. Please specify include_dir manually.")
        
        logger.info(f"Auto-detected include directory: {include_dir}")
        
        # public_headers_file 是必需的，必须由调用者提供
        if not public_headers_file:
            raise ValueError(
                "public_headers_file is required. "
                "Please provide a file listing the header files to analyze (one header name per line, e.g., 'cjson.h')."
            )
        
        # 检查文件是否存在
        if not self._file_exists_in_container(public_headers_file):
            raise FileNotFoundError(
                f"public_headers_file not found in container: {public_headers_file}"
            )
        
        return self.extract_apis_clang(
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            output_dir=output_dir,
            project_name=project_name or self.benchmark.project
        )
    
    def _copy_script_to_container(self) -> str:
        """
        复制 extract_included_functions.py 到容器的固定位置
        
        Returns:
            容器内的脚本路径（固定为 /tmp/extract_included_functions.py）
        """
        container_script_path = '/tmp/extract_included_functions.py'
        return self._copy_file_to_container(
            self.extract_script,
            container_script_path,
            make_executable=False
        )

