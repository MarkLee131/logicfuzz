"""
混合 API 提取器

整合 Clang 和 LLVM 提取器，提供完整的 API 提取功能
"""
import os
import logging
import subprocess as sp
import tempfile
import shutil
from typing import Dict, List, Optional, Set
from pathlib import Path

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

from liberator_adapter.extractors.clang_extractor import ClangAPIExtractor
from liberator_adapter.extractors.llvm_extractor import LLVMAPIExtractor
from liberator_adapter.common.api import Api
from liberator_adapter.common.utils import Utils

logger = logging.getLogger(__name__)


class HybridAPIExtractor:
    """
    混合提取器：整合 Clang 和 LLVM 提取功能
    
    工作流程：
    1. 使用 Clang 提取器从头文件提取 apis_clang.json
    2. 使用 wllvm 编译项目到 bitcode
    3. 使用 LLVM 提取器从 bitcode 提取 apis_llvm.json
    4. 使用 Utils.get_api_list() 合并数据生成 Api 对象
    """
    
    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None):
        """
        初始化混合提取器
        
        Args:
            benchmark: 项目基准对象
            container: 可选的容器工具（如果已创建）
        """
        self.benchmark = benchmark
        self.container = container or ProjectContainerTool(benchmark, name='hybrid_extract')
        
        # 创建子提取器（共享同一个容器）
        self.clang_extractor = ClangAPIExtractor(benchmark, self.container)
        self.llvm_extractor = LLVMAPIExtractor(benchmark, self.container)
        
        # 输出目录（容器内）
        self.output_dir = '/tmp/liberator_extract'
        
        # 本地临时目录（用于存储从容器复制的文件）
        self.local_temp_dir = None
    
    def extract(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Dict[str, Api]:
        """
        提取 API 信息
        
        Args:
            function_signatures: 要提取的函数签名列表（可选，如果为 None 则提取所有）
            include_dir: 头文件目录（可选，如果为 None 则自动检测）
            public_headers_file: 公共头文件列表（可选）
            bc_file: bitcode 文件路径（可选，如果为 None 且 compile_project=True 则自动编译）
            compile_project: 是否编译项目（如果 bc_file 未提供）
        
        Returns:
            函数名到 Api 对象的字典
        """
        logger.info(f"Starting hybrid API extraction for project: {self.benchmark.project}")
        
        # 1. 提取 apis_clang.json
        logger.info("Step 1: Extracting apis_clang.json...")
        if include_dir:
            apis_clang_path = self.clang_extractor.extract_apis_clang(
                include_dir=include_dir,
                public_headers_file=public_headers_file,
                output_dir=self.output_dir,
                project_name=self.benchmark.project
            )
        else:
            apis_clang_path = self.clang_extractor.extract_with_auto_detect(
                output_dir=self.output_dir,
                project_name=self.benchmark.project
            )
        
        # 2. 准备 bitcode 文件
        logger.info("Step 2: Preparing bitcode file...")
        if not bc_file:
            if compile_project:
                bc_file = self.llvm_extractor.compile_to_bitcode()
            else:
                raise ValueError("bc_file not provided and compile_project=False")
        
        # 3. 提取 apis_llvm.json
        logger.info("Step 3: Extracting apis_llvm.json...")
        apis_llvm_path = self.llvm_extractor.extract_apis_llvm(
            bc_file=bc_file,
            apis_clang_path=apis_clang_path,
            output_dir=self.output_dir
        )
        
        # 4. 读取并合并数据
        logger.info("Step 4: Merging Clang and LLVM data...")
        apis = self._merge_apis(
            apis_clang_path=apis_clang_path,
            apis_llvm_path=apis_llvm_path,
            function_signatures=function_signatures
        )
        
        logger.info(f"Successfully extracted {len(apis)} APIs")
        return apis
    
    def _merge_apis(
        self,
        apis_clang_path: str,
        apis_llvm_path: str,
        function_signatures: Optional[List[str]] = None
    ) -> Dict[str, Api]:
        """
        使用 Utils.get_api_list() 合并 Clang 和 LLVM 数据
        
        Args:
            apis_clang_path: apis_clang.json 路径（容器内）
            apis_llvm_path: apis_llvm.json 路径（容器内）
            function_signatures: 要提取的函数签名列表（可选）
        
        Returns:
            函数名到 Api 对象的字典
        """
        # 创建本地临时目录
        if not self.local_temp_dir:
            self.local_temp_dir = tempfile.mkdtemp(prefix=f'liberator_extract_{self.benchmark.project}_')
            logger.info(f"Created local temp directory: {self.local_temp_dir}")
        
        # 准备其他必需的文件路径（容器内）
        coerce_log_path = f'{self.output_dir}/coerce.log'
        exported_functions_path = f'{self.output_dir}/exported_functions.txt'
        incomplete_types_path = f'{self.output_dir}/incomplete_types.txt'
        minimum_apis_path = ''  # 可选
        
        # 如果指定了函数签名，创建 minimum_apis 文件
        if function_signatures:
            # 提取函数名
            function_names = [self._extract_function_name(sig) for sig in function_signatures]
            function_names = [name for name in function_names if name]
            
            if function_names:
                minimum_apis_path = f'{self.output_dir}/minimum_apis.txt'
                # 在容器内创建文件
                content = '\n'.join(function_names)
                self.container.write_to_file(content, minimum_apis_path)
        
        # 复制文件从容器到本地
        files_to_copy = [
            (apis_clang_path, 'apis_clang.json'),
            (apis_llvm_path, 'apis_llvm.json'),
        ]
        
        # 可选文件
        if self._file_exists_in_container(coerce_log_path):
            files_to_copy.append((coerce_log_path, 'coerce.log'))
        if self._file_exists_in_container(exported_functions_path):
            files_to_copy.append((exported_functions_path, 'exported_functions.txt'))
        if self._file_exists_in_container(incomplete_types_path):
            files_to_copy.append((incomplete_types_path, 'incomplete_types.txt'))
        if minimum_apis_path and self._file_exists_in_container(minimum_apis_path):
            files_to_copy.append((minimum_apis_path, 'minimum_apis.txt'))
        
        # 复制文件
        local_paths = {}
        for container_path, local_name in files_to_copy:
            local_path = os.path.join(self.local_temp_dir, local_name)
            self._copy_from_container(container_path, local_path)
            local_paths[local_name] = local_path
        
        # 使用 Utils.get_api_list() 读取
        try:
            api_set = Utils.get_api_list(
                apis_llvm=local_paths.get('apis_llvm.json', ''),
                apis_clang=local_paths.get('apis_clang.json', ''),
                coerce_map=local_paths.get('coerce.log', ''),
                hedader_folder=local_paths.get('exported_functions.txt', ''),
                incomplete_types=local_paths.get('incomplete_types.txt', ''),
                minimum_apis=local_paths.get('minimum_apis.txt', '')
            )
            
            # 转换为字典
            apis_dict = {}
            for api in api_set:
                apis_dict[api.function_name] = api
            
            return apis_dict
        except Exception as e:
            logger.error(f"Failed to merge APIs: {e}")
            raise
    
    def _copy_from_container(self, container_path: str, local_path: str):
        """从容器复制文件到本地"""
        try:
            # 使用 docker cp 复制文件
            cmd = ['docker', 'cp', f'{self.container.container_id}:{container_path}', local_path]
            result = sp.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                # 如果直接复制失败，尝试先复制到临时位置
                temp_local = local_path + '.tmp'
                cmd = ['docker', 'cp', f'{self.container.container_id}:{container_path}', temp_local]
                result = sp.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    shutil.move(temp_local, local_path)
                else:
                    raise RuntimeError(f"Failed to copy {container_path}: {result.stderr}")
            
            logger.debug(f"Copied {container_path} to {local_path}")
        except Exception as e:
            logger.error(f"Error copying file from container: {e}")
            raise
    
    def _extract_function_name(self, signature: str) -> Optional[str]:
        """从函数签名中提取函数名"""
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', signature)
        return match.group(1) if match else None
    
    def _file_exists_in_container(self, file_path: str) -> bool:
        """检查容器内文件是否存在"""
        result = self.container.execute(f'test -f "{file_path}" && echo "exists" || echo "not_found"')
        return result.stdout.strip() == 'exists'
    
    def get_api(self, function_name: str) -> Optional[Api]:
        """
        获取单个函数的 API 信息
        
        Args:
            function_name: 函数名
        
        Returns:
            Api 对象，如果不存在则返回 None
        """
        # 如果还没有提取，先提取所有
        if not hasattr(self, '_cached_apis'):
            self._cached_apis = self.extract()
        
        return self._cached_apis.get(function_name)
    
    def cleanup(self):
        """清理资源"""
        # 清理本地临时目录
        if self.local_temp_dir and os.path.exists(self.local_temp_dir):
            try:
                shutil.rmtree(self.local_temp_dir)
                logger.info(f"Cleaned up local temp directory: {self.local_temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp directory: {e}")
        
        # 关闭容器
        if self.container:
            self.container.terminate()

