"""
Integrate Clang and LLVM extractors, provide complete API extraction functionality.
"""
import os
import logging
import tempfile
import shutil
from typing import Dict, List, Optional

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

from liberator_adapter.extractors.base_extractor import BaseAPIExtractor
from liberator_adapter.extractors.clang_extractor import ClangAPIExtractor
from liberator_adapter.extractors.llvm_extractor import LLVMAPIExtractor
from liberator_adapter.common.api import Api
from liberator_adapter.common.utils import Utils

logger = logging.getLogger(__name__)


class HybridAPIExtractor(BaseAPIExtractor):
    """
    Integrate Clang and LLVM extractors, provide complete API extraction functionality.

    Workflow:
    1. Use Clang extractor to extract apis_clang.json from header files
    2. Use wllvm to compile project to bitcode
    3. Use LLVM extractor to extract apis_llvm.json from bitcode
    4. Use Utils.get_api_list() to merge data and generate Api objects
    """

    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None,
                 use_llvm14_builder: bool = True):
        """
        Initialize hybrid extractor

        Args:
            benchmark: benchmark object
            container: optional container tool (if created)
            use_llvm14_builder: whether to use custom base-builder with LLVM 14
                               (default True since LLVM extraction requires clang-14)
        """
        # LLVM extraction requires clang-14, so use_llvm14_builder should default to True
        super().__init__(benchmark, container, container_name='hybrid_extract',
                         use_llvm14_builder=use_llvm14_builder)

        # Create sub-extractors (share the same container, no need to pass use_llvm14_builder
        # since they share the already-created container)
        self.clang_extractor = ClangAPIExtractor(benchmark, self.container)
        self.llvm_extractor = LLVMAPIExtractor(benchmark, self.container)
        
        # Output directory (inside container)
        self.output_dir = '/tmp/liberator_extract'
        
        # Local temporary directory (for storing files copied from container)
        self.local_temp_dir = None
        # Record recent metadata (container/local paths)
        self.last_metadata = {}
    
    def extract(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Dict[str, Api]:
        """
        Extract API information
        
        Args:
            function_signatures: list of function signatures to extract (optional, if None then extract all)
            include_dir: header file directory (optional, if None then auto-detect)
            public_headers_file: list of public header files (optional)
            bc_file: bitcode file path (optional, if None and compile_project=True then auto-compile)
            compile_project: whether to compile project (if bc_file is not provided)
        
        Returns:
            dictionary of function names to Api objects
        """
        logger.info(f"Starting hybrid API extraction for project: {self.benchmark.project}")
        
        # 1. Extract apis_clang.json
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
                project_name=self.benchmark.project,
                public_headers_file=public_headers_file
            )
        
        # 2. Prepare bitcode file
        logger.info("Step 2: Preparing bitcode file...")
        if not bc_file:
            if compile_project:
                bc_file = self.llvm_extractor.compile_to_bitcode()
            else:
                raise ValueError("bc_file not provided and compile_project=False")

        # 3. Extract apis_llvm.json (runs on host)
        # Note: LLVM extraction runs on HOST, so output goes to a HOST directory
        logger.info("Step 3: Extracting apis_llvm.json on host...")
        if not self.local_temp_dir:
            self.local_temp_dir = tempfile.mkdtemp(prefix=f'liberator_extract_{self.benchmark.project}_')
            logger.info(f"Created local temp directory: {self.local_temp_dir}")

        # Extract to local temp dir (HOST path)
        self.llvm_extractor.extract_apis_llvm_on_host(
            bc_file=bc_file,
            apis_clang_path=apis_clang_path,
            output_dir=self.local_temp_dir  # Use HOST temp dir, not container path
        )

        # 4. Read and merge data
        logger.info("Step 4: Merging Clang and LLVM data...")
        apis = self._merge_apis(
            apis_clang_path=apis_clang_path,  # Container path
            llvm_output_dir=self.local_temp_dir,  # Host path with LLVM results
            function_signatures=function_signatures
        )
        
        logger.info(f"Successfully extracted {len(apis)} APIs")
        return apis
    
    def _merge_apis(
        self,
        apis_clang_path: str,
        llvm_output_dir: str,
        function_signatures: Optional[List[str]] = None
    ) -> Dict[str, Api]:
        """
        Merge Clang and LLVM data using Utils.get_api_list()

        Args:
            apis_clang_path: Path to apis_clang.json (inside container)
            llvm_output_dir: LLVM extraction result directory (on HOST, contains apis_llvm.json, conditions.json, etc.)
            function_signatures: List of function signatures to extract (optional)

        Returns:
            Dictionary mapping function names to Api objects
        """
        # llvm_output_dir is already local_temp_dir, use directly
        local_paths = {}

        # LLVM results are already on HOST (llvm_output_dir)
        llvm_files = ['apis_llvm.json', 'conditions.json', 'data_layout.txt']
        for filename in llvm_files:
            host_path = os.path.join(llvm_output_dir, filename)
            if os.path.exists(host_path):
                local_paths[filename] = host_path
                logger.debug(f"Using LLVM result from host: {host_path}")

        # Clang results are in container, need to copy
        local_apis_clang = os.path.join(llvm_output_dir, 'apis_clang.json')
        self._copy_from_container(apis_clang_path, local_apis_clang)
        local_paths['apis_clang.json'] = local_apis_clang

        # Prepare other required file paths (inside container)
        exported_functions_path = f'{self.output_dir}/exported_functions.txt'
        incomplete_types_path = f'{self.output_dir}/incomplete_types.txt'
        minimum_apis_path = ''  # Optional

        # If function signatures specified, create minimum_apis file
        if function_signatures:
            # Extract function names
            function_names = [self._extract_function_name(sig) for sig in function_signatures]
            function_names = [name for name in function_names if name]

            if function_names:
                minimum_apis_path = os.path.join(llvm_output_dir, 'minimum_apis.txt')
                with open(minimum_apis_path, 'w') as f:
                    f.write('\n'.join(function_names))
                local_paths['minimum_apis.txt'] = minimum_apis_path

        # Copy other optional files from container
        optional_container_files = [
            (exported_functions_path, 'exported_functions.txt'),
            (incomplete_types_path, 'incomplete_types.txt'),
        ]

        for container_path, local_name in optional_container_files:
            if self._file_exists_in_container(container_path):
                local_path = os.path.join(llvm_output_dir, local_name)
                self._copy_from_container(container_path, local_path)
                local_paths[local_name] = local_path

        # Utils.get_api_list requires all file paths to exist (doesn't handle empty strings)
        # Create empty files for optional ones that don't exist
        optional_files_with_defaults = [
            ('coerce.log', ''),
            ('exported_functions.txt', ''),
            ('incomplete_types.txt', ''),
        ]
        for filename, default_content in optional_files_with_defaults:
            if filename not in local_paths:
                local_path = os.path.join(llvm_output_dir, filename)
                with open(local_path, 'w') as f:
                    f.write(default_content)
                local_paths[filename] = local_path

        # Verify required files exist
        required_files = ['apis_llvm.json', 'apis_clang.json']
        for filename in required_files:
            if filename not in local_paths or not os.path.exists(local_paths[filename]):
                raise RuntimeError(f"Required file {filename} not found in local_paths")

        # Read using Utils.get_api_list()
        try:
            api_set = Utils.get_api_list(
                apis_llvm=local_paths['apis_llvm.json'],
                apis_clang=local_paths['apis_clang.json'],
                coerce_map=local_paths['coerce.log'],
                hedader_folder=local_paths['exported_functions.txt'],
                incomplete_types=local_paths['incomplete_types.txt'],
                minimum_apis=local_paths.get('minimum_apis.txt', '')
            )
            
            # Convert to dictionary
            apis_dict = {}
            for api in api_set:
                apis_dict[api.function_name] = api

            # Record metadata for subsequent DataLayout/ConditionManager usage
            # Note: LLVM results are on HOST, Clang results copied from container
            self.last_metadata = {
                "container": {
                    "apis_clang": apis_clang_path,
                    # LLVM extraction runs on host, no container paths for LLVM results
                    "incomplete_types": incomplete_types_path,
                    "exported_functions": exported_functions_path,
                },
                "local": {
                    "apis_clang": local_paths.get('apis_clang.json'),
                    "apis_llvm": local_paths.get('apis_llvm.json'),
                    "conditions": local_paths.get('conditions.json'),
                    "data_layout": local_paths.get('data_layout.txt'),
                    "incomplete_types": local_paths.get('incomplete_types.txt'),
                    "exported_functions": local_paths.get('exported_functions.txt'),
                },
                "llvm_output_dir": llvm_output_dir,
            }
            
            return apis_dict
        except Exception as e:
            logger.error(f"Failed to merge APIs: {e}")
            raise
    
    # _copy_from_container is inherited from BaseAPIExtractor
    
    def _extract_function_name(self, signature: str) -> Optional[str]:
        """Extract function name from function signature"""
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', signature)
        return match.group(1) if match else None
    
    def get_last_metadata(self):
        """Return metadata from the most recent extraction (container/local paths)"""
        return self.last_metadata
    
    def get_api(self, function_name: str) -> Optional[Api]:
        """
        Get API information for a single function
        
        Args:
            function_name: Function name
        
        Returns:
            Api object, or None if not found
        """
        # If not yet extracted, extract all first
        if not hasattr(self, '_cached_apis'):
            self._cached_apis = self.extract()
        
        return self._cached_apis.get(function_name)
    
    def cleanup(self):
        """Clean up resources"""
        # Clean up local temporary directory
        if self.local_temp_dir and os.path.exists(self.local_temp_dir):
            try:
                shutil.rmtree(self.local_temp_dir)
                logger.info(f"Cleaned up local temp directory: {self.local_temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp directory: {e}")
        
        # Call base class cleanup method (close container)
        super().cleanup()

