"""
Transform LogicFuzz data source to Liberator API model

Support two data sources:
FuzzIntrospector API (original way, inferred by adapter)
   - Need FuzzIntrospector API available
   - Inferred flag, size, const information by adapter

Clang/LLVM (new way, inferred by adapter)
   - Need benchmark object and source code access
   - Inferred flag, size, const information by adapter
"""
from typing import Dict, List, Set, Optional
from liberator_adapter.common.api import Api, Arg
from liberator_adapter.dependency import DependencyGraph, TypeDependencyGraphGenerator
from agent_graph.api_context_extractor import APIContextExtractor

class LiberatorAPIAdapter:
    """
    Adapter to transform LogicFuzz data source to Liberator API model
    """
    
    def __init__(self, project_name: str, use_clang_llvm: bool = False, benchmark=None):
        """
        Initialize adapter
        
        Args:
            project_name: project name
            use_clang_llvm: whether to use Clang/LLVM directly (need benchmark)
                - True: use Clang/LLVM directly, no FuzzIntrospector needed
                - False: use FuzzIntrospector API (default)
            benchmark: benchmark object (required when use Clang/LLVM)
        
        Note:
            - When use_clang_llvm=True, no FuzzIntrospector API needed
            - When use_clang_llvm=False, FuzzIntrospector API needed
        """
        self.project_name = project_name
        self.use_clang_llvm = use_clang_llvm
        self.api_cache: Dict[str, Api] = {}
        
        if use_clang_llvm:
            if not benchmark:
                raise ValueError("benchmark is required when use_clang_llvm=True")
            from liberator_adapter.extractors.hybrid_extractor import HybridAPIExtractor
            self.hybrid_extractor = HybridAPIExtractor(benchmark)
            self.extractor = None  # no FuzzIntrospector used
        else:
            self.extractor = APIContextExtractor(project_name)
            self.hybrid_extractor = None
        
    def convert_to_liberator_api(
        self, 
        function_signature: str,
        api_context: Optional[Dict] = None
    ) -> Optional[Api]:
        """
        Transform function information to Liberator API object
        
        Select data source based on use_clang_llvm parameter:
        - use_clang_llvm=True: use Clang/LLVM directly (no FuzzIntrospector)
        - use_clang_llvm=False: use FuzzIntrospector API (original way)
        
        Args:
            function_signature: function signature (e.g. "int curl_easy_setopt(CURL *, int, ...)")
            api_context: optional FuzzIntrospector context (only used in non-Clang/LLVM mode)
                - if provided, can avoid duplicate query to FuzzIntrospector
                - this parameter is ignored in Clang/LLVM mode
        
        Returns:
            Api object, return None if conversion fails
        """
        # if using Clang/LLVM extraction
        if self.use_clang_llvm and self.hybrid_extractor:
            func_name = self._extract_function_name(function_signature)
            if not func_name:
                return None
            
            # check cache
            if func_name in self.api_cache:
                return self.api_cache[func_name]
            
            # get API from hybrid extractor
            api = self.hybrid_extractor.get_api(func_name)
            if api:
                self.api_cache[func_name] = api
            return api
        
        # original way: use FuzzIntrospector
        # 1. get or use provided context
        if not api_context:
            api_context = self.extractor.extract(function_signature)
        
        if not api_context:
            return None
        
        # 2. parse function signature
        func_name = self._extract_function_name(function_signature)
        if not func_name:
            return None
        
        # 3. build Arg object list
        arguments_info = []
        for param in api_context.get('parameters', []):
            arg = Arg(
                name=param.get('name', ''),
                flag=self._determine_flag(param),  # 'ref', 'val', etc.
                size=self._determine_size(param),
                type=param.get('type', 'void'),
                is_const=self._determine_const(param)
            )
            arguments_info.append(arg)
        
        # 4. build return value Arg
        return_info = Arg(
            name='return',
            flag='val',
            size=0,
            type=api_context.get('return_type', 'void'),
            is_const=[False]
        )
        
        # 5. build Api object
        api = Api(
            function_name=func_name,
            is_vararg=self._is_vararg(function_signature),
            return_info=return_info,
            arguments_info=arguments_info,
            namespace=self._extract_namespace(func_name)
        )
        
        self.api_cache[func_name] = api
        return api
    
    def extract_all_apis(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Dict[str, Api]:
        """
        Extract all APIs (only available when use_clang_llvm=True)
        
        Args:
            function_signatures: function signatures to extract (optional)
            include_dir: include directory (optional)
            public_headers_file: public headers file list (optional)
            bc_file: bitcode file path (optional)
            compile_project: whether to compile project (if bc_file is not provided)
        
        Returns:
            Dictionary of function name to Api object
        """
        if not self.use_clang_llvm or not self.hybrid_extractor:
            raise RuntimeError("extract_all_apis() is only available when use_clang_llvm=True")
        
        return self.hybrid_extractor.extract(
            function_signatures=function_signatures,
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            bc_file=bc_file,
            compile_project=compile_project
        )
    
    def _extract_function_name(self, signature: str) -> Optional[str]:
        """Extract function name from function signature"""
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', signature)
        return match.group(1) if match else None
    
    def _determine_flag(self, param: Dict) -> str:
        """Determine parameter flag (ref/val)"""
        param_type = param.get('type', '')
        if '*' in param_type or '[' in param_type:
            return 'ref'
        return 'val'
    
    def _determine_size(self, param: Dict) -> int:
        """Determine parameter size (in bytes)"""
        param_type = param.get('type', '')
        if not param_type:
            return 0
        
        # try to use DataLayout to get type size
        try:
            from liberator_adapter.common.datalayout import DataLayout
            # note: DataLayout returns bits, need to convert to bytes
            size_bits = DataLayout.instance().infer_type_size(param_type)
            return size_bits // 8  # convert to bytes
        except:
            # if DataLayout is not initialized or type is unknown, use simple heuristic rule
            if '*' in param_type:
                return 8  # pointer is 8 bytes on 64-bit system
            elif 'int' in param_type:
                if 'long' in param_type:
                    return 8
                elif 'short' in param_type:
                    return 2
                else:
                    return 4
            elif 'char' in param_type:
                return 1
            elif 'float' in param_type:
                return 4
            elif 'double' in param_type:
                return 8
            else:
                return 0  # unknown type
    
    def _determine_const(self, param: Dict) -> List[bool]:
        """Determine const modifier"""
        param_type = param.get('type', '')
        return ['const' in param_type]
    
    def _is_vararg(self, signature: str) -> bool:
        """Check if it is a variadic function"""
        return '...' in signature or ', ...' in signature
    
    def _extract_namespace(self, func_name: str) -> List[str]:
        """Extract namespace (based on function name prefix)"""
        parts = func_name.split('_')
        if len(parts) > 1:
            return parts[:-1]  # except the last part (function name)
        return []
    
    def cleanup(self):
        """Clean up resources"""
        if self.hybrid_extractor:
            self.hybrid_extractor.cleanup()

