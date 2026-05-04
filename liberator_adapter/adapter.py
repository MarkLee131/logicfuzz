"""
Transform LogicFuzz data source to Liberator API model.

Uses Clang/LLVM (HybridAPIExtractor) for API extraction directly from source.
"""
from typing import Dict, List, Optional

from liberator_adapter.common.api import Api, Arg
from liberator_adapter.dependency import DependencyGraph, TypeDependencyGraphGenerator


class LiberatorAPIAdapter:
    """Adapter that fronts HybridAPIExtractor."""

    def __init__(self, project_name: str, benchmark):
        if not benchmark:
            raise ValueError("benchmark is required for API extraction")

        self.project_name = project_name
        self.api_cache: Dict[str, Api] = {}
        self.last_metadata: Dict = {}
        self.benchmark = benchmark

        from liberator_adapter.extractors.hybrid_extractor import HybridAPIExtractor
        self.hybrid_extractor = HybridAPIExtractor(benchmark)

    def convert_to_liberator_api(
        self,
        function_signature: str,
        api_context: Optional[Dict] = None,
    ) -> Optional[Api]:
        func_name = self._extract_function_name(function_signature)
        if not func_name:
            return None
        if func_name in self.api_cache:
            return self.api_cache[func_name]
        api = self.hybrid_extractor.get_api(func_name)
        if api:
            self.api_cache[func_name] = api
        return api

    def extract_all_apis(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True,
    ) -> Dict[str, Api]:
        apis = self.hybrid_extractor.extract(
            function_signatures=function_signatures,
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            bc_file=bc_file,
            compile_project=compile_project,
        )
        try:
            self.last_metadata = self.hybrid_extractor.get_last_metadata() or {}
        except Exception:
            self.last_metadata = {}
        return apis

    def _extract_function_name(self, signature: str) -> Optional[str]:
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(',
                          signature)
        return match.group(1) if match else None

    def _determine_flag(self, param: Dict) -> str:
        param_type = param.get('type', '')
        if '*' in param_type or '[' in param_type:
            return 'ref'
        return 'val'

    def _determine_size(self, param: Dict) -> int:
        param_type = param.get('type', '')
        if not param_type:
            return 0
        try:
            from liberator_adapter.common.datalayout import DataLayout
            size_bits = DataLayout.instance().infer_type_size(param_type)
            return size_bits // 8
        except Exception:
            if '*' in param_type:
                return 8
            if 'int' in param_type:
                if 'long' in param_type:
                    return 8
                if 'short' in param_type:
                    return 2
                return 4
            if 'char' in param_type:
                return 1
            if 'float' in param_type:
                return 4
            if 'double' in param_type:
                return 8
            return 0

    def _determine_const(self, param: Dict) -> List[bool]:
        param_type = param.get('type', '')
        return ['const' in param_type]

    def _is_vararg(self, signature: str) -> bool:
        return '...' in signature or ', ...' in signature

    def _extract_namespace(self, func_name: str) -> List[str]:
        parts = func_name.split('_')
        if len(parts) > 1:
            return parts[:-1]
        return []

    def cleanup(self):
        if self.hybrid_extractor:
            self.hybrid_extractor.cleanup()
