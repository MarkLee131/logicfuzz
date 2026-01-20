#!/usr/bin/env python3
"""
API Context Extractor

Extract API context from FuzzIntrospector for LLM to generate correct fuzzer:
Features:
1. Query function signature and parameter types from FuzzIntrospector
2. Query related type definitions
3. Extract usage examples from existing fuzzers
4. Identify types that need initialization
5. Generate structured API context

"""

import logging
import re
from typing import Dict, List, Optional, Set
from data_prep import introspector
from src.utils.api_heuristics import (
    INIT_SUFFIXES,
    CLEANUP_SUFFIXES,
    INIT_REQUIRED_KEYWORDS,
    clean_type_name,
    is_primitive_type,
    requires_initialization as check_requires_initialization,
    get_base_name_from_type
)

logger = logging.getLogger(__name__)


class APIContextExtractor:
    """Extract API context from FuzzIntrospector"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
        self._all_functions_cache: Optional[Set[str]] = None
    
    def extract(self, function_signature: str) -> Dict:
        """
        Extract function's API context
        
        Args:
            function_signature: Function signature (e.g., "igraph_sparsemat_arpack_rssolve")
        
        Returns:
            Dictionary containing the following fields:
            - parameters: Parameter list
            - return_type: Return type
            - type_definitions: Type definition dictionary
            - usage_examples: Usage example list
            - initialization_patterns: Initialization pattern list
            - related_functions: Related function list
        """
        logger.info(f"Extracting API context for {function_signature}")
        
        context = {
            'parameters': [],
            'return_type': '',
            'type_definitions': {},
            'usage_examples': [],
            'initialization_patterns': [],
            'related_functions': [],
            'side_effects': {}  # NEW: Side effect analysis
        }
        
        try:
            # 1. Extract function information (parameters and return type)
            self._extract_function_info(function_signature, context)
            
            # 2. Extract type definitions
            self._extract_type_definitions(context)
            
            # 3. Extract usage examples
            self._extract_usage_examples(function_signature, context)
            
            # 4. Identify initialization patterns
            self._identify_initialization_patterns(context)
            
            # 5. Find related functions
            self._find_related_functions(context)
            
            # 6. Identify side effects (NEW)
            self._identify_side_effects(function_signature, context)
            
            logger.info(f"Successfully extracted API context for {function_signature}")
            logger.info(f"  - Parameters: {len(context['parameters'])}")
            logger.info(f"  - Type definitions: {len(context['type_definitions'])}")
            logger.info(f"  - Usage examples: {len(context['usage_examples'])}")
            logger.info(f"  - Initialization patterns: {len(context['initialization_patterns'])}")
            logger.info(f"  - Side effects identified: {bool(context['side_effects'])}")
            
        except Exception as e:
            logger.error(f"Failed to extract API context: {e}", exc_info=True)
        
        return context
    
    def _extract_function_info(self, func_sig: str, context: Dict):
        """Extract function signature information"""
        logger.debug(f"Extracting function info for {func_sig}")
        
        # Method 1 (NEW): Use Debug Types API (more accurate)
        try:
            arg_types = introspector.query_introspector_function_debug_arg_types(
                self.project_name, func_sig
            )
            if arg_types:
                # Debug types returns parameter type list
                context['parameters'] = [
                    {
                        'name': f'param{i}',
                        'type': arg_type
                    }
                    for i, arg_type in enumerate(arg_types)
                ]
                logger.debug(f"Extracted {len(arg_types)} parameters from debug types")
                
                # Try to get return type (infer from function signature)
                context['return_type'] = self._infer_return_type_from_signature(func_sig)
                return
        except Exception as e:
            logger.debug(f"Could not get debug types: {e}")
        
        # Method 2 (Fallback): Parse from source code
        func_source = introspector.query_introspector_function_source(
            self.project_name, func_sig
        )
        
        if func_source:
            # Parse function signature from source code
            parsed = self._parse_function_signature_from_source(func_source)
            if parsed:
                context['parameters'] = parsed.get('parameters', [])
                context['return_type'] = parsed.get('return_type', '')
                logger.debug(f"Parsed {len(context['parameters'])} parameters from source")
                return
        
        # Method 3: Use default values (last resort)
        logger.warning(f"Could not get function info for {func_sig}, using defaults")
        context['parameters'] = []
        context['return_type'] = 'int'  # Default
    
    def _infer_return_type_from_signature(self, func_sig: str) -> str:
        """Infer return type from function signature"""
        # Simple heuristic rules
        if func_sig.startswith('void '):
            return 'void'
        elif func_sig.startswith('int '):
            return 'int'
        elif func_sig.startswith('char '):
            return 'char'
        elif func_sig.startswith('bool '):
            return 'bool'
        elif '*' in func_sig.split('(')[0]:
            return 'pointer'
        else:
            return 'int'  # Default
    
    def _parse_function_signature_from_source(self, source: str) -> Optional[Dict]:
        """Parse function signature from source code"""
        # Simple regex parsing
        # Match: return_type function_name(params) {
        pattern = r'^\s*([a-zA-Z_][\w\s\*]*?)\s+([a-zA-Z_]\w*)\s*\((.*?)\)\s*\{'
        
        match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
        if not match:
            return None
        
        return_type = match.group(1).strip()
        params_str = match.group(3).strip()
        
        # Parse parameters
        parameters = []
        if params_str and params_str != 'void':
            for param in params_str.split(','):
                param = param.strip()
                if not param:
                    continue
                
                # Simple parsing: type name
                parts = param.rsplit(None, 1)
                if len(parts) == 2:
                    param_type, param_name = parts
                    parameters.append({
                        'name': param_name,
                        'type': param_type
                    })
                else:
                    # Only type, no name
                    parameters.append({
                        'name': f'param{len(parameters)}',
                        'type': param
                    })
        
        return {
            'return_type': return_type,
            'parameters': parameters
        }
    
    def _extract_type_definitions(self, context: Dict):
        """Extract parameter type definitions"""
        logger.debug("Extracting type definitions")
        
        # Get all type definitions for project (single query)
        try:
            all_types = introspector.query_introspector_type_definition(
                self.project_name
            )
            # Build type name to definition mapping
            type_map = {t.get('name', ''): t for t in all_types if t.get('name')}
            logger.debug(f"Loaded {len(type_map)} type definitions")
        except Exception as e:
            logger.debug(f"Could not get type definitions: {e}")
            type_map = {}
        
        # Look up type definition for each parameter
        for param in context['parameters']:
            param_type = clean_type_name(param['type'])
            
            # Skip primitive types
            if is_primitive_type(param_type):
                continue
            
            # Look up type definition
            if param_type in type_map:
                context['type_definitions'][param_type] = type_map[param_type]
                logger.debug(f"Found type definition for {param_type}")
    
    def _extract_usage_examples(self, func_sig: str, context: Dict):
        """Extract usage examples from existing code (optimized sampling strategy)"""
        logger.debug(f"Extracting usage examples for {func_sig}")
        
        # Method 0 (HIGHEST PRIORITY): Extract usage from test files (cleanest API usage examples)
        try:
            # Extract simple function name from signature for test xref query
            # e.g., "void curl_easy_perform(CURL *)" -> "curl_easy_perform"
            func_name = self._extract_function_name(func_sig)
            if func_name:
                logger.debug(f"Querying test xrefs for function: {func_name}")
                test_xrefs = introspector.query_introspector_for_tests_xref(
                    self.project_name, [func_name]
                )
                
                # test_xrefs format: {'source': [lines], 'details': [structured_snippets]}
                if test_xrefs:
                    # Prefer 'details' if available (structured call information)
                    details = test_xrefs.get('details', [])
                    if details:
                        logger.debug(f"Found {len(details)} detailed test examples")
                        for i, detail_lines in enumerate(details[:3], 1):  # Limit to 3
                            if detail_lines:  # detail_lines is a list of code lines
                                source_code = '\n'.join(detail_lines)
                                context['usage_examples'].append({
                                    'source': source_code,
                                    'file': 'test_file',  # Generic, FI doesn't give specific path
                                    'function': f'test_example_{i}',
                                    'line': 0,
                                    'source_type': 'test_file',  # HIGHEST quality marker
                                    'priority': 1000  # Far higher than other sources
                                })
                        logger.info(f"✓ Added {len(details[:3])} high-quality test examples")
                        return  # Test files are the cleanest examples - use them exclusively
                    
                    # Fallback: use 'source' (plain text snippets)
                    source_lines = test_xrefs.get('source', [])
                    if source_lines:
                        # source_lines is a list of strings, need to group them
                        source_code = '\n'.join(source_lines[:50])  # Limit total lines
                        if source_code.strip():
                            context['usage_examples'].append({
                                'source': source_code,
                                'file': 'test_file',
                                'function': 'test_example',
                                'line': 0,
                                'source_type': 'test_file',
                                'priority': 1000
                            })
                            logger.info(f"✓ Added test file example ({len(source_lines)} lines)")
                            return
        except Exception as e:
            logger.debug(f"Could not get test xrefs: {e}")
        
        # Method 1 (Fallback): Use Sample XRefs API (preprocessed high-quality examples)
        try:
            sample_xrefs = introspector.query_introspector_sample_xrefs(
                self.project_name, func_sig
            )
            if sample_xrefs:
                logger.debug(f"Found {len(sample_xrefs)} sample cross-references")
                
                # Sample xrefs are already preprocessed code snippets
                for i, source_code in enumerate(sample_xrefs[:3]):  # Limit to 3
                    context['usage_examples'].append({
                        'source': source_code,
                        'file': '',  # Sample xrefs don't contain file information
                        'function': f'example_{i+1}',
                        'line': 0,
                        'source_type': 'sample_xref'
                    })
                logger.debug(f"Added {len(context['usage_examples'])} sample xref examples")
                return  # If sample xrefs exist, prioritize using them
        except Exception as e:
            logger.debug(f"Could not get sample xrefs: {e}")
        
        # Note: Method 2 (call_sites) has been removed
        # Reasons:
        #  - test_xrefs and sample_xrefs already provide sufficiently high-quality examples
        #  - call_sites requires secondary queries, priority sorting, snippet extraction, high complexity
        #  - Quality is not as good as the former two (contains internal implementation, business logic)
        # 特殊用例（如 function_analyzer 的迭代学习）仍可直接调用底层 API
    
    def _identify_initialization_patterns(self, context: Dict):
        """识别需要初始化的类型和初始化方法"""
        logger.debug("Identifying initialization patterns")
        
        for param in context['parameters']:
            param_type = clean_type_name(param['type'])
            param_name = param['name']
            
            # 检查是否需要初始化
            if check_requires_initialization(param_type, param):
                # 推断初始化方法
                init_method = self._infer_initialization_method(param_type)
                
                context['initialization_patterns'].append({
                    'parameter': param_name,
                    'type': param_type,
                    'method': init_method,
                    'reason': self._get_initialization_reason(param_type)
                })
                
                logger.debug(f"Identified initialization pattern for {param_type}")
    
    
    def _infer_initialization_method(self, param_type: str) -> str:
        """推断初始化方法"""
        base_name = get_base_name_from_type(param_type)
        
        # 检查是否存在初始化函数
        for suffix in INIT_SUFFIXES:
            init_func = base_name + suffix
            if self._function_exists(init_func):
                return f"{init_func}(&var)"
        
        # 默认：使用 memset
        return f"memset(&var, 0, sizeof({param_type}))"
    
    def _get_initialization_reason(self, param_type: str) -> str:
        """获取需要初始化的原因"""
        type_lower = param_type.lower()
        
        for kw in INIT_REQUIRED_KEYWORDS:
            if kw in type_lower:
                return f"Type name contains '{kw}', typically requires initialization"
        
        return "Output parameter of struct type"
    
    def _find_related_functions(self, context: Dict):
        """查找相关的初始化/清理函数"""
        logger.debug("Finding related functions")
        
        for param_type in context['type_definitions'].keys():
            base_name = get_base_name_from_type(param_type)
            
            # 查找初始化函数
            for suffix in INIT_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'initialization',
                        'for_type': param_type
                    })
            
            # 查找清理函数
            for suffix in CLEANUP_SUFFIXES:
                func_name = base_name + suffix
                if self._function_exists(func_name):
                    context['related_functions'].append({
                        'name': func_name,
                        'type': 'cleanup',
                        'for_type': param_type
                    })
    
    def _identify_side_effects(self, func_sig: str, context: Dict):
        """识别函数的副作用
        
        使用两种方法：
        1. 分析函数源代码中的关键词（快速但可能不完整）
        2. 分析函数调用的其他函数（functions_reached）（更准确）
        """
        logger.debug(f"Identifying side effects for {func_sig}")
        
        side_effects = {
            'modifies_global_state': False,
            'performs_io': False,
            'allocates_memory': False,
            'frees_memory': False,
            'has_output_params': False,
            'indicators': []
        }
        
        try:
            # 方法1: 从函数源码推断副作用（原有方法）
            func_source = introspector.query_introspector_function_source(
                self.project_name, func_sig
            )
            
            if func_source:
                source_lower = func_source.lower()
                
                # 检查I/O操作
                io_keywords = ['printf', 'fprintf', 'write', 'read', 'fwrite', 'fread', 
                               'fopen', 'fclose', 'open(', 'close(']
                if any(kw in source_lower for kw in io_keywords):
                    side_effects['performs_io'] = True
                    side_effects['indicators'].append('Contains I/O operations (source)')
                
                # 检查内存分配
                alloc_keywords = ['malloc', 'calloc', 'realloc', 'new ', 'alloc']
                if any(kw in source_lower for kw in alloc_keywords):
                    side_effects['allocates_memory'] = True
                    side_effects['indicators'].append('Allocates memory (source)')
                
                # 检查内存释放
                free_keywords = ['free(', 'delete ', 'release']
                if any(kw in source_lower for kw in free_keywords):
                    side_effects['frees_memory'] = True
                    side_effects['indicators'].append('Frees memory (source)')
                
                # 检查全局变量访问
                if 'static ' in source_lower or 'global' in source_lower:
                    side_effects['modifies_global_state'] = True
                    side_effects['indicators'].append('May modify global state (source)')
            
            # 方法2: 从 functions_reached 推断副作用（新增）
            try:
                functions_reached = introspector.query_introspector_functions_reached(
                    self.project_name, func_sig
                )
                
                if functions_reached:
                    logger.debug(f"Analyzing {len(functions_reached)} functions reached")
                    
                    for called_func in functions_reached:
                        func_lower = called_func.lower()
                        
                        # I/O 函数
                        io_funcs = ['printf', 'fprintf', 'scanf', 'fscanf', 'fopen', 
                                   'fclose', 'fread', 'fwrite', 'write', 'read', 
                                   'open', 'close', 'puts', 'fputs', 'gets', 'fgets']
                        if any(io_func in func_lower for io_func in io_funcs):
                            if not side_effects['performs_io']:
                                side_effects['performs_io'] = True
                                side_effects['indicators'].append(
                                    f'Calls I/O function: {called_func[:50]}'
                                )
                        
                        # 内存管理函数
                        alloc_funcs = ['malloc', 'calloc', 'realloc', 'operator new']
                        if any(alloc_func in func_lower for alloc_func in alloc_funcs):
                            if not side_effects['allocates_memory']:
                                side_effects['allocates_memory'] = True
                                side_effects['indicators'].append(
                                    f'Calls allocation: {called_func[:50]}'
                                )
                        
                        free_funcs = ['free', 'delete', 'operator delete']
                        if any(free_func in func_lower for free_func in free_funcs):
                            if not side_effects['frees_memory']:
                                side_effects['frees_memory'] = True
                                side_effects['indicators'].append(
                                    f'Calls free: {called_func[:50]}'
                                )
            
            except Exception as e:
                logger.debug(f"Could not analyze functions_reached: {e}")
            
            # 从参数推断副作用
            for param in context.get('parameters', []):
                param_type = param.get('type', '')
                # 输出参数（非const指针）
                if '*' in param_type and 'const' not in param_type.lower():
                    side_effects['has_output_params'] = True
                    side_effects['indicators'].append(f'Has output parameter: {param["name"]}')
                    break
            
            context['side_effects'] = side_effects
            logger.debug(f"Identified {len(side_effects['indicators'])} side effect indicators")
            
        except Exception as e:
            logger.debug(f"Could not identify side effects: {e}")
            context['side_effects'] = side_effects
    
    def _extract_function_name(self, func_sig: str) -> Optional[str]:
        """
        从函数签名中提取简单函数名
        
        Examples:
            "void curl_easy_perform(CURL *)" -> "curl_easy_perform"
            "int parse_header(const char*, size_t)" -> "parse_header"
            "igraph_sparsemat_arpack_rssolve" -> "igraph_sparsemat_arpack_rssolve"
        """
        import re
        
        # Case 1: Full signature with parentheses (e.g., "void func(int x)")
        if '(' in func_sig:
            # Extract the last identifier before '('
            match = re.search(r'\b([a-zA-Z_]\w*)\s*\(', func_sig)
            if match:
                return match.group(1)
        
        # Case 2: Simple function name without signature
        # Clean up any leading type info (e.g., "void func" -> "func")
        parts = func_sig.strip().split()
        if parts:
            return parts[-1]  # Last word is likely the function name
        
        return None
    
    def _function_exists(self, func_name: str) -> bool:
        """检查函数是否存在"""
        # 懒加载：第一次调用时获取所有函数列表
        if self._all_functions_cache is None:
            try:
                # 查询项目的所有函数
                all_funcs = introspector.query_introspector_all_functions(
                    self.project_name
                )
                self._all_functions_cache = set(
                    f.get('function-name', '') for f in all_funcs
                )
                logger.debug(f"Cached {len(self._all_functions_cache)} function names")
            except Exception as e:
                logger.debug(f"Could not get all functions: {e}")
                self._all_functions_cache = set()
        
        return func_name in self._all_functions_cache


def get_api_context(project_name: str, function_signature: str) -> Optional[Dict]:
    """
    便捷函数：获取函数的 API 上下文
    
    Args:
        project_name: 项目名称（如 "igraph"）
        function_signature: 函数签名（如 "igraph_sparsemat_arpack_rssolve"）
    
    Returns:
        API 上下文字典，如果提取失败则返回 None
    """
    try:
        extractor = APIContextExtractor(project_name)
        context = extractor.extract(function_signature)
        return context if context['parameters'] or context['usage_examples'] else None
    except Exception as e:
        logger.error(f"Failed to get API context: {e}", exc_info=True)
        return None


def format_api_context_for_prompt(context: Dict) -> str:
    """
    将 API 上下文格式化为适合注入 prompt 的文本（优化版）
    
    Args:
        context: API 上下文字典
    
    Returns:
        格式化的文本
    """
    if not context:
        return ""
    
    sections = []
    
    # 1. 参数信息
    if context.get('parameters'):
        sections.append("### Parameters\n")
        for param in context['parameters']:
            sections.append(f"- `{param['name']}` ({param['type']})")
        sections.append("")
    
    # 2. 副作用信息（NEW - 重要！）
    if context.get('side_effects') and context['side_effects'].get('indicators'):
        sections.append("### ⚠️ Side Effects & Behavior\n")
        side_effects = context['side_effects']
        for indicator in side_effects['indicators']:
            sections.append(f"- {indicator}")
        sections.append("")
    
    # 3. 初始化要求（重要！）
    if context.get('initialization_patterns'):
        sections.append("### ⚠️ Initialization Requirements\n")
        for pattern in context['initialization_patterns']:
            sections.append(
                f"- **{pattern['parameter']}** ({pattern['type']}): "
                f"{pattern['method']}"
            )
            sections.append(f"  Reason: {pattern['reason']}")
        sections.append("")
    
    # 4. 相关函数
    if context.get('related_functions'):
        init_funcs = [f for f in context['related_functions'] if f['type'] == 'initialization']
        cleanup_funcs = [f for f in context['related_functions'] if f['type'] == 'cleanup']
        
        if init_funcs:
            sections.append("### Related Initialization Functions\n")
            for func in init_funcs:
                sections.append(f"- `{func['name']}` for `{func['for_type']}`")
            sections.append("")
        
        if cleanup_funcs:
            sections.append("### Related Cleanup Functions\n")
            for func in cleanup_funcs:
                sections.append(f"- `{func['name']}` for `{func['for_type']}`")
            sections.append("")
    
    # 5. 用法示例（优化：优先显示测试文件，明确标注质量）
    if context.get('usage_examples'):
        sections.append("### Usage Examples from Existing Code\n")
        for i, example in enumerate(context['usage_examples'][:2], 1):
            source_type = example.get('source_type', 'unknown')
            
            # Quality indicators (from highest to lowest)
            if source_type == 'test_file':
                quality_indicator = "🏆 TEST FILE (Highest Quality - Clean API Usage)"
            elif source_type == 'sample_xref':
                quality_indicator = "✓ High-quality"
            else:
                quality_indicator = ""
            
            sections.append(f"#### Example {i}: {example['function']} {quality_indicator}")
            if example.get('file'):
                sections.append(f"Source: {example['file']}")
            sections.append(f"```c\n{example['source']}\n```\n")
    
    if sections:
        return "## API Context\n\n" + "\n".join(sections)
    
    return ""

