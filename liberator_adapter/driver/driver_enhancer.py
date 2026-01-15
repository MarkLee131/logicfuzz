"""
Driver Enhancer - Enhance Driver generation using special pattern analysis

Integrates special pattern analysis (VarLen, Loop, Callback, TLV) into driver generation workflow.

Main features:
1. Enhanced Callback stub generation (using CallbackAnalyzer)
2. Provide VarLen relationship information for parameter allocation
3. Identify APIs that need loops
4. Mark TLV parsers for seed generation
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from liberator_adapter.common.api import Api
from liberator_adapter.constraints.special_patterns import (
    SpecialPatternAnalyzer,
    VarLenAnalyzer,
    VarLenRelation,
    LoopPatternAnalyzer,
    LoopPatternInfo,
    CallbackAnalyzer,
    CallbackInfo,
    CallbackType,
    TLVAnalysisResult,
    LLMClient,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Enhanced Callback Stub Code Generation
# =============================================================================

class EnhancedCallbackStubGenerator:
    """
    Enhanced Callback Stub Generator

    Generates more appropriate stub code based on CallbackAnalyzer analysis results
    """

    def __init__(self, callback_analyzer: Optional[CallbackAnalyzer] = None):
        self.callback_analyzer = callback_analyzer or CallbackAnalyzer()
        self._generated_stubs: Dict[str, str] = {}  # func_name -> stub_code

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.callback_analyzer.set_llm_client(llm_client)

    def generate_stub_for_api(self, api: Api, arg_idx: int,
                               func_name: str) -> Tuple[str, CallbackType]:
        """
        Generate stub for specific callback parameter of API

        Args:
            api: API object
            arg_idx: Callback parameter index
            func_name: Generated function name

        Returns:
            (stub_code, callback_type)
        """
        # Analyze callback
        result = self.callback_analyzer.analyze(api)

        # Find corresponding callback info
        callback_info = None
        for cb in result.callbacks:
            if cb.arg_idx == arg_idx:
                callback_info = cb
                break

        if callback_info is None:
            # Not analyzed, return empty stub
            return self._generate_empty_stub(func_name), CallbackType.UNKNOWN

        # Use analyzed stub code
        if callback_info.stub_code:
            stub = callback_info.stub_code
            # Replace placeholder name
            stub = self._customize_stub_name(stub, func_name, callback_info)
            self._generated_stubs[func_name] = stub
            return stub, callback_info.callback_type

        # Generate from template
        stub = self._generate_from_template(func_name, callback_info)
        self._generated_stubs[func_name] = stub
        return stub, callback_info.callback_type

    def _generate_empty_stub(self, func_name: str) -> str:
        """Generate empty stub"""
        return f'''
void {func_name}(void) {{
    // Generic empty callback stub
}}
'''

    def _customize_stub_name(self, stub: str, func_name: str,
                             callback_info: CallbackInfo) -> str:
        """自定义stub名称"""
        # 替换模板中的占位符
        old_patterns = [
            f"fuzz_comparator_{callback_info.arg_name}",
            f"fuzz_handler_{callback_info.arg_name}",
            f"fuzz_reader_{callback_info.arg_name}",
            f"fuzz_writer_{callback_info.arg_name}",
            f"fuzz_allocator_{callback_info.arg_name}",
            f"fuzz_deallocator_{callback_info.arg_name}",
            f"fuzz_visitor_{callback_info.arg_name}",
            f"fuzz_callback_{callback_info.arg_name}",
        ]

        for pattern in old_patterns:
            if pattern in stub:
                stub = stub.replace(pattern, func_name)
                break

        # 替换Context类型名
        stub = stub.replace(
            f"FuzzReaderCtx_{callback_info.arg_name}",
            f"FuzzReaderCtx_{func_name}"
        )

        return stub

    def _generate_from_template(self, func_name: str,
                                callback_info: CallbackInfo) -> str:
        """根据callback类型生成stub"""
        templates = {
            CallbackType.COMPARATOR: f'''
int {func_name}(const void* a, const void* b) {{
    return memcmp(a, b, 1);
}}
''',
            CallbackType.HANDLER: f'''
void {func_name}(void* user_data) {{
    (void)user_data;
}}
''',
            CallbackType.READER: f'''
typedef struct {{
    const uint8_t* data;
    size_t size;
    size_t pos;
}} FuzzReaderCtx_{func_name};

size_t {func_name}(void* ptr, size_t size, void* stream) {{
    FuzzReaderCtx_{func_name}* ctx = (FuzzReaderCtx_{func_name}*)stream;
    size_t avail = ctx->size - ctx->pos;
    size_t to_read = (size < avail) ? size : avail;
    if (to_read > 0) {{
        memcpy(ptr, ctx->data + ctx->pos, to_read);
        ctx->pos += to_read;
    }}
    return to_read;
}}
''',
            CallbackType.WRITER: f'''
size_t {func_name}(const void* ptr, size_t size, void* stream) {{
    (void)ptr;
    (void)stream;
    return size;
}}
''',
            CallbackType.ALLOCATOR: f'''
void* {func_name}(size_t size) {{
    if (size > 1024 * 1024) return NULL;
    return malloc(size);
}}
''',
            CallbackType.DEALLOCATOR: f'''
void {func_name}(void* ptr) {{
    free(ptr);
}}
''',
            CallbackType.VISITOR: f'''
int {func_name}(void* item, void* user_data) {{
    (void)item;
    (void)user_data;
    return 0;
}}
''',
        }

        return templates.get(callback_info.callback_type,
                            self._generate_empty_stub(func_name))

    def get_all_stubs(self) -> Dict[str, str]:
        """获取所有生成的stub"""
        return self._generated_stubs.copy()


# =============================================================================
# API模式信息缓存
# =============================================================================

@dataclass
class APIPatternCache:
    """API模式分析结果缓存"""
    varlen_relations: Dict[str, List[VarLenRelation]] = field(default_factory=dict)
    loop_patterns: Dict[str, LoopPatternInfo] = field(default_factory=dict)
    callback_infos: Dict[str, List[CallbackInfo]] = field(default_factory=dict)
    tlv_results: Dict[str, TLVAnalysisResult] = field(default_factory=dict)

    def has_varlen(self, api_name: str) -> bool:
        return api_name in self.varlen_relations and len(self.varlen_relations[api_name]) > 0

    def needs_loop(self, api_name: str) -> bool:
        return api_name in self.loop_patterns and self.loop_patterns[api_name].needs_loop

    def has_callbacks(self, api_name: str) -> bool:
        return api_name in self.callback_infos and len(self.callback_infos[api_name]) > 0

    def is_structured_parser(self, api_name: str) -> bool:
        return api_name in self.tlv_results and self.tlv_results[api_name].is_structured


# =============================================================================
# Driver增强器
# =============================================================================

class DriverEnhancer:
    """
    Driver增强器

    在Driver生成流程中集成特殊模式分析，提供：
    1. Callback stub增强
    2. VarLen关系信息
    3. Loop模式检测
    4. TLV解析器标记
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.pattern_analyzer = SpecialPatternAnalyzer(llm_client)
        self.stub_generator = EnhancedCallbackStubGenerator()
        self.cache = APIPatternCache()

        if llm_client:
            self.stub_generator.set_llm_client(llm_client)

    def set_llm_client(self, llm_client: LLMClient):
        """设置LLM客户端"""
        self.llm_client = llm_client
        self.pattern_analyzer.set_llm_client(llm_client)
        self.stub_generator.set_llm_client(llm_client)

    def analyze_api(self, api: Api) -> None:
        """
        分析单个API并缓存结果

        Args:
            api: API对象
        """
        result = self.pattern_analyzer.analyze(api)

        # 缓存结果
        if result.varlen:
            self.cache.varlen_relations[api.function_name] = result.varlen.relations

        if result.loop:
            self.cache.loop_patterns[api.function_name] = result.loop

        if result.callbacks:
            self.cache.callback_infos[api.function_name] = result.callbacks.callbacks

        if result.tlv:
            self.cache.tlv_results[api.function_name] = result.tlv

    def analyze_apis(self, apis: List[Api]) -> None:
        """批量分析API"""
        for api in apis:
            self.analyze_api(api)

    def get_varlen_relations(self, api_name: str) -> List[VarLenRelation]:
        """获取API的var-len关系"""
        return self.cache.varlen_relations.get(api_name, [])

    def get_loop_pattern(self, api_name: str) -> Optional[LoopPatternInfo]:
        """获取API的循环模式信息"""
        return self.cache.loop_patterns.get(api_name)

    def needs_loop(self, api_name: str) -> bool:
        """检查API是否需要循环调用"""
        return self.cache.needs_loop(api_name)

    def get_callback_infos(self, api_name: str) -> List[CallbackInfo]:
        """获取API的callback信息"""
        return self.cache.callback_infos.get(api_name, [])

    def is_structured_parser(self, api_name: str) -> bool:
        """检查API是否是结构化数据解析器"""
        return self.cache.is_structured_parser(api_name)

    def generate_callback_stub(self, api: Api, arg_idx: int,
                                func_name: str) -> Tuple[str, CallbackType]:
        """
        为callback参数生成stub代码

        Args:
            api: API对象
            arg_idx: callback参数索引
            func_name: 生成的函数名

        Returns:
            (stub_code, callback_type)
        """
        return self.stub_generator.generate_stub_for_api(api, arg_idx, func_name)

    def get_buffer_size_constraint(self, api_name: str,
                                    buffer_arg_idx: int) -> Optional[Tuple[int, str]]:
        """
        获取buffer参数的size约束

        Args:
            api_name: API名称
            buffer_arg_idx: buffer参数索引

        Returns:
            (size_arg_idx, relationship) 或 None
        """
        relations = self.get_varlen_relations(api_name)
        for rel in relations:
            if rel.buffer_arg_idx == buffer_arg_idx:
                return (rel.length_arg_idx, rel.relationship)
        return None

    def get_enhancement_summary(self) -> Dict[str, Any]:
        """获取增强信息摘要"""
        return {
            "total_apis_analyzed": len(self.cache.varlen_relations) +
                                   len(self.cache.loop_patterns),
            "apis_with_varlen": sum(1 for rels in self.cache.varlen_relations.values()
                                    if len(rels) > 0),
            "apis_needing_loop": sum(1 for info in self.cache.loop_patterns.values()
                                     if info.needs_loop),
            "apis_with_callbacks": sum(1 for cbs in self.cache.callback_infos.values()
                                       if len(cbs) > 0),
            "structured_parsers": sum(1 for res in self.cache.tlv_results.values()
                                      if res.is_structured),
        }

    def clear_cache(self):
        """清除缓存"""
        self.cache = APIPatternCache()
        self.pattern_analyzer.clear_cache()


# =============================================================================
# 增强的Context（可选替换原有Context）
# =============================================================================

def enhance_context_get_function_pointer(original_method):
    """
    装饰器：增强Context.get_function_pointer方法

    使用CallbackAnalyzer生成更智能的stub
    """
    def enhanced_method(self, type, api=None, arg_idx=None, enhancer=None):
        if enhancer and api and arg_idx is not None:
            # 使用增强的stub生成
            func_name = f"fuzz_cb_{api.function_name}_{arg_idx}"
            stub_code, cb_type = enhancer.generate_callback_stub(api, arg_idx, func_name)

            # 创建Function对象
            from liberator_adapter.driver.ir import Function
            func = Function(func_name, type)
            func.stub_code = stub_code
            func.callback_type = cb_type

            self.stub_functions[type] = func
            return func

        # 回退到原始方法
        return original_method(self, type)

    return enhanced_method


# =============================================================================
# 工具函数
# =============================================================================

def create_driver_enhancer(llm_client: Optional[LLMClient] = None) -> DriverEnhancer:
    """创建DriverEnhancer实例"""
    return DriverEnhancer(llm_client)


def analyze_api_patterns(apis: List[Api],
                         llm_client: Optional[LLMClient] = None) -> APIPatternCache:
    """
    分析API列表的特殊模式

    Args:
        apis: API列表
        llm_client: LLM客户端（可选）

    Returns:
        APIPatternCache: 分析结果缓存
    """
    enhancer = DriverEnhancer(llm_client)
    enhancer.analyze_apis(apis)
    return enhancer.cache


def get_varlen_for_api(api: Api,
                       llm_client: Optional[LLMClient] = None) -> List[VarLenRelation]:
    """快速获取单个API的var-len关系"""
    analyzer = VarLenAnalyzer(llm_client)
    result = analyzer.analyze(api)
    return result.relations


def get_loop_info_for_api(api: Api,
                          llm_client: Optional[LLMClient] = None) -> LoopPatternInfo:
    """快速获取单个API的循环模式信息"""
    analyzer = LoopPatternAnalyzer(llm_client)
    return analyzer.analyze(api)
