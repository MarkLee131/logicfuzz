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
    VarLenRelation,
    LoopPatternInfo,
    CallbackAnalyzer,
    CallbackInfo,
    CallbackType,
    TLVAnalysisResult,
    LLMClient,
)
from src.llm.adapter import create_llm_adapter

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
            # Not analyzed: return empty stub_code so the LFBackendDriver's
            # signature-aware default fallback runs at emit time. The
            # earlier ``_generate_empty_stub`` emitted ``void f(void)``,
            # which is shorter but breaks the link when the real callback
            # signature is anything else (the most common case).
            # 2026-05 DriverEnhancer review (issue #1).
            return "", CallbackType.UNKNOWN

        # Use analyzed stub code
        if callback_info.stub_code:
            stub = callback_info.stub_code
            # Replace placeholder name
            stub = self._customize_stub_name(stub, func_name, callback_info)
            return stub, callback_info.callback_type

        # Generate from template
        stub = self._generate_from_template(func_name, callback_info)
        return stub, callback_info.callback_type

    def _customize_stub_name(self, stub: str, func_name: str,
                             callback_info: CallbackInfo) -> str:
        """Customize stub name"""
        # Replace placeholders in template
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

        # Replace Context type name
        stub = stub.replace(
            f"FuzzReaderCtx_{callback_info.arg_name}",
            f"FuzzReaderCtx_{func_name}"
        )

        return stub

    def _generate_from_template(self, func_name: str,
                                callback_info: CallbackInfo) -> str:
        """Generate stub based on callback type"""
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
            # READER stub: previously defined a ``FuzzReaderCtx_xxx`` struct
            # and dereferenced ``stream`` as a pointer to it. CBFactory does
            # not emit the matching caller-side context allocation, so the
            # callee dereferenced whatever pointer the API was called with
            # — often NULL → segfault. Safer: signature-correct stub that
            # treats stream as an opaque cookie and returns 0 (EOF). This
            # loses the "feed fuzz data through the read callback" coverage
            # signal, but doesn't crash. Full restoration needs CBFactory
            # to emit a typed context variable AND wire it as the stream
            # arg. TODO tracked in docs/driverenhancer_refactor_2026_05.md.
            CallbackType.READER: f'''
size_t {func_name}(void* ptr, size_t size, void* stream) {{
    (void)ptr;
    (void)size;
    (void)stream;
    return 0;  // EOF — safe default until CBFactory wires a real context
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

        # Same fail-soft policy as the ``callback_info is None`` path: if
        # we don't have a template for this callback type, return ""
        # so LFBackendDriver.emit_stub_functions falls through to the
        # signature-aware default rather than emitting a wrong-signature
        # ``void f(void)``. 2026-05 DriverEnhancer review (issue #1).
        return templates.get(callback_info.callback_type, "")


# =============================================================================
# API Pattern Information Cache
# =============================================================================

@dataclass
class APIPatternCache:
    """API pattern analysis result cache"""
    varlen_relations: Dict[str, List[VarLenRelation]] = field(default_factory=dict)
    loop_patterns: Dict[str, LoopPatternInfo] = field(default_factory=dict)
    callback_infos: Dict[str, List[CallbackInfo]] = field(default_factory=dict)
    tlv_results: Dict[str, TLVAnalysisResult] = field(default_factory=dict)

    def needs_loop(self, api_name: str) -> bool:
        return api_name in self.loop_patterns and self.loop_patterns[api_name].needs_loop

    def is_structured_parser(self, api_name: str) -> bool:
        return api_name in self.tlv_results and self.tlv_results[api_name].is_structured


# =============================================================================
# Driver Enhancer
# =============================================================================

class DriverEnhancer:
    """
    Driver Enhancer

    Integrates special pattern analysis into driver generation workflow, providing:
    1. Callback stub enhancement
    2. VarLen relationship information
    3. Loop pattern detection
    4. TLV parser marking
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        # Wrap the LLM model in an adapter to provide query() method
        adapted_client = create_llm_adapter(llm_client)
        self.llm_client = adapted_client
        self.pattern_analyzer = SpecialPatternAnalyzer(adapted_client)
        self.stub_generator = EnhancedCallbackStubGenerator()
        self.cache = APIPatternCache()

        if adapted_client:
            self.stub_generator.set_llm_client(adapted_client)

    def analyze_api(self, api: Api) -> None:
        """
        Analyze single API and cache results

        Args:
            api: API object
        """
        result = self.pattern_analyzer.analyze(api)

        # Cache results
        if result.varlen:
            self.cache.varlen_relations[api.function_name] = result.varlen.relations

        if result.loop:
            self.cache.loop_patterns[api.function_name] = result.loop

        if result.callbacks:
            self.cache.callback_infos[api.function_name] = result.callbacks.callbacks

        if result.tlv:
            self.cache.tlv_results[api.function_name] = result.tlv

    def analyze_apis(self, apis: List[Api]) -> None:
        """Batch analyze APIs"""
        for api in apis:
            self.analyze_api(api)

    def get_varlen_relations(self, api_name: str) -> List[VarLenRelation]:
        """Get API's var-len relationships"""
        return self.cache.varlen_relations.get(api_name, [])

    def needs_loop(self, api_name: str) -> bool:
        """Check if API needs loop calls"""
        return self.cache.needs_loop(api_name)

    def is_structured_parser(self, api_name: str) -> bool:
        """Check if API is a structured data parser"""
        return self.cache.is_structured_parser(api_name)

    def generate_callback_stub(self, api: Api, arg_idx: int,
                                func_name: str) -> Tuple[str, CallbackType]:
        """
        Generate stub code for callback parameter

        Args:
            api: API object
            arg_idx: Callback parameter index
            func_name: Generated function name

        Returns:
            (stub_code, callback_type)
        """
        return self.stub_generator.generate_stub_for_api(api, arg_idx, func_name)

    def get_buffer_size_constraint(self, api_name: str,
                                    buffer_arg_idx: int) -> Optional[Tuple[int, str]]:
        """
        Get buffer parameter's size constraint

        Args:
            api_name: API name
            buffer_arg_idx: Buffer parameter index

        Returns:
            (size_arg_idx, relationship) or None
        """
        relations = self.get_varlen_relations(api_name)
        for rel in relations:
            if rel.buffer_arg_idx == buffer_arg_idx:
                return (rel.length_arg_idx, rel.relationship)
        return None

    def get_enhancement_summary(self) -> Dict[str, Any]:
        """Get enhancement information summary"""
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
        """Clear cache"""
        self.cache = APIPatternCache()
        self.pattern_analyzer.clear_cache()
