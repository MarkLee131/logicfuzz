"""
Special Pattern Analyzers

Implements two-phase analysis for four special scenarios:
- S1. Var-len: Variable-length parameter relationships
- S2. TLV: Type-Length-Value format
- S3. Loop: Loop call patterns
- S4. Callback: Callback functions

Design principles:
- Phase 1 (Static analysis): High recall, allows false positives
- Phase 2 (LLM reasoning): High precision, filters false positives
"""

import re
import logging
from enum import Enum
from typing import List, Tuple, Optional, Dict, Protocol
from dataclasses import dataclass, field

from liberator_adapter.common.api import Api
from liberator_adapter.prompt_loader import get_prompt_manager

logger = logging.getLogger(__name__)


# =============================================================================
# LLM Client Protocol (reused from sequence_filter definition)
# =============================================================================

class LLMClient(Protocol):
    """LLM client protocol"""
    def query(self, prompt: str) -> str:
        """Send prompt and return response"""
        ...


# =============================================================================
# S1. Var-len Variable-length Parameter Analysis
# =============================================================================

@dataclass
class VarLenRelation:
    """Variable-length parameter relationship"""
    buffer_arg_idx: int          # Buffer parameter index
    buffer_arg_name: str         # Buffer parameter name
    buffer_arg_type: str         # Buffer parameter type
    length_arg_idx: int          # Length parameter index
    length_arg_name: str         # Length parameter name
    length_arg_type: str         # Length parameter type
    relationship: str = "=="     # Relationship: ==, >=, size*count, etc.
    confidence: float = 0.0      # Confidence (0-1)
    reasoning: str = ""          # Reasoning basis


@dataclass
class VarLenAnalysisResult:
    """Var-len analysis result"""
    api_name: str
    relations: List[VarLenRelation] = field(default_factory=list)
    phase1_candidates: List[Tuple[int, int]] = field(default_factory=list)  # Phase1 candidates
    llm_confirmed: bool = False  # Whether confirmed by LLM


class VarLenAnalyzer:
    """
    Variable-length parameter analyzer

    Phase 1: Static analysis identifies candidate (pointer, integer) pairs
    Phase 2: LLM confirms semantic relationships
    """

    # Pointer type patterns
    POINTER_TYPES = {
        'char *', 'char*', 'const char *', 'const char*',
        'void *', 'void*', 'const void *', 'const void*',
        'uint8_t *', 'uint8_t*', 'const uint8_t *', 'const uint8_t*',
        'unsigned char *', 'unsigned char*', 'const unsigned char *',
        'int8_t *', 'int8_t*', 'const int8_t *',
        'byte *', 'byte*', 'BYTE *', 'BYTE*',
    }

    # Length type patterns
    LENGTH_TYPES = {
        'size_t', 'int', 'unsigned int', 'uint32_t', 'uint64_t',
        'long', 'unsigned long', 'ssize_t', 'int32_t', 'int64_t',
        'unsigned', 'uint', 'DWORD', 'SIZE_T',
    }

    # Naming patterns (buffer_pattern, length_pattern)
    NAME_PATTERNS = [
        (r'(?i)(buf|buffer|data|input|output|src|dst|ptr|mem|bytes)',
         r'(?i)(len|length|size|sz|n|count|num|cb)'),
        (r'(?i)(str|string|text|msg|message)',
         r'(?i)(len|length|size|n)'),
        (r'(?i)(key|value|payload|content|body)',
         r'(?i)(len|length|size|sz)'),
    ]

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self._cache: Dict[str, VarLenAnalysisResult] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client

    def analyze(self, api: Api) -> VarLenAnalysisResult:
        """
        Analyze API's var-len relationships

        Args:
            api: API object

        Returns:
            VarLenAnalysisResult: Analysis result
        """
        # Check cache
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # Phase 1: Static analysis identifies candidates
        candidates = self._phase1_static_analysis(api)

        result = VarLenAnalysisResult(
            api_name=api.function_name,
            phase1_candidates=candidates
        )

        if not candidates:
            self._cache[api.function_name] = result
            return result

        # Phase 2: LLM confirmation
        if self.llm_client:
            result = self._phase2_llm_confirm(api, candidates)
            result.llm_confirmed = True
        else:
            # No LLM, use heuristics to build relationships
            result.relations = self._heuristic_build_relations(api, candidates)

        self._cache[api.function_name] = result
        return result

    def _phase1_static_analysis(self, api: Api) -> List[Tuple[int, int]]:
        """
        Phase 1: Static analysis identifies candidate (buffer_idx, length_idx) pairs

        Strategy: Loose matching, allows false positives
        """
        candidates = []
        args = api.arguments_info

        if len(args) < 2:
            return candidates

        # Identify pointer parameters and integer parameters
        pointer_indices = []
        integer_indices = []

        for i, arg in enumerate(args):
            if self._is_pointer_type(arg.type):
                pointer_indices.append(i)
            if self._is_length_type(arg.type):
                integer_indices.append(i)

        # For each pointer parameter, find possible length parameter
        for ptr_idx in pointer_indices:
            ptr_arg = args[ptr_idx]

            for int_idx in integer_indices:
                if int_idx == ptr_idx:
                    continue

                int_arg = args[int_idx]

                # Check naming patterns
                if self._names_match(ptr_arg.name, int_arg.name):
                    candidates.append((ptr_idx, int_idx))
                # Check position patterns (adjacent parameters)
                elif abs(ptr_idx - int_idx) == 1:
                    candidates.append((ptr_idx, int_idx))

        # Deduplicate
        candidates = list(set(candidates))

        logger.debug(f"Phase1 candidates for {api.function_name}: {candidates}")
        return candidates

    def _is_pointer_type(self, type_str: str) -> bool:
        """Check if it's a pointer type"""
        type_str = type_str.strip()

        # Direct match
        if type_str in self.POINTER_TYPES:
            return True

        # Pattern match: contains * and is not a function pointer
        if '*' in type_str and '(*)' not in type_str:
            # Exclude char** etc. secondary pointers (usually not buffers)
            if type_str.count('*') == 1:
                return True

        return False

    def _is_length_type(self, type_str: str) -> bool:
        """Check if it's a length type"""
        type_str = type_str.strip()

        # Direct match
        if type_str in self.LENGTH_TYPES:
            return True

        # Pattern match
        for length_type in self.LENGTH_TYPES:
            if length_type in type_str and '*' not in type_str:
                return True

        return False

    def _names_match(self, ptr_name: str, int_name: str) -> bool:
        """Check if names match"""
        for buf_pattern, len_pattern in self.NAME_PATTERNS:
            if re.search(buf_pattern, ptr_name) and re.search(len_pattern, int_name):
                return True
        return False

    def _heuristic_build_relations(self, api: Api,
                                    candidates: List[Tuple[int, int]]) -> List[VarLenRelation]:
        """Heuristically build var-len relationships (used when no LLM)"""
        relations = []
        args = api.arguments_info

        for ptr_idx, int_idx in candidates:
            ptr_arg = args[ptr_idx]
            int_arg = args[int_idx]

            # Calculate confidence
            confidence = 0.5
            if self._names_match(ptr_arg.name, int_arg.name):
                confidence = 0.8
            elif abs(ptr_idx - int_idx) == 1:
                confidence = 0.6

            relations.append(VarLenRelation(
                buffer_arg_idx=ptr_idx,
                buffer_arg_name=ptr_arg.name,
                buffer_arg_type=ptr_arg.type,
                length_arg_idx=int_idx,
                length_arg_name=int_arg.name,
                length_arg_type=int_arg.type,
                relationship=">=",  # Conservative assumption
                confidence=confidence,
                reasoning="Heuristic: type and name pattern matching"
            ))

        return relations

    def _phase2_llm_confirm(self, api: Api,
                            candidates: List[Tuple[int, int]]) -> VarLenAnalysisResult:
        """Phase 2: LLM confirms semantic relationships"""
        # Build signature
        params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info])
        signature = f"{api.return_info.type} {api.function_name}({params})"

        # Build parameter description
        param_desc = []
        for i, arg in enumerate(api.arguments_info):
            param_desc.append(f"  [{i}] {arg.type} {arg.name}")

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_varlen_prompt(
            signature=signature,
            parameters="\n".join(param_desc)
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_llm_response(api, response, candidates)
            return result
        except Exception as e:
            logger.warning(f"LLM var-len analysis failed for {api.function_name}: {e}")
            # Use heuristics on failure
            return VarLenAnalysisResult(
                api_name=api.function_name,
                phase1_candidates=candidates,
                relations=self._heuristic_build_relations(api, candidates),
                llm_confirmed=False
            )

    def _parse_llm_response(self, api: Api, response: str,
                            candidates: List[Tuple[int, int]]) -> VarLenAnalysisResult:
        """Parse LLM response"""
        import json

        result = VarLenAnalysisResult(
            api_name=api.function_name,
            phase1_candidates=candidates
        )

        # Try to parse JSON
        try:
            # Extract JSON
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse LLM response as JSON: {response[:200]}")
            return result

        if data.get("no_varlen", False):
            return result

        # Build parameter name to index mapping
        name_to_idx = {arg.name: i for i, arg in enumerate(api.arguments_info)}

        for rel in data.get("relations", []):
            buf_name = rel.get("buffer_param", "")
            len_name = rel.get("length_param", "")

            buf_idx = name_to_idx.get(buf_name, -1)
            len_idx = name_to_idx.get(len_name, -1)

            if buf_idx >= 0 and len_idx >= 0:
                buf_arg = api.arguments_info[buf_idx]
                len_arg = api.arguments_info[len_idx]

                result.relations.append(VarLenRelation(
                    buffer_arg_idx=buf_idx,
                    buffer_arg_name=buf_name,
                    buffer_arg_type=buf_arg.type,
                    length_arg_idx=len_idx,
                    length_arg_name=len_name,
                    length_arg_type=len_arg.type,
                    relationship=rel.get("relationship", ">="),
                    confidence=0.9,  # High confidence for LLM confirmation
                    reasoning=rel.get("reasoning", "LLM confirmed")
                ))

        return result

    def clear_cache(self):
        """Clear cache"""
        self._cache.clear()


# =============================================================================
# S3. Loop Pattern Analysis
# =============================================================================

class LoopType(Enum):
    """Loop type"""
    ITERATOR = "iterator"           # Iterator pattern
    INCREMENTAL = "incremental"     # Incremental read pattern
    STATE_MACHINE = "state_machine" # State machine pattern
    NONE = "none"                   # No loop needed


@dataclass
class LoopPatternInfo:
    """Loop pattern information"""
    api_name: str
    needs_loop: bool = False
    loop_type: LoopType = LoopType.NONE
    termination_condition: str = ""      # Termination condition
    max_iterations: int = 100            # Maximum iterations (safety boundary)
    code_template: str = ""              # Code template
    confidence: float = 0.0
    reasoning: str = ""


class LoopPatternAnalyzer:
    """
    Loop pattern analyzer

    Phase 1: Static analysis to identify APIs that may need loops
    Phase 2: LLM confirmation of loop pattern and termination condition
    """

    # Iterator naming patterns
    ITERATOR_PATTERNS = [
        r'(?i)_next$', r'(?i)_iterate', r'(?i)_foreach',
        r'(?i)^get_next', r'(?i)^next_', r'(?i)_step$',
    ]

    # Incremental read naming patterns
    INCREMENTAL_PATTERNS = [
        r'(?i)_read$', r'(?i)^read_', r'(?i)_recv$', r'(?i)^recv_',
        r'(?i)_fetch', r'(?i)_consume', r'(?i)_pull',
    ]

    # State machine naming patterns
    STATE_MACHINE_PATTERNS = [
        r'(?i)_process$', r'(?i)_run$', r'(?i)_execute$',
        r'(?i)_tick$', r'(?i)_update$', r'(?i)_pump$',
    ]

    # Return types indicating "more available"
    CONTINUATION_RETURN_TYPES = {'bool', 'int', 'ssize_t', 'size_t'}

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self._cache: Dict[str, LoopPatternInfo] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client

    def analyze(self, api: Api) -> LoopPatternInfo:
        """Analyze loop pattern for API"""
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # Phase 1: Static analysis
        phase1_result = self._phase1_static_analysis(api)

        if not phase1_result.needs_loop:
            self._cache[api.function_name] = phase1_result
            return phase1_result

        # Phase 2: LLM confirmation
        if self.llm_client:
            result = self._phase2_llm_confirm(api, phase1_result)
        else:
            result = phase1_result

        self._cache[api.function_name] = result
        return result

    def _phase1_static_analysis(self, api: Api) -> LoopPatternInfo:
        """Phase 1: Static analysis to identify loop candidates"""
        func_name = api.function_name
        return_type = api.return_info.type

        # Check naming patterns
        loop_type = LoopType.NONE
        confidence = 0.0

        for pattern in self.ITERATOR_PATTERNS:
            if re.search(pattern, func_name):
                loop_type = LoopType.ITERATOR
                confidence = 0.7
                break

        if loop_type == LoopType.NONE:
            for pattern in self.INCREMENTAL_PATTERNS:
                if re.search(pattern, func_name):
                    loop_type = LoopType.INCREMENTAL
                    confidence = 0.7
                    break

        if loop_type == LoopType.NONE:
            for pattern in self.STATE_MACHINE_PATTERNS:
                if re.search(pattern, func_name):
                    loop_type = LoopType.STATE_MACHINE
                    confidence = 0.5
                    break

        # Check return type (only when function name doesn't have obvious non-loop characteristics)
        non_loop_name_patterns = [
            r'(?i)^init', r'(?i)_init$', r'(?i)^create', r'(?i)_create$',
            r'(?i)^new', r'(?i)_new$', r'(?i)^alloc', r'(?i)_alloc$',
            r'(?i)^open', r'(?i)_open$', r'(?i)^close', r'(?i)_close$',
            r'(?i)^free', r'(?i)_free$', r'(?i)^destroy', r'(?i)_destroy$',
            r'(?i)^set_', r'(?i)^get_(?!next)', r'(?i)_set$',
        ]

        is_non_loop_name = any(re.search(p, func_name) for p in non_loop_name_patterns)

        if loop_type == LoopType.NONE and not is_non_loop_name:
            # Returning pointer might be iterator
            if '*' in return_type and 'void' not in return_type.lower():
                loop_type = LoopType.ITERATOR
                confidence = 0.4
            # Returning int/size_t might be incremental read
            elif any(t in return_type for t in self.CONTINUATION_RETURN_TYPES):
                # Check if there's an output buffer parameter (not Context/State type)
                has_output_buffer = any(
                    '*' in arg.type and
                    not any(c in arg.type for c in ['const']) and
                    not any(kw in arg.type.lower() for kw in ['context', 'state', 'ctx', 'handle'])
                    for arg in api.arguments_info
                )
                if has_output_buffer:
                    loop_type = LoopType.INCREMENTAL
                    confidence = 0.4

        # Build result
        needs_loop = loop_type != LoopType.NONE
        termination = self._guess_termination(loop_type, return_type)

        return LoopPatternInfo(
            api_name=func_name,
            needs_loop=needs_loop,
            loop_type=loop_type,
            termination_condition=termination,
            max_iterations=100,
            confidence=confidence,
            reasoning="Phase1: name pattern and return type analysis"
        )

    def _guess_termination(self, loop_type: LoopType, return_type: str) -> str:
        """Guess termination condition"""
        if loop_type == LoopType.ITERATOR:
            if '*' in return_type:
                return "return == NULL"
            return "return == 0"
        elif loop_type == LoopType.INCREMENTAL:
            return "return <= 0"
        elif loop_type == LoopType.STATE_MACHINE:
            return "return == DONE"
        return ""

    def _phase2_llm_confirm(self, api: Api,
                            phase1: LoopPatternInfo) -> LoopPatternInfo:
        """Phase 2: LLM confirmation"""
        params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info])
        signature = f"{api.return_info.type} {api.function_name}({params})"

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_loop_prompt(
            signature=signature,
            return_type=api.return_info.type,
            parameters=params or "void"
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            return self._parse_llm_response(api, response)
        except Exception as e:
            logger.warning(f"LLM loop analysis failed for {api.function_name}: {e}")
            return phase1

    def _parse_llm_response(self, api: Api, response: str) -> LoopPatternInfo:
        """Parse LLM response"""
        import json

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse loop LLM response: {response[:200]}")
            return LoopPatternInfo(api_name=api.function_name)

        loop_type_map = {
            "iterator": LoopType.ITERATOR,
            "incremental": LoopType.INCREMENTAL,
            "state_machine": LoopType.STATE_MACHINE,
            "none": LoopType.NONE,
        }

        return LoopPatternInfo(
            api_name=api.function_name,
            needs_loop=data.get("needs_loop", False),
            loop_type=loop_type_map.get(data.get("loop_type", "none"), LoopType.NONE),
            termination_condition=data.get("termination_condition", ""),
            max_iterations=data.get("max_iterations", 100),
            code_template=data.get("code_template", ""),
            confidence=0.9 if data.get("needs_loop") else 0.5,
            reasoning=data.get("reasoning", "LLM analysis")
        )

    def clear_cache(self):
        """Clear cache"""
        self._cache.clear()


# =============================================================================
# S4. Callback Function Analysis
# =============================================================================

class CallbackType(Enum):
    """Callback function type"""
    COMPARATOR = "comparator"       # Comparison function
    HANDLER = "handler"             # Event handler
    READER = "reader"               # Read function
    WRITER = "writer"               # Write function
    ALLOCATOR = "allocator"         # Allocator
    DEALLOCATOR = "deallocator"     # Deallocator
    VISITOR = "visitor"             # Visitor
    UNKNOWN = "unknown"


@dataclass
class CallbackInfo:
    """Callback function information"""
    arg_idx: int                    # Argument index
    arg_name: str                   # Argument name
    arg_type: str                   # Argument type
    callback_type: CallbackType = CallbackType.UNKNOWN
    can_be_null: bool = False       # Whether NULL can be passed
    stub_code: str = ""             # Stub code
    constraints: List[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class CallbackAnalysisResult:
    """Callback analysis result"""
    api_name: str
    callbacks: List[CallbackInfo] = field(default_factory=list)
    llm_confirmed: bool = False


class CallbackAnalyzer:
    """
    Callback function analyzer

    Phase 1: Static analysis to identify function pointer parameters
    Phase 2: LLM generates appropriate stub implementations
    """

    # Function pointer type patterns
    FUNC_PTR_PATTERN = r'\(\s*\*\s*\w*\s*\)\s*\(|^\w+\s*\(\s*\*\s*\)\s*\('

    # Comparator function signature patterns
    COMPARATOR_PATTERN = r'\(.*const\s+void\s*\*.*,.*const\s+void\s*\*.*\)\s*->\s*int|\(.*const\s+void\s*\*.*,.*const\s+void\s*\*.*\)'

    # Common callback type characteristics
    CALLBACK_SIGNATURES = {
        CallbackType.COMPARATOR: [
            (r'const\s+void\s*\*', r'const\s+void\s*\*', r'int'),  # qsort style
        ],
        CallbackType.READER: [
            (r'void\s*\*', r'size_t', r'size_t'),  # fread style
        ],
        CallbackType.WRITER: [
            (r'const\s+void\s*\*', r'size_t', r'size_t'),  # fwrite style
        ],
        CallbackType.ALLOCATOR: [
            (r'size_t', None, r'void\s*\*'),  # malloc style
        ],
        CallbackType.DEALLOCATOR: [
            (r'void\s*\*', None, r'void'),  # free style
        ],
    }

    # Stub templates
    STUB_TEMPLATES = {
        CallbackType.COMPARATOR: '''
int fuzz_comparator_{name}(const void* a, const void* b) {{
    // Simple byte comparison
    return memcmp(a, b, 1);
}}
''',
        CallbackType.HANDLER: '''
void fuzz_handler_{name}(void* user_data) {{
    // Empty handler - just acknowledge the callback
    (void)user_data;
}}
''',
        CallbackType.READER: '''
typedef struct {{
    const uint8_t* data;
    size_t size;
    size_t pos;
}} FuzzReaderCtx_{name};

size_t fuzz_reader_{name}(void* ptr, size_t size, void* stream) {{
    FuzzReaderCtx_{name}* ctx = (FuzzReaderCtx_{name}*)stream;
    size_t avail = ctx->size - ctx->pos;
    size_t to_read = (size < avail) ? size : avail;
    if (to_read > 0) {{
        memcpy(ptr, ctx->data + ctx->pos, to_read);
        ctx->pos += to_read;
    }}
    return to_read;
}}
''',
        CallbackType.WRITER: '''
size_t fuzz_writer_{name}(const void* ptr, size_t size, void* stream) {{
    // Discard written data
    (void)ptr;
    (void)stream;
    return size;
}}
''',
        CallbackType.ALLOCATOR: '''
void* fuzz_allocator_{name}(size_t size) {{
    if (size > 1024 * 1024) return NULL;  // Limit allocation size
    return malloc(size);
}}
''',
        CallbackType.DEALLOCATOR: '''
void fuzz_deallocator_{name}(void* ptr) {{
    free(ptr);
}}
''',
        CallbackType.VISITOR: '''
int fuzz_visitor_{name}(void* item, void* user_data) {{
    (void)item;
    (void)user_data;
    return 0;  // Continue visiting
}}
''',
        CallbackType.UNKNOWN: '''
void fuzz_callback_{name}(void) {{
    // Generic empty callback
}}
''',
    }

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self._cache: Dict[str, CallbackAnalysisResult] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client

    def analyze(self, api: Api) -> CallbackAnalysisResult:
        """Analyze callback parameters of API"""
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # Phase 1: Static analysis to identify function pointer parameters
        callbacks = self._phase1_static_analysis(api)

        result = CallbackAnalysisResult(
            api_name=api.function_name,
            callbacks=callbacks
        )

        if not callbacks:
            self._cache[api.function_name] = result
            return result

        # Phase 2: LLM generates stub
        if self.llm_client:
            result = self._phase2_llm_generate(api, callbacks)
            result.llm_confirmed = True
        else:
            # Use template to generate stub
            for cb in result.callbacks:
                cb.stub_code = self._generate_stub(cb, api.function_name)

        self._cache[api.function_name] = result
        return result

    def _phase1_static_analysis(self, api: Api) -> List[CallbackInfo]:
        """Phase 1: Static analysis to identify function pointer parameters"""
        callbacks = []

        for i, arg in enumerate(api.arguments_info):
            if self._is_function_pointer(arg.type):
                cb_type = self._classify_callback(arg.type)
                callbacks.append(CallbackInfo(
                    arg_idx=i,
                    arg_name=arg.name,
                    arg_type=arg.type,
                    callback_type=cb_type,
                    reasoning="Phase1: function pointer type detected"
                ))

        return callbacks

    def _is_function_pointer(self, type_str: str) -> bool:
        """Check if it's a function pointer type"""
        # Pattern 1: (*)(...)  e.g., void (*)(int) or int (*)(const void*, const void*)
        if re.search(self.FUNC_PTR_PATTERN, type_str):
            return True

        # Pattern 2: return_type (*)(params)  e.g., int (*)(const void*, const void*)
        if re.search(r'\w+\s*\(\s*\*\s*\)\s*\([^)]*\)', type_str):
            return True

        # Pattern 3: Type name contains _func, _callback, _handler, etc.
        type_lower = type_str.lower()
        callback_keywords = ['_func', '_callback', '_handler', '_hook',
                            '_fn', 'callback', 'handler', 'func_t']
        if any(kw in type_lower for kw in callback_keywords):
            return True

        return False

    def _classify_callback(self, type_str: str) -> CallbackType:
        """Classify callback type"""
        type_lower = type_str.lower()

        # Based on naming
        if 'compar' in type_lower or 'cmp' in type_lower:
            return CallbackType.COMPARATOR
        if 'read' in type_lower:
            return CallbackType.READER
        if 'write' in type_lower:
            return CallbackType.WRITER
        if 'alloc' in type_lower:
            return CallbackType.ALLOCATOR
        if 'free' in type_lower or 'dealloc' in type_lower:
            return CallbackType.DEALLOCATOR
        if 'visit' in type_lower or 'walk' in type_lower:
            return CallbackType.VISITOR
        if 'handler' in type_lower or 'callback' in type_lower:
            return CallbackType.HANDLER

        # Based on signature analysis
        # Comparator: int (*)(const void*, const void*)
        if re.search(r'int\s*\(\s*\*\s*\)\s*\(\s*const\s+void\s*\*\s*,\s*const\s+void\s*\*\s*\)', type_str):
            return CallbackType.COMPARATOR

        # Allocator: void* (*)(size_t) or similar
        if re.search(r'void\s*\*\s*\(\s*\*\s*\)\s*\(\s*size_t\s*\)', type_str):
            return CallbackType.ALLOCATOR

        # Deallocator: void (*)(void*)
        if re.search(r'void\s*\(\s*\*\s*\)\s*\(\s*void\s*\*\s*\)', type_str):
            return CallbackType.DEALLOCATOR

        return CallbackType.UNKNOWN

    def _generate_stub(self, callback: CallbackInfo, api_name: str) -> str:
        """Generate stub code"""
        template = self.STUB_TEMPLATES.get(
            callback.callback_type,
            self.STUB_TEMPLATES[CallbackType.UNKNOWN]
        )

        # Generate unique name
        name = f"{api_name}_{callback.arg_name}".replace('-', '_')
        return template.format(name=name)

    def _phase2_llm_generate(self, api: Api,
                             callbacks: List[CallbackInfo]) -> CallbackAnalysisResult:
        """Phase 2: LLM generates stub"""
        result = CallbackAnalysisResult(
            api_name=api.function_name,
            callbacks=[]
        )

        params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info])
        signature = f"{api.return_info.type} {api.function_name}({params})"

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()

        for cb in callbacks:
            prompt = pm.get_callback_prompt(
                signature=signature,
                callback_param=cb.arg_name,
                callback_type=cb.arg_type
            )

            try:
                response = self.llm_client.query(prompt)  # type: ignore
                cb_info = self._parse_llm_response(cb, response, api.function_name)
                result.callbacks.append(cb_info)
            except Exception as e:
                logger.warning(f"LLM callback analysis failed for {cb.arg_name}: {e}")
                cb.stub_code = self._generate_stub(cb, api.function_name)
                result.callbacks.append(cb)

        return result

    def _parse_llm_response(self, callback: CallbackInfo,
                            response: str, api_name: str) -> CallbackInfo:
        """Parse LLM response"""
        import json

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse callback LLM response: {response[:200]}")
            callback.stub_code = self._generate_stub(callback, api_name)
            return callback

        type_map = {
            "comparator": CallbackType.COMPARATOR,
            "handler": CallbackType.HANDLER,
            "reader": CallbackType.READER,
            "writer": CallbackType.WRITER,
            "allocator": CallbackType.ALLOCATOR,
            "deallocator": CallbackType.DEALLOCATOR,
            "visitor": CallbackType.VISITOR,
            "unknown": CallbackType.UNKNOWN,
        }

        return CallbackInfo(
            arg_idx=callback.arg_idx,
            arg_name=callback.arg_name,
            arg_type=callback.arg_type,
            callback_type=type_map.get(data.get("callback_purpose", "unknown"),
                                       CallbackType.UNKNOWN),
            can_be_null=data.get("can_be_null", False),
            stub_code=data.get("stub_code", self._generate_stub(callback, api_name)),
            constraints=data.get("constraints", []),
            reasoning=data.get("reasoning", "LLM analysis")
        )

    def clear_cache(self):
        """Clear cache"""
        self._cache.clear()


# =============================================================================
# S2. TLV Format Analysis
# =============================================================================

class StructuredFormat(Enum):
    """Structured data format"""
    TLV = "tlv"                     # Type-Length-Value
    FIXED_HEADER = "fixed_header"   # Fixed header
    LENGTH_PREFIXED = "length_prefixed"  # Length prefixed
    RAW = "raw"                     # Raw data
    UNKNOWN = "unknown"


@dataclass
class TLVAnalysisResult:
    """TLV analysis result"""
    api_name: str
    is_structured: bool = False
    format_type: StructuredFormat = StructuredFormat.UNKNOWN
    min_size: int = 0                # Minimum valid input size
    magic_bytes: Optional[bytes] = None  # Magic bytes
    constraints: List[str] = field(default_factory=list)
    reasoning: str = ""
    llm_confirmed: bool = False


class TLVAnalyzer:
    """
    TLV/Structured data format analyzer

    Phase 1: Static analysis to identify APIs that may parse structured data
    Phase 2: LLM confirms format and constraints
    """

    # Parser function naming patterns
    PARSE_PATTERNS = [
        r'(?i)_parse$', r'(?i)^parse_', r'(?i)_decode$', r'(?i)^decode_',
        r'(?i)_deserialize', r'(?i)_unmarshal', r'(?i)_unpack',
        r'(?i)_read$', r'(?i)_load$', r'(?i)_from_',
    ]

    # Typical parser parameter patterns
    PARSE_PARAM_PATTERNS = [
        (r'const\s+uint8_t\s*\*', r'size_t'),
        (r'const\s+char\s*\*', r'size_t'),
        (r'const\s+void\s*\*', r'size_t'),
        (r'const\s+unsigned\s+char\s*\*', r'(size_t|int|unsigned)'),
    ]

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self._cache: Dict[str, TLVAnalysisResult] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client

    def analyze(self, api: Api) -> TLVAnalysisResult:
        """Analyze whether API handles structured data"""
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # Phase 1: Static analysis
        phase1_result = self._phase1_static_analysis(api)

        if not phase1_result.is_structured:
            self._cache[api.function_name] = phase1_result
            return phase1_result

        # Phase 2: LLM confirmation
        if self.llm_client:
            result = self._phase2_llm_confirm(api)
            result.llm_confirmed = True
        else:
            result = phase1_result

        self._cache[api.function_name] = result
        return result

    def _phase1_static_analysis(self, api: Api) -> TLVAnalysisResult:
        """Phase 1: Static analysis"""
        func_name = api.function_name

        # Check naming patterns
        is_parser = False
        for pattern in self.PARSE_PATTERNS:
            if re.search(pattern, func_name):
                is_parser = True
                break

        if not is_parser:
            return TLVAnalysisResult(api_name=func_name)

        # Check parameter patterns
        has_parse_params = self._check_parse_params(api)

        if not has_parse_params:
            return TLVAnalysisResult(api_name=func_name)

        return TLVAnalysisResult(
            api_name=func_name,
            is_structured=True,
            format_type=StructuredFormat.UNKNOWN,
            min_size=1,
            reasoning="Phase1: name and parameter pattern match"
        )

    def _check_parse_params(self, api: Api) -> bool:
        """Check if there are parser function parameter patterns"""
        args = api.arguments_info

        if len(args) < 2:
            return False

        # Check if there is a (buffer, size) parameter pair
        for i in range(len(args) - 1):
            arg1_type = args[i].type
            arg2_type = args[i + 1].type

            for buf_pattern, size_pattern in self.PARSE_PARAM_PATTERNS:
                if re.search(buf_pattern, arg1_type) and re.search(size_pattern, arg2_type):
                    return True

        return False

    def _phase2_llm_confirm(self, api: Api) -> TLVAnalysisResult:
        """Phase 2: LLM confirmation"""
        params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info])
        signature = f"{api.return_info.type} {api.function_name}({params})"

        # Use prompt_loader to get prompt
        pm = get_prompt_manager()
        prompt = pm.get_tlv_prompt(signature=signature)

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            return self._parse_llm_response(api, response)
        except Exception as e:
            logger.warning(f"LLM TLV analysis failed for {api.function_name}: {e}")
            return TLVAnalysisResult(
                api_name=api.function_name,
                is_structured=True,
                format_type=StructuredFormat.UNKNOWN,
                reasoning=f"LLM error: {e}"
            )

    def _parse_llm_response(self, api: Api, response: str) -> TLVAnalysisResult:
        """Parse LLM response"""
        import json

        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse TLV LLM response: {response[:200]}")
            return TLVAnalysisResult(api_name=api.function_name)

        format_map = {
            "tlv": StructuredFormat.TLV,
            "fixed_header": StructuredFormat.FIXED_HEADER,
            "length_prefixed": StructuredFormat.LENGTH_PREFIXED,
            "raw": StructuredFormat.RAW,
            "unknown": StructuredFormat.UNKNOWN,
        }

        magic = data.get("magic_bytes")
        if magic and isinstance(magic, str):
            try:
                magic = bytes.fromhex(magic.replace("0x", ""))
            except ValueError:
                magic = None

        return TLVAnalysisResult(
            api_name=api.function_name,
            is_structured=data.get("is_structured", False),
            format_type=format_map.get(data.get("format_type", "unknown"),
                                       StructuredFormat.UNKNOWN),
            min_size=data.get("min_size", 0),
            magic_bytes=magic,
            constraints=data.get("constraints", []),
            reasoning=data.get("reasoning", "LLM analysis")
        )

    def clear_cache(self):
        """Clear cache"""
        self._cache.clear()


# =============================================================================
# Unified Analyzer
# =============================================================================

@dataclass
class APIPatternAnalysisResult:
    """Comprehensive API pattern analysis result"""
    api_name: str
    varlen: Optional[VarLenAnalysisResult] = None
    loop: Optional[LoopPatternInfo] = None
    callbacks: Optional[CallbackAnalysisResult] = None
    tlv: Optional[TLVAnalysisResult] = None


class SpecialPatternAnalyzer:
    """
    Unified special pattern analyzer

    Integrates analysis for all special scenarios:
    - S1. Var-len
    - S2. TLV
    - S3. Loop
    - S4. Callback
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.varlen_analyzer = VarLenAnalyzer(llm_client)
        self.loop_analyzer = LoopPatternAnalyzer(llm_client)
        self.callback_analyzer = CallbackAnalyzer(llm_client)
        self.tlv_analyzer = TLVAnalyzer(llm_client)

    def set_llm_client(self, llm_client: LLMClient):
        """Set LLM client"""
        self.llm_client = llm_client
        self.varlen_analyzer.set_llm_client(llm_client)
        self.loop_analyzer.set_llm_client(llm_client)
        self.callback_analyzer.set_llm_client(llm_client)
        self.tlv_analyzer.set_llm_client(llm_client)

    def analyze(self, api: Api,
                analyze_varlen: bool = True,
                analyze_loop: bool = True,
                analyze_callback: bool = True,
                analyze_tlv: bool = True) -> APIPatternAnalysisResult:
        """
        Analyze all special patterns for API

        Args:
            api: API object
            analyze_varlen: Whether to analyze var-len
            analyze_loop: Whether to analyze loop
            analyze_callback: Whether to analyze callback
            analyze_tlv: Whether to analyze TLV

        Returns:
            APIPatternAnalysisResult: Comprehensive analysis result
        """
        result = APIPatternAnalysisResult(api_name=api.function_name)

        if analyze_varlen:
            result.varlen = self.varlen_analyzer.analyze(api)

        if analyze_loop:
            result.loop = self.loop_analyzer.analyze(api)

        if analyze_callback:
            result.callbacks = self.callback_analyzer.analyze(api)

        if analyze_tlv:
            result.tlv = self.tlv_analyzer.analyze(api)

        return result

    def clear_cache(self):
        """Clear all caches"""
        self.varlen_analyzer.clear_cache()
        self.loop_analyzer.clear_cache()
        self.callback_analyzer.clear_cache()
        self.tlv_analyzer.clear_cache()

    def get_varlen_relations(self, api: Api) -> List[VarLenRelation]:
        """Get var-len relations for API"""
        result = self.varlen_analyzer.analyze(api)
        return result.relations

    def needs_loop(self, api: Api) -> bool:
        """Check if API needs loop calls"""
        result = self.loop_analyzer.analyze(api)
        return result.needs_loop

    def get_callbacks(self, api: Api) -> List[CallbackInfo]:
        """Get callback parameters for API"""
        result = self.callback_analyzer.analyze(api)
        return result.callbacks

    def is_structured_parser(self, api: Api) -> bool:
        """Check if API is a structured data parser"""
        result = self.tlv_analyzer.analyze(api)
        return result.is_structured
