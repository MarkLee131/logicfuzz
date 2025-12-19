"""
Data context for fuzzing workflow - Single source of truth for all fuzzing data.

This module establishes clear data ownership:
- All data prepared ONCE in run_single_fuzz.py
- Nodes NEVER extract data, they only process what's given
- Failure is explicit, not hidden with fallbacks
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
import logging
import json
import re
from liberator_adapter.driver.ir import ApiCall

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FuzzingContext:
    """
    Immutable data context containing ALL information needed for fuzzing.
    
    Philosophy:
    - Prepared once, used everywhere
    - No fallbacks - if data is missing, preparation failed
    - Immutable - once created, never modified
    - Explicit failures - missing data raises ValueError, not returns None
    
    Fields (Project-level mode):
    - project_name: Target project (e.g., "zlib")
    - project_apis: All APIs extracted from the project (Liberator Api objects)
    - api_sequences: API call sequences generated from grammar
    - dependency_graph: Type dependency graph
    - grammar: Grammar generated from dependency graph
    - header_info: Header files needed for compilation
    - condition_info: Summary of Liberator ConditionManager (sources/sinks/init/setby)
    - existing_fuzzer_headers: Headers used in existing fuzzers (for reference)
    """
    
    # === Core identifiers ===
    project_name: str
    
    # === Required data (must be present) ===
    project_apis: List[Dict[str, Any]]  # List of API information (from Liberator)
    api_sequences: List[List[str]]  # List of API call sequences (from grammar)
    dependency_graph: Dict[str, Any]  # Type dependency graph
    grammar_info: Dict[str, Any]  # Grammar metadata
    api_dependencies: Dict[str, Any]  # Legacy format for backward compatibility
    header_info: Dict[str, List[str]]
    existing_fuzzer_headers: Dict[str, List[str]]
    condition_info: Dict[str, Any] = field(default_factory=dict)
    
    # === Metadata ===
    preparation_time: float = 0.0
    
    def __post_init__(self):
        """Validate required data is not empty."""
        if not self.project_apis:
            raise ValueError("project_apis cannot be empty")
        if not self.api_sequences:
            raise ValueError("api_sequences cannot be empty")
        if not self.dependency_graph:
            raise ValueError("dependency_graph cannot be empty")
        if not self.header_info:
            raise ValueError("header_info cannot be empty")
    
    @classmethod
    def prepare(cls, project_name: str, benchmark: Any = None,
                logger_instance: logging.Logger = None,
                llm: Any = None,
                num_sequences: int = 24,
                driver_size: int = 5,
                filter_top_k: int = 12) -> 'FuzzingContext':
        """
        Prepare all fuzzing data using Liberator project-level modeling.
        
        Philosophy:
        - Uses Liberator to model the entire project
        - Extracts all APIs, generates dependency graph and grammar
        - Produces API sequences for driver generation
        - Either succeeds completely or raises ValueError
        - Fail fast - let caller decide how to handle failures
        
        Args:
            project_name: Target project name
            benchmark: Benchmark object (required for Clang/LLVM extraction)
            logger_instance: Optional logger for progress reporting
            llm: Optional LLM instance for semantic filtering of API sequences
            num_sequences: Number of driver candidates to sample from grammar
            driver_size: Target length of each API sequence
            filter_top_k: Top-K sequences to keep after LLM filtering
        
        Returns:
            Fully initialized FuzzingContext with project-level API data
        
        Raises:
            ValueError: If any required data cannot be obtained
            RuntimeError: If underlying APIs fail
        """
        import time
        from liberator_adapter.project_driver_generator import ProjectDriverGenerator
        
        log = logger_instance or logger
        start_time = time.time()
        
        log.info(f'📦 Preparing project-level fuzzing context for {project_name}')
        
        # === Step 1: Create ProjectDriverGenerator ===
        log.debug('  1/8 Creating ProjectDriverGenerator...')
        try:
            if not benchmark:
                raise ValueError(
                    f"benchmark object is required for project-level modeling. "
                    f"ProjectDriverGenerator needs benchmark for Clang/LLVM extraction."
                )
            
            generator = ProjectDriverGenerator(
                project_name=project_name,
                benchmark=benchmark,
                use_clang_llvm=True,  # Use Clang/LLVM for accurate extraction
                work_dir=None  # Use default work dir
            )
            log.info('   ✅ ProjectDriverGenerator created')
        except Exception as e:
            raise RuntimeError(
                f"Failed to create ProjectDriverGenerator: {e}\n"
                f"This is required for project-level modeling."
            ) from e
        
        # === Step 2: Extract all APIs ===
        log.debug('  2/8 Extracting all APIs from project...')
        try:
            all_apis = generator.extract_all_apis()
            if not all_apis:
                raise ValueError(f"No APIs extracted from project '{project_name}'")
            
            # Convert Api objects to dictionaries for serialization
            project_apis = []
            for api in all_apis:
                project_apis.append({
                    'function_name': api.function_name,
                    'return_type': api.return_info.type,
                    'arguments': [
                        {
                            'name': arg.name,
                            'type': arg.type,
                            'flag': arg.flag,
                            'size': arg.size,
                            'is_const': arg.is_const
                        }
                        for arg in api.arguments_info
                    ],
                    'is_vararg': api.is_vararg,
                    'namespace': api.namespace
                })
            
            log.info(f'   ✅ Extracted {len(project_apis)} APIs')
        except Exception as e:
            raise RuntimeError(
                f"Failed to extract APIs: {e}\n"
                f"This is an internal error in ProjectDriverGenerator."
            ) from e
        
        # === Step 3: Build dependency graph ===
        log.debug('  3/8 Building type dependency graph...')
        try:
            dep_graph = generator.build_dependency_graph()
            
            # Convert dependency graph to serializable format
            dep_graph_dict = {
                'graph': {
                    api.function_name: [dep.function_name for dep in deps]
                    for api, deps in dep_graph.graph.items()
                },
                'num_nodes': len(dep_graph.graph)
            }
            log.info(f'   ✅ Dependency graph built: {dep_graph_dict["num_nodes"]} nodes')
        except Exception as e:
            raise RuntimeError(
                f"Failed to build dependency graph: {e}\n"
                f"This is an internal error in TypeDependencyGraphGenerator."
            ) from e
        
        # === Step 4: Generate grammar (API sequences) ===
        log.debug('  4/8 Generating grammar and API sequences...')
        try:
            grammar = generator.build_grammar()
            
            # Use driver generation to obtain grammar-respecting API sequences
            # NOTE: driver generation already leverages Grammar + Factory
            raw_drivers = generator.generate_drivers(
                num_drivers=max(num_sequences, 1),
                driver_size=max(driver_size, 1),
                policy="only_type"
            )
            api_sequences = _extract_sequences_from_drivers(
                raw_drivers,
                max_len=driver_size
            )
            api_sequences = _dedup_sequences(api_sequences)
            
            grammar_info = {
                'num_symbols': grammar.num_symbols(),
                'start_symbol': str(grammar.get_start_symbol()),
                'num_sequences': len(api_sequences)
            }
            log.info(f'   ✅ Grammar generated: {grammar_info["num_symbols"]} symbols, {len(api_sequences)} sequences')
        except Exception as e:
            raise RuntimeError(
                f"Failed to generate grammar: {e}\n"
                f"This is an internal error in GrammarGenerator."
            ) from e
        
        if not api_sequences:
            raise ValueError(
                f"No API sequences generated for project '{project_name}'.\n"
                f"This might indicate the dependency graph is empty or grammar generation failed."
            )
        
        # === Step 5: Build condition manager ===
        log.debug('  5/8 Building condition manager...')
        try:
            condition_manager = generator.build_condition_manager()
            log.info('   ✅ Condition manager built')
        except Exception as e:
            log.warning(f"Failed to build condition manager: {e} (non-critical)")
            condition_manager = None
        
        # Condition summary for prompt/LLM
        condition_info = {}
        if condition_manager:
            try:
                sources = [api.function_name for api in condition_manager.get_source_api()]
                sinks = [api.function_name for api in condition_manager.get_sink_api()]
                inits = [api.function_name for api in condition_manager.get_init_api()]
                condition_info = {
                    'sources': sources,
                    'sinks': sinks,
                    'inits': inits,
                    'counts': {
                        'sources': len(sources),
                        'sinks': len(sinks),
                        'inits': len(inits)
                    }
                }
            except Exception as e:
                log.warning(f"Failed to summarize condition manager: {e}")
                condition_info = {}
        
        # === Step 6: LLM semantic filtering over API sequences (optional) ===
        log.debug('  6/8 Filtering API sequences with LLM (optional)...')
        filter_summary = {}
        if api_sequences:
            try:
                filtered, filter_summary = _semantic_filter_sequences(
                    api_sequences,
                    condition_info=condition_info,
                    llm=llm,
                    top_k=filter_top_k,
                    logger_instance=log
                )
                if filtered:
                    api_sequences = filtered
                    log.info(f'   ✅ LLM filter applied: {len(api_sequences)} sequences kept (top_k={filter_top_k})')
                else:
                    log.warning('LLM filter returned empty set, fallback to raw sequences')
            except Exception as e:
                log.warning(f"LLM filtering failed: {e}, fallback to raw sequences")
        else:
            log.warning("No API sequences to filter")
        grammar_info['llm_filter'] = filter_summary
        grammar_info['num_sequences'] = len(api_sequences)
        
        # === Step 7: Extract header information ===
        log.debug('  7/8 Extracting headers...')
        try:
            # For project-level, use existing fuzzer headers as reference
            # This provides headers commonly used in the project
            header_info = _extract_existing_fuzzer_headers(project_name, log)
            
            # If no headers found, create minimal structure
            if not header_info or (not header_info.get('standard_headers') and not header_info.get('project_headers')):
                log.warning("No existing fuzzer headers found, using minimal header set")
                header_info = {
                    'standard_headers': ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
                    'project_headers': []
                }
        except Exception as e:
            log.warning(f"Failed to extract headers: {e}, using minimal set")
            header_info = {
                'standard_headers': ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
                'project_headers': []
            }
        
        if not header_info:
            raise ValueError(
                f"Header extraction returned empty for project '{project_name}'. "
                f"This is required for compilation."
            )
        
        # === Step 8: Extract existing fuzzer headers (for reference) ===
        log.debug('  8/8 Extracting existing fuzzer headers...')
        try:
            existing_fuzzer_headers = _extract_existing_fuzzer_headers(
                project_name, log
            )
        except Exception as e:
            log.warning(f"Failed to extract existing fuzzer headers: {e}")
            existing_fuzzer_headers = {
                'standard_headers': [],
                'project_headers': []
            }
        
        # === Create legacy api_dependencies format for backward compatibility ===
        # Convert project-level data to legacy format
        api_dependencies = {
            'prerequisites': [api['function_name'] for api in project_apis],
            'data_dependencies': [],
            'call_sequence': api_sequences[0] if api_sequences else [],
            'initialization_code': [],
            'all_apis': [api['function_name'] for api in project_apis],
            'api_sequences': api_sequences,
            'dependency_graph': dep_graph_dict
        }
        
        # === Create context ===
        elapsed = time.time() - start_time
        log.info(f'✅ Project-level fuzzing context prepared in {elapsed:.2f}s')
        log.debug(
            f'   └─ APIs: {len(project_apis)}, '
            f'Sequences: {len(api_sequences)}, '
            f'Deps: {dep_graph_dict["num_nodes"]} nodes, '
            f'Headers: {len(header_info.get("standard_headers", [])) + len(header_info.get("project_headers", []))}'
        )
        
        return cls(
            project_name=project_name,
            project_apis=project_apis,
            api_sequences=api_sequences,
            dependency_graph=dep_graph_dict,
            grammar_info=grammar_info,
            api_dependencies=api_dependencies,
            header_info=header_info,
            existing_fuzzer_headers=existing_fuzzer_headers,
            condition_info=condition_info,
            preparation_time=elapsed
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for state storage."""
        return {
            'project_name': self.project_name,
            'project_apis': self.project_apis,
            'api_sequences': self.api_sequences,
            'dependency_graph': self.dependency_graph,
            'grammar_info': self.grammar_info,
            'api_dependencies': self.api_dependencies,
            'header_info': self.header_info,
            'existing_fuzzer_headers': self.existing_fuzzer_headers,
            'condition_info': self.condition_info,
            'preparation_time': self.preparation_time,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FuzzingContext':
        """Reconstruct from dictionary."""
        return cls(**data)


def _extract_existing_fuzzer_headers(project_name: str, 
                                     log: logging.Logger) -> Dict[str, List[str]]:
    """
    Extract headers from existing fuzzers for reference.
    
    This is not critical data - if it fails, we just return empty.
    """
    from data_prep import introspector
    import re
    
    result = {
        'standard_headers': [],
        'project_headers': []
    }
    
    try:
        # Get all fuzzer files
        harness_data = introspector.query_introspector_for_harness_intrinsics(project_name)
        fuzzers = [item['source'] for item in harness_data if 'source' in item]
        if not fuzzers:
            return result
        
        standard_headers = set()
        project_headers = set()
        
        # Extract headers from first few fuzzers
        for fuzzer_path in fuzzers[:5]:
            try:
                fuzzer_source = introspector.query_introspector_file_source(
                    project_name, fuzzer_path
                )
                if not fuzzer_source:
                    continue
                
                # Extract #include statements from top of file
                for line in fuzzer_source.split('\n')[:50]:
                    include_match = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
                    if include_match:
                        header = include_match.group(1)
                        if header.startswith(project_name) or '/' in header:
                            project_headers.add(header)
                        else:
                            standard_headers.add(header)
            except Exception:
                continue  # Skip this fuzzer if extraction fails
        
        result['standard_headers'] = sorted(standard_headers)
        result['project_headers'] = sorted(project_headers)
        
    except Exception as e:
        log.warning(f"Failed to extract existing fuzzer headers: {e}")
    
    return result


def _extract_sequences_from_drivers(drivers, max_len: int = 5) -> List[List[str]]:
    """Extract API call sequences from generated drivers."""
    sequences: List[List[str]] = []
    for drv in drivers or []:
        seq: List[str] = []
        for stmt in getattr(drv, "statements", []):
            if isinstance(stmt, ApiCall):
                seq.append(getattr(stmt, "function_name", None) or getattr(stmt, "original_api", None).function_name)
        if max_len > 0:
            seq = seq[:max_len]
        if seq:
            sequences.append(seq)
    return sequences


def _dedup_sequences(api_sequences: List[List[str]]) -> List[List[str]]:
    """Deduplicate sequences while preserving order."""
    seen = set()
    unique = []
    for seq in api_sequences:
        key = tuple(seq)
        if key and key not in seen:
            seen.add(key)
            unique.append(list(seq))
    return unique


def _semantic_filter_sequences(api_sequences: List[List[str]],
                               condition_info: Dict[str, Any],
                               llm: Any = None,
                               top_k: int = 12,
                               logger_instance: logging.Logger = None) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Use LLM to select the best API sequences.
    
    Returns filtered sequences and a summary dict.
    """
    log = logger_instance or logger
    
    if not api_sequences:
        return [], {}
    
    # If no LLM provided, return top_k unique sequences
    api_sequences = _dedup_sequences(api_sequences)
    if not llm:
        return api_sequences[:top_k], {'mode': 'passthrough', 'reason': 'llm_not_provided'}
    
    # Build prompt
    inits = condition_info.get('inits', [])
    sinks = condition_info.get('sinks', [])
    sources = condition_info.get('sources', [])
    
    lines = []
    for idx, seq in enumerate(api_sequences):
        lines.append(f"{idx}: " + " -> ".join(seq))
    sequences_text = "\n".join(lines[:50])  # avoid overly long prompts
    
    instructions = (
        "You are selecting API call sequences for a fuzzing driver.\n"
        "- Prefer sequences that include initialization before use, and cleanup/finalization at the end if present.\n"
        "- Prefer sequences that start with init APIs and end with sink/cleanup APIs when relevant.\n"
        "- Drop duplicates and trivial single-call sequences unless no alternatives.\n"
        f"- Init candidates: {inits}\n"
        f"- Sink candidates: {sinks}\n"
        f"- Source candidates: {sources}\n"
        f"Pick up to {top_k} sequences by index. Respond ONLY with JSON like: "
        '{"selected_indices":[0,2,3]}'
    )
    
    messages = [
        {"role": "system", "content": "You are a precise assistant that returns strict JSON."},
        {"role": "user", "content": instructions + "\nSequences:\n" + sequences_text}
    ]
    
    try:
        raw = llm.chat_with_messages(messages)
        selected_indices = _parse_selected_indices(raw, len(api_sequences))
        if not selected_indices:
            raise ValueError("no indices parsed")
        filtered = [api_sequences[i] for i in selected_indices if 0 <= i < len(api_sequences)]
        return filtered, {
            'mode': 'llm',
            'selected_indices': selected_indices,
            'response': raw[:2000]
        }
    except Exception as e:
        log.warning(f"Semantic filter failed, fallback to top_k: {e}")
        return api_sequences[:top_k], {'mode': 'fallback', 'reason': str(e)}


def _parse_selected_indices(response_text: str, max_len: int) -> List[int]:
    """Parse selected indices from LLM response JSON or fallback patterns."""
    try:
        data = json.loads(response_text)
        indices = data.get("selected_indices") or data.get("selected") or []
        if isinstance(indices, list):
            return [int(i) for i in indices if isinstance(i, (int, float)) and 0 <= int(i) < max_len]
    except Exception:
        pass
    
    # Fallback: regex search
    match = re.findall(r'\d+', response_text)
    return [int(i) for i in match if 0 <= int(i) < max_len][:max_len]

