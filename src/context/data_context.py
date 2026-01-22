"""
Data context for fuzzing workflow - Single source of truth for all fuzzing data.

This module establishes clear data ownership:
- All data prepared ONCE in run_single_fuzz.py
- Nodes NEVER extract data, they only process what's given
- Failure is explicit, not hidden with fallbacks
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import logging
import json
import re

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
    - pattern_analysis: Special pattern analysis results (VarLen, Loop, Callback, TLV)
    - skeleton_drivers: Pre-generated skeleton drivers with holes
    """

    # === Core identifiers ===
    project_name: str

    # === Required data (must be present) ===
    project_apis: List[Dict[str, Any]]  # List of API information (from Liberator)
    api_sequences: List[List[str]]  # List of API call sequences (from grammar)
    dependency_graph: Dict[str, Any]  # Type dependency graph
    grammar_info: Dict[str, Any]  # Grammar metadata
    header_info: Dict[str, List[str]]
    existing_fuzzer_headers: Dict[str, List[str]]
    condition_info: Dict[str, Any] = field(default_factory=dict)

    # === Pattern analysis (P1: DriverEnhancer integration) ===
    pattern_analysis: Dict[str, Any] = field(default_factory=dict)  # VarLen/Loop/Callback/TLV

    # === Skeleton drivers (P0: SkeletonGenerator integration) ===
    skeleton_drivers: List[Dict[str, Any]] = field(default_factory=list)  # Pre-generated skeletons

    # === Synthesized drivers (CBFactory program synthesis) ===
    # Note: Synthesis is always enabled - CBFactory generates base drivers, LLM Prototyper refines them
    synthesized_drivers: List[Dict[str, Any]] = field(default_factory=list)  # Full drivers from CBFactory

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
    def load_from_cache(cls, project_name: str,
                        logger_instance: logging.Logger = None) -> Optional['FuzzingContext']:
        """
        Try to load static analysis results from cache.

        Checks if results/{project}/static_analysis/ contains all required files
        and loads them to reconstruct a FuzzingContext.

        Args:
            project_name: Target project name
            logger_instance: Optional logger for progress reporting

        Returns:
            FuzzingContext if cache is valid, None otherwise
        """
        log = logger_instance or logger
        cache_dir = Path(f"./results/{project_name}/static_analysis")

        required_files = [
            'project_apis.json',
            'filtered_sequences.json',
            'dependency_graph.json',
            'analysis_summary.json',
            'pattern_analysis.json'
        ]

        # Check if cache directory and all required files exist
        if not cache_dir.exists():
            log.debug(f'Cache directory not found: {cache_dir}')
            return None

        missing_files = [f for f in required_files if not (cache_dir / f).exists()]
        if missing_files:
            log.debug(f'Cache incomplete, missing: {missing_files}')
            return None

        try:
            log.info(f'📂 Loading cached static analysis from {cache_dir}')

            # Load project APIs
            with open(cache_dir / 'project_apis.json', 'r') as f:
                apis_data = json.load(f)
                project_apis = apis_data.get('apis', [])

            # Load filtered sequences
            with open(cache_dir / 'filtered_sequences.json', 'r') as f:
                seq_data = json.load(f)
                api_sequences = [s['apis'] for s in seq_data.get('sequences', [])]

            # Load dependency graph
            with open(cache_dir / 'dependency_graph.json', 'r') as f:
                dependency_graph = json.load(f)

            # Load analysis summary (contains grammar_info and condition_info)
            with open(cache_dir / 'analysis_summary.json', 'r') as f:
                summary = json.load(f)
                grammar_info = summary.get('grammar_info', {})
                condition_info = summary.get('condition_info', {})

            # Load pattern analysis
            with open(cache_dir / 'pattern_analysis.json', 'r') as f:
                pattern_analysis = json.load(f)

            # Header info - use minimal set (will be supplemented at runtime if needed)
            header_info = {
                'standard_headers': ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
                'project_headers': []
            }

            # Existing fuzzer headers - try to load or use empty
            existing_fuzzer_headers = {
                'standard_headers': [],
                'project_headers': []
            }

            # Skeleton drivers - optional, may not exist in older caches
            skeleton_drivers = []
            skeleton_path = cache_dir / 'skeleton_drivers.json'
            if skeleton_path.exists():
                try:
                    with open(skeleton_path, 'r') as f:
                        skeleton_drivers = json.load(f)
                except Exception:
                    pass

            # Validate required data
            if not project_apis:
                log.warning('Cached project_apis is empty, cache invalid')
                return None
            if not api_sequences:
                log.warning('Cached api_sequences is empty, cache invalid')
                return None

            log.info(f'   ✅ Loaded {len(project_apis)} APIs, {len(api_sequences)} sequences from cache')

            return cls(
                project_name=project_name,
                project_apis=project_apis,
                api_sequences=api_sequences,
                dependency_graph=dependency_graph,
                grammar_info=grammar_info,
                header_info=header_info,
                existing_fuzzer_headers=existing_fuzzer_headers,
                condition_info=condition_info,
                pattern_analysis=pattern_analysis,
                skeleton_drivers=skeleton_drivers,
                preparation_time=0.0  # Loaded from cache
            )

        except Exception as e:
            log.warning(f'Failed to load cache: {e}')
            return None

    @classmethod
    def prepare(cls, project_name: str, benchmark: Any = None,
                logger_instance: logging.Logger = None,
                num_sequences: int = 24,
                driver_size: int = 5,
                filter_top_k: int = 12,
                use_cache: bool = True,
                num_synthesis_drivers: int = 5) -> 'FuzzingContext':
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
            num_sequences: Number of driver candidates to sample from grammar
            driver_size: Target length of each API sequence
            filter_top_k: Top-K sequences to keep after heuristic filtering
            use_cache: Whether to try loading from cache first (default: True)
            num_synthesis_drivers: Number of drivers to synthesize with CBFactory (default: 5)

        Returns:
            Fully initialized FuzzingContext with project-level API data

        Raises:
            ValueError: If any required data cannot be obtained
            RuntimeError: If underlying APIs fail
        """
        import time
        from liberator_adapter.project_driver_generator import ProjectDriverGenerator

        log = logger_instance or logger

        # Try to load from cache first
        if use_cache:
            cached = cls.load_from_cache(project_name, logger_instance=log)
            if cached:
                log.info(f'✅ Using cached static analysis for {project_name} (skipping ~60s analysis)')
                return cached
            log.info(f'📦 No valid cache found, running full static analysis for {project_name}')

        start_time = time.time()
        
        log.info(f'📦 Preparing project-level fuzzing context for {project_name}')
        
        # === Step 1: Create ProjectDriverGenerator ===
        log.debug('  1/10 Creating ProjectDriverGenerator...')
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
        log.debug('  2/10 Extracting all APIs from project...')
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
        log.debug('  3/10 Building type dependency graph...')
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
        log.debug('  4/10 Generating grammar and API sequences...')
        try:
            grammar = generator.build_grammar()

            # Generate API sequences directly from grammar expansion
            api_sequences = _generate_sequences_from_grammar(
                grammar=grammar,
                num_sequences=num_sequences,
                max_len=driver_size,
                log=log
            )
            api_sequences = _dedup_sequences(api_sequences)

            grammar_info = {
                'num_symbols': grammar.num_symbols(),
                'start_symbol': str(grammar.get_start_symbol()),
                'num_sequences': len(api_sequences)
            }
            # Save raw sequences before any filtering
            raw_api_sequences = list(api_sequences)  # Make a copy
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
        
        # === Step 5: Build data layout (required for ConditionManager) ===
        log.debug('  5/10 Building data layout...')
        try:
            generator.build_data_layout()
            log.info('   ✅ Data layout built')
        except Exception as e:
            log.warning(f"Failed to build data layout: {e} (ConditionManager may have reduced precision)")

        # === Step 5b: Build condition manager ===
        log.debug('  5b/10 Building condition manager...')
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
        
        # === Step 6: Simple heuristic filtering (no LLM needed) ===
        log.debug('  6/10 Filtering API sequences with heuristics...')
        filter_summary = {}
        if api_sequences:
            try:
                filtered, filter_summary = _heuristic_filter_sequences(
                    api_sequences,
                    condition_info=condition_info,
                    top_k=filter_top_k,
                    logger_instance=log
                )
                if filtered:
                    api_sequences = filtered
                    log.info(f'   ✅ Heuristic filter applied: {len(api_sequences)} sequences kept')
                else:
                    log.warning('Filter returned empty set, using raw sequences')
            except Exception as e:
                log.warning(f"Filtering failed: {e}, using raw sequences")
        else:
            log.warning("No API sequences to filter")
        grammar_info['filter'] = filter_summary
        grammar_info['num_sequences'] = len(api_sequences)
        
        # === Step 7: Extract header information ===
        log.debug('  7/10 Extracting headers...')
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
        log.debug('  8/10 Extracting existing fuzzer headers...')
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

        # === Step 9: Pattern analysis (P1 - DriverEnhancer integration) ===
        # NOTE: LLM disabled - using heuristics only for pattern analysis
        # Each analyzer (VarLen, Loop, Callback, TLV) has built-in heuristic fallbacks
        log.debug('  9/10 Analyzing special patterns (VarLen/Loop/Callback/TLV) using heuristics...')
        pattern_analysis = {}
        try:
            # Analyze special patterns using DriverEnhancer (heuristics only, no LLM)
            generator.analyze_special_patterns(llm_client=None)
            enhancer = generator.driver_enhancer

            if enhancer:
                # Serialize pattern analysis results
                cache = enhancer.cache

                # VarLen relations
                varlen_data = {}
                for api_name, relations in cache.varlen_relations.items():
                    varlen_data[api_name] = [
                        {
                            'buffer_arg_idx': rel.buffer_arg_idx,
                            'buffer_arg_name': rel.buffer_arg_name,
                            'length_arg_idx': rel.length_arg_idx,
                            'length_arg_name': rel.length_arg_name,
                            'relationship': rel.relationship,
                            'confidence': rel.confidence
                        }
                        for rel in relations
                    ]

                # Loop patterns
                loop_data = {}
                for api_name, info in cache.loop_patterns.items():
                    if info.needs_loop:
                        loop_data[api_name] = {
                            'loop_type': info.loop_type.value,
                            'termination_condition': info.termination_condition,
                            'max_iterations': info.max_iterations,
                            'confidence': info.confidence
                        }

                # Callback info
                callback_data = {}
                for api_name, callbacks in cache.callback_infos.items():
                    if callbacks:
                        callback_data[api_name] = [
                            {
                                'arg_idx': cb.arg_idx,
                                'arg_name': cb.arg_name,
                                'callback_type': cb.callback_type.value,
                                'can_be_null': cb.can_be_null
                            }
                            for cb in callbacks
                        ]

                # TLV/structured parsers
                tlv_data = {}
                for api_name, result in cache.tlv_results.items():
                    if result.is_structured:
                        tlv_data[api_name] = {
                            'format_type': result.format_type.value,
                            'min_size': result.min_size
                        }

                pattern_analysis = {
                    'varlen': varlen_data,
                    'loop': loop_data,
                    'callback': callback_data,
                    'tlv': tlv_data,
                    'summary': enhancer.get_enhancement_summary()
                }

                summary = pattern_analysis.get('summary', {})
                log.info(
                    f'   ✅ Pattern analysis: '
                    f'{summary.get("apis_with_varlen", 0)} varlen, '
                    f'{summary.get("apis_needing_loop", 0)} loop, '
                    f'{summary.get("apis_with_callbacks", 0)} callback, '
                    f'{summary.get("structured_parsers", 0)} TLV'
                )
        except Exception as e:
            log.warning(f"Pattern analysis failed (non-critical): {e}")
            pattern_analysis = {}

        # === Step 10: Generate skeleton drivers (P0 - SkeletonGenerator integration) ===
        log.debug('  10/10 Generating skeleton drivers...')
        skeleton_drivers = []
        try:
            # Generate skeleton drivers using the synthesis module
            skeletons = generator.generate_skeleton_drivers(
                num_drivers=min(num_sequences, 5),  # Limit to 5 skeletons
                driver_size=driver_size,
                llm_client=None  # LLM filtering moved to Prototyper agent
            )

            if skeletons:
                from liberator_adapter.driver.synthesis.skeleton_generator import render_skeleton

                # Determine if target is C++ from benchmark target_path
                target_path = benchmark.target_path if hasattr(benchmark, 'target_path') else ''
                cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
                is_cpp_target = target_path.lower().endswith(cpp_extensions)

                for skeleton in skeletons:
                    # Get API sequence from target_apis
                    api_seq = [api.function_name for api in skeleton.target_apis] if skeleton.target_apis else []

                    # Render skeleton code (use extern "C" only for C++ targets)
                    try:
                        rendered_code = render_skeleton(skeleton, mark_holes=True, is_cpp_target=is_cpp_target)
                    except Exception:
                        rendered_code = str(skeleton)

                    # Extract hole information
                    holes_info = []
                    if hasattr(skeleton, 'holes') and skeleton.holes:
                        # HoleSet stores holes in .holes dict
                        holes_dict = skeleton.holes.holes if hasattr(skeleton.holes, 'holes') else {}
                        for hole in holes_dict.values():
                            holes_info.append({
                                'hole_type': hole.kind.value if hasattr(hole.kind, 'value') else str(hole.kind),
                                'name': hole.name,
                                'filled': hole.is_filled
                            })

                    skeleton_drivers.append({
                        'name': skeleton.name,
                        'api_sequence': api_seq,
                        'code': rendered_code,
                        'holes': holes_info
                    })
                log.info(f'   ✅ Generated {len(skeleton_drivers)} skeleton drivers')
        except Exception as e:
            log.warning(f"Skeleton generation failed (non-critical): {e}")
            skeleton_drivers = []

        # === Step 11: Generate synthesized drivers with CBFactory (always enabled) ===
        # Philosophy: CBFactory generates structurally correct base drivers, LLM Prototyper refines them
        log.info(f'  11/11 Generating synthesized drivers with CBFactory...')
        synthesized_drivers = []
        try:
            synthesized_drivers = _generate_cbfactory_drivers(
                generator=generator,
                num_drivers=num_synthesis_drivers,
                driver_size=driver_size,
                project_name=project_name,
                log=log
            )
            if synthesized_drivers:
                log.info(f'   ✅ Generated {len(synthesized_drivers)} synthesized drivers with CBFactory')
            else:
                log.warning('   ⚠️ No drivers synthesized (CBFactory returned empty)')
        except Exception as e:
            log.warning(f"CBFactory synthesis failed: {e}")
            import traceback
            log.debug(traceback.format_exc())
            synthesized_drivers = []

        # === Create context ===
        elapsed = time.time() - start_time
        log.info(f'✅ Project-level fuzzing context prepared in {elapsed:.2f}s')
        log.debug(
            f'   └─ APIs: {len(project_apis)}, '
            f'Sequences: {len(api_sequences)}, '
            f'Deps: {dep_graph_dict["num_nodes"]} nodes, '
            f'Headers: {len(header_info.get("standard_headers", [])) + len(header_info.get("project_headers", []))}'
        )

        # === Save intermediate results to results folder ===
        results_dir = f"./results/{project_name}"
        log.info(f'📁 Saving intermediate results to {results_dir}/static_analysis/')
        save_intermediate_results(
            project_name=project_name,
            results_dir=results_dir,
            dependency_graph=dep_graph_dict,
            raw_sequences=raw_api_sequences,
            filtered_sequences=api_sequences,
            pattern_analysis=pattern_analysis,
            project_apis=project_apis,
            grammar_info=grammar_info,
            condition_info=condition_info,
            skeleton_drivers=skeleton_drivers,
            log=log
        )

        return cls(
            project_name=project_name,
            project_apis=project_apis,
            api_sequences=api_sequences,
            dependency_graph=dep_graph_dict,
            grammar_info=grammar_info,
            header_info=header_info,
            existing_fuzzer_headers=existing_fuzzer_headers,
            condition_info=condition_info,
            pattern_analysis=pattern_analysis,
            skeleton_drivers=skeleton_drivers,
            synthesized_drivers=synthesized_drivers,
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
            'header_info': self.header_info,
            'existing_fuzzer_headers': self.existing_fuzzer_headers,
            'condition_info': self.condition_info,
            'pattern_analysis': self.pattern_analysis,
            'skeleton_drivers': self.skeleton_drivers,
            'synthesized_drivers': self.synthesized_drivers,
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


def _heuristic_filter_sequences(
    api_sequences: List[List[str]],
    condition_info: Dict[str, Any],
    top_k: int = 12,
    logger_instance: logging.Logger = None
) -> Tuple[List[List[str]], Dict[str, Any]]:
    """
    Filter API sequences using simple heuristic rules (no LLM needed).

    Heuristics:
    1. Prefer sequences with init/create APIs at the start
    2. Prefer sequences with cleanup/free APIs at the end
    3. Prefer longer sequences (more API coverage)
    4. Deduplicate

    This replaces LLM-based filtering for efficiency.
    """
    log = logger_instance or logger

    if not api_sequences:
        return [], {'mode': 'empty_input'}

    # Deduplicate
    api_sequences = _dedup_sequences(api_sequences)

    # Filter out internal APIs (functions starting with '_')
    # These are typically plugin/internal APIs not meant for normal usage
    def _filter_internal_apis(seq: List[str]) -> List[str]:
        return [api for api in seq if not api.startswith('_')]

    filtered_sequences = []
    internal_api_count = 0
    for seq in api_sequences:
        filtered_seq = _filter_internal_apis(seq)
        if len(filtered_seq) >= 2:  # Keep sequences with at least 2 public APIs
            filtered_sequences.append(filtered_seq)
            internal_api_count += len(seq) - len(filtered_seq)

    if internal_api_count > 0:
        log.info(f'   🔒 Filtered {internal_api_count} internal APIs (starting with _)')

    api_sequences = filtered_sequences if filtered_sequences else api_sequences

    # Get init/cleanup hints from condition_info
    inits = set(condition_info.get('inits', []))
    sinks = set(condition_info.get('sinks', []))

    # Common init/cleanup patterns
    init_patterns = {'create', 'new', 'init', 'open', 'alloc', 'start', 'begin'}
    cleanup_patterns = {'free', 'delete', 'destroy', 'close', 'cleanup', 'end', 'finish', 'release'}
    # Parser patterns - these consume external input and have highest fuzzing value
    parser_patterns = {'parse', 'read', 'load', 'decode', 'deserialize', 'unmarshal', 'from'}

    def score_sequence(seq: List[str]) -> float:
        """Score a sequence based on heuristics."""
        score = 0.0

        if not seq:
            return -1000

        first_api = seq[0].lower()
        last_api = seq[-1].lower()

        # HIGH PRIORITY: Parser APIs - consume external input, highest fuzzing value
        for api in seq:
            api_lower = api.lower()
            if any(p in api_lower for p in parser_patterns):
                score += 20  # Significant bonus for parser APIs

        # Bonus for init-like start
        if seq[0] in inits:
            score += 10
        elif any(p in first_api for p in init_patterns):
            score += 5

        # Bonus for cleanup-like end
        if seq[-1] in sinks:
            score += 10
        elif any(p in last_api for p in cleanup_patterns):
            score += 5

        # Bonus for sequence length (more coverage)
        score += len(seq) * 0.5

        # Bonus for diversity (unique APIs)
        score += len(set(seq)) * 0.3

        return score

    # Score and sort sequences
    scored = [(score_sequence(seq), seq) for seq in api_sequences]
    scored.sort(key=lambda x: x[0], reverse=True)

    # Take top_k
    filtered = [seq for _, seq in scored[:top_k]]

    summary = {
        'mode': 'heuristic',
        'input_sequences': len(api_sequences),
        'output_sequences': len(filtered),
        'top_scores': [s for s, _ in scored[:5]]
    }

    log.info(f'   📊 Heuristic filter: {len(api_sequences)} -> {len(filtered)} sequences')

    return filtered, summary


def _generate_sequences_from_grammar(
    grammar,
    num_sequences: int,
    max_len: int,
    log: logging.Logger
) -> List[List[str]]:
    """
    Generate API sequences directly from grammar expansion.

    Expands the grammar's non-terminals randomly to produce valid API call sequences
    that respect the type dependency relationships encoded in the grammar.

    Args:
        grammar: Grammar object from GrammarGenerator
        num_sequences: Number of sequences to generate
        max_len: Maximum length of each sequence
        log: Logger instance

    Returns:
        List of API name sequences
    """
    import random
    from liberator_adapter.grammar import Terminal, NonTerminal

    sequences = []
    max_attempts = num_sequences * 3  # Allow some failures
    attempts = 0

    while len(sequences) < num_sequences and attempts < max_attempts:
        attempts += 1
        try:
            # Start with the grammar's start symbol
            symbols = [grammar.get_start_symbol()]
            expansion_trials = 0
            max_expansion_trials = 50

            # Expand non-terminals until we have only terminals or reach max_len
            while any(isinstance(s, NonTerminal) for s in symbols) and len(symbols) <= max_len:
                # Find non-terminals to expand
                nonterminals = [s for s in symbols if isinstance(s, NonTerminal)]
                if not nonterminals:
                    break

                # Pick a random non-terminal to expand
                symbol_to_expand = random.choice(nonterminals)

                # Get possible expansions
                expansions = grammar[symbol_to_expand]
                if not expansions:
                    # No expansions available, convert to terminal
                    idx = symbols.index(symbol_to_expand)
                    symbols[idx] = Terminal(symbol_to_expand.name)
                    continue

                # Pick a random expansion
                expansion = random.choice(tuple(expansions))

                # Replace the non-terminal with its expansion
                idx = symbols.index(symbol_to_expand)
                del symbols[idx]
                for i, e in enumerate(expansion):
                    symbols.insert(idx + i, e)

                expansion_trials += 1
                if expansion_trials >= max_expansion_trials:
                    break

            # Extract terminal names as the API sequence
            sequence = []
            for s in symbols:
                if isinstance(s, Terminal):
                    name = s.name
                    if name not in ('start', 'end', ''):
                        sequence.append(name)
                elif isinstance(s, NonTerminal):
                    # Convert remaining non-terminals to terminals
                    name = s.name
                    if name not in ('start', 'end', ''):
                        sequence.append(name)

            # Only keep sequences with at least 2 API calls
            if len(sequence) >= 2:
                sequences.append(sequence[:max_len])

        except Exception as e:
            log.debug(f"Grammar expansion failed (attempt {attempts}): {e}")
            continue

    if not sequences:
        log.warning("No sequences generated from grammar, falling back to simple API list")
        # Fallback: just list all APIs from grammar terminals
        all_apis = []
        try:
            for symbol in grammar.symbols():
                if isinstance(symbol, Terminal) and symbol.name not in ('start', 'end', ''):
                    all_apis.append(symbol.name)
            if all_apis:
                # Create simple sequences of random API combinations
                for _ in range(min(num_sequences, 10)):
                    if len(all_apis) >= 2:
                        seq = random.sample(all_apis, min(max_len, len(all_apis)))
                        sequences.append(seq)
        except Exception as e:
            log.warning(f"Fallback sequence generation failed: {e}")

    log.debug(f"Generated {len(sequences)} sequences from grammar (requested {num_sequences})")
    return sequences


def _generate_cbfactory_drivers(
    generator,
    num_drivers: int,
    driver_size: int,
    project_name: str,
    log: logging.Logger
) -> List[Dict[str, Any]]:
    """
    Generate full fuzz drivers using CBFactory (traditional program synthesis).

    This uses Liberator's constraint-based synthesis to generate complete,
    compilable fuzz driver code without LLM involvement.

    Args:
        generator: ProjectDriverGenerator instance (must have condition_manager initialized)
        num_drivers: Number of drivers to generate
        driver_size: Number of API calls per driver
        project_name: Project name (for logging)
        log: Logger instance

    Returns:
        List of synthesized driver dictionaries containing:
        - name: Driver name
        - code: Complete C/C++ driver source code
        - api_sequence: List of API names called
        - synthesis_info: Metadata about the synthesis process
    """
    from liberator_adapter.driver.factory.constraint_based import CBFactory
    from liberator_adapter.backend.libfuzz import LFBackendDriver
    from liberator_adapter.bias import Bias
    import tempfile
    import os

    synthesized_drivers = []

    # Check prerequisites
    if not generator.condition_manager:
        log.warning("ConditionManager not available - CBFactory requires LLVM extraction")
        log.warning("Ensure LLVM extraction is enabled (not --disable-llvm-extraction)")
        return []

    if not generator.function_conditions:
        log.warning("FunctionConditions not available - CBFactory requires conditions.json")
        return []

    if not generator.all_apis:
        log.warning("No APIs available for synthesis")
        return []

    if not generator.dependency_graph:
        log.warning("Dependency graph not available")
        return []

    log.info(f"   🔧 CBFactory synthesis: {num_drivers} drivers, {driver_size} API calls each")

    try:
        # Filter APIs to those with conditions
        available_conditions = set(generator.function_conditions.fun_cond_set.keys())
        filtered_apis = {api for api in generator.all_apis if api.function_name in available_conditions}

        if not filtered_apis:
            log.warning("No APIs have conditions available")
            return []

        log.debug(f"   Using {len(filtered_apis)}/{len(generator.all_apis)} APIs with conditions")

        # Create CBFactory
        bias = Bias()
        factory = CBFactory(
            api_list=filtered_apis,
            driver_size=driver_size,
            dgraph=generator.dependency_graph,
            conditions=generator.function_conditions,
            bias=bias,
            enable_z3_validation=False
        )

        # Create temporary directory for rendering drivers
        with tempfile.TemporaryDirectory() as tmpdir:
            seeds_dir = os.path.join(tmpdir, 'seeds')
            os.makedirs(seeds_dir, exist_ok=True)

            # Setup backend for rendering (if headers available)
            backend = None
            if hasattr(generator, 'headers_dir') and generator.headers_dir:
                try:
                    backend = LFBackendDriver(
                        working_dir=tmpdir,
                        seeds_dir=seeds_dir,
                        num_seeds=1,
                        headers_dir=generator.headers_dir,
                        public_headers=getattr(generator, 'public_headers_path', None)
                    )
                except Exception as e:
                    log.debug(f"Backend setup failed (will use fallback): {e}")

            # Generate drivers
            for i in range(num_drivers):
                try:
                    driver_ir = factory.create_random_driver()

                    # Extract API sequence
                    api_sequence = []
                    for stmt in driver_ir.statements:
                        if hasattr(stmt, 'function_name'):
                            api_sequence.append(stmt.function_name)

                    # Render to C code
                    if backend:
                        driver_name = f"fuzz_driver_{i}"
                        try:
                            backend.emit_driver(driver_ir, driver_name)
                            driver_path = os.path.join(tmpdir, f"{driver_name}.cc")
                            if os.path.exists(driver_path):
                                with open(driver_path, 'r') as f:
                                    driver_code = f.read()
                            else:
                                driver_code = _render_driver_fallback(driver_ir, project_name)
                        except Exception as e:
                            log.debug(f"Backend render failed: {e}, using fallback")
                            driver_code = _render_driver_fallback(driver_ir, project_name)
                    else:
                        driver_code = _render_driver_fallback(driver_ir, project_name)

                    synthesized_drivers.append({
                        'name': f'cbfactory_driver_{i}',
                        'code': driver_code,
                        'api_sequence': api_sequence,
                        'synthesis_info': {
                            'method': 'CBFactory',
                            'driver_size': driver_size,
                            'num_apis_used': len(api_sequence),
                            'has_cleanup': hasattr(driver_ir, 'clean_up') and bool(driver_ir.clean_up),
                        }
                    })
                    log.debug(f"   Generated driver {i+1}/{num_drivers}: {len(api_sequence)} API calls")

                except Exception as e:
                    log.warning(f"   Failed to generate driver {i+1}: {e}")
                    continue

    except Exception as e:
        log.error(f"CBFactory synthesis failed: {e}")
        import traceback
        log.debug(traceback.format_exc())

    return synthesized_drivers


def _render_driver_fallback(driver_ir, project_name: str) -> str:
    """
    Fallback driver rendering when LFBackendDriver is not available.

    Generates a basic LibFuzzer harness from the Driver IR.
    """
    lines = []

    # Standard includes
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("#include <string.h>")
    lines.append("#include <stdlib.h>")
    lines.append("")

    # Try to add project headers (simplified)
    lines.append(f"// TODO: Add {project_name} headers")
    lines.append("")

    # Stub functions (if any)
    if hasattr(driver_ir, 'stub_functions') and driver_ir.stub_functions:
        lines.append("// === Stub Functions ===")
        for func in driver_ir.stub_functions:
            if hasattr(func, 'stub_code') and func.stub_code:
                lines.append(func.stub_code)
            else:
                lines.append(f"// Stub for {func}")
        lines.append("")

    # Main fuzzer function
    lines.append("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
    lines.append("    if (size == 0) return 0;")
    lines.append("")

    # Render statements
    for stmt in driver_ir.statements:
        stmt_str = str(stmt)
        # Indent and add
        for line in stmt_str.split('\n'):
            if line.strip():
                lines.append(f"    {line}")

    lines.append("")

    # Cleanup section
    if hasattr(driver_ir, 'clean_up') and driver_ir.clean_up:
        lines.append("    // Cleanup")
        for cleanup_stmt in driver_ir.clean_up:
            lines.append(f"    {cleanup_stmt}")

    lines.append("    return 0;")
    lines.append("}")

    return "\n".join(lines)


def save_intermediate_results(
    project_name: str,
    results_dir: str,
    dependency_graph: Dict[str, Any],
    raw_sequences: List[List[str]],
    filtered_sequences: List[List[str]],
    pattern_analysis: Dict[str, Any],
    project_apis: List[Dict[str, Any]],
    grammar_info: Dict[str, Any],
    condition_info: Dict[str, Any],
    skeleton_drivers: List[Dict[str, Any]] = None,
    log: logging.Logger = None
) -> None:
    """
    Save all intermediate static analysis results to the results folder.

    Saves:
    - dependency_graph.json: Type dependency graph
    - raw_sequences.json: API sequences before LLM filtering
    - filtered_sequences.json: API sequences after LLM filtering
    - pattern_analysis.json: VarLen/Loop/Callback/TLV analysis
    - project_apis.json: All extracted APIs
    - analysis_summary.json: Combined summary
    """
    log = log or logger

    results_path = Path(results_dir) / "static_analysis"
    results_path.mkdir(parents=True, exist_ok=True)

    try:
        # Save dependency graph
        dep_graph_path = results_path / "dependency_graph.json"
        with open(dep_graph_path, 'w') as f:
            json.dump(dependency_graph, f, indent=2)
        log.info(f"   📄 Saved dependency graph: {dep_graph_path}")

        # Save raw sequences (before LLM filtering)
        raw_seq_path = results_path / "raw_sequences.json"
        with open(raw_seq_path, 'w') as f:
            json.dump({
                'num_sequences': len(raw_sequences),
                'sequences': [
                    {'index': i, 'apis': seq, 'length': len(seq)}
                    for i, seq in enumerate(raw_sequences)
                ]
            }, f, indent=2)
        log.info(f"   📄 Saved raw sequences ({len(raw_sequences)}): {raw_seq_path}")

        # Save filtered sequences (after LLM filtering)
        filtered_seq_path = results_path / "filtered_sequences.json"
        with open(filtered_seq_path, 'w') as f:
            json.dump({
                'num_sequences': len(filtered_sequences),
                'sequences': [
                    {'index': i, 'apis': seq, 'length': len(seq)}
                    for i, seq in enumerate(filtered_sequences)
                ]
            }, f, indent=2)
        log.info(f"   📄 Saved filtered sequences ({len(filtered_sequences)}): {filtered_seq_path}")

        # Save detailed LLM filter results (if available)
        llm_filter_info = grammar_info.get('llm_filter', {})
        if llm_filter_info and llm_filter_info.get('mode') == 'llm_sequence_filter':
            filter_details_path = results_path / "llm_filter_details.json"
            with open(filter_details_path, 'w') as f:
                json.dump({
                    'filter_mode': llm_filter_info.get('mode'),
                    'input_sequences': llm_filter_info.get('input_sequences', 0),
                    'valid_sequences': llm_filter_info.get('valid_sequences', 0),
                    'filter_stats': llm_filter_info.get('filter_stats', {}),
                    'api_lifecycle_cache_size': llm_filter_info.get('api_lifecycle_cache_size', 0),
                    'sequence_details': llm_filter_info.get('details', [])
                }, f, indent=2)
            log.info(f"   📄 Saved LLM filter details: {filter_details_path}")

        # Save pattern analysis
        pattern_path = results_path / "pattern_analysis.json"
        with open(pattern_path, 'w') as f:
            json.dump(pattern_analysis, f, indent=2)
        log.info(f"   📄 Saved pattern analysis: {pattern_path}")

        # Save project APIs
        apis_path = results_path / "project_apis.json"
        with open(apis_path, 'w') as f:
            json.dump({
                'num_apis': len(project_apis),
                'apis': project_apis
            }, f, indent=2)
        log.info(f"   📄 Saved project APIs ({len(project_apis)}): {apis_path}")

        # Save skeleton drivers (for cache loading)
        if skeleton_drivers:
            skeleton_path = results_path / "skeleton_drivers.json"
            with open(skeleton_path, 'w') as f:
                json.dump(skeleton_drivers, f, indent=2)
            log.info(f"   📄 Saved skeleton drivers ({len(skeleton_drivers)}): {skeleton_path}")

        # Save combined summary
        summary_path = results_path / "analysis_summary.json"
        summary = {
            'project_name': project_name,
            'statistics': {
                'total_apis': len(project_apis),
                'dependency_graph_nodes': dependency_graph.get('num_nodes', 0),
                'raw_sequences': len(raw_sequences),
                'filtered_sequences': len(filtered_sequences),
                'filter_reduction': f"{(1 - len(filtered_sequences)/max(len(raw_sequences), 1))*100:.1f}%"
            },
            'grammar_info': grammar_info,
            'condition_info': condition_info,
            'pattern_summary': pattern_analysis.get('summary', {})
        }
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        log.info(f"   📄 Saved analysis summary: {summary_path}")

        log.info(f"✅ All intermediate results saved to: {results_path}")

    except Exception as e:
        log.warning(f"Failed to save intermediate results: {e}")

