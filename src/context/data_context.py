"""
Data context for fuzzing workflow - Single source of truth for all fuzzing data.

This module establishes clear data ownership:
- All data prepared ONCE in run_single_fuzz.py
- Nodes NEVER extract data, they only process what's given
- Failure is explicit, not hidden with fallbacks
"""

from dataclasses import dataclass, field, replace
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
import logging
import json
import os
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
    project_apis: List[Dict[str,
                            Any]]  # List of API information (from Liberator)
    api_sequences: List[List[str]]  # List of API call sequences (from grammar)
    dependency_graph: Dict[str, Any]  # Type dependency graph
    grammar_info: Dict[str, Any]  # Grammar metadata
    header_info: Dict[str, List[str]]
    existing_fuzzer_headers: Dict[str, List[str]]
    condition_info: Dict[str, Any] = field(default_factory=dict)

    # === Pattern analysis (P1: DriverEnhancer integration) ===
    pattern_analysis: Dict[str, Any] = field(
        default_factory=dict)  # VarLen/Loop/Callback/TLV

    # === Z3-validated skeleton drivers (program synthesis as precondition for LLM refinement) ===
    # One skeleton per L4-viable sequence (1:1 binding). Trial N picks
    # skeleton_drivers[(N-1) % K] as its base; LLM refines from there.
    skeleton_drivers: List[Dict[str, Any]] = field(default_factory=list)

    # === Existing driver knowledge (extracted from OSS-Fuzz fuzzers via LLM) ===
    # Contains patterns, configurations, and fuzzing strategies learned from existing drivers
    existing_driver_knowledge: Dict[str, Any] = field(default_factory=dict)

    # === L1: Entry Point Analysis (Progressive Filter Pipeline) ===
    # Entry Points are APIs that directly consume fuzzer data without complex initialization
    entry_point_analysis: Dict[str, Any] = field(default_factory=dict)

    # === L2: Lifecycle Analysis (Progressive Filter Pipeline) ===
    # Lifecycle pairs: init-destroy relationships (e.g., ares_init -> ares_destroy)
    lifecycle_analysis: Dict[str, Any] = field(default_factory=dict)

    # === L3: State Machine Analysis (Progressive Filter Pipeline) ===
    # State machine: API preconditions/postconditions derived from lifecycle
    state_machine_analysis: Dict[str, Any] = field(default_factory=dict)

    # === L4: Coverage Ranking (Progressive Filter Pipeline) ===
    # Final ranking and selection of top-k sequences by coverage potential
    coverage_ranking: Dict[str, Any] = field(default_factory=dict)

    # === Knowledge layer (comprehender) ===
    # comprehension: per-API usage notes + library purpose. Comprehender-A.
    #   Shape: {"purpose": str, "functions": {api_name: usage_text}}
    # sequence_semantics: per-sequence semantic verdict from Comprehender-B.
    #   Shape: list of {"sequence", "semantic_status", "diagnosis", "repair", "invariants_for_prototyper"}
    comprehension: Dict[str, Any] = field(default_factory=dict)
    sequence_semantics: List[Dict[str, Any]] = field(default_factory=list)

    # === Project-adaptive automaton (P3) ===
    # Lightweight summary; the live ``AutomatonArtifact`` (with PTA + EDSM
    # + UseDefGraph) is too heavy to keep in the immutable context. We carry
    # only:
    #   - "summary": ``artifact.to_summary()`` for telemetry / inspection
    #   - "sample_paths": K accepting paths sampled at prepare-time, used
    #     by the prototyper as protocol templates
    # Set to {} when automaton learning failed or was skipped.
    automaton: Dict[str, Any] = field(default_factory=dict)

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
    def load_from_cache(cls,
                        project_name: str,
                        logger_instance: logging.Logger = None
                        ) -> Optional['FuzzingContext']:
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
            'project_apis.json', 'filtered_sequences.json',
            'dependency_graph.json', 'analysis_summary.json',
            'pattern_analysis.json'
        ]

        # Check if cache directory and all required files exist
        if not cache_dir.exists():
            log.debug(f'Cache directory not found: {cache_dir}')
            return None

        missing_files = [
            f for f in required_files if not (cache_dir / f).exists()
        ]
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
                api_sequences = [
                    s['apis'] for s in seq_data.get('sequences', [])
                ]

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
                'standard_headers':
                ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
                'project_headers': []
            }

            # Existing fuzzer headers — disk-backed extractor; empty if the
            # human-written-targets corpus hasn't been downloaded yet.
            existing_fuzzer_headers = _extract_existing_fuzzer_headers(
                project_name, log)

            # Z3-validated skeleton drivers — optional, may not exist in older
            # caches. A cache HIT can skip CBFactory entirely, which is the
            # long pole on first runs (Z3 + ConditionManager).
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

            log.info(
                f'   ✅ Loaded {len(project_apis)} APIs, '
                f'{len(api_sequences)} sequences, '
                f'{len(skeleton_drivers)} Z3 skeletons from cache'
            )

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
    def prepare(cls,
                project_name: str,
                benchmark: Any = None,
                logger_instance: logging.Logger = None,
                num_sequences: int = 24,
                driver_size: int = 5,
                # Budget cap on the per-project driver count after L4
                # greedy max-coverage. NOT a viability filter — viability
                # is decided by L0–L5 + the greedy itself, which already
                # orders by marginal coverage and self-terminates when no
                # candidate adds new APIs. This cap just bounds compile /
                # fuzz / LLM cost. Matches PromeFuzz CCS'25's per-project
                # driver count for direct comparability.
                filter_top_k: int = 10,
                use_cache: bool = True,
                llm_client: Any = None,
                closed_loop_iters: int = 0,
                closed_loop_early_stop: int = 0,
                use_doxygen_priors: bool = False,
                use_readme_purpose: bool = False) -> 'FuzzingContext':
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
            llm_client: Optional LLM client for extracting knowledge from existing drivers

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
                log.info(
                    f'✅ Using cached static analysis for {project_name} (skipping ~60s analysis)'
                )

                # Even when loading from cache, extract knowledge from existing drivers
                # This ensures we always have the latest driver patterns
                log.info(
                    '  📚 Extracting knowledge from existing OSS-Fuzz drivers...'
                )
                existing_driver_knowledge = {}
                try:
                    existing_driver_knowledge = _extract_existing_driver_knowledge(
                        project_name=project_name,
                        log=log,
                        llm_client=llm_client,
                        max_drivers=3)
                    if existing_driver_knowledge.get('driver_sources'):
                        num_drivers = len(
                            existing_driver_knowledge['driver_sources'])
                        has_analysis = bool(
                            existing_driver_knowledge.get('analysis'))
                        extra_str = " (with LLM analysis)" if has_analysis else ""
                        log.info(
                            f'   ✅ Extracted knowledge from {num_drivers} existing drivers{extra_str}'
                        )
                    else:
                        log.info(
                            '   ℹ️ No existing drivers found for knowledge extraction'
                        )
                except Exception as e:
                    log.warning(
                        f"Driver knowledge extraction failed (non-critical): {e}"
                    )

                # Create new context with driver knowledge (FuzzingContext is frozen)
                return replace(
                    cached,
                    existing_driver_knowledge=existing_driver_knowledge)
            log.info(
                f'📦 No valid cache found, running full static analysis for {project_name}'
            )

        start_time = time.time()

        log.info(
            f'📦 Preparing project-level fuzzing context for {project_name}')

        # === Step 1: Create ProjectDriverGenerator ===
        log.debug('  1/12 Creating ProjectDriverGenerator...')
        try:
            if not benchmark:
                raise ValueError(
                    f"benchmark object is required for project-level modeling. "
                    f"ProjectDriverGenerator needs benchmark for Clang/LLVM extraction."
                )

            generator = ProjectDriverGenerator(
                project_name=project_name,
                benchmark=benchmark,
                work_dir=None
            )
            log.info('   ✅ ProjectDriverGenerator created')
        except Exception as e:
            raise RuntimeError(
                f"Failed to create ProjectDriverGenerator: {e}\n"
                f"This is required for project-level modeling.") from e

        # === Step 2: Extract all APIs ===
        log.debug('  2/12 Extracting all APIs from project...')
        try:
            all_apis = generator.extract_all_apis()
            if not all_apis:
                raise ValueError(
                    f"No APIs extracted from project '{project_name}'")

            # Convert Api objects to dictionaries for serialization
            project_apis = []
            for api in all_apis:
                project_apis.append({
                    'function_name':
                    api.function_name,
                    'return_type':
                    api.return_info.type,
                    'arguments': [{
                        'name': arg.name,
                        'type': arg.type,
                        'flag': arg.flag,
                        'size': arg.size,
                        'is_const': arg.is_const
                    } for arg in api.arguments_info],
                    'is_vararg':
                    api.is_vararg,
                    'namespace':
                    api.namespace
                })

            log.info(f'   ✅ Extracted {len(project_apis)} APIs')
        except Exception as e:
            raise RuntimeError(
                f"Failed to extract APIs: {e}\n"
                f"This is an internal error in ProjectDriverGenerator.") from e

        # === Step 3: Build dependency graph ===
        log.debug('  3/12 Building type dependency graph...')
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
            log.info(
                f'   ✅ Dependency graph built: {dep_graph_dict["num_nodes"]} nodes'
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to build dependency graph: {e}\n"
                f"This is an internal error in TypeDependencyGraphGenerator."
            ) from e

        # === Step 3.5: Build data layout (must come BEFORE grammar gen) ===
        # GrammarGenerator.has_incomplete_type → Factory.normalize_type
        # consults DataLayout.instance() for type size/incompleteness/struct
        # classification. The 2026-05 synthesis refactor (cluster 5) removed
        # Factory.normalize_type's try/except fallback that previously
        # masked uninitialised-DataLayout AttributeErrors; without that
        # mask, grammar gen now crashes unless DataLayout is initialised
        # first. Moved up from former Step 5 position. Only depends on
        # extract_metadata (set in Step 2) and self.adapter (init time),
        # so safe to run here.
        log.debug('  3.5/12 Building data layout...')
        try:
            generator.build_data_layout()
            log.info('   ✅ Data layout built')
        except Exception as e:
            log.warning(
                f"Failed to build data layout: {e} (ConditionManager may have reduced precision)"
            )

        # === Step 4: Generate grammar (API sequences) ===
        log.debug('  4/12 Generating grammar and API sequences...')
        try:
            grammar = generator.build_grammar()

            # Generate API sequences directly from grammar expansion
            api_sequences = _generate_sequences_from_grammar(
                grammar=grammar,
                num_sequences=num_sequences,
                max_len=driver_size,
                log=log)
            api_sequences = _dedup_sequences(api_sequences)

            grammar_info = {
                'num_symbols': grammar.num_symbols(),
                'start_symbol': str(grammar.get_start_symbol()),
                'num_sequences': len(api_sequences)
            }
            # Save raw sequences before any filtering
            raw_api_sequences = list(api_sequences)  # Make a copy
            log.info(
                f'   ✅ Grammar generated: {grammar_info["num_symbols"]} symbols, {len(api_sequences)} sequences'
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to generate grammar: {e}\n"
                f"This is an internal error in GrammarGenerator.") from e

        if not api_sequences:
            raise ValueError(
                f"No API sequences generated for project '{project_name}'.\n"
                f"This might indicate the dependency graph is empty or grammar generation failed."
            )

        # === Step 5b: Build condition manager ===
        log.debug('  5b/12 Building condition manager...')
        try:
            condition_manager = generator.build_condition_manager()
            log.info('   ✅ Condition manager built')
        except Exception as e:
            log.warning(
                f"Failed to build condition manager: {e} (non-critical)")
            condition_manager = None

        # Condition summary for prompt/LLM
        condition_info = {}
        if condition_manager:
            try:
                sources = [
                    api.function_name
                    for api in condition_manager.get_source_api()
                ]
                sinks = [
                    api.function_name
                    for api in condition_manager.get_sink_api()
                ]
                inits = [
                    api.function_name
                    for api in condition_manager.get_init_api()
                ]
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

        # === Step 5c: L1 Entry Point Analysis (Progressive Filter Pipeline) ===
        log.debug('  5c/12 Analyzing Entry Points (L1 filter)...')
        entry_point_analysis_result = {}
        try:
            from liberator_adapter.constraints import (
                analyze_entry_points,
                filter_sequences_by_entry_point
            )

            # Analyze Entry Points from project APIs
            ep_analysis = analyze_entry_points(project_apis, logger_instance=log)
            entry_point_analysis_result = ep_analysis.to_dict()

            ep_stats = ep_analysis.get_stats()
            log.info(
                f'   ✅ Entry Point analysis: {ep_stats["entry_point_count"]}/{ep_stats["total_apis"]} '
                f'({ep_stats["entry_point_ratio"]:.1%}) APIs are Entry Points'
            )

            # Apply L1 filter: ALWAYS generate Entry Point-focused sequences
            # Grammar-generated sequences have channel/handle APIs mixed in due to type compatibility,
            # which causes crashes when these APIs receive NULL (uninitialized handle).
            # Solution: Generate clean sequences with just Entry Point + proper cleanup.
            if ep_analysis.entry_point_names:
                pre_filter_count = len(api_sequences)

                # Get all API names for finding cleanup APIs
                # project_apis can be list of dicts (with 'function_name') or Api objects
                all_api_names = set()
                for api in project_apis:
                    if isinstance(api, dict):
                        all_api_names.add(api.get('function_name', ''))
                    else:
                        all_api_names.add(api.function_name)

                # Pre-compute lifecycle pairs so the seeder can append the
                # canonical destroyer to each ``[creator, consumer]`` pattern.
                # This is the same call Step 5d makes; running it here too
                # is idempotent (pure analysis over project_apis) and keeps
                # the seeder a single source of truth for cleanup APIs
                # (i.e. uses L2 facts, not ad-hoc naming heuristics).
                from liberator_adapter.constraints import analyze_lifecycle as _early_lc
                try:
                    _early_lc_pairs = [p.to_dict() for p in _early_lc(project_apis).pairs]
                except Exception as _exc:
                    log.debug('Early lifecycle analysis failed (non-critical): %s', _exc)
                    _early_lc_pairs = []

                # Generate Entry Point-focused sequences (replaces grammar sequences).
                # Pass indirect-pair info so consumer-only names like
                # `ucl_parser_add_chunk` get prefixed with their creator
                # (`ucl_parser_new`) instead of being emitted bare.
                ep_focused = _generate_entry_point_sequences(
                    ep_analysis.entry_point_names,
                    all_api_names,
                    log,
                    indirect_consumer_names=ep_analysis.indirect_consumer_names,
                    indirect_creators_for_consumer=ep_analysis.indirect_creators_for_consumer,
                    lifecycle_pairs=_early_lc_pairs,
                )

                if ep_focused:
                    api_sequences = ep_focused
                    entry_point_analysis_result['filter_summary'] = {
                        'strategy': 'entry_point_focused',
                        'input': pre_filter_count,
                        'output': len(ep_focused),
                        'entry_points_used': len(ep_analysis.entry_point_names),
                    }
                    log.info(
                        f'   ✅ L1 Entry Point filter: {pre_filter_count} -> {len(ep_focused)} sequences '
                        f'(generated clean Entry Point-focused sequences)'
                    )
                else:
                    # Fallback to filtering if generation fails
                    api_sequences, ep_filter_summary = filter_sequences_by_entry_point(
                        api_sequences,
                        ep_analysis,
                        strategy="first",
                        n=3,
                        logger_instance=log
                    )
                    entry_point_analysis_result['filter_summary'] = ep_filter_summary
                    log.warning(
                        f'L1 generation failed, falling back to filter: {pre_filter_count} -> {len(api_sequences)}'
                    )
            else:
                log.warning(
                    'No Entry Points found, skipping L1 filter (all sequences kept)'
                )

        except ImportError as e:
            log.warning(f"Entry Point analyzer not available: {e}")
        except Exception as e:
            log.warning(f"Entry Point analysis failed (non-critical): {e}")

        # === Step 5d: L2 Lifecycle Analysis (Progressive Filter Pipeline) ===
        log.debug('  5d/12 Analyzing Lifecycle pairs (L2 filter)...')
        lifecycle_analysis_result = {}
        try:
            from liberator_adapter.constraints import (
                analyze_lifecycle,
                filter_sequences_by_lifecycle
            )

            # Analyze lifecycle pairs from project APIs and condition_info
            lc_analysis = analyze_lifecycle(
                project_apis,
                condition_info=condition_info,
                logger_instance=log
            )
            lifecycle_analysis_result = lc_analysis.to_dict()

            lc_stats = lc_analysis.get_stats()
            log.info(
                f'   ✅ Lifecycle analysis: {lc_stats["pair_count"]} pairs found '
                f'({lc_stats["init_api_count"]} init, {lc_stats["destroy_api_count"]} destroy)'
            )

            # Apply L2 filter: auto-complete sequences with cleanup APIs
            if lc_analysis.pairs:
                pre_filter_count = len(api_sequences)
                api_sequences, lc_filter_summary = filter_sequences_by_lifecycle(
                    api_sequences,
                    lc_analysis,
                    strategy="auto_complete",
                    logger_instance=log
                )
                lifecycle_analysis_result['filter_summary'] = lc_filter_summary

                if lc_filter_summary.get('auto_completed_count', 0) > 0:
                    log.info(
                        f'   ✅ L2 Lifecycle filter: auto-completed {lc_filter_summary["auto_completed_count"]} '
                        f'sequences with cleanup APIs'
                    )
            else:
                log.info('   ℹ️ No lifecycle pairs found, skipping L2 filter')

        except ImportError as e:
            log.warning(f"Lifecycle analyzer not available: {e}")
        except Exception as e:
            log.warning(f"Lifecycle analysis failed (non-critical): {e}")

        # === Step 5e: L3 State Machine Analysis (Progressive Filter Pipeline) ===
        log.debug('  5e/12 Analyzing State Machine (L3 filter)...')
        state_machine_analysis_result = {}
        try:
            from liberator_adapter.constraints import (
                analyze_state_machine,
                filter_sequences_by_state_machine
            )

            # Analyze state machine from lifecycle analysis
            sm_analysis = analyze_state_machine(
                project_apis,
                lifecycle_analysis=lifecycle_analysis_result,
                condition_info=condition_info,
                logger_instance=log
            )
            state_machine_analysis_result = sm_analysis.to_dict()

            sm_stats = sm_analysis.get_stats()
            log.info(
                f'   ✅ State Machine analysis: {sm_stats["apis_with_constraints"]} APIs with constraints, '
                f'{len(sm_stats["resource_types"])} resource types'
            )

            # Apply L3 filter: remove sequences with critical state violations
            if sm_analysis.constraints:
                pre_filter_count = len(api_sequences)
                api_sequences, sm_filter_summary = filter_sequences_by_state_machine(
                    api_sequences,
                    sm_analysis,
                    strategy="fixable",  # Keep fixable sequences (missing init can be added later)
                    logger_instance=log
                )
                state_machine_analysis_result['filter_summary'] = sm_filter_summary

                if sm_filter_summary.get('invalid_count', 0) > 0:
                    log.info(
                        f'   ✅ L3 State Machine filter: removed {sm_filter_summary["invalid_count"]} '
                        f'sequences with critical violations (use-after-free, double-free)'
                    )
            else:
                log.info('   ℹ️ No state constraints found, skipping L3 filter')

        except ImportError as e:
            log.warning(f"State Machine analyzer not available: {e}")
        except Exception as e:
            log.warning(f"State Machine analysis failed (non-critical): {e}")

        # === Step 5f: L4/L5 Coverage Ranking (Progressive Filter Pipeline) ===
        # L4: Rank sequences by diversity and entry point position
        # L5: Coverage-aware filtering to avoid re-testing already covered code
        log.debug('  5f/12 Ranking sequences by coverage potential (L4/L5)...')
        coverage_ranking_result = {}

        # Fetch the only OSS-Fuzz-specific input we still need: per-function
        # coverage from the cloud Fuzz Introspector. This is the single FI call
        # site in the project; everything else now uses local static analysis.
        existing_coverage = _fetch_oss_fuzz_function_coverage(project_name, log)

        # === Step 5e2: Learn project-adaptive automaton (P3) ===
        # Built from the project's own tests/examples via libclang AST walk;
        # produces a typestate automaton whose accepted language reflects how
        # the library is *actually* used in practice. Used by L4 / L5 below
        # as a soft signal (acceptance score, creator-prefix grafting,
        # accepting-path sample injection). Optional — if learning fails,
        # ranker degrades to pre-automaton behaviour.
        automaton_artifact = None
        try:
            from liberator_adapter.analysis import learn_project_automaton
            project_root_dir = Path(f"./results/{project_name}")
            src_candidates = [
                project_root_dir / "src_ossfuzz" / project_name,
                project_root_dir / "src_ossfuzz",
            ]
            src_root = next((p for p in src_candidates if p.exists()), None)
            if src_root and src_root.is_dir():
                # If we landed on the parent, descend into the first project-name dir.
                if src_root.name != project_name:
                    sub = src_root / project_name
                    if sub.exists():
                        src_root = sub
                # Probe common consumer path names and keep what exists.
                consumer_candidates = ['tests', 'test', 'examples', 'example',
                                       'samples', 'unittests', 'unit', 'testbed']
                consumer_paths = [
                    p for p in consumer_candidates
                    if (src_root / p).exists() and (src_root / p).is_dir()
                ]
                if not consumer_paths:
                    log.debug('  5e2/12 No consumer-path dirs under %s; skipping automaton', src_root)
                else:
                    log.debug('  5e2/12 Learning project-adaptive automaton (consumer_paths=%s)...',
                              consumer_paths)
                    output_dir = project_root_dir / "automaton"
                    automaton_artifact = learn_project_automaton(
                        project=project_name,
                        source_root=src_root,
                        consumer_paths=consumer_paths,
                        project_apis=project_apis,
                        output_dir=output_dir,
                        # Default include dirs that almost every C/C++ project has.
                        include_dirs=[
                            (src_root / d).resolve()
                            for d in ('include', 'src', 'lib', '.')
                            if (src_root / d).exists()
                        ],
                        enable_llm_oracle=False,  # P2 work; oracle off in production for now
                    )
                    log.info(
                        '   ✅ Automaton learned: %d traces → %d merged states '
                        '(observed %d unique APIs)',
                        automaton_artifact.n_traces,
                        automaton_artifact.n_merged_states,
                        len(automaton_artifact.observed_apis()),
                    )
            else:
                log.debug('  5e2/12 No src_ossfuzz/%s; skipping automaton learning', project_name)
        except Exception as exc:
            log.warning('Automaton learning failed (non-critical): %s', exc)
            automaton_artifact = None

        try:
            from liberator_adapter.constraints import select_top_k_sequences

            # Compute the length-1-safe API set: an API can legitimately
            # appear as a single-call sequence iff its USE set is empty
            # (no upstream handle required). The use-def graph gives this
            # exactly. ``automaton_artifact.graph.effect(api).use`` is the
            # single source of truth — same notion downstream uses.
            length_floor_safe: Set[str] = set()
            if automaton_artifact is not None and automaton_artifact.graph is not None:
                for eff in automaton_artifact.graph.all_effects():
                    if not eff.use:
                        length_floor_safe.add(eff.name)

            # Rank and select top-k sequences (with L5 coverage-aware filtering
            # + automaton signal + length-floor defensive guard when available)
            pre_rank_count = len(api_sequences)
            import os as _os
            _disable_cov = _os.environ.get(
                'LOGICFUZZ_DISABLE_COVERAGE_FILTER', '0'
            ).lower() in ('1', 'true', 'yes')
            # filter_top_k is a budget cap (default 10); greedy max-coverage
            # may stop earlier when no candidate adds new APIs (viability
            # self-termination at coverage_ranker.py:394).
            api_sequences, ranking_summary = select_top_k_sequences(
                api_sequences,
                entry_point_analysis=entry_point_analysis_result,
                top_k=filter_top_k,
                logger_instance=log,
                existing_coverage=existing_coverage if existing_coverage else None,
                automaton_artifact=automaton_artifact,
                length_floor_safe_apis=length_floor_safe or None,
                disable_coverage_filter=_disable_cov,
            )
            coverage_ranking_result = ranking_summary

            log.info(
                f'   ✅ L4 Coverage Ranking: {pre_rank_count} -> {len(api_sequences)} sequences '
                f'(covering {ranking_summary.get("api_coverage", 0)} unique APIs)'
            )
            if ranking_summary.get('automaton', {}).get('enabled'):
                log.info(
                    '   ✅ Automaton signal active: %s',
                    ranking_summary['automaton'],
                )

        except ImportError as e:
            log.warning(f"Coverage ranker not available: {e}, falling back to heuristic filter")
            # Fallback to old heuristic filter
            if api_sequences:
                try:
                    filtered, filter_summary = _heuristic_filter_sequences(
                        api_sequences,
                        condition_info=condition_info,
                        top_k=filter_top_k,
                        logger_instance=log)
                    if filtered:
                        api_sequences = filtered
                        log.info(f'   ✅ Heuristic filter applied: {len(api_sequences)} sequences kept')
                    coverage_ranking_result = {'fallback': 'heuristic', **filter_summary}
                except Exception as e2:
                    log.warning(f"Heuristic filter also failed: {e2}")
        except Exception as e:
            log.warning(f"Coverage ranking failed (non-critical): {e}")

        grammar_info['filter'] = coverage_ranking_result
        grammar_info['num_sequences'] = len(api_sequences)

        # === Step 6b: Knowledge comprehension (comprehender-A + B) ===
        # Runs only on the unique APIs / sequences that survived L0-L4 filtering.
        # All LLM calls are fail-soft: if the model is unreachable, we keep the
        # deterministic facts (ConditionManager + lifecycle pairs) and continue.
        comprehension_dict: Dict[str, Any] = {}
        sequence_semantics_dicts: List[Dict[str, Any]] = []
        try:
            from src.knowledge import Comprehender, LibraryComprehension

            unique_apis_in_sequences = sorted({
                api for seq in api_sequences for api in seq if api
            })
            log.debug(
                '  6b/12 Comprehending %d unique APIs across %d sequences...',
                len(unique_apis_in_sequences), len(api_sequences))

            # T1 priors: extract README purpose + doxygen comments from
            # ground-truth project sources before the LLM is consulted.
            # Both flags are opt-in (default OFF) so the first 17-bench
            # A/B run can measure their contribution against baseline.
            # See docs/knowledge_t1_2026_05.md.
            readme_excerpt = ""
            api_docstrings: Dict[str, str] = {}
            cache = None
            if use_readme_purpose or use_doxygen_priors:
                from src.knowledge.cache import KnowledgeCache
                cache = KnowledgeCache(project_name)
                cached_priors = cache.load_docs_priors()
            else:
                cached_priors = {}

            if use_readme_purpose:
                cached_readme = cached_priors.get('readme_purpose', '') if isinstance(cached_priors, dict) else ''
                if cached_readme:
                    readme_excerpt = cached_readme
                    log.info('   📖 README purpose loaded from cache')
                else:
                    from src.knowledge.project_docs import extract_readme_purpose
                    project_root_dir = Path(f"./results/{project_name}")
                    readme_candidates = [
                        project_root_dir / "src_ossfuzz" / project_name,
                        project_root_dir / "src_ossfuzz",
                    ]
                    for cand in readme_candidates:
                        if cand.exists():
                            extracted = extract_readme_purpose(cand)
                            if extracted:
                                readme_excerpt = extracted
                                break
                    if readme_excerpt:
                        log.info(
                            '   📖 README purpose extracted (%d chars)',
                            len(readme_excerpt),
                        )

            if use_doxygen_priors:
                cached_docs = cached_priors.get('api_docstrings', {}) if isinstance(cached_priors, dict) else {}
                if cached_docs:
                    api_docstrings = cached_docs
                    log.info(
                        '   📖 Doxygen priors loaded from cache (%d APIs)',
                        len(api_docstrings),
                    )
                else:
                    try:
                        local_meta = (
                            generator.extract_metadata.get('local', {})
                            if getattr(generator, 'extract_metadata', None)
                            else {}
                        )
                        public_headers_file = local_meta.get('public_headers')
                        public_header_names: List[str] = []
                        if public_headers_file and os.path.exists(public_headers_file):
                            with open(public_headers_file, 'r') as fh:
                                public_header_names = [
                                    ln.strip() for ln in fh if ln.strip()
                                ]
                        headers_dir = getattr(generator, 'headers_dir', None)
                        if headers_dir and public_header_names and unique_apis_in_sequences:
                            from src.knowledge.project_docs import extract_doxygen_comments
                            api_docstrings = extract_doxygen_comments(
                                headers_dir=Path(headers_dir),
                                public_headers=public_header_names,
                                api_names=unique_apis_in_sequences,
                            )
                    except Exception as exc:
                        log.warning(
                            'Doxygen extraction failed (T1 prior unused): %s', exc,
                        )

            # Persist T1 priors so subsequent runs skip the libclang walk.
            if cache is not None and (readme_excerpt or api_docstrings):
                cache.save_docs_priors({
                    'readme_purpose': readme_excerpt,
                    'api_docstrings': api_docstrings,
                })

            comprehender = Comprehender(project_name)
            purpose = comprehender.comprehend_purpose(
                library_name=project_name,
                doc_excerpts=readme_excerpt,
            )

            api_usages = comprehender.comprehend_apis(
                api_names=unique_apis_in_sequences,
                project_apis=project_apis,
                purpose=purpose,
                condition_info=condition_info,
                lifecycle_analysis=lifecycle_analysis_result,
                api_docstrings=api_docstrings if use_doxygen_priors else None,
            )
            comprehension = LibraryComprehension(purpose=purpose, functions=api_usages)
            comprehension_dict = comprehension.to_dict()
            log.info(
                f'   ✅ Comprehender-A: {len(api_usages)}/{len(unique_apis_in_sequences)} APIs annotated'
            )

            sequence_semantics = comprehender.comprehend_sequences(
                sequences=api_sequences,
                api_usages=api_usages,
                purpose=purpose,
                allowed_apis=unique_apis_in_sequences,
                condition_info=condition_info,
                lifecycle_analysis=lifecycle_analysis_result,
                automaton_acceptance_fn=(
                    automaton_artifact.acceptance_score
                    if automaton_artifact is not None else None
                ),
            )
            sequence_semantics_dicts = [s.to_dict() for s in sequence_semantics]

            invalid = sum(1 for s in sequence_semantics if s.semantic_status == "INVALID")
            suboptimal = sum(1 for s in sequence_semantics if s.semantic_status == "SUBOPTIMAL")
            log.info(
                f'   ✅ Comprehender-B: {len(sequence_semantics)} sequences judged '
                f'({invalid} INVALID, {suboptimal} SUBOPTIMAL)'
            )
        except Exception as e:
            log.warning(f"Knowledge comprehension failed (non-critical): {e}")

        # === Step 7: Build the project's compile header_info ===
        # This is the set of #includes the synthesised drivers must emit to
        # see the target project's API surface. Source-of-truth is the
        # ``public_headers.txt`` produced by the Clang/LLVM hybrid extractor
        # (Liberator path) and recorded by ``ProjectDriverGenerator`` as
        # ``extract_metadata['local']['public_headers']``.
        #
        # FAIL-FAST contract: public_headers MUST exist by this stage —
        # either auto-extracted upstream or pre-provided. If missing, raise
        # immediately rather than degrading to an empty project_headers
        # list. Pre-LLM, so the failure is recoverable by re-running
        # extraction or providing the file manually.
        #
        # Distinct from Step 8's ``existing_fuzzer_headers`` (which carries
        # reference ``#include`` lines from real OSS-Fuzz drivers and feeds
        # the Prototyper's include-path-hint block).
        log.debug('  7/12 Building project header_info...')

        public_headers_path: Optional[str] = None
        if (hasattr(generator, 'extract_metadata')
                and generator.extract_metadata):
            local_meta = generator.extract_metadata.get('local', {}) or {}
            public_headers_path = local_meta.get('public_headers')

        if not public_headers_path:
            raise ValueError(
                f"Project '{project_name}' has no public_headers file. "
                f"The Clang/LLVM hybrid extractor was supposed to record "
                f"it as generator.extract_metadata['local']['public_headers']. "
                f"Either re-run extraction (drop --disable-llvm-extraction), "
                f"or pre-populate <work_dir>/public_headers.txt and set the "
                f"metadata key manually before invoking prepare()."
            )
        if not os.path.exists(public_headers_path):
            raise ValueError(
                f"Project '{project_name}' public_headers path "
                f"{public_headers_path!r} does not exist on disk. "
                f"Re-run extraction or restore the file before invoking "
                f"prepare()."
            )

        with open(public_headers_path, 'r') as f:
            public_headers = [h.strip() for h in f if h.strip()]
        if not public_headers:
            raise ValueError(
                f"Project '{project_name}' public_headers file "
                f"{public_headers_path!r} is empty. The extractor produced "
                f"a header list with zero entries; without project headers "
                f"the synthesised driver cannot #include the target API. "
                f"Re-run extraction or hand-edit the file."
            )

        header_info = {
            'standard_headers':
            ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
            'project_headers': public_headers,
        }
        log.info(
            f"   ✅ Loaded {len(public_headers)} project headers from "
            f"{public_headers_path}"
        )

        # === Step 8: Extract existing fuzzer headers (for reference) ===
        log.debug('  8/12 Extracting existing fuzzer headers...')
        try:
            existing_fuzzer_headers = _extract_existing_fuzzer_headers(
                project_name, log)
        except Exception as e:
            log.warning(f"Failed to extract existing fuzzer headers: {e}")
            existing_fuzzer_headers = {
                'standard_headers': [],
                'project_headers': []
            }

        # === Step 9: Pattern analysis (P1 - DriverEnhancer integration) ===
        # NOTE: LLM disabled - using heuristics only for pattern analysis
        # Each analyzer (VarLen, Loop, Callback, TLV) has built-in heuristic fallbacks
        log.debug(
            '  9/12 Analyzing special patterns (VarLen/Loop/Callback/TLV) using heuristics...'
        )
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
                    varlen_data[api_name] = [{
                        'buffer_arg_idx': rel.buffer_arg_idx,
                        'buffer_arg_name': rel.buffer_arg_name,
                        'length_arg_idx': rel.length_arg_idx,
                        'length_arg_name': rel.length_arg_name,
                        'relationship': rel.relationship,
                        'confidence': rel.confidence
                    } for rel in relations]

                # Loop patterns
                loop_data = {}
                for api_name, info in cache.loop_patterns.items():
                    if info.needs_loop:
                        loop_data[api_name] = {
                            'loop_type': info.loop_type.value,
                            'termination_condition':
                            info.termination_condition,
                            'max_iterations': info.max_iterations,
                            'confidence': info.confidence
                        }

                # Callback info
                callback_data = {}
                for api_name, callbacks in cache.callback_infos.items():
                    if callbacks:
                        callback_data[api_name] = [{
                            'arg_idx':
                            cb.arg_idx,
                            'arg_name':
                            cb.arg_name,
                            'callback_type':
                            cb.callback_type.value,
                            'can_be_null':
                            cb.can_be_null
                        } for cb in callbacks]

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
                log.info(f'   ✅ Pattern analysis: '
                         f'{summary.get("apis_with_varlen", 0)} varlen, '
                         f'{summary.get("apis_needing_loop", 0)} loop, '
                         f'{summary.get("apis_with_callbacks", 0)} callback, '
                         f'{summary.get("structured_parsers", 0)} TLV')
        except Exception as e:
            log.warning(f"Pattern analysis failed (non-critical): {e}")
            pattern_analysis = {}

        # === Step 10: Z3-validated skeleton drivers (program synthesis as
        # the deterministic precondition before LLM refinement) ===
        #
        # This step produces ONE constraint-validated DriverSkeleton per
        # L4-viable sequence. The skeleton is structurally correct
        # (CBFactory's varlen_relations / type matching / lifecycle
        # constraints all enforced) and marks the parts requiring
        # semantic judgment (callbacks, buffer sizes) as Holes. The LLM
        # then refines this skeleton — it does NOT generate the driver
        # from scratch.
        #
        # The previous implementation routed through
        # ``generator.generate_skeleton_drivers()``, which only used
        # SkeletonGenerator's pattern path (no Z3 validation, type-string
        # heuristics only). We now go through CBFactory's
        # ``create_skeleton_for_sequence`` so:
        #   - Each sequence is Z3-checked; infeasible ones are dropped
        #     (viability analysis self-decides, no numeric cap).
        #   - The resulting skeleton's structure derives from CBFactory's
        #     varlen / typestate analysis, not from regex on type strings.
        log.debug('  10/12 Generating Z3-validated skeleton drivers...')
        skeleton_drivers = []
        filtered_api_sequences: List[List[Any]] = []  # consumed by Step 11
        try:
            api_name_to_obj = {api.function_name: api for api in generator.all_apis}
            for seq in api_sequences:
                api_objs = [api_name_to_obj[name]
                            for name in seq if name in api_name_to_obj]
                if api_objs:
                    filtered_api_sequences.append(api_objs)

            if filtered_api_sequences:
                log.info(f'   ℹ️ Using {len(filtered_api_sequences)} filtered sequences from L0-L4 pipeline')
            else:
                log.warning('   ⚠️ No valid filtered sequences, falling back to auto-generation')

            skeleton_drivers = _synthesize_skeletons_per_sequence(
                generator=generator,
                target_sequences=filtered_api_sequences,
                driver_size=driver_size,
                benchmark=benchmark,
                log=log,
                automaton_artifact=automaton_artifact,
            )
            if skeleton_drivers:
                log.info(
                    f'   ✅ {len(skeleton_drivers)}/{len(filtered_api_sequences)} sequences passed Z3 → skeletons emitted')
        except Exception as e:
            log.warning(f"Skeleton generation failed (non-critical): {e}")
            skeleton_drivers = []

        # Single SSOT for trial-bound list. Overwrite api_sequences with the
        # Z3-passed subset when non-empty so downstream consumers (prototyper
        # PRIMARY index, _format_api_sequences, _format_synthesis_base_driver)
        # all see the same K' = len(skeleton_drivers) list. Trial N then
        # picks index (N-1) % K' across BOTH api_sequences[i] and
        # skeleton_drivers[i] — they refer to the same logical sequence.
        # When skeleton_drivers is empty (Z3 rejected every L4-viable seq,
        # or skeleton synthesis failed), keep the original L0-L4 name list
        # so the LLM still sees protocol candidates in the prompt.
        if skeleton_drivers:
            api_sequences = [s.get('api_sequence', []) for s in skeleton_drivers]
            log.info(
                f'   🔗 api_sequences aligned with skeleton_drivers '
                f'(K={len(api_sequences)})')

        # === Step 11 (Phase G): Closed-loop automaton feedback ===
        # When ``closed_loop_iters > 0`` and the project has a learned
        # automaton, run N feedback iterations. Each iteration feeds the
        # current viable skeletons' API sequences as evidence (incremental
        # EDSM merge), then re-synthesises additional drivers under the
        # grown automaton. The artifact is mutated in-place; Phase E
        # post-parse extensions and Phase H acceptance guard read the
        # mutated artifact automatically when prepare()'s automaton
        # snapshot block (below) reads `sample_accepting_paths` etc.
        #
        # cl_result.final_drivers is intentionally discarded: the LLM
        # consumes ``skeleton_drivers`` as its base. The closed loop's
        # value here is the automaton mutation it preserves through
        # ``persist_dir`` and through the artifact passed by reference.
        log.info(
            "  11/12 Phase G gate: closed_loop_iters=%d, "
            "automaton_artifact=%s, skeleton_drivers=%d",
            closed_loop_iters,
            "present" if automaton_artifact is not None else "None",
            len(skeleton_drivers),
        )
        if (closed_loop_iters > 0
                and automaton_artifact is not None
                and skeleton_drivers):
            try:
                from src.closed_loop import run_closed_loop

                def _resynth(art, k: int) -> List[Dict[str, Any]]:
                    return _generate_cbfactory_drivers(
                        generator=generator,
                        num_drivers=k,
                        driver_size=driver_size,
                        project_name=project_name,
                        log=log,
                        automaton_artifact=art,
                    ) or []

                cl_result = run_closed_loop(
                    project=project_name,
                    automaton_artifact=automaton_artifact,
                    initial_drivers=skeleton_drivers,
                    resynthesize_fn=_resynth,
                    n_iters=closed_loop_iters,
                    early_stop_delta=closed_loop_early_stop,
                    target_drivers_per_iter=len(skeleton_drivers),
                    persist_dir=Path(f"./results/{project_name}/automaton"),
                    log=log,
                )
                log.info(
                    "   🔁 Closed-loop done: %d iters run (early_stopped=%s, "
                    "reason=%s); evidence drivers in last iter=%d",
                    len(cl_result.iterations),
                    cl_result.early_stopped,
                    cl_result.early_stop_reason or "n/a",
                    len(cl_result.final_drivers),
                )
            except Exception as exc:
                log.warning("Closed-loop feedback failed (non-critical): %s",
                            exc)

        # === Step 12: Extract knowledge from existing drivers (optional, requires LLM) ===
        log.info('  12/12 Extracting knowledge from existing drivers...')
        existing_driver_knowledge = {}
        try:
            existing_driver_knowledge = _extract_existing_driver_knowledge(
                project_name=project_name,
                log=log,
                llm_client=llm_client,
                max_drivers=3)
            if existing_driver_knowledge.get('driver_sources'):
                num_drivers = len(existing_driver_knowledge['driver_sources'])
                has_analysis = bool(existing_driver_knowledge.get('analysis'))
                log.info(
                    f'   ✅ Extracted knowledge from {num_drivers} existing drivers'
                    f'{" (with LLM analysis)" if has_analysis else ""}')
            else:
                log.info(
                    '   ℹ️ No existing drivers found for knowledge extraction')
        except Exception as e:
            log.warning(
                f"Driver knowledge extraction failed (non-critical): {e}")
            existing_driver_knowledge = {}

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
        log.info(
            f'📁 Saving intermediate results to {results_dir}/static_analysis/')
        save_intermediate_results(project_name=project_name,
                                  results_dir=results_dir,
                                  dependency_graph=dep_graph_dict,
                                  raw_sequences=raw_api_sequences,
                                  filtered_sequences=api_sequences,
                                  pattern_analysis=pattern_analysis,
                                  project_apis=project_apis,
                                  grammar_info=grammar_info,
                                  condition_info=condition_info,
                                  skeleton_drivers=skeleton_drivers,
                                  log=log)

        return cls(project_name=project_name,
                   project_apis=project_apis,
                   api_sequences=api_sequences,
                   dependency_graph=dep_graph_dict,
                   grammar_info=grammar_info,
                   header_info=header_info,
                   existing_fuzzer_headers=existing_fuzzer_headers,
                   condition_info=condition_info,
                   pattern_analysis=pattern_analysis,
                   skeleton_drivers=skeleton_drivers,
                   existing_driver_knowledge=existing_driver_knowledge,
                   entry_point_analysis=entry_point_analysis_result,
                   lifecycle_analysis=lifecycle_analysis_result,
                   state_machine_analysis=state_machine_analysis_result,
                   coverage_ranking=coverage_ranking_result,
                   comprehension=comprehension_dict,
                   sequence_semantics=sequence_semantics_dicts,
                   automaton=(
                       {
                           'summary': automaton_artifact.to_summary(),
                           'sample_paths': automaton_artifact.sample_accepting_paths(n=8),
                           'observed_apis': sorted(automaton_artifact.observed_apis()),
                       }
                       if automaton_artifact is not None else {}
                   ),
                   preparation_time=elapsed)

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
            'existing_driver_knowledge': self.existing_driver_knowledge,
            'entry_point_analysis': self.entry_point_analysis,
            'lifecycle_analysis': self.lifecycle_analysis,
            'state_machine_analysis': self.state_machine_analysis,
            'coverage_ranking': self.coverage_ranking,
            'comprehension': self.comprehension,
            'sequence_semantics': self.sequence_semantics,
            'automaton': self.automaton,
            'preparation_time': self.preparation_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FuzzingContext':
        """Reconstruct from dictionary."""
        return cls(**data)


def _fetch_oss_fuzz_function_coverage(
        project_name: str,
        log: logging.Logger) -> Dict[str, float]:
    """Single Fuzz Introspector call site for the whole project.

    Returns ``{function_name: code_coverage_percent}`` from the cloud OSS-Fuzz
    introspector (or ``{}`` on any failure). Endpoint can be overridden by
    setting ``LOGICFUZZ_FI_ENDPOINT`` in the environment.
    """
    try:
        from data_prep import introspector
    except ImportError as e:
        log.debug(f"FI client unavailable: {e}")
        return {}

    endpoint = os.environ.get('LOGICFUZZ_FI_ENDPOINT')
    if endpoint:
        introspector.set_introspector_endpoints(endpoint)

    try:
        all_funcs = introspector.query_introspector_all_functions(project_name)
    except Exception as e:
        log.debug(f"Could not fetch existing coverage (non-critical): {e}")
        return {}

    coverage: Dict[str, float] = {}
    for func in all_funcs or []:
        name = func.get('function_name') or func.get('raw-function-name', '')
        cov = func.get('code_coverage', func.get('code-coverage', 0))
        if not name or cov is None:
            continue
        try:
            coverage[name] = float(cov)
        except (TypeError, ValueError):
            continue
    if coverage:
        log.info(
            f'   ℹ️ Loaded existing coverage for {len(coverage)} functions '
            f'from cloud FuzzIntrospector')
    return coverage


_DRIVER_SIGNATURE_RE = re.compile(
    r"LLVMFuzzerTestOneInput|extern\s+\"C\"\s+int\s+LLVMFuzzer")
_DRIVER_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s+([<"])([^>"]+)[>"]', re.MULTILINE)
_DRIVER_FILE_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.c++')


def _resolve_drivers_root(project_name: str) -> Optional[Path]:
    """Locate the on-disk corpus of human-written fuzz drivers for a project.

    The corpus is populated by ``data_prep/extract_all_fuzz_drivers.py`` (GCS
    pull from ``oss-fuzz-llm-public/human_written_targets/``). We probe in
    order:

      1. ``$LOGICFUZZ_DRIVERS_ROOT/{project_name}/`` (operator override)
      2. ``./extracted_fuzz_drivers/{project_name}/`` (script default,
         relative to current working directory)
      3. ``<repo_root>/extracted_fuzz_drivers/{project_name}/`` (script
         default when run from anywhere else in the tree)

    Returns the first existing directory, or ``None`` if no corpus is
    available — callers are expected to degrade gracefully (the
    pre-resurrection behaviour was to return empty unconditionally).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent

    candidates: List[Path] = []
    env_root = os.environ.get('LOGICFUZZ_DRIVERS_ROOT')
    if env_root:
        candidates.append(Path(env_root) / project_name)
    candidates.append(Path('extracted_fuzz_drivers') / project_name)
    candidates.append(repo_root / 'extracted_fuzz_drivers' / project_name)

    for cand in candidates:
        if cand.is_dir():
            return cand
    return None


def _iter_driver_source_files(root: Path) -> List[Path]:
    """List driver source files under ``root``.

    A file is a driver iff it (a) has a C/C++ source extension and (b)
    contains the ``LLVMFuzzerTestOneInput`` entry point. Filename pattern
    alone is unreliable — OSS-Fuzz drivers don't all match ``*_fuzzer.*``
    (some use ``fuzz_*.cc``, ``*_harness.cc``, plain ``main.cc``, etc.).
    """
    drivers: List[Path] = []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _DRIVER_FILE_EXTS:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if _DRIVER_SIGNATURE_RE.search(text):
            drivers.append(path)
    return drivers


def _extract_existing_fuzzer_headers(
        project_name: str, log: logging.Logger) -> Dict[str, List[str]]:
    """Extract ``#include`` directives used by the project's existing fuzzers.

    Disk-backed: reads driver sources downloaded by
    ``data_prep/extract_all_fuzz_drivers.py``. Returns
    ``{'standard_headers': ['<stdio.h>', ...], 'project_headers':
    ['cJSON.h', ...]}`` — angle-bracket and quote-form includes split for
    the prototyper's include-path context (it renders project headers
    as ``#include "..."`` references).

    Returns empty lists when the corpus is unavailable; this preserves
    the call-site behaviour the wiring assumes. Operators wanting the
    feature run the download script once and set
    ``LOGICFUZZ_DRIVERS_ROOT`` or place the corpus at
    ``./extracted_fuzz_drivers/{project}/``.
    """
    root = _resolve_drivers_root(project_name)
    if root is None:
        log.debug(
            "No existing-fuzzer corpus for '%s' (looked under "
            "LOGICFUZZ_DRIVERS_ROOT / ./extracted_fuzz_drivers/; run "
            "data_prep/extract_all_fuzz_drivers.py to populate)",
            project_name,
        )
        return {'standard_headers': [], 'project_headers': []}

    standard: Set[str] = set()
    project: Set[str] = set()
    driver_files = _iter_driver_source_files(root)
    for path in driver_files:
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for delim, header in _DRIVER_INCLUDE_RE.findall(text):
            header = header.strip()
            if not header:
                continue
            # Strip leading ./ or directory components for the quote-form
            # references — the prototyper uses these as include name hints,
            # not literal paths.
            if delim == '<':
                standard.add(f'<{header}>')
            else:
                project.add(header)

    headers = {
        'standard_headers': sorted(standard),
        'project_headers': sorted(project),
    }
    if driver_files:
        log.info(
            "   📚 Loaded %d existing fuzzer driver(s) for header reference "
            "(%d standard, %d project includes) from %s",
            len(driver_files), len(headers['standard_headers']),
            len(headers['project_headers']), root,
        )
    return headers


def _strip_license_header(source: str) -> str:
    """
    Remove license header from source code while preserving the actual code.

    Handles common license patterns:
    - /* ... */ block comments at the start
    - // line comments at the start
    - Copyright notices
    - License boilerplate (Apache, MIT, BSD, etc.)

    Args:
        source: Raw source code string

    Returns:
        Source code with license header removed
    """
    lines = source.split('\n')

    # Track where the license block ends
    code_start_index = 0
    in_block_comment = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Handle block comment start
        if stripped.startswith('/*'):
            in_block_comment = True
            # Check if block comment ends on same line
            if '*/' in stripped:
                in_block_comment = False
            code_start_index = i + 1
            continue

        # Handle block comment end
        if in_block_comment:
            if '*/' in stripped:
                in_block_comment = False
            code_start_index = i + 1
            continue

        # Handle line comments at the start (often license headers)
        if stripped.startswith('//'):
            # Check if this looks like license/copyright
            lower = stripped.lower()
            if any(kw in lower for kw in [
                    'copyright', 'license', 'permission', 'redistribution',
                    'disclaimer', 'warranty', 'use of this source', 'apache',
                    'mit', 'bsd'
            ]):
                code_start_index = i + 1
                continue
            # Stop if we see actual code comments (not license)
            if not any(kw in lower for kw in [
                    'copyright', 'license', 'permission', 'redistribution',
                    'http://', 'https://'
            ]):
                break

        # Empty lines at the start - keep scanning
        if not stripped:
            code_start_index = i + 1
            continue

        # Non-comment, non-empty line - this is code, stop here
        break

    # Return code starting from after the license
    result = '\n'.join(lines[code_start_index:])

    # Strip leading empty lines
    return result.lstrip('\n')


def _extract_existing_driver_knowledge(project_name: str,
                                       log: logging.Logger,
                                       llm_client: Any = None,
                                       max_drivers: int = 3) -> Dict[str, Any]:
    """Load existing OSS-Fuzz drivers and optionally run LLM pattern analysis.

    Disk-backed: reads driver sources downloaded by
    ``data_prep/extract_all_fuzz_drivers.py``. Returns:

        {
          'driver_sources': [{'path': <abs path>, 'source': <full text>}, ...],
          'analysis': {                       # only when llm_client is given
              'core_functionality': str,
              'setup_teardown': str,
              'code_patterns': str,
          } | None,
        }

    The Prototyper renders ``driver_sources`` as ``<reference_drivers>`` and
    ``analysis`` as ``<core_apis>`` / ``<code_patterns>`` / ``<setup_teardown>``
    blocks in the prompt (see ``prototyper._format_driver_knowledge``).

    Returns empty when the corpus is unavailable; callers degrade
    gracefully (the formatter emits no block at all).
    """
    root = _resolve_drivers_root(project_name)
    if root is None:
        log.debug(
            "No existing-fuzzer corpus for '%s' driver-knowledge extraction "
            "(LOGICFUZZ_DRIVERS_ROOT not set, ./extracted_fuzz_drivers/ "
            "absent); falling back to empty knowledge",
            project_name,
        )
        return {'driver_sources': [], 'analysis': None}

    driver_files = _iter_driver_source_files(root)
    if not driver_files:
        log.debug(
            "Corpus for '%s' exists at %s but no driver sources detected "
            "(no file matched LLVMFuzzerTestOneInput)",
            project_name, root,
        )
        return {'driver_sources': [], 'analysis': None}

    driver_sources: List[Dict[str, str]] = []
    for path in driver_files[:max_drivers]:
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError as e:
            log.debug("Skipping driver %s: %s", path, e)
            continue
        driver_sources.append({'path': str(path), 'source': text})

    log.info(
        "   📚 Loaded %d existing driver(s) for knowledge extraction from %s",
        len(driver_sources), root,
    )

    analysis: Optional[Dict[str, str]] = None
    if llm_client is not None and driver_sources:
        try:
            analysis = _analyze_driver_patterns(
                driver_sources, project_name, llm_client, log)
        except Exception as e:
            log.warning(f"LLM pattern analysis failed (non-critical): {e}")
            analysis = None

    return {'driver_sources': driver_sources, 'analysis': analysis}


def _analyze_driver_patterns(driver_sources: List[Dict[str, str]],
                             project_name: str, llm_client: Any,
                             log: logging.Logger) -> Dict[str, str]:
    """
    Analyze existing drivers to extract reusable patterns using XML tag format.

    Returns dict with 'core_functionality', 'setup_teardown', and 'code_patterns' keys.
    """
    from src.utils.prompt_loader import load_prompt_file
    from src.agents.utils import parse_tag

    # Format driver code - strip license headers to save tokens
    drivers_text = ""
    for i, d in enumerate(driver_sources[:5]):
        source = _strip_license_header(d['source'])
        drivers_text += f"\n=== Driver {i+1}: {d['path']} ===\n{source}\n"

    # Load prompt from file
    try:
        prompt_template = load_prompt_file(
            'driver_pattern_analyzer_prompt.txt')
        prompt = prompt_template.replace('{PROJECT_NAME}', project_name)
        prompt = prompt.replace('{DRIVERS_TEXT}', drivers_text)
    except FileNotFoundError:
        log.warning("driver_pattern_analyzer_prompt.txt not found")
        return {
            'core_functionality': '',
            'setup_teardown': '',
            'code_patterns': ''
        }

    try:
        response = llm_client.query(prompt)
        log.info('Analyzed driver patterns with LLM')

        # Parse XML tags from response
        result = {
            'core_functionality': parse_tag(response, 'core_functionality'),
            'setup_teardown': parse_tag(response, 'setup_teardown'),
            'code_patterns': parse_tag(response, 'code_patterns'),
        }

        # Log if any tags are missing
        for key, value in result.items():
            if not value:
                log.debug(
                    f"Missing <{key}> tag in driver pattern analysis response")

        return result

    except Exception as e:
        log.warning(f"Driver pattern analysis failed: {e}")
        return {
            'core_functionality': '',
            'setup_teardown': '',
            'code_patterns': ''
        }


def _generate_entry_point_sequences(
    entry_point_names: set,
    all_api_names: set,
    log,
    indirect_consumer_names: Optional[set] = None,
    indirect_creators_for_consumer: Optional[Dict[str, List[str]]] = None,
    lifecycle_pairs: Optional[List[Dict[str, Any]]] = None,
) -> List[List[str]]:
    """
    Generate Entry Point-focused sequences with proper cleanup APIs.

    Grammar-generated sequences mix Entry Points with channel-dependent APIs
    due to type compatibility. This function generates clean sequences with just:
    - Entry Point API (parser that consumes fuzzer input). For *indirect* entry
      points (consumer requires a handle produced by another API) the canonical
      creator is prefixed automatically: ``[creator, consumer, ...cleanup]``.
    - Proper cleanup API (matched by naming pattern, not from grammar)

    Args:
        entry_point_names: Set of Entry Point API names (direct + indirect-consumers)
        all_api_names: Set of all API names in the project
        log: Logger instance
        indirect_consumer_names: Subset of entry_point_names that are *indirect*
            consumers (e.g. ``ucl_parser_add_chunk``).
        indirect_creators_for_consumer: Map ``consumer_name -> [creator_name, ...]``
            ranked best-first. Used to prefix consumer-only sequences.

    Returns:
        List of Entry Point-focused sequences
    """
    result = []
    indirect_consumer_names = indirect_consumer_names or set()
    indirect_creators_for_consumer = indirect_creators_for_consumer or {}
    lifecycle_pairs = lifecycle_pairs or []

    # Find common prefix (e.g., "ares" for c-ares)
    prefix = _find_api_prefix(entry_point_names)

    # ---- cleanup-API lookup, two sources ----
    # 1. *Primary*: L2 LifecycleAnalysis pairs. ``init_api → destroy_api``
    #    are project-discovered (name + type + semantic patterns), so this
    #    works for any project whose L2 found pairs — no per-project naming
    #    heuristic needed. Single source of truth for lifecycle facts.
    # 2. *Fallback*: ``_find_cleanup_for_entry_point`` (naming-pattern
    #    matcher) for projects whose L2 missed pairs.
    init_to_destroy: Dict[str, str] = {}
    for pair in lifecycle_pairs:
        i, d = pair.get('init_api'), pair.get('destroy_api')
        if i and d:
            init_to_destroy[i] = d

    ep_to_cleanup: Dict[str, str] = {}
    for ep_name in entry_point_names:
        # Try L2-discovered destroyer first (covers libucl-shape libraries).
        if ep_name in init_to_destroy:
            ep_to_cleanup[ep_name] = init_to_destroy[ep_name]
            continue
        # Fall back to naming pattern (covers c-ares-shape libraries).
        cleanup_api = _find_cleanup_for_entry_point(ep_name, all_api_names, prefix)
        if cleanup_api:
            ep_to_cleanup[ep_name] = cleanup_api

    # Generate sequences
    for ep_name in sorted(entry_point_names):  # Sort for determinism
        is_indirect = ep_name in indirect_consumer_names
        creators = indirect_creators_for_consumer.get(ep_name, []) if is_indirect else []
        prefix_apis = [creators[0]] if creators else []

        # Skip indirect consumers with no creator — bare [consumer] would
        # crash because the handle arg would be NULL.
        if is_indirect and not prefix_apis:
            log.debug(
                f"Skipping indirect consumer '{ep_name}': no creator registered"
            )
            continue

        # Simple sequence: (creator) + entry point
        result.append(prefix_apis + [ep_name])

        # Cleanup append. For indirect consumers we also try the *creator's*
        # destroyer (the handle the creator opened needs closing).
        cleanup_api = ep_to_cleanup.get(ep_name)
        if cleanup_api:
            result.append(prefix_apis + [ep_name, cleanup_api])
        elif prefix_apis:
            # No cleanup for the consumer itself, but the upstream creator
            # may have a paired destroyer — emit ``[creator, consumer, creator_destroy]``.
            creator_destroy = init_to_destroy.get(prefix_apis[0])
            if creator_destroy:
                result.append(prefix_apis + [ep_name, creator_destroy])

    # Deduplicate
    seen = set()
    unique = []
    for seq in result:
        key = tuple(seq)
        if key not in seen:
            seen.add(key)
            unique.append(seq)

    log.debug(
        f"Generated {len(unique)} Entry Point-focused sequences from "
        f"{len(entry_point_names)} Entry Points "
        f"({len(indirect_consumer_names)} indirect)"
    )
    return unique


def _find_api_prefix(api_names: set) -> str:
    """Find common prefix from API names (e.g., 'ares' from ares_parse_*)."""
    if not api_names:
        return ''

    # Get first API and find its prefix
    first_api = next(iter(api_names))
    parts = first_api.split('_')
    if parts:
        return parts[0]
    return ''


def _find_cleanup_for_entry_point(ep_name: str, all_api_names: set, prefix: str) -> str:
    """
    Find the proper cleanup API for an Entry Point based on naming patterns.

    Patterns:
    - {prefix}_parse_*_reply -> {prefix}_free_data or {prefix}_free_hostent
    - {prefix}_dns_parse -> {prefix}_dns_record_destroy
    - {prefix}_create_query -> {prefix}_free_string (query buffer)
    """
    # Pattern 1: parse_*_reply functions use free_data or free_hostent
    if '_parse_' in ep_name and '_reply' in ep_name:
        # Try free_data first (generic cleanup)
        free_data = f'{prefix}_free_data'
        if free_data in all_api_names:
            return free_data
        # Try free_hostent (for host resolution results)
        free_hostent = f'{prefix}_free_hostent'
        if free_hostent in all_api_names:
            return free_hostent

    # Pattern 2: dns_parse uses dns_record_destroy
    if '_dns_parse' in ep_name:
        dns_destroy = f'{prefix}_dns_record_destroy'
        if dns_destroy in all_api_names:
            return dns_destroy

    # Pattern 3: create_query needs the query buffer freed
    if '_create_query' in ep_name or '_mkquery' in ep_name:
        free_string = f'{prefix}_free_string'
        if free_string in all_api_names:
            return free_string
        # Some libraries use plain free() - return None to let driver handle it
        return None

    # No specific cleanup found - return None (driver handles cleanup)
    return None


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
        if len(filtered_seq
               ) >= 2:  # Keep sequences with at least 2 public APIs
            filtered_sequences.append(filtered_seq)
            internal_api_count += len(seq) - len(filtered_seq)

    if internal_api_count > 0:
        log.info(
            f'   🔒 Filtered {internal_api_count} internal APIs (starting with _)'
        )

    api_sequences = filtered_sequences if filtered_sequences else api_sequences

    # Get init/cleanup hints from condition_info
    inits = set(condition_info.get('inits', []))
    sinks = set(condition_info.get('sinks', []))

    # Common init/cleanup patterns
    init_patterns = {
        'create', 'new', 'init', 'open', 'alloc', 'start', 'begin'
    }
    cleanup_patterns = {
        'free', 'delete', 'destroy', 'close', 'cleanup', 'end', 'finish',
        'release'
    }
    # Parser patterns - these consume external input and have highest fuzzing value
    parser_patterns = {
        'parse', 'read', 'load', 'decode', 'deserialize', 'unmarshal', 'from'
    }

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

    log.info(
        f'   📊 Heuristic filter: {len(api_sequences)} -> {len(filtered)} sequences'
    )

    return filtered, summary


def _generate_sequences_from_grammar(grammar, num_sequences: int, max_len: int,
                                     log: logging.Logger) -> List[List[str]]:
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
            while any(isinstance(s, NonTerminal)
                      for s in symbols) and len(symbols) <= max_len:
                # Find non-terminals to expand
                nonterminals = [
                    s for s in symbols if isinstance(s, NonTerminal)
                ]
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
        log.warning(
            "No sequences generated from grammar, falling back to simple API list"
        )
        # Fallback: just list all APIs from grammar terminals
        all_apis = []
        try:
            for symbol in grammar.symbols():
                if isinstance(
                        symbol,
                        Terminal) and symbol.name not in ('start', 'end', ''):
                    all_apis.append(symbol.name)
            if all_apis:
                # Create simple sequences of random API combinations
                for _ in range(min(num_sequences, 10)):
                    if len(all_apis) >= 2:
                        seq = random.sample(all_apis,
                                            min(max_len, len(all_apis)))
                        sequences.append(seq)
        except Exception as e:
            log.warning(f"Fallback sequence generation failed: {e}")

    log.debug(
        f"Generated {len(sequences)} sequences from grammar (requested {num_sequences})"
    )
    return sequences


def _synthesize_skeletons_per_sequence(
    generator,
    target_sequences: List[List[Any]],
    driver_size: int,
    benchmark: Any,
    log: logging.Logger,
    automaton_artifact: Optional[Any] = None,
    automaton_threshold: float = 0.6,
) -> List[Dict[str, Any]]:
    """
    For each L4-viable sequence, produce ONE Z3-validated skeleton with
    holes via ``CBFactory.create_skeleton_for_sequence``. This is the
    program-synthesis-precondition path that feeds the LLM prototyper
    refinement step (PromeFuzz-style scaffolding, not from-scratch
    generation).

    Returns a list of dicts shaped to be consumed by the prototyper:
        {'name', 'api_sequence', 'code', 'holes', 'synthesis_info'}

    Sequences that Z3 rejects are silently dropped — viability analysis
    decides, no numeric cap. Falls back to empty list on any unexpected
    failure (caller treats skeleton drivers as non-critical context).
    """
    if not target_sequences:
        return []

    # CBFactory needs the same prerequisites as in _generate_cbfactory_drivers.
    if (not generator.condition_manager
            or not generator.function_conditions
            or not generator.all_apis
            or not generator.dependency_graph):
        log.warning(
            "CBFactory prerequisites missing; cannot run Z3 skeleton synthesis "
            "(needs condition_manager, function_conditions, all_apis, dgraph).")
        return []

    from liberator_adapter.driver.factory.constraint_based import CBFactory
    from liberator_adapter.bias import Bias
    from liberator_adapter.driver.synthesis.skeleton_generator import render_skeleton

    available_conditions = set(generator.function_conditions.fun_cond_set.keys())
    filtered_apis = {
        api for api in generator.all_apis
        if api.function_name in available_conditions
    }
    if not filtered_apis:
        log.warning("No APIs have conditions available for skeleton synthesis")
        return []

    factory = CBFactory(
        api_list=filtered_apis,
        driver_size=driver_size,
        dgraph=generator.dependency_graph,
        conditions=generator.function_conditions,
        bias=Bias(),
        enable_z3_validation=True,
        automaton_artifact=automaton_artifact,
        automaton_threshold=automaton_threshold,
    )

    # ``target_path`` is no longer needed for renderer dispatch — the
    # generated skeleton always emits ``#ifdef __cplusplus`` extern "C"
    # guards (OSS-Fuzz drives clang++ on .c files too). Kept here only
    # for downstream telemetry that still references it.
    target_path = getattr(benchmark, 'target_path', '') or ''
    _ = target_path  # noqa: F841

    skeletons: List[Dict[str, Any]] = []
    z3_rejected = 0
    automaton_pruned = 0
    # When the CBFactory has an AutomatonAcceptanceGuard wired in, sequences
    # whose automaton acceptance_score < threshold are dropped BEFORE Z3
    # ever runs. We pre-compute the score per sequence so the helper can
    # report "X pruned by automaton, Y rejected by Z3" — without this
    # split the two failure modes are indistinguishable in logs.
    artifact_for_score = automaton_artifact if automaton_artifact is not None else None
    for i, target_seq in enumerate(target_sequences):
        try:
            if artifact_for_score is not None:
                try:
                    score = float(
                        artifact_for_score.acceptance_score(target_seq))
                    if score < float(automaton_threshold):
                        automaton_pruned += 1
                        log.debug(
                            "[skeleton-helper] automaton pruned seq %s "
                            "(score=%.3f < threshold=%.2f)",
                            [api.function_name for api in target_seq],
                            score, automaton_threshold)
                        continue
                except Exception:
                    # Score computation failed — fall through to Z3.
                    pass

            skeleton = factory.create_skeleton_for_sequence(target_seq)
            if skeleton is None:
                # Z3 rejected or skeleton infrastructure unavailable. The
                # CBFactory method already logs a precise reason. Note:
                # automaton-pruned sequences were already dropped above,
                # so this counter only reflects Z3 / SKELETON_AVAILABLE
                # failures.
                z3_rejected += 1
                continue

            try:
                rendered_code = render_skeleton(skeleton, mark_holes=True)
            except Exception:
                rendered_code = str(skeleton)

            api_seq = [api.function_name for api in skeleton.target_apis] \
                if skeleton.target_apis else []

            holes_info: List[Dict[str, Any]] = []
            if hasattr(skeleton, 'holes') and skeleton.holes:
                holes_dict = (skeleton.holes.holes
                              if hasattr(skeleton.holes, 'holes') else {})
                for hole in holes_dict.values():
                    holes_info.append({
                        'hole_type': (hole.kind.value
                                      if hasattr(hole.kind, 'value')
                                      else str(hole.kind)),
                        'name': hole.name,
                        'filled': hole.is_filled,
                    })

            skeletons.append({
                'name': f'cbfactory_skeleton_{i}',
                'api_sequence': api_seq,
                'code': rendered_code,
                'holes': holes_info,
                'synthesis_info': {
                    'method': 'CBFactory_skeleton_for_sequence',
                    'driver_size': driver_size,
                    'num_apis_used': len(api_seq),
                    'num_holes': len(holes_info),
                },
            })
        except Exception as e:
            # One bad sequence must not torpedo the whole batch.
            log.warning(
                f"Skeleton synthesis failed for sequence {i} "
                f"({[api.function_name for api in target_seq]}): {e}")

    total = len(target_sequences)
    if automaton_pruned or z3_rejected:
        log.info(
            f"   ⚠️ Skeleton synthesis attrition on {total} sequences: "
            f"automaton_pruned={automaton_pruned} (acceptance_score < "
            f"{automaton_threshold}), z3_rejected={z3_rejected} "
            f"(infeasible under type/lifecycle/provenance), "
            f"emitted={len(skeletons)}")
    return skeletons


def _generate_cbfactory_drivers(generator, num_drivers: int, driver_size: int,
                                project_name: str,
                                log: logging.Logger,
                                output_skeleton: bool = False,
                                automaton_artifact: Optional[Any] = None,
                                automaton_threshold: float = 0.6) -> List[Dict[str, Any]]:
    """
    Generate fuzz drivers using CBFactory (traditional program synthesis).

    This uses Liberator's constraint-based synthesis to generate drivers.
    When output_skeleton=True, generates DriverSkeletons with holes for LLM filling.
    When output_skeleton=False, generates complete compilable driver code.

    Args:
        generator: ProjectDriverGenerator instance (must have condition_manager initialized)
        num_drivers: Number of drivers to generate
        driver_size: Number of API calls per driver
        project_name: Project name (for logging)
        log: Logger instance
        output_skeleton: If True, return DriverSkeletons with holes instead of complete drivers

    Returns:
        List of synthesized driver dictionaries containing:
        - name: Driver name
        - code: Complete C/C++ driver source code (or skeleton code with hole placeholders)
        - api_sequence: List of API names called
        - synthesis_info: Metadata about the synthesis process
        - holes: List of hole definitions (only when output_skeleton=True)
    """
    from liberator_adapter.driver.factory.constraint_based import CBFactory
    from liberator_adapter.backend.libfuzz import LFBackendDriver
    from liberator_adapter.bias import Bias
    import tempfile
    import os

    synthesized_drivers: List[Dict[str, Any]] = []
    factory: Any = None  # bound below if synthesis reaches that far

    # Check prerequisites
    if not generator.condition_manager:
        log.warning(
            "ConditionManager not available - CBFactory requires LLVM extraction"
        )
        log.warning(
            "Ensure LLVM extraction is enabled (not --disable-llvm-extraction)"
        )
        return []

    if not generator.function_conditions:
        log.warning(
            "FunctionConditions not available - CBFactory requires conditions.json"
        )
        return []

    if not generator.all_apis:
        log.warning("No APIs available for synthesis")
        return []

    if not generator.dependency_graph:
        log.warning("Dependency graph not available")
        return []

    log.info(
        f"   🔧 CBFactory synthesis: {num_drivers} drivers, {driver_size} API calls each"
    )

    try:
        # Filter APIs to those with conditions
        available_conditions = set(
            generator.function_conditions.fun_cond_set.keys())
        filtered_apis = {
            api
            for api in generator.all_apis
            if api.function_name in available_conditions
        }

        if not filtered_apis:
            log.warning("No APIs have conditions available")
            return []

        log.debug(
            f"   Using {len(filtered_apis)}/{len(generator.all_apis)} APIs with conditions"
        )

        # Create CBFactory with Z3 validation enabled. Phase H: when an
        # automaton artifact is supplied, the Z3-guided controller installs
        # an AutomatonAcceptanceGuard that hard-prunes candidates whose
        # running-sequence acceptance falls below ``automaton_threshold``.
        bias = Bias()
        factory = CBFactory(
            api_list=filtered_apis,
            driver_size=driver_size,
            dgraph=generator.dependency_graph,
            conditions=generator.function_conditions,
            bias=bias,
            enable_z3_validation=True,  # Use Z3 to validate sequence feasibility
            automaton_artifact=automaton_artifact,
            automaton_threshold=automaton_threshold,
        )
        if automaton_artifact is not None and factory.z3_controller is not None:
            guard_stats_pre = factory.z3_controller.get_automaton_stats() or {}
            log.info(
                "   ⚙️  CBFactory automaton guard: strong=%s threshold=%.3f",
                guard_stats_pre.get('strong'),
                guard_stats_pre.get('threshold', automaton_threshold),
            )

        # Create temporary directory for rendering drivers
        with tempfile.TemporaryDirectory() as tmpdir:
            seeds_dir = os.path.join(tmpdir, 'seeds')
            os.makedirs(seeds_dir, exist_ok=True)

            # Setup the LFBackendDriver renderer. ``public_headers`` reads
            # from the canonical source — ProjectDriverGenerator records it
            # under ``extract_metadata['local']['public_headers']``. The
            # pre-2026-05 code read ``generator.public_headers_path``, an
            # attribute that has NEVER existed; the resulting None crashed
            # LFBackendDriver.__init__ on every run and the surrounding
            # try/except silently routed every CBFactory call to
            # ``_render_driver_fallback`` instead. Step 7's fail-fast
            # check now guarantees the path exists, so this construction
            # cannot legitimately fail — let it surface if it does.
            backend = None
            if hasattr(generator, 'headers_dir') and generator.headers_dir:
                local_meta = (
                    generator.extract_metadata.get('local', {})
                    if getattr(generator, 'extract_metadata', None)
                    else {}
                )
                public_headers_file = local_meta.get('public_headers')
                backend = LFBackendDriver(
                    working_dir=tmpdir,
                    seeds_dir=seeds_dir,
                    num_seeds=1,
                    headers_dir=generator.headers_dir,
                    public_headers=public_headers_file)

            # Generate drivers (skeleton mode or full driver mode)
            for i in range(num_drivers):
                try:
                    if output_skeleton:
                        # Skeleton mode: Generate skeleton with holes
                        skeleton = factory.create_random_driver_skeleton()
                        if skeleton is None:
                            log.warning(f"   Skeleton generation not available for driver {i+1}")
                            continue

                        # Use to_dict() for serialization
                        skeleton_dict = skeleton.to_dict()
                        skeleton_dict['name'] = f'cbfactory_skeleton_{i}'
                        skeleton_dict['synthesis_info'] = {
                            'method': 'template_based_synthesis',
                            'driver_size': driver_size,
                            'num_apis_used': len(skeleton_dict.get('api_sequence', [])),
                            'has_holes': len(skeleton_dict.get('holes', [])) > 0,
                            'num_holes': len(skeleton_dict.get('holes', [])),
                        }
                        synthesized_drivers.append(skeleton_dict)
                        log.debug(
                            f"   Generated skeleton {i+1}/{num_drivers}: "
                            f"{len(skeleton_dict.get('api_sequence', []))} APIs, "
                            f"{len(skeleton_dict.get('holes', []))} holes"
                        )
                    else:
                        # Full driver mode: Generate complete driver
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
                                driver_path = os.path.join(tmpdir,
                                                           f"{driver_name}.cc")
                                if os.path.exists(driver_path):
                                    with open(driver_path, 'r') as f:
                                        driver_code = f.read()
                                else:
                                    driver_code = _render_driver_fallback(
                                        driver_ir, project_name)
                            except Exception as e:
                                log.debug(
                                    f"Backend render failed: {e}, using fallback")
                                driver_code = _render_driver_fallback(
                                    driver_ir, project_name)
                        else:
                            driver_code = _render_driver_fallback(
                                driver_ir, project_name)

                        synthesized_drivers.append({
                            'name': f'cbfactory_driver_{i}',
                            'code': driver_code,
                            'api_sequence': api_sequence,
                            'synthesis_info': {
                                'method':
                                'CBFactory',
                                'driver_size':
                                driver_size,
                                'num_apis_used':
                                len(api_sequence),
                                'has_cleanup':
                                hasattr(driver_ir, 'clean_up')
                                and bool(driver_ir.clean_up),
                            }
                        })
                        log.debug(
                            f"   Generated driver {i+1}/{num_drivers}: {len(api_sequence)} API calls"
                        )

                except Exception as e:
                    log.warning(f"   Failed to generate driver {i+1}: {e}")
                    continue

    except Exception as e:
        log.error(f"CBFactory synthesis failed: {e}")
        import traceback
        log.debug(traceback.format_exc())

    # Phase H: post-synthesis automaton-guard telemetry. Surfaces how many
    # candidates were rejected by the acceptance gate so callers can size
    # the threshold and relax cadence empirically.
    if (automaton_artifact is not None
            and factory is not None
            and getattr(factory, 'z3_controller', None) is not None):
        try:
            stats = factory.z3_controller.get_automaton_stats()
            if stats:
                log.info(
                    "   📊 Automaton guard final: pruned=%d passed=%d "
                    "relaxes=%d threshold=%.3f",
                    stats.get('pruned', 0),
                    stats.get('passed', 0),
                    stats.get('relaxes', 0),
                    stats.get('threshold', automaton_threshold),
                )
        except Exception:
            pass  # Non-critical telemetry

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
    lines.append(
        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {"
    )
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


def save_intermediate_results(project_name: str,
                              results_dir: str,
                              dependency_graph: Dict[str, Any],
                              raw_sequences: List[List[str]],
                              filtered_sequences: List[List[str]],
                              pattern_analysis: Dict[str, Any],
                              project_apis: List[Dict[str, Any]],
                              grammar_info: Dict[str, Any],
                              condition_info: Dict[str, Any],
                              skeleton_drivers: List[Dict[str, Any]] = None,
                              log: logging.Logger = None) -> None:
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
            json.dump(
                {
                    'num_sequences':
                    len(raw_sequences),
                    'sequences': [{
                        'index': i,
                        'apis': seq,
                        'length': len(seq)
                    } for i, seq in enumerate(raw_sequences)]
                },
                f,
                indent=2)
        log.info(
            f"   📄 Saved raw sequences ({len(raw_sequences)}): {raw_seq_path}")

        # Save filtered sequences (after LLM filtering)
        filtered_seq_path = results_path / "filtered_sequences.json"
        with open(filtered_seq_path, 'w') as f:
            json.dump(
                {
                    'num_sequences':
                    len(filtered_sequences),
                    'sequences': [{
                        'index': i,
                        'apis': seq,
                        'length': len(seq)
                    } for i, seq in enumerate(filtered_sequences)]
                },
                f,
                indent=2)
        log.info(
            f"   📄 Saved filtered sequences ({len(filtered_sequences)}): {filtered_seq_path}"
        )

        # Save detailed LLM filter results (if available)
        llm_filter_info = grammar_info.get('llm_filter', {})
        if llm_filter_info and llm_filter_info.get(
                'mode') == 'llm_sequence_filter':
            filter_details_path = results_path / "llm_filter_details.json"
            with open(filter_details_path, 'w') as f:
                json.dump(
                    {
                        'filter_mode':
                        llm_filter_info.get('mode'),
                        'input_sequences':
                        llm_filter_info.get('input_sequences', 0),
                        'valid_sequences':
                        llm_filter_info.get('valid_sequences', 0),
                        'filter_stats':
                        llm_filter_info.get('filter_stats', {}),
                        'api_lifecycle_cache_size':
                        llm_filter_info.get('api_lifecycle_cache_size', 0),
                        'sequence_details':
                        llm_filter_info.get('details', [])
                    },
                    f,
                    indent=2)
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
            },
                      f,
                      indent=2)
        log.info(f"   📄 Saved project APIs ({len(project_apis)}): {apis_path}")

        # Save Z3-validated skeleton drivers (for cache loading) — this
        # lets cache hits skip Z3 synthesis on rerun, the slowest LLM-free
        # step.
        if skeleton_drivers:
            skeleton_path = results_path / "skeleton_drivers.json"
            with open(skeleton_path, 'w') as f:
                json.dump(skeleton_drivers, f, indent=2)
            log.info(
                f"   📄 Saved skeleton drivers ({len(skeleton_drivers)}): {skeleton_path}"
            )

        # Save combined summary
        summary_path = results_path / "analysis_summary.json"
        summary = {
            'project_name': project_name,
            'statistics': {
                'total_apis':
                len(project_apis),
                'dependency_graph_nodes':
                dependency_graph.get('num_nodes', 0),
                'raw_sequences':
                len(raw_sequences),
                'filtered_sequences':
                len(filtered_sequences),
                'filter_reduction':
                f"{(1 - len(filtered_sequences)/max(len(raw_sequences), 1))*100:.1f}%"
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
