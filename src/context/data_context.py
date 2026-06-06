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

    # === API Semantic Model (redesign G1) ===
    # Reconciled per-API role + arg semantics (IR ⊕ doc/naming ⊕ usage).
    # The full model is persisted to results/{project}/state/api_semantic_model.json;
    # here we carry only a lightweight summary + the role map (name → APIRole
    # value) the comprehender / downstream consumers read. {} when the build
    # was skipped or failed.
    api_semantic_model: Dict[str, Any] = field(default_factory=dict)

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
                # is decided by L0–L4 + the greedy itself, which already
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

        # Try to load from cache first. LOGICFUZZ_NO_CACHE=1 forces a fresh
        # prepare() so iterative changes to Step 5h (construct) / Step 10
        # (skeleton synthesis) actually take effect — the cache hit otherwise
        # restores api_sequences + skeletons and returns before those steps run.
        if use_cache and not os.environ.get('LOGICFUZZ_NO_CACHE'):
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

        # === Step 5f: L4 Coverage Ranking (Progressive Filter Pipeline) ===
        # L4: Rank sequences by automaton reachability + diversity + entry point.
        # (L5 novelty pre-filter was deleted in G3 — see CLAUDE.md "Failed
        # Attempts"; ranking is now reachability-first.)
        log.debug('  5f/12 Ranking sequences by coverage potential (L4)...')
        coverage_ranking_result = {}

        # Fetch the only OSS-Fuzz-specific input we still need: per-function
        # coverage from the cloud Fuzz Introspector. This is the single FI call
        # site in the project; everything else now uses local static analysis.
        existing_coverage = _fetch_oss_fuzz_function_coverage(project_name, log)

        # === Step 5e2: Learn project-adaptive automaton (P3) ===
        # Built from the project's own tests/examples via libclang AST walk;
        # produces a typestate automaton whose accepted language reflects how
        # the library is *actually* used in practice. Used by L4 below
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

            # Rank and select top-k sequences by automaton *reachability*
            # (G3 — L5 novelty pre-filter deleted; diversity demoted to a
            # tiebreak) + length-floor defensive guard when available.
            # NOTE: when G2 construction (Step 5h) is enabled, this ranks the
            # grammar candidates that Step 5h MERGES with the constructed
            # chains as a synthesizability floor (not replace — pure-replace
            # regressed lcms 1→0); the floor also covers when construction
            # yields nothing.
            pre_rank_count = len(api_sequences)
            # filter_top_k is a budget cap (default 10); greedy max-coverage
            # may stop earlier when no candidate adds new APIs (viability
            # self-termination at coverage_ranker.py:394).
            api_sequences, ranking_summary = select_top_k_sequences(
                api_sequences,
                entry_point_analysis=entry_point_analysis_result,
                top_k=filter_top_k,
                logger_instance=log,
                automaton_artifact=automaton_artifact,
                length_floor_safe_apis=length_floor_safe or None,
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

        # === Step 5g: Build APISemanticModel (redesign G1) ===
        # Fuse IR (mechanism) ⊕ doc/naming (intent) ⊕ usage (composition) into
        # one reconciled per-API model BEFORE construction. Deterministic-only
        # (no LLM — token-budget invariant). This model is the new role
        # authority, demoting ConditionManager (whose IR-only labels mislabel
        # e.g. lcms ``cmsFree*`` free-array out-pointers as CREATORs).
        api_semantic_model = None
        api_semantic_model_dict: Dict[str, Any] = {}
        _lc_pairs: List[Tuple[str, str]] = []   # bound for Step 5h even if 5g fails
        try:
            from liberator_adapter.analysis import reconcile as _reconcile_model

            # (init, destroy) pairs → IR KILL-edge wiring for the mechanism side.
            for _pair in (lifecycle_analysis_result.get('pairs') or []):
                if isinstance(_pair, dict):
                    _i = _pair.get('init') or _pair.get('init_api')
                    _d = _pair.get('destroy') or _pair.get('destroy_api')
                    if _i and _d:
                        _lc_pairs.append((_i, _d))

            # Structured doc signals (best-effort; the naming verb carries role
            # without them, which is the lcms case — no doxygen present).
            _doc_signals: Dict[str, Any] = {}
            try:
                _lmeta = (generator.extract_metadata.get('local', {})
                          if getattr(generator, 'extract_metadata', None) else {})
                _ph_file = _lmeta.get('public_headers')
                _ph_names: List[str] = []
                if _ph_file and os.path.exists(_ph_file):
                    with open(_ph_file, 'r') as _fh:
                        _ph_names = [ln.strip() for ln in _fh if ln.strip()]
                _hdr_dir = _lmeta.get('headers_dir') or _lmeta.get('source_dir')
                _all_api_names = [
                    a.get('function_name', '') for a in project_apis
                    if a.get('function_name')
                ]
                if _hdr_dir and _ph_names and _all_api_names:
                    from src.knowledge.project_docs import extract_doc_signals
                    _doc_signals = extract_doc_signals(
                        Path(_hdr_dir), _ph_names, _all_api_names)
            except Exception as _de:
                log.debug('  5g/12 structured doc-signal extraction skipped: %s', _de)

            _accept_paths = (
                automaton_artifact.sample_accepting_paths(n=16)
                if automaton_artifact is not None else None
            )

            # Typedef-handle recovery (root cause for void*-collapsed handles).
            # Liberator's extractor expands typedefs to their underlying type, so
            # an opaque handle (``typedef void* cmsHPROFILE``) collapses to
            # ``void*``/``i8*`` and the handle classifier drops every
            # produces/requires edge — the dependency graph for such a library is
            # empty (lcms: profiles/transforms/IT8 all void*), so no
            # creator→consumer→destroyer chain (e.g. open→cmsReadTag→close, the
            # cmstypes.c tag-deserializer coverage path) can be constructed.
            # Re-type the collapsed slots back to the typedef found in the public
            # headers + exported_functions before reconcile reads effects.
            # Safety: only UPGRADES void*/i8* to a non-primitive typedef; byte
            # buffers (declared ``const void*``) stay buffers. Disable with
            # LOGICFUZZ_DISABLE_TYPEDEF_RECOVERY=1.
            if not os.environ.get('LOGICFUZZ_DISABLE_TYPEDEF_RECOVERY'):
                try:
                    from liberator_adapter.analysis.handle_typedef_recovery \
                        import recover_from_extract_metadata
                    _n_up = recover_from_extract_metadata(
                        project_apis,
                        getattr(generator, 'extract_metadata', None))
                    if _n_up:
                        log.info('   5g/12 typedef-handle recovery: upgraded '
                                 '%d collapsed handle slots', _n_up)
                except Exception as _tre:
                    log.debug('   5g typedef-handle recovery skipped: %s', _tre)

            # Annotate args with the SVF per-arg write signal (conditions.json)
            # so the caller-alloc INIT producer channel (usedef) is SVF-gated: an
            # init-named single-pointer struct (``deflateInit_(z_stream*)``)
            # counts as PRODUCING the struct unless SVF positively saw it
            # read-only. Without this the deflate/inflate family's z_stream looks
            # unproduced and the whole family is unconstructable. Best-effort;
            # absent conditions → naming-only fallback.
            try:
                from liberator_adapter.analysis.usedef import annotate_svf_writes
                _cond_path = Path(f"./results/{project_name}/conditions.json")
                if _cond_path.exists():
                    with open(_cond_path) as _cf:
                        annotate_svf_writes(project_apis, json.load(_cf))
            except Exception as _ae:
                log.debug('   5g/12 SVF-write annotation skipped: %s', _ae)

            _reconcile_kwargs = dict(
                project=project_name,
                condition_info=condition_info,
                lifecycle_pairs=_lc_pairs or None,
                doc_signals=_doc_signals or None,
                accepting_paths=_accept_paths,
            )
            # Pass 1 — deterministic reconcile (IR ⊕ doc/naming ⊕ usage).
            api_semantic_model = _reconcile_model(project_apis, **_reconcile_kwargs)

            # Pass 2 — LLM role AUTHORITY over the uncertain residual only.
            # The deterministic model mis-roles the hard cases (CONSUMER vs
            # CREATOR siblings, a void* that is a fuzzer INPUT_BUFFER vs an
            # opaque handle). We hand the LLM exactly the APIs the rules are
            # unsure about (role UNKNOWN or confidence < the override floor),
            # classify them in one batched (cached) call, and re-reconcile —
            # reconcile() folds the LLM verdict in surgically (confident rule
            # roles still stand). Bounds LLM cost to the ambiguous subset and
            # leaves the certain structure to program analysis. Disable with
            # LOGICFUZZ_DISABLE_LLM_ROLES=1 (then it's the old deterministic
            # model, zero LLM).
            if not os.environ.get('LOGICFUZZ_DISABLE_LLM_ROLES'):
                _uncertain = [
                    n for n, s in api_semantic_model.apis.items()
                    if s.role.value == 'UNKNOWN' or s.role_confidence < 0.7
                ]
                if _uncertain:
                    try:
                        from src.knowledge import Comprehender
                        _comp = Comprehender(project_name)
                        _uset = set(_uncertain)

                        # (1) library purpose (cached; reused by Step 6b).
                        _role_purpose = _comp.comprehend_purpose(
                            library_name=project_name)

                        # (2) doxygen @brief/@param for each uncertain API.
                        _role_docs: Dict[str, str] = {}
                        for _n in _uncertain:
                            _sig = _doc_signals.get(_n) or {}
                            _brief = (_sig.get('brief') or '').strip()
                            if _brief:
                                _role_docs[_n] = _brief[:240]

                        # (3) real call neighbours from the automaton traces —
                        # composition evidence ("who creates it, what consumes
                        # its result") is what makes a role genuine.
                        _role_usage: Dict[str, List[str]] = {}
                        try:
                            _tp = Path(f"./results/{project_name}/automaton/traces.json")
                            _seqs: List[List[str]] = []
                            if _tp.exists():
                                with open(_tp) as _tf:
                                    _traw = json.load(_tf)
                                _traw = _traw if isinstance(_traw, list) else _traw.get('traces', [])
                                for _t in _traw:
                                    _seqs.append([c.get('api_name') for c in
                                                  (_t.get('api_calls') or [])
                                                  if c.get('api_name')])
                            for _p in _seqs:
                                for _i, _a in enumerate(_p):
                                    if _a in _uset and len(_role_usage.get(_a, [])) < 2:
                                        _lo, _hi = max(0, _i - 2), min(len(_p), _i + 3)
                                        _win = ' → '.join(
                                            (f'[{_x}]' if _x == _a else _x)
                                            for _x in _p[_lo:_hi])
                                        _role_usage.setdefault(_a, [])
                                        if _win not in _role_usage[_a]:
                                            _role_usage[_a].append(_win)
                        except Exception:
                            _role_usage = {}
                        _role_usage_s = {k: '; '.join(v) for k, v in _role_usage.items()}

                        # (4) deterministic verdict + conflicting claims, and the
                        # opaque-handle type catalogue (handle arg ≠ data buffer).
                        _role_verd: Dict[str, str] = {}
                        for _n in _uncertain:
                            _s = api_semantic_model.apis[_n]
                            _claims = '; '.join(
                                f'{_e.source}={_e.value}({_e.confidence:.2f})'
                                for _e in _s.evidence if _e.field == 'role')
                            _role_verd[_n] = (f'role={_s.role.value}@'
                                              f'{_s.role_confidence:.2f}'
                                              + (f' [{_claims}]' if _claims else ''))
                        _handle_types: set = set()
                        for _s in api_semantic_model.apis.values():
                            _handle_types |= set(_s.produces) | set(_s.requires) \
                                | set(_s.destroys)

                        _llm_roles = _comp.classify_roles(
                            api_names=_uncertain, project_apis=project_apis,
                            purpose=_role_purpose, api_docstrings=_role_docs,
                            usage_context=_role_usage_s, det_verdicts=_role_verd,
                            handle_types=_handle_types)
                        if _llm_roles:
                            api_semantic_model = _reconcile_model(
                                project_apis, **_reconcile_kwargs,
                                llm_roles=_llm_roles)
                            log.info(
                                '  5g/12 🧠 LLM role authority: classified %d '
                                'uncertain APIs (of %d total)',
                                len(_llm_roles), len(api_semantic_model.apis))
                    except Exception as _lre:
                        log.warning(
                            '  5g/12 LLM role classification skipped (%s); '
                            'deterministic-only', _lre)
            _asm_path = Path(f"./results/{project_name}/state/api_semantic_model.json")
            api_semantic_model.save(_asm_path)

            # Telemetry: how many IR roles doc/naming overrode — this count is
            # the band-aid (Phase A / F1) that the redesign deletes; it should
            # trend down as the model gets the role right up front.
            _ir_overrides = sum(
                1 for _s in api_semantic_model.apis.values()
                for _e in _s.evidence
                if _e.field == 'role' and not _e.won and _e.source == 'IR'
            )
            log.info(
                '  5g/12 ✅ APISemanticModel: %d APIs (%d creators, %d destroyers); '
                '%d IR-role overrides by doc/naming; doc_signals=%d',
                len(api_semantic_model.apis),
                len(api_semantic_model.creators()),
                len(api_semantic_model.destroyers()),
                _ir_overrides, len(_doc_signals),
            )
            api_semantic_model_dict = {
                'summary': {
                    'n_apis': len(api_semantic_model.apis),
                    'n_creators': len(api_semantic_model.creators()),
                    'n_destroyers': len(api_semantic_model.destroyers()),
                    'n_ir_overrides': _ir_overrides,
                    'n_doc_signals': len(_doc_signals),
                    'path': str(_asm_path),
                },
                'roles': {
                    n: s.role.value for n, s in api_semantic_model.apis.items()
                },
            }
        except Exception as _ae:
            log.warning('APISemanticModel build failed (non-critical): %s', _ae)
            api_semantic_model = None

        # === Step 5h: Construct sequences from the model (redesign G2) ===
        # Build dependency-resolved creator→mutator*→consumer→destroyer chains
        # from APISemanticModel — lifecycle-complete by construction. These are
        # PREPENDED to (not replacing) the L4-ranked grammar candidates, which
        # stay as a synthesizability floor: a constructed chain is
        # lifecycle-valid but may still fail CBFactory's finer type/provenance/
        # variable-binding checks (esp. APIs with unbindable non-handle args on
        # complex libs like lcms), whereas the grammar candidates are
        # L0-type-compatible and known-bindable. Merging avoids the regression
        # pure-replace caused (lcms 1→0 skeletons).
        #
        # We deliberately do NOT seed raw ``automaton.sample_accepting_paths``
        # as candidates: those are mid-stream trace *fragments* (a consumer with
        # no creator before it), so they fail CBFactory's lifecycle check — yet
        # they score acceptance≈1.0 and would crowd out the real constructed
        # chains under reachability ranking. The automaton's value is the
        # ranking SIGNAL (acceptance_score), not raw candidates.
        #
        # Disable for A/B via LOGICFUZZ_DISABLE_G2_CONSTRUCT=1.
        _disable_g2 = os.environ.get(
            'LOGICFUZZ_DISABLE_G2_CONSTRUCT', '0'
        ).lower() in ('1', 'true', 'yes')
        if api_semantic_model is not None and not _disable_g2:
            try:
                from liberator_adapter.analysis import (
                    construct_sequences, compute_gap_apis)
                # G5: coverage-gap signal — APIs the OSS-Fuzz baseline does NOT
                # cover. Direct construction + ranking TOWARD them so we add
                # NEW lines instead of re-covering the baseline (the §10B
                # line_diff=0 problem). On lcms the baseline touches 5/297 APIs,
                # so the gap is ~98% of the surface.
                _all_api_names = [a.get('function_name', '') for a in project_apis
                                  if a.get('function_name')]
                _gap_apis = compute_gap_apis(
                    _all_api_names, project=project_name,
                    existing_coverage=existing_coverage or None)
                # Top-down WORKFLOW backbone: the automaton's accepting paths
                # are real usage compositions from the library's own tests
                # (e.g. lcms profile→transform→dotransform) — domain knowledge
                # bottom-up type-walking can't infer. graft_fn completes
                # mid-stream fragments. construct_mode=merged (offline-validated
                # best: workflow depth + bottom-up breadth + gap), so the
                # automaton AUGMENTS rather than replaces (it's only a test
                # subset; workflow-only loses most APIs). Self-filtered by the
                # Typestate oracle (project_apis + lifecycle pairs).
                # Workflow backbone = RAW per-test traces, NOT
                # sample_accepting_paths. Each raw trace is one test function's
                # actual call sequence (clean single-purpose workflow, e.g.
                # cmsCreateXYZProfile→cmsCreateTransform→cmsDoTransform→cleanup);
                # sample_accepting_paths random-walks the MERGED automaton and
                # blends many tests into noisy mixed chains. Offline-validated:
                # raw traces surface 5 clean transform workflows on lcms; random
                # walks surfaced none clean. Fall back to sampled paths if the
                # traces file is absent.
                _accept = None
                if automaton_artifact is not None:
                    _accept = []
                    _tpath = Path(f"./results/{project_name}/automaton/traces.json")
                    if _tpath.exists():
                        try:
                            with open(_tpath) as _tf:
                                _tr = json.load(_tf)
                            _tr = _tr if isinstance(_tr, list) else _tr.get('traces', [])
                            for _t in _tr:
                                _names = [c.get('api_name')
                                          for c in (_t.get('api_calls') or [])
                                          if c.get('api_name')]
                                if len(_names) >= 2:
                                    _accept.append(_names)
                        except Exception:
                            _accept = []
                    if not _accept:
                        _accept = automaton_artifact.sample_accepting_paths(n=40)
                _graft = (automaton_artifact.graft_creator_prefix
                          if automaton_artifact is not None else None)
                _cmode = os.environ.get('LOGICFUZZ_CONSTRUCT_MODE', 'merged')
                _cres = construct_sequences(
                    api_semantic_model,
                    project_apis=project_apis,
                    lifecycle_pairs=_lc_pairs or None,
                    gap_apis=_gap_apis or None,
                    accepting_paths=_accept,
                    graft_fn=_graft,
                    construct_mode=_cmode)
                _constructed = _cres.sequences
                # Provenance set for the Step 10 cap: which constructed
                # sequences are workflow-backbone (real per-test compositions).
                # The cap gives these their own tier so the focused transform
                # workflow isn't ranked below longer generic builder chains.
                _workflow_seq_set = {tuple(s) for s in _cres.workflow_sequences}
                if _constructed:
                    # The Z3 trial pool must carry BOTH novelty and feasibility,
                    # or it regresses: gap APIs (novel) are often exactly the
                    # ones CBFactory can't bind (lcms void*/struct args), so
                    # ranking gap-first ALONE starves the synthesizable
                    # candidates out of the budget → 0 skeletons emitted
                    # (observed: lcms 5→0). We therefore build the pool from
                    # THREE strands, deduped, so Z3 always gets feasible options:
                    #   (a) gap-first  — novelty toward baseline-uncovered code
                    #   (b) acceptance-first — automaton-validated ⇒ likely Z3-feasible
                    #   (c) grammar floor — L0-type-valid safety net
                    # Step 10 then emits one skeleton per Z3-viable sequence and
                    # keeps the top-K (gap-leading) — so feasible+novel wins,
                    # feasible-only fills the rest, and we never drop to 0.
                    _acc = (automaton_artifact.acceptance_score
                            if automaton_artifact is not None else (lambda s: 0.0))
                    def _acc_of(seq, _a=_acc):
                        try:
                            return float(_a(seq))
                        except Exception:
                            return 0.0
                    def _gap_hits(seq, _g=_gap_apis):
                        return sum(1 for a in seq if a in _g) if _g else 0
                    # Buffer-consuming entry points (parsers) are the coverage
                    # goldmines: a single ``cmsOpenProfileFromMem(data,size)``
                    # drives the fuzzer bytes through thousands of lines of ICC
                    # parsing, whereas a 3-gap-API MLU chain covers a handful.
                    # Gap-COUNT ranking alone buried the parsers (1 gap hit) under
                    # multi-gap shallow chains, so we add a top-priority strand:
                    # any sequence whose entry is a top-level parser.
                    #
                    # A parser ENTRY is a CREATOR/CONSUMER decoder that takes the
                    # fuzzer byte buffer (INPUT_BUFFER) — bytes in, handle/result
                    # out (cmsOpenProfileFromMem, cmsIT8LoadFromMem). Role is now
                    # LLM-authoritative (Step 5g), so this clean role check
                    # correctly excludes a buffer-taking MUTATOR (cmsWriteRawTag
                    # writes into an already-open profile) — which is ubiquitous
                    # among gap-targeted sequences and, if mistaken for an entry,
                    # made this FIRST unbounded strand swallow the whole budget.
                    _buffer_entry_apis = {
                        n for n, s in api_semantic_model.apis.items()
                        if s.role.value in ('CREATOR', 'CONSUMER')
                        and any(a.role.value == 'INPUT_BUFFER' for a in s.args)
                    }
                    def _has_buffer_entry(seq, _b=_buffer_entry_apis):
                        return any(a in _b for a in seq)
                    _buffer_ranked = sorted(
                        [s for s in _constructed if _has_buffer_entry(s)],
                        key=lambda s: (_gap_hits(s), _acc_of(s), -len(s)),
                        reverse=True)
                    _gap_ranked = sorted(
                        _constructed, key=lambda s: (_gap_hits(s), _acc_of(s)),
                        reverse=True)
                    _acc_ranked = sorted(_constructed, key=_acc_of, reverse=True)
                    # Protected WORKFLOW strand (top-down): the real per-test
                    # usage compositions (profile→transform→dotransform), ranked
                    # focused-first (4..12 APIs) so the high-value transform
                    # workflow isn't buried by gap-COUNT ranking — which rewards
                    # long multi-API breadth and otherwise crowds the focused
                    # workflows out of the budget entirely (lcms: 0 DoTransform
                    # workflows survived without this strand).
                    _wf_ranked = sorted(
                        _cres.workflow_sequences,
                        key=lambda s: (0 if 4 <= len(s) <= 12 else 1,
                                       -_gap_hits(s)))
                    _grammar_candidates = list(api_sequences)
                    _budget = max(filter_top_k * 4, 40) if filter_top_k else (
                        len(_constructed) + len(_grammar_candidates))
                    _k = filter_top_k or 12
                    # Strand order = priority: parser entries first (deepest
                    # coverage per call), then the protected workflow backbone,
                    # then gap-novelty, automaton-feasible, and the grammar
                    # floor. Step 10's top-K cap keeps parser entries + focused
                    # workflows; the rest provide breadth + a floor.
                    _seen2: set = set()
                    _merged: List[List[str]] = []
                    for _seq in (_buffer_ranked + _wf_ranked[:_k]
                                 + _gap_ranked[:_k]
                                 + _acc_ranked[:_k] + _grammar_candidates
                                 + _gap_ranked):
                        _key = tuple(_seq)
                        if _key and _key not in _seen2:
                            _seen2.add(_key)
                            _merged.append(_seq)
                        if len(_merged) >= _budget:
                            break

                    # #2 SUBSYSTEM BALANCE (opt-in: LOGICFUZZ_SUBSYS_BALANCE=1,
                    # default OFF). The rank strands above (gap/acceptance/focus)
                    # cluster on the same dense API families, so whole subsystems
                    # (c-ares dns_write/query/dns_record, nghttp2 submit/sfparse)
                    # never reach the budget pool — measured: only 21-42 of
                    # 138-429 project APIs entered the pool, and the missed
                    # families exactly matched the coverage_diff HUMAN_NEW gap.
                    # Reserve the last third of the budget for a PARAMETER-FREE
                    # greedy max-new-API pass: repeatedly take the constructed
                    # sequence adding the most not-yet-pooled APIs (ties: fewer
                    # total = more focused). Widens API/subsystem coverage of the
                    # pool without removing the quality leaders (they fill the
                    # first two thirds). Default off → existing results unchanged.
                    if os.environ.get('LOGICFUZZ_SUBSYS_BALANCE'):
                        _reserve = max(1, _budget // 3)
                        _qkeep = _merged[:max(0, _budget - _reserve)]
                        _kept_keys = {tuple(s) for s in _qkeep}
                        _pooled = {a for s in _qkeep for a in s}
                        _rest = [s for s in _constructed
                                 if tuple(s) not in _kept_keys]
                        _greedy: List[List[str]] = []
                        while _rest and len(_qkeep) + len(_greedy) < _budget:
                            _bi, _bg, _bl = -1, 0, 10**9
                            for _ix, _s in enumerate(_rest):
                                _g = len(set(_s) - _pooled)
                                if _g > _bg or (_g == _bg and len(_s) < _bl):
                                    _bi, _bg, _bl = _ix, _g, len(_s)
                            if _bi < 0 or _bg <= 0:
                                break
                            _chosen = _rest.pop(_bi)
                            _greedy.append(_chosen)
                            _pooled.update(_chosen)
                        _merged = _qkeep + _greedy
                        log.info(
                            '   🧩 subsystem-balance: %d quality + %d breadth '
                            '(greedy max-new-API) → pool covers %d APIs',
                            len(_qkeep), len(_greedy), len(_pooled))

                    api_sequences = _merged
                    grammar_info.setdefault('g2_construction', {})
                    grammar_info['g2_construction']['buffer_entry_seqs'] = len(_buffer_ranked)
                    grammar_info['num_sequences'] = len(api_sequences)
                    grammar_info['g2_construction'] = {
                        **_cres.metrics,
                        'selected': len(api_sequences),
                        'grammar_floor': len(_grammar_candidates),
                        'z3_budget': _budget,
                    }
                    log.info(
                        '  5h/12 ✅ G2 construct-from-model: %d constructed '
                        'merged with %d grammar floor → '
                        '%d candidates to Z3 (gap+reachability-ranked, budget=%d); '
                        'G5 gap: reached %d/%d baseline-uncovered APIs',
                        _cres.metrics['n_sequences'],
                        len(_grammar_candidates), len(api_sequences), _budget,
                        _cres.metrics.get('gap_apis_reached', 0),
                        _cres.metrics.get('gap_apis_total', 0),
                    )
                else:
                    log.info('  5h/12 G2 construct produced 0 sequences; '
                             'keeping grammar candidates')
            except Exception as _ge:
                log.warning('G2 construction failed (non-critical): %s', _ge)

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
                        # libclang doxygen walk needs a HOST-side directory
                        # containing the headers. Probe in priority order:
                        # explicit ``headers_dir`` from metadata → the host
                        # source dir fetched from the OSS-Fuzz image →
                        # ``generator.headers_dir`` attribute (rare/none).
                        # ``generator.headers_dir`` is never set as an
                        # instance attribute on ProjectDriverGenerator —
                        # the var lives only as a local inside
                        # ``_ensure_sources`` — so the getattr fallback is
                        # primarily for documentation, not production.
                        headers_dir = (
                            local_meta.get('headers_dir')
                            or local_meta.get('source_dir')
                            or getattr(generator, 'headers_dir', None)
                        )
                        if headers_dir and public_header_names and unique_apis_in_sequences:
                            from src.knowledge.project_docs import extract_doxygen_comments
                            api_docstrings = extract_doxygen_comments(
                                headers_dir=Path(headers_dir),
                                public_headers=public_header_names,
                                api_names=unique_apis_in_sequences,
                            )
                        else:
                            # Surface the skip path so silent empty results
                            # in docs_priors.json don't look like "doxygen
                            # ran and found nothing" when it didn't run at all.
                            log.warning(
                                'Doxygen extraction skipped: headers_dir=%s, '
                                'public_header_names=%d entries, '
                                'unique_apis_in_sequences=%d',
                                headers_dir if headers_dir else 'None',
                                len(public_header_names),
                                len(unique_apis_in_sequences),
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
                # G1: APISemanticModel role is the authority (demotes
                # ConditionManager's IR-only role inside the comprehender).
                api_roles=(
                    api_semantic_model_dict.get('roles')
                    if api_semantic_model_dict else None
                ),
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

        # Host-side directory where ``project_headers`` actually live.
        # The headers in ``public_headers.txt`` are bare basenames
        # (e.g. ``cJSON.h``); downstream consumers (UnifiedCodeValidator
        # libclang walk, LFBackendDriver) need a directory to put on the
        # -I include path. Source-of-truth is the same
        # ``extract_metadata['local']['source_dir']`` that ``_ensure_sources``
        # records when it fetches source from the OSS-Fuzz container.
        source_dir = None
        if (hasattr(generator, 'extract_metadata')
                and generator.extract_metadata):
            local_meta_for_src = generator.extract_metadata.get('local', {}) or {}
            source_dir = local_meta_for_src.get('source_dir')

        header_info = {
            'standard_headers':
            ['<stddef.h>', '<stdint.h>', '<stdlib.h>', '<string.h>'],
            'project_headers': public_headers,
            'include_dirs': [source_dir] if source_dir else [],
        }
        log.info(
            f"   ✅ Loaded {len(public_headers)} project headers from "
            f"{public_headers_path}"
            + (f" (-I {source_dir})" if source_dir else "")
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

            # Phase D — Path-aware Planner. Read Phase B idioms (run
            # distillation early; deterministic, no token cost) and
            # rerank / synthesise candidates. Idiom-aligned candidates
            # come first → graft + Z3 get the strongest signal first;
            # CONTEXT_NULL_PASS-implicated APIs missing from L4 get a
            # synthesised entry that downstream LLM can flesh out.
            #
            # ``planner_idioms_payload`` is defined here (not inside the try)
            # so it's always bound for the Planner call below even if the
            # distillation setup fails.
            planner_idioms_payload: Optional[Dict[str, Any]] = None
            try:
                # F3 (2026-05-23): Step 10 owns the canonical idiom
                # distillation pass — it loads driver sources, distills
                # once, AND persists ``state/idioms.json``. Step 12 then
                # receives the dict via ``precomputed_idioms=`` and
                # skips the redundant re-distill.
                from src.knowledge.idiom_distiller import distill_and_persist
                from src.state.path_planner import plan_and_persist
                early_root = _resolve_drivers_root(project_name)
                if early_root is not None:
                    early_files = _iter_driver_source_files(early_root)
                    early_sources = []
                    for p in early_files:
                        try:
                            early_sources.append({
                                'path': str(p),
                                'source': p.read_text(
                                    encoding='utf-8', errors='ignore'),
                            })
                        except OSError:
                            continue
                    if early_sources:
                        early_lib = distill_and_persist(
                            project_name, early_sources)
                        planner_idioms_payload = early_lib.to_dict()
                # Plan: rerank + maybe synthesise.
                seqs_as_names = [
                    [a.function_name for a in s] for s in filtered_api_sequences]
                project_api_names = {a.function_name for a in generator.all_apis}
                planned_names, _ledger = plan_and_persist(
                    project=project_name,
                    target_sequences=seqs_as_names,
                    idioms_payload=planner_idioms_payload,
                    project_api_names=project_api_names,
                )
                # Translate back to Api objects, preserving the planner's
                # ordering and appending any synthesised one-element
                # sequences that resolve to known APIs.
                name_to_api = {a.function_name: a for a in generator.all_apis}
                planned_api_sequences: List[List[Any]] = []
                for names in planned_names:
                    apis = [name_to_api[n] for n in names if n in name_to_api]
                    if apis:
                        planned_api_sequences.append(apis)
                if planned_api_sequences:
                    filtered_api_sequences = planned_api_sequences
                    log.info(
                        f'   🧭 Planner: {len(planned_api_sequences)} candidates '
                        f'(rerank+synthesis applied)')
            except Exception as exc:
                log.warning(
                    f"Path-aware planner failed (non-critical, falling back "
                    f"to L4 order): {exc}")

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
                # === Divide-and-conquer driver PORTFOLIO (round-robin) ===
                # We union K drivers, so we deliberately fund BOTH strategies
                # instead of ranking one above the other (which starved the
                # other — 27 workflow seqs filled all 10 slots). Three buckets,
                # drawn round-robin so the union always carries each:
                #   A parser-input    : fuzzer bytes → a CREATOR/CONSUMER decoder
                #                       (cmsOpenProfileFromMem). Deepest parse
                #                       coverage per call.
                #   B exploit-workflow: a real per-test trace workflow OR a
                #                       synthesized lifecycle-complete pseudo-
                #                       workflow (creator→…→destroyer). Mirrors
                #                       how the library is actually used — and
                #                       the pseudo-workflows fill this role even
                #                       when the project has NO tests (don't
                #                       over-rely on traces).
                #   C explore-novel   : everything else non-trivial — reach the
                #                       API combinations the tests never exercise
                #                       (the unexplored region, which is exactly
                #                       where the marginal coverage is).
                # Empty buckets (no tests + no lifecycle pairs ⇒ B empty)
                # redistribute their slots automatically. Role classification is
                # now LLM-authoritative (Step 5g), so a clean role check replaces
                # the old requires/LENGTH heuristics: a MUTATOR that writes a
                # buffer into an open handle is no longer mistaken for a parser.
                if api_semantic_model is not None:
                    _entry_apis = {
                        n for n, s in api_semantic_model.apis.items()
                        if s.role.value in ('CREATOR', 'CONSUMER')
                        and any(a.role.value == 'INPUT_BUFFER' for a in s.args)
                    }
                    _creator_apis = set(api_semantic_model.creators())
                    _destroyer_apis = set(api_semantic_model.destroyers())
                    _wf_set = locals().get('_workflow_seq_set') or set()

                    def _focus(seq):
                        return abs(len(seq) - 6)   # 4-7 API focused workflows win

                    def _is_pseudo_workflow(seq):
                        # lifecycle-complete composed usage: open→…→close,
                        # substantive — a synthesized stand-in for a real
                        # workflow when the project ships no tests.
                        return (4 <= len(seq) <= 12
                                and any(a in _creator_apis for a in seq)
                                and any(a in _destroyer_apis for a in seq))

                    _bA: List[Dict[str, Any]] = []   # parser-input
                    _bB: List[Dict[str, Any]] = []   # exploit-workflow
                    _bC: List[Dict[str, Any]] = []   # explore-novel
                    for d in skeleton_drivers:
                        seq = d.get('api_sequence') or []
                        if _entry_apis and any(a in _entry_apis for a in seq):
                            _bA.append(d)
                        elif tuple(seq) in _wf_set or _is_pseudo_workflow(seq):
                            _bB.append(d)
                        else:
                            _bC.append(d)
                    for _b in (_bA, _bB, _bC):
                        _b.sort(key=lambda d: _focus(d.get('api_sequence') or []))

                    _cap = filter_top_k or len(skeleton_drivers)
                    _buckets = [_bA, _bB, _bC]
                    _used = [[False] * len(_b) for _b in _buckets]
                    _portfolio: List[Dict[str, Any]] = []

                    # #2 SUBSYSTEM BALANCE at the cap (opt-in): prefer the next
                    # driver that introduces an unseen API-family, so the kept-K
                    # spread across subsystems instead of piling onto the
                    # dominant one. Family = first two '_'-tokens (nghttp2_submit_*
                    # → "nghttp2_submit"; ares_dns_write → "ares_dns"; ares_parse_*
                    # → "ares_parse") — a deterministic name proxy that matched
                    # the measured missed families. Default OFF.
                    _balance = bool(os.environ.get('LOGICFUZZ_SUBSYS_BALANCE'))

                    def _fam(api):
                        _t = (api or '').split('_')
                        return '_'.join(_t[:2]) if len(_t) >= 2 else (api or '')

                    def _fams(d):
                        return {_fam(a) for a in (d.get('api_sequence') or [])}
                    _seen_fams: set = set()

                    def _pick_from(_b, _u):
                        if _balance:
                            for _i, _d in enumerate(_b):
                                if not _u[_i] and (_fams(_d) - _seen_fams):
                                    return _i
                        for _i, _d in enumerate(_b):
                            if not _u[_i]:
                                return _i
                        return -1

                    while len(_portfolio) < _cap:
                        _moved = False
                        for _j, _b in enumerate(_buckets):
                            _i = _pick_from(_b, _used[_j])
                            if _i >= 0:
                                _portfolio.append(_b[_i])
                                _used[_j][_i] = True
                                _seen_fams |= _fams(_b[_i])
                                _moved = True
                                if len(_portfolio) >= _cap:
                                    break
                        if not _moved:
                            break
                    log.info(
                        '   🎯 portfolio (round-robin%s): %d parser + %d workflow '
                        '+ %d novel available → kept %d of %d (%d families)',
                        ', subsys-balanced' if _balance else '',
                        len(_bA), len(_bB), len(_bC), len(_portfolio),
                        len(skeleton_drivers), len(_seen_fams))
                    skeleton_drivers = _portfolio
                elif filter_top_k and len(skeleton_drivers) > filter_top_k:
                    # No semantic model → fall back to a plain top-K cap.
                    skeleton_drivers = skeleton_drivers[:filter_top_k]
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

        # === Step 10b: Semantic value-intent on holes (redesign G4) ===
        # Attach per-arg value intent (in-range/out-of-range for scalars,
        # structured-input for parser buffers, length-pairing, output, live
        # handle) derived from APISemanticModel, so the Prototyper fills holes
        # with intent — not just a type. Deterministic; no LLM.
        if skeleton_drivers and api_semantic_model is not None:
            try:
                from liberator_adapter.analysis import annotate_skeletons
                # T2: named-constant vocabulary from the public headers, so enum
                # CONFIG args get their exact legal constant set (e.g. lcms
                # cmsColorSpaceSignature, zlib Z_*) instead of a blind range.
                _const_vocab = _build_constant_vocabulary(project_name, log)
                _n_annot = annotate_skeletons(
                    skeleton_drivers, api_semantic_model, _const_vocab)
                log.info('  10b/12 ✅ G4 value-intent: %d/%d skeletons annotated'
                         ' (%d enum families)',
                         _n_annot, len(skeleton_drivers),
                         len((_const_vocab or {}).get('enums', {})))
            except Exception as _he:
                log.warning('G4 hole annotation failed (non-critical): %s', _he)

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
                max_drivers=3,
                # F3 (2026-05-23): pass Step 10's distilled idioms so
                # Step 12 doesn't redo the work; if Step 10 didn't run
                # (planner_idioms_payload still None) Step 12 distills
                # fresh.
                precomputed_idioms=planner_idioms_payload)
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
                   api_semantic_model=api_semantic_model_dict,
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
            'api_semantic_model': self.api_semantic_model,
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

    # Span the maximal LEADING comment region: contiguous blank / ``//`` /
    # ``/* ... */`` lines before the first real code line. A license header is a
    # multi-line comment that often opens with a decorative divider
    # (``//------``) or blank ``//`` lines carrying no keyword — the old
    # line-by-line keyword gate broke on those and stripped nothing (lcms's
    # ``//----`` header survived verbatim). We instead consume the whole leading
    # comment block, then strip it ONLY if a license keyword appears anywhere in
    # it — so a genuine leading doc comment with no license text is preserved.
    region_end = 0          # first index that is real code
    in_block_comment = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if in_block_comment:
            region_end = i + 1
            if '*/' in stripped:
                in_block_comment = False
                # block may close and reopen / be followed by code on same line
                if stripped.endswith('*/'):
                    continue
            continue
        if not stripped:
            region_end = i + 1
            continue
        if stripped.startswith('/*'):
            in_block_comment = '*/' not in stripped
            region_end = i + 1
            continue
        if stripped.startswith('//'):
            region_end = i + 1
            continue
        break   # first non-blank, non-comment line → real code

    header = '\n'.join(lines[:region_end]).lower()
    is_license = any(kw in header for kw in (
        'copyright', 'license', 'permission', 'redistribution', 'disclaimer',
        'warranty', 'use of this source', 'spdx', 'apache', '(c)', 'all rights',
    ))
    if not is_license:
        return source.lstrip('\n')
    return '\n'.join(lines[region_end:]).lstrip('\n')


def _build_constant_vocabulary(project_name: str, log) -> Dict[str, Any]:
    """T2: extract the named-constant vocabulary (true enums + prefix-grouped
    #defines) from the project's public headers, for enum CONFIG value-intents.

    Best-effort: resolves public-header basenames against the cached source
    tree by glob; returns ``{}`` on any failure (the caller falls back to the
    generic range hint).
    """
    import glob as _glob
    from liberator_adapter.analysis.named_constants import extract_constant_vocabulary
    try:
        ph_file = Path(f'./results/{project_name}/public_headers.txt')
        names = []
        if ph_file.exists():
            names = [ln.strip() for ln in ph_file.read_text().splitlines() if ln.strip()]
        roots = [f'./results/{project_name}/src_ossfuzz', f'./results/{project_name}']
        paths = []
        for nm in names:
            base = os.path.basename(nm)
            for root in roots:
                hits = _glob.glob(os.path.join(root, '**', base), recursive=True)
                if hits:
                    paths.append(hits[0])
                    break
        if not paths:
            return {}
        return extract_constant_vocabulary(paths)
    except Exception as exc:
        log.debug('   10b constant-vocabulary build skipped: %s', exc)
        return {}


def _extract_existing_driver_knowledge(project_name: str,
                                       log: logging.Logger,
                                       llm_client: Any = None,
                                       max_drivers: int = 3,
                                       precomputed_idioms: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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

    # Load ALL driver files for Phase B distillation (deterministic
    # regex, no token cost). The Prototyper-facing
    # ``driver_sources`` and ``analysis`` paths still cap at
    # ``max_drivers`` to keep LLM prompt size bounded — those
    # consume tokens proportional to source length. lcms has 15
    # baseline drivers but only 3 land in the Prototyper prompt; we
    # don't want to throw away the other 12 drivers' idiom signal.
    all_driver_sources: List[Dict[str, str]] = []
    for path in driver_files:
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError as e:
            log.debug("Skipping driver %s: %s", path, e)
            continue
        # Strip the license/copyright header at the single point where driver
        # sources are loaded, so EVERY downstream consumer (Prototyper
        # <reference_drivers>, pattern analyzer, idiom distiller) sees clean
        # code — not the ~15-line Apache/Google boilerplate that is pure prompt
        # noise and burns tokens. Robust block-/line-comment strip; idempotent.
        all_driver_sources.append(
            {'path': str(path), 'source': _strip_license_header(text)})

    # The Prototyper-facing slice is bounded by ``max_drivers``.
    driver_sources = all_driver_sources[:max_drivers]

    log.info(
        "   📚 Loaded %d existing driver(s) for Prototyper context "
        "(%d total available for distillation) from %s",
        len(driver_sources), len(all_driver_sources), root,
    )

    analysis: Optional[Dict[str, str]] = None
    if llm_client is not None and driver_sources:
        try:
            analysis = _analyze_driver_patterns(
                driver_sources, project_name, llm_client, log)
        except Exception as e:
            log.warning(f"LLM pattern analysis failed (non-critical): {e}")
            analysis = None

    # Phase B — Synthesis Distillation. Run on the FULL driver set so
    # libraries with many baseline drivers (lcms: 15) yield rich idiom
    # libraries instead of being capped at the LLM-prompt budget.
    #
    # F3 (2026-05-23): if Step 10 already distilled idioms for the
    # Planner, reuse them rather than re-running the same regex pass.
    # The Step 10 distillation also persists idioms.json, so this
    # function can skip both the compute and the write.
    idiom_library_dict: Optional[Dict[str, Any]] = precomputed_idioms
    if idiom_library_dict is None and all_driver_sources:
        try:
            from src.knowledge.idiom_distiller import distill_and_persist
            idiom_library = distill_and_persist(project_name, all_driver_sources)
            idiom_library_dict = idiom_library.to_dict()
        except Exception as exc:
            log.warning(
                f"Idiom distillation failed for {project_name} "
                f"(non-critical): {exc}")
    elif idiom_library_dict is not None:
        log.debug(
            "Reusing precomputed idioms for %s (Phase B F3 dedupe): "
            "%d idioms", project_name,
            idiom_library_dict.get('idiom_count', 0))

    return {
        'driver_sources': driver_sources,
        'analysis': analysis,
        'idioms': idiom_library_dict,
    }


def _analyze_driver_patterns(driver_sources: List[Dict[str, str]],
                             project_name: str, llm_client: Any,
                             log: logging.Logger) -> Dict[str, str]:
    """
    Analyze existing drivers to extract reusable patterns using XML tag format.

    Returns dict with 'core_functionality', 'setup_teardown', and 'code_patterns' keys.
    """
    from src.utils.prompt_loader import load_prompt_file
    from src.agents.utils import parse_tag

    # Driver sources are already license-stripped at load time
    # (_extract_existing_driver_knowledge), so this is a plain format.
    drivers_text = ""
    for i, d in enumerate(driver_sources[:5]):
        drivers_text += f"\n=== Driver {i+1}: {d['path']} ===\n{d['source']}\n"

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
    For each viable sequence, produce ONE Z3-validated skeleton with holes
    via ``CBFactory.create_skeleton_for_sequence``. This is the
    program-synthesis-precondition path that feeds the LLM prototyper
    refinement step (PromeFuzz-style scaffolding, not from-scratch
    generation).

    G2 note: sequences now arrive *constructed from the APISemanticModel*
    (Step 5h) — lifecycle-complete by construction — so the old Phase A
    repair engine (graft / patched-sequence retry on CBFactory rejection)
    was removed: a rejection here is now a genuine type/var infeasibility,
    not a fixable lifecycle mislabel. Z3 rejections are dropped, no cap.

    Returns a list of dicts shaped to be consumed by the prototyper:
        {'name', 'api_sequence', 'code', 'holes', 'synthesis_info'}

    Sequences that Z3 rejects are silently dropped — viability analysis
    decides, no numeric cap. Falls back to empty list on any unexpected
    failure (caller treats skeleton drivers as non-critical context).
    """
    if not target_sequences:
        return []

    # The TRULY required prerequisites for emitting a skeleton are api_list +
    # dgraph (CBFactory's ``create_skeleton_unchecked`` only needs those plus a
    # SkeletonGenerator). condition_manager / function_conditions drive the Z3-
    # validated path (``create_skeleton_for_sequence``); when LLVM extraction
    # falls back to clang-only (observed on nghttp2 + liblouis 2026-05-29) those
    # conditions come in empty. Previously that hit ``return []`` and the whole
    # portfolio collapsed to 1 LLM-only trial — Bug #6, ~5500 lines lost across
    # those two projects per coverage_diff. Degrade gracefully: build CBFactory
    # with an empty conditions set and force the unchecked render path.
    if not generator.all_apis or not generator.dependency_graph:
        log.warning(
            "Skeleton synthesis impossible: missing all_apis or dependency_graph.")
        return []

    _degraded = (not generator.condition_manager
                 or not generator.function_conditions)

    from liberator_adapter.driver.factory.constraint_based import CBFactory
    from liberator_adapter.bias import Bias
    from liberator_adapter.common.conditions import FunctionConditionsSet
    from liberator_adapter.driver.synthesis.skeleton_generator import render_skeleton

    if _degraded:
        log.warning(
            "CBFactory degraded mode: function_conditions empty (LLVM "
            "extraction likely fell back to clang-only). Z3 validation off; "
            "skeletons via the model-unchecked render path. Without this we "
            "would emit 0 skeletons → 1 LLM-only trial → lost portfolio.")
        filtered_apis = set(generator.all_apis)
        conditions_arg = FunctionConditionsSet()
    else:
        available_conditions = set(
            generator.function_conditions.fun_cond_set.keys())
        filtered_apis = {
            api for api in generator.all_apis
            if api.function_name in available_conditions
        }
        conditions_arg = generator.function_conditions
        if not filtered_apis:
            log.warning("No APIs have conditions available for skeleton synthesis")
            return []

    try:
        factory = CBFactory(
            api_list=filtered_apis,
            driver_size=driver_size,
            dgraph=generator.dependency_graph,
            conditions=conditions_arg,
            bias=Bias(),
            enable_z3_validation=not _degraded,
            enable_z3_guidance=not _degraded,
            automaton_artifact=automaton_artifact,
            automaton_threshold=automaton_threshold,
        )
    except (AttributeError, KeyError, RuntimeError) as exc:
        # CBFactory's __init__ touches ``ConditionManager.instance()`` for
        # things like ``source_api``; in degraded environments where the
        # singleton wasn't fully populated (or in tests with synthetic
        # generators) the construction can fail with AttributeError. Degrade
        # further to []. In real runs Step 5b ensures the singleton is set up.
        log.warning("CBFactory construction failed (%s: %s); skipping "
                    "skeleton synthesis.", type(exc).__name__, exc)
        return []

    # ``target_path`` is no longer needed for renderer dispatch — the
    # generated skeleton always emits ``#ifdef __cplusplus`` extern "C"
    # guards (OSS-Fuzz drives clang++ on .c files too). Kept here only
    # for downstream telemetry that still references it.
    target_path = getattr(benchmark, 'target_path', '') or ''
    _ = target_path  # noqa: F841

    skeletons: List[Dict[str, Any]] = []
    z3_rejected = 0
    unchecked_emitted = 0   # skeletons rendered via the no-Z3-gate model path
    automaton_low_score = 0
    _z3_mode = os.environ.get('LOGICFUZZ_Z3_MODE', 'soft').lower()
    if _degraded:
        # No function_conditions → Z3 has nothing to validate against; go
        # straight to the model-unchecked render path for every sequence.
        _z3_mode = 'off'
    # **Positive-only automaton signal** (2026-05-12 redesign): the
    # acceptance_score is computed for telemetry but is NOT used to
    # reject candidates. Rationale: the project automaton is trained
    # from a finite test corpus and represents a *subset* of valid
    # library usage. A sequence not present in the automaton is not
    # necessarily invalid — it may be a novel-but-correct combination
    # that the project's tests just don't exercise. Hard-rejecting on
    # "not seen" starved cjson / c-ares / lcms uniformly (10/10 prune
    # on all three benches; see docs/automaton_refactor §3 + §4 calibration
    # finding). Real infeasibility (type / lifecycle / provenance) is
    # left to Z3 below, which has actual semantic grounds for rejection.
    #
    # The score is still useful as: (a) a positive-only L4 ranking boost
    # (already wired in coverage_ranker.py), (b) a Comprehender-B prefilter
    # for fast-path VALID labeling, and (c) telemetry here to track how
    # many candidates would have been filtered under the old policy —
    # useful for re-evaluating whether to ever re-enable rejection.
    artifact_for_score = automaton_artifact if automaton_artifact is not None else None
    for i, target_seq in enumerate(target_sequences):
        try:
            if artifact_for_score is not None:
                try:
                    score = float(
                        artifact_for_score.acceptance_score(target_seq))
                    if score < float(automaton_threshold):
                        # Telemetry only — do not skip. The candidate proceeds
                        # to CBFactory + Z3 like any other.
                        automaton_low_score += 1
                        log.debug(
                            "[skeleton-helper] low automaton score (informational) "
                            "for seq %s: score=%.3f < threshold=%.2f",
                            [api.function_name for api in target_seq],
                            score, automaton_threshold)
                except Exception:
                    # Score computation failed — treat as unscored; forward
                    # the candidate unchanged.
                    pass

            # Z3 role is a tunable knob (LOGICFUZZ_Z3_MODE), being A/B'd from
            # coverage feedback because Z3 has a history of FALSE rejections
            # (void*/config/nullable args have no producer ⇒ it judges UNSAT
            # though they're valid). The one true hard gate is lifecycle
            # ORDERING — and that's enforced upstream by the Typestate
            # self-filter, not here. Modes:
            #   gate  : legacy — Z3 reject drops the sequence.
            #   off   : skip Z3 entirely; render via the model path.
            #   soft  : try Z3 (its pass = a quality signal, tagged); on reject,
            #           render anyway via the model path (don't drop). [default]
            skeleton = None
            z3_passed = False
            if _z3_mode in ('gate', 'soft', 'selective'):
                skeleton = factory.create_skeleton_for_sequence(target_seq)
                z3_passed = skeleton is not None
            if skeleton is None and _z3_mode != 'gate':
                # Render without the prove-or-reject gate: wire handle args to
                # prior producers (symbolic), leave scalars/buffers/void* as
                # holes for the LLM. Recovers candidates Z3 falsely rejects.
                skeleton = factory.create_skeleton_unchecked(target_seq)
                if skeleton is not None:
                    unchecked_emitted += 1
            if skeleton is None:
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
                    'method': ('CBFactory_z3' if z3_passed
                               else 'model_unchecked'),
                    'z3_passed': z3_passed,
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
    log.info(
        f"   📊 Skeleton synthesis on {total} sequences: "
        f"automaton_low_score={automaton_low_score} (informational), "
        f"z3_rejected={z3_rejected} (truly unrenderable), "
        f"emitted={len(skeletons)} (of which {unchecked_emitted} via the "
        f"no-Z3-gate model path = recovered gap candidates)")

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
