#!/usr/bin/env python3
"""
Project-level Driver Generator

Based on Liberator's static modeling capabilities, generates drivers for entire projects
without needing to specify individual APIs.

Features:
1. Extract all APIs from the project
2. Generate type dependency graph
3. Generate semantic sequences (Grammar)
4. Manage constraint conditions (ConditionManager)
5. Generate driver code
"""
import logging
import os
import subprocess
from typing import Dict, List, Set, Optional
from pathlib import Path

from liberator_adapter.adapter import LiberatorAPIAdapter
from liberator_adapter.dependency import DependencyGraph, TypeDependencyGraphGenerator
from liberator_adapter.grammar import GrammarGenerator, NonTerminal, Terminal, Grammar
from liberator_adapter.constraints import ConditionManager
from liberator_adapter.common import Api, FunctionConditionsSet, DataLayout
from liberator_adapter.common.utils import Utils
from liberator_adapter.driver import Driver
from liberator_adapter.driver.factory import Factory
# OTFactory has been removed - only CBFactory is supported now
# from liberator_adapter.driver.factory.only_type import OTFactory
from liberator_adapter.driver.factory.constraint_based import CBFactory
from liberator_adapter.bias import Bias
from liberator_adapter.backend.libfuzz import LFBackendDriver
from liberator_adapter.driver.driver_enhancer import DriverEnhancer, APIPatternCache

# FuzzIntrospector header lookup removed; public headers are discovered locally.

# Hybrid synthesis module
from liberator_adapter.driver.synthesis import (
    SkeletonGenerator,
    SkeletonRenderer,
    DriverSkeleton,
    HoleFiller,
    ConstraintCollector,
    render_skeleton,
    fill_skeleton_holes,
)

logger = logging.getLogger(__name__)


class ProjectDriverGenerator:
    """
    Project-level Driver Generator
    
    Uses Liberator's complete static modeling capabilities:
    - Type system: Type dependency graph
    - Semantic sequences: Grammar generator
    - Constraint management: ConditionManager
    """
    
    def __init__(
        self,
        project_name: str,
        benchmark=None,
        work_dir: Optional[str] = None
    ):
        """
        Initialize project-level driver generator

        Args:
            project_name: Project name
            benchmark: Benchmark object (required for Clang/LLVM extraction)
            work_dir: Working directory (for storing generated drivers)
        """
        self.project_name = project_name
        self.work_dir = Path(work_dir) if work_dir else Path(f"./results/{project_name}")
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self.adapter = LiberatorAPIAdapter(
            project_name=project_name,
            benchmark=benchmark
        )
        
        # Components (lazy initialization)
        self.all_apis: Set[Api] = set()
        self.dependency_graph: Optional[DependencyGraph] = None
        self.grammar = None
        self.condition_manager: Optional[ConditionManager] = None
        self.function_conditions: Optional[FunctionConditionsSet] = None
        self.extract_metadata: Dict = {}

        # Special pattern analysis enhancer
        self.driver_enhancer: Optional[DriverEnhancer] = None
        self.pattern_cache: Optional[APIPatternCache] = None

        logger.info(f"✅ ProjectDriverGenerator initialized for {project_name}")
    
    def extract_all_apis(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Set[Api]:
        """
        Extract all APIs from the project
        
        Args:
            function_signatures: List of function signatures to extract (optional, None means extract all)
            include_dir: Header file directory
            public_headers_file: Public header file list
            bc_file: Bitcode file path
            compile_project: Whether to compile the project
        
        Returns:
            API set
        """
        logger.info(f"📦 Extracting all APIs for project {self.project_name}...")

        # Auto-fetch source from OSS-Fuzz style docker image if paths are not provided
        include_dir, public_headers_file = self._ensure_sources(
            include_dir=include_dir,
            public_headers_file=public_headers_file
        )
        
        # Use adapter to extract all APIs
        apis_dict = self.adapter.extract_all_apis(
            function_signatures=function_signatures,
            include_dir=include_dir,
            public_headers_file=public_headers_file,
            bc_file=bc_file,
            compile_project=compile_project
        )
        # Save extraction metadata (e.g., apis_llvm/conditions/data_layout paths)
        try:
            self.extract_metadata = getattr(self.adapter, "last_metadata", {}) or {}
        except Exception:
            self.extract_metadata = {}
        
        self.all_apis = set(apis_dict.values())
        logger.info(f"✅ Extracted {len(self.all_apis)} APIs")
        
        return self.all_apis
    
    def build_dependency_graph(
        self,
        function_conditions: Optional[FunctionConditionsSet] = None,
        enable_provenance_filter: bool = True,
        enable_z3_pruning: bool = False
    ) -> DependencyGraph:
        """
        Build type dependency graph

        Args:
            function_conditions: Function constraint condition set (optional, for provenance filtering)
            enable_provenance_filter: Whether to enable provenance filtering (default True)
            enable_z3_pruning: Whether to enable Z3 constraint pruning (requires z3-solver)

        Returns:
            Type dependency graph
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")

        logger.info("🔗 Building type dependency graph...")
        if enable_z3_pruning:
            logger.info("   Z3 constraint pruning: enabled")

        # If provenance filtering enabled but no conditions provided, try to load
        if enable_provenance_filter and function_conditions is None:
            conditions_file = None
            apis_llvm_file = None
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                conditions_file = local_meta.get("conditions")
                apis_llvm_file = local_meta.get("apis_llvm")
            if conditions_file and apis_llvm_file:
                try:
                    function_conditions = Utils.prase_function_conditions(conditions_file, apis_llvm_file)
                    logger.info(f"✅ Loaded function conditions for provenance filtering")
                except Exception as e:
                    logger.warning(f"Failed to load conditions for provenance filtering: {e}")
                    logger.warning("Continuing with provenance filter disabled")
                    enable_provenance_filter = False

        # Use TypeDependencyGraphGenerator to generate dependency graph
        dep_gen = TypeDependencyGraphGenerator(
            list(self.all_apis),
            function_conditions=function_conditions,
            enable_provenance_filter=enable_provenance_filter,
            enable_z3_pruning=enable_z3_pruning
        )
        self.dependency_graph = dep_gen.create()

        logger.info(f"✅ Dependency graph built: {len(self.dependency_graph.graph)} nodes")

        return self.dependency_graph
    
    def build_grammar(self) -> Grammar:
        """
        Generate grammar rules (semantic sequences) from dependency graph
        
        Returns:
            Grammar object
        """
        if not self.dependency_graph:
            raise RuntimeError("No dependency graph. Call build_dependency_graph() first.")
        
        logger.info("📝 Generating grammar from dependency graph...")
        
        # Create grammar generator
        start_term = NonTerminal("start")
        end_term = Terminal("end")
        grammar_gen = GrammarGenerator(start_term, end_term)
        
        # Generate grammar from dependency graph
        self.grammar = grammar_gen.create(self.dependency_graph)
        
        logger.info(f"✅ Grammar generated: {self.grammar.num_symbols()} symbols")
        
        return self.grammar
    
    def build_condition_manager(
        self,
        function_conditions: Optional[FunctionConditionsSet] = None
    ) -> ConditionManager:
        """
        Build constraint manager
        
        Args:
            function_conditions: Function constraint condition set (optional, creates empty if None)
        
        Returns:
            ConditionManager instance
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")
        
        logger.info("🔒 Building condition manager...")
        
        # If no constraint conditions provided, try to parse from extracted conditions.json
        if function_conditions is None:
            parsed = None
            conditions_file = None
            apis_llvm_file = None
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                conditions_file = local_meta.get("conditions")
                apis_llvm_file = local_meta.get("apis_llvm")
            if conditions_file and apis_llvm_file:
                try:
                    parsed = Utils.prase_function_conditions(conditions_file, apis_llvm_file)
                    logger.info(f"✅ Parsed function conditions from {conditions_file}")
                except Exception as e:
                    logger.warning(f"Failed to parse function conditions ({conditions_file}): {e}")
            function_conditions = parsed or FunctionConditionsSet()
            if parsed is None:
                logger.warning("No function conditions provided, using empty set")
        
        self.function_conditions = function_conditions
        
        # Get ConditionManager instance and setup
        condition_manager = ConditionManager.instance()
        condition_manager.setup(
            api_list=self.all_apis,
            api_list_all=self.all_apis,  # Use the same API list
            conditions=function_conditions
        )
        
        self.condition_manager = condition_manager
        
        logger.info("✅ Condition manager built")
        logger.info(f"   - Source APIs: {len(condition_manager.get_source_api())}")
        logger.info(f"   - Sink APIs: {len(condition_manager.get_sink_api())}")
        logger.info(f"   - Init APIs: {len(condition_manager.get_init_api())}")
        
        return condition_manager
    
    def analyze_special_patterns(self, llm_client=None) -> APIPatternCache:
        """
        Analyze special patterns of APIs (VarLen, Loop, Callback, TLV)

        Args:
            llm_client: LLM client (optional, for Phase 2 semantic validation)

        Returns:
            APIPatternCache: Analysis result cache
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")

        logger.info("🔍 Analyzing special patterns for APIs...")

        # Create enhancer
        self.driver_enhancer = DriverEnhancer(llm_client)

        # Analyze all APIs
        self.driver_enhancer.analyze_apis(list(self.all_apis))

        # Save cache
        self.pattern_cache = self.driver_enhancer.cache

        # Print summary
        summary = self.driver_enhancer.get_enhancement_summary()
        logger.info(f"✅ Special pattern analysis complete:")
        logger.info(f"   - APIs with var-len: {summary['apis_with_varlen']}")
        logger.info(f"   - APIs needing loop: {summary['apis_needing_loop']}")
        logger.info(f"   - APIs with callbacks: {summary['apis_with_callbacks']}")
        logger.info(f"   - Structured parsers: {summary['structured_parsers']}")

        return self.pattern_cache

    # =========================================================================
    # Hybrid Synthesis Methods
    # =========================================================================

    def generate_skeleton_drivers(
        self,
        api_sequences: Optional[List[List[Api]]] = None,
        num_drivers: int = 10,
        driver_size: int = 5,
        llm_client=None
    ) -> List[DriverSkeleton]:
        """
        Generate driver skeletons using hybrid synthesis

        Hybrid synthesis process:
        1. Generate API sequences (using Grammar or given sequences)
        2. Generate skeleton (with Holes) for each sequence
        3. Fill simple Holes with rules/constraints
        4. Fill complex Holes with LLM

        Args:
            api_sequences: Predefined API sequences (optional, auto-generate if None)
            num_drivers: Number of drivers to generate
            driver_size: Number of API calls per driver
            llm_client: LLM client (for complex Hole filling)

        Returns:
            List of DriverSkeleton
        """
        if not self.all_apis:
            raise RuntimeError("No APIs extracted. Call extract_all_apis() first.")

        logger.info(f"🔧 Generating {num_drivers} skeleton drivers (hybrid synthesis)...")

        # Prepare special pattern information
        varlen_relations = {}
        loop_patterns = {}
        callback_infos = {}

        if self.pattern_cache:
            # Convert to format required by SkeletonGenerator
            for api_name, relations in self.pattern_cache.varlen_relations.items():
                varlen_relations[api_name] = [
                    (r.buffer_arg_idx, r.length_arg_idx, r.relationship)
                    for r in relations
                ]

            for api_name, loop_info in self.pattern_cache.loop_patterns.items():
                loop_patterns[api_name] = {
                    'needs_loop': loop_info.needs_loop,
                    'loop_type': loop_info.loop_type.value if loop_info.loop_type else None,
                    'termination_condition': loop_info.termination_condition,
                    'max_iterations': loop_info.max_iterations,
                }

            for api_name, cbs in self.pattern_cache.callback_infos.items():
                callback_infos[api_name] = [
                    {
                        'arg_idx': cb.arg_idx,
                        'callback_type': cb.callback_type.value if cb.callback_type else None,
                        'stub_code': cb.stub_code,
                    }
                    for cb in cbs
                ]

        # Generate or use API sequences
        if api_sequences is None:
            api_sequences = self._generate_api_sequences(num_drivers, driver_size)

        # Determine if C++ project (for FuzzedDataProvider include)
        is_cpp = True  # Default to C++ (safer, includes FuzzedDataProvider)
        if self.adapter and self.adapter.benchmark:
            is_cpp = self.adapter.benchmark.is_cpp_project

        # Create skeleton generator and filler
        skeleton_generator = SkeletonGenerator()
        hole_filler = HoleFiller(llm_client=llm_client)

        skeletons = []
        for i, sequence in enumerate(api_sequences[:num_drivers]):
            try:
                # 1. Generate skeleton
                skeleton = skeleton_generator.generate(
                    api_sequence=sequence,
                    varlen_relations=varlen_relations,
                    loop_patterns=loop_patterns,
                    callback_infos=callback_infos,
                    driver_name=f"fuzz_driver_{i}",
                    is_cpp=is_cpp
                )

                # 2. Fill Holes
                report = hole_filler.fill_all(skeleton)

                logger.debug(
                    f"Driver {i}: {len(sequence)} APIs, "
                    f"{report.filled_count}/{report.total_holes} holes filled"
                )

                skeletons.append(skeleton)

            except Exception as e:
                logger.warning(f"Failed to generate skeleton driver {i}: {e}")

        logger.info(f"✅ Generated {len(skeletons)} skeleton drivers")

        return skeletons

    def render_skeleton_to_code(
        self,
        skeleton: DriverSkeleton,
        mark_holes: bool = False,
        is_cpp_target: bool = True
    ) -> str:
        """
        Render skeleton to C/C++ code

        Args:
            skeleton: Driver skeleton
            mark_holes: Whether to mark unfilled Holes in code
            is_cpp_target: If True, use 'extern "C"' for C++ fuzz target.
                          If False, emit pure C code (no extern "C").

        Returns:
            C/C++ code string
        """
        renderer = SkeletonRenderer()
        if mark_holes:
            return renderer.render_with_holes_marked(skeleton, is_cpp_target=is_cpp_target)
        return renderer.render(skeleton, is_cpp_target=is_cpp_target)

    def save_skeleton_drivers(
        self,
        skeletons: List[DriverSkeleton],
        output_dir: Optional[str] = None
    ) -> List[str]:
        """
        Save skeleton drivers to files

        Args:
            skeletons: List of DriverSkeleton
            output_dir: Output directory

        Returns:
            List of saved file paths
        """
        if output_dir is None:
            out_path = self.work_dir / "skeleton_drivers"
        else:
            out_path = Path(output_dir)

        out_path.mkdir(parents=True, exist_ok=True)

        saved_files = []
        for skeleton in skeletons:
            code = self.render_skeleton_to_code(skeleton)

            # Check if there are unfilled Holes
            unfilled = skeleton.get_unfilled_holes()
            if unfilled:
                logger.warning(
                    f"Driver {skeleton.name} has {len(unfilled)} unfilled holes"
                )
                # Still save, but add comment marker
                code = f"// WARNING: {len(unfilled)} holes not filled\n" + code

            file_path = out_path / f"{skeleton.name}.cc"
            with open(file_path, 'w') as f:
                f.write(code)

            saved_files.append(str(file_path))
            logger.debug(f"Saved: {file_path}")

        logger.info(f"✅ Saved {len(saved_files)} skeleton drivers to {out_path}")

        return saved_files

    def _generate_api_sequences(
        self,
        num_sequences: int,
        sequence_size: int
    ) -> List[List[Api]]:
        """
        Generate API sequences (using Grammar or simple strategy), supports loop pattern awareness

        Args:
            num_sequences: Number of sequences
            sequence_size: Length of each sequence

        Returns:
            List of API sequences
        """
        import random
        sequences = []

        # Get list of APIs that need loops (from pattern_cache)
        loop_apis = self._get_loop_apis()

        if self.grammar:
            # Use Grammar to generate sequences
            for _ in range(num_sequences):
                try:
                    # Sample a sequence from Grammar
                    sequence = self._sample_sequence_from_grammar(sequence_size)
                    if sequence:
                        # Apply loop pattern enhancement
                        sequence = self._apply_loop_patterns(sequence, loop_apis)
                        sequences.append(sequence)
                except Exception as e:
                    logger.debug(f"Failed to sample from grammar: {e}")

        # If Grammar unavailable or insufficient generation, use simple strategy
        while len(sequences) < num_sequences:
            # Simple strategy: randomly select APIs to form sequence
            api_list = list(self.all_apis)
            if len(api_list) >= sequence_size:
                sequence = random.sample(api_list, sequence_size)
            else:
                sequence = random.choices(api_list, k=sequence_size)

            # Apply loop pattern enhancement
            sequence = self._apply_loop_patterns(sequence, loop_apis)
            sequences.append(sequence)

        return sequences

    def _get_loop_apis(self) -> Dict[str, dict]:
        """
        Get API information that needs loop calls from pattern_cache

        Returns:
            Dict[api_name, loop_info]: APIs that need loops and their loop information
        """
        loop_apis = {}

        if self.pattern_cache:
            for api_name, loop_info in self.pattern_cache.loop_patterns.items():
                if loop_info.needs_loop:
                    loop_apis[api_name] = {
                        'loop_type': loop_info.loop_type.value if loop_info.loop_type else 'iterator',
                        'max_iterations': loop_info.max_iterations or 3,
                        'termination_condition': loop_info.termination_condition,
                    }

        return loop_apis

    def _apply_loop_patterns(
        self,
        sequence: List[Api],
        loop_apis: Dict[str, dict]
    ) -> List[Api]:
        """
        Apply loop patterns to APIs in sequence that need loops

        If an API in the sequence is identified as needing loop calls (e.g., iterator, incremental read),
        repeat that API multiple times in the sequence to simulate loop behavior.

        Args:
            sequence: Original API sequence
            loop_apis: APIs that need loops and their loop information

        Returns:
            Enhanced API sequence
        """
        if not loop_apis:
            return sequence

        enhanced_sequence = []

        for api in sequence:
            api_name = api.function_name

            if api_name in loop_apis:
                loop_info = loop_apis[api_name]
                loop_type = loop_info.get('loop_type', 'iterator')
                max_iterations = loop_info.get('max_iterations', 3)

                # Determine repeat count based on loop type
                # - iterator: Usually needs multiple calls until returns NULL or termination condition
                # - incremental: Incremental read/write, needs multiple calls
                # - state_machine: State machine driven, until termination state reached
                if loop_type == 'iterator':
                    repeat_count = min(max_iterations, 3)  # Iterator mode: repeat 2-3 times
                elif loop_type == 'incremental':
                    repeat_count = min(max_iterations, 4)  # Incremental mode: repeat 3-4 times
                elif loop_type == 'state_machine':
                    repeat_count = min(max_iterations, 5)  # State machine: repeat more times
                else:
                    repeat_count = 2  # Default: repeat 2 times

                # Add repeated calls
                for _ in range(repeat_count):
                    enhanced_sequence.append(api)

                logger.debug(
                    f"Applied loop pattern for {api_name}: "
                    f"{loop_type}, repeated {repeat_count} times"
                )
            else:
                enhanced_sequence.append(api)

        return enhanced_sequence

    def _sample_sequence_from_grammar(self, max_size: int) -> List[Api]:
        """Sample an API sequence from Grammar"""
        if not self.grammar:
            return []

        # Simple sampling implementation
        # TODO: Use smarter sampling strategy
        sequence = []
        visited = set()

        # Find start rule
        start = self.grammar.start
        if hasattr(start, 'rules') and start.rules:
            import random
            # Randomly traverse rules
            for _ in range(max_size * 2):  # Allow some attempts
                if len(sequence) >= max_size:
                    break

                # Randomly select a reachable API
                for rule in start.rules:
                    if hasattr(rule, 'rhs') and rule.rhs:
                        for symbol in rule.rhs:
                            if hasattr(symbol, 'token') and symbol.token not in visited:
                                # Find corresponding API
                                for api in self.all_apis:
                                    if api.function_name == symbol.token:
                                        sequence.append(api)
                                        visited.add(symbol.token)
                                        break

        return sequence

    def build_data_layout(
        self,
        apis_clang_path: Optional[str] = None,
        apis_llvm_path: Optional[str] = None,
        incomplete_types_path: Optional[str] = None,
        data_layout_path: Optional[str] = None,
        enum_types_path: Optional[str] = None
    ):
        """
        Initialize DataLayout (type layout information)
        
        Args:
            apis_clang_path: Clang API file path
            apis_llvm_path: LLVM API file path
            incomplete_types_path: Incomplete types list path
            data_layout_path: Data layout file path
            enum_types_path: Enum types list path
        """
        logger.info("📊 Building data layout...")
        
        data_layout = DataLayout.instance()
        
        # If paths provided, setup DataLayout
        if all([apis_clang_path, apis_llvm_path, incomplete_types_path, 
                data_layout_path, enum_types_path]):
            data_layout.setup(
                apis_clang_p=apis_clang_path,
                apis_llvm_p=apis_llvm_path,
                incomplete_types_p=incomplete_types_path,
                data_layout_p=data_layout_path,
                enum_types_p=enum_types_path
            )
            logger.info("✅ Data layout initialized from files")
        # Try to auto-configure using extraction metadata
        elif self.extract_metadata:
            local_meta = self.extract_metadata.get("local", {})
            ac = local_meta.get("apis_clang")
            al = local_meta.get("apis_llvm")
            inc = local_meta.get("incomplete_types")
            dl = local_meta.get("data_layout")
            # Use parameter if provided, otherwise get from metadata
            et = enum_types_path or local_meta.get("enum_types")
            if all([ac, al, inc, dl, et]):
                data_layout.setup(
                    apis_clang_p=ac,
                    apis_llvm_p=al,
                    incomplete_types_p=inc,
                    data_layout_p=dl,
                    enum_types_p=et
                )
                logger.info("✅ Data layout initialized from extraction metadata")
            else:
                logger.warning("Data layout files not provided (metadata incomplete), using default")
        else:
            logger.warning("Data layout files not provided, using default")
    
    def generate_drivers(
        self,
        num_drivers: int = 10,
        driver_size: int = 5,
        enable_z3_validation: bool = True
    ) -> List[Driver]:
        """
        Generate driver list using CBFactory (constraint-based synthesis).

        Note: OTFactory (only_type) has been removed. Only CBFactory is supported.

        Args:
            num_drivers: Number of drivers to generate
            driver_size: Number of API calls in each driver
            enable_z3_validation: Whether to enable Z3 sequence validation

        Returns:
            List of Drivers
        """
        if not self.grammar:
            raise RuntimeError("No grammar. Call build_grammar() first.")

        logger.info(f"🚀 Generating {num_drivers} drivers (size={driver_size}, policy=constraint_based)...")
        if enable_z3_validation:
            logger.info("   Z3 sequence validation: enabled")

        drivers = []

        # Use CBFactory (constraint-based) - OTFactory has been removed
        factory = self._create_cb_factory(driver_size, enable_z3_validation)

        # Generate drivers
        for i in range(num_drivers):
            try:
                driver = factory.create_random_driver()
                drivers.append(driver)
                logger.debug(f"Generated driver {i+1}/{num_drivers}")
            except Exception as e:
                logger.warning(f"Failed to generate driver {i+1}: {e}")

        logger.info(f"✅ Generated {len(drivers)} drivers")

        return drivers
    
    def generate_all(
        self,
        num_drivers: int = 10,
        driver_size: int = 5,
        function_conditions: Optional[FunctionConditionsSet] = None,
        analyze_patterns: bool = True,
        llm_client=None,
        enable_z3_validation: bool = True,
        **extract_kwargs
    ) -> List[Driver]:
        """
        Complete generation pipeline: Extract API -> Build dependency graph -> Generate grammar -> Manage constraints -> Analyze patterns -> Generate drivers

        Note: Uses CBFactory (constraint-based) for driver generation. OTFactory has been removed.

        Args:
            num_drivers: Number of drivers to generate
            driver_size: Number of API calls in each driver
            function_conditions: Function constraint conditions (optional)
            analyze_patterns: Whether to analyze special patterns (VarLen/Loop/Callback/TLV)
            llm_client: LLM client (for Phase 2 analysis of special patterns)
            enable_z3_validation: Whether to enable Z3 sequence validation
            **extract_kwargs: Arguments passed to extract_all_apis

        Returns:
            List of Drivers
        """
        logger.info("🎯 Starting complete driver generation pipeline...")

        # 1. Extract all APIs
        self.extract_all_apis(**extract_kwargs)

        # 2. Build dependency graph
        self.build_dependency_graph()

        # 3. Generate grammar
        self.build_grammar()

        # 4. Build constraint manager
        self.build_condition_manager(function_conditions)

        # 5. Analyze special patterns (optional)
        if analyze_patterns:
            self.analyze_special_patterns(llm_client)

        # 6. Generate drivers using CBFactory
        drivers = self.generate_drivers(
            num_drivers=num_drivers,
            driver_size=driver_size,
            enable_z3_validation=enable_z3_validation
        )

        logger.info("✅ Complete pipeline finished")

        return drivers
    
    def _create_cb_factory(self, driver_size: int, enable_z3_validation: bool = True):
        """
        Create CBFactory (constraint_based policy)

        Args:
            driver_size: Number of API calls in driver
            enable_z3_validation: Whether to enable Z3 sequence validation
        """
        if not self.dependency_graph:
            raise RuntimeError("No dependency graph available for CBFactory")
        if not self.all_apis:
            raise RuntimeError("No APIs available for CBFactory")
        if not self.condition_manager:
            raise RuntimeError("No condition manager available for CBFactory. Call build_condition_manager() first.")

        bias = Bias()

        return CBFactory(
            api_list=self.all_apis,
            driver_size=driver_size,
            dgraph=self.dependency_graph,
            conditions=self.function_conditions or FunctionConditionsSet(),
            bias=bias,
            enable_z3_validation=enable_z3_validation,
            driver_enhancer=self.driver_enhancer  # Pass DriverEnhancer for enhanced callback generation
        )
    
    def create_backend(
        self,
        backend_type: str = "libfuzz",
        headers_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        num_seeds: int = 10
    ):
        """
        Create Backend for generating driver code
        
        Args:
            backend_type: Backend type (currently only "libfuzz" supported)
            headers_dir: Header file directory
            public_headers_file: Public header file list file path
            num_seeds: Number of seeds per driver
        
        Returns:
            BackendDriver instance
        """
        if backend_type != "libfuzz":
            raise ValueError(f"Unsupported backend type: {backend_type}. Only 'libfuzz' is supported.")
        
        if not headers_dir:
            # Try to get from extract_metadata
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                headers_dir = local_meta.get("headers_dir")
        
        if not headers_dir:
            raise ValueError("headers_dir is required for LibFuzzer backend")
        
        if not public_headers_file:
            # Try to get from extract_metadata
            if self.extract_metadata:
                local_meta = self.extract_metadata.get("local", {})
                public_headers_file = local_meta.get("public_headers")
        
        if not public_headers_file:
            raise ValueError("public_headers_file is required for LibFuzzer backend")
        
        drivers_dir = self.work_dir / "drivers"
        seeds_dir = self.work_dir / "seeds"
        drivers_dir.mkdir(parents=True, exist_ok=True)
        seeds_dir.mkdir(parents=True, exist_ok=True)
        
        return LFBackendDriver(
            working_dir=str(drivers_dir),
            seeds_dir=str(seeds_dir),
            num_seeds=num_seeds,
            headers_dir=headers_dir,
            public_headers=public_headers_file
        )
    
    # === Internal helpers ===
    def _ensure_sources(
        self,
        include_dir: Optional[str],
        public_headers_file: Optional[str]
    ):
        """
        Ensure include_dir and public_headers_file are available.
        If not provided, try to fetch sources from OSS-Fuzz docker image.
        """
        fetched_src_dir = None
        
        if not include_dir:
            try:
                fetched_src_dir = self._fetch_source_from_oss_fuzz_image()
                # NOTE: Do NOT set include_dir here! The fetched path is a HOST path,
                # but clang extraction runs INSIDE the container. Let the extractor
                # auto-detect the correct container path (e.g., /src/cjson/).
                logger.info(f"📥 Fetched source from OSS-Fuzz image: {fetched_src_dir}")
            except Exception as e:
                logger.warning(f"Failed to fetch source from OSS-Fuzz image: {e}")

        # Use fetched_src_dir (host path) to generate public_headers.txt
        if not public_headers_file and fetched_src_dir:
            try:
                headers_path = Path(self.work_dir) / "public_headers.txt"
                self._generate_public_headers_file(fetched_src_dir, headers_path)
                public_headers_file = str(headers_path)
                logger.info(f"📄 Generated public headers list: {public_headers_file}")
            except Exception as e:
                logger.warning(f"Failed to generate public headers list: {e}")
        
        # Record into metadata for downstream usage
        local_meta = self.extract_metadata.get("local", {}) if self.extract_metadata else {}
        if include_dir:
            local_meta["headers_dir"] = include_dir
        if public_headers_file:
            local_meta["public_headers"] = public_headers_file
        if fetched_src_dir:
            local_meta["source_dir"] = fetched_src_dir
        if local_meta:
            self.extract_metadata["local"] = local_meta
        
        return include_dir, public_headers_file
    
    def _fetch_source_from_oss_fuzz_image(self) -> str:
        """
        Extract source code from the project container.

        Uses the existing container from HybridAPIExtractor (same image used for fuzzing).
        Handles cases where the source directory name differs from the project name
        (e.g., libaom project has source in /src/aom).

        Returns:
            Path to the extracted source directory.
        """
        # Use existing container from adapter (same image as fuzzing)
        if not (self.adapter and self.adapter.hybrid_extractor and
                self.adapter.hybrid_extractor.container):
            raise RuntimeError(
                "No container available for source extraction. "
                "Ensure HybridAPIExtractor has been initialized."
            )

        container = self.adapter.hybrid_extractor.container
        logger.info(f"📦 Using container {container.container_id} for source extraction")

        src_out_parent = Path(self.work_dir) / "src_ossfuzz"
        src_out_parent.mkdir(parents=True, exist_ok=True)

        skip_dirs = {
            'aflplusplus', 'libfuzzer', 'honggfuzz', 'fuzztest', 'centipede',
            'oss-fuzz', 'fuzzer', 'fuzzers'
        }

        cid = container.container_id

        # First, try the project name directly
        src_container_path = f"/src/{self.project_name}"
        try:
            subprocess.check_call(
                ["docker", "cp", f"{cid}:{src_container_path}", str(src_out_parent)],
                stderr=subprocess.DEVNULL
            )
            src_out = src_out_parent / self.project_name
            if src_out.exists():
                logger.info(f"📦 Found source at {src_container_path}")
                return str(src_out)
        except subprocess.CalledProcessError:
            logger.debug(f"Source not at {src_container_path}, searching /src/...")

        # List /src/ to find actual source directory
        result = container.execute("ls -1 /src/")
        if result.returncode != 0:
            raise RuntimeError(f"Failed to list /src/ in container: {result.stderr}")

        ls_output = result.stdout.strip()
        candidates = [d for d in ls_output.split('\n') if d and d.lower() not in skip_dirs]
        logger.debug(f"Source directory candidates in /src/: {candidates}")

        # Find likely match
        source_dir = None
        for candidate in candidates:
            if self.project_name.startswith(candidate) or candidate.startswith(self.project_name.replace('lib', '')):
                source_dir = candidate
                break

        if not source_dir and candidates:
            source_dir = candidates[0]

        if source_dir:
            src_container_path = f"/src/{source_dir}"
            subprocess.check_call(
                ["docker", "cp", f"{cid}:{src_container_path}", str(src_out_parent)]
            )
            src_out = src_out_parent / source_dir
            if src_out.exists():
                logger.info(f"📦 Found source at {src_container_path} (project: {self.project_name})")
                return str(src_out)

        raise RuntimeError(f"Could not find source directory for {self.project_name} in /src/")

    def _generate_public_headers_file(self, include_dir: str, output_path: Path):
        """Scan |include_dir| for public header files and write basenames to |output_path|.

        Strategy:
        1. Look in include/ directory first
        2. If a header matches project name (e.g., cjson.h), use only that
        3. Otherwise collect all headers, excluding test/example/internal directories
        """
        logger.info("Detecting public headers via local heuristics")
        header_exts = {".h", ".hpp", ".hxx", ".hh"}
        # Exclude test/example directories
        exclude_dirs = {'tests', 'test', 'testing', 'examples', 'example',
                        'benchmarks', 'benchmark', 'docs', 'doc', 'unity'}
        # Internal implementation directories (common patterns for C/C++ libraries)
        internal_dir_patterns = {'internal', 'private', 'detail', 'impl', 'src',
                                  '_dsp', '_util', '_mem', '_port', '_scale'}

        include_subdir = Path(include_dir) / "include"
        search_dir = str(include_subdir) if include_subdir.exists() else include_dir

        # Normalize project name for matching (e.g., "libaom" -> "aom", "cjson" -> "cjson")
        project_name_lower = self.project_name.lower().replace('-', '_').replace(' ', '_')
        # Also try without "lib" prefix (libaom -> aom, libpng -> png)
        project_name_core = project_name_lower.lstrip('lib')

        project_header_patterns = [
            f"{project_name_lower}.h",
            f"{project_name_lower}.hpp",
            f"{project_name_core}.h",
            f"{project_name_core}.hpp",
            f"{self.project_name.lower()}.h",
            f"{self.project_name}.h",
        ]

        header_paths = []
        project_header_found = None
        project_api_dir = None  # Directory containing public API (e.g., "aom/" for libaom)

        def should_exclude_dir(dirname: str) -> bool:
            """Check if directory should be excluded (test/internal directories)"""
            dirname_lower = dirname.lower()
            if dirname_lower in exclude_dirs:
                return True
            # Exclude internal implementation directories
            return any(pattern in dirname_lower for pattern in internal_dir_patterns)

        def is_internal_path(path: str) -> bool:
            """Check if path contains internal directory"""
            parts = Path(path).parts
            for part in parts:
                if should_exclude_dir(part):
                    return True
            return False

        # Step 1: Check for a project-related top-level directory (e.g., aom/ for libaom)
        search_path = Path(search_dir)
        for item in search_path.iterdir():
            if item.is_dir():
                item_lower = item.name.lower()
                # Check if directory name matches project core name
                if item_lower == project_name_core or item_lower == project_name_lower:
                    # Found project API directory! Only use headers from here
                    project_api_dir = item.name
                    logger.info(f"Found project API directory: {project_api_dir}/")
                    break

        # Scan for headers
        for root, dirs, files in os.walk(search_dir):
            # Prune excluded directories from traversal
            dirs[:] = [d for d in dirs if not should_exclude_dir(d)]

            for f in files:
                if Path(f).suffix.lower() not in header_exts:
                    continue

                rel_path = os.path.relpath(os.path.join(root, f), search_dir)

                # Skip if in excluded/internal directory
                if is_internal_path(rel_path):
                    continue

                # If we found a project API directory, only include headers from there
                if project_api_dir:
                    if not rel_path.startswith(project_api_dir + os.sep) and not rel_path.startswith(project_api_dir + "/"):
                        continue

                # Check if this matches project name
                f_lower = f.lower()
                if f_lower in project_header_patterns:
                    project_header_found = rel_path
                    logger.info(f"Found project header: {rel_path}")

                header_paths.append(rel_path)

        # Exclude internal/plugin headers by filename
        internal_header_patterns = {'_plugin', '_internal', '_private', '_impl', '_p.h'}

        def is_internal_header(name: str) -> bool:
            name_lower = name.lower()
            return any(p in name_lower for p in internal_header_patterns)

        # Filter out internal headers
        header_paths = [h for h in header_paths if not is_internal_header(h)]

        # If project-named header found, use only that (+ closely related headers)
        if project_header_found and not project_api_dir:
            # Also include headers with similar names (e.g., cJSON.h + cJSON_Utils.h)
            # but exclude internal/plugin headers
            base_name = Path(project_header_found).stem.lower()
            related_headers = [
                h for h in header_paths
                if Path(h).stem.lower().startswith(base_name)
            ]
            if related_headers:
                header_paths = related_headers
                logger.info(f"Using project-related headers: {related_headers}")
            else:
                header_paths = [project_header_found]
                logger.info(f"Using single project header: {project_header_found}")

        if not header_paths:
            raise RuntimeError(f"No headers found under {search_dir}")

        logger.info(f"Generated public headers list with {len(header_paths)} header(s)")

        with open(output_path, "w") as f:
            for h in sorted(header_paths):
                f.write(h + "\n")
    
    def save_drivers(
        self,
        drivers: List[Driver],
        backend: Optional[LFBackendDriver] = None,
    ):
        """
        Save generated drivers to files (using backend to generate code)

        Args:
            drivers: List of Drivers
            backend: BackendDriver instance (if None, will try to auto-create)

        Returns:
            List of saved driver files
        """
        if backend is None:
            logger.info("No backend provided, attempting to create LibFuzzer backend...")
            try:
                backend = self.create_backend()
            except Exception as e:
                raise RuntimeError(
                    f"Failed to create backend automatically: {e}\n"
                    f"Please provide backend explicitly or ensure headers_dir and public_headers_file are available."
                ) from e
        
        logger.info(f"💾 Saving {len(drivers)} drivers using {type(backend).__name__}...")
        
        saved_files = []
        for driver in drivers:
            try:
                driver_filename = backend.get_name()
                backend.emit_driver(driver, driver_filename)
                backend.emit_seeds(driver, driver_filename)
                saved_files.append(driver_filename)
                logger.debug(f"Saved driver: {driver_filename}")
            except Exception as e:
                logger.warning(f"Failed to save driver: {e}")
        
        logger.info(f"✅ Saved {len(saved_files)} drivers")
        
        return saved_files

