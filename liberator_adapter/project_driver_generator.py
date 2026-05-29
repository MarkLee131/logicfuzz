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

# Skeleton synthesis re-exports for downstream consumers.
# The HoleFiller / ConstraintCollector layer was removed in 2026-05;
# see ``docs/synthesis_refactor_2026_05.md``. CBFactory drives skeleton
# synthesis directly via ``SkeletonGenerator``.
from liberator_adapter.driver.synthesis import SkeletonGenerator  # noqa: F401

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
        # Save extraction metadata (e.g., apis_llvm/conditions/data_layout
        # paths). Pre-2026-05 this overwrote ``self.extract_metadata`` with
        # the adapter's ``last_metadata``, which silently nuked the
        # ``local`` sub-dict that ``_ensure_sources`` wrote earlier with
        # ``public_headers`` / ``headers_dir`` / ``source_dir``. The bug
        # was latent because data_context.Step 7 used to soft-degrade to
        # empty headers; the F1 fail-fast in the 2026-05 data_context
        # refactor now raises, exposing this. Fix: merge instead of
        # overwrite, preserving the local sub-dict.
        try:
            adapter_meta = getattr(self.adapter, "last_metadata", {}) or {}
            preserved_local = (self.extract_metadata or {}).get("local", {})
            self.extract_metadata = dict(adapter_meta)
            if preserved_local:
                merged_local = dict(self.extract_metadata.get("local", {}) or {})
                merged_local.update(preserved_local)
                self.extract_metadata["local"] = merged_local
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

    # The earlier ``generate_skeleton_drivers`` /
    # ``render_skeleton_to_code`` / ``save_skeleton_drivers`` /
    # ``_generate_api_sequences`` / ``_get_loop_apis`` /
    # ``_apply_loop_patterns`` / ``_sample_sequence_from_grammar``
    # methods were removed in the 2026-05 synthesis refactor. The live
    # path now goes through ``CBFactory.create_skeleton_for_sequence``
    # in ``src/context/data_context.py`` Step 10. See
    # ``docs/synthesis_refactor_2026_05.md`` for details.

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
            # Relaxed fallback: the strict heuristic excludes ``src/`` as an
            # internal dir, but for single-header / non-standard-layout libraries
            # the public API IS in ``src/`` (pugixml: ``src/pugixml.hpp``;
            # several header-only libs). Rescan keeping ONLY test/example/docs
            # exclusions, and treat anything that survives as public. Worst case
            # = a few extra candidate APIs the downstream filters drop, not
            # wrong analysis.
            from pathlib import Path as _PP
            _relaxed_excludes = {'tests', 'test', 'testing', 'examples',
                                 'example', 'benchmarks', 'benchmark',
                                 'docs', 'doc'}
            _relaxed = []
            for _p in _PP(search_dir).rglob("*"):
                if not _p.is_file() or _p.suffix.lower() not in header_exts:
                    continue
                if any(_part.lower() in _relaxed_excludes
                       for _part in _p.relative_to(search_dir).parts):
                    continue
                _relaxed.append(str(_p.relative_to(search_dir)))
            if _relaxed:
                header_paths = sorted(_relaxed)
                logger.info(
                    "Strict heuristic found 0; relaxed fallback (kept "
                    "test/example/docs exclusions only) found %d header(s)",
                    len(header_paths))
            else:
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

