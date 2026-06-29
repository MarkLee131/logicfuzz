"""
Integrate Clang and LLVM extractors, provide complete API extraction functionality.
"""
import os
import logging
import tempfile
import shutil
from typing import Dict, List, Optional

from tool.container_tool import ProjectContainerTool
from experiment.benchmark import Benchmark

from liberator_adapter.extractors.base_extractor import (
    BaseAPIExtractor, DegradedReason, extraction_status_fields,
    classify_degraded_reason)
from liberator_adapter.extractors.clang_extractor import ClangAPIExtractor
from liberator_adapter.extractors.llvm_extractor import LLVMAPIExtractor
from liberator_adapter.common.api import Api
from liberator_adapter.common.utils import Utils

logger = logging.getLogger(__name__)


class HybridAPIExtractor(BaseAPIExtractor):
    """
    Integrate Clang and LLVM extractors, provide complete API extraction functionality.

    Workflow:
    1. Use Clang extractor to extract apis_clang.json from header files
    2. Use wllvm to compile project to bitcode
    3. Use LLVM extractor to extract apis_llvm.json from bitcode
    4. Use Utils.get_api_list() to merge data and generate Api objects
    """

    def __init__(self, benchmark: Benchmark, container: Optional[ProjectContainerTool] = None,
                 use_llvm14_builder: bool = True):
        """
        Initialize hybrid extractor

        Args:
            benchmark: benchmark object
            container: optional container tool (if created)
            use_llvm14_builder: whether to use custom base-builder with LLVM 14
                               (default True since LLVM extraction requires clang-14)
        """
        # LLVM extraction requires clang-14, so use_llvm14_builder should default to True
        super().__init__(benchmark, container, container_name='hybrid_extract',
                         use_llvm14_builder=use_llvm14_builder)

        # Create sub-extractors (share the same container, no need to pass use_llvm14_builder
        # since they share the already-created container)
        self.clang_extractor = ClangAPIExtractor(benchmark, self.container)
        self.llvm_extractor = LLVMAPIExtractor(benchmark, self.container)
        
        # Output directory (inside container)
        self.output_dir = '/tmp/liberator_extract'
        
        # Local temporary directory (for storing files copied from container)
        self.local_temp_dir = None
        # Record recent metadata (container/local paths)
        self.last_metadata = {}
    
    def extract(
        self,
        function_signatures: Optional[List[str]] = None,
        include_dir: Optional[str] = None,
        public_headers_file: Optional[str] = None,
        bc_file: Optional[str] = None,
        compile_project: bool = True
    ) -> Dict[str, Api]:
        """
        Extract API information
        
        Args:
            function_signatures: list of function signatures to extract (optional, if None then extract all)
            include_dir: header file directory (optional, if None then auto-detect)
            public_headers_file: list of public header files (optional)
            bc_file: bitcode file path (optional, if None and compile_project=True then auto-compile)
            compile_project: whether to compile project (if bc_file is not provided)
        
        Returns:
            dictionary of function names to Api objects
        """
        logger.info(f"Starting hybrid API extraction for project: {self.benchmark.project}")

        # 1. Compile project first (generates headers for amalgamation projects like sqlite3)
        logger.info("Step 1: Compiling project to bitcode...")
        llvm_extraction_failed = False
        self._degraded_reason = None
        compiled_ok = False
        if not bc_file:
            if compile_project:
                try:
                    bc_file = self.llvm_extractor.compile_to_bitcode()
                    compiled_ok = True
                except Exception as e:
                    self._degraded_reason = classify_degraded_reason(str(e))
                    logger.warning(f"LLVM compilation failed, falling back to clang-only mode: {e}")
                    llvm_extraction_failed = True
            else:
                raise ValueError("bc_file not provided and compile_project=False")

        # 1.5 Amalgamation fix: the public-header heuristic ran on the raw source
        # checkout, where the canonical generated header (e.g. sqlite3's
        # bld/sqlite3.h amalgamation) does NOT yet exist — so it grabbed
        # subdirectory headers (sqlite3 -> all ext/* internals) instead of the
        # real public API. Now that the in-container `compile` has produced the
        # canonical {project}.h, prefer it. Library-agnostic, fail-open.
        if compiled_ok:
            public_headers_file = self._prefer_generated_public_header(
                include_dir, public_headers_file)

        # 2. Extract apis_clang.json (after compile, so generated headers are available)
        logger.info("Step 2: Extracting apis_clang.json...")
        if include_dir:
            apis_clang_path = self.clang_extractor.extract_apis_clang(
                include_dir=include_dir,
                public_headers_file=public_headers_file,
                output_dir=self.output_dir,
                project_name=self.benchmark.project
            )
        else:
            apis_clang_path = self.clang_extractor.extract_with_auto_detect(
                output_dir=self.output_dir,
                project_name=self.benchmark.project,
                public_headers_file=public_headers_file
            )

        # 3. Extract apis_llvm.json (runs on host) - skip if LLVM extraction failed
        if not self.local_temp_dir:
            self.local_temp_dir = tempfile.mkdtemp(prefix=f'liberator_extract_{self.benchmark.project}_')
            logger.info(f"Created local temp directory: {self.local_temp_dir}")

        if not llvm_extraction_failed:
            # Note: LLVM extraction runs on HOST, so output goes to a HOST directory
            logger.info("Step 3: Extracting apis_llvm.json on host...")
            try:
                # Extract to local temp dir (HOST path)
                self.llvm_extractor.extract_apis_llvm_on_host(
                    bc_file=bc_file,
                    apis_clang_path=apis_clang_path,
                    output_dir=self.local_temp_dir  # Use HOST temp dir, not container path
                )
            except Exception as e:
                self._degraded_reason = classify_degraded_reason(str(e))
                logger.warning(f"LLVM extraction failed, falling back to clang-only mode: {e}")
                llvm_extraction_failed = True

        # 4. Read and merge data (or use clang-only)
        if llvm_extraction_failed:
            logger.info("Step 4: Using clang-only extraction (no LLVM data)...")
            apis = self._clang_only_extraction(apis_clang_path, function_signatures)
        else:
            logger.info("Step 4: Merging Clang and LLVM data...")
            apis = self._merge_apis(
                apis_clang_path=apis_clang_path,  # Container path
                llvm_output_dir=self.local_temp_dir,  # Host path with LLVM results
                function_signatures=function_signatures
            )
        
        logger.info(f"Successfully extracted {len(apis)} APIs")
        return apis

    def _prefer_generated_public_header(
        self,
        include_dir: Optional[str],
        public_headers_file: Optional[str],
    ) -> Optional[str]:
        """Re-point ``public_headers_file`` at the canonical, build-GENERATED
        ``{project}.h`` when it exists in the container post-compile.

        Amalgamation projects (sqlite3) generate their single public header
        (``bld/sqlite3.h``, 369 SQLITE_API funcs) only during the build. The
        pre-build header heuristic therefore can't see it and instead collects
        subdirectory headers (sqlite3 -> all ``ext/*`` internals = the wrong
        258-API surface, no public sqlite3_* API). Here, after the in-container
        ``compile`` produced ``{project}.h``, we rewrite the public-headers list
        to that single canonical header (path relative to the clang include dir).

        Library-agnostic: keyed on "the build produced a header literally named
        after the project that was absent from the original list". Fail-open:
        any error / not-found leaves ``public_headers_file`` untouched, so this
        can never blank a project that was working before.
        """
        try:
            project = self.benchmark.project
            # Normalise project name -> candidate header basenames.
            pname = project.lower().replace('-', '_').replace(' ', '_')
            pcore = pname.lstrip('lib')
            candidate_basenames = []
            for stem in {pname, pcore, project.lower(), project}:
                for ext in ('.h', '.hpp'):
                    candidate_basenames.append(stem + ext)
            candidate_basenames = list(dict.fromkeys(candidate_basenames))

            # The clang extractor resolves header paths relative to this dir.
            base_dir = include_dir or self.clang_extractor._find_include_dir()
            if not base_dir:
                return public_headers_file

            # If the current list already references a project-named header,
            # the build header (if any) is already in play — leave it alone.
            n_existing = 0
            if public_headers_file and os.path.exists(public_headers_file):
                with open(public_headers_file) as _fh:
                    existing = [ln.strip() for ln in _fh if ln.strip()]
                n_existing = len(existing)
                if any(os.path.basename(h).lower() in
                       {b.lower() for b in candidate_basenames}
                       for h in existing):
                    return public_headers_file

            # Search the container project dir for a generated {project}.h.
            # Prefer the shallowest match (build output near the root, e.g.
            # bld/sqlite3.h), excluding test/ext internal copies.
            name_expr = ' -o '.join(
                f'-name "{b}"' for b in candidate_basenames)
            find_cmd = (
                f'find "{base_dir}" -maxdepth 4 -type f \\( {name_expr} \\) '
                r"-not -path '*/test/*' -not -path '*/ext/*' "
                r"-printf '%d\t%p\n' 2>/dev/null | sort -n"
            )
            res = self.container.execute(find_cmd)
            if res.returncode != 0 or not res.stdout.strip():
                return public_headers_file

            best_abs = res.stdout.strip().split('\n')[0].split('\t', 1)[1].strip()
            # Path relative to the clang include dir.
            rel = os.path.relpath(best_abs, base_dir)

            # Write a fresh single-header list next to the existing one.
            out_dir = (os.path.dirname(public_headers_file)
                       if public_headers_file else tempfile.gettempdir())
            new_path = os.path.join(
                out_dir or tempfile.gettempdir(),
                f'public_headers_{project}_generated.txt')
            with open(new_path, 'w') as _fh:
                _fh.write(rel + '\n')
            logger.info(
                "Amalgamation public-header fix: using build-generated header "
                "'%s' (rel '%s') instead of %s",
                best_abs, rel,
                f"{n_existing} pre-build header(s)"
                if n_existing else "auto-detect",
            )
            return new_path
        except Exception as exc:  # fail-open — never break a working project
            logger.warning(
                "Generated-public-header preference failed (fail-open): %s", exc)
            return public_headers_file

    def _merge_apis(
        self,
        apis_clang_path: str,
        llvm_output_dir: str,
        function_signatures: Optional[List[str]] = None
    ) -> Dict[str, Api]:
        """
        Merge Clang and LLVM data using Utils.get_api_list()

        Args:
            apis_clang_path: Path to apis_clang.json (inside container)
            llvm_output_dir: LLVM extraction result directory (on HOST, contains apis_llvm.json, conditions.json, etc.)
            function_signatures: List of function signatures to extract (optional)

        Returns:
            Dictionary mapping function names to Api objects
        """
        # llvm_output_dir is already local_temp_dir, use directly
        local_paths = {}

        # LLVM results are already on HOST (llvm_output_dir)
        llvm_files = ['apis_llvm.json', 'conditions.json', 'data_layout.txt']
        for filename in llvm_files:
            host_path = os.path.join(llvm_output_dir, filename)
            if os.path.exists(host_path):
                local_paths[filename] = host_path
                logger.debug(f"Using LLVM result from host: {host_path}")

        # Clang results are in container, need to copy
        local_apis_clang = os.path.join(llvm_output_dir, 'apis_clang.json')
        self._copy_from_container(apis_clang_path, local_apis_clang)
        local_paths['apis_clang.json'] = local_apis_clang

        # Prepare other required file paths (inside container)
        exported_functions_path = f'{self.output_dir}/exported_functions.txt'
        incomplete_types_path = f'{self.output_dir}/incomplete_types.txt'
        enum_types_path = f'{self.output_dir}/enum_types.txt'  # Generated by Clang extractor
        minimum_apis_path = ''  # Optional

        # If function signatures specified, create minimum_apis file
        if function_signatures:
            # Extract function names
            function_names = [self._extract_function_name(sig) for sig in function_signatures]
            function_names = [name for name in function_names if name]

            if function_names:
                minimum_apis_path = os.path.join(llvm_output_dir, 'minimum_apis.txt')
                with open(minimum_apis_path, 'w') as f:
                    f.write('\n'.join(function_names))
                local_paths['minimum_apis.txt'] = minimum_apis_path

        # Copy other optional files from container
        # These are generated by extract_included_functions.py (Clang extractor)
        optional_container_files = [
            (exported_functions_path, 'exported_functions.txt'),
            (incomplete_types_path, 'incomplete_types.txt'),
            (enum_types_path, 'enum_types.txt'),  # Required for DataLayout.is_enum_type()
        ]

        for container_path, local_name in optional_container_files:
            if self._file_exists_in_container(container_path):
                local_path = os.path.join(llvm_output_dir, local_name)
                self._copy_from_container(container_path, local_path)
                local_paths[local_name] = local_path

        # Utils.get_api_list requires all file paths to exist (doesn't handle empty strings)
        # Create empty files for optional ones that don't exist
        optional_files_with_defaults = [
            ('coerce.log', ''),
            ('exported_functions.txt', ''),
            ('incomplete_types.txt', ''),
            ('enum_types.txt', ''),  # Required for DataLayout.is_enum_type()
        ]
        for filename, default_content in optional_files_with_defaults:
            if filename not in local_paths:
                local_path = os.path.join(llvm_output_dir, filename)
                with open(local_path, 'w') as f:
                    f.write(default_content)
                local_paths[filename] = local_path

        # Verify required files exist
        required_files = ['apis_llvm.json', 'apis_clang.json']
        for filename in required_files:
            if filename not in local_paths or not os.path.exists(local_paths[filename]):
                raise RuntimeError(f"Required file {filename} not found in local_paths")

        # Read using Utils.get_api_list()
        try:
            api_set = Utils.get_api_list(
                apis_llvm=local_paths['apis_llvm.json'],
                apis_clang=local_paths['apis_clang.json'],
                coerce_map=local_paths['coerce.log'],
                hedader_folder=local_paths['exported_functions.txt'],
                incomplete_types=local_paths['incomplete_types.txt'],
                minimum_apis=local_paths.get('minimum_apis.txt', '')
            )
            
            # Convert to dictionary
            apis_dict = {}
            for api in api_set:
                apis_dict[api.function_name] = api

            # Record metadata for subsequent DataLayout/ConditionManager usage
            # Note: LLVM results are on HOST, Clang results copied from container
            self.last_metadata = {
                "container": {
                    "apis_clang": apis_clang_path,
                    # LLVM extraction runs on host, no container paths for LLVM results
                    "incomplete_types": incomplete_types_path,
                    "exported_functions": exported_functions_path,
                    "enum_types": enum_types_path,
                },
                "local": {
                    "apis_clang": local_paths.get('apis_clang.json'),
                    "apis_llvm": local_paths.get('apis_llvm.json'),
                    "conditions": local_paths.get('conditions.json'),
                    "data_layout": local_paths.get('data_layout.txt'),
                    "incomplete_types": local_paths.get('incomplete_types.txt'),
                    "exported_functions": local_paths.get('exported_functions.txt'),
                    "enum_types": local_paths.get('enum_types.txt'),  # For DataLayout.is_enum_type()
                },
                "llvm_output_dir": llvm_output_dir,
                **extraction_status_fields(
                    False, None,
                    recovery=getattr(self.llvm_extractor, "bitcode_recovery", None)),
            }
            
            return apis_dict
        except Exception as e:
            import traceback
            logger.error(f"Failed to merge APIs: {e}")
            logger.error(f"Traceback:\n{traceback.format_exc()}")
            raise

    def _clang_only_extraction(
        self,
        apis_clang_path: str,
        function_signatures: Optional[List[str]] = None
    ) -> Dict[str, Api]:
        """
        Fallback extraction using only Clang data (when LLVM extraction fails).

        This provides basic API information without LLVM-specific data like
        conditions and detailed data layout analysis.

        Args:
            apis_clang_path: Path to apis_clang.json (inside container)
            function_signatures: List of function signatures to extract (optional)

        Returns:
            Dictionary mapping function names to Api objects
        """
        import json

        # Copy apis_clang.json from container
        local_apis_clang = os.path.join(self.local_temp_dir, 'apis_clang.json')
        self._copy_from_container(apis_clang_path, local_apis_clang)

        # Read apis_clang.json (line-delimited JSON format)
        apis_clang_data = {}
        with open(local_apis_clang, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    api_entry = json.loads(line)
                    func_name = api_entry.get('function_name', '')
                    if func_name:
                        apis_clang_data[func_name] = api_entry
                except json.JSONDecodeError:
                    continue

        # Copy optional files from container
        incomplete_types_path = f'{self.output_dir}/incomplete_types.txt'
        enum_types_path = f'{self.output_dir}/enum_types.txt'
        exported_functions_path = f'{self.output_dir}/exported_functions.txt'

        local_incomplete_types = os.path.join(self.local_temp_dir, 'incomplete_types.txt')
        local_enum_types = os.path.join(self.local_temp_dir, 'enum_types.txt')
        local_exported_functions = os.path.join(self.local_temp_dir, 'exported_functions.txt')

        # Copy optional files if they exist
        for container_path, local_path in [
            (incomplete_types_path, local_incomplete_types),
            (enum_types_path, local_enum_types),
            (exported_functions_path, local_exported_functions),
        ]:
            if self._file_exists_in_container(container_path):
                self._copy_from_container(container_path, local_path)
            else:
                # Create empty file
                with open(local_path, 'w') as f:
                    f.write('')

        # Convert clang data to Api objects
        apis_dict = {}
        for func_name, func_data in apis_clang_data.items():
            try:
                api = Api.from_clang_only(func_name, func_data)
                if api:
                    apis_dict[func_name] = api
            except Exception as e:
                logger.debug(f"Failed to create Api for {func_name}: {e}")

        # Record metadata (clang-only mode)
        self.last_metadata = {
            "container": {
                "apis_clang": apis_clang_path,
                "incomplete_types": incomplete_types_path,
                "exported_functions": exported_functions_path,
                "enum_types": enum_types_path,
            },
            "local": {
                "apis_clang": local_apis_clang,
                "apis_llvm": None,  # No LLVM data
                "conditions": None,
                "data_layout": None,
                "incomplete_types": local_incomplete_types,
                "exported_functions": local_exported_functions,
                "enum_types": local_enum_types,
            },
            "llvm_output_dir": self.local_temp_dir,
            "clang_only_mode": True,  # Flag to indicate clang-only mode (back-compat)
            **extraction_status_fields(True, getattr(self, "_degraded_reason", None)),
        }

        logger.info(f"Clang-only extraction completed: {len(apis_dict)} APIs extracted")
        return apis_dict

    def _extract_function_name(self, signature: str) -> Optional[str]:
        """Extract function name from function signature"""
        import re
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', signature)
        return match.group(1) if match else None
    
    def get_last_metadata(self):
        """Return metadata from the most recent extraction (container/local paths)"""
        return self.last_metadata
    
    def get_api(self, function_name: str) -> Optional[Api]:
        """
        Get API information for a single function
        
        Args:
            function_name: Function name
        
        Returns:
            Api object, or None if not found
        """
        # If not yet extracted, extract all first
        if not hasattr(self, '_cached_apis'):
            self._cached_apis = self.extract()
        
        return self._cached_apis.get(function_name)
    
    def cleanup(self):
        """Clean up resources"""
        # Clean up local temporary directory
        if self.local_temp_dir and os.path.exists(self.local_temp_dir):
            try:
                shutil.rmtree(self.local_temp_dir)
                logger.info(f"Cleaned up local temp directory: {self.local_temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp directory: {e}")
        
        # Call base class cleanup method (close container)
        super().cleanup()

