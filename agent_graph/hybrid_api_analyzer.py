#!/usr/bin/env python3
"""
Hybrid API Dependency Analyzer: Combines Liberator and LogicFuzz analysis capabilities

Combines Liberator's type-driven analysis with LogicFuzz's heuristic+LLM analysis,
providing more accurate and complete API dependency relationship analysis.
"""
import logging
from typing import Dict, List, Optional, Set
from liberator_adapter.adapter import LiberatorAPIAdapter
from liberator_adapter.dependency import DependencyGraph, TypeDependencyGraphGenerator
from liberator_adapter.common.api import Api
from agent_graph.api_composition_analyzer import APICompositionAnalyzer

logger = logging.getLogger(__name__)


class HybridAPIAnalyzer:
    """
    Hybrid analyzer: Combines Liberator's type-driven analysis with LogicFuzz's heuristic+LLM analysis
    
    Analysis strategies:
    1. Liberator type-driven analysis: Based on strict type matching, identifies type dependencies
    2. LogicFuzz heuristic analysis: Based on real code usage patterns and heuristic rules
    3. LLM analysis (optional): Uses LLM for deep semantic analysis
    
    Result merging strategy:
    - Prioritize Liberator's type dependencies (most reliable)
    - Supplement with LogicFuzz usage patterns (more comprehensive)
    - Merge and deduplicate, preserve all valid dependency relationships
    """
    
    def __init__(
        self,
        project_name: str,
        use_liberator: bool = True,
        use_heuristic: bool = True,
        use_llm: bool = False,
        llm = None,
        project_dir: str = ""
    ):
        """
        Initialize hybrid analyzer
        
        Args:
            project_name: Project name
            use_liberator: Whether to enable Liberator type-driven analysis
            use_heuristic: Whether to enable LogicFuzz heuristic analysis
            use_llm: Whether to enable LLM analysis
            llm: LLM instance (if LLM analysis is enabled)
            project_dir: Project directory path
        """
        self.project_name = project_name
        self.project_dir = project_dir
        self.use_liberator = use_liberator
        self.use_heuristic = use_heuristic
        self.use_llm = use_llm
        
        # Liberator components
        if use_liberator:
            try:
                self.liberator_adapter = LiberatorAPIAdapter(project_name)
                self.liberator_apis: Set[Api] = set()
                self.liberator_dep_graph: Optional[DependencyGraph] = None
                logger.info("✅ Liberator type-driven analysis enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize Liberator adapter: {e}. Disabling Liberator analysis.")
                self.use_liberator = False
                self.liberator_adapter = None
        
        # LogicFuzz components
        if use_heuristic or use_llm:
            try:
                self.composition_analyzer = APICompositionAnalyzer(
                    project_name=project_name,
                    project_dir=project_dir,
                    llm=llm,
                    use_llm=use_llm
                )
                logger.info("✅ LogicFuzz heuristic/LLM analysis enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize LogicFuzz analyzer: {e}. Disabling heuristic analysis.")
                self.use_heuristic = False
                self.use_llm = False
                self.composition_analyzer = None
    
    def analyze_dependencies(
        self,
        target_function: Optional[str] = None,
        api_context: Optional[Dict] = None
    ) -> Dict:
        """
        Hybrid analysis: Combine Liberator and LogicFuzz results
        
        Args:
            target_function: Target function name (e.g., "curl_easy_setopt"), if None then perform project-level analysis
            api_context: Optional FuzzIntrospector context (to avoid redundant queries)
        
        Returns:
            Dictionary containing the following fields:
            - prerequisites: Prerequisite API list (merged and deduplicated)
            - data_dependencies: Data dependency relationships [(producer, consumer), ...]
            - call_sequence: Recommended call order (prioritize Liberator's topological sort)
            - initialization_code: Initialization code templates (merged)
            - liberator_metadata: Liberator analysis results (if enabled)
            - heuristic_metadata: Heuristic analysis results (if enabled)
        """
        if target_function:
            logger.info(f"🔍 Hybrid analysis for {target_function}")
        else:
            logger.info(f"🔍 Project-level hybrid analysis for {self.project_name}")
        
        results = {
            'prerequisites': [],
            'data_dependencies': [],
            'call_sequence': [],
            'initialization_code': [],
            'liberator_metadata': {},
            'heuristic_metadata': {}
        }
        
        # 1. Liberator type-driven analysis
        if self.use_liberator and self.liberator_adapter:
            try:
                if target_function:
                    liberator_result = self._analyze_with_liberator(target_function, api_context)
                else:
                    # Project-level analysis: use ProjectDriverGenerator
                    liberator_result = self._analyze_project_level()
                
                if liberator_result:
                    results['liberator_metadata'] = liberator_result
                    # Merge dependency relationships
                    results['prerequisites'].extend(
                        liberator_result.get('prerequisites', [])
                    )
                    results['data_dependencies'].extend(
                        liberator_result.get('data_dependencies', [])
                    )
                    logger.info(f"✅ Liberator found {len(liberator_result.get('prerequisites', []))} prerequisites")
            except Exception as e:
                logger.warning(f"Liberator analysis failed: {e}", exc_info=True)
        
        # 2. LogicFuzz heuristic/LLM analysis (only when target function is provided)
        if target_function and (self.use_heuristic or self.use_llm) and self.composition_analyzer:
            try:
                heuristic_result = self.composition_analyzer.find_api_combinations(
                    target_function, api_context
                )
                if heuristic_result:
                    results['heuristic_metadata'] = heuristic_result
                    # Merge dependency relationships (deduplicate)
                    for prereq in heuristic_result.get('prerequisites', []):
                        if prereq not in results['prerequisites']:
                            results['prerequisites'].append(prereq)
                    for dep in heuristic_result.get('data_dependencies', []):
                        if dep not in results['data_dependencies']:
                            results['data_dependencies'].append(dep)
                    logger.info(f"✅ LogicFuzz found {len(heuristic_result.get('prerequisites', []))} prerequisites")
            except Exception as e:
                logger.warning(f"LogicFuzz analysis failed: {e}", exc_info=True)
        
        # 3. Generate unified call sequence (prioritize Liberator's topological sort)
        liberator_sequence = results.get('liberator_metadata', {}).get('call_sequence', [])
        heuristic_sequence = results.get('heuristic_metadata', {}).get('call_sequence', [])
        results['call_sequence'] = self._merge_call_sequences(
            liberator_sequence,
            heuristic_sequence
        )
        
        # 4. Generate initialization code (merge)
        liberator_init = results.get('liberator_metadata', {}).get('initialization_code', [])
        heuristic_init = results.get('heuristic_metadata', {}).get('initialization_code', [])
        results['initialization_code'] = self._merge_initialization_code(
            liberator_init,
            heuristic_init
        )
        
        logger.info(
            f"📊 Hybrid analysis complete: {len(results['prerequisites'])} prerequisites, "
            f"{len(results['data_dependencies'])} data deps, "
            f"{len(results['call_sequence'])} APIs in sequence"
        )
        
        return results
    
    def _analyze_with_liberator(
        self,
        target_function: str,
        api_context: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Use Liberator for type-driven dependency analysis
        
        Based on strict type matching, identifies type dependency relationships between APIs.
        """
        try:
            # 1. Convert target function to Api object
            target_api = self.liberator_adapter.convert_to_liberator_api(
                target_function, api_context
            )
            if not target_api:
                logger.warning(f"Failed to convert {target_function} to Liberator Api object")
                return None
            
            # 2. Get all related APIs (from FuzzIntrospector or static analysis results)
            all_apis = self._collect_all_apis(target_function, api_context)
            if not all_apis:
                logger.warning(f"No APIs collected for {target_function}")
                return None
            
            # 3. Build type dependency graph
            dep_gen = TypeDependencyGraphGenerator(all_apis)
            dep_graph = dep_gen.create()
            self.liberator_dep_graph = dep_graph
            
            # 4. Analyze dependency relationships
            prerequisites = []
            data_dependencies = []
            
            # Find dependencies of target API
            target_deps = dep_graph.graph.get(target_api, [])
            for dep in target_deps:
                prereq_name = dep.function_name
                if prereq_name not in prerequisites:
                    prerequisites.append(prereq_name)
                data_dependencies.append((prereq_name, target_api.function_name))
            
            # 5. Generate call sequence (topological sort)
            call_sequence = self._generate_call_sequence_from_graph(
                dep_graph, target_api
            )
            
            return {
                'prerequisites': prerequisites,
                'data_dependencies': data_dependencies,
                'call_sequence': call_sequence,
                'initialization_code': []  # Requires ConditionManager support
            }
            
        except Exception as e:
            logger.warning(f"Liberator analysis failed: {e}", exc_info=True)
            return None
    
    def _collect_all_apis(
        self,
        target_function: str,
        api_context: Optional[Dict] = None
    ) -> List[Api]:
        """
        Collect all related APIs in the project (from FuzzIntrospector or static analysis results)
        
        Strategy:
        1. Extract from api_context's related_functions
        2. Extract from usage_examples
        3. Use cache if available
        """
        apis = []
        
        # If cached, return directly
        if self.liberator_apis:
            apis = list(self.liberator_apis)
            # Ensure target function is also in the list
            target_api = self.liberator_adapter.convert_to_liberator_api(
                target_function, api_context
            )
            if target_api and target_api not in apis:
                apis.append(target_api)
            return apis
        
        # 1. Extract related functions from api_context
        if api_context:
            # Extract from related_functions
            for related in api_context.get('related_functions', []):
                func_name = related.get('name', '')
                if func_name:
                    api = self.liberator_adapter.convert_to_liberator_api(func_name)
                    if api:
                        apis.append(api)
            
            # Extract function calls from usage_examples
            for example in api_context.get('usage_examples', []):
                # Simple extraction: find function call patterns
                import re
                func_calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', example)
                for func_name in func_calls:
                    if func_name not in [a.function_name for a in apis]:
                        api = self.liberator_adapter.convert_to_liberator_api(func_name)
                        if api:
                            apis.append(api)
        
        # 2. Ensure target function is in the list
        target_api = self.liberator_adapter.convert_to_liberator_api(
            target_function, api_context
        )
        if target_api and target_api not in apis:
            apis.append(target_api)
        
        # 3. Update cache
        self.liberator_apis = set(apis)
        
        return apis
    
    def _generate_call_sequence_from_graph(
        self,
        dep_graph: DependencyGraph,
        target_api: Api
    ) -> List[str]:
        """
        Generate call sequence from dependency graph (topological sort)
        
        Uses Kahn's algorithm for topological sorting to ensure correct dependency relationships.
        """
        try:
            # Build adjacency list and in-degree
            graph = {}
            in_degree = {}
            all_apis = set()
            
            # Collect all nodes
            for api in dep_graph.graph.keys():
                all_apis.add(api)
                graph[api] = []
                in_degree[api] = 0
            
            for api, deps in dep_graph.graph.items():
                all_apis.add(api)
                if api not in graph:
                    graph[api] = []
                    in_degree[api] = 0
                for dep in deps:
                    all_apis.add(dep)
                    if dep not in graph:
                        graph[dep] = []
                        in_degree[dep] = 0
                    graph[dep].append(api)
                    in_degree[api] = in_degree.get(api, 0) + 1
            
            # Kahn's algorithm
            queue = [api for api in all_apis if in_degree.get(api, 0) == 0]
            result = []
            visited = set()
            
            while queue:
                # Prioritize dependencies of target API
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                result.append(node.function_name)
                
                for neighbor in graph.get(node, []):
                    in_degree[neighbor] = in_degree.get(neighbor, 0) - 1
                    if in_degree[neighbor] == 0 and neighbor not in visited:
                        queue.append(neighbor)
            
            # If target API is not in result, add it at the end
            target_name = target_api.function_name
            if target_name not in result and target_api in all_apis:
                result.append(target_name)
            
            return result
            
        except Exception as e:
            logger.warning(f"Failed to generate call sequence: {e}", exc_info=True)
            return []
    
    def _merge_call_sequences(
        self,
        seq1: List[str],
        seq2: List[str]
    ) -> List[str]:
        """
        Merge two call sequences, preserving order
        
        Strategy:
        1. Prioritize Liberator's topological sort (more reliable)
        2. If Liberator sequence is empty, use heuristic sequence
        3. Maintain dependency order when merging
        """
        if not seq1 and not seq2:
            return []
        
        if not seq1:
            return seq2
        
        if not seq2:
            return seq1
        
        # Prioritize Liberator's sequence (type-driven, more reliable)
        # But supplement with APIs missing from heuristic sequence
        merged = list(seq1)
        for api in seq2:
            if api not in merged:
                merged.append(api)
        
        return merged
    
    def _merge_initialization_code(
        self,
        code1: List[str],
        code2: List[str]
    ) -> List[str]:
        """Merge initialization code, deduplicate"""
        merged = list(code1)
        for line in code2:
            if line not in merged:
                merged.append(line)
        return merged
    
    def _analyze_project_level(self) -> Optional[Dict]:
        """
        Project-level analysis: Use ProjectDriverGenerator for project-level analysis
        
        Returns:
            Dictionary containing project-level analysis results
        """
        try:
            from liberator_adapter.project_driver_generator import ProjectDriverGenerator
            
            # Create project-level generator (requires benchmark object)
            # Note: benchmark needs to be passed from outside, using simplified version for now
            logger.info(f"🚀 Starting project-level analysis for {self.project_name}")
            
            # If adapter supports Clang/LLVM, use it to extract all APIs
            if hasattr(self.liberator_adapter, 'use_clang_llvm') and self.liberator_adapter.use_clang_llvm:
                # Extract all APIs
                all_apis_dict = self.liberator_adapter.extract_all_apis()
                all_apis = set(all_apis_dict.values())
                
                if not all_apis:
                    logger.warning("No APIs extracted for project-level analysis")
                    return None
                
                # Build type dependency graph
                from liberator_adapter.dependency import TypeDependencyGraphGenerator
                dep_gen = TypeDependencyGraphGenerator(list(all_apis))
                dep_graph = dep_gen.create()
                
                # Generate grammar
                from liberator_adapter.grammar import GrammarGenerator, NonTerminal, Terminal
                start_term = NonTerminal("start")
                end_term = Terminal("end")
                grammar_gen = GrammarGenerator(start_term, end_term)
                grammar = grammar_gen.create(dep_graph)
                
                # Collect all API names
                all_api_names = [api.function_name for api in all_apis]
                
                return {
                    'prerequisites': all_api_names,  # All APIs can be candidates
                    'data_dependencies': [],  # Project-level doesn't return specific dependencies
                    'call_sequence': all_api_names,  # Sequence of all APIs
                    'initialization_code': [],
                    'all_apis': all_api_names,
                    'dependency_graph_size': len(dep_graph.graph),
                    'grammar_symbols': grammar.num_symbols()
                }
            else:
                logger.warning("Project-level analysis requires Clang/LLVM mode")
                return None
                
        except Exception as e:
            logger.warning(f"Project-level analysis failed: {e}", exc_info=True)
            return None

