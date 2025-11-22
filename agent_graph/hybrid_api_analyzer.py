#!/usr/bin/env python3
"""
混合 API 依赖分析器：融合 Liberator 和 LogicFuzz 的分析能力

结合 Liberator 的类型驱动分析和 LogicFuzz 的启发式+LLM 分析，
提供更准确和完整的 API 依赖关系分析。
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
    混合分析器：结合 Liberator 的类型驱动分析和 LogicFuzz 的启发式+LLM 分析
    
    分析策略：
    1. Liberator 类型驱动分析：基于严格的类型匹配，识别类型依赖关系
    2. LogicFuzz 启发式分析：基于真实代码使用模式和启发式规则
    3. LLM 分析（可选）：使用 LLM 进行深度语义分析
    
    结果合并策略：
    - 优先使用 Liberator 的类型依赖（最可靠）
    - 补充 LogicFuzz 的使用模式（更全面）
    - 合并去重，保留所有有效的依赖关系
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
        初始化混合分析器
        
        Args:
            project_name: 项目名称
            use_liberator: 是否启用 Liberator 类型驱动分析
            use_heuristic: 是否启用 LogicFuzz 启发式分析
            use_llm: 是否启用 LLM 分析
            llm: LLM 实例（如果启用 LLM 分析）
            project_dir: 项目目录路径
        """
        self.project_name = project_name
        self.project_dir = project_dir
        self.use_liberator = use_liberator
        self.use_heuristic = use_heuristic
        self.use_llm = use_llm
        
        # Liberator 组件
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
        
        # LogicFuzz 组件
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
        target_function: str,
        api_context: Optional[Dict] = None
    ) -> Dict:
        """
        混合分析：结合 Liberator 和 LogicFuzz 的结果
        
        Args:
            target_function: 目标函数名（如 "curl_easy_setopt"）
            api_context: 可选的 FuzzIntrospector 上下文（避免重复查询）
        
        Returns:
            包含以下字段的字典：
            - prerequisites: 前置依赖 API 列表（合并去重）
            - data_dependencies: 数据依赖关系 [(producer, consumer), ...]
            - call_sequence: 推荐的调用顺序（优先使用 Liberator 的拓扑排序）
            - initialization_code: 初始化代码模板（合并）
            - liberator_metadata: Liberator 分析结果（如果启用）
            - heuristic_metadata: 启发式分析结果（如果启用）
        """
        logger.info(f"🔍 Hybrid analysis for {target_function}")
        
        results = {
            'prerequisites': [],
            'data_dependencies': [],
            'call_sequence': [],
            'initialization_code': [],
            'liberator_metadata': {},
            'heuristic_metadata': {}
        }
        
        # 1. Liberator 类型驱动分析
        if self.use_liberator and self.liberator_adapter:
            try:
                liberator_result = self._analyze_with_liberator(target_function, api_context)
                if liberator_result:
                    results['liberator_metadata'] = liberator_result
                    # 合并依赖关系
                    results['prerequisites'].extend(
                        liberator_result.get('prerequisites', [])
                    )
                    results['data_dependencies'].extend(
                        liberator_result.get('data_dependencies', [])
                    )
                    logger.info(f"✅ Liberator found {len(liberator_result.get('prerequisites', []))} prerequisites")
            except Exception as e:
                logger.warning(f"Liberator analysis failed: {e}", exc_info=True)
        
        # 2. LogicFuzz 启发式/LLM 分析
        if (self.use_heuristic or self.use_llm) and self.composition_analyzer:
            try:
                heuristic_result = self.composition_analyzer.find_api_combinations(
                    target_function, api_context
                )
                if heuristic_result:
                    results['heuristic_metadata'] = heuristic_result
                    # 合并依赖关系（去重）
                    for prereq in heuristic_result.get('prerequisites', []):
                        if prereq not in results['prerequisites']:
                            results['prerequisites'].append(prereq)
                    for dep in heuristic_result.get('data_dependencies', []):
                        if dep not in results['data_dependencies']:
                            results['data_dependencies'].append(dep)
                    logger.info(f"✅ LogicFuzz found {len(heuristic_result.get('prerequisites', []))} prerequisites")
            except Exception as e:
                logger.warning(f"LogicFuzz analysis failed: {e}", exc_info=True)
        
        # 3. 生成统一的调用序列（优先使用 Liberator 的拓扑排序）
        liberator_sequence = results.get('liberator_metadata', {}).get('call_sequence', [])
        heuristic_sequence = results.get('heuristic_metadata', {}).get('call_sequence', [])
        results['call_sequence'] = self._merge_call_sequences(
            liberator_sequence,
            heuristic_sequence
        )
        
        # 4. 生成初始化代码（合并）
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
        使用 Liberator 进行类型驱动的依赖分析
        
        基于严格的类型匹配，识别 API 之间的类型依赖关系。
        """
        try:
            # 1. 转换目标函数为 Api 对象
            target_api = self.liberator_adapter.convert_to_liberator_api(
                target_function, api_context
            )
            if not target_api:
                logger.warning(f"Failed to convert {target_function} to Liberator Api object")
                return None
            
            # 2. 获取所有相关 API（从 FuzzIntrospector 或静态分析结果）
            all_apis = self._collect_all_apis(target_function, api_context)
            if not all_apis:
                logger.warning(f"No APIs collected for {target_function}")
                return None
            
            # 3. 构建类型依赖图
            dep_gen = TypeDependencyGraphGenerator(all_apis)
            dep_graph = dep_gen.create()
            self.liberator_dep_graph = dep_graph
            
            # 4. 分析依赖关系
            prerequisites = []
            data_dependencies = []
            
            # 查找目标 API 的依赖
            target_deps = dep_graph.graph.get(target_api, [])
            for dep in target_deps:
                prereq_name = dep.function_name
                if prereq_name not in prerequisites:
                    prerequisites.append(prereq_name)
                data_dependencies.append((prereq_name, target_api.function_name))
            
            # 5. 生成调用序列（拓扑排序）
            call_sequence = self._generate_call_sequence_from_graph(
                dep_graph, target_api
            )
            
            return {
                'prerequisites': prerequisites,
                'data_dependencies': data_dependencies,
                'call_sequence': call_sequence,
                'initialization_code': []  # 需要 ConditionManager 支持
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
        收集项目中所有相关 API（从 FuzzIntrospector 或静态分析结果）
        
        策略：
        1. 从 api_context 的 related_functions 中提取
        2. 从 usage_examples 中提取
        3. 如果缓存中有，使用缓存
        """
        apis = []
        
        # 如果缓存中有，直接返回
        if self.liberator_apis:
            apis = list(self.liberator_apis)
            # 确保目标函数也在列表中
            target_api = self.liberator_adapter.convert_to_liberator_api(
                target_function, api_context
            )
            if target_api and target_api not in apis:
                apis.append(target_api)
            return apis
        
        # 1. 从 api_context 中提取相关函数
        if api_context:
            # 从 related_functions 中提取
            for related in api_context.get('related_functions', []):
                func_name = related.get('name', '')
                if func_name:
                    api = self.liberator_adapter.convert_to_liberator_api(func_name)
                    if api:
                        apis.append(api)
            
            # 从 usage_examples 中提取函数调用
            for example in api_context.get('usage_examples', []):
                # 简单提取：查找函数调用模式
                import re
                func_calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:_[a-zA-Z0-9_]+)*)\s*\(', example)
                for func_name in func_calls:
                    if func_name not in [a.function_name for a in apis]:
                        api = self.liberator_adapter.convert_to_liberator_api(func_name)
                        if api:
                            apis.append(api)
        
        # 2. 确保目标函数在列表中
        target_api = self.liberator_adapter.convert_to_liberator_api(
            target_function, api_context
        )
        if target_api and target_api not in apis:
            apis.append(target_api)
        
        # 3. 更新缓存
        self.liberator_apis = set(apis)
        
        return apis
    
    def _generate_call_sequence_from_graph(
        self,
        dep_graph: DependencyGraph,
        target_api: Api
    ) -> List[str]:
        """
        从依赖图生成调用序列（拓扑排序）
        
        使用 Kahn 算法进行拓扑排序，确保依赖关系正确。
        """
        try:
            # 构建邻接表和入度
            graph = {}
            in_degree = {}
            all_apis = set()
            
            # 收集所有节点
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
                # 优先选择目标 API 的依赖
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                result.append(node.function_name)
                
                for neighbor in graph.get(node, []):
                    in_degree[neighbor] = in_degree.get(neighbor, 0) - 1
                    if in_degree[neighbor] == 0 and neighbor not in visited:
                        queue.append(neighbor)
            
            # 如果目标 API 不在结果中，添加到末尾
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
        合并两个调用序列，保留顺序
        
        策略：
        1. 优先使用 Liberator 的拓扑排序（更可靠）
        2. 如果 Liberator 序列为空，使用启发式序列
        3. 合并时保持依赖顺序
        """
        if not seq1 and not seq2:
            return []
        
        if not seq1:
            return seq2
        
        if not seq2:
            return seq1
        
        # 优先使用 Liberator 的序列（类型驱动，更可靠）
        # 但补充启发式序列中缺失的 API
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
        """合并初始化代码，去重"""
        merged = list(code1)
        for line in code2:
            if line not in merged:
                merged.append(line)
        return merged

