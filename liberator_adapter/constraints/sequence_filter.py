"""
API Sequence Filter - LLM-based过滤

使用LLM进行API序列的语义过滤，不依赖硬编码的启发式规则。

设计原则：
1. 不使用静态分析启发式规则（避免误杀）
2. 使用LLM理解API语义
3. 基于API生命周期进行验证
"""

import logging
from enum import Enum
from typing import List, Tuple, Optional, Dict, Any, Protocol
from dataclasses import dataclass, field

from liberator_adapter.common.api import Api
from liberator_adapter.common.conditions import FunctionConditionsSet
from liberator_adapter.prompt_loader import get_prompt_manager

logger = logging.getLogger(__name__)


# =============================================================================
# LLM Client Protocol
# =============================================================================

class LLMClient(Protocol):
    """LLM客户端协议"""
    def query(self, prompt: str) -> str:
        """发送prompt并返回响应"""
        ...


# =============================================================================
# 数据结构
# =============================================================================

class APILifecyclePhase(Enum):
    """API生命周期阶段"""
    CREATE = "create"       # 创建/分配资源
    INIT = "init"           # 初始化资源
    USE = "use"             # 使用资源（读/写/转换）
    CLEANUP = "cleanup"     # 清理/释放资源
    UNKNOWN = "unknown"     # 未知


@dataclass
class APILifecycleInfo:
    """API的生命周期信息"""
    api_name: str
    phase: APILifecyclePhase
    resource_type: Optional[str] = None  # 操作的资源类型
    reasoning: str = ""                  # 推理依据


@dataclass
class FilterResult:
    """过滤结果"""
    is_valid: bool
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    @staticmethod
    def valid() -> 'FilterResult':
        return FilterResult(is_valid=True)

    @staticmethod
    def invalid(reason: str, details: Optional[Dict[str, Any]] = None) -> 'FilterResult':
        return FilterResult(is_valid=False, reason=reason, details=details)


@dataclass
class LifecycleValidationResult:
    """生命周期验证结果"""
    is_valid: bool
    violations: List[str] = field(default_factory=list)
    lifecycle_info: List[APILifecycleInfo] = field(default_factory=list)
    reasoning: str = ""


# =============================================================================
# LLM-based API Lifecycle Classifier
# =============================================================================

class LLMLifecycleValidator:
    """
    基于LLM的API生命周期验证器

    完全依赖LLM理解API语义，不使用硬编码的启发式规则。
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        Args:
            llm_client: LLM客户端，需要实现 query(prompt) -> str 方法
        """
        self.llm_client = llm_client
        self._cache: Dict[str, APILifecycleInfo] = {}

    def set_llm_client(self, llm_client: LLMClient):
        """设置LLM客户端"""
        self.llm_client = llm_client

    def classify_api(self, api: Api) -> APILifecycleInfo:
        """
        使用LLM分类单个API的生命周期阶段

        Args:
            api: API对象

        Returns:
            APILifecycleInfo: 生命周期信息
        """
        # 检查缓存
        if api.function_name in self._cache:
            return self._cache[api.function_name]

        # 没有LLM客户端，返回UNKNOWN
        if self.llm_client is None:
            return APILifecycleInfo(
                api_name=api.function_name,
                phase=APILifecyclePhase.UNKNOWN,
                reasoning="No LLM client available"
            )

        result = self._llm_classify_single(api)
        self._cache[api.function_name] = result
        return result

    def classify_batch(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """
        批量分类API（更高效）

        Args:
            apis: API列表

        Returns:
            分类结果列表
        """
        if not apis:
            return []

        # 检查哪些需要分类
        uncached = [api for api in apis if api.function_name not in self._cache]

        if uncached and self.llm_client:
            # 批量调用LLM
            batch_results = self._llm_classify_batch(uncached)
            for info in batch_results:
                self._cache[info.api_name] = info

        # 返回所有结果（从缓存）
        return [
            self._cache.get(
                api.function_name,
                APILifecycleInfo(api.function_name, APILifecyclePhase.UNKNOWN),
            )
            for api in apis
        ]

    def validate_sequence(self, sequence: List[Api]) -> LifecycleValidationResult:
        """
        验证API序列的生命周期有效性

        完全使用LLM进行语义验证，不使用硬编码规则。

        Args:
            sequence: API序列

        Returns:
            LifecycleValidationResult: 验证结果
        """
        if not sequence:
            return LifecycleValidationResult(is_valid=True)

        if self.llm_client is None:
            # 没有LLM，无法验证，默认通过
            return LifecycleValidationResult(
                is_valid=True,
                reasoning="No LLM client available, skipping validation"
            )

        # 先获取生命周期分类（用于结果返回）
        lifecycle_infos = self.classify_batch(sequence)

        # 使用LLM验证序列
        return self._llm_validate_sequence(sequence, lifecycle_infos)

    def _llm_classify_single(self, api: Api) -> APILifecycleInfo:
        """使用LLM分类单个API"""
        params_desc = ", ".join([
            f"{arg.type} {arg.name}" for arg in api.arguments_info
        ]) or "void"

        signature = f"{api.return_info.type} {api.function_name}({params_desc})"

        # 使用prompt_loader获取prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_classify_prompt(
            api_name=api.function_name,
            signature=signature,
            return_type=api.return_info.type,
            parameters=params_desc
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            phase_map = {
                "CREATE": APILifecyclePhase.CREATE,
                "INIT": APILifecyclePhase.INIT,
                "USE": APILifecyclePhase.USE,
                "CLEANUP": APILifecyclePhase.CLEANUP,
                "UNKNOWN": APILifecyclePhase.UNKNOWN,
            }

            return APILifecycleInfo(
                api_name=api.function_name,
                phase=phase_map.get(result.get("phase", "UNKNOWN"), APILifecyclePhase.UNKNOWN),
                resource_type=result.get("resource_type"),
                reasoning=result.get("reasoning", "")
            )
        except Exception as e:
            logger.warning(f"LLM classification failed for {api.function_name}: {e}")
            return APILifecycleInfo(
                api_name=api.function_name,
                phase=APILifecyclePhase.UNKNOWN,
                reasoning=f"LLM error: {e}"
            )

    def _llm_classify_batch(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """使用LLM批量分类API"""
        # 构建API列表描述
        api_descriptions = []
        for i, api in enumerate(apis):
            params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info]) or "void"
            sig = f"{api.return_info.type} {api.function_name}({params})"
            api_descriptions.append(f"{i+1}. {sig}")

        # 使用prompt_loader获取prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_batch_classify_prompt(
            api_list="\n".join(api_descriptions)
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            phase_map = {
                "CREATE": APILifecyclePhase.CREATE,
                "INIT": APILifecyclePhase.INIT,
                "USE": APILifecyclePhase.USE,
                "CLEANUP": APILifecyclePhase.CLEANUP,
                "UNKNOWN": APILifecyclePhase.UNKNOWN,
            }

            infos = []
            classifications = result.get("classifications", [])

            # 按API名称匹配结果
            api_name_to_api = {api.function_name: api for api in apis}

            for cls in classifications:
                api_name = cls.get("api_name", "")
                if api_name in api_name_to_api:
                    infos.append(APILifecycleInfo(
                        api_name=api_name,
                        phase=phase_map.get(cls.get("phase", "UNKNOWN"), APILifecyclePhase.UNKNOWN),
                        resource_type=cls.get("resource_type"),
                        reasoning=""
                    ))

            # 补充未分类的API
            classified_names = {info.api_name for info in infos}
            for api in apis:
                if api.function_name not in classified_names:
                    infos.append(APILifecycleInfo(
                        api_name=api.function_name,
                        phase=APILifecyclePhase.UNKNOWN,
                        reasoning="Not in LLM response"
                    ))

            return infos

        except Exception as e:
            logger.warning(f"Batch LLM classification failed: {e}")
            return [
                APILifecycleInfo(api.function_name, APILifecyclePhase.UNKNOWN)
                for api in apis
            ]

    def _llm_validate_sequence(self, sequence: List[Api],
                                lifecycle_infos: List[APILifecycleInfo]) -> LifecycleValidationResult:
        """使用LLM验证序列"""
        # 构建序列描述
        api_descriptions = []
        for i, (api, info) in enumerate(zip(sequence, lifecycle_infos)):
            params = ", ".join([f"{arg.type} {arg.name}" for arg in api.arguments_info]) or "void"
            sig = f"{api.return_info.type} {api.function_name}({params})"
            phase_str = f"[{info.phase.value}]" if info.phase != APILifecyclePhase.UNKNOWN else ""
            api_descriptions.append(f"{i+1}. {sig} {phase_str}")

        # 使用prompt_loader获取prompt
        pm = get_prompt_manager()
        prompt = pm.get_lifecycle_validate_prompt(
            api_sequence="\n".join(api_descriptions)
        )

        try:
            response = self.llm_client.query(prompt)  # type: ignore
            result = self._parse_json_response(response)

            return LifecycleValidationResult(
                is_valid=result.get("is_valid", True),
                violations=result.get("violations", []),
                lifecycle_info=lifecycle_infos,
                reasoning=result.get("reasoning", "")
            )

        except Exception as e:
            logger.warning(f"LLM sequence validation failed: {e}")
            return LifecycleValidationResult(
                is_valid=True,  # 出错时默认通过，避免误杀
                reasoning=f"LLM error: {e}",
                lifecycle_info=lifecycle_infos
            )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """解析LLM的JSON响应"""
        import json
        import re

        # 尝试直接解析
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # 尝试提取JSON块
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'\{[\s\S]*\}',
        ]

        for pattern in json_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(1) if '```' in pattern else match.group(0)
                    return json.loads(json_str)
                except (json.JSONDecodeError, IndexError):
                    continue

        # 解析失败，返回空字典
        logger.warning(f"Failed to parse JSON from response: {response[:200]}...")
        return {}

    def clear_cache(self):
        """清除分类缓存"""
        self._cache.clear()


# =============================================================================
# Sequence Filter (简化版，主要依赖LLM)
# =============================================================================

class SequenceFilter:
    """
    API序列过滤器

    简化版本，只做最基本的检查，主要过滤逻辑交给LLM。
    """

    def __init__(self, conditions: Optional[FunctionConditionsSet] = None):
        """
        Args:
            conditions: 函数条件信息（可选，预留接口）
        """
        self.conditions = conditions
        self._stats = {
            "total": 0,
            "passed": 0,
            "filtered": 0,
        }

    def filter_sequence(self, sequence: List[Api]) -> FilterResult:
        """
        基本过滤检查

        只做最基本的检查，不使用复杂的启发式规则。
        """
        self._stats["total"] += 1

        # 基本检查：空序列
        if not sequence:
            self._stats["filtered"] += 1
            return FilterResult.invalid("Empty sequence")

        # 基本检查：序列过长（可能是无效路径）
        if len(sequence) > 20:
            self._stats["filtered"] += 1
            return FilterResult.invalid(f"Sequence too long: {len(sequence)} APIs")

        self._stats["passed"] += 1
        return FilterResult.valid()

    def filter_sequences(self, sequences: List[List[Api]]) -> List[List[Api]]:
        """批量过滤"""
        return [seq for seq in sequences if self.filter_sequence(seq).is_valid]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self._stats.copy()

    def reset_stats(self):
        """重置统计"""
        self._stats = {"total": 0, "passed": 0, "filtered": 0}


# =============================================================================
# 组合过滤器
# =============================================================================

class LLMSequenceFilter:
    """
    基于LLM的API序列过滤器

    主要使用LLM进行语义过滤，替代传统的启发式规则。
    """

    def __init__(self, llm_client: Optional[LLMClient] = None,
                 conditions: Optional[FunctionConditionsSet] = None):
        """
        Args:
            llm_client: LLM客户端
            conditions: 函数条件信息（预留）
        """
        self.basic_filter = SequenceFilter(conditions)
        self.llm_validator = LLMLifecycleValidator(llm_client)

        self._stats: Dict[str, Any] = {
            "total": 0,
            "basic_filtered": 0,
            "llm_filtered": 0,
            "passed": 0,
        }

    def set_llm_client(self, llm_client: LLMClient):
        """设置LLM客户端"""
        self.llm_validator.set_llm_client(llm_client)

    def filter(self, sequence: List[Api]) -> Tuple[bool, Optional[str]]:
        """
        过滤单个序列

        Returns:
            (是否有效, 拒绝原因)
        """
        self._stats["total"] += 1

        # Step 1: 基本检查
        basic_result = self.basic_filter.filter_sequence(sequence)
        if not basic_result.is_valid:
            self._stats["basic_filtered"] += 1
            return False, f"[Basic] {basic_result.reason}"

        # Step 2: LLM语义验证
        llm_result = self.llm_validator.validate_sequence(sequence)
        if not llm_result.is_valid:
            self._stats["llm_filtered"] += 1
            violations_str = "; ".join(llm_result.violations) if llm_result.violations else llm_result.reasoning
            return False, f"[LLM] {violations_str}"

        self._stats["passed"] += 1
        return True, None

    def filter_batch(self, sequences: List[List[Api]]) -> List[List[Api]]:
        """批量过滤"""
        valid = []
        for seq in sequences:
            is_valid, reason = self.filter(seq)
            if is_valid:
                valid.append(seq)
            else:
                logger.debug(f"Filtered sequence: {reason}")
        return valid

    def classify_apis(self, apis: List[Api]) -> List[APILifecycleInfo]:
        """
        分类API列表的生命周期阶段

        可以单独使用，用于理解API语义。
        """
        return self.llm_validator.classify_batch(apis)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self._stats.copy()
        stats["basic_filter_stats"] = self.basic_filter.get_stats()
        return stats

    def reset_stats(self):
        """重置统计"""
        self._stats = {
            "total": 0,
            "basic_filtered": 0,
            "llm_filtered": 0,
            "passed": 0,
        }
        self.basic_filter.reset_stats()


# =============================================================================
# 向后兼容的别名
# =============================================================================

# 保持与旧代码的兼容性
TwoPhaseSequenceFilter = LLMSequenceFilter
