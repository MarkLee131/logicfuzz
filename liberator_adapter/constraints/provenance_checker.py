"""
Provenance Checker - Python层的Provenance兼容性检查

负责：
1. 从JSON中解析provenance信息
2. 提供provenance兼容性检查
3. 用于依赖图过滤
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


class ProvenanceTag(Enum):
    """Provenance标签枚举"""
    HEAP_MALLOC = "HEAP_MALLOC"        # malloc/calloc分配
    HEAP_CUSTOM = "HEAP_CUSTOM"        # 自定义allocator
    RETURN_OPAQUE = "RETURN_OPAQUE"    # 返回opaque指针
    PARAM_BORROWED = "PARAM_BORROWED"  # 参数借用
    GLOBAL = "GLOBAL"                  # 全局变量
    STACK = "STACK"                    # 栈上分配
    UNKNOWN = "UNKNOWN"                # 未知来源


@dataclass
class ProvenanceInfo:
    """Provenance信息"""
    tag: ProvenanceTag
    allocator_name: str = ""
    type_string: str = ""

    @classmethod
    def from_dict(cls, data: Dict) -> 'ProvenanceInfo':
        """从JSON字典构造ProvenanceInfo"""
        if isinstance(data, str):
            # 如果直接是字符串，就是tag
            tag_str = data
            allocator = ""
        else:
            tag_str = data.get("provenance", "UNKNOWN")
            allocator = data.get("allocator_name", "")

        try:
            tag = ProvenanceTag(tag_str)
        except ValueError:
            tag = ProvenanceTag.UNKNOWN

        return cls(tag=tag, allocator_name=allocator)

    def __str__(self) -> str:
        if self.allocator_name:
            return f"{self.tag.value}({self.allocator_name})"
        return self.tag.value


class ProvenanceChecker:
    """Provenance兼容性检查器"""

    @staticmethod
    def is_compatible(source_prov: ProvenanceInfo, sink_prov: ProvenanceInfo) -> bool:
        """
        检查source的provenance是否可以传给sink的provenance

        过滤规则：
        1. HEAP_MALLOC 不能传给 RETURN_OPAQUE 参数
        2. RETURN_OPAQUE 可以传给 同类型的RETURN_OPAQUE参数
        3. HEAP_CUSTOM 可以传给 RETURN_OPAQUE（库内部分配的对象）
        4. STACK/GLOBAL 不能传给需要heap分配的参数
        5. UNKNOWN 保守处理：允许
        """

        # 规则1: HEAP_MALLOC -> RETURN_OPAQUE (禁止)
        if (source_prov.tag == ProvenanceTag.HEAP_MALLOC and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return False

        # 规则2: RETURN_OPAQUE -> RETURN_OPAQUE (允许)
        if (source_prov.tag == ProvenanceTag.RETURN_OPAQUE and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return True

        # 规则3: HEAP_CUSTOM -> RETURN_OPAQUE (允许)
        if (source_prov.tag == ProvenanceTag.HEAP_CUSTOM and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return True

        # 规则4: STACK/GLOBAL -> HEAP_MALLOC (禁止)
        if (source_prov.tag in [ProvenanceTag.STACK, ProvenanceTag.GLOBAL] and
            sink_prov.tag == ProvenanceTag.HEAP_MALLOC):
            return False

        # 规则5: UNKNOWN 保守处理
        if (source_prov.tag == ProvenanceTag.UNKNOWN or
            sink_prov.tag == ProvenanceTag.UNKNOWN):
            return True

        # 规则6: 相同tag通常兼容
        if source_prov.tag == sink_prov.tag:
            return True

        # 默认：保守允许
        return True

    @staticmethod
    def check_api_compatibility(source_api: Dict, sink_api: Dict,
                                source_is_return: bool = True,
                                sink_param_idx: int = 0) -> bool:
        """
        检查两个API之间的provenance兼容性

        Args:
            source_api: 源API的JSON数据
            sink_api: 目标API的JSON数据
            source_is_return: 是否检查源API的返回值（True）还是参数（False）
            sink_param_idx: 目标API的参数索引

        Returns:
            bool: 是否兼容
        """

        # 提取source的provenance
        if source_is_return:
            source_metadata = source_api.get("return", {})
        else:
            param_key = f"param_{sink_param_idx}"
            source_metadata = source_api.get(param_key, {})

        # 提取sink的provenance
        sink_param_key = f"param_{sink_param_idx}"
        sink_metadata = sink_api.get(sink_param_key, {})

        # 从AccessTypeSet中提取provenance
        source_ats = source_metadata.get("access_type_set", [])
        sink_ats = sink_metadata.get("access_type_set", [])

        if not source_ats or not sink_ats:
            # 如果没有AccessType信息，保守允许
            return True

        # 检查每个AccessType的provenance兼容性
        # 只要有一个兼容的组合就允许
        for source_at in source_ats:
            source_prov = ProvenanceInfo.from_dict(source_at.get("provenance", "UNKNOWN"))

            for sink_at in sink_ats:
                sink_prov = ProvenanceInfo.from_dict(sink_at.get("provenance", "UNKNOWN"))

                if ProvenanceChecker.is_compatible(source_prov, sink_prov):
                    return True

        # 所有组合都不兼容
        return False

    @staticmethod
    def filter_dependencies_by_provenance(api_list: List[Dict],
                                         dependency_graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        使用provenance过滤依赖图

        Args:
            api_list: API列表，包含provenance信息
            dependency_graph: 原始依赖图 {api_name: [dep1, dep2, ...]}

        Returns:
            过滤后的依赖图
        """

        # 构建API名称到API数据的映射
        api_map = {api["function_name"]: api for api in api_list}

        filtered_graph = {}

        for api_name, deps in dependency_graph.items():
            if api_name not in api_map:
                filtered_graph[api_name] = deps
                continue

            sink_api = api_map[api_name]
            filtered_deps = []

            for dep_name in deps:
                if dep_name not in api_map:
                    # 依赖的API不在列表中，保守保留
                    filtered_deps.append(dep_name)
                    continue

                source_api = api_map[dep_name]

                # 检查返回值和所有参数的兼容性
                # TODO: 这里简化处理，只检查返回值
                # 更精确的实现需要检查类型匹配的参数
                if ProvenanceChecker.check_api_compatibility(
                    source_api, sink_api, source_is_return=True, sink_param_idx=0
                ):
                    filtered_deps.append(dep_name)

            filtered_graph[api_name] = filtered_deps

        return filtered_graph

    @staticmethod
    def get_provenance_statistics(api_list: List[Dict]) -> Dict[str, int]:
        """
        统计API列表中的provenance分布

        Returns:
            {provenance_tag: count}
        """
        stats = {tag.value: 0 for tag in ProvenanceTag}

        for api in api_list:
            # 检查返回值的provenance
            ret_metadata = api.get("return", {})
            ret_ats = ret_metadata.get("access_type_set", [])

            for at in ret_ats:
                prov = ProvenanceInfo.from_dict(at.get("provenance", "UNKNOWN"))
                stats[prov.tag.value] += 1

            # 检查参数的provenance
            for key, value in api.items():
                if key.startswith("param_"):
                    param_ats = value.get("access_type_set", [])
                    for at in param_ats:
                        prov = ProvenanceInfo.from_dict(at.get("provenance", "UNKNOWN"))
                        stats[prov.tag.value] += 1

        return stats


# 便捷函数
def is_provenance_compatible(source_tag_str: str, sink_tag_str: str) -> bool:
    """
    便捷函数：检查两个provenance标签字符串是否兼容

    Args:
        source_tag_str: 源provenance标签（字符串）
        sink_tag_str: 目标provenance标签（字符串）

    Returns:
        bool: 是否兼容
    """
    try:
        source_prov = ProvenanceInfo(ProvenanceTag(source_tag_str))
        sink_prov = ProvenanceInfo(ProvenanceTag(sink_tag_str))
        return ProvenanceChecker.is_compatible(source_prov, sink_prov)
    except ValueError:
        # 无效的标签，保守允许
        return True
