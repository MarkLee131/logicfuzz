"""
Provenance Checker - Python layer Provenance compatibility checking

Responsibilities:
1. Parse provenance information from JSON
2. Provide provenance compatibility checking
3. Used for dependency graph filtering
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


class ProvenanceTag(Enum):
    """Provenance tag enumeration"""
    HEAP_MALLOC = "HEAP_MALLOC"        # malloc/calloc allocation
    HEAP_CUSTOM = "HEAP_CUSTOM"        # Custom allocator
    RETURN_OPAQUE = "RETURN_OPAQUE"    # Return opaque pointer
    PARAM_BORROWED = "PARAM_BORROWED"  # Parameter borrowing
    GLOBAL = "GLOBAL"                  # Global variable
    STACK = "STACK"                    # Stack allocation
    UNKNOWN = "UNKNOWN"                # Unknown source


@dataclass
class ProvenanceInfo:
    """Provenance information"""
    tag: ProvenanceTag
    allocator_name: str = ""
    type_string: str = ""

    @classmethod
    def from_dict(cls, data: Dict) -> 'ProvenanceInfo':
        """Construct ProvenanceInfo from JSON dictionary"""
        if isinstance(data, str):
            # If it's directly a string, it's the tag
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
    """Provenance compatibility checker"""

    @staticmethod
    def is_compatible(source_prov: ProvenanceInfo, sink_prov: ProvenanceInfo) -> bool:
        """
        Check if source's provenance can be passed to sink's provenance

        Filtering rules:
        1. HEAP_MALLOC cannot be passed to RETURN_OPAQUE parameters
        2. RETURN_OPAQUE can be passed to same-type RETURN_OPAQUE parameters
        3. HEAP_CUSTOM can be passed to RETURN_OPAQUE (library-internal allocated objects)
        4. STACK/GLOBAL cannot be passed to parameters requiring heap allocation
        5. UNKNOWN conservatively handled: allowed
        """

        # Rule 1: HEAP_MALLOC -> RETURN_OPAQUE (forbidden)
        if (source_prov.tag == ProvenanceTag.HEAP_MALLOC and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return False

        # Rule 2: RETURN_OPAQUE -> RETURN_OPAQUE (allowed)
        if (source_prov.tag == ProvenanceTag.RETURN_OPAQUE and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return True

        # Rule 3: HEAP_CUSTOM -> RETURN_OPAQUE (allowed)
        if (source_prov.tag == ProvenanceTag.HEAP_CUSTOM and
            sink_prov.tag == ProvenanceTag.RETURN_OPAQUE):
            return True

        # Rule 4: STACK/GLOBAL -> HEAP_MALLOC (forbidden)
        if (source_prov.tag in [ProvenanceTag.STACK, ProvenanceTag.GLOBAL] and
            sink_prov.tag == ProvenanceTag.HEAP_MALLOC):
            return False

        # Rule 5: UNKNOWN conservatively handled
        if (source_prov.tag == ProvenanceTag.UNKNOWN or
            sink_prov.tag == ProvenanceTag.UNKNOWN):
            return True

        # Rule 6: Same tag usually compatible
        if source_prov.tag == sink_prov.tag:
            return True

        # Default: conservatively allow
        return True

    @staticmethod
    def check_api_compatibility(source_api: Dict, sink_api: Dict,
                                source_is_return: bool = True,
                                sink_param_idx: int = 0) -> bool:
        """
        Check provenance compatibility between two APIs

        Args:
            source_api: Source API's JSON data
            sink_api: Target API's JSON data
            source_is_return: Whether to check source API's return value (True) or parameter (False)
            sink_param_idx: Target API's parameter index

        Returns:
            bool: Whether compatible
        """

        # Extract source's provenance
        if source_is_return:
            source_metadata = source_api.get("return", {})
        else:
            param_key = f"param_{sink_param_idx}"
            source_metadata = source_api.get(param_key, {})

        # Extract sink's provenance
        sink_param_key = f"param_{sink_param_idx}"
        sink_metadata = sink_api.get(sink_param_key, {})

        # Extract provenance from AccessTypeSet
        source_ats = source_metadata.get("access_type_set", [])
        sink_ats = sink_metadata.get("access_type_set", [])

        if not source_ats or not sink_ats:
            # If no AccessType information, conservatively allow
            return True

        # Check provenance compatibility for each AccessType
        # Allow if there's at least one compatible combination
        for source_at in source_ats:
            source_prov = ProvenanceInfo.from_dict(source_at.get("provenance", "UNKNOWN"))

            for sink_at in sink_ats:
                sink_prov = ProvenanceInfo.from_dict(sink_at.get("provenance", "UNKNOWN"))

                if ProvenanceChecker.is_compatible(source_prov, sink_prov):
                    return True

        # All combinations are incompatible
        return False

    @staticmethod
    def filter_dependencies_by_provenance(api_list: List[Dict],
                                         dependency_graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Filter dependency graph using provenance

        Args:
            api_list: API list containing provenance information
            dependency_graph: Original dependency graph {api_name: [dep1, dep2, ...]}

        Returns:
            Filtered dependency graph
        """

        # Build mapping from API name to API data
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
                    # Dependent API not in list, conservatively keep
                    filtered_deps.append(dep_name)
                    continue

                source_api = api_map[dep_name]

                # Check compatibility of return value and all parameters
                # TODO: Simplified handling here, only checking return value
                # More precise implementation needs to check type-matched parameters
                if ProvenanceChecker.check_api_compatibility(
                    source_api, sink_api, source_is_return=True, sink_param_idx=0
                ):
                    filtered_deps.append(dep_name)

            filtered_graph[api_name] = filtered_deps

        return filtered_graph

    @staticmethod
    def get_provenance_statistics(api_list: List[Dict]) -> Dict[str, int]:
        """
        Get provenance distribution statistics in API list

        Returns:
            {provenance_tag: count}
        """
        stats = {tag.value: 0 for tag in ProvenanceTag}

        for api in api_list:
            # Check return value's provenance
            ret_metadata = api.get("return", {})
            ret_ats = ret_metadata.get("access_type_set", [])

            for at in ret_ats:
                prov = ProvenanceInfo.from_dict(at.get("provenance", "UNKNOWN"))
                stats[prov.tag.value] += 1

            # Check parameters' provenance
            for key, value in api.items():
                if key.startswith("param_"):
                    param_ats = value.get("access_type_set", [])
                    for at in param_ats:
                        prov = ProvenanceInfo.from_dict(at.get("provenance", "UNKNOWN"))
                        stats[prov.tag.value] += 1

        return stats


# Convenience functions
def is_provenance_compatible(source_tag_str: str, sink_tag_str: str) -> bool:
    """
    Convenience function: Check if two provenance tag strings are compatible

    Args:
        source_tag_str: Source provenance tag (string)
        sink_tag_str: Target provenance tag (string)

    Returns:
        bool: Whether compatible
    """
    try:
        source_prov = ProvenanceInfo(ProvenanceTag(source_tag_str))
        sink_prov = ProvenanceInfo(ProvenanceTag(sink_tag_str))
        return ProvenanceChecker.is_compatible(source_prov, sink_prov)
    except ValueError:
        # Invalid tag, conservatively allow
        return True
