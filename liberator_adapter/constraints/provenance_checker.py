"""
Provenance Checker - Python layer Provenance compatibility checking

Responsibilities:
1. Parse provenance information from JSON
2. Provide provenance compatibility checking
3. Used for dependency graph filtering
"""

from enum import Enum
from typing import Dict
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
