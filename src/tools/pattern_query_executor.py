"""
Pattern Query Executor

Provides data for API pattern query tools used by LLM agents.
Extracts pattern information from FuzzingContext and formats it for LLM consumption.
"""

import logging
from typing import TYPE_CHECKING, List, Optional, Dict, Any

if TYPE_CHECKING:
    from src.context.data_context import FuzzingContext

logger = logging.getLogger(__name__)


class PatternQueryExecutor:
    """
    Executor for API pattern query tools.

    Provides methods to query special patterns (var-len, loop, callback, TLV)
    from FuzzingContext and format results as strings for LLM consumption.

    Usage:
        executor = PatternQueryExecutor(fuzzing_context)
        varlen_tool = QueryVarLenRelationsTool(executor=executor.query_varlen)
    """

    def __init__(self, context: "FuzzingContext"):
        """
        Initialize with FuzzingContext.

        Args:
            context: FuzzingContext containing pattern_analysis and project_apis
        """
        self.context = context
        self._api_map: Dict[str, Any] = {}

        # Build API name -> API object mapping for fast lookup
        if context.project_apis:
            for api in context.project_apis:
                self._api_map[api.function_name] = api

    def _get_pattern_analysis(self, api_name: str) -> Optional[Any]:
        """Get pattern analysis result for an API."""
        if not self.context.pattern_analysis:
            return None

        # pattern_analysis is a dict: api_name -> APIPatternAnalysisResult
        return self.context.pattern_analysis.get(api_name)

    def _get_api(self, api_name: str) -> Optional[Any]:
        """Get API object by name."""
        return self._api_map.get(api_name)

    def query_varlen(self, api_name: str) -> str:
        """
        Query variable-length parameter relationships for an API.

        Returns formatted string describing buffer-length parameter pairs.
        """
        analysis = self._get_pattern_analysis(api_name)

        if not analysis or not analysis.varlen:
            # Try to get API info for context
            api = self._get_api(api_name)
            if api:
                params = ", ".join([
                    f"{arg.type} {arg.name}" for arg in api.arguments_info
                ])
                return (
                    f"No var-len analysis available for {api_name}.\n"
                    f"API signature: {api.return_info.type} {api_name}({params})\n"
                    f"You may need to analyze the parameters manually to identify "
                    f"buffer-length relationships."
                )
            return f"API '{api_name}' not found in project."

        varlen = analysis.varlen
        if not varlen.relations:
            return f"No var-len relationships detected for {api_name}."

        # Format the results
        lines = [f"## Var-len relationships for {api_name}\n"]

        for rel in varlen.relations:
            lines.append(f"### Relationship {rel.buffer_arg_idx + 1}")
            lines.append(f"- Buffer parameter: `{rel.buffer_arg_type} {rel.buffer_arg_name}` (arg #{rel.buffer_arg_idx})")
            lines.append(f"- Length parameter: `{rel.length_arg_type} {rel.length_arg_name}` (arg #{rel.length_arg_idx})")
            lines.append(f"- Relationship: buffer size {rel.relationship} length value")
            lines.append(f"- Confidence: {rel.confidence:.1%}")
            if rel.reasoning:
                lines.append(f"- Reasoning: {rel.reasoning}")
            lines.append("")

        if varlen.llm_confirmed:
            lines.append("*Analysis confirmed by LLM*")

        return "\n".join(lines)

    def query_loop_pattern(self, api_name: str) -> str:
        """
        Query loop pattern information for an API.

        Returns formatted string describing loop requirements.
        """
        analysis = self._get_pattern_analysis(api_name)

        if not analysis or not analysis.loop:
            api = self._get_api(api_name)
            if api:
                params = ", ".join([
                    f"{arg.type} {arg.name}" for arg in api.arguments_info
                ])
                return (
                    f"No loop analysis available for {api_name}.\n"
                    f"API signature: {api.return_info.type} {api_name}({params})\n"
                    f"Check function name patterns (e.g., _next, _read, _iterate) "
                    f"to determine if loop calls are needed."
                )
            return f"API '{api_name}' not found in project."

        loop = analysis.loop

        lines = [f"## Loop pattern for {api_name}\n"]
        lines.append(f"- Needs loop: **{'Yes' if loop.needs_loop else 'No'}**")

        if loop.needs_loop:
            lines.append(f"- Loop type: {loop.loop_type.value}")
            lines.append(f"- Termination condition: `{loop.termination_condition}`")
            lines.append(f"- Max iterations (safety): {loop.max_iterations}")

            if loop.code_template:
                lines.append(f"\n### Suggested code template:")
                lines.append(f"```c\n{loop.code_template}\n```")

        lines.append(f"- Confidence: {loop.confidence:.1%}")
        if loop.reasoning:
            lines.append(f"- Reasoning: {loop.reasoning}")

        return "\n".join(lines)

    def query_callback_info(self, api_name: str) -> str:
        """
        Query callback function parameters for an API.

        Returns formatted string describing callback parameters and stubs.
        """
        analysis = self._get_pattern_analysis(api_name)

        if not analysis or not analysis.callbacks:
            api = self._get_api(api_name)
            if api:
                params = ", ".join([
                    f"{arg.type} {arg.name}" for arg in api.arguments_info
                ])
                return (
                    f"No callback analysis available for {api_name}.\n"
                    f"API signature: {api.return_info.type} {api_name}({params})\n"
                    f"Look for function pointer types or *_callback/*_func parameters."
                )
            return f"API '{api_name}' not found in project."

        callbacks = analysis.callbacks
        if not callbacks.callbacks:
            return f"No callback parameters detected for {api_name}."

        lines = [f"## Callback parameters for {api_name}\n"]

        for cb in callbacks.callbacks:
            lines.append(f"### Callback #{cb.arg_idx}: `{cb.arg_name}`")
            lines.append(f"- Type: `{cb.arg_type}`")
            lines.append(f"- Callback kind: {cb.callback_type.value}")
            lines.append(f"- Can be NULL: {'Yes' if cb.can_be_null else 'No (required)'}")

            if cb.constraints:
                lines.append(f"- Constraints: {', '.join(cb.constraints)}")

            if cb.stub_code:
                lines.append(f"\n#### Suggested stub implementation:")
                lines.append(f"```c\n{cb.stub_code.strip()}\n```")

            if cb.reasoning:
                lines.append(f"- Reasoning: {cb.reasoning}")
            lines.append("")

        if callbacks.llm_confirmed:
            lines.append("*Analysis confirmed by LLM*")

        return "\n".join(lines)

    def query_tlv_format(self, api_name: str) -> str:
        """
        Query TLV/structured data format information for an API.

        Returns formatted string describing format requirements.
        """
        analysis = self._get_pattern_analysis(api_name)

        if not analysis or not analysis.tlv:
            api = self._get_api(api_name)
            if api:
                params = ", ".join([
                    f"{arg.type} {arg.name}" for arg in api.arguments_info
                ])
                return (
                    f"No TLV/format analysis available for {api_name}.\n"
                    f"API signature: {api.return_info.type} {api_name}({params})\n"
                    f"Check if function name contains _parse, _decode, _deserialize "
                    f"to determine if structured input is expected."
                )
            return f"API '{api_name}' not found in project."

        tlv = analysis.tlv

        lines = [f"## TLV/Format analysis for {api_name}\n"]
        lines.append(f"- Is structured parser: **{'Yes' if tlv.is_structured else 'No'}**")

        if tlv.is_structured:
            lines.append(f"- Format type: {tlv.format_type.value}")
            lines.append(f"- Minimum input size: {tlv.min_size} bytes")

            if tlv.magic_bytes:
                hex_str = tlv.magic_bytes.hex()
                lines.append(f"- Magic bytes: `0x{hex_str}`")

            if tlv.constraints:
                lines.append(f"\n### Format constraints:")
                for constraint in tlv.constraints:
                    lines.append(f"- {constraint}")

        if tlv.reasoning:
            lines.append(f"- Reasoning: {tlv.reasoning}")

        if tlv.llm_confirmed:
            lines.append("\n*Analysis confirmed by LLM*")

        return "\n".join(lines)

    def query_all_patterns(self, api_name: str, pattern_types: List[str]) -> str:
        """
        Query all specified patterns for an API.

        Args:
            api_name: API function name
            pattern_types: List of pattern types to query

        Returns:
            Formatted string with all requested pattern information.
        """
        results = [f"# API Pattern Analysis: {api_name}\n"]

        if "varlen" in pattern_types:
            results.append(self.query_varlen(api_name))
            results.append("\n---\n")

        if "loop" in pattern_types:
            results.append(self.query_loop_pattern(api_name))
            results.append("\n---\n")

        if "callback" in pattern_types:
            results.append(self.query_callback_info(api_name))
            results.append("\n---\n")

        if "tlv" in pattern_types:
            results.append(self.query_tlv_format(api_name))

        return "\n".join(results)


def create_pattern_query_tools(context: "FuzzingContext") -> Dict[str, Any]:
    """
    Factory function to create pattern query tools with injected executor.

    Args:
        context: FuzzingContext containing pattern analysis

    Returns:
        Dictionary of tool instances ready for use with LangGraph ToolNode
    """
    from src.tools.langchain_adapters import (
        QueryVarLenRelationsTool,
        QueryLoopPatternTool,
        QueryCallbackInfoTool,
        QueryTLVFormatTool,
        QueryAllAPIPattersTool,
    )

    executor = PatternQueryExecutor(context)

    return {
        "query_varlen_relations": QueryVarLenRelationsTool(
            executor=executor.query_varlen
        ),
        "query_loop_pattern": QueryLoopPatternTool(
            executor=executor.query_loop_pattern
        ),
        "query_callback_info": QueryCallbackInfoTool(
            executor=executor.query_callback_info
        ),
        "query_tlv_format": QueryTLVFormatTool(
            executor=executor.query_tlv_format
        ),
        "query_all_api_patterns": QueryAllAPIPattersTool(
            executor=executor.query_all_patterns
        ),
    }
