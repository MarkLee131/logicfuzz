"""
ToolCallingMixin - ReAct-style tool-calling loop using LangGraph ToolNode.

Loop terminates when LLM stops making tool calls (standard ReAct behavior).
"""

from abc import abstractmethod
from typing import Any, Dict, List, Tuple
from langchain_core.tools import BaseTool
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.prebuilt import ToolNode

import logger


class ToolCallingMixin:
    """
    Mixin providing ReAct-style tool-calling loop with LangGraph ToolNode.

    Agents must implement:
    - get_langchain_tools(): Return LangChain BaseTool instances
    - parse_response(): Extract structured result from final LLM response
    """

    @abstractmethod
    def get_langchain_tools(self) -> List[BaseTool]:
        """Return the LangChain BaseTool instances for this agent."""
        pass

    @abstractmethod
    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse the final LLM response into structured result."""
        pass

    def run_tool_calling_loop(
        self,
        initial_prompt: str,
        state: Any,
        max_rounds: int = 10,
        log_prefix: str = "REACT"
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Execute ReAct-style tool-calling loop.

        Loop terminates when LLM responds without tool calls.
        """
        langchain_tools = self.get_langchain_tools()
        tool_node = ToolNode(langchain_tools, handle_tool_errors=True)
        openai_tools = self._convert_to_openai_format(langchain_tools)

        messages = [
            {"role": "system", "content": self.system_message},  # type: ignore
            {"role": "user", "content": initial_prompt}
        ]

        all_responses: List[str] = []

        for cur_round in range(max_rounds):
            # Call LLM
            response_data = self.call_llm_with_tools(  # type: ignore
                messages=messages,
                tools=openai_tools,
                state=state,
                log_prefix=f"{log_prefix}_R{cur_round:02d}"
            )

            assistant_message = response_data["message"]
            content = assistant_message.get("content", "") or ""
            tool_calls = assistant_message.get("tool_calls", []) or []

            messages.append(assistant_message)

            if content:
                all_responses.append(content)

            logger.info(
                f'<{log_prefix} R{cur_round}> tools={len(tool_calls)} content={len(content)} chars',
                trial=self.trial  # type: ignore
            )

            # ReAct termination: no tool calls = done
            if not tool_calls:
                return self.parse_response(content), all_responses

            # Execute tools via ToolNode
            ai_msg = AIMessage(content=content, tool_calls=[
                {
                    "id": tc.get("id", ""),
                    "name": tc["function"]["name"],
                    "args": self._parse_args(tc["function"].get("arguments", "{}"))
                }
                for tc in tool_calls
            ])

            tool_results = tool_node.invoke({"messages": [ai_msg]})

            for tool_msg in tool_results.get("messages", []):
                if isinstance(tool_msg, ToolMessage):
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_msg.tool_call_id,
                        "content": self._truncate(tool_msg.content)
                    })

        # Max rounds reached
        logger.warning(f"{log_prefix}: max rounds ({max_rounds}) reached", trial=self.trial)  # type: ignore
        return self.parse_response(all_responses[-1] if all_responses else ""), all_responses

    def _convert_to_openai_format(self, tools: List[BaseTool]) -> List[Dict[str, Any]]:
        """Convert LangChain tools to OpenAI format."""
        result = []
        for tool in tools:
            schema = (tool.args_schema.model_json_schema()
                     if tool.args_schema and hasattr(tool.args_schema, 'model_json_schema')
                     else {"type": "object", "properties": {}, "required": []})
            schema.pop("title", None)
            result.append({
                "type": "function",
                "function": {"name": tool.name, "description": tool.description or "", "parameters": schema}
            })
        return result

    def _parse_args(self, raw: Any) -> Dict[str, Any]:
        """Parse tool arguments."""
        import json
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
        return raw if isinstance(raw, dict) else {}

    def _truncate(self, text: Any, max_len: int = 10000) -> str:
        """Truncate tool output."""
        s = str(text) if not isinstance(text, str) else text
        return s[:max_len] + f"...[truncated {len(s)-max_len}]" if len(s) > max_len else s
