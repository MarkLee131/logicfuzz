"""
ToolCallingMixin - ReAct-style tool-calling loop with direct tool execution.

Loop terminates when LLM stops making tool calls (standard ReAct behavior).

Features:
- Custom error handling with context
- Tool execution logging with timing
- Parallel tool execution via ThreadPoolExecutor
"""

import time
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from langchain_core.tools import BaseTool
from langchain_core.messages import ToolMessage

import logger


class ToolCallingMixin:
    """
    Mixin providing ReAct-style tool-calling loop with direct tool execution.

    Agents must implement:
    - get_langchain_tools(): Return LangChain BaseTool instances
    - parse_response(): Extract structured result from final LLM response

    Features:
    - Custom error handling with context
    - Tool execution logging with timing
    - Parallel tool execution via ThreadPoolExecutor
    """

    @abstractmethod
    def get_langchain_tools(self) -> List[BaseTool]:
        """Return the LangChain BaseTool instances for this agent."""
        pass

    @abstractmethod
    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse the final LLM response into structured result."""
        pass

    def _execute_single_tool(
        self,
        tool: BaseTool,
        tool_call: Dict[str, Any],
        log_prefix: str,
        trial: int
    ) -> ToolMessage:
        """
        Execute a single tool with timing and error handling.

        Args:
            tool: The BaseTool to execute
            tool_call: Dict with 'id', 'name', 'args' keys
            log_prefix: Prefix for log messages
            trial: Trial number for logging

        Returns:
            ToolMessage with result or error
        """
        tool_call_id = tool_call.get("id", "")
        tool_name = tool_call.get("name", "unknown")
        args = tool_call.get("args", {})

        start_time = time.time()
        logger.debug(f"<{log_prefix}> Executing tool: {tool_name}", trial=trial)

        try:
            result = tool.invoke(args)
            elapsed = time.time() - start_time
            logger.debug(
                f"<{log_prefix}> Tool '{tool_name}' completed in {elapsed:.2f}s",
                trial=trial
            )
            return ToolMessage(
                content=str(result),
                tool_call_id=tool_call_id,
                name=tool_name
            )
        except Exception as e:
            elapsed = time.time() - start_time
            exc_type = type(e).__name__
            error_msg = f"Tool execution failed with {exc_type}: {e}"
            logger.warning(
                f"<{log_prefix}> Tool '{tool_name}' failed after {elapsed:.2f}s: {e}",
                trial=trial
            )
            return ToolMessage(
                content=error_msg,
                tool_call_id=tool_call_id,
                name=tool_name
            )

    def _execute_tools_parallel(
        self,
        tools_by_name: Dict[str, BaseTool],
        tool_calls: List[Dict[str, Any]],
        log_prefix: str,
        trial: int
    ) -> List[ToolMessage]:
        """
        Execute multiple tools in parallel.

        Args:
            tools_by_name: Dict mapping tool names to BaseTool instances
            tool_calls: List of tool call dicts
            log_prefix: Prefix for log messages
            trial: Trial number for logging

        Returns:
            List of ToolMessages in order of tool_calls
        """
        if len(tool_calls) == 1:
            # Single tool - execute directly without thread pool overhead
            tc = tool_calls[0]
            tool = tools_by_name.get(tc.get("name", ""))
            if tool:
                return [self._execute_single_tool(tool, tc, log_prefix, trial)]
            else:
                return [ToolMessage(
                    content=f"Unknown tool: {tc.get('name', 'unknown')}",
                    tool_call_id=tc.get("id", ""),
                    name=tc.get("name", "unknown")
                )]

        # Multiple tools - execute in parallel
        results: Dict[str, ToolMessage] = {}

        with ThreadPoolExecutor(max_workers=min(len(tool_calls), 4)) as executor:
            futures = {}
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool = tools_by_name.get(tool_name)
                if tool:
                    future = executor.submit(
                        self._execute_single_tool, tool, tc, log_prefix, trial
                    )
                    futures[future] = tc.get("id", "")
                else:
                    # Unknown tool - create error message immediately
                    results[tc.get("id", "")] = ToolMessage(
                        content=f"Unknown tool: {tool_name}",
                        tool_call_id=tc.get("id", ""),
                        name=tool_name
                    )

            for future in as_completed(futures):
                tool_call_id = futures[future]
                results[tool_call_id] = future.result()

        # Return results in order of original tool_calls
        return [results[tc.get("id", "")] for tc in tool_calls if tc.get("id", "") in results]

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

        Features:
        - Custom error handling with context
        - Tool execution logging with timing
        - Parallel tool execution via ThreadPoolExecutor
        """
        langchain_tools = self.get_langchain_tools()
        tools_by_name = {t.name: t for t in langchain_tools}
        trial = getattr(self, 'trial', 0)

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
                trial=trial
            )

            # ReAct termination: no tool calls = done
            if not tool_calls:
                return self.parse_response(content), all_responses

            # Parse tool calls
            parsed_tool_calls = [
                {
                    "id": tc.get("id", ""),
                    "name": tc["function"]["name"],
                    "args": self._parse_args(tc["function"].get("arguments", "{}"))
                }
                for tc in tool_calls
            ]

            # Execute tools in parallel
            tool_messages = self._execute_tools_parallel(
                tools_by_name, parsed_tool_calls, log_prefix, trial
            )

            # Add tool results to messages
            for tool_msg in tool_messages:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_msg.tool_call_id,
                    "content": self._truncate(tool_msg.content)
                })

        # Max rounds reached
        logger.warning(f"{log_prefix}: max rounds ({max_rounds}) reached", trial=trial)
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
