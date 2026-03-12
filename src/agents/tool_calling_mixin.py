"""
ToolCallingMixin - ReAct-style tool-calling loop using LangChain.

This mixin provides a standardized way for agents to execute tool-calling loops
using LangChain's native message types and model interfaces.

Loop terminates when LLM stops making tool calls (standard ReAct behavior).
"""

import time
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import BaseTool

import logger
from src.workflow.state import update_token_usage


class ToolCallingMixin:
    """
    Mixin providing ReAct-style tool-calling loop using LangChain.

    Agents must implement:
    - get_chat_model(): Return LangChain BaseChatModel
    - get_tools(): Return list of LangChain BaseTool instances
    - parse_response(): Extract structured result from final LLM response

    Features:
    - Uses LangChain's native message types
    - Automatic tool binding via model.bind_tools()
    - Parallel tool execution via ThreadPoolExecutor
    - Tool execution timing and error handling
    """

    @abstractmethod
    def get_chat_model(self) -> BaseChatModel:
        """Return the LangChain chat model for this agent."""
        pass

    @abstractmethod
    def get_tools(self) -> List[BaseTool]:
        """Return the LangChain BaseTool instances for this agent."""
        pass

    @abstractmethod
    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse the final LLM response into structured result."""
        pass

    def _execute_single_tool(self, tool: BaseTool, tool_call: Dict[str, Any],
                             log_prefix: str, trial: int) -> ToolMessage:
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
        logger.debug(f"<{log_prefix}> Executing tool: {tool_name}",
                     trial=trial)

        try:
            result = tool.invoke(args)
            elapsed = time.time() - start_time
            logger.debug(
                f"<{log_prefix}> Tool '{tool_name}' completed in {elapsed:.2f}s",
                trial=trial)
            return ToolMessage(content=str(result),
                               tool_call_id=tool_call_id,
                               name=tool_name)
        except Exception as e:
            elapsed = time.time() - start_time
            exc_type = type(e).__name__
            error_msg = f"Tool execution failed with {exc_type}: {e}"
            logger.warning(
                f"<{log_prefix}> Tool '{tool_name}' failed after {elapsed:.2f}s: {e}",
                trial=trial)
            return ToolMessage(content=error_msg,
                               tool_call_id=tool_call_id,
                               name=tool_name)

    def _execute_tools_parallel(self, tools_by_name: Dict[str, BaseTool],
                                tool_calls: List[Dict[str,
                                                      Any]], log_prefix: str,
                                trial: int) -> List[ToolMessage]:
        """
        Execute multiple tools in parallel.

        Args:
            tools_by_name: Dict mapping tool names to BaseTool instances
            tool_calls: List of tool call dicts with 'id', 'name', 'args' keys
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
                return [
                    ToolMessage(
                        content=f"Unknown tool: {tc.get('name', 'unknown')}",
                        tool_call_id=tc.get("id", ""),
                        name=tc.get("name", "unknown"))
                ]

        # Multiple tools - execute in parallel
        results: Dict[str, ToolMessage] = {}

        with ThreadPoolExecutor(
                max_workers=min(len(tool_calls), 4)) as executor:
            futures = {}
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool = tools_by_name.get(tool_name)
                if tool:
                    future = executor.submit(self._execute_single_tool, tool,
                                             tc, log_prefix, trial)
                    futures[future] = tc.get("id", "")
                else:
                    # Unknown tool - create error message immediately
                    results[tc.get("id", "")] = ToolMessage(
                        content=f"Unknown tool: {tool_name}",
                        tool_call_id=tc.get("id", ""),
                        name=tool_name)

            for future in as_completed(futures):
                tool_call_id = futures[future]
                results[tool_call_id] = future.result()

        # Return results in order of original tool_calls
        return [
            results[tc.get("id", "")] for tc in tool_calls
            if tc.get("id", "") in results
        ]

    def run_tool_calling_loop(
            self,
            initial_prompt: str,
            state: Any,
            max_rounds: int = 10,
            log_prefix: str = "REACT") -> Tuple[Dict[str, Any], List[str]]:
        """
        Execute ReAct-style tool-calling loop using LangChain.

        Loop terminates when LLM responds without tool calls.

        Args:
            initial_prompt: The initial user prompt
            state: Agent state (passed through, not directly used by mixin)
            max_rounds: Maximum number of conversation rounds
            log_prefix: Prefix for log messages

        Returns:
            Tuple of (parsed_result, all_responses)
        """
        # Get model and tools
        model = self.get_chat_model()
        tools = self.get_tools()
        tools_by_name = {t.name: t for t in tools}
        trial = getattr(self, 'trial', 0)

        # Bind tools to model
        model_with_tools = model.bind_tools(tools)

        # Build initial messages
        messages: List[BaseMessage] = [
            SystemMessage(content=self.system_message),  # type: ignore
            HumanMessage(content=initial_prompt)
        ]

        all_responses: List[str] = []

        # Get agent name for token tracking
        agent_name = getattr(self, 'name', 'unknown_agent')

        for cur_round in range(max_rounds):
            # Call LLM with tools
            response: AIMessage = model_with_tools.invoke(
                messages)  # type: ignore
            messages.append(response)

            # Track token usage
            token_usage = self._extract_token_usage_from_response(response)
            if token_usage and state is not None:
                update_token_usage(state, agent_name,
                                   token_usage.get('prompt_tokens', 0),
                                   token_usage.get('completion_tokens', 0),
                                   token_usage.get('total_tokens', 0))

            content = response.content or ""
            if isinstance(content, list):
                # Handle multi-part content (some models return list)
                content = "".join(str(c) for c in content)
            tool_calls = response.tool_calls or []

            if content:
                all_responses.append(content)

            logger.info(
                f'<{log_prefix} R{cur_round}> tools={len(tool_calls)} content={len(content)} chars',
                trial=trial)

            # ReAct termination: no tool calls = done
            if not tool_calls:
                return self.parse_response(content), all_responses

            # Convert LangChain tool calls to our format
            parsed_tool_calls = [{
                "id": tc.get("id", ""),
                "name": tc.get("name", ""),
                "args": tc.get("args", {})
            } for tc in tool_calls]

            # Execute tools in parallel
            tool_messages = self._execute_tools_parallel(
                tools_by_name, parsed_tool_calls, log_prefix, trial)

            # Truncate tool results and add to messages
            for tool_msg in tool_messages:
                truncated_content = self._truncate(tool_msg.content)
                messages.append(
                    ToolMessage(content=truncated_content,
                                tool_call_id=tool_msg.tool_call_id,
                                name=tool_msg.name))

        # Max rounds reached
        logger.warning(f"{log_prefix}: max rounds ({max_rounds}) reached",
                       trial=trial)
        return self.parse_response(
            all_responses[-1] if all_responses else ""), all_responses

    def _truncate(self, text: Any, max_len: int = 10000) -> str:
        """Truncate tool output to avoid context overflow."""
        s = str(text) if not isinstance(text, str) else text
        if len(s) > max_len:
            return s[:max_len] + f"...[truncated {len(s) - max_len} chars]"
        return s

    def _extract_token_usage_from_response(
            self, response: AIMessage) -> Optional[Dict[str, int]]:
        """
        Extract token usage from LangChain response if available.

        Args:
            response: The AIMessage response from LLM

        Returns:
            Dict with prompt_tokens, completion_tokens, total_tokens or None
        """
        if hasattr(response,
                   'response_metadata') and response.response_metadata:
            usage = response.response_metadata.get(
                'token_usage') or response.response_metadata.get('usage')
            if usage:
                return {
                    'prompt_tokens':
                    usage.get('prompt_tokens', 0)
                    or usage.get('input_tokens', 0),
                    'completion_tokens':
                    usage.get('completion_tokens', 0)
                    or usage.get('output_tokens', 0),
                    'total_tokens':
                    usage.get('total_tokens', 0)
                }
        return None
