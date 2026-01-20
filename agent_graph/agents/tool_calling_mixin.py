"""
ToolCallingMixin - Reusable tool-calling loop logic for LangGraph agents.

This mixin encapsulates the common multi-round tool-calling pattern used by
CoverageAnalyzer, CrashAnalyzer, Fixer, and CrashFeasibilityAnalyzer.

Key features:
- Unified tool-calling loop with MAX_TOOL_CALLS limit
- Support for custom conclusion detection and parsing
- Placeholder responses for skipped tool calls (OpenAI API requirement)
- Session memory extraction from responses
- Proper cleanup handling via context managers
"""

from abc import abstractmethod
from typing import Any, Dict, List, Tuple
from langchain_core.tools import BaseTool

import logger


class ToolCallingMixin:
    """
    Mixin class providing reusable tool-calling loop logic.

    Agents using this mixin must:
    1. Define `get_langchain_tools()` to return LangChain BaseTool instances
    2. Define `has_conclusion()` to detect when LLM has provided a conclusion
    3. Define `parse_conclusion()` to extract structured result from conclusion
    4. Optionally override `get_default_result()` for timeout/error cases

    The mixin provides:
    - `run_tool_calling_loop()`: Main loop executing multi-round tool interactions
    - Automatic MAX_TOOL_CALLS limit enforcement
    - Placeholder responses for skipped tool calls
    - Prompt for conclusion when limit is reached
    """

    # Default configuration - can be overridden by subclasses
    MAX_TOOL_CALLS: int = 10
    PROMPT_FOR_CONCLUSION_MESSAGE: str = "Tool call limit reached. Please provide your conclusion now."
    PROMPT_WHEN_NO_TOOLS_MESSAGE: str = "Please provide your final conclusion."

    @abstractmethod
    def get_langchain_tools(self) -> List[BaseTool]:
        """
        Return the LangChain BaseTool instances for this agent.

        These tools should have their executors bound to the appropriate
        agent-specific execution logic.

        Returns:
            List of BaseTool instances
        """
        pass

    @abstractmethod
    def has_conclusion(self, content: str) -> bool:
        """
        Check if the LLM response contains a conclusion.

        Args:
            content: The text content from LLM response

        Returns:
            True if a conclusion is detected
        """
        pass

    @abstractmethod
    def parse_conclusion(self, content: str) -> Dict[str, Any]:
        """
        Parse the conclusion from LLM response into structured result.

        Args:
            content: The text content containing the conclusion

        Returns:
            Dictionary with parsed conclusion data
        """
        pass

    def get_default_result(self) -> Dict[str, Any]:
        """
        Return a default result when loop completes without conclusion.

        Override in subclass for agent-specific defaults.

        Returns:
            Default result dictionary
        """
        return {"analyzed": False, "reason": "No conclusion reached"}

    def run_tool_calling_loop(
        self,
        initial_prompt: str,
        state: Any,
        max_rounds: int = 10,
        log_prefix: str = "TOOL_LOOP",
        collect_responses: bool = True
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Execute the multi-round tool-calling loop.

        This method handles:
        - LLM calls with tool definitions
        - Tool execution via LangChain tools
        - MAX_TOOL_CALLS enforcement
        - Conclusion detection and parsing
        - Placeholder responses for skipped calls

        Args:
            initial_prompt: The initial user prompt to send to LLM
            state: Workflow state for token tracking
            max_rounds: Maximum number of conversation rounds
            log_prefix: Prefix for log messages
            collect_responses: Whether to collect text responses for session memory

        Returns:
            Tuple of (result_dict, all_text_responses)
            - result_dict: Parsed conclusion or default result
            - all_text_responses: List of text responses for session memory extraction
        """
        # Get LangChain tools
        langchain_tools = self.get_langchain_tools()

        # Convert LangChain tools to OpenAI format for the LLM call
        # The base agent's call_llm_with_tools expects OpenAI format
        openai_tools = self._convert_to_openai_format(langchain_tools)

        # Build tool name -> LangChain tool mapping for execution
        tool_map: Dict[str, BaseTool] = {tool.name: tool for tool in langchain_tools}

        # Initialize conversation with system message and initial prompt
        messages = [
            {"role": "system", "content": self.system_message},  # type: ignore
            {"role": "user", "content": initial_prompt}
        ]

        all_responses: List[str] = []
        total_tool_calls = 0
        cur_round = 0

        while cur_round < max_rounds:
            # Call LLM with tools (using base agent's method)
            response_data = self.call_llm_with_tools(  # type: ignore
                messages=messages,
                tools=openai_tools,
                state=state,
                log_prefix=f"{log_prefix}_ROUND_{cur_round:02d}"
            )

            # Extract response components
            assistant_message = response_data["message"]
            content = assistant_message.get("content", "") or ""
            tool_calls = assistant_message.get("tool_calls", []) or []

            # Add assistant message to conversation
            messages.append(assistant_message)

            # Collect text responses for session memory
            if collect_responses and content:
                all_responses.append(content)

            # Log the round
            logger.info(
                f'<{log_prefix} ROUND {cur_round}>\n{content[:500] if content else "(no content)"}\n'
                f'Tool calls: {len(tool_calls)}\n</{log_prefix} ROUND {cur_round}>',
                trial=self.trial  # type: ignore
            )

            # Check if we have a conclusion
            if content and self.has_conclusion(content):
                logger.info(
                    f'----- ROUND {cur_round:02d} Received conclusion -----',
                    trial=self.trial  # type: ignore
                )
                result = self.parse_conclusion(content)
                return result, all_responses

            # Execute tool calls if any
            if tool_calls:
                for i, tool_call in enumerate(tool_calls):
                    # Check tool call limit
                    if total_tool_calls >= self.MAX_TOOL_CALLS:
                        # Add placeholder responses for skipped tool calls
                        # OpenAI API requires every tool_call_id to have a response
                        for skipped_call in tool_calls[i:]:
                            messages.append({
                                "role": "tool",
                                "tool_call_id": skipped_call.get("id", ""),
                                "content": "[Skipped: tool call limit reached]"
                            })
                        logger.warning(
                            f"Max tool calls ({self.MAX_TOOL_CALLS}) reached, "
                            f"{len(tool_calls) - i} calls skipped",
                            trial=self.trial  # type: ignore
                        )
                        break

                    total_tool_calls += 1

                    # Execute tool via LangChain tool
                    tool_result = self._execute_langchain_tool(tool_call, tool_map)

                    # Add tool result to conversation
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", ""),
                        "content": tool_result
                    })

                # Check if we hit the limit - request conclusion
                if total_tool_calls >= self.MAX_TOOL_CALLS:
                    messages.append({
                        "role": "user",
                        "content": self.PROMPT_FOR_CONCLUSION_MESSAGE
                    })

                cur_round += 1
                continue

            # If no tool calls and no conclusion
            if not tool_calls:
                if not content:
                    # No content and no tool calls - stuck
                    logger.warning(
                        f"Round {cur_round}: No tool calls and no content. Breaking.",
                        trial=self.trial  # type: ignore
                    )
                    break
                else:
                    # Has content but no conclusion - prompt for it
                    messages.append({
                        "role": "user",
                        "content": self.PROMPT_WHEN_NO_TOOLS_MESSAGE
                    })

            cur_round += 1

        # Loop completed without conclusion
        return self.get_default_result(), all_responses

    def _convert_to_openai_format(self, langchain_tools: List[BaseTool]) -> List[Dict[str, Any]]:
        """
        Convert LangChain tools to OpenAI function calling format.

        LangChain tools have their own schema format, but we need OpenAI format
        for the LLM call via models.py.

        Args:
            langchain_tools: List of LangChain BaseTool instances

        Returns:
            List of tool definitions in OpenAI format
        """
        openai_tools = []
        for tool in langchain_tools:
            # Get the input schema from the tool
            # args_schema is a type (BaseModel subclass), not an instance
            if tool.args_schema is not None and hasattr(tool.args_schema, 'model_json_schema'):
                schema = tool.args_schema.model_json_schema()
            else:
                schema = {
                    "type": "object",
                    "properties": {},
                    "required": []
                }

            # Remove title field if present (not needed for OpenAI)
            schema.pop("title", None)

            # Build OpenAI format tool definition
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": schema
                }
            }
            openai_tools.append(openai_tool)

        return openai_tools

    def _execute_langchain_tool(
        self,
        tool_call: Dict[str, Any],
        tool_map: Dict[str, BaseTool]
    ) -> str:
        """
        Execute a tool call using LangChain tool.

        Args:
            tool_call: OpenAI format tool call dict
            tool_map: Mapping from tool name to LangChain BaseTool

        Returns:
            Tool execution result as string
        """
        import json

        # Extract tool name and arguments from OpenAI format
        if "function" in tool_call:
            func_info = tool_call["function"]
            tool_name = func_info.get("name", "")
            arguments_raw = func_info.get("arguments", {})
        else:
            tool_name = tool_call.get("name", "")
            arguments_raw = tool_call.get("arguments", {})

        # Parse arguments (may be JSON string or dict)
        if isinstance(arguments_raw, str):
            try:
                arguments = json.loads(arguments_raw)
            except json.JSONDecodeError:
                arguments = {}
        else:
            arguments = arguments_raw

        # Get the LangChain tool
        tool = tool_map.get(tool_name)
        if not tool:
            return f"Error: Unknown tool '{tool_name}'"

        try:
            # Execute via LangChain tool's invoke method
            # This handles argument unpacking based on the tool's args_schema
            result = tool.invoke(arguments)

            # Truncate result if needed
            if hasattr(self, 'truncate_tool_output'):
                result = self.truncate_tool_output(result)  # type: ignore

            return result

        except Exception as e:
            logger.error(
                f"Tool execution error for '{tool_name}': {e}",
                trial=self.trial  # type: ignore
            )
            return f"Error executing {tool_name}: {str(e)}"
