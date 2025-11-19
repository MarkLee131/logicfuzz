"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import argparse
import json

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.memory import get_agent_messages, add_agent_message
from agent_graph.logger import LangGraphLogger, NullLogger


class LangGraphAgent(ABC):
    """
    Base class for LangGraph-compatible agents.
    
    Key differences from ADKBaseAgent:
    - No session management (state-based)
    - Agent-specific message history
    - Direct LLM interaction
    - Cleaner interface
    """
    
    def __init__(
        self,
        name: str,
        llm: LLM,
        trial: int,
        args: argparse.Namespace,
        system_message: str = "",
        enable_detailed_logging: bool = True
    ):
        """
        Initialize a LangGraph agent.
        
        Args:
            name: Unique agent name (e.g., "function_analyzer")
            llm: LLM instance
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
            enable_detailed_logging: If True, log all LLM interactions to files
        """
        self.name = name
        self.llm = llm
        self.trial = trial
        self.args = args
        self.system_message = system_message
        
        # Initialize detailed logging system (uses NullLogger pattern to avoid None checks)
        self.enable_detailed_logging = enable_detailed_logging
        
        # Get base_dir from work_dirs if available
        base_dir = None
        if hasattr(args, 'work_dirs') and args.work_dirs:
            base_dir = str(args.work_dirs.base)
        
        self._langgraph_logger = (
            LangGraphLogger.get_logger(workflow_id="fuzzing_workflow", trial=trial, base_dir=base_dir)
            if enable_detailed_logging
            else NullLogger()
        )
        self._round = 0
        self._tool_system_prompt_logged = False

    def _get_llm_model_name(self) -> str:
        """
        The LangGraph agents always receive concrete `LLM` subclasses that expose a
        `name` attribute (see `llm_toolkit.models.LLM`). Use that directly so logs
        reflect the configured model without extra indirection.
        """
        return self.llm.name
    
    def chat_llm(
        self,
        state: FuzzingWorkflowState,
        prompt: str
    ) -> str:
        """
        Chat with LLM using agent-specific message history.
        
        This method:
        1. Gets this agent's message history from state
        2. Adds the new prompt as a user message
        3. Calls LLM with the agent's messages
        4. Adds the response as an assistant message
        5. Trims messages to 50k tokens
        6. Logs interaction to detailed log files
        
        Args:
            state: The workflow state
            prompt: User prompt to send to LLM
        
        Returns:
            LLM response text
        """
        # OPTIMIZATION: Disable conversation history storage to reduce token usage
        # See MEMORY_OPTIMIZATION_ANALYSIS.md for details
        # All context now comes from session_memory only
        
        # === COMMENTED OUT: Agent message history storage ===
        # # Get this agent's messages (initializes with system message if first time)
        # messages = get_agent_messages(state, self.name, self.system_message)
        # 
        # # Add user prompt
        # add_agent_message(state, self.name, "user", prompt)
        # 
        # # Get updated messages for LLM call
        # messages = state["agent_messages"][self.name]
        
        # NEW: Stateless LLM call with system message + prompt only
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": prompt}
        ]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        # Log the prompt (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )
        
        # Detailed logging: log prompt with metadata
        prompt_metadata = {
                'model': self._get_llm_model_name(),
                'temperature': getattr(self.args, 'temperature', None),
                'num_messages': len(messages)
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        # Call LLM with messages (now stateless: system + prompt only)
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage
        token_usage = None
        if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # === COMMENTED OUT: Agent message history storage ===
        # # Add assistant response
        # add_agent_message(state, self.name, "assistant", response)
        
        # Log the response (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        # Detailed logging: log response with metadata
        response_metadata = {
                'model': self._get_llm_model_name(),
                'tokens': token_usage
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        return response
    
    def ask_llm(self, prompt: str, state: Optional[FuzzingWorkflowState] = None) -> str:
        """
        Ask LLM a one-off question without conversation history.
        
        This is useful for stateless queries that don't need context.
        
        Args:
            prompt: The question/prompt
            state: Optional state for tracking token usage
        
        Returns:
            LLM response
        """
        messages = [{"role": "user", "content": prompt}]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        # Detailed logging: log one-off prompt
        if self._langgraph_logger:
            prompt_metadata = {
                'model': self._get_llm_model_name(),
                'temperature': getattr(self.args, 'temperature', None),
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        token_usage = None
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Detailed logging: log one-off response
        if self._langgraph_logger:
            response_metadata = {
                'model': self._get_llm_model_name(),
                'tokens': token_usage,
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        logger.info(
            f'<AGENT {self.name} ONEOFF RESPONSE>\n{response}\n</AGENT {self.name} ONEOFF RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def call_llm_stateless(
        self, 
        prompt: str, 
        state: Optional[FuzzingWorkflowState] = None,
        log_prefix: str = "STATELESS"
    ) -> str:
        """
        Call LLM without conversation history (stateless).
        
        This method is used for iterative analysis where we manage state explicitly
        rather than relying on LLM conversation history. Each call is independent,
        with only system message + current prompt.
        
        Differences from ask_llm():
        - Includes system message (ask_llm doesn't)
        - Explicitly designed for iterative refinement patterns
        - Better logging for stateless iteration
        
        Args:
            prompt: User prompt (state should be embedded in the prompt)
            state: Optional state for tracking token usage
            log_prefix: Prefix for log messages
        
        Returns:
            LLM response
        """
        # Construct stateless messages: system + user prompt only
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": prompt}
        ]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        logger.debug(
            f'<AGENT {self.name} {log_prefix}>\n{prompt[:500]}...\n</AGENT {self.name} {log_prefix}>',
            trial=self.trial
        )
        
        # Detailed logging: log stateless prompt
        if self._langgraph_logger:
            prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'type': 'stateless (no conversation history)',
                'prompt_length': len(prompt)
            }
            self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        # Call LLM
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        token_usage = None
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Detailed logging: log stateless response
        if self._langgraph_logger:
            response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage,
                'type': 'stateless (no conversation history)',
                'response_length': len(response)
            }
            self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        logger.debug(
            f'<AGENT {self.name} {log_prefix} RESPONSE>\n{response[:500]}...\n</AGENT {self.name} {log_prefix} RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def call_llm_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        state: Optional[FuzzingWorkflowState] = None,
        log_prefix: str = "TOOLS"
    ) -> Dict[str, Any]:
        """
        Call LLM with tool support while capturing detailed logs and token usage.
        
        Args:
            messages: Conversation history shown to the LLM
            tools: Tool definitions in OpenAI function calling format
            state: Optional workflow state for token accounting
            log_prefix: Label for log messages (helps correlate multi-round loops)
        
        Returns:
            Raw response dict returned by the underlying LLM implementation
        """
        if not messages:
            raise ValueError("messages cannot be empty for tool calls")
        
        self._round += 1
        
        # Log system message once per agent to avoid duplication
        if not self._tool_system_prompt_logged:
            system_msg = next((m for m in messages if m.get("role") == "system"), None)
            if system_msg:
                system_log = self._format_message_for_log(system_msg)
                self._langgraph_logger.log_interaction(
                    agent_name=self.name,
                    interaction_type='prompt',
                    content=system_log,
                    round_num=self._round,
                    metadata={
                        'mode': 'tool_call',
                        'log_prefix': f'{log_prefix}_SYSTEM',
                        'message_role': 'system'
                    }
                )
            self._tool_system_prompt_logged = True
        
        latest_message = messages[-1]
        prompt_log = self._format_message_for_log(latest_message)
        prompt_metadata = {
            'mode': 'tool_call',
            'log_prefix': log_prefix,
            'message_role': latest_message.get('role', 'unknown'),
            'messages_in_context': len(messages),
            'tools_available': len(tools)
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='prompt',
            content=prompt_log,
            round_num=self._round,
            metadata=prompt_metadata
        )
        
        response = self.llm.chat_with_tools(messages=messages, tools=tools)
        
        token_usage = getattr(self.llm, 'last_token_usage', None)
        if state and token_usage:
            from agent_graph.state import update_token_usage
            update_token_usage(
                state,
                self.name,
                token_usage.get('prompt_tokens', 0),
                token_usage.get('completion_tokens', 0),
                token_usage.get('total_tokens', 0)
            )
        
        assistant_message, content, tool_calls = self._normalize_tool_response(response)
        response_log = self._format_tool_response_for_log(content, tool_calls)
        response_metadata = {
            'mode': 'tool_call',
            'log_prefix': log_prefix,
            'tool_call_count': len(tool_calls),
            'tokens': token_usage
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='response',
            content=response_log,
            round_num=self._round,
            metadata=response_metadata
        )
        
        logger.debug(
            f'<AGENT {self.name} {log_prefix} RESPONSE>\n'
            f'{content[:500]}...\n'
            f'Tool calls: {len(tool_calls)}\n'
            f'</AGENT {self.name} {log_prefix} RESPONSE>',
            trial=self.trial
        )
        
        # Return normalized response with properly formatted tool_calls for OpenAI API
        return {
            "content": content,
            "tool_calls": tool_calls,
            "message": assistant_message  # Include normalized assistant message
        }
    
    def _format_message_for_log(self, message: Dict[str, Any], max_chars: int = 6000) -> str:
        """Format a conversation message for structured logging."""
        if not message:
            return "<empty message>"
        
        role = message.get('role', 'unknown').upper()
        header_parts = [f"Role: {role}"]
        if tool_id := message.get('tool_call_id'):
            header_parts.append(f"ToolCallID: {tool_id}")
        if name := message.get('name'):
            header_parts.append(f"Name: {name}")
        header = " | ".join(header_parts)
        
        content = message.get('content', '')
        if isinstance(content, list):
            content = json.dumps(content, indent=2)
        elif not isinstance(content, str):
            content = str(content)
        
        return f"{header}\n{self._truncate_for_log(content, max_chars)}"
    
    def _format_tool_response_for_log(
        self,
        content: str,
        tool_calls: List[Dict[str, Any]],
        max_chars: int = 6000
    ) -> str:
        """Format tool-enabled LLM responses for logging."""
        sections = []
        sections.append("Assistant Response:")
        sections.append(self._truncate_for_log(content or "<empty>", max_chars))
        
        if tool_calls:
            tool_json = json.dumps(tool_calls, indent=2, ensure_ascii=False)
            sections.append("")
            sections.append(f"Tool Calls ({len(tool_calls)}):")
            sections.append(self._truncate_for_log(tool_json, max_chars))
        else:
            sections.append("")
            sections.append("Tool Calls: none")
        
        return "\n".join(sections)
    
    def _truncate_for_log(self, text: str, max_chars: int) -> str:
        """Truncate large text blocks for logging purposes."""
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    
    def _normalize_tool_response(
        self,
        response: Dict[str, Any]
    ) -> tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
        """
        Normalize tool responses from models.py format to OpenAI API format.
        
        models.py returns: {"content": str, "tool_calls": [{"id": str, "name": str, "arguments": dict}]}
        OpenAI API needs: {"role": "assistant", "content": str, "tool_calls": [{"id": str, "type": "function", "function": {...}}]}
        
        Returns:
            (assistant_message, text_content, tool_calls)
        """
        import json
        
        # models.py always returns dict with "content" and "tool_calls" keys
        content = response.get("content", "") or ""
        tool_calls_raw = response.get("tool_calls", [])
        
        # Convert tool_calls from internal format to OpenAI API format
        tool_calls: List[Dict[str, Any]] = []
        for tc in tool_calls_raw:
            tool_calls.append({
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": json.dumps(tc["arguments"])  # arguments is always dict from models.py
                }
            })
        
        # Set content to None if we have tool_calls and no content (OpenAI API requirement)
        assistant_content = None if (tool_calls and not content) else (content if content else None)
        
        # Build assistant message; only include tool_calls when non-empty to avoid
        # sending `tool_calls: []`, which the OpenAI API rejects.
        assistant: Dict[str, Any] = {
            "role": "assistant",
            "content": assistant_content,
        }
        if tool_calls:
            assistant["tool_calls"] = tool_calls
        return assistant, content, tool_calls
    
    @abstractmethod
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Execute the agent's main logic.
        
        Args:
            state: Current workflow state
        
        Returns:
            Dictionary of state updates
        """
        pass

