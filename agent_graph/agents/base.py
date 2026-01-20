"""
LangGraph-native agent base class using LangChain models.

This module provides a clean agent interface designed for LangGraph,
using LangChain's native message types and model interfaces.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import argparse
import json

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)

import logger
from llm_toolkit.models import get_chat_model, DEFAULT_MODEL
from agent_graph.state import FuzzingWorkflowState
from agent_graph.logger import LangGraphLogger, NullLogger


class LangGraphAgent(ABC):
    """
    Base class for LangGraph-compatible agents using LangChain models.

    Key features:
    - Uses LangChain's native message types
    - Direct BaseChatModel interface
    - Agent-specific logging
    - Token usage tracking
    """

    def __init__(
        self,
        name: str,
        model_name: str,
        trial: int,
        args: argparse.Namespace,
        system_message: str = "",
        enable_detailed_logging: bool = True,
        temperature: float = 0.4,
        max_tokens: int = 4096,
    ):
        """
        Initialize a LangGraph agent.

        Args:
            name: Unique agent name (e.g., "function_analyzer")
            model_name: Name of the LLM model (e.g., "gpt-4o", "deepseek-chat")
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
            enable_detailed_logging: If True, log all LLM interactions to files
            temperature: Sampling temperature for the model
            max_tokens: Maximum tokens for model response
        """
        self.name = name
        self.model_name = model_name
        self.trial = trial
        self.args = args
        self.system_message = system_message
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Lazy-load the chat model
        self._chat_model: Optional[BaseChatModel] = None

        # Initialize detailed logging system
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

    def get_chat_model(self) -> BaseChatModel:
        """
        Get the LangChain chat model for this agent.

        Returns:
            BaseChatModel instance
        """
        if self._chat_model is None:
            self._chat_model = get_chat_model(
                self.model_name,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
        return self._chat_model

    def _messages_to_langchain(
        self,
        messages: List[Dict[str, str]]
    ) -> List[BaseMessage]:
        """Convert dict messages to LangChain message types."""
        result: List[BaseMessage] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                result.append(SystemMessage(content=content))
            elif role == "user":
                result.append(HumanMessage(content=content))
            elif role == "assistant":
                result.append(AIMessage(content=content))
            else:
                # Default to human message for unknown roles
                result.append(HumanMessage(content=content))
        return result

    def chat_llm(
        self,
        state: FuzzingWorkflowState,
        prompt: str
    ) -> str:
        """
        Chat with LLM using system message + prompt.

        Args:
            state: The workflow state
            prompt: User prompt to send to LLM

        Returns:
            LLM response text
        """
        # Build messages
        messages: List[BaseMessage] = [
            SystemMessage(content=self.system_message),
            HumanMessage(content=prompt)
        ]

        # Increment round counter for detailed logging
        self._round += 1

        # Log the prompt
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )

        # Detailed logging
        prompt_metadata = {
            'model': self.model_name,
            'temperature': self.temperature,
            'num_messages': len(messages)
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='prompt',
            content=prompt,
            round_num=self._round,
            metadata=prompt_metadata
        )

        # Call LLM
        model = self.get_chat_model()
        response = model.invoke(messages)
        response_text = response.content if isinstance(response.content, str) else str(response.content)

        # Track token usage (if available via callbacks)
        token_usage = self._extract_token_usage(response)
        if token_usage:
            from agent_graph.state import update_token_usage
            update_token_usage(
                state,
                self.name,
                token_usage.get('prompt_tokens', 0),
                token_usage.get('completion_tokens', 0),
                token_usage.get('total_tokens', 0)
            )

        # Log the response
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response_text}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )

        # Detailed logging
        response_metadata = {
            'model': self.model_name,
            'tokens': token_usage
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='response',
            content=response_text,
            round_num=self._round,
            metadata=response_metadata
        )

        return response_text

    def ask_llm(
        self,
        prompt: str,
        state: Optional[FuzzingWorkflowState] = None
    ) -> str:
        """
        Ask LLM a one-off question without system message.

        Args:
            prompt: The question/prompt
            state: Optional state for tracking token usage

        Returns:
            LLM response
        """
        messages: List[BaseMessage] = [HumanMessage(content=prompt)]

        self._round += 1

        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )

        # Detailed logging
        prompt_metadata = {
            'model': self.model_name,
            'temperature': self.temperature,
            'type': 'one-off (no history)'
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='prompt',
            content=prompt,
            round_num=self._round,
            metadata=prompt_metadata
        )

        model = self.get_chat_model()
        response = model.invoke(messages)
        response_text = response.content if isinstance(response.content, str) else str(response.content)

        # Track token usage
        token_usage = self._extract_token_usage(response)
        if state and token_usage:
            from agent_graph.state import update_token_usage
            update_token_usage(
                state,
                self.name,
                token_usage.get('prompt_tokens', 0),
                token_usage.get('completion_tokens', 0),
                token_usage.get('total_tokens', 0)
            )

        # Detailed logging
        response_metadata = {
            'model': self.model_name,
            'tokens': token_usage,
            'type': 'one-off (no history)'
        }
        self._langgraph_logger.log_interaction(
            agent_name=self.name,
            interaction_type='response',
            content=response_text,
            round_num=self._round,
            metadata=response_metadata
        )

        logger.info(
            f'<AGENT {self.name} ONEOFF RESPONSE>\n{response_text}\n</AGENT {self.name} ONEOFF RESPONSE>',
            trial=self.trial
        )

        return response_text

    def call_llm_stateless(
        self,
        prompt: str,
        state: Optional[FuzzingWorkflowState] = None,
        log_prefix: str = "STATELESS"
    ) -> str:
        """
        Call LLM without conversation history (system + prompt only).

        Args:
            prompt: User prompt
            state: Optional state for tracking token usage
            log_prefix: Prefix for log messages

        Returns:
            LLM response
        """
        messages: List[BaseMessage] = [
            SystemMessage(content=self.system_message),
            HumanMessage(content=prompt)
        ]

        self._round += 1

        logger.debug(
            f'<AGENT {self.name} {log_prefix}>\n{prompt[:500]}...\n</AGENT {self.name} {log_prefix}>',
            trial=self.trial
        )

        # Detailed logging
        if self._langgraph_logger:
            prompt_metadata = {
                'model': self.model_name,
                'temperature': self.temperature,
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

        model = self.get_chat_model()
        response = model.invoke(messages)
        response_text = response.content if isinstance(response.content, str) else str(response.content)

        # Track token usage
        token_usage = self._extract_token_usage(response)
        if state and token_usage:
            from agent_graph.state import update_token_usage
            update_token_usage(
                state,
                self.name,
                token_usage.get('prompt_tokens', 0),
                token_usage.get('completion_tokens', 0),
                token_usage.get('total_tokens', 0)
            )

        # Detailed logging
        if self._langgraph_logger:
            response_metadata = {
                'model': self.model_name,
                'tokens': token_usage,
                'type': 'stateless (no conversation history)',
                'response_length': len(response_text)
            }
            self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response_text,
                round_num=self._round,
                metadata=response_metadata
            )

        logger.debug(
            f'<AGENT {self.name} {log_prefix} RESPONSE>\n{response_text[:500]}...\n</AGENT {self.name} {log_prefix} RESPONSE>',
            trial=self.trial
        )

        return response_text

    def _extract_token_usage(self, response: AIMessage) -> Optional[Dict[str, int]]:
        """Extract token usage from LangChain response if available."""
        # Token usage may be in response_metadata for some providers
        if hasattr(response, 'response_metadata') and response.response_metadata:
            usage = response.response_metadata.get('token_usage') or response.response_metadata.get('usage')
            if usage:
                return {
                    'prompt_tokens': usage.get('prompt_tokens', 0) or usage.get('input_tokens', 0),
                    'completion_tokens': usage.get('completion_tokens', 0) or usage.get('output_tokens', 0),
                    'total_tokens': usage.get('total_tokens', 0)
                }
        return None

    def truncate_tool_output(self, output: str, max_chars: int = 10000) -> str:
        """
        Truncate tool output to prevent context overflow.

        Args:
            output: Raw tool output string
            max_chars: Maximum characters to keep (default: 10000)

        Returns:
            Truncated output with indicator if truncated
        """
        if not output or len(output) <= max_chars:
            return output
        return output[:max_chars] + f"\n\n[... truncated {len(output) - max_chars} chars]"

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
