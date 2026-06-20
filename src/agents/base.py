"""
LangGraph-native agent base class using LangChain models.

This module provides a clean agent interface designed for LangGraph,
using LangChain's native message types and model interfaces.
"""
from abc import ABC, abstractmethod
import time
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
from src.llm.models import get_chat_model, DEFAULT_MODEL
from src.workflow.state import FuzzingWorkflowState


# Network-level errors that warrant a retry of ``model.invoke``. We
# *do not* retry on RateLimitError / AuthenticationError / etc — the
# LangChain providers already implement their own backoff for those,
# and re-retrying compounds the wait. We also do not retry on
# ValueError / TypeError / JSON-parse exceptions — those indicate a
# bug in our prompt or response parsing, not a transient issue.
#
# 2026-05 Agent review (cluster F).
_RETRIABLE_NETWORK_EXCEPTIONS = (
    TimeoutError,
    ConnectionError,
    OSError,  # broad but covers socket-level failures
)


def _invoke_with_retry(model: BaseChatModel, messages: List[BaseMessage],
                       max_attempts: int = 2,
                       initial_backoff_seconds: float = 1.0):
    """Invoke a LangChain chat model, retrying on transient network errors.

    Returns the model's response on success; re-raises on the final
    failure or on any non-retriable exception. ``max_attempts=2``
    means one initial try + one retry by default (matches typical
    transient-fault windows without amplifying rate-limit waits).
    """
    last_exc: Optional[BaseException] = None
    backoff = float(initial_backoff_seconds)
    for attempt in range(max_attempts):
        try:
            return model.invoke(messages)
        except _RETRIABLE_NETWORK_EXCEPTIONS as exc:
            last_exc = exc
            if attempt == max_attempts - 1:
                # Final attempt failed; let it propagate.
                raise
            time.sleep(backoff)
            backoff *= 2
    # Unreachable; placate the type checker.
    raise last_exc if last_exc else RuntimeError("retry loop exited without resolution")


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

    def get_chat_model(self) -> BaseChatModel:
        """
        Get the LangChain chat model for this agent.

        Returns:
            BaseChatModel instance
        """
        if self._chat_model is None:
            self._chat_model = get_chat_model(self.model_name,
                                              temperature=self.temperature,
                                              max_tokens=self.max_tokens)
        return self._chat_model

    def _messages_to_langchain(
            self, messages: List[Dict[str, str]]) -> List[BaseMessage]:
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

    def truncate_tool_output(self, output: str, max_chars: int = 8000) -> str:
        """
        Truncate tool output to prevent context overflow.

        Default 8000 chars (~8KB) matches the CLAUDE.md "8KB output
        truncation" claim. Was 10000 historically; aligned in the
        2026-05 Agent review (cluster A) so every agent uses the
        same cap.

        Args:
            output: Raw tool output string
            max_chars: Maximum characters to keep (default: 8000)

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
