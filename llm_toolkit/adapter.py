"""
LLM Adapter

Provides adapter classes that wrap LLM models to provide
the interfaces expected by different components:
- query(prompt: str) -> str - for special_patterns.py, sequence_filter.py
- complete(prompt: str) -> str - for hole_filler.py
"""

from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


class LLMAdapter:
    """
    Adapter that wraps an LLM model object to provide simplified interfaces.

    This adapter converts the chat-based interface (chat_with_messages)
    to simpler prompt-response interfaces (query, complete).
    """

    def __init__(self, llm_model: Any):
        """
        Initialize adapter with an LLM model.

        Args:
            llm_model: An LLM model object that has chat_with_messages() method
        """
        self.llm_model = llm_model

    def query(self, prompt: str) -> str:
        """
        Send a prompt and get a response.

        This method wraps the prompt in a user message and calls
        chat_with_messages().

        Args:
            prompt: The prompt text

        Returns:
            The LLM response text
        """
        messages = [{"role": "user", "content": prompt}]
        try:
            response = self.llm_model.chat_with_messages(messages)
            return response
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            raise

    def complete(self, prompt: str) -> str:
        """
        Complete a prompt (alias for query).

        Args:
            prompt: The prompt text

        Returns:
            The completion text
        """
        return self.query(prompt)


def create_llm_adapter(llm_model: Any) -> Optional[LLMAdapter]:
    """
    Create an LLM adapter from an LLM model.

    Args:
        llm_model: An LLM model object, or None

    Returns:
        LLMAdapter wrapping the model, or None if model is None
    """
    if llm_model is None:
        return None
    return LLMAdapter(llm_model)
