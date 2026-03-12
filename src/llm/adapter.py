"""
LLM Adapter

Provides adapter classes that wrap LangChain chat models to provide
the interfaces expected by different components:
- query(prompt: str) -> str - for special_patterns.py, sequence_filter.py
- complete(prompt: str) -> str - for hole_filler.py
"""

from typing import Optional, Union
import logging

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage

logger = logging.getLogger(__name__)


class LLMAdapter:
    """
    Adapter that wraps a LangChain chat model to provide simplified interfaces.

    This adapter converts the chat-based interface to simpler prompt-response
    interfaces (query, complete).
    """

    def __init__(self, chat_model: BaseChatModel):
        """
        Initialize adapter with a LangChain chat model.

        Args:
            chat_model: A LangChain BaseChatModel instance
        """
        self.chat_model = chat_model

    def query(self, prompt: str) -> str:
        """
        Send a prompt and get a response.

        This method wraps the prompt in a HumanMessage and invokes the model.

        Args:
            prompt: The prompt text

        Returns:
            The LLM response text
        """
        try:
            response = self.chat_model.invoke([HumanMessage(content=prompt)])
            content = response.content
            # Handle case where content might be a list (multimodal response)
            if isinstance(content, list):
                return "".join(str(item) for item in content)
            return str(content) if content else ""
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


def create_llm_adapter(
        model: Union[BaseChatModel, str, None]) -> Optional[LLMAdapter]:
    """
    Create an LLM adapter from a model.

    Args:
        model: A LangChain BaseChatModel, a model name string, or None

    Returns:
        LLMAdapter wrapping the model, or None if model is None
    """
    if model is None:
        return None

    # If it's a string, create the model from registry
    if isinstance(model, str):
        from src.llm.models import get_chat_model
        model = get_chat_model(model)

    return LLMAdapter(model)
