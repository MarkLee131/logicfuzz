"""
LangChain-based LLM models for LogicFuzz.

This module provides a unified interface for LLM providers that support tool calling.
Supported providers: OpenAI, DeepSeek, Anthropic Claude.
"""

import logging
import os
from typing import Any, Callable, Dict, List

from langchain_core.language_models import BaseChatModel
from langchain_core.runnables import Runnable

logger = logging.getLogger(__name__)

# Default parameters
MAX_TOKENS: int = 4096
TEMPERATURE: float = 0.4
DEFAULT_MODEL = "gpt-5.2"


def _create_openai_model(model_name: str,
                         temperature: float = TEMPERATURE,
                         max_tokens: int = MAX_TOKENS,
                         **kwargs) -> BaseChatModel:
    """Create an OpenAI chat model."""
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model=model_name,
                      temperature=temperature,
                      max_tokens=max_tokens,
                      **kwargs)


def _create_deepseek_model(model_name: str = "deepseek-chat",
                           temperature: float = TEMPERATURE,
                           max_tokens: int = MAX_TOKENS,
                           **kwargs) -> BaseChatModel:
    """Create a DeepSeek chat model (OpenAI-compatible API)."""
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model=model_name,
                      base_url="https://api.deepseek.com",
                      api_key=os.getenv("DEEPSEEK_API_KEY"),
                      temperature=temperature,
                      max_tokens=max_tokens,
                      **kwargs)


# Model registry: maps model names to factory functions
# Only models with tool calling support are included
MODEL_REGISTRY: Dict[str, Callable[..., BaseChatModel]] = {
    # OpenAI models (all support tool calling)
    "gpt-5.2":
    lambda **kw: _create_openai_model("gpt-5.2", **kw),
    "gpt-5-mini":
    lambda **kw: _create_openai_model("gpt-5-mini", **kw),
    "gpt-4o":
    lambda **kw: _create_openai_model("gpt-4o", **kw),
    "gpt-4o-mini":
    lambda **kw: _create_openai_model("gpt-4o-mini", **kw),

    # DeepSeek models (OpenAI-compatible, support tool calling).
    # deepseek-chat IS DeepSeek V3. Override max_tokens to 8192 (the API maximum
    # for deepseek-chat; default is 4096) so the Prototyper doesn't truncate large
    # multi-API drivers. 8192 is the hard output ceiling — higher is rejected.
    # NOTE: there is no DeepSeek "V4" — the API exposes only deepseek-chat (V3)
    # and deepseek-reasoner (R1); add deepseek-reasoner here if R1 is wanted.
    "deepseek-V3":
    lambda **kw: _create_deepseek_model("deepseek-chat", **{**kw, "max_tokens": 8192}),
}


def get_chat_model(name: str,
                   temperature: float = TEMPERATURE,
                   max_tokens: int = MAX_TOKENS,
                   **kwargs) -> BaseChatModel:
    """
    Get a LangChain chat model by name.

    Args:
        name: Model name (e.g., "gpt-5.2", "gpt-4o", "deepseek-chat", "claude-3-5-sonnet")
        temperature: Sampling temperature (default: 0.4)
        max_tokens: Maximum tokens for response (default: 4096)
        **kwargs: Additional arguments passed to the model constructor

    Returns:
        LangChain BaseChatModel instance

    Raises:
        ValueError: If model name is not recognized
    """
    if name not in MODEL_REGISTRY:
        raise ValueError(
            f"Unknown model: {name}. Available: {list(MODEL_REGISTRY.keys())}")
    return MODEL_REGISTRY[name](temperature=temperature,
                                max_tokens=max_tokens,
                                **kwargs)


def get_available_models() -> List[str]:
    """Return list of available model names."""
    return list(MODEL_REGISTRY.keys())


