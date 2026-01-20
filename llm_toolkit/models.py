"""
Compatibility shim - imports from new location src/llm/models.py

This file is kept for backward compatibility. New code should import from src.llm.models.
"""

# Re-export everything from the new location
from src.llm.models import (
    get_chat_model,
    get_available_models,
    get_model_with_tools,
    DEFAULT_MODEL,
    MAX_TOKENS,
    TEMPERATURE,
    MODEL_REGISTRY,
)

__all__ = [
    "get_chat_model",
    "get_available_models",
    "get_model_with_tools",
    "DEFAULT_MODEL",
    "MAX_TOKENS",
    "TEMPERATURE",
    "MODEL_REGISTRY",
]
