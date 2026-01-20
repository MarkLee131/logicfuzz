"""
Compatibility shim - imports from new location src/llm/adapter.py

This file is kept for backward compatibility. New code should import from src.llm.adapter.
"""

# Re-export everything from the new location
from src.llm.adapter import LLMAdapter, create_llm_adapter

__all__ = ["LLMAdapter", "create_llm_adapter"]
