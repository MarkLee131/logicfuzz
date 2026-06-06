"""
Prompt Loader for Liberator Adapter

NOTE: Most prompt-loading methods have been removed because the corresponding
LLM calls were disabled in favor of heuristic-based analysis.

Kept for potential future use if LLM-based analysis is re-enabled.
"""

import os
from typing import Dict, Optional


# Prompts directory path
PROMPT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'prompts')
)


def load_prompt_file(filename: str) -> str:
    """
    Load prompt file from prompts directory

    Args:
        filename: File name

    Returns:
        Prompt content

    Raises:
        FileNotFoundError: Raised when file does not exist
    """
    filepath = os.path.join(PROMPT_DIR, filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Prompt file not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


class LiberatorPromptManager:
    """
    Prompt manager for Liberator Adapter

    NOTE: Most methods removed - LLM-based pattern analysis disabled.
    Using heuristics instead for VarLen, Loop, Callback, TLV, Lifecycle analysis.
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def _get_prompt(self, filename: str) -> str:
        """Load and cache prompt"""
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]



    def clear_cache(self):
        """Clear cache"""
        self._cache.clear()


# Global instance
_prompt_manager: Optional[LiberatorPromptManager] = None


def get_prompt_manager() -> LiberatorPromptManager:
    """Get global PromptManager instance"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = LiberatorPromptManager()
    return _prompt_manager
