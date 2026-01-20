"""
Unified interface for loading all agent prompts.

Supports language-specific prompts for C vs C++ projects.
"""
import os
from typing import Dict, Optional


# Base directory for agent prompts (root/prompts/, not src/prompts/)
PROMPT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                 'prompts'))

# Mapping of language strings to file suffixes
LANGUAGE_SUFFIX_MAP = {
    'c': '_c',
    'c++': '_cpp',
    'cpp': '_cpp',
    'cxx': '_cpp',
}


def load_prompt_file(filename: str) -> str:
    """
    Load a prompt file from the prompts directory.

    Args:
        filename: Name of the prompt file

    Returns:
        Contents of the prompt file

    Raises:
        FileNotFoundError: If the prompt file doesn't exist
    """
    filepath = os.path.join(PROMPT_DIR, filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Prompt file not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


class PromptManager:
    """
    Manager for loading and caching prompts for LangGraph agents.

    Standard naming convention:
    - System prompt: {agent_name}_system.txt
    - User prompt: {agent_name}_prompt.txt
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def get_system_prompt(self, agent_name: str) -> str:
        """
        Get system prompt for an agent.

        Args:
            agent_name: Name of the agent (e.g., "prototyper")

        Returns:
            System prompt text from {agent_name}_system.txt
        """
        filename = f"{agent_name}_system.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def get_user_prompt_template(self, agent_name: str, language: Optional[str] = None) -> str:
        """
        Get user prompt template for an agent, optionally language-specific.

        Args:
            agent_name: Name of the agent (e.g., "prototyper")
            language: Optional language ("c", "c++", "cpp") for language-specific prompts

        Returns:
            User prompt template text from {agent_name}_prompt[_lang].txt
        """
        # Try language-specific prompt first if language is specified
        if language:
            lang_lower = language.lower()
            suffix = LANGUAGE_SUFFIX_MAP.get(lang_lower)
            if suffix:
                lang_filename = f"{agent_name}_prompt{suffix}.txt"
                lang_filepath = os.path.join(PROMPT_DIR, lang_filename)
                if os.path.exists(lang_filepath):
                    if lang_filename not in self._cache:
                        self._cache[lang_filename] = load_prompt_file(lang_filename)
                    return self._cache[lang_filename]

        # Fall back to default prompt
        filename = f"{agent_name}_prompt.txt"
        filepath = os.path.join(PROMPT_DIR, filename)

        # If default doesn't exist, try C++ as fallback (backward compatibility)
        if not os.path.exists(filepath):
            cpp_filename = f"{agent_name}_prompt_cpp.txt"
            cpp_filepath = os.path.join(PROMPT_DIR, cpp_filename)
            if os.path.exists(cpp_filepath):
                filename = cpp_filename

        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def build_user_prompt(self, agent_name: str, language: Optional[str] = None, **kwargs) -> str:
        """
        Build a user prompt by loading template and formatting it.

        Args:
            agent_name: Name of the agent
            language: Optional language ("c", "c++") for language-specific prompts
            **kwargs: Variables to substitute in the template

        Returns:
            Formatted user prompt
        """
        template = self.get_user_prompt_template(agent_name, language=language)
        result = template
        for key, value in kwargs.items():
            placeholder = "{" + key.upper() + "}"
            result = result.replace(placeholder, str(value))
        return result

    def get_session_memory_header(self) -> str:
        """Get session memory header template."""
        filename = "session_memory_header.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def get_session_memory_footer(self) -> str:
        """Get session memory footer template."""
        filename = "session_memory_footer.txt"
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def clear_cache(self):
        """Clear the prompt cache."""
        self._cache.clear()


# Global prompt manager instance
_prompt_manager = PromptManager()


def get_prompt_manager() -> PromptManager:
    """Get the global prompt manager instance."""
    return _prompt_manager
