"""
Prompt Loader for Liberator Adapter

Unified loading of all prompts used by liberator_adapter module.
Prompts are stored in prompts/ directory, managed as files.
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

    Supported prompts:
    - varlen_analyzer_prompt.txt - Var-len relationship analysis
    - loop_analyzer_prompt.txt - Loop pattern analysis
    - callback_analyzer_prompt.txt - Callback function analysis
    - tlv_analyzer_prompt.txt - TLV format analysis
    - lifecycle_classify_prompt.txt - Lifecycle classification
    - lifecycle_validate_sequence_prompt.txt - Sequence validation
    - lifecycle_batch_classify_prompt.txt - Batch classification
    - hole_callback_impl_prompt.txt - Callback implementation hole
    - hole_loop_condition_prompt.txt - Loop condition hole
    - hole_error_handling_prompt.txt - Error handling hole
    - hole_resource_cleanup_prompt.txt - Resource cleanup hole
    - hole_param_constraint_prompt.txt - Parameter constraint hole
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def _get_prompt(self, filename: str) -> str:
        """Load and cache prompt"""
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def _format_prompt(self, template: str, **kwargs) -> str:
        """Format prompt template"""
        result = template
        for key, value in kwargs.items():
            placeholder = "{" + key + "}"
            result = result.replace(placeholder, str(value))
        return result

    # =========================================================================
    # Special Patterns Prompts
    # =========================================================================

    def get_varlen_prompt(self, signature: str, parameters: str) -> str:
        """Get Var-len analysis prompt"""
        template = self._get_prompt("varlen_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   parameters=parameters)

    def get_loop_prompt(self, signature: str, return_type: str,
                        parameters: str) -> str:
        """Get loop pattern analysis prompt"""
        template = self._get_prompt("loop_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   return_type=return_type,
                                   parameters=parameters)

    def get_callback_prompt(self, signature: str, callback_param: str,
                            callback_type: str) -> str:
        """Get callback analysis prompt"""
        template = self._get_prompt("callback_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   callback_param=callback_param,
                                   callback_type=callback_type)

    def get_tlv_prompt(self, signature: str) -> str:
        """Get TLV analysis prompt"""
        template = self._get_prompt("tlv_analyzer_prompt.txt")
        return self._format_prompt(template, signature=signature)

    # =========================================================================
    # Lifecycle Prompts
    # =========================================================================

    def get_lifecycle_classify_prompt(self, api_name: str, signature: str,
                                      return_type: str, parameters: str) -> str:
        """Get lifecycle classification prompt"""
        template = self._get_prompt("lifecycle_classify_prompt.txt")
        return self._format_prompt(template,
                                   api_name=api_name,
                                   signature=signature,
                                   return_type=return_type,
                                   parameters=parameters)

    def get_lifecycle_validate_prompt(self, api_sequence: str) -> str:
        """Get sequence validation prompt"""
        template = self._get_prompt("lifecycle_validate_sequence_prompt.txt")
        return self._format_prompt(template, api_sequence=api_sequence)

    def get_lifecycle_batch_classify_prompt(self, api_list: str) -> str:
        """Get batch classification prompt"""
        template = self._get_prompt("lifecycle_batch_classify_prompt.txt")
        return self._format_prompt(template, api_list=api_list)

    # =========================================================================
    # Hole Filling Prompts
    # =========================================================================

    def get_hole_callback_impl_prompt(self, callback_signature: str,
                                      callback_type: str,
                                      expected_behavior: str = "") -> str:
        """Get callback implementation hole prompt"""
        template = self._get_prompt("hole_callback_impl_prompt.txt")
        return self._format_prompt(template,
                                   callback_signature=callback_signature,
                                   callback_type=callback_type,
                                   expected_behavior=expected_behavior or "Generic callback stub")

    def get_hole_loop_condition_prompt(self, loop_type: str,
                                       api_return_type: str,
                                       termination_hint: str = "") -> str:
        """Get loop condition hole prompt"""
        template = self._get_prompt("hole_loop_condition_prompt.txt")
        return self._format_prompt(template,
                                   loop_type=loop_type,
                                   api_return_type=api_return_type,
                                   termination_hint=termination_hint or "None")

    def get_hole_error_handling_prompt(self, error_source: str,
                                       error_type: str,
                                       cleanup_list: str) -> str:
        """Get error handling hole prompt"""
        template = self._get_prompt("hole_error_handling_prompt.txt")
        return self._format_prompt(template,
                                   error_source=error_source,
                                   error_type=error_type,
                                   cleanup_list=cleanup_list)

    def get_hole_resource_cleanup_prompt(self, resources: str,
                                         cleanup_order: str) -> str:
        """Get resource cleanup hole prompt"""
        template = self._get_prompt("hole_resource_cleanup_prompt.txt")
        return self._format_prompt(template,
                                   resources=resources,
                                   cleanup_order=cleanup_order)

    def get_hole_param_constraint_prompt(self, param_name: str,
                                         param_type: str) -> str:
        """Get parameter constraint hole prompt"""
        template = self._get_prompt("hole_param_constraint_prompt.txt")
        return self._format_prompt(template,
                                   param_name=param_name,
                                   param_type=param_type)

    # =========================================================================
    # Raw Template Access
    # =========================================================================

    def get_raw_template(self, prompt_name: str) -> str:
        """
        Get raw prompt template (unformatted)

        Args:
            prompt_name: Prompt file name (without .txt)

        Returns:
            Raw template content
        """
        return self._get_prompt(f"{prompt_name}_prompt.txt")

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
