"""
Prompt Loader for Liberator Adapter

统一加载liberator_adapter模块使用的所有prompts。
Prompts存储在 prompts/ 目录下，以文件形式管理。
"""

import os
from typing import Dict, Optional


# Prompts目录路径
PROMPT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'prompts')
)


def load_prompt_file(filename: str) -> str:
    """
    从prompts目录加载prompt文件

    Args:
        filename: 文件名

    Returns:
        Prompt内容

    Raises:
        FileNotFoundError: 文件不存在时抛出
    """
    filepath = os.path.join(PROMPT_DIR, filename)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Prompt file not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


class LiberatorPromptManager:
    """
    Liberator Adapter的Prompt管理器

    支持的prompts:
    - varlen_analyzer_prompt.txt - Var-len关系分析
    - loop_analyzer_prompt.txt - 循环模式分析
    - callback_analyzer_prompt.txt - 回调函数分析
    - tlv_analyzer_prompt.txt - TLV格式分析
    - lifecycle_classify_prompt.txt - 生命周期分类
    - lifecycle_validate_sequence_prompt.txt - 序列验证
    - lifecycle_batch_classify_prompt.txt - 批量分类
    - hole_callback_impl_prompt.txt - 回调实现孔
    - hole_loop_condition_prompt.txt - 循环条件孔
    - hole_error_handling_prompt.txt - 错误处理孔
    - hole_resource_cleanup_prompt.txt - 资源清理孔
    - hole_param_constraint_prompt.txt - 参数约束孔
    """

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def _get_prompt(self, filename: str) -> str:
        """加载并缓存prompt"""
        if filename not in self._cache:
            self._cache[filename] = load_prompt_file(filename)
        return self._cache[filename]

    def _format_prompt(self, template: str, **kwargs) -> str:
        """格式化prompt模板"""
        result = template
        for key, value in kwargs.items():
            placeholder = "{" + key + "}"
            result = result.replace(placeholder, str(value))
        return result

    # =========================================================================
    # Special Patterns Prompts
    # =========================================================================

    def get_varlen_prompt(self, signature: str, parameters: str) -> str:
        """获取Var-len分析prompt"""
        template = self._get_prompt("varlen_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   parameters=parameters)

    def get_loop_prompt(self, signature: str, return_type: str,
                        parameters: str) -> str:
        """获取循环模式分析prompt"""
        template = self._get_prompt("loop_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   return_type=return_type,
                                   parameters=parameters)

    def get_callback_prompt(self, signature: str, callback_param: str,
                            callback_type: str) -> str:
        """获取回调分析prompt"""
        template = self._get_prompt("callback_analyzer_prompt.txt")
        return self._format_prompt(template,
                                   signature=signature,
                                   callback_param=callback_param,
                                   callback_type=callback_type)

    def get_tlv_prompt(self, signature: str) -> str:
        """获取TLV分析prompt"""
        template = self._get_prompt("tlv_analyzer_prompt.txt")
        return self._format_prompt(template, signature=signature)

    # =========================================================================
    # Lifecycle Prompts
    # =========================================================================

    def get_lifecycle_classify_prompt(self, api_name: str, signature: str,
                                      return_type: str, parameters: str) -> str:
        """获取生命周期分类prompt"""
        template = self._get_prompt("lifecycle_classify_prompt.txt")
        return self._format_prompt(template,
                                   api_name=api_name,
                                   signature=signature,
                                   return_type=return_type,
                                   parameters=parameters)

    def get_lifecycle_validate_prompt(self, api_sequence: str) -> str:
        """获取序列验证prompt"""
        template = self._get_prompt("lifecycle_validate_sequence_prompt.txt")
        return self._format_prompt(template, api_sequence=api_sequence)

    def get_lifecycle_batch_classify_prompt(self, api_list: str) -> str:
        """获取批量分类prompt"""
        template = self._get_prompt("lifecycle_batch_classify_prompt.txt")
        return self._format_prompt(template, api_list=api_list)

    # =========================================================================
    # Hole Filling Prompts
    # =========================================================================

    def get_hole_callback_impl_prompt(self, callback_signature: str,
                                      callback_type: str,
                                      expected_behavior: str = "") -> str:
        """获取回调实现孔prompt"""
        template = self._get_prompt("hole_callback_impl_prompt.txt")
        return self._format_prompt(template,
                                   callback_signature=callback_signature,
                                   callback_type=callback_type,
                                   expected_behavior=expected_behavior or "Generic callback stub")

    def get_hole_loop_condition_prompt(self, loop_type: str,
                                       api_return_type: str,
                                       termination_hint: str = "") -> str:
        """获取循环条件孔prompt"""
        template = self._get_prompt("hole_loop_condition_prompt.txt")
        return self._format_prompt(template,
                                   loop_type=loop_type,
                                   api_return_type=api_return_type,
                                   termination_hint=termination_hint or "None")

    def get_hole_error_handling_prompt(self, error_source: str,
                                       error_type: str,
                                       cleanup_list: str) -> str:
        """获取错误处理孔prompt"""
        template = self._get_prompt("hole_error_handling_prompt.txt")
        return self._format_prompt(template,
                                   error_source=error_source,
                                   error_type=error_type,
                                   cleanup_list=cleanup_list)

    def get_hole_resource_cleanup_prompt(self, resources: str,
                                         cleanup_order: str) -> str:
        """获取资源清理孔prompt"""
        template = self._get_prompt("hole_resource_cleanup_prompt.txt")
        return self._format_prompt(template,
                                   resources=resources,
                                   cleanup_order=cleanup_order)

    def get_hole_param_constraint_prompt(self, param_name: str,
                                         param_type: str) -> str:
        """获取参数约束孔prompt"""
        template = self._get_prompt("hole_param_constraint_prompt.txt")
        return self._format_prompt(template,
                                   param_name=param_name,
                                   param_type=param_type)

    # =========================================================================
    # Raw Template Access
    # =========================================================================

    def get_raw_template(self, prompt_name: str) -> str:
        """
        获取原始prompt模板（不格式化）

        Args:
            prompt_name: prompt文件名（不含.txt）

        Returns:
            原始模板内容
        """
        return self._get_prompt(f"{prompt_name}_prompt.txt")

    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()


# 全局实例
_prompt_manager: Optional[LiberatorPromptManager] = None


def get_prompt_manager() -> LiberatorPromptManager:
    """获取全局PromptManager实例"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = LiberatorPromptManager()
    return _prompt_manager
