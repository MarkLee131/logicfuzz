"""Compatibility layer for BaseAgent used by build_generator and build_fixer."""
import argparse
import subprocess as sp
from abc import ABC, abstractmethod
from typing import Any, Optional

import logging
from llm_toolkit.models import LLM
from tool.base_tool import BaseTool


class BaseAgent(ABC):
  """Base class for agents used in build generation and fixing.
  
  This is a compatibility layer for experimental modules that haven't migrated
  to the new agent_graph architecture yet.
  """

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               tools: Optional[list[BaseTool]] = None,
               name: str = ''):
    """Initialize base agent.
    
    Args:
      trial: Trial number
      llm: LLM instance
      args: Command line arguments
      tools: Optional list of tools
      name: Agent name
    """
    self.trial = trial
    self.llm = llm
    self.args = args
    self.tools = tools or []
    self.name = name or self.__class__.__name__
    self.logger = logging.getLogger(self.name)
    self.max_round = getattr(args, 'max_round', 10)

  def chat_llm(self, round_num: int, client: Any, prompt: Any, trial: int) -> str:
    """Chat with LLM - compatibility method for build_generator.
    
    Args:
      round_num: Round number
      client: LLM client
      prompt: Prompt object (from llm_toolkit.prompts.Prompt)
      trial: Trial number
      
    Returns:
      LLM response as string
    """
    # Convert Prompt to messages format if needed
    if hasattr(prompt, 'messages'):
      messages = prompt.messages
    elif hasattr(prompt, 'content'):
      messages = [{"role": "user", "content": str(prompt)}]
    else:
      messages = [{"role": "user", "content": str(prompt)}]
    
    # Use LLM's chat_llm method
    return self.llm.chat_llm(client, messages)

  def _format_bash_execution_result(
      self,
      process: sp.CompletedProcess,
      previous_prompt: Optional[Any] = None) -> str:
    """Formats a prompt based on bash execution result."""
    if previous_prompt:
      previous_prompt_text = str(previous_prompt)
    else:
      previous_prompt_text = ''
    stdout = self.llm.truncate_prompt(process.stdout,
                                      previous_prompt_text).strip()
    stderr = self.llm.truncate_prompt(process.stderr,
                                      stdout + previous_prompt_text).strip()
    return (f'<bash>\n{process.args}\n</bash>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{stdout}\n</stdout>\n'
            f'<stderr>\n{stderr}\n</stderr>\n')

  @abstractmethod
  def execute(self, *args, **kwargs):
    """Execute the agent's main logic."""
    pass

