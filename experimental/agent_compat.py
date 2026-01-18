"""Compatibility layer for BaseAgent used by build_generator and build_fixer."""
import argparse
from abc import ABC, abstractmethod
from typing import Any, Optional

import logger
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
    self.logger = logger.get_logger()
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

  @abstractmethod
  def execute(self, *args, **kwargs):
    """Execute the agent's main logic."""
    pass

