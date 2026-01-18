"""Prompt class for LLM interactions."""
from typing import Any, Dict, List, Optional


class Prompt:
  """Prompt wrapper for LLM interactions."""
  
  def __init__(self, content: str = "", messages: Optional[List[Dict[str, str]]] = None):
    """Initialize prompt.
    
    Args:
      content: Prompt content as string
      messages: Optional list of message dicts with 'role' and 'content'
    """
    self.content = content
    if messages:
      self.messages = messages
    else:
      self.messages = [{"role": "user", "content": content}]
  
  def __str__(self) -> str:
    """Return prompt as string."""
    return self.content or "\n".join([msg.get("content", "") for msg in self.messages])
  
  def __repr__(self) -> str:
    """Return prompt representation."""
    return f"Prompt(content={self.content!r}, messages={len(self.messages)} messages)"

