"""
LLM models and their functions.
"""

import logging
import math
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import traceback
from abc import abstractmethod
from typing import Any, Callable, Optional, Type
import openai
import tiktoken

logger = logging.getLogger(__name__)

# Model hyper-parameters.
MAX_TOKENS: int = 2000
NUM_SAMPLES: int = 1
TEMPERATURE: float = 0.4

class LLM:
  """Base LLM."""

  # Should be set by the subclass.
  name: str
  context_window: int = 2000  # Default token size.

  MAX_INPUT_TOKEN: int = sys.maxsize

  _max_attempts = 5  # Maximum number of attempts to get prediction response

  def __init__(
      self,
      ai_binary: str,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
  ):
    self.ai_binary = ai_binary

    # Model parameters.
    self.max_tokens = max_tokens
    self.num_samples = num_samples
    self.temperature = temperature
    self.temperature_list = temperature_list

  def cloud_setup(self):
    """Runs Cloud specific-setup."""
    # Only a subset of models need a cloud specific set up, so
    # we can pass for the remainder of the models as they don't
    # need to implement specific handling of this.

  @classmethod
  def setup(
      cls,
      ai_binary: str,
      name: str,
      max_tokens: int = MAX_TOKENS,
      num_samples: int = NUM_SAMPLES,
      temperature: float = TEMPERATURE,
      temperature_list: Optional[list[float]] = None,
  ):
    """Prepares the LLM for fuzz target generation."""
    for subcls in cls.all_llm_subclasses():
      if getattr(subcls, 'name', None) == name:
        return subcls(
            ai_binary,
            max_tokens,
            num_samples,
            temperature,
            temperature_list,
        )

    raise ValueError(f'Bad model type {name}')

  @classmethod
  def all_llm_subclasses(cls):
    """All subclasses."""
    yield cls
    for subcls in cls.__subclasses__():
      yield from subcls.all_llm_subclasses()

  @classmethod
  def all_llm_names(cls):
    """Returns the current model name and all child model names."""
    names = set()
    for subcls in cls.all_llm_subclasses():
      if hasattr(subcls, 'name') and subcls.name:
        names.add(subcls.name)
    return list(names)

  @abstractmethod
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""

  # ============================== Generation ============================== #
  @abstractmethod
  def chat_llm(self, client: Any, messages: list[dict[str, str]]) -> str:
    """Queries the LLM in the given chat session and returns the response."""

  def chat_with_messages(self, messages: list[dict[str, str]]) -> str:
    """
    Chat with LLM using a list of messages.
    
    This is a convenience method for LangGraph agents that work with message lists.
    
    Args:
        messages: List of message dicts with 'role' and 'content' keys
    
    Returns:
        LLM response text
    """
    # Get or create a client
    client = self.get_chat_client(None)
    
    # Call the existing chat_llm method directly with messages
    # Note: prompt_type() returned typing.Any which cannot be instantiated.
    # Modern LLMs accept message lists directly without a wrapper class.
    return self.chat_llm(client, messages)
  
  def chat_with_tools(
      self,
      messages: list[dict[str, str]],
      tools: list[dict[str, Any]]
  ) -> dict[str, Any]:
    """
    Chat with LLM and provide tool definitions for function calling.
    
    This method enables LLM to call tools (functions) as needed. The LLM
    will return either a text response or tool calls.
    
    Args:
        messages: List of message dicts with 'role' and 'content' keys
        tools: List of tool definitions in OpenAI function calling format:
            [{
                "type": "function",
                "function": {
                    "name": "tool_name",
                    "description": "Tool description",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "param_name": {
                                "type": "string",
                                "description": "Parameter description"
                            }
                        },
                        "required": ["param_name"]
                    }
                }
            }]
    
    Returns:
        Dictionary containing:
        {
            "content": str,  # LLM response text (may be None if only tool calls)
            "tool_calls": [  # List of tool calls (empty if no tools called)
                {
                    "id": str,  # Unique call ID
                    "name": str,  # Tool name
                    "arguments": dict  # Tool arguments as dict
                }
            ]
        }
    """
    # Default implementation raises NotImplementedError
    # Subclasses should override this if they support tool calling
    raise NotImplementedError(
        f"{self.__class__.__name__} does not support tool calling. "
        "Please use a model that supports function calling (e.g., GPT-4, GPT-4o)."
    )

  @abstractmethod
  def get_model(self) -> Any:
    """Returns the underlying model instance."""


  def _delay_for_retry(self, attempt_count: int) -> None:
    """Sleeps for a while based on the |attempt_count|."""
    # Exponentially increase from 5 to 80 seconds + some random to jitter.
    delay = 5 * 2**attempt_count + random.randint(1, 5)
    logging.warning('Retry in %d seconds...', delay)
    time.sleep(delay)

  def _is_retryable_error(self, err: Exception,
                          api_errors: list[Type[Exception]],
                          tb: traceback.StackSummary) -> bool:
    """Validates if |err| is worth retrying."""
    if any(isinstance(err, api_error) for api_error in api_errors):
      return True

    # A known case from vertex package, no content due to mismatch roles.
    if (isinstance(err, ValueError) and
        'Content roles do not match' in str(err) and tb[-1].filename.endswith(
            'vertexai/generative_models/_generative_models.py')):
      return True

    # A known case from vertex package, content blocked by safety filters.
    if (isinstance(err, ValueError) and
        'blocked by the safety filters' in str(err) and
        tb[-1].filename.endswith(
            'vertexai/generative_models/_generative_models.py')):
      return True

    return False

  def _save_prompt_on_error(self, err: Exception, prompt_data: Any) -> None:
    """Save prompt to file when encountering token limit or other errors."""
    import json
    from datetime import datetime
    
    # Check if it's a token limit error
    is_token_error = False
    error_str = str(err)
    
    if any(keyword in error_str.lower() for keyword in [
        'context_length_exceeded', 'token', 'too long', 'max_tokens',
        'input tokens exceed', 'context length'
    ]):
      is_token_error = True
    
    if not is_token_error:
      return  # Only save for token errors
    
    # Create error_prompts directory if it doesn't exist
    error_dir = os.path.join(os.getcwd(), 'error_prompts')
    os.makedirs(error_dir, exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'token_error_{timestamp}.json'
    filepath = os.path.join(error_dir, filename)
    
    # Prepare data to save
    save_data = {
      'timestamp': timestamp,
      'error_message': error_str,
      'model_name': getattr(self, 'name', 'unknown'),
      'prompt_data': prompt_data,
    }
    
    # Try to extract token count from error message
    import re
    token_match = re.search(r'(\d+)\s*tokens', error_str)
    if token_match:
      save_data['token_count'] = int(token_match.group(1))
    
    limit_match = re.search(r'limit of (\d+)', error_str)
    if limit_match:
      save_data['token_limit'] = int(limit_match.group(1))
    
    try:
      with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(save_data, f, indent=2, ensure_ascii=False)
      
      logging.error(
          f'Token limit exceeded! Prompt saved to: {filepath}')
      logging.error(
          f'Token usage: {save_data.get("token_count", "unknown")} / '
          f'{save_data.get("token_limit", "unknown")}')
    except Exception as save_err:
      logging.error(f'Failed to save prompt: {save_err}')

  def _is_token_limit_error(self, err: Exception) -> bool:
    """Check if the error is a token limit error."""
    error_str = str(err).lower()
    return any(keyword in error_str for keyword in [
        'context_length_exceeded', 
        'input tokens exceed',
        'max_tokens',
        'token limit',
        'context length'
    ])

  def with_retry_on_error(self, func: Callable,
                          api_errs: list[Type[Exception]]) -> Any:
    """
    Retry when the function returns an expected error with exponential backoff.
    """
    for attempt in range(1, self._max_attempts + 1):
      try:
        return func()
      except Exception as err:
        logging.warning('LLM API Error when responding (attempt %d): %s',
                        attempt, err)
        
        # Check if it's a token limit error
        is_token_error = self._is_token_limit_error(err)
        
        # Save prompt on token limit error (first attempt only)
        if attempt == 1 and is_token_error:
          try:
            # Try to get prompt data from self.messages or self.conversation_history
            prompt_data = None
            if hasattr(self, 'messages') and self.messages:
              prompt_data = self.messages
            elif hasattr(self, 'conversation_history') and self.conversation_history:
              prompt_data = self.conversation_history
            
            if prompt_data:
              self._save_prompt_on_error(err, prompt_data)
          except Exception as save_err:
            logging.warning(f'Failed to save error prompt: {save_err}')
        
        if is_token_error:
          logging.error(
              'Token limit error is not retryable. Failing immediately.')
          logging.error(
              'Please check error_prompts/ directory for the saved prompt.')
          raise err
        
        tb = traceback.extract_tb(err.__traceback__)
        if (not self._is_retryable_error(err, api_errs, tb) or
            attempt == self._max_attempts):
          logging.warning(
              'LLM API cannot fix error when responding (attempt %d) %s: %s',
              attempt, err, traceback.format_exc())
          raise err
        self._delay_for_retry(attempt_count=attempt)
    return None

  def _save_output(self, index: int, content: str, response_dir: str) -> None:
    """Saves the raw |content| from the model ouput."""
    sample_id = index + 1
    raw_output_path = os.path.join(response_dir, f'{sample_id:02}.rawoutput')
    with open(raw_output_path, 'w+') as output_file:
      output_file.write(content)

  def truncate_prompt(self,
                      raw_prompt_text: Any,
                      extra_text: Any = None) -> Any:
    """Truncates the prompt text to fit in MAX_INPUT_TOKEN."""
    del extra_text
    return raw_prompt_text

  @abstractmethod
  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""

class GPT(LLM):
  """OpenAI's GPT model encapsulator."""

  name = 'gpt-3.5-turbo'

  def get_model(self) -> Any:
    """Returns the underlying model instance."""
    # Placeholder: No suitable implementation/usage yet.

  def get_chat_client(self, model: Any) -> Any:
    """Returns a new chat session."""
    return self._get_client()

  def _get_tiktoken_encoding(self, model_name: str):
    """Returns the tiktoken encoding for the model."""
    try:
      return tiktoken.encoding_for_model(model_name)
    except KeyError:
      logger.info('Could not get a tiktoken encoding for %s.', model_name)
      return tiktoken.get_encoding('cl100k_base')

  def _get_client(self):
    """Returns the OpenAI client."""
    return openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

  # ================================ Prompt ================================ #
  def estimate_token_num(self, text) -> int:
    """Estimates the number of tokens in |text|."""

    encoder = self._get_tiktoken_encoding(self.name)

    if isinstance(text, str):
      return len(encoder.encode(text))

    num_tokens = 0
    for message in text:
      num_tokens += 3
      for key, value in message.items():
        num_tokens += len(encoder.encode(value))
        if key == 'name':
          num_tokens += 1
    num_tokens += 3

    return num_tokens


  def chat_llm(self, client: Any, messages: list[dict[str, str]]) -> str:
    """Queries LLM in a chat session and returns its response."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=messages,
                                               model=self.name,
                                               n=self.num_samples,
                                               temperature=self.temperature),
        [openai.OpenAIError])

    # Store token usage info for later retrieval
    self.last_token_usage = {
          'prompt_tokens': completion.usage.prompt_tokens,
          'completion_tokens': completion.usage.completion_tokens,
          'total_tokens': completion.usage.total_tokens
      }


    llm_response = completion.choices[0].message.content

    return llm_response

  def chat_with_tools(
      self,
      messages: list[dict[str, str]],
      tools: list[dict[str, Any]]
  ) -> dict[str, Any]:
    """
    Chat with LLM using OpenAI function calling.
    
    Args:
        messages: List of message dicts with 'role' and 'content' keys
        tools: List of tool definitions in OpenAI function calling format
    
    Returns:
        Dictionary with 'content' (str) and 'tool_calls' (list) keys
    """
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('OpenAI does not allow temperature list: %s',
                  self.temperature_list)

    client = self._get_client()

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(
            messages=messages,
            model=self.name,
            tools=tools,
            n=self.num_samples,
            temperature=self.temperature
        ),
        [openai.OpenAIError]
    )

    # Store token usage info
    if hasattr(completion, 'usage') and completion.usage:
      self.last_token_usage = {
          'prompt_tokens': completion.usage.prompt_tokens,
          'completion_tokens': completion.usage.completion_tokens,
          'total_tokens': completion.usage.total_tokens
      }
    else:
      self.last_token_usage = None

    message = completion.choices[0].message
    
    # Extract content
    content = message.content if message.content else ""
    
    # Extract tool calls
    tool_calls = []
    if message.tool_calls:
      import json
      for tool_call in message.tool_calls:
        tool_calls.append({
            "id": tool_call.id,
            "name": tool_call.function.name,
            "arguments": json.loads(tool_call.function.arguments)
        })
    
    return {
        "content": content,
        "tool_calls": tool_calls
    }


class GPT5(GPT):
  """OpenAI's GPT-5 model (no temperature setting)."""

  name = 'gpt-5'

  def chat_llm(self, client: Any, messages: list[dict[str, str]]) -> str:
    """Queries LLM in a chat session and returns its response (no temperature)."""
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('GPT-5 does not allow temperature list: %s',
                  self.temperature_list)

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(messages=messages,
                                               model=self.name,
                                               n=self.num_samples),
        [openai.OpenAIError])

    # Store token usage info for later retrieval
    if hasattr(completion, 'usage') and completion.usage:
      self.last_token_usage = {
          'prompt_tokens': completion.usage.prompt_tokens,
          'completion_tokens': completion.usage.completion_tokens,
          'total_tokens': completion.usage.total_tokens
      }
    else:
      self.last_token_usage = None

    llm_response = completion.choices[0].message.content

    return llm_response
  
  def chat_with_tools(
      self,
      messages: list[dict[str, str]],
      tools: list[dict[str, Any]]
  ) -> dict[str, Any]:
    """
    Chat with LLM using OpenAI function calling (no temperature).
    
    Args:
        messages: List of message dicts with 'role' and 'content' keys
        tools: List of tool definitions in OpenAI function calling format
    
    Returns:
        Dictionary with 'content' (str) and 'tool_calls' (list) keys
    """
    if self.ai_binary:
      raise ValueError(f'OpenAI does not use local AI binary: {self.ai_binary}')
    if self.temperature_list:
      logger.info('GPT-5 does not allow temperature list: %s',
                  self.temperature_list)

    client = self._get_client()

    completion = self.with_retry_on_error(
        lambda: client.chat.completions.create(
            messages=messages,
            model=self.name,
            tools=tools,
            n=self.num_samples
            # No temperature parameter for GPT-5
        ),
        [openai.OpenAIError]
    )

    # Store token usage info
    if hasattr(completion, 'usage') and completion.usage:
      self.last_token_usage = {
          'prompt_tokens': completion.usage.prompt_tokens,
          'completion_tokens': completion.usage.completion_tokens,
          'total_tokens': completion.usage.total_tokens
      }
    else:
      self.last_token_usage = None

    message = completion.choices[0].message
    
    # Extract content
    content = message.content if message.content else ""
    
    # Extract tool calls
    tool_calls = []
    if message.tool_calls:
      import json
      for tool_call in message.tool_calls:
        tool_calls.append({
            "id": tool_call.id,
            "name": tool_call.function.name,
            "arguments": json.loads(tool_call.function.arguments)
        })
    
    return {
        "content": content,
        "tool_calls": tool_calls
    }


class GPT51(GPT5):
  """OpenAI's GPT-5.1 model."""

  name = 'gpt-5.1'


class GPT52(GPT5):
  """OpenAI's GPT-5.2 model."""

  name = 'gpt-5.2'


class DeepSeek(GPT):
  """DeepSeek's model encapsulator using OpenAI API."""
  
  name = None

  def _get_client(self):
    """Returns the DeepSeek client using OpenAI API format."""
    return openai.OpenAI(
        api_key=os.getenv('DEEPSEEK_API_KEY'),
        base_url="https://api.deepseek.com"
    )

class DeepSeekChat(DeepSeek):
  """DeepSeek Chat model."""

  name = 'deepseek-chat'
  MAX_INPUT_TOKEN = 128000

class DeepSeekReasoner(DeepSeek):
  """DeepSeek Reasoner model."""

  name = 'deepseek-reasoner'
  MAX_INPUT_TOKEN = 128000

class Qwen(GPT):
  """Qwen's model encapsulator using OpenAI API.
  """
  name = 'qwen-plus'
  def _get_client(self):
    """Returns the Qwen client using OpenAI API format."""
    # Check for API key (prefer DASHSCOPE_API_KEY, fallback to QWEN_API_KEY)
    api_key = os.getenv('DASHSCOPE_API_KEY') or os.getenv('QWEN_API_KEY')
    if not api_key:
      raise ValueError(
          'Qwen API key not found. Please set DASHSCOPE_API_KEY environment variable. '
          'Get your API key at: https://www.alibabacloud.com/help/en/model-studio/get-api-key'
      )
    
    base_url = os.getenv(
        'QWEN_BASE_URL',
        'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'  # Singapore region
    )
    
    return openai.OpenAI(api_key=api_key, base_url=base_url)

class QwenCoder(Qwen):
  """Qwen Turbo model."""

  name = 'qwen3-coder-plus'
  MAX_INPUT_TOKEN = 20000

class QwenMax(Qwen):
  """Qwen Max model.""" 

  name = 'qwen-max'
  MAX_INPUT_TOKEN = 258048

class QWQ(Qwen):
  """Qwen 3 model."""

  name = 'qwq-plus'
  MAX_INPUT_TOKEN = 32768

DefaultModel = QwenMax
