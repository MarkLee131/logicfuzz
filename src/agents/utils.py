"""
Shared utility functions for agents.

This module provides common utilities used by both BaseAgent
and LangGraphAgent hierarchies.
"""

import re


def parse_tag(response: str, tag: str) -> str:
    """
    Parse XML-style tags from LLM response.

    Args:
        response: LLM response text
        tag: Tag name to extract (e.g., 'fuzz_target', 'conclusion')

    Returns:
        Content within the tag, or empty string if not found
    """
    # XML style: <tag>...</tag>
    pattern = rf'<{tag}>(.*?)</{tag}>'
    match = re.search(pattern, response, re.DOTALL)

    if match:
        content = match.group(1).strip()
        # Remove CDATA wrapper if present
        content = strip_cdata(content)
        # Remove markdown code block markers if present
        # (LLMs sometimes output ```c ... ``` even inside XML tags)
        content = strip_markdown_code_blocks(content)
        return content

    return ''


def strip_cdata(content: str) -> str:
    """
    Remove CDATA wrapper from content if present.

    Handles: <![CDATA[...]]> or just the markers without proper XML structure.
    """
    content = content.strip()

    # Remove <![CDATA[ at the beginning
    if content.startswith('<![CDATA['):
        content = content[9:]  # len('<![CDATA[') == 9

    # Remove ]]> at the end
    if content.endswith(']]>'):
        content = content[:-3]

    return content.strip()


def strip_markdown_code_blocks(content: str) -> str:
    """
    Remove markdown code block markers from content.

    Handles patterns like:
    - ```c ... ```
    - ```cpp ... ```
    - ```python ... ```
    - ``` ... ```

    This is needed because LLMs sometimes output markdown code blocks
    even when asked to use XML tags.

    Args:
        content: Content that may contain markdown code block markers

    Returns:
        Content with markdown code block markers removed
    """
    if not content:
        return content

    content = content.strip()

    # Pattern 1: Opening ``` with optional language specifier at the start
    # Matches: ```c, ```cpp, ```python, ```, etc.
    if content.startswith('```'):
        # Find the end of the first line (the language specifier line)
        first_newline = content.find('\n')
        if first_newline != -1:
            content = content[first_newline + 1:]
        else:
            # No newline, just strip the backticks
            content = content[3:]

    # Pattern 2: Closing ``` at the end
    content = content.strip()
    if content.endswith('```'):
        content = content[:-3]

    return content.strip()
