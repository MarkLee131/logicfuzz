"""
Shared utility functions for agents.

This module provides common utilities used by both BaseAgent
and LangGraphAgent hierarchies.
"""

import re


def parse_tag(response: str, tag: str) -> str:
    """
    Parse XML-style or code block-style tags from LLM response.

    Args:
        response: LLM response text
        tag: Tag name to extract (e.g., 'fuzz_target', 'solution')

    Returns:
        Content within the tag, or empty string if not found
    """
    patterns = [
        rf'<{tag}>(.*?)</{tag}>',  # XML style: <tag>...</tag>
        rf'```{tag}\n?(.*?)```'    # Code block style: ```tag...```
    ]

    # For fuzz_target, also try common code block languages
    if tag == 'fuzz_target':
        patterns.extend([
            r'```cpp\n?(.*?)```',   # ```cpp code block
            r'```c\n?(.*?)```',     # ```c code block
            r'```c\+\+\n?(.*?)```', # ```c++ code block
        ])

    for pattern in patterns:
        match = re.search(pattern, response, re.DOTALL)
        if match:
            content = match.group(1).strip()
            # Remove CDATA wrapper if present
            content = strip_cdata(content)
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

