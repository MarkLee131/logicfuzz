"""Base input schemas for agent tools (Bash, GDB)."""

from pydantic import BaseModel, Field


class CommandInput(BaseModel):
    """Input schema for command-based tools (Bash, GDB)."""
    command: str = Field(description="The command to execute")
