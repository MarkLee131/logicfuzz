# Agent Graph Prompts

This directory contains prompt templates for LangGraph agents. All prompts use XML tag format for better structure and parsing.

## Prompt Files Structure

For each agent, there are two files:

1. **`{agent_name}_system.txt`** - System prompt that defines the agent's role
2. **`{agent_name}_prompt.txt`** - User prompt template with placeholders

Some agents have language-specific prompts:
- `{agent_name}_prompt_c.txt` - For C projects
- `{agent_name}_prompt_cpp.txt` - For C++ projects

## Available Agents

### 1. Prototyper
- **System**: `prototyper_system.txt`
- **Prompt**: `prototyper_prompt_c.txt`, `prototyper_prompt_cpp.txt`
- **Purpose**: Generate LibFuzzer fuzz target code from API sequences
- **Output Tag**: `<fuzz_target>`

### 2. Fixer
- **System**: `fixer_system.txt`
- **Prompt**: `fixer_prompt.txt`
- **Purpose**: Fix compilation and runtime errors in fuzz targets
- **Output Tags**: `<fuzz_target>`, `<build_script>`

### 3. Coverage Analyzer
- **System**: `coverage_analyzer_system.txt`
- **Prompt**: `coverage_analyzer_prompt.txt`, `coverage_analyzer_prompt_c.txt`, `coverage_analyzer_prompt_cpp.txt`
- **Purpose**: Analyze code coverage and suggest improvements
- **Output Tags**: `<conclusion>`, `<insights>`, `<suggestions>`

### 4. Improver
- **System**: `improver_system.txt`
- **Prompt**: `improver_prompt_c.txt`, `improver_prompt_cpp.txt`
- **Purpose**: Rewrite fuzz drivers to maximize code coverage
- **Output Tags**: `<conclusion>`, `<fuzz_target>`, `<coverage_strategy>`

### 5. Crash Analyzer
- **System**: `crash_analyzer_system.txt`
- **Prompt**: `crash_analyzer_prompt.txt`
- **Purpose**: Analyze crashes to determine if bugs are in driver or project
- **Output Tags**: `<conclusion>`, `<root_cause>`, `<determination>`, `<severity>`, `<recommendations>`

### 6. Crash Feasibility Analyzer
- **System**: `crash_feasibility_analyzer_system.txt`
- **Prompt**: `crash_feasibility_analyzer_prompt.txt`
- **Purpose**: Determine if crashes are reachable from public entry points
- **Output Tags**: `<feasible>`, `<analysis>`, `<source_code_evidence>`, `<recommendations>`

## XML Tag Format

All prompts use XML tags for structured input and output:

### Input Structure
```xml
<task>Task description</task>
<context>Context information</context>
<instructions>Step-by-step instructions</instructions>
<output_format>Expected output format</output_format>
```

### Output Structure
```xml
<conclusion>Brief analysis conclusion</conclusion>
<fuzz_target>
// Complete fuzz driver code
</fuzz_target>
```

## Prompt Template Syntax

Prompts use `{VARIABLE_NAME}` placeholders:

```xml
<task>
Generate a fuzz driver for project: {PROJECT_NAME}
</task>

<current_code>
{CURRENT_CODE}
</current_code>
```

## Usage in Code

```python
from src.utils.prompt_loader import get_prompt_manager

pm = get_prompt_manager()

# Load system prompt
system_prompt = pm.get_system_prompt("prototyper")

# Load and format user prompt (language-specific)
user_prompt = pm.build_user_prompt(
    "prototyper",
    language="c++",
    project_name="cjson",
    ...
)
```

## Parsing Output

Use `parse_tag()` to extract XML-tagged content:

```python
from src.utils.parse import parse_tag

response = llm_response
code = parse_tag(response, 'fuzz_target')
conclusion = parse_tag(response, 'conclusion')
```
