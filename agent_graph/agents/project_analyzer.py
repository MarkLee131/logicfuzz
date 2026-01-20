"""
Project Analyzer agent for understanding project context before driver generation.

This agent analyzes the project to understand:
1. What is this project? (application scenario)
2. What are the core functions to fuzz? (high-value targets)
3. What input format does it expect? (structured/binary/text)
4. What are the key API patterns? (parse, transform, serialize)

This understanding guides the prototyper to generate better initial drivers.
"""
from typing import Any, Dict, List, Optional
import argparse
import json

import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from data_prep.api_classifier import classify_project_apis, APIClassificationResult


class ProjectAnalyzer(LangGraphAgent):
    """
    Analyzes project to understand context and identify fuzzing priorities.

    This runs BEFORE the prototyper to provide focused guidance.
    """

    SYSTEM_MESSAGE = """You are an expert at understanding software projects and identifying fuzzing priorities.

Your job is to analyze a project's APIs and determine:
1. What is this project? What problem does it solve?
2. What are the CORE functions that should be fuzzed for maximum security impact?
3. What input format does the project expect? (JSON, XML, binary, text, etc.)
4. What is the typical data flow? (Parse → Transform → Serialize? Create → Modify → Output?)

You think step-by-step and provide clear, actionable insights.
"""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        super().__init__(
            name="project_analyzer",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=self.SYSTEM_MESSAGE
        )

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze project and produce understanding for prototyper.

        Returns:
            State update with project_understanding dict
        """
        benchmark = state["benchmark"]
        context = state.get('context', {})
        project_apis = context.get('project_apis', [])

        project_name = benchmark.get('project', 'unknown')

        # Step 1: Classify APIs using heuristics
        api_classification = classify_project_apis(project_name, project_apis)
        logger.info(
            f'API Classification: {len(api_classification.parsers)} parsers, '
            f'{len(api_classification.creators)} creators, '
            f'{len(api_classification.accessors)} accessors, '
            f'{len(api_classification.mutators)} mutators, '
            f'{len(api_classification.destructors)} destructors, '
            f'{len(api_classification.serializers)} serializers',
            trial=self.trial
        )

        # Step 2: Ask LLM to understand the project
        prompt = self._build_analysis_prompt(
            project_name,
            project_apis,
            api_classification
        )

        response = self.chat_llm(state, prompt)

        # Step 3: Parse LLM response
        project_understanding = self._parse_understanding(response, api_classification)

        # Log the understanding
        logger.info(
            f'Project Understanding:\n'
            f'  Scenario: {project_understanding.get("scenario", "unknown")}\n'
            f'  Input Format: {project_understanding.get("input_format", "unknown")}\n'
            f'  Core APIs: {project_understanding.get("core_apis", [])[:5]}\n'
            f'  Data Flow: {project_understanding.get("data_flow", "unknown")}',
            trial=self.trial
        )

        self._langgraph_logger.flush_agent_logs(self.name)

        return {
            "project_understanding": project_understanding,
            "api_classification": api_classification.to_dict(),
        }

    def _build_analysis_prompt(
        self,
        project_name: str,
        apis: List[Dict],
        classification: APIClassificationResult
    ) -> str:
        """Build prompt for project analysis."""

        # Format classified APIs
        classified_summary = []

        if classification.parsers:
            classified_summary.append("**Parser APIs** (consume external input):")
            for api in classification.parsers[:5]:
                classified_summary.append(f"  - {api.name}")

        if classification.creators:
            classified_summary.append("**Creator APIs** (create objects):")
            for api in classification.creators[:5]:
                classified_summary.append(f"  - {api.name}")

        if classification.accessors:
            classified_summary.append("**Accessor APIs** (read data):")
            for api in classification.accessors[:5]:
                classified_summary.append(f"  - {api.name}")

        if classification.mutators:
            classified_summary.append("**Mutator APIs** (modify data):")
            for api in classification.mutators[:5]:
                classified_summary.append(f"  - {api.name}")

        if classification.serializers:
            classified_summary.append("**Serializer APIs** (output data):")
            for api in classification.serializers[:5]:
                classified_summary.append(f"  - {api.name}")

        if classification.destructors:
            classified_summary.append("**Destructor APIs** (cleanup):")
            for api in classification.destructors[:3]:
                classified_summary.append(f"  - {api.name}")

        classified_text = "\n".join(classified_summary)

        # Format all APIs with signatures
        all_apis_text = []
        for api in apis[:30]:  # Limit to 30 for prompt size
            fn = api.get("function_name", "unknown")
            rt = api.get("return_type", "void")
            args = api.get("arguments", [])
            args_str = self._format_args(args)
            all_apis_text.append(f"  {rt} {fn}({args_str})")

        if len(apis) > 30:
            all_apis_text.append(f"  ... and {len(apis) - 30} more APIs")

        apis_text = "\n".join(all_apis_text)

        return f"""Analyze this project and help me understand what to fuzz.

## Project: {project_name}

## API Classification (heuristic):
{classified_text}

## All APIs (sample):
{apis_text}

## Your Task

Think step-by-step:

1. **What is this project?**
   - What problem does it solve?
   - What category does it belong to? (JSON parser, compression, crypto, image processing, etc.)

2. **What input format does it expect?**
   - Structured text (JSON, XML, YAML, INI)?
   - Binary data (images, archives, protocols)?
   - Free-form text (paths, URLs, commands)?
   - Raw bytes?

3. **What are the CORE functions to fuzz?**
   - Which APIs consume external/untrusted input?
   - Which APIs have complex parsing/validation logic?
   - Which APIs are most likely to have security bugs?
   - Prioritize: Parsers > Serializers > Complex Mutators

4. **What is the typical data flow?**
   - Parse → Transform → Serialize?
   - Create → Modify → Query → Destroy?
   - Init → Process → Cleanup?

5. **What fuzzing strategy would maximize coverage?**
   - For parsers: Generate structured valid input, not random strings
   - For lookup APIs: Pre-populate state to hit both found/not-found branches
   - For type-check APIs: Prepare multiple object types

## Output Format

Respond with your analysis in the following XML format:

<project_understanding>
<scenario>Brief description of what this project does (1-2 sentences)</scenario>
<category>One of: json_parser, xml_parser, compression, crypto, image, network, database, other</category>
<input_format>One of: json, xml, yaml, binary, text, raw_bytes, mixed</input_format>
<data_flow>The typical processing pattern, e.g., "Parse → Query → Serialize"</data_flow>
<core_apis>
<api priority="1">Most important API to fuzz</api>
<api priority="2">Second most important</api>
<api priority="3">Third most important</api>
</core_apis>
<fuzzing_strategy>
Specific advice for how to generate good inputs for this project.
Include: what format, what edge cases, what states to prepare.
</fuzzing_strategy>
<branch_coverage_tips>
Specific tips for hitting more branches in this project.
e.g., "For HasObjectItem, pre-populate objects with known keys"
</branch_coverage_tips>
</project_understanding>
"""

    def _parse_understanding(
        self,
        response: str,
        classification: APIClassificationResult
    ) -> Dict[str, Any]:
        """Parse LLM response into structured understanding."""

        understanding = {
            "scenario": "",
            "category": "other",
            "input_format": "raw_bytes",
            "data_flow": "",
            "core_apis": [],
            "fuzzing_strategy": "",
            "branch_coverage_tips": "",
            "api_classification_summary": {
                "parsers": [api.name for api in classification.parsers],
                "creators": [api.name for api in classification.creators],
                "accessors": [api.name for api in classification.accessors],
                "mutators": [api.name for api in classification.mutators],
                "serializers": [api.name for api in classification.serializers],
                "destructors": [api.name for api in classification.destructors],
            }
        }

        # Parse XML tags from response
        scenario = parse_tag(response, 'scenario')
        if scenario:
            understanding["scenario"] = scenario.strip()

        category = parse_tag(response, 'category')
        if category:
            understanding["category"] = category.strip().lower()

        input_format = parse_tag(response, 'input_format')
        if input_format:
            understanding["input_format"] = input_format.strip().lower()

        data_flow = parse_tag(response, 'data_flow')
        if data_flow:
            understanding["data_flow"] = data_flow.strip()

        fuzzing_strategy = parse_tag(response, 'fuzzing_strategy')
        if fuzzing_strategy:
            understanding["fuzzing_strategy"] = fuzzing_strategy.strip()

        branch_tips = parse_tag(response, 'branch_coverage_tips')
        if branch_tips:
            understanding["branch_coverage_tips"] = branch_tips.strip()

        # Parse core_apis
        core_apis_block = parse_tag(response, 'core_apis')
        if core_apis_block:
            import re
            api_matches = re.findall(r'<api[^>]*>([^<]+)</api>', core_apis_block)
            understanding["core_apis"] = [api.strip() for api in api_matches]

        # Fallback: use classification-based priority if LLM didn't provide
        if not understanding["core_apis"]:
            priority_apis = classification.get_priority_apis()[:5]
            understanding["core_apis"] = [api.name for api in priority_apis]

        return understanding

    def _format_args(self, args: List) -> str:
        """Format arguments list as a string."""
        if not args:
            return ""

        parts = []
        for arg in args[:4]:  # Limit args shown
            if isinstance(arg, dict):
                arg_type = arg.get('type', arg.get('type_clang', ''))
                arg_name = arg.get('name', '')
                parts.append(f"{arg_type} {arg_name}".strip())
            else:
                parts.append(str(arg))

        if len(args) > 4:
            parts.append("...")

        return ", ".join(parts)


def format_understanding_for_prototyper(understanding: Dict[str, Any]) -> str:
    """
    Format project understanding for injection into prototyper prompt.

    Args:
        understanding: Dict from ProjectAnalyzer

    Returns:
        Formatted string for prompt injection
    """
    lines = [
        "## Project Understanding (from pre-analysis)",
        "",
        f"**Scenario**: {understanding.get('scenario', 'Unknown')}",
        f"**Category**: {understanding.get('category', 'other')}",
        f"**Input Format**: {understanding.get('input_format', 'raw_bytes')}",
        f"**Data Flow**: {understanding.get('data_flow', 'Unknown')}",
        "",
        "**Core APIs to Focus On** (in priority order):",
    ]

    for i, api in enumerate(understanding.get('core_apis', [])[:5], 1):
        lines.append(f"  {i}. {api}")

    lines.append("")

    # Add fuzzing strategy
    strategy = understanding.get('fuzzing_strategy', '')
    if strategy:
        lines.append("**Recommended Fuzzing Strategy**:")
        lines.append(strategy)
        lines.append("")

    # Add branch coverage tips
    tips = understanding.get('branch_coverage_tips', '')
    if tips:
        lines.append("**Branch Coverage Tips**:")
        lines.append(tips)
        lines.append("")

    # Add API classification summary
    classification = understanding.get('api_classification_summary', {})
    parsers = classification.get('parsers', [])
    if parsers:
        lines.append("**Parser APIs** (should receive structured input, not random strings):")
        for api in parsers[:3]:
            lines.append(f"  - {api}")
        lines.append("")

    accessors = classification.get('accessors', [])
    if accessors:
        lines.append("**Accessor APIs** (need to hit both found/not-found branches):")
        for api in accessors[:3]:
            lines.append(f"  - {api}")
        lines.append("")

    return "\n".join(lines)
