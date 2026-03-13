"""
LangGraphPrototyper agent for LangGraph workflow.

Refactored to use ToolCallingMixin for FuzzIntrospector tool access.
LLM can query function source code and usage examples when needed.
"""
from typing import Any, Dict, List
import argparse

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.agents.utils import parse_tag
from src.utils.prompt_loader import get_prompt_manager
from src.tools.langchain_adapters import (
    GetFunctionImplementationTool,
    GetFunctionSignatureTool,
    GetSampleCrossReferencesTool,
    GetTestsForFunctionsTool,
)
from data_prep.api_classifier import classify_project_apis


class LangGraphPrototyper(LangGraphAgent, ToolCallingMixin):
    """
    Prototyper agent for LangGraph.

    Now supports FuzzIntrospector tool access for querying:
    - Function source code (to understand implementation details)
    - Usage examples (to learn correct API patterns)
    - Function signatures (to verify parameter types)

    LLM can decide when to use tools based on uncertainty about API usage.
    """

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("prototyper")
        super().__init__(name="prototyper",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.fi_tool = None
        self.project_name = None
        self.benchmark = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """Return FuzzIntrospector tools for API understanding."""
        return [
            GetFunctionImplementationTool(
                executor=self._get_function_implementation),
            GetFunctionSignatureTool(executor=self._get_function_signature),
            GetSampleCrossReferencesTool(
                executor=self._get_sample_cross_references),
            GetTestsForFunctionsTool(executor=self._get_tests_for_functions),
        ]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse final LLM response to extract fuzz target code or hole fillings.

        Supports two output modes:
        1. Hole-filling mode: JSON hole fillings in <hole_fillings> tags
        2. Complete code mode: Full code in <fuzz_target> tags
        """
        # Try hole-filling mode first (preferred in skeleton template mode)
        hole_fillings = self._parse_hole_fillings(content)
        if hole_fillings:
            return {
                'hole_fillings': hole_fillings,
                'mode': 'hole_filling',
                'raw_response': content
            }

        # Fallback: complete code mode
        fuzz_target_code = parse_tag(content, 'fuzz_target')
        return {
            'fuzz_target_code': fuzz_target_code,
            'mode': 'complete_code',
            'raw_response': content
        }

    def _parse_hole_fillings(self, content: str) -> Dict[str, str]:
        """Parse JSON hole fillings from LLM response.

        Extracts hole fillings from <hole_fillings> tags containing JSON.

        Args:
            content: LLM response content

        Returns:
            Dictionary mapping hole placeholders to their fill values,
            or empty dict if parsing fails.
        """
        import json

        # Try to extract from <hole_fillings> tag
        fillings_text = parse_tag(content, 'hole_fillings')
        if not fillings_text:
            return {}

        # Clean up the JSON text
        fillings_text = fillings_text.strip()

        # Handle potential markdown code block wrapping
        if fillings_text.startswith('```'):
            # Remove markdown code block markers
            lines = fillings_text.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            fillings_text = '\n'.join(lines)

        try:
            fillings = json.loads(fillings_text)
            if isinstance(fillings, dict):
                logger.info(f'Parsed {len(fillings)} hole fillings from JSON',
                           trial=self.trial)
                return fillings
            else:
                logger.warning(
                    'Hole fillings JSON is not a dictionary',
                    trial=self.trial)
                return {}
        except json.JSONDecodeError as e:
            logger.warning(
                f'Failed to parse hole fillings JSON: {e}',
                trial=self.trial)
            return {}

    def _merge_holes_into_skeleton(self, skeleton_code: str,
                                   hole_fillings: Dict[str, str]) -> str:
        """Merge hole fillings into skeleton code.

        Replaces hole placeholders in the skeleton with their filled values.

        Args:
            skeleton_code: Skeleton code containing __HOLE_xxx__ placeholders
            hole_fillings: Dictionary mapping placeholders to fill values

        Returns:
            Code with holes filled in.
        """
        if not skeleton_code:
            logger.warning('No skeleton code provided for merging',
                          trial=self.trial)
            return ""

        result = skeleton_code

        # Replace each hole placeholder with its filling
        for placeholder, filling in hole_fillings.items():
            if placeholder in result:
                result = result.replace(placeholder, filling)
                logger.debug(
                    f'Filled hole {placeholder} with: {filling[:50]}...'
                    if len(filling) > 50 else f'Filled hole {placeholder} with: {filling}',
                    trial=self.trial)
            else:
                # Try to match without the leading/trailing underscores
                # in case the format differs slightly
                clean_placeholder = placeholder.strip('_')
                for pattern in [
                    f'__{clean_placeholder}__',
                    f'__HOLE_{clean_placeholder}__',
                    f'__BUFSIZE_{clean_placeholder}__',
                    f'__CALLBACK_{clean_placeholder}__',
                    f'__INIT_{clean_placeholder}__',
                    f'__LOOPCOND_{clean_placeholder}__',
                    f'__LOOPBOUND_{clean_placeholder}__',
                    f'__CLEANUP_{clean_placeholder}__',
                ]:
                    if pattern in result:
                        result = result.replace(pattern, filling)
                        logger.debug(
                            f'Filled hole {pattern} with: {filling[:50]}...'
                            if len(filling) > 50 else f'Filled hole {pattern} with: {filling}',
                            trial=self.trial)
                        break

        # Check for unfilled holes
        import re
        unfilled = re.findall(r'__(?:HOLE|BUFSIZE|CALLBACK|INIT|LOOPCOND|LOOPBOUND|CLEANUP|ARRLEN)_[^_]+__', result)
        if unfilled:
            logger.warning(
                f'{len(unfilled)} holes remain unfilled: {unfilled[:5]}',
                trial=self.trial)

        return result

    # =========================================================================
    # Tool Executors
    # =========================================================================

    def _init_fi_tool(self):
        """Initialize FuzzIntrospector tool for the project."""
        if self.fi_tool is None and self.benchmark is not None:
            from tool.fuzz_introspector_tool import FuzzIntrospectorTool
            from experiment import benchmark as benchmarklib
            benchmark_obj = benchmarklib.Benchmark.from_dict(self.benchmark)
            logger.info(
                f"Initializing FuzzIntrospector for project: {benchmark_obj.project}",
                trial=self.trial)
            self.fi_tool = FuzzIntrospectorTool(benchmark_obj)
            self.project_name = benchmark_obj.project

    def _get_function_implementation(self, function_name: str) -> str:
        """Get function source code via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        impl = self.fi_tool.get_function_implementation(
            self.project_name, function_name)
        if impl:
            return f"Source code for '{function_name}':\n```c\n{impl}\n```"
        return f"Error: Could not find source code for function '{function_name}'"

    def _get_function_signature(self, function_name: str) -> str:
        """Get function signature via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        signature = self.fi_tool.get_function_signature(function_name)
        if signature:
            return f"Function signature: {signature}"
        return f"Error: Could not find signature for function '{function_name}'"

    def _get_sample_cross_references(self, function_signature: str) -> str:
        """Get sample usage examples via FuzzIntrospector."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        cross_refs = self.fi_tool.get_sample_cross_references(
            function_signature)
        if cross_refs:
            result = f"Usage examples for '{function_signature}':\n\n"
            for i, ref in enumerate(cross_refs[:5], 1):
                result += f"Example {i}:\n```c\n{ref}\n```\n\n"
            return result
        return f"No usage examples found for '{function_signature}'"

    def _get_tests_for_functions(self, function_names: List[str]) -> str:
        """Get test code that uses these functions."""
        self._init_fi_tool()
        if not self.fi_tool:
            return f"Error: FuzzIntrospector not available"
        tests = self.fi_tool.get_tests_for_functions(function_names)
        if tests and tests.get('source'):
            result = f"Test examples using functions: {', '.join(function_names)}\n\n"
            for i, snippet in enumerate(tests['source'][:3], 1):
                result += f"Test {i}:\n```c\n{snippet}\n```\n\n"
            return result
        return f"No tests found for functions: {', '.join(function_names)}"

    # =========================================================================
    # Main Execution
    # =========================================================================

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Generate fuzz target code with optional tool access."""
        from src.context.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates)

        benchmark = state["benchmark"]
        self.benchmark = benchmark  # Store for FI tool initialization
        function_analysis = state.get("function_analysis", {})
        context = state.get('context', {})

        # === Synthesis mode is always enabled (CBFactory as base for LLM refinement) ===
        synthesized_drivers = context.get('synthesized_drivers', [])

        project_apis = context.get('project_apis', [])
        api_sequences = context.get('api_sequences', [])
        dependency_graph = context.get('dependency_graph', {})
        condition_info = context.get('condition_info', {})
        skeleton_drivers = context.get('skeleton_drivers', [])
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})
        existing_driver_knowledge = context.get('existing_driver_knowledge',
                                                {})

        # Get target path info for include path calculation
        target_path = benchmark.get('target_path', '')

        # Determine target language from file extension
        library_language = benchmark.get('language', 'c++').lower()
        cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
        is_cpp_target = target_path.lower().endswith(cpp_extensions)
        is_c_project = library_language in ('c', )

        target_language = 'c++' if is_cpp_target else 'c'
        needs_extern = is_cpp_target and is_c_project

        is_regeneration = state.get("compile_success") == False and state.get(
            "fuzz_target_source", "") != ""

        prompt_manager = get_prompt_manager()
        additional_context = ""
        if is_regeneration:
            build_errors = state.get("build_errors", [])
            if build_errors:
                additional_context = f"\n**Note**: Previous code generation failed to compile. Key errors:\n"
                additional_context += "\n".join(build_errors[:3])
                additional_context += "\n\nPlease generate a completely new approach that avoids these issues."

        skeleton_code = self._retrieve_skeleton(function_analysis)
        srs_specification = self._format_analysis_summary(function_analysis)

        # === API Classification ===
        project_name = benchmark.get('project', 'unknown')
        api_classification = classify_project_apis(project_name, project_apis)
        api_understanding_text = self._format_api_understanding(
            api_classification)

        logger.info(
            f'API Classification: {len(api_classification.parsers)} parsers, '
            f'{len(api_classification.creators)} creators, '
            f'{len(api_classification.accessors)} accessors, '
            f'{len(api_classification.mutators)} mutators',
            trial=self.trial)

        api_sequences_text = self._format_api_sequences(api_sequences, limit=8)
        project_apis_text = self._format_project_apis(project_apis, limit=20)
        dep_graph_text = self._format_dependency_graph(dependency_graph,
                                                       limit=12)
        condition_text = self._format_condition_info(condition_info)

        # Try to get skeleton as mandatory template first
        skeleton_template_code, holes_description, has_skeleton_template = \
            self._format_skeleton_as_template(skeleton_drivers, limit=1)

        # Fallback to legacy format if no template available
        skeleton_text = self._format_skeleton_drivers(skeleton_drivers,
                                                      limit=2)
        include_path_context = self._format_include_path_context(
            target_path, existing_fuzzer_headers)
        driver_knowledge_text = self._format_driver_knowledge(
            existing_driver_knowledge)

        # === Synthesis mode: Format CBFactory base driver for LLM refinement ===
        synthesis_base_text = ""
        if synthesized_drivers:
            synthesis_base_text = self._format_synthesis_base_driver(
                synthesized_drivers, state)
            logger.info(
                f'[Synthesis Mode] Providing {len(synthesized_drivers)} CBFactory drivers as base for LLM refinement',
                trial=self.trial)

        # Add extern "C" guidance if needed
        extern_c_note = ""
        if needs_extern:
            extern_c_note = """
**IMPORTANT: extern "C" Required**
This is a C++ fuzz target for a C library. You MUST wrap all C library headers in `extern "C"`:
```cpp
extern "C" {
#include "library_header.h"
}
```
"""
            if additional_context:
                additional_context = extern_c_note + "\n" + additional_context
            else:
                additional_context = extern_c_note

        # Build the base prompt
        try:
            base_prompt = prompt_manager.build_user_prompt(
                "prototyper",
                language=target_language,
                project_name=benchmark.get('project', 'unknown'),
                function_name="",
                function_signature="",
                srs_specification=srs_specification,
                additional_context=additional_context,
                skeleton_code=skeleton_code)
            # Add explicit language guidance
            lang_guidance = ""
            if target_language == 'c':
                lang_guidance = """
**IMPORTANT - C Language Rules:**
- This is a C library. You MUST use `struct` keyword: `struct type_name *ptr`
- Do NOT write C++ style: `type_name *ptr` (this will fail to compile!)
- Example: `struct ares_mx_reply *mx = NULL;` (correct for C)
"""

            base_prompt += f"""

<task>
Generate a high-coverage LibFuzzer fuzz driver for the {benchmark.get('project', 'unknown')} project.
Target language: **{target_language.upper()}**
{lang_guidance}
</task>

<step1_understand_project>
{api_understanding_text}

Before writing any code, think about:
1. What is this project's main purpose?
2. Which APIs are PARSERS that consume external input? (These are fuzzing priority!)
3. What input format do the parsers expect? (JSON? XML? Binary?)
4. What is the typical data flow? (Parse → Query → Modify → Serialize?)
</step1_understand_project>

<reference_information>

<include_paths>
{include_path_context}
</include_paths>

<api_sequences>
{api_sequences_text}
</api_sequences>

<project_apis>
{project_apis_text}
</project_apis>

<dependency_graph>
{dep_graph_text}
</dependency_graph>

<constraints>
{condition_text}
</constraints>

<skeleton_drivers>
{skeleton_text}
</skeleton_drivers>
{driver_knowledge_text}
{synthesis_base_text}
</reference_information>"""

            # Add skeleton template mode section if available
            if has_skeleton_template:
                base_prompt += f"""

<skeleton_template_mode>
**MANDATORY SKELETON MODE ENABLED**

A type-safe skeleton has been generated for you. You MUST use this skeleton as your template.
Do NOT modify the skeleton structure, API sequence, or variable declarations.
Your task is to fill the marked holes with appropriate code.

<skeleton_template>
```c
{skeleton_template_code}
```
</skeleton_template>

<holes_to_fill>
{holes_description}
</holes_to_fill>

**IMPORTANT INSTRUCTIONS:**
1. The skeleton above contains placeholders like __HOLE_xxx__ or __BUFSIZE_xxx__
2. Replace each placeholder with appropriate code
3. Keep ALL other code exactly as shown
4. Do NOT add new API calls or change the API sequence
5. Do NOT modify variable declarations or types

**OUTPUT FORMAT:**
You have two options:

**Option 1 (Preferred): JSON Hole Fillings**
Output your hole fillings as JSON wrapped in <hole_fillings> tags:
<hole_fillings>
{{"__HOLE_callback_1__": "int my_callback(void* data) {{ return 0; }}", "__BUFSIZE_bufsize_1__": "size"}}
</hole_fillings>

**Option 2: Complete Code**
If JSON mode doesn't work, output the complete filled code in <fuzz_target> tags.
</skeleton_template_mode>
"""
            else:
                base_prompt += """

<tool_usage_guidance>
**You have access to tools to query more information about APIs if needed:**

- **get_function_implementation**: Get the source code of any API function
  Use when: You need to understand how a function handles parameters (e.g., var-len relationships, buffer handling)

- **get_function_signature**: Get the exact signature of a function
  Use when: You're unsure about parameter types

- **get_sample_cross_references**: Get real usage examples from the codebase
  Use when: You want to see how other code correctly uses an API (especially for callbacks, complex patterns)

- **get_tests_for_functions**: Get test code that uses these functions
  Use when: You want to learn from existing test patterns

**When to use tools:**
- If you're uncertain about buffer-size relationships → query source code
- If you need to implement callbacks → query usage examples to see signatures
- If you're unsure about API lifecycle → query tests to see correct patterns
- If the API usage is straightforward → no need to query, just generate code

**Tool calls are optional** - use them only when you need more information.
</tool_usage_guidance>

<generation_rules>
Generate a fuzz driver following these CRITICAL rules:

**TYPE CORRECTNESS (CRITICAL for C libraries):**
- For C libraries: ALWAYS use `struct` keyword with struct types: `struct foo_t *ptr`
- For C++ libraries: struct keyword is optional: `foo_t *ptr`
- Check the library language and use the correct syntax!
- If <skeleton_drivers> are provided, FOLLOW their type declarations exactly

**API SELECTION:**
1. PRIORITY: Focus on PARSER APIs - They consume external input and have highest bug potential
2. If <skeleton_drivers> show a working API sequence, START from that sequence
3. For parsers: Generate STRUCTURED input (not random strings!)
   - JSON parsers need valid JSON structure with fuzz-derived values
   - XML parsers need valid XML structure
   - Binary parsers need valid headers/magic bytes

**CODE QUALITY:**
4. For accessor APIs (Has*, Get*, Is*): Hit BOTH branches
   - Pre-populate objects with known keys to hit "found" path
   - Query with missing keys to hit "not found" path
5. For type checks (IsArray, IsObject): Test multiple types
6. Follow the dependency order in sequences
7. Clean up resources properly
8. Use correct include paths - the fuzz target will be placed at the location shown above
</generation_rules>

<output_format>
Output your fuzz driver code inside <fuzz_target> tags.
</output_format>
"""
        except Exception as e:
            logger.warning(
                f"Prompt template may not support project-level mode: {e}",
                trial=self.trial)
            base_prompt = self._build_fallback_prompt(
                benchmark, include_path_context, api_sequences_text,
                project_apis_text, dep_graph_text, condition_text,
                skeleton_text, srs_specification, skeleton_code,
                additional_context)

        prompt = build_prompt_with_session_memory(state,
                                                  base_prompt,
                                                  agent_name=self.name)

        # Use tool calling loop - LLM can optionally use tools
        try:
            parsed_result, all_responses = self.run_tool_calling_loop(
                initial_prompt=prompt,
                state=state,
                max_rounds=getattr(self.args, 'max_round',
                                   5),  # Allow a few rounds for tool use
                log_prefix="PROTOTYPER")
        except Exception as e:
            logger.warning(
                f"Tool calling loop failed, falling back to direct call: {e}",
                trial=self.trial)
            response = self.chat_llm(state, prompt)
            parsed_result = self.parse_response(response)
            all_responses = [response]

        # Extract session memory updates
        combined_response = "\n\n".join(all_responses)
        session_memory_updates = extract_session_memory_updates_from_response(
            combined_response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0))
        updated_session_memory = merge_session_memory_updates(
            state, session_memory_updates)

        # Handle both hole-filling mode and complete code mode
        generation_mode = parsed_result.get('mode', 'complete_code')

        if generation_mode == 'hole_filling':
            # Hole-filling mode: merge hole fillings into skeleton
            hole_fillings = parsed_result.get('hole_fillings', {})
            skeleton_code, _, _ = self._get_active_skeleton(state)

            if skeleton_code and hole_fillings:
                fuzz_target_code = self._merge_holes_into_skeleton(
                    skeleton_code, hole_fillings)
                logger.info(
                    f'Generated code via hole-filling: '
                    f'{len(hole_fillings)} holes filled',
                    trial=self.trial)
            else:
                # Fallback: try to extract from fuzz_target tag
                fuzz_target_code = parse_tag(parsed_result.get('raw_response', ''), 'fuzz_target')
                if fuzz_target_code:
                    logger.warning(
                        'Hole-filling mode failed, using fallback fuzz_target extraction',
                        trial=self.trial)
                else:
                    logger.error(
                        'Hole-filling mode failed: no skeleton or hole fillings',
                        trial=self.trial)
                    fuzz_target_code = ''
        else:
            # Complete code mode: extract fuzz_target directly
            fuzz_target_code = parsed_result.get('fuzz_target_code', '')
            if not fuzz_target_code:
                logger.error('No <fuzz_target> tag found in prototyper response',
                             trial=self.trial)

        validation_warnings = self._validate_api_usage(
            fuzz_target_code, benchmark.get('project', 'unknown'))

        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "compile_success": None,
            "build_errors": [],
            "session_memory": updated_session_memory,
            "api_validation_warnings": validation_warnings
        }

        if is_regeneration:
            prototyper_regenerate_count = state.get(
                "prototyper_regenerate_count", 0)
            state_update[
                "prototyper_regenerate_count"] = prototyper_regenerate_count + 1
            state_update["compilation_retry_count"] = 0
            logger.info(
                f'Prototyper regeneration #{prototyper_regenerate_count + 1}',
                trial=self.trial)

        self._langgraph_logger.flush_agent_logs(self.name)

        return state_update

    def _build_fallback_prompt(self, benchmark, include_path_context,
                               api_sequences_text, project_apis_text,
                               dep_graph_text, condition_text, skeleton_text,
                               srs_specification, skeleton_code,
                               additional_context):
        """Build fallback prompt when template fails."""
        return f"""<task>
Generate a LibFuzzer fuzz driver for project {benchmark.get('project', 'unknown')}.
</task>

<reference_information>

<include_paths>
{include_path_context}
</include_paths>

<api_sequences>
{api_sequences_text}
</api_sequences>

<project_apis>
{project_apis_text}
</project_apis>

<dependency_graph>
{dep_graph_text}
</dependency_graph>

<constraints>
{condition_text}
</constraints>

<skeleton_drivers>
{skeleton_text}
</skeleton_drivers>

<project_analysis>
{srs_specification}
</project_analysis>

<skeleton_code>
{skeleton_code}
</skeleton_code>

{additional_context}

</reference_information>

<tool_usage_guidance>
You have access to FuzzIntrospector tools:
- get_function_implementation: Get function source code
- get_sample_cross_references: Get usage examples
- get_tests_for_functions: Get test code

Use these when you need to understand API patterns (var-len, callbacks, lifecycle).
</tool_usage_guidance>

<generation_rules>
Generate a complete LibFuzzer-compatible fuzz driver using the API sequences above.
Use correct include paths - the fuzz target will be placed at the location shown above.
</generation_rules>

<output_format>
Output your fuzz driver code inside <fuzz_target> tags.
</output_format>"""

    # =========================================================================
    # Formatting helpers (unchanged from original)
    # =========================================================================

    def _format_synthesis_base_driver(self,
                                      synthesized_drivers: List[Dict[str,
                                                                     Any]],
                                      state: FuzzingWorkflowState) -> str:
        """Format CBFactory synthesized drivers as base for LLM refinement."""
        if not synthesized_drivers:
            return ""

        lines = []
        lines.append("")
        lines.append(
            "**=== CBFactory SYNTHESIZED DRIVER (Base for Refinement) ===**")
        lines.append("")
        lines.append(
            "The following driver was generated by CBFactory (traditional program synthesis)."
        )
        lines.append(
            "It is structurally correct and respects API constraints, but needs YOUR refinement:"
        )
        lines.append("")
        lines.append("**Your tasks:**")
        lines.append(
            "1. **Fix compilation issues** - Add missing headers, fix type errors"
        )
        lines.append(
            "2. **Improve input generation** - Replace basic buffers with structured fuzzer input"
        )
        lines.append(
            "3. **Add error handling** - Check return values, handle NULL pointers"
        )
        lines.append("4. **Enhance coverage** - Add branches, test edge cases")
        lines.append(
            "5. **Keep the API sequence** - The call order is constraint-validated, preserve it"
        )
        lines.append("")

        synthesis_index = state.get("synthesis_driver_index",
                                    0) if state else 0
        if synthesis_index >= len(synthesized_drivers):
            synthesis_index = 0

        driver = synthesized_drivers[synthesis_index]
        driver_name = driver.get('name', f'cbfactory_driver_{synthesis_index}')
        api_sequence = driver.get('api_sequence', [])
        code = driver.get('code', '')
        synthesis_info = driver.get('synthesis_info', {})

        lines.append(f"**Driver: {driver_name}**")
        lines.append(
            f"  - API sequence ({len(api_sequence)} calls): {' → '.join(api_sequence[:8])}"
            + (" ..." if len(api_sequence) > 8 else ""))
        if synthesis_info:
            lines.append(
                f"  - Synthesis method: {synthesis_info.get('method', 'CBFactory')}"
            )
            lines.append(
                f"  - Has cleanup: {synthesis_info.get('has_cleanup', False)}")
        lines.append("")
        lines.append("**Base Code (REFINE THIS):**")
        lines.append("```cpp")
        code_lines = code.split('\n')
        if len(code_lines) > 80:
            lines.extend(code_lines[:80])
            lines.append("// ... (truncated)")
        else:
            lines.append(code)
        lines.append("```")
        lines.append("")
        lines.append(
            "**IMPORTANT:** Use this as your starting point. Keep the API call sequence,"
        )
        lines.append(
            "but improve the driver to be compilable and achieve high code coverage."
        )
        lines.append("")

        if len(synthesized_drivers) > 1:
            lines.append(
                f"*({len(synthesized_drivers) - 1} more synthesized drivers available)*"
            )
            lines.append("")

        return "\n".join(lines)

    def _format_api_understanding(self, classification) -> str:
        """Format API classification into project understanding guidance."""
        from data_prep.api_classifier import APIClassificationResult

        if not isinstance(classification, APIClassificationResult):
            return "  (API classification not available)"

        lines = []
        lines.append("**API Role Analysis** (automated classification):")
        lines.append(f"  Total APIs analyzed: {len(classification.apis)}")
        lines.append("")

        if classification.parsers:
            lines.append(
                "**🎯 PARSER APIs (PRIORITY - consume external input):**")
            for api in classification.parsers[:5]:
                lines.append(
                    f"  • {api.name} (confidence: {api.confidence:.0%})")
                if api.signature:
                    lines.append(f"    Signature: {api.signature}")
            if len(classification.parsers) > 5:
                lines.append(
                    f"  ... and {len(classification.parsers) - 5} more")
            lines.append("")

        if classification.accessors:
            lines.append(
                "**🔍 ACCESSOR APIs (need both found/not-found branches):**")
            for api in classification.accessors[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.accessors) > 5:
                lines.append(
                    f"  ... and {len(classification.accessors) - 5} more")
            lines.append("")

        if classification.creators:
            lines.append("**🏗️ CREATOR APIs (construct objects):**")
            for api in classification.creators[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.creators) > 5:
                lines.append(
                    f"  ... and {len(classification.creators) - 5} more")
            lines.append("")

        if classification.mutators:
            lines.append("**✏️ MUTATOR APIs (modify objects):**")
            for api in classification.mutators[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.mutators) > 5:
                lines.append(
                    f"  ... and {len(classification.mutators) - 5} more")
            lines.append("")

        if classification.serializers:
            lines.append("**📤 SERIALIZER APIs (output data):**")
            for api in classification.serializers[:3]:
                lines.append(f"  • {api.name}")
            lines.append("")

        if classification.destructors:
            lines.append("**🗑️ DESTRUCTOR APIs (cleanup - call last):**")
            for api in classification.destructors[:3]:
                lines.append(f"  • {api.name}")
            lines.append("")

        lines.append("**📋 RECOMMENDED FUZZING PRIORITY:**")
        priority_apis = classification.get_priority_apis()[:8]
        for i, api in enumerate(priority_apis, 1):
            lines.append(f"  {i}. {api.name} ({api.role.value})")

        return "\n".join(lines)

    def _format_api_sequences(self,
                              api_sequences: List[List[str]],
                              limit: int = 10) -> str:
        if not api_sequences:
            return "  (none)"
        lines = []
        for i, seq in enumerate(api_sequences[:limit]):
            seq_str = " → ".join(seq)
            lines.append(f"  Sequence {i+1}: {seq_str}")
        if len(api_sequences) > limit:
            lines.append(f"  ... and {len(api_sequences) - limit} more")
        return "\n".join(lines)

    def _format_project_apis(self,
                             project_apis: List[Dict[str, Any]],
                             limit: int = 20) -> str:
        if not project_apis:
            return "  (none)"
        lines = []
        for api in project_apis[:limit]:
            fn = api.get("function_name", "unknown")
            rt = api.get("return_type", "void")
            args = api.get("arguments", [])
            args_formatted = []
            for arg in args[:3]:
                if isinstance(arg, dict):
                    arg_type = arg.get("type", arg.get("type_clang", ""))
                    arg_name = arg.get("name", "")
                    args_formatted.append(f"{arg_type} {arg_name}".strip())
                else:
                    args_formatted.append(str(arg))
            args_str = ", ".join(args_formatted)
            if len(args) > 3:
                args_str += ", ..."
            lines.append(f"  • {rt} {fn}({args_str})")
        if len(project_apis) > limit:
            lines.append(f"  ... and {len(project_apis) - limit} more")
        return "\n".join(lines)

    def _format_dependency_graph(self,
                                 dep_graph: Dict[str, Any],
                                 limit: int = 12) -> str:
        graph = dep_graph.get("graph", {}) if isinstance(dep_graph,
                                                         dict) else {}
        if not graph:
            return "  (empty)"
        lines = []
        lines.append(
            f"  Total nodes: {dep_graph.get('num_nodes', len(graph))}")
        lines.append(f"  Showing up to {limit} dependencies:")
        for api, deps in list(graph.items())[:limit]:
            if deps:
                deps_str = ", ".join(
                    deps[:5]) + (" ..." if len(deps) > 5 else "")
                lines.append(f"    {api} depends on: {deps_str}")
            else:
                lines.append(f"    {api} depends on: (none)")
        return "\n".join(lines)

    def _format_condition_info(self, condition_info: Dict[str, Any]) -> str:
        if not condition_info:
            return "  (no constraints parsed)"
        sources = condition_info.get("sources", [])
        sinks = condition_info.get("sinks", [])
        inits = condition_info.get("inits", [])
        lines = []
        lines.append(f"  Sources ({len(sources)}): {', '.join(sources[:10])}" +
                     (" ..." if len(sources) > 10 else ""))
        lines.append(f"  Sinks ({len(sinks)}): {', '.join(sinks[:10])}" +
                     (" ..." if len(sinks) > 10 else ""))
        lines.append(f"  Init ({len(inits)}): {', '.join(inits[:10])}" +
                     (" ..." if len(inits) > 10 else ""))
        return "\n".join(lines)

    def _format_skeleton_drivers(self,
                                 skeleton_drivers: List[Dict[str, Any]],
                                 limit: int = 2) -> str:
        """Format pre-generated skeleton drivers for prompt (legacy reference mode)."""
        if not skeleton_drivers:
            return "  (no skeleton drivers available)"

        lines = []
        for i, skeleton in enumerate(skeleton_drivers[:limit]):
            name = skeleton.get("name", f"skeleton_{i}")
            api_seq = skeleton.get("api_sequence", [])
            holes = skeleton.get("holes", [])
            code = skeleton.get("code", "")

            lines.append(f"\n  **Skeleton {i+1}: {name}**")
            lines.append(f"    API sequence: {' → '.join(api_seq[:5])}" +
                         (" ..." if len(api_seq) > 5 else ""))

            if holes:
                unfilled = [h for h in holes if not h.get("filled", False)]
                hole_types = [str(h['hole_type']) for h in unfilled[:3]]
                lines.append(
                    f"    Holes to fill: {len(unfilled)} ({', '.join(hole_types)})"
                )

            if code:
                code_lines = code.split('\n')[:15]
                lines.append("    Code preview:")
                lines.append("    ```c")
                for line in code_lines:
                    lines.append(f"    {line}")
                if len(code.split('\n')) > 15:
                    lines.append("    // ... (truncated)")
                lines.append("    ```")

        if len(skeleton_drivers) > limit:
            lines.append(
                f"\n  ... and {len(skeleton_drivers) - limit} more skeleton drivers"
            )

        return "\n".join(lines)

    def _format_skeleton_as_template(
            self, skeleton_drivers: List[Dict[str, Any]],
            limit: int = 1) -> tuple:
        """Format skeleton as mandatory template with hole markers.

        This method formats the first skeleton as a mandatory template that the LLM
        must follow, extracting holes that need to be filled with appropriate code.

        Args:
            skeleton_drivers: List of skeleton driver dictionaries
            limit: Number of skeletons to use (default 1)

        Returns:
            Tuple of (skeleton_code, holes_description, has_skeleton)
            - skeleton_code: The skeleton code with hole placeholders
            - holes_description: Formatted description of holes to fill
            - has_skeleton: Whether a valid skeleton was found
        """
        if not skeleton_drivers:
            return "", "", False

        # Use the first skeleton with holes
        skeleton = None
        for sk in skeleton_drivers[:limit]:
            if sk.get('holes') and sk.get('code'):
                skeleton = sk
                break

        if skeleton is None:
            # Fallback to first skeleton even without explicit holes
            skeleton = skeleton_drivers[0]
            if not skeleton.get('code'):
                return "", "", False

        code = skeleton.get('code', '')
        holes = skeleton.get('holes', [])
        api_sequence = skeleton.get('api_sequence', [])

        # Format holes as structured list for LLM
        holes_desc_lines = []
        holes_desc_lines.append(f"API Sequence: {' → '.join(api_sequence)}")
        holes_desc_lines.append("")
        holes_desc_lines.append("Holes to fill:")

        if holes:
            for i, hole in enumerate(holes, 1):
                hole_name = hole.get('name', f'HOLE_{i}')
                hole_type = hole.get('hole_type', 'UNKNOWN')
                placeholder = hole.get('placeholder', f'__HOLE_{hole_name}__')
                is_simple = hole.get('is_simple', False)

                # Build description based on hole type
                desc = self._describe_hole(hole)
                holes_desc_lines.append(
                    f"  {i}. {placeholder}")
                holes_desc_lines.append(f"     Type: {hole_type}")
                holes_desc_lines.append(f"     {desc}")

                # Add hints for specific hole types
                if hole_type == 'CALLBACK_IMPL':
                    sig = hole.get('callback_signature', '')
                    if sig:
                        holes_desc_lines.append(f"     Signature: {sig}")
                elif hole_type == 'BUFFER_SIZE':
                    buf_idx = hole.get('buffer_arg_idx', -1)
                    len_idx = hole.get('length_arg_idx', -1)
                    rel = hole.get('relationship', '>=')
                    if buf_idx >= 0 and len_idx >= 0:
                        holes_desc_lines.append(
                            f"     Constraint: buffer[{buf_idx}] size {rel} param[{len_idx}]"
                        )
                holes_desc_lines.append("")
        else:
            holes_desc_lines.append(
                "  (No explicit holes - review code and fill any __HOLE_*__ placeholders)"
            )

        return code, "\n".join(holes_desc_lines), True

    def _describe_hole(self, hole: Dict[str, Any]) -> str:
        """Generate a description for a hole to guide LLM filling."""
        hole_type = hole.get('hole_type', 'UNKNOWN')

        descriptions = {
            'BUFFER_SIZE':
            'Fill with buffer size expression (e.g., "size", "data_len")',
            'ARRAY_LENGTH':
            'Fill with array length (e.g., "16", "MAX_ITEMS")',
            'CALLBACK_IMPL':
            'Fill with callback function implementation',
            'LOOP_CONDITION':
            'Fill with loop termination condition',
            'LOOP_BOUND':
            'Fill with maximum loop iterations (e.g., "100", "1000")',
            'INIT_VALUE':
            'Fill with initialization value (e.g., "0", "NULL", "data")',
            'RESOURCE_CLEANUP':
            'Fill with cleanup code for allocated resources',
            'ERROR_HANDLING':
            'Fill with error handling code',
        }

        return descriptions.get(hole_type, 'Fill with appropriate code')

    def _get_active_skeleton(
            self, state: FuzzingWorkflowState) -> tuple:
        """Get the active skeleton for the current synthesis attempt.

        Returns:
            Tuple of (skeleton_code, holes_list, api_sequence) or (None, None, None)
        """
        context = state.get('context', {})
        skeleton_drivers = context.get('skeleton_drivers', [])
        synthesized_drivers = context.get('synthesized_drivers', [])

        # First try synthesized drivers (from CBFactory skeleton mode)
        for driver in synthesized_drivers:
            if driver.get('synthesis_info', {}).get('method') == 'CBFactory_Skeleton':
                return (driver.get('code', ''),
                        driver.get('holes', []),
                        driver.get('api_sequence', []))

        # Fallback to skeleton_drivers
        if skeleton_drivers:
            sk = skeleton_drivers[0]
            return (sk.get('code', ''),
                    sk.get('holes', []),
                    sk.get('api_sequence', []))

        return None, None, None

    def _validate_skeleton_adherence(self, generated_code: str,
                                     skeleton_code: str,
                                     api_sequence: List[str]) -> bool:
        """Validate that generated code follows the skeleton structure.

        Checks:
        1. All APIs from the sequence appear in the generated code
        2. No unfilled holes remain

        Args:
            generated_code: The generated/merged code
            skeleton_code: The original skeleton code
            api_sequence: Expected API call sequence

        Returns:
            True if the code adheres to skeleton structure
        """
        if not generated_code:
            return False

        import re

        # Check for unfilled holes
        unfilled_holes = re.findall(
            r'__(?:HOLE|BUFSIZE|CALLBACK|INIT|LOOPCOND|LOOPBOUND|CLEANUP|ARRLEN)_[^_]+__',
            generated_code)
        if unfilled_holes:
            logger.warning(
                f'Generated code has {len(unfilled_holes)} unfilled holes',
                trial=self.trial)
            return False

        # Check that all APIs from sequence appear in generated code
        missing_apis = []
        for api in api_sequence:
            if api not in generated_code:
                missing_apis.append(api)

        if missing_apis:
            logger.warning(
                f'Generated code missing {len(missing_apis)} APIs from sequence: {missing_apis[:5]}',
                trial=self.trial)
            # Still return True if most APIs are present (>70%)
            return len(missing_apis) < len(api_sequence) * 0.3

        return True

    def _get_generation_mode(self, state: FuzzingWorkflowState) -> str:
        """Determine which generation mode to use based on state.

        Returns one of:
        - 'skeleton_strict': Use skeleton template with hole filling
        - 'skeleton_reference': Use skeleton as reference (legacy)
        - 'freeform': No skeleton, generate from scratch
        """
        skeleton_code, holes, api_sequence = self._get_active_skeleton(state)

        # Check if we have a valid skeleton with holes
        if skeleton_code and holes:
            return 'skeleton_strict'

        # Check if we have skeleton code at all (for reference)
        if skeleton_code:
            return 'skeleton_reference'

        # No skeleton available
        return 'freeform'

    def _format_driver_knowledge(self, driver_knowledge: Dict[str,
                                                              Any]) -> str:
        """Format knowledge extracted from existing drivers."""
        if not driver_knowledge:
            return ""

        driver_sources = driver_knowledge.get('driver_sources', [])
        analysis = driver_knowledge.get('analysis', {}) or {}

        if not driver_sources and not analysis:
            return ""

        lines = ["<existing_driver_knowledge>"]
        lines.append(
            f"Learn from {len(driver_sources)} existing OSS-Fuzz fuzz drivers."
        )
        lines.append("")

        core_func = analysis.get('core_functionality', '')
        if core_func:
            lines.append("<core_apis>")
            lines.append(core_func)
            lines.append("</core_apis>")
            lines.append("")

        code_patterns = analysis.get('code_patterns', '')
        if code_patterns:
            lines.append("<code_patterns>")
            lines.append(
                "IMPORTANT: These patterns show how to effectively use fuzz data."
            )
            lines.append(code_patterns)
            lines.append("</code_patterns>")
            lines.append("")

        setup_teardown = analysis.get('setup_teardown', '')
        if setup_teardown:
            lines.append("<setup_teardown>")
            lines.append(setup_teardown)
            lines.append("</setup_teardown>")
            lines.append("")

        if driver_sources:
            lines.append("<reference_drivers>")
            for d in driver_sources[:3]:
                source = d['source']
                # Strip license header if present (simple heuristic)
                if source.startswith('/*') or source.startswith('//'):
                    import re
                    source = re.sub(r'^(/\*.*?\*/|//.*?\n)+\s*',
                                    '',
                                    source,
                                    flags=re.DOTALL)
                lines.append(f"<driver path=\"{d['path']}\">")
                lines.append(source)
                lines.append("</driver>")
            lines.append("</reference_drivers>")

        lines.append("</existing_driver_knowledge>")
        return "\n".join(lines)

    def _format_include_path_context(
            self, target_path: str, existing_fuzzer_headers: Dict[str,
                                                                  Any]) -> str:
        """Format include path context."""
        import os

        lines = []

        if target_path:
            lines.append(f"  **Fuzz target location**: `{target_path}`")
            target_dir = os.path.dirname(target_path)
            lines.append(f"  **Target directory**: `{target_dir}`")
            lines.append("")
            lines.append("  When writing #include statements, remember:")
            lines.append(f"  - Your code will be saved to `{target_path}`")
            lines.append(
                "  - Use relative paths from this location to reach header files"
            )
        else:
            lines.append("  (target path not specified)")

        project_headers = existing_fuzzer_headers.get('project_headers', [])
        if project_headers:
            lines.append("")
            lines.append(
                "  **Reference includes from existing fuzzers** (COPY THESE EXACTLY):"
            )
            for header in project_headers[:5]:
                lines.append(f"    #include \"{header}\"")
            if len(project_headers) > 5:
                lines.append(f"    ... and {len(project_headers) - 5} more")

        if not lines:
            return "  (no include path context available)"

        return "\n".join(lines)

    def _validate_api_usage(self, code: str, project_name: str) -> str:
        """Validate generated code for internal/private API usage."""
        try:
            from src.utils.api_validator import validate_fuzz_target

            is_valid, report = validate_fuzz_target(code, project_name)

            if not is_valid:
                logger.warning('Generated code contains internal API usage',
                               trial=self.trial)
                return report
            else:
                logger.info('Generated code passed API validation',
                            trial=self.trial)
                return ""
        except Exception as e:
            logger.warning(f'API validation failed with error: {e}',
                           trial=self.trial)
            return ""

    def _format_analysis_summary(self, function_analysis: dict) -> str:
        """Format analysis summary for the Prototyper prompt."""
        srs_data = function_analysis.get('srs_data')
        if not srs_data:
            return function_analysis.get('raw_analysis',
                                         'No analysis available')

        # Build formatted SRS specification (kept for backward compatibility)
        output = []

        archetype = srs_data.get('archetype', {})
        output.append("### Archetype Pattern")
        output.append(
            f"**Primary Pattern**: {archetype.get('primary_pattern', 'Unknown')}"
        )
        output.append(f"**Reference**: {archetype.get('reference', 'N/A')}")
        output.append("")

        return "\n".join(output)

    def _retrieve_skeleton(self, _function_analysis: dict) -> str:
        """Retrieve skeleton code based on archetype (currently disabled)."""
        # Skeleton generation is now handled by CBFactory
        return ""
