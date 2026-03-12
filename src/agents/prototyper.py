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
        """Parse final LLM response to extract fuzz target code."""
        fuzz_target_code = parse_tag(content, 'fuzz_target')
        return {'fuzz_target_code': fuzz_target_code, 'raw_response': content}

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
            base_prompt += f"""

<task>
Generate a high-coverage LibFuzzer fuzz driver for the {benchmark.get('project', 'unknown')} project.
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
</reference_information>

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

1. PRIORITY: Focus on PARSER APIs - They consume external input and have highest bug potential
2. For parsers: Generate STRUCTURED input (not random strings!)
   - JSON parsers need valid JSON structure with fuzz-derived values
   - XML parsers need valid XML structure
   - Binary parsers need valid headers/magic bytes
3. For accessor APIs (Has*, Get*, Is*): Hit BOTH branches
   - Pre-populate objects with known keys to hit "found" path
   - Query with missing keys to hit "not found" path
4. For type checks (IsArray, IsObject): Test multiple types
5. Follow the dependency order in sequences
6. Clean up resources properly
7. Use correct include paths - the fuzz target will be placed at the location shown above
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
        """Format pre-generated skeleton drivers for prompt."""
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
