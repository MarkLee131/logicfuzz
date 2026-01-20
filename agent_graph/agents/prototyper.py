"""
LangGraphPrototyper agent for LangGraph workflow.
"""
from typing import Any, Dict, List, Optional
import argparse

import logger
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from agent_graph.prompt_loader import get_prompt_manager
from data_prep.api_classifier import classify_project_apis, APIRole


class LangGraphPrototyper(LangGraphAgent):
    """Prototyper agent for LangGraph."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("prototyper")
        super().__init__(
            name="prototyper",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Generate fuzz target code."""
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )

        benchmark = state["benchmark"]
        function_analysis = state.get("function_analysis", {})
        context = state.get('context', {})

        # === Synthesis mode is always enabled (CBFactory as base for LLM refinement) ===
        synthesized_drivers = context.get('synthesized_drivers', [])

        project_apis = context.get('project_apis', [])
        api_sequences = context.get('api_sequences', [])
        dependency_graph = context.get('dependency_graph', {})
        condition_info = context.get('condition_info', {})
        pattern_analysis = context.get('pattern_analysis', {})
        skeleton_drivers = context.get('skeleton_drivers', [])
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})

        # Get target path info for include path calculation
        target_path = benchmark.get('target_path', '')

        language = benchmark.get('language', 'C++')
        is_regeneration = state.get("compile_success") == False and state.get("fuzz_target_source", "") != ""

        prompt_manager = get_prompt_manager()
        additional_context = ""
        if is_regeneration:
            build_errors = state.get("build_errors", [])
            if build_errors:
                additional_context = f"\n**Note**: Previous code generation failed to compile. Key errors:\n"
                additional_context += "\n".join(build_errors[:3])  # Show first 3 errors
                additional_context += "\n\nPlease generate a completely new approach that avoids these issues."

        skeleton_code = self._retrieve_skeleton(function_analysis)
        # NOTE: SRS has been removed; this now formats the raw analysis summary
        srs_specification = self._format_analysis_summary(function_analysis)

        # === API Classification and Project Understanding ===
        # Classify APIs by semantic role to guide generation strategy
        project_name = benchmark.get('project', 'unknown')
        api_classification = classify_project_apis(project_name, project_apis)
        api_understanding_text = self._format_api_understanding(api_classification)

        logger.info(
            f'API Classification: {len(api_classification.parsers)} parsers, '
            f'{len(api_classification.creators)} creators, '
            f'{len(api_classification.accessors)} accessors, '
            f'{len(api_classification.mutators)} mutators',
            trial=self.trial
        )

        api_sequences_text = self._format_api_sequences(api_sequences, limit=8)
        project_apis_text = self._format_project_apis(project_apis, limit=20)
        dep_graph_text = self._format_dependency_graph(dependency_graph, limit=12)
        condition_text = self._format_condition_info(condition_info)
        pattern_text = self._format_pattern_analysis(pattern_analysis)
        skeleton_text = self._format_skeleton_drivers(skeleton_drivers, limit=2)
        include_path_context = self._format_include_path_context(target_path, existing_fuzzer_headers)

        # === Synthesis mode: Format CBFactory base driver for LLM refinement ===
        # Note: Synthesis is always enabled - CBFactory generates base, LLM refines
        synthesis_base_text = ""
        if synthesized_drivers:
            synthesis_base_text = self._format_synthesis_base_driver(synthesized_drivers, state)
            logger.info(
                f'[Synthesis Mode] Providing {len(synthesized_drivers)} CBFactory drivers as base for LLM refinement',
                trial=self.trial
            )

        try:
            base_prompt = prompt_manager.build_user_prompt(
                "prototyper",
                project_name=benchmark.get('project', 'unknown'),
                function_name="",  # Empty for project-level
                function_signature="",  # Empty for project-level
                srs_specification=srs_specification,
                additional_context=additional_context,
                skeleton_code=skeleton_code
            )
            base_prompt += f"""

**=== STEP 1: UNDERSTAND THE PROJECT (Think before coding!) ===**

{api_understanding_text}

Before writing any code, think about:
1. What is this project's main purpose?
2. Which APIs are PARSERS that consume external input? (These are fuzzing priority!)
3. What input format do the parsers expect? (JSON? XML? Binary?)
4. What is the typical data flow? (Parse → Query → Modify → Serialize?)

**=== STEP 2: REFERENCE INFORMATION ===**

**Include Path Context (IMPORTANT for correct #include statements):**
{include_path_context}

**API Sequences (from Liberator grammar):**
{api_sequences_text}

**Project APIs (sample):**
{project_apis_text}

**Dependency Graph (sample):**
{dep_graph_text}

**Liberator Constraints (ConditionManager):**
{condition_text}

**Special Pattern Analysis (VarLen/Loop/Callback/TLV):**
{pattern_text}

**Pre-generated Skeleton Drivers (reference):**
{skeleton_text}
{synthesis_base_text}
**=== STEP 3: GENERATE HIGH-COVERAGE DRIVER ===**

Generate a fuzz driver following these CRITICAL rules:

1. **PRIORITY: Focus on PARSER APIs** - They consume external input and have highest bug potential
2. **For parsers**: Generate STRUCTURED input (not random strings!)
   - JSON parsers need valid JSON structure with fuzz-derived values
   - XML parsers need valid XML structure
   - Binary parsers need valid headers/magic bytes
3. **For accessor APIs (Has*, Get*, Is*)**: Hit BOTH branches
   - Pre-populate objects with known keys to hit "found" path
   - Query with missing keys to hit "not found" path
4. **For type checks (IsArray, IsObject)**: Test multiple types
5. Follow the dependency order in sequences
6. Clean up resources properly
7. **Use correct include paths** - the fuzz target will be placed at the location shown above
"""
        except Exception as e:
            # Fallback: build prompt manually if template doesn't support project-level
            logger.warning(f"Prompt template may not support project-level mode: {e}", trial=self.trial)
            base_prompt = f"""Generate a fuzz target for project {benchmark.get('project', 'unknown')}.

**Include Path Context (IMPORTANT for correct #include statements):**
{include_path_context}

**API Sequences (from Liberator grammar):**
{api_sequences_text}

**Project APIs (sample):**
{project_apis_text}

**Dependency Graph (sample):**
{dep_graph_text}

**Liberator Constraints (ConditionManager):**
{condition_text}

**Special Pattern Analysis (VarLen/Loop/Callback/TLV):**
{pattern_text}

**Pre-generated Skeleton Drivers (reference):**
{skeleton_text}

**Project Analysis:**
{srs_specification}

**Skeleton Code:**
{skeleton_code}

{additional_context}

Generate a complete LibFuzzer-compatible fuzz driver using the API sequences above.
Handle var-len relationships and use appropriate callback stubs if needed.
**Use correct include paths** - the fuzz target will be placed at the location shown above."""

        prompt = build_prompt_with_session_memory(state, base_prompt, agent_name=self.name)
        response = self.chat_llm(state, prompt)

        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)

        fuzz_target_code = parse_tag(response, 'fuzz_target')
        if not fuzz_target_code:
            # Fallback: use entire response, but still strip CDATA if present
            from agent_graph.agents.utils import strip_cdata
            fuzz_target_code = strip_cdata(response)

        validation_warnings = self._validate_api_usage(
            fuzz_target_code,
            benchmark.get('project', 'unknown')
        )

        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "compile_success": None,
            "build_errors": [],
            "retry_count": 0,
            "session_memory": updated_session_memory,
            "api_validation_warnings": validation_warnings
        }

        if is_regeneration:
            prototyper_regenerate_count = state.get("prototyper_regenerate_count", 0)
            state_update["prototyper_regenerate_count"] = prototyper_regenerate_count + 1
            state_update["compilation_retry_count"] = 0
            logger.info(f'Prototyper regeneration #{prototyper_regenerate_count + 1}, '
                       f'resetting compilation_retry_count', trial=self.trial)

        self._langgraph_logger.flush_agent_logs(self.name)

        return state_update

    # === Synthesis mode support ===

    def _format_synthesis_base_driver(self, synthesized_drivers: List[Dict[str, Any]],
                                      state: FuzzingWorkflowState) -> str:
        """
        Format CBFactory synthesized drivers as base for LLM refinement.

        In synthesis mode, CBFactory generates structurally correct but basic drivers.
        The LLM's job is to refine and improve these drivers by:
        - Adding proper error handling
        - Improving input generation strategy
        - Adding coverage-improving logic
        - Fixing any compilation issues

        Args:
            synthesized_drivers: List of synthesized driver dictionaries
            state: Current workflow state (for tracking which driver to use)

        Returns:
            Formatted string to include in the prompt
        """
        if not synthesized_drivers:
            return ""

        lines = []
        lines.append("")
        lines.append("**=== CBFactory SYNTHESIZED DRIVER (Base for Refinement) ===**")
        lines.append("")
        lines.append("The following driver was generated by CBFactory (traditional program synthesis).")
        lines.append("It is structurally correct and respects API constraints, but needs YOUR refinement:")
        lines.append("")
        lines.append("**Your tasks:**")
        lines.append("1. **Fix compilation issues** - Add missing headers, fix type errors")
        lines.append("2. **Improve input generation** - Replace basic buffers with structured fuzzer input")
        lines.append("3. **Add error handling** - Check return values, handle NULL pointers")
        lines.append("4. **Enhance coverage** - Add branches, test edge cases")
        lines.append("5. **Keep the API sequence** - The call order is constraint-validated, preserve it")
        lines.append("")

        # Select which driver to show (can rotate through them on regeneration)
        synthesis_index = state.get("synthesis_driver_index", 0) if state else 0
        if synthesis_index >= len(synthesized_drivers):
            synthesis_index = 0

        # Show the selected driver
        driver = synthesized_drivers[synthesis_index]
        driver_name = driver.get('name', f'cbfactory_driver_{synthesis_index}')
        api_sequence = driver.get('api_sequence', [])
        code = driver.get('code', '')
        synthesis_info = driver.get('synthesis_info', {})

        lines.append(f"**Driver: {driver_name}**")
        lines.append(f"  - API sequence ({len(api_sequence)} calls): {' → '.join(api_sequence[:8])}" +
                    (" ..." if len(api_sequence) > 8 else ""))
        if synthesis_info:
            lines.append(f"  - Synthesis method: {synthesis_info.get('method', 'CBFactory')}")
            lines.append(f"  - Has cleanup: {synthesis_info.get('has_cleanup', False)}")
        lines.append("")
        lines.append("**Base Code (REFINE THIS):**")
        lines.append("```cpp")
        # Truncate if too long
        code_lines = code.split('\n')
        if len(code_lines) > 80:
            lines.extend(code_lines[:80])
            lines.append("// ... (truncated, see full code in synthesis output)")
        else:
            lines.append(code)
        lines.append("```")
        lines.append("")
        lines.append("**IMPORTANT:** Use this as your starting point. Keep the API call sequence,")
        lines.append("but improve the driver to be compilable and achieve high code coverage.")
        lines.append("")

        # If there are more drivers, mention them
        if len(synthesized_drivers) > 1:
            lines.append(f"*({len(synthesized_drivers) - 1} more synthesized drivers available for reference)*")
            lines.append("")

        return "\n".join(lines)

    # === Formatting helpers ===

    def _format_api_understanding(self, classification) -> str:
        """
        Format API classification into project understanding guidance.

        This helps the LLM understand the project's API structure and
        guides it to generate better initial drivers.
        """
        from data_prep.api_classifier import APIClassificationResult

        if not isinstance(classification, APIClassificationResult):
            return "  (API classification not available)"

        lines = []

        # Summary
        lines.append("**API Role Analysis** (automated classification):")
        lines.append(f"  Total APIs analyzed: {len(classification.apis)}")
        lines.append("")

        # Parser APIs - HIGHEST PRIORITY
        if classification.parsers:
            lines.append("**🎯 PARSER APIs (PRIORITY - consume external input):**")
            lines.append("  These APIs should be the PRIMARY fuzzing targets!")
            for api in classification.parsers[:5]:
                lines.append(f"  • {api.name} (confidence: {api.confidence:.0%})")
                if api.signature:
                    lines.append(f"    Signature: {api.signature}")
            if len(classification.parsers) > 5:
                lines.append(f"  ... and {len(classification.parsers) - 5} more")
            lines.append("")
            lines.append("  ⚠️ CRITICAL: For parser APIs, generate STRUCTURED input!")
            lines.append("     DO NOT use fdp.ConsumeRandomLengthString() for parsers.")
            lines.append("     Instead, generate valid structure with fuzz-derived values.")
            lines.append("")

        # Accessor APIs - Need branch coverage
        if classification.accessors:
            lines.append("**🔍 ACCESSOR APIs (need both found/not-found branches):**")
            for api in classification.accessors[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.accessors) > 5:
                lines.append(f"  ... and {len(classification.accessors) - 5} more")
            lines.append("")
            lines.append("  ⚠️ TIP: Pre-populate objects with known keys,")
            lines.append("     then query both existing and missing keys.")
            lines.append("")

        # Creator APIs
        if classification.creators:
            lines.append("**🏗️ CREATOR APIs (construct objects):**")
            for api in classification.creators[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.creators) > 5:
                lines.append(f"  ... and {len(classification.creators) - 5} more")
            lines.append("")

        # Mutator APIs
        if classification.mutators:
            lines.append("**✏️ MUTATOR APIs (modify objects):**")
            for api in classification.mutators[:5]:
                lines.append(f"  • {api.name}")
            if len(classification.mutators) > 5:
                lines.append(f"  ... and {len(classification.mutators) - 5} more")
            lines.append("")

        # Serializer APIs
        if classification.serializers:
            lines.append("**📤 SERIALIZER APIs (output data):**")
            for api in classification.serializers[:3]:
                lines.append(f"  • {api.name}")
            lines.append("")

        # Destructor APIs
        if classification.destructors:
            lines.append("**🗑️ DESTRUCTOR APIs (cleanup - call last):**")
            for api in classification.destructors[:3]:
                lines.append(f"  • {api.name}")
            lines.append("")

        # Priority recommendation
        lines.append("**📋 RECOMMENDED FUZZING PRIORITY:**")
        priority_apis = classification.get_priority_apis()[:8]
        for i, api in enumerate(priority_apis, 1):
            lines.append(f"  {i}. {api.name} ({api.role.value})")

        return "\n".join(lines)

    def _format_api_sequences(self, api_sequences: List[List[str]], limit: int = 10) -> str:
        if not api_sequences:
            return "  (none)"
        lines = []
        for i, seq in enumerate(api_sequences[:limit]):
            seq_str = " → ".join(seq)
            lines.append(f"  Sequence {i+1}: {seq_str}")
        if len(api_sequences) > limit:
            lines.append(f"  ... and {len(api_sequences) - limit} more")
        return "\n".join(lines)

    def _format_project_apis(self, project_apis: List[Dict[str, Any]], limit: int = 20) -> str:
        if not project_apis:
            return "  (none)"
        lines = []
        for api in project_apis[:limit]:
            fn = api.get("function_name", "unknown")
            rt = api.get("return_type", "void")
            args = api.get("arguments", [])
            # Handle args that can be either strings or dicts
            args_formatted = []
            for arg in args[:3]:
                if isinstance(arg, dict):
                    # Format dict args as "type name"
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

    def _format_dependency_graph(self, dep_graph: Dict[str, Any], limit: int = 12) -> str:
        graph = dep_graph.get("graph", {}) if isinstance(dep_graph, dict) else {}
        if not graph:
            return "  (empty)"
        lines = []
        lines.append(f"  Total nodes: {dep_graph.get('num_nodes', len(graph))}")
        lines.append(f"  Showing up to {limit} dependencies:")
        for api, deps in list(graph.items())[:limit]:
            if deps:
                deps_str = ", ".join(deps[:5]) + (" ..." if len(deps) > 5 else "")
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
        lines.append(f"  Sources ({len(sources)}): {', '.join(sources[:10])}" + (" ..." if len(sources) > 10 else ""))
        lines.append(f"  Sinks ({len(sinks)}): {', '.join(sinks[:10])}" + (" ..." if len(sinks) > 10 else ""))
        lines.append(f"  Init ({len(inits)}): {', '.join(inits[:10])}" + (" ..." if len(inits) > 10 else ""))
        return "\n".join(lines)

    def _format_pattern_analysis(self, pattern_analysis: Dict[str, Any]) -> str:
        """Format pattern analysis results (VarLen/Loop/Callback/TLV) for prompt."""
        if not pattern_analysis:
            return "  (no pattern analysis available)"

        lines = []

        # Summary
        summary = pattern_analysis.get("summary", {})
        if summary:
            lines.append(f"  Summary: {summary.get('apis_with_varlen', 0)} APIs with var-len, "
                        f"{summary.get('apis_needing_loop', 0)} needing loop, "
                        f"{summary.get('apis_with_callbacks', 0)} with callbacks, "
                        f"{summary.get('structured_parsers', 0)} TLV parsers")

        # VarLen relations
        varlen = pattern_analysis.get("varlen", {})
        if varlen:
            lines.append("\n  **Var-Len Relations** (buffer ↔ size parameters):")
            for api_name, relations in list(varlen.items())[:5]:
                for rel in relations:
                    lines.append(f"    • {api_name}: {rel['buffer_arg_name']} {rel['relationship']} {rel['length_arg_name']}")

        # Loop patterns
        loop = pattern_analysis.get("loop", {})
        if loop:
            lines.append("\n  **Loop Patterns** (APIs that may need loop calls):")
            for api_name, info in list(loop.items())[:5]:
                lines.append(f"    • {api_name}: {info['loop_type']} loop, terminate when {info['termination_condition']}")

        # Callback info
        callback = pattern_analysis.get("callback", {})
        if callback:
            lines.append("\n  **Callback Parameters** (function pointers):")
            for api_name, cbs in list(callback.items())[:5]:
                for cb in cbs:
                    lines.append(f"    • {api_name}[{cb['arg_idx']}]: {cb['callback_type']} callback ({cb['arg_name']})")

        # TLV parsers
        tlv = pattern_analysis.get("tlv", {})
        if tlv:
            lines.append("\n  **Structured Data Parsers** (TLV/protocol):")
            for api_name, info in list(tlv.items())[:5]:
                lines.append(f"    • {api_name}: {info['format_type']} format, min_size={info['min_size']}")

        return "\n".join(lines) if lines else "  (no patterns detected)"

    def _format_skeleton_drivers(self, skeleton_drivers: List[Dict[str, Any]], limit: int = 2) -> str:
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
            lines.append(f"    API sequence: {' → '.join(api_seq[:5])}" + (" ..." if len(api_seq) > 5 else ""))

            if holes:
                unfilled = [h for h in holes if not h.get("filled", False)]
                hole_types = [str(h['hole_type']) for h in unfilled[:3]]
                lines.append(f"    Holes to fill: {len(unfilled)} ({', '.join(hole_types)})")

            # Show truncated code snippet
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
            lines.append(f"\n  ... and {len(skeleton_drivers) - limit} more skeleton drivers")

        return "\n".join(lines)

    def _format_include_path_context(self, target_path: str, existing_fuzzer_headers: Dict[str, Any]) -> str:
        """
        Format include path context to help LLM generate correct #include statements.

        Args:
            target_path: Where the fuzz target will be placed (e.g., /src/cjson/fuzzing/cjson_read_fuzzer.c)
            existing_fuzzer_headers: Headers extracted from existing fuzzers

        Returns:
            Formatted context string with target location and example includes
        """
        import os

        lines = []

        # 1. Show where the target will be placed
        if target_path:
            lines.append(f"  **Fuzz target location**: `{target_path}`")
            target_dir = os.path.dirname(target_path)
            lines.append(f"  **Target directory**: `{target_dir}`")
            lines.append("")
            lines.append("  When writing #include statements, remember:")
            lines.append(f"  - Your code will be saved to `{target_path}`")
            lines.append("  - Use relative paths from this location to reach header files")
            lines.append("  - Example: if header is at `/src/project/header.h` and target is at `/src/project/fuzzing/fuzz.c`,")
            lines.append("    use `#include \"../header.h\"` (go up one directory)")
        else:
            lines.append("  (target path not specified)")

        # 2. Show existing fuzzer includes as reference
        project_headers = existing_fuzzer_headers.get('project_headers', [])
        if project_headers:
            lines.append("")
            lines.append("  **Reference includes from existing fuzzers** (COPY THESE EXACTLY):")
            for header in project_headers[:5]:
                lines.append(f"    #include \"{header}\"")
            if len(project_headers) > 5:
                lines.append(f"    ... and {len(project_headers) - 5} more")

        if not lines:
            return "  (no include path context available)"

        return "\n".join(lines)

    def _validate_api_usage(self, code: str, project_name: str) -> str:
        """
        Validate generated code for internal/private API usage.
        
        Args:
            code: Generated fuzz target code
            project_name: Project name
        
        Returns:
            Formatted validation warnings (empty string if no issues)
        """
        try:
            from agent_graph.api_validator import validate_fuzz_target
            
            is_valid, report = validate_fuzz_target(code, project_name)
            
            if not is_valid:
                logger.warning(
                    f'Generated code contains internal API usage - validation failed',
                    trial=self.trial
                )
                logger.info(f'Validation report:\n{report}', trial=self.trial)
                return report
            else:
                logger.info('Generated code passed API validation', trial=self.trial)
                return ""
        
        except Exception as e:
            logger.warning(f'API validation failed with error: {e}', trial=self.trial)
            return ""
    
    def _format_analysis_summary(self, function_analysis: dict) -> str:
        """
        Format analysis summary for the Prototyper prompt.

        NOTE: SRS has been removed. This method now simply returns the raw_analysis
        text generated by the function analyzer from Liberator data.

        Args:
            function_analysis: Analysis containing raw_analysis text

        Returns:
            Formatted analysis summary string
        """
        # SRS has been removed - srs_data is always None now
        # Simply return the raw analysis text from function analyzer
        srs_data = function_analysis.get('srs_data')

        # Always fall back to raw analysis (srs_data is always None now)
        if not srs_data:
            return function_analysis.get('raw_analysis', 'No analysis available')
        
        # Build formatted SRS specification
        output = []
        
        # Add archetype information
        archetype = srs_data.get('archetype', {})
        output.append("### Archetype Pattern")
        output.append(f"**Primary Pattern**: {archetype.get('primary_pattern', 'Unknown')}")
        output.append(f"**Reference**: {archetype.get('reference', 'N/A')}")
        output.append(f"**Confidence**: {archetype.get('confidence', 'Unknown')}")
        output.append(f"**Evidence**: {archetype.get('evidence_count', 'N/A')}")
        output.append("")
        
        # Add functional requirements
        frs = srs_data.get('functional_requirements', [])
        if frs:
            output.append("### Functional Requirements")
            for fr in frs:
                output.append(f"**{fr.get('id', 'FR-?')}** [{fr.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {fr.get('requirement', 'N/A')}")
                if fr.get('parameter'):
                    output.append(f"- **Parameter**: {fr['parameter']}")
                output.append(f"- **Rationale**: {fr.get('rationale', 'N/A')}")
                impl = fr.get('implementation', {})
                if impl.get('code'):
                    output.append(f"- **Implementation**:")
                    output.append(f"```{impl.get('language', 'c')}")
                    output.append(impl['code'])
                    output.append("```")
                output.append(f"- **Failure Mode**: {fr.get('failure_mode', 'Unknown')}")
                output.append("")
        
        # Add preconditions
        pres = srs_data.get('preconditions', [])
        if pres:
            output.append("### Preconditions")
            for pre in pres:
                output.append(f"**{pre.get('id', 'PRE-?')}** [{pre.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {pre.get('requirement', 'N/A')}")
                output.append(f"- **Check Method**: {pre.get('check_method', 'N/A')}")
                output.append(f"- **Rationale**: {pre.get('rationale', 'N/A')}")
                output.append(f"- **Violation → {pre.get('violation_consequence', 'Unknown')}**")
                output.append("")
        
        # Add postconditions
        posts = srs_data.get('postconditions', [])
        if posts:
            output.append("### Postconditions")
            for post in posts:
                output.append(f"**{post.get('id', 'POST-?')}** [{post.get('priority', 'MANDATORY')}]")
                output.append(f"- **Requirement**: {post.get('requirement', 'N/A')}")
                output.append(f"- **Check Method**: {post.get('check_method', 'N/A')}")
                output.append(f"- **Rationale**: {post.get('rationale', 'N/A')}")
                output.append("")
        
        # Add constraints
        cons = srs_data.get('constraints', [])
        if cons:
            output.append("### Constraints")
            for con in cons:
                output.append(f"**{con.get('id', 'CON-?')}** [Type: {con.get('type', 'Unknown')}]")
                output.append(f"- **Requirement**: {con.get('requirement', 'N/A')}")
                if con.get('parameter'):
                    output.append(f"- **Parameter**: {con['parameter']}")
                output.append(f"- **Valid Range/Sequence**: {con.get('valid_range_or_sequence', 'N/A')}")
                output.append(f"- **Rationale**: {con.get('rationale', 'N/A')}")
                
                # Add execution sequence if available
                impl = con.get('implementation', {})
                sequence = impl.get('sequence', [])
                if sequence:
                    output.append("- **Execution Sequence**:")
                    for step in sequence:
                        output.append(f"  {step.get('step', '?')}. {step.get('description', 'N/A')}")
                        if step.get('code'):
                            output.append(f"     ```c")
                            output.append(f"     {step['code']}")
                            output.append(f"     ```")
                output.append("")
        
        # Add parameter strategies
        params = srs_data.get('parameter_strategies', [])
        if params:
            output.append("### Parameter Strategies")
            for param in params:
                output.append(f"**Parameter**: `{param.get('parameter', 'unknown')}`")
                output.append(f"- **Type**: {param.get('type', 'unknown')}")
                output.append(f"- **Strategy**: {param.get('strategy', 'DIRECT_FUZZ')}")
                output.append(f"- **Construction**: {param.get('construction_method', 'N/A')}")
                if param.get('constraints'):
                    output.append(f"- **Constraints**: {param['constraints']}")
                if param.get('fixed_value'):
                    output.append(f"- **Fixed Value**: {param['fixed_value']}")
                if param.get('driver_code'):
                    output.append(f"- **Driver Code**:")
                    output.append(f"```c")
                    output.append(param['driver_code'])
                    output.append("```")
                output.append("")
        
        # Add metadata
        metadata = srs_data.get('metadata', {})
        if metadata:
            output.append("### Metadata")
            output.append(f"- **Category**: {metadata.get('category', 'Unknown')}")
            output.append(f"- **Complexity**: {metadata.get('complexity', 'Unknown')}")
            output.append(f"- **State Model**: {metadata.get('state_model', 'Unknown')}")
            output.append(f"- **Recommended Approach**: {metadata.get('recommended_approach', 'direct_call')}")
            output.append(f"- **Purpose**: {metadata.get('purpose', 'N/A')}")
            output.append("")
        
        return "\n".join(output)
    
    def _retrieve_skeleton(self, function_analysis: dict) -> str:
        """
        Retrieve skeleton code based on archetype.

        Note: long_term_memory module has been removed. This method now returns
        empty string. Skeleton generation is handled by Liberator's CBFactory.

        Args:
            function_analysis: Analysis containing archetype and header information

        Returns:
            Empty string (skeleton retrieval disabled)
        """
        # long_term_memory module has been removed
        # Skeleton generation is now handled by Liberator's driver generation pipeline
        return ""
    
    def _format_header_section(self, header_info: dict, archetype: str = None) -> str:
        """
        Format header information as C/C++ comments for skeleton injection.
        
        Priority (NEW - API-aware):
        - For C APIs: FuzzIntrospector headers > Definition file headers
        - For C++ APIs: Definition file headers > FuzzIntrospector headers
        
        Rationale:
        - C APIs often have separate declaration headers (e.g., ada_c.h vs ada.cpp)
        - C++ APIs usually declare in the same header they include (e.g., ada.h)
        
        Args:
            header_info: Dictionary containing header information
            archetype: Archetype name (used to determine required standard headers)
        """
        if not header_info:
            return "// NOTE: Header file information not available"
        
        # Detect API type
        is_c_api = header_info.get('is_c_api', False)
        
        # Start with LibFuzzer required headers
        header_lines = [
            "// === HEADER FILES ===",
            "// IMPORTANT: These headers are carefully selected from the project's source code.",
            "// Do NOT modify unless you encounter build errors (e.g., 'file not found').",
            "// If you see errors about internal headers (../../internal/, _impl.h, etc.),",
            "// remove them and use the public API headers instead.",
            "//",
            "// LibFuzzer required headers",
            "#include <stddef.h>",
            "#include <stdint.h>"
        ]
        
        # Add archetype-specific standard headers
        if archetype == "round_trip":
            header_lines.extend([
                "#include <stdlib.h>",
                "#include <string.h>",
                "#include <assert.h>"
            ])
        elif archetype == "file_based":
            header_lines.extend([
                "#include <stdio.h>",
                "#include <unistd.h>"
            ])
        
        header_lines.append("")  # Blank line after standard headers
        
        # ===== HEADER PRIORITY: EXISTING FUZZERS FIRST =====
        # RATIONALE: Existing fuzzer headers are PROVEN to compile in OSS-Fuzz
        # They are the ONLY source that guarantees correct paths and availability
        
        func_header = header_info.get('function_header')
        related_headers = header_info.get('related_headers', [])
        definition_headers = header_info.get('definition_file_headers')
        existing = header_info.get('existing_fuzzer_headers', {})
        
        has_fi_headers = func_header or related_headers
        has_definition = definition_headers and (
            definition_headers.get('standard_headers') or 
            definition_headers.get('project_headers')
        )
        has_existing = existing.get('standard_headers') or existing.get('project_headers')
        
        # PRIORITY 1 (HIGHEST): Headers from existing fuzzers
        if has_existing:
            header_lines.append("//")
            header_lines.append("// PRIMARY HEADERS (from working fuzzers - COPY THESE):")
            header_lines.append("// ⚠️ THESE ARE PROVEN TO COMPILE - use exactly as shown")
            header_lines.append("//")
            
            # Add project headers from existing fuzzers (highest confidence)
            existing_proj = existing.get('project_headers', [])[:5]  # Top 5 most common
            if existing_proj:
                # CRITICAL FILTER: Remove inappropriate headers
                filtered_headers = []
                for proj_h in existing_proj:
                    # ⚠️ KEEP .cpp/.cc files if they appear in existing fuzzers!
                    # Some projects (e.g., ada-url, header-only libs) explicitly include
                    # implementation files. If existing fuzzers use them, they're valid.
                    # DO NOT filter them out - trust the existing fuzzer patterns.
                    # (Previously we skipped .cpp files, but this broke single-header patterns)
                    
                    # For C API functions: prioritize C headers but keep .cpp if used by existing fuzzers
                    if is_c_api:
                        base_name = proj_h.lower()
                        
                        # ALWAYS keep .cpp/.cc/.cxx files (implementation includes)
                        # Even C API fuzzers may need them (e.g., ada_c.c needs ada.cpp)
                        if proj_h.endswith('.cpp') or proj_h.endswith('.cc') or proj_h.endswith('.cxx'):
                            filtered_headers.append(proj_h)
                            logger.debug(f'Keeping implementation file for C API (from existing fuzzers): {proj_h}', trial=self.trial)
                        # Keep C API headers (e.g., ada_c.h)
                        elif '_c.h' in base_name or base_name.endswith('_c.h'):
                            filtered_headers.append(proj_h)
                        # Keep generic .h files (might be C-compatible)
                        elif base_name.endswith('.h') and not any(cpp_indicator in base_name for cpp_indicator in ['.hpp', 'xx']):
                            filtered_headers.append(proj_h)
                        else:
                            # Skip pure C++ headers (ada.h, ada.hpp) for C API
                            logger.debug(f'Skipping C++ header for C API function: {proj_h}', trial=self.trial)
                    else:
                        # For C++ API: keep all headers (including both C++ and C headers)
                        filtered_headers.append(proj_h)
                
                if filtered_headers:
                    header_lines.append("// Project headers (copy these first):")
                    for proj_h in filtered_headers:
                        header_lines.append(f'#include "{proj_h}"')
                    header_lines.append("")
                else:
                    logger.warning(f'All existing project headers were filtered out for {"C" if is_c_api else "C++"} API', trial=self.trial)
            
            # Add standard headers from existing fuzzers (as comments - uncomment if needed)
            existing_std = existing.get('standard_headers', [])[:8]
            if existing_std:
                header_lines.append("// Standard headers from working fuzzers (uncomment if needed):")
                for std_h in existing_std:
                    header_lines.append(f'// #include <{std_h}>')
                header_lines.append("")
        
        # PRIORITY 2: API-specific headers (FI or Definition) - AS FALLBACK/REFERENCE
        # CASE 1: C API - FuzzIntrospector headers as SECONDARY/REFERENCE
        if is_c_api and has_fi_headers:
            header_lines.append("//")
            header_lines.append("// SECONDARY: FuzzIntrospector headers (C API - uncomment if needed):")
            header_lines.append("// NOTE: Existing fuzzer headers above are higher priority")
            header_lines.append("//")
            
            # Add FI's primary header as COMMENT (not directly included)
            if func_header:
                header_lines.append(f'// #include "{func_header}"  // FI suggestion')
                logger.info(f'FI header for C API (as reference): {func_header}', trial=self.trial)
            
            # Add related FI headers as comments (optional)
            if related_headers:
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
            
            header_lines.append("")
            
            # Definition file headers become TERTIARY (supplementary standard headers only)
            if has_definition:
                std_headers = definition_headers.get('standard_headers', [])[:10]  # Limit to top 10
                if std_headers:
                    header_lines.append("// Supplementary standard headers (from definition file):")
                    for std_h in sorted(set(std_headers)):
                        header_lines.append(f'// #include {std_h}  // Uncomment if needed')
                    header_lines.append("")
        
        # CASE 2: C++ API OR No FI headers - Definition file headers as SECONDARY
        elif has_definition and not has_existing:
            # Only use definition headers if NO existing fuzzer headers are available
            header_lines.append("//")
            if is_c_api:
                header_lines.append("// SECONDARY: Headers from definition file (C API fallback):")
            else:
                header_lines.append("// SECONDARY: Headers from definition file (C++ API):")
            header_lines.append("//")
            
            # Add project headers (from definition file) - most important
            proj_headers = definition_headers.get('project_headers', [])
            if proj_headers:
                for proj_h in sorted(set(proj_headers)):
                    # Already includes " "
                    header_lines.append(f'#include {proj_h}')
                header_lines.append("")
            
            # Add standard library headers (from definition file) as comments
            std_headers = definition_headers.get('standard_headers', [])[:10]
            if std_headers:
                header_lines.append("// Standard headers from definition (uncomment if needed):")
                for std_h in sorted(set(std_headers)):
                    # Already includes < >
                    header_lines.append(f'// #include {std_h}')
                header_lines.append("")
            
            # FI headers become TERTIARY (as comments)
            if has_fi_headers:
                header_lines.append("// FuzzIntrospector headers (uncomment if needed):")
                if func_header:
                    header_lines.append(f'// #include "{func_header}"')
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
                header_lines.append("")
        
        # CASE 3: Fallback - only FI headers available (lowest priority)
        elif has_fi_headers and not has_existing:
            header_lines.append("//")
            header_lines.append("// Headers from FuzzIntrospector (use with caution):")
            header_lines.append("//")
            
            if func_header:
                header_lines.append(f'// #include "{func_header}"  // May need path adjustment')
            
            if related_headers:
                for h in related_headers[:3]:
                    header_lines.append(f'// #include "{h}"')
            
            header_lines.append("")
        # ===============================================
        
        header_lines.append("// ====================")
        return "\n".join(header_lines)
    
    def _extract_archetype_from_analysis(self, analysis_text: str) -> Optional[str]:
        """
        Extract archetype from function analysis text.
        
        Looks for explicit archetype declarations or infers from keywords.
        """
        if not analysis_text:
            return None
        
        # Look for explicit archetype declaration
        import re
        
        # Pattern 1: "Primary pattern: {archetype}"
        # FIX: Use non-greedy match and stop at line end to avoid capturing next line
        pattern1 = r"Primary pattern:\s*([A-Za-z\-\s]+?)(?:\n|$)"
        match = re.search(pattern1, analysis_text, re.IGNORECASE)
        if match:
            archetype_name = match.group(1).strip().lower()
            # Normalize to our archetype names
            mapping = {
                "stateless parser": "stateless_parser",
                "object lifecycle": "object_lifecycle",
                "state machine": "state_machine",
                "stream processor": "stream_processor",
                "round-trip": "round_trip",
                "round trip": "round_trip",
                "file-based": "file_based",
                "file based": "file_based",
                "global initialization": "global_initialization",
                "global init": "global_initialization",
                "stateful fuzzing": "stateful_fuzzing",
                "stateful": "stateful_fuzzing"
            }
            result = mapping.get(archetype_name)
            if result:
                logger.debug(f"Extracted archetype via Pattern 1: '{archetype_name}' -> '{result}'", trial=self.trial)
                return result
        
        # Pattern 2: "Archetype: {archetype}"
        # FIX: Use non-greedy match and stop at line end
        pattern2 = r"Archetype:\s*([A-Za-z\-\s]+?)(?:\n|$)"
        match = re.search(pattern2, analysis_text, re.IGNORECASE)
        if match:
            archetype_name = match.group(1).strip().lower()
            mapping = {
                "stateless parser": "stateless_parser",
                "object lifecycle": "object_lifecycle",
                "state machine": "state_machine",
                "stream processor": "stream_processor",
                "round-trip": "round_trip",
                "round trip": "round_trip",
                "file-based": "file_based",
                "file based": "file_based",
                "global initialization": "global_initialization",
                "global init": "global_initialization",
                "stateful fuzzing": "stateful_fuzzing",
                "stateful": "stateful_fuzzing"
            }
            result = mapping.get(archetype_name)
            if result:
                logger.debug(f"Extracted archetype via Pattern 2: '{archetype_name}' -> '{result}'", trial=self.trial)
                return result
        
        logger.debug(f"No archetype pattern matched in analysis text (length: {len(analysis_text)})", trial=self.trial)
        return None
    

