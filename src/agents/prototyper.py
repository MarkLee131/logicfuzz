"""
LangGraphPrototyper agent for LangGraph workflow.

Generates fuzz drivers from API sequences using context provided in the prompt.
The FuzzIntrospector tool surface was removed; all context is pre-fetched.
"""
from typing import Any, Dict, List, Optional
import argparse

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.agents.utils import parse_tag
from src.utils.prompt_loader import get_prompt_manager
from data_prep.api_classifier import classify_project_apis


class LangGraphPrototyper(LangGraphAgent, ToolCallingMixin):
    """Prototyper agent that generates fuzz drivers from pre-fetched context."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("prototyper")
        super().__init__(name="prototyper",
                         model_name=model_name,
                         trial=trial,
                         args=args,
                         system_message=system_message)
        self.project_name = None
        self.benchmark = None

    # =========================================================================
    # ToolCallingMixin Implementation
    # =========================================================================

    def get_tools(self) -> List[BaseTool]:
        """No tools - all context is pre-fetched into the prompt."""
        return []

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

        import re

        result = skeleton_code
        filled_count = 0

        # First pass: direct replacement for exact matches
        for placeholder, filling in hole_fillings.items():
            if placeholder in result:
                result = result.replace(placeholder, str(filling))
                filled_count += 1
                logger.debug(
                    f'Filled hole {placeholder} with: {str(filling)[:50]}...'
                    if len(str(filling)) > 50 else f'Filled hole {placeholder} with: {filling}',
                    trial=self.trial)

        # Second pass: fuzzy matching for different key formats
        # LLM might return: "callback_1", "__CALLBACK_callback_1__", "CALLBACK_callback_1", etc.
        for placeholder, filling in hole_fillings.items():
            # Extract the core name from the placeholder
            # Handle formats: callback_1, __CALLBACK_callback_1__, CALLBACK_callback_1, etc.
            clean_name = placeholder.strip('_')

            # Remove known prefixes to get the base name
            prefixes = ['HOLE_', 'BUFSIZE_', 'CALLBACK_', 'INIT_', 'LOOPCOND_',
                       'LOOPBOUND_', 'CLEANUP_', 'ARRLEN_', 'ERRHANDLE_', 'COMPLEX_HOLE_']
            base_name = clean_name
            for prefix in prefixes:
                if clean_name.upper().startswith(prefix):
                    base_name = clean_name[len(prefix):]
                    break

            # Try all possible placeholder formats with this base name
            possible_patterns = [
                f'__{base_name}__',
                f'__HOLE_{base_name}__',
                f'__BUFSIZE_{base_name}__',
                f'__CALLBACK_{base_name}__',
                f'__INIT_{base_name}__',
                f'__LOOPCOND_{base_name}__',
                f'__LOOPBOUND_{base_name}__',
                f'__CLEANUP_{base_name}__',
                f'__ARRLEN_{base_name}__',
                f'__ERRHANDLE_{base_name}__',
                f'__COMPLEX_HOLE_{base_name}__',
            ]

            for pattern in possible_patterns:
                if pattern in result:
                    result = result.replace(pattern, str(filling))
                    filled_count += 1
                    logger.debug(
                        f'Filled hole {pattern} (from key {placeholder}) with: {str(filling)[:50]}...'
                        if len(str(filling)) > 50 else f'Filled hole {pattern} with: {filling}',
                        trial=self.trial)
                    break

        # Check for unfilled holes using a more comprehensive regex
        # Pattern matches: __TYPE_name__ where name can contain letters, digits, and underscores
        unfilled_pattern = r'__(?:HOLE|BUFSIZE|CALLBACK|INIT|LOOPCOND|LOOPBOUND|CLEANUP|ARRLEN|ERRHANDLE|COMPLEX_HOLE)_[\w]+__'
        unfilled = re.findall(unfilled_pattern, result)

        # Also check for HOLE comments that weren't filled
        hole_comments = re.findall(r'/\* HOLE\[[^\]]+\]:[^\*]+\*/', result)

        if unfilled:
            logger.warning(
                f'{len(unfilled)} holes remain unfilled: {unfilled[:5]}',
                trial=self.trial)

            # Try one more fallback: look for patterns in unfilled and match with fillings by number
            for unfilled_hole in unfilled:
                # Extract number from unfilled hole (e.g., __CALLBACK_callback_1__ -> 1)
                num_match = re.search(r'_(\d+)__$', unfilled_hole)
                if num_match:
                    hole_num = num_match.group(1)
                    # Look for any filling with this number
                    for placeholder, filling in hole_fillings.items():
                        if hole_num in placeholder and unfilled_hole in result:
                            result = result.replace(unfilled_hole, str(filling))
                            logger.debug(f'Fallback fill: {unfilled_hole} with {str(filling)[:30]}...',
                                        trial=self.trial)
                            break

        if hole_comments:
            logger.warning(
                f'{len(hole_comments)} HOLE comments remain: {hole_comments[:2]}',
                trial=self.trial)

        logger.info(f'Hole filling complete: {filled_count} holes filled', trial=self.trial)
        return result

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

        project_apis = context.get('project_apis', [])
        api_sequences = context.get('api_sequences', [])
        dependency_graph = context.get('dependency_graph', {})
        condition_info = context.get('condition_info', {})
        skeleton_drivers = context.get('skeleton_drivers', [])
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})
        existing_driver_knowledge = context.get('existing_driver_knowledge',
                                                {})
        header_info = context.get('header_info', {})

        # Get target path info for include path calculation
        target_path = benchmark.get('target_path', '')

        # Determine target language from file extension
        library_language = benchmark.get('language', 'c++').lower()
        cpp_extensions = ('.cpp', '.cc', '.cxx', '.c++')
        is_cpp_target = target_path.lower().endswith(cpp_extensions)
        is_c_project = library_language in ('c', )

        target_language = 'c++' if is_cpp_target else 'c'
        # OSS-Fuzz ALWAYS uses clang++ ($CXX) to compile fuzz targets, even .c files
        # When clang++ compiles C code, it applies C++ name mangling to functions
        # This breaks the linker because libFuzzer expects unmangled 'LLVMFuzzerTestOneInput'
        # Therefore, C projects always need extern "C" wrapper regardless of file extension
        needs_extern = is_c_project

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

        # Knowledge layer (comprehender output). Empty dict / list when the
        # comprehender was skipped or failed; downstream formatters degrade.
        comprehension = context.get('comprehension', {}) or {}
        sequence_semantics = context.get('sequence_semantics', []) or []
        library_purpose = comprehension.get('purpose', '')
        api_usages = comprehension.get('functions', {}) or {}

        # Per-trial primary sequence: trial N optimises for
        # api_sequences[(N-1) % K] specifically. Without this, every
        # trial sees the same top-K with no orientation, and the LLM
        # converges on the top-1 protocol — collapsing trial diversity
        # to LLM stochasticity. See note in _format_api_sequences for
        # the cjson/zlib symptom that motivated this fix.
        primary_index_for_trial: Optional[int] = None
        if api_sequences:
            primary_index_for_trial = (self.trial - 1) % len(api_sequences)
        api_sequences_text = self._format_api_sequences(
            api_sequences, limit=8, primary_index=primary_index_for_trial)
        sequence_signatures_text = self._format_sequence_api_signatures(
            api_sequences, project_apis, api_usages=api_usages)
        sequence_invariants_text = self._format_sequence_invariants(
            sequence_semantics)
        library_purpose_text = self._format_library_purpose(library_purpose)
        # Project-adaptive protocol templates (P3): N accepting paths sampled
        # directly from the project's learned automaton. These are *guaranteed
        # correct* shapes the project's tests already exercise — the LLM may
        # adapt or extend them to reach uncovered code, but should preserve
        # the protocol shape (creator → consumer order, paired destroy, etc.).
        protocol_templates_text = self._format_protocol_templates(
            (context.get('automaton') or {}).get('sample_paths') or []
        )
        project_apis_text = self._format_project_apis(project_apis, limit=20)
        dep_graph_text = self._format_dependency_graph(dependency_graph,
                                                       limit=12)
        condition_text = self._format_condition_info(condition_info)

        # === Single active skeleton for this trial ===
        # Trial N picks skeleton_drivers[(N-1) % K] once at the top; all
        # downstream renderers (template, base-driver, hole-merge,
        # generation_mode) consume the SAME element. Without this, three
        # separate format helpers each pinned different indices and trial
        # diversity collapsed (cjson/zlib repro: trial diff was just
        # whitespace).
        active_skeleton: Optional[Dict[str, Any]] = None
        if skeleton_drivers:
            active_idx = (self.trial - 1) % len(skeleton_drivers)
            active_skeleton = skeleton_drivers[active_idx]
            logger.info(
                f'[Synthesis Mode] Trial {self.trial} → '
                f'skeleton_drivers[{active_idx}] of {len(skeleton_drivers)}',
                trial=self.trial)

        skeleton_template_code, holes_description, has_skeleton_template = \
            self._format_skeleton_as_template(active_skeleton)
        include_path_context = self._format_include_path_context(
            target_path, existing_fuzzer_headers)
        driver_knowledge_text = self._format_driver_knowledge(
            existing_driver_knowledge)

        # The Z3-validated skeleton rendered as "base for refinement". The
        # LLM is told to refine THIS specific driver (preserve API order,
        # fix compilation, improve coverage). Mutually consistent with
        # has_skeleton_template above — same active_skeleton, two views.
        synthesis_base_text = ""
        if active_skeleton is not None:
            synthesis_base_text = self._format_synthesis_base_driver(
                active_skeleton)

        # Add extern "C" guidance if needed
        extern_c_note = ""
        if needs_extern:
            extern_c_note = """
**CRITICAL: extern "C" Required for C Projects**
OSS-Fuzz compiles all fuzz targets with clang++ (C++ compiler), even .c files.
You MUST declare LLVMFuzzerTestOneInput with extern "C" linkage:
```c
#ifdef __cplusplus
extern "C" {
#endif

#include "library_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // ... your code ...
    return 0;
}

#ifdef __cplusplus
}
#endif
```
Without extern "C", the linker will fail with "undefined reference to LLVMFuzzerTestOneInput".
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
{library_purpose_text}{api_understanding_text}

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

<sequence_api_signatures>
{sequence_signatures_text}
</sequence_api_signatures>

{protocol_templates_text}
{sequence_invariants_text}

<project_apis>
{project_apis_text}
</project_apis>

<dependency_graph>
{dep_graph_text}
</dependency_graph>

<constraints>
{condition_text}
</constraints>

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
                synthesis_base_text, srs_specification, skeleton_code,
                additional_context)

        prompt = build_prompt_with_session_memory(state,
                                                  base_prompt,
                                                  agent_name=self.name)

        # Use tool calling loop - LLM can optionally use tools
        parsed_result, all_responses = self.run_tool_calling_loop(
            initial_prompt=prompt,
            state=state,
            max_rounds=getattr(self.args, 'max_round', 5),
            log_prefix="PROTOTYPER")

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

        # Fix common header issues (FuzzedDataProvider, etc.)
        if fuzz_target_code:
            fuzz_target_code = self._fix_common_header_issues(fuzz_target_code)

        # Ensure project headers are included (post-processing fix for LLM-generated code)
        if fuzz_target_code and header_info.get('project_headers'):
            fuzz_target_code = self._ensure_project_headers(
                fuzz_target_code, header_info, target_language)

        # Ensure extern "C" wrapper for C projects (OSS-Fuzz always uses clang++)
        if fuzz_target_code and is_c_project:
            fuzz_target_code = self._ensure_extern_c_wrapper(fuzz_target_code)

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
                               dep_graph_text, condition_text,
                               synthesis_base_text,
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

{synthesis_base_text}

<project_analysis>
{srs_specification}
</project_analysis>

<skeleton_code>
{skeleton_code}
</skeleton_code>

{additional_context}

</reference_information>

<generation_rules>
CRITICAL: Generate a fuzz driver using ONLY the APIs listed in <api_sequences> above.
These sequences were carefully selected by our Progressive Filter Pipeline (L0-L4) to maximize coverage.
DO NOT substitute with different APIs even if you think they are similar or better.
DO NOT use APIs like ares_parse_a_reply or ares_parse_mx_reply unless they appear in <api_sequences>.

Requirements:
1. Use EXACTLY the APIs from <api_sequences> - they have been validated for:
   - Type compatibility (L0)
   - Entry point presence (L1)
   - Lifecycle correctness (L2)
   - State machine validity (L3)
   - Coverage potential (L4)
2. Preserve the API call order from the sequence
3. Use correct include paths - the fuzz target will be placed at the location shown above
</generation_rules>

<output_format>
Output your fuzz driver code inside <fuzz_target> tags.
</output_format>"""

    # =========================================================================
    # Formatting helpers (unchanged from original)
    # =========================================================================

    def _format_synthesis_base_driver(
        self,
        active_skeleton: Optional[Dict[str, Any]],
    ) -> str:
        """Render the trial-bound Z3 skeleton as the LLM's refinement base.

        Caller selected the active_skeleton via trial-rotation upstream;
        no rotation logic here. Returns "" if active_skeleton is falsy
        (no skeletons synthesised this run).
        """
        if not active_skeleton:
            return ""

        driver_name = active_skeleton.get('name', 'cbfactory_skeleton')
        api_sequence = active_skeleton.get('api_sequence', [])
        code = active_skeleton.get('code', '')
        synthesis_info = active_skeleton.get('synthesis_info', {})

        lines = [
            "",
            "**=== CBFactory SYNTHESIZED DRIVER (Base for Refinement) ===**",
            "",
            "The following driver was generated by CBFactory (traditional program synthesis).",
            "It is structurally correct and respects API constraints, but needs YOUR refinement:",
            "",
            "**Your tasks:**",
            "1. **Fix compilation issues** - Add missing headers, fix type errors",
            "2. **Improve input generation** - Replace basic buffers with structured fuzzer input",
            "3. **Add error handling** - Check return values, handle NULL pointers",
            "4. **Enhance coverage** - Add branches, test edge cases",
            "5. **Keep the API sequence** - The call order is constraint-validated, preserve it",
            "",
            f"**Driver: {driver_name}**",
            f"  - API sequence ({len(api_sequence)} calls): "
            + " → ".join(api_sequence[:8])
            + (" ..." if len(api_sequence) > 8 else ""),
        ]
        if synthesis_info:
            lines.append(
                f"  - Synthesis method: {synthesis_info.get('method', 'CBFactory')}"
            )
            lines.append(
                f"  - Has cleanup: {synthesis_info.get('has_cleanup', False)}")
        lines += [
            "",
            "**Base Code (REFINE THIS):**",
            "```cpp",
        ]
        code_lines = code.split('\n')
        if len(code_lines) > 80:
            lines.extend(code_lines[:80])
            lines.append("// ... (truncated)")
        else:
            lines.append(code)
        lines += [
            "```",
            "",
            "**IMPORTANT:** Use this as your starting point. Keep the API call sequence,",
            "but improve the driver to be compilable and achieve high code coverage.",
            "",
        ]
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
                              limit: int = 10,
                              primary_index: Optional[int] = None) -> str:
        """Render the top-K API sequences for the prototyper prompt.

        ``primary_index`` (default None for backwards-compat) marks ONE
        sequence as the trial's main target — the LLM is then instructed
        to optimise for that sub-language specifically. Without it, all
        N samples of the same benchmark pin on the same top-1 protocol
        and merge_drivers ends up folding LLM-stochastic copies of the
        same protocol (the silent bug found in cjson/zlib runs: trial
        diff was just whitespace + variable naming).
        """
        if not api_sequences:
            return "  (none)"
        lines = []
        # Render up to `limit` sequences, prefixing the primary one with
        # an explicit marker so the LLM knows which to optimise for.
        if primary_index is not None and 0 <= primary_index < len(api_sequences):
            lines.append(
                f"  *** PRIMARY for this trial — optimise this sequence's "
                f"coverage specifically *** (Sequence {primary_index + 1})")
        for i, seq in enumerate(api_sequences[:limit]):
            seq_str = " → ".join(seq)
            marker = (" ★ PRIMARY" if i == primary_index else "")
            lines.append(f"  Sequence {i+1}{marker}: {seq_str}")
        if len(api_sequences) > limit:
            lines.append(f"  ... and {len(api_sequences) - limit} more")
        return "\n".join(lines)

    def _format_sequence_api_signatures(self,
                                        api_sequences: List[List[str]],
                                        project_apis: List[Dict[str, Any]],
                                        api_usages: Optional[Dict[str, str]] = None) -> str:
        """Format FULL signatures for APIs that appear in sequences.

        This is critical for LLM to understand pointer semantics correctly.
        Unlike _format_project_apis which truncates at 3 args, this shows ALL args.
        When ``api_usages`` is provided (from comprehender-A) each signature is
        followed by its usage note so the model gets type + intent in one place.
        """
        if not api_sequences or not project_apis:
            return "  (none)"

        # Collect unique API names from sequences
        sequence_apis = set()
        for seq in api_sequences:
            sequence_apis.update(seq)

        # Build API name -> full info lookup
        api_lookup = {}
        for api in project_apis:
            fn = api.get("function_name", "")
            if fn:
                api_lookup[fn] = api

        lines = []
        lines.append("**FULL SIGNATURES for APIs in your sequences:**")
        lines.append("(IMPORTANT: Pay attention to pointer types like `type **` which are output parameters!)")
        lines.append("")

        for api_name in sorted(sequence_apis):
            if api_name not in api_lookup:
                continue
            api = api_lookup[api_name]
            rt = api.get("return_type", api.get("return_info", {}).get("type_clang", "void"))
            args = api.get("arguments", api.get("arguments_info", []))

            # Format ALL arguments with full type info
            args_formatted = []
            for i, arg in enumerate(args):
                if isinstance(arg, dict):
                    arg_type = arg.get("type", arg.get("type_clang", "unknown"))
                    arg_const = arg.get("const", [])
                    # Add const qualifier if present
                    if arg_const and arg_const[0]:
                        arg_type = f"const {arg_type}"
                    arg_name = arg.get("name", f"arg{i}")
                    args_formatted.append(f"{arg_type} {arg_name}".strip())
                else:
                    args_formatted.append(str(arg))

            args_str = ", ".join(args_formatted)

            # Highlight output pointer arguments
            has_output_ptr = any("* *" in a or "**" in a for a in args_formatted)
            note = ""
            if has_output_ptr:
                note = "  // ⚠️ Has output pointer parameter (type **)"

            lines.append(f"  {rt} {api_name}({args_str});{note}")
            if api_usages:
                usage = api_usages.get(api_name, "").strip()
                if usage:
                    lines.append(f"      usage: {usage}")

        if not lines[3:]:  # No APIs formatted
            return "  (no matching APIs found)"

        return "\n".join(lines)

    def _format_library_purpose(self, purpose: str) -> str:
        """Render the library-purpose blurb (comprehender-A output)."""
        purpose = (purpose or "").strip()
        if not purpose:
            return ""
        return f"<library_purpose>\n{purpose}\n</library_purpose>\n"

    def _format_protocol_templates(
            self,
            sample_paths: List[List[str]],
            limit: int = 4) -> str:
        """Render automaton-sampled protocol templates (P3 output).

        Each path is a sequence of API names that the project's tests
        already exercise (post EDSM merging — may compose multiple test
        bodies). They are *templates*, not constraints: the LLM may extend
        them with novel APIs to reach uncovered code, but should preserve
        the protocol shape (creator → consumer order; paired destroy at the
        end; etc.).
        """
        if not sample_paths:
            return ""
        lines: List[str] = ["<protocol_templates>"]
        lines.append(
            "(API call shapes the project's own tests use; treat as "
            "templates, not exact requirements — feel free to substitute "
            "or extend APIs to maximise coverage, but keep the lifecycle/"
            "ordering structure.)"
        )
        for i, path in enumerate(sample_paths[:limit], 1):
            if not path:
                continue
            lines.append(f"  template_{i}: {' -> '.join(path)}")
        lines.append("</protocol_templates>\n")
        return "\n".join(lines)

    def _format_sequence_invariants(
            self, sequence_semantics: List[Dict[str, Any]]) -> str:
        """Surface comprehender-B verdicts so the prototyper respects invariants.

        For each non-VALID sequence we expose: the original sequence, the
        diagnosis, the repair recommendation (if any), and the prototyper-facing
        invariants. VALID sequences only appear if they carried any invariants.
        """
        if not sequence_semantics:
            return ""
        lines: List[str] = []
        for entry in sequence_semantics:
            status = (entry.get("semantic_status") or "VALID").upper()
            invariants = entry.get("invariants_for_prototyper") or []
            diagnosis = (entry.get("diagnosis") or "").strip()
            repair = entry.get("repair") or {}
            patched = repair.get("patched_sequence")
            action = (repair.get("action") or "NONE").upper()
            if status == "VALID" and not invariants and not patched:
                continue
            seq = entry.get("sequence") or []
            lines.append(f"- sequence: {' -> '.join(seq) or '(empty)'}")
            lines.append(f"    status: {status}")
            if diagnosis:
                lines.append(f"    diagnosis: {diagnosis}")
            if patched and action != "NONE":
                rationale = (repair.get("rationale") or "").strip()
                lines.append(
                    f"    suggested fix ({action}): {' -> '.join(patched)}"
                    + (f"  // {rationale}" if rationale else ""))
            for inv in invariants[:3]:
                inv_text = (inv or "").strip()
                if inv_text:
                    lines.append(f"    invariant: {inv_text}")
        if not lines:
            return ""
        return ("<sequence_semantics>\n"
                "(verdicts from semantic comprehender; respect any invariants "
                "and prefer the suggested fix when available)\n"
                + "\n".join(lines)
                + "\n</sequence_semantics>\n")

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

    def _format_skeleton_as_template(
            self,
            active_skeleton: Optional[Dict[str, Any]]) -> tuple:
        """Render the trial's active skeleton as a MANDATORY hole-filling
        template (LLM must preserve structure, only fill marked holes).

        Caller selected the active_skeleton via trial-rotation upstream;
        no rotation here.

        Returns:
            Tuple of (skeleton_code, holes_description, has_skeleton).
            Returns ("", "", False) when active_skeleton is None or has
            no code.
        """
        if not active_skeleton or not active_skeleton.get('code'):
            return "", "", False

        skeleton = active_skeleton
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
        """Get this trial's active Z3 skeleton.

        Trial N picks ``skeleton_drivers[(N-1) % K]`` — the same rotation
        used at the prompt-rendering top of ``__call__``. Both call sites
        (hole-merge and ``_get_generation_mode``) get the SAME skeleton
        the prompt was built from.

        Returns:
            Tuple of (skeleton_code, holes_list, api_sequence) or
            (None, None, None) when no skeletons are available.
        """
        skeleton_drivers = state.get('context', {}).get('skeleton_drivers', [])
        if not skeleton_drivers:
            return None, None, None

        active_idx = (self.trial - 1) % len(skeleton_drivers)
        sk = skeleton_drivers[active_idx]
        return (sk.get('code', ''),
                sk.get('holes', []),
                sk.get('api_sequence', []))

    # The earlier ``_validate_skeleton_adherence`` and
    # ``_get_generation_mode`` methods were removed in the 2026-05 Agent
    # review — both were defined but never called from anywhere in the
    # codebase. ``llm_vs_traditional_choices.md`` §A historically
    # described a "validator re-checks LLM output against the skeleton"
    # gate; that contract is now enforced at synthesis time via the
    # skeleton-template prompt mode (see ``_format_skeleton_as_template``)
    # and post-hoc via the runtime build attempt + Fixer cycle, not via
    # a separate Python-side adherence checker.
    #
    # The dead ``unauthorized_apis = ['ares_parse_a_reply', ...]`` hardcode
    # from the deleted method is also gone — same pattern as the L2
    # c-ares-specific patterns we already flagged for generalisation.

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
        """Validate generated code for internal/private API usage.

        Previously swallowed validator exceptions and returned ``""`` (the
        signal for "validation passed"). The 2026-05 Agent review caught
        this — under CLAUDE.md's "No fallbacks — explicit failures"
        principle, a validator crash should not be reported as a clean
        pass. Now we tag the validation_warnings string so the Fixer
        sees the failure mode and can react.
        """
        try:
            from src.utils.unified_validator import UnifiedCodeValidator, format_validation_report

            validator = UnifiedCodeValidator()
            result = validator.validate(code=code, project_name=project_name)

            if not result.success:
                logger.warning('Generated code contains internal API usage',
                               trial=self.trial)
                return format_validation_report(result)
            logger.info('Generated code passed API validation',
                        trial=self.trial)
            return ""
        except Exception as e:
            logger.warning(f'API validation crashed with {type(e).__name__}: {e}',
                           trial=self.trial)
            return f"validator_error: {type(e).__name__}: {e}"

    def _format_analysis_summary(self, function_analysis: dict) -> str:
        """Format analysis summary for the Prototyper prompt."""
        srs_data = function_analysis.get('srs_data')
        if not srs_data:
            return function_analysis.get('raw_analysis',
                                         'No analysis available')

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

    def _ensure_extern_c_wrapper(self, code: str) -> str:
        """Ensure extern "C" wrapper is present for C projects.

        OSS-Fuzz ALWAYS uses clang++ ($CXX) to compile fuzz targets, even .c files.
        Without extern "C", C++ name mangling will cause linker errors.

        Args:
            code: Generated fuzz target source code

        Returns:
            Code with extern "C" wrapper added if missing
        """
        import re

        if not code or not code.strip():
            return code

        # Check if extern "C" is already present
        if 'extern "C"' in code or "extern 'C'" in code:
            return code

        # Find the LLVMFuzzerTestOneInput function
        fuzzer_pattern = r'(int\s+LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{)'
        match = re.search(fuzzer_pattern, code)
        if not match:
            return code

        # Find include section end
        lines = code.split('\n')
        include_end_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#include'):
                include_end_idx = i + 1
            elif stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
                # First non-include, non-comment line
                if include_end_idx > 0:
                    break

        # Insert extern "C" wrapper after includes
        new_lines = lines[:include_end_idx]
        new_lines.append('')
        new_lines.append('#ifdef __cplusplus')
        new_lines.append('extern "C" {')
        new_lines.append('#endif')
        new_lines.append('')

        # Add remaining code
        new_lines.extend(lines[include_end_idx:])

        # Add closing brace before end of file
        # Find the closing brace of LLVMFuzzerTestOneInput
        result = '\n'.join(new_lines)

        # Add closing extern "C" at the very end
        result = result.rstrip() + '\n\n#ifdef __cplusplus\n}\n#endif\n'

        return result

    def _ensure_project_headers(self, code: str, header_info: Dict[str, Any], target_language: str) -> str:
        """Ensure project headers are included in the generated code.

        This is a post-processing step to fix LLM-generated code that may be
        missing required project headers.

        Args:
            code: Generated fuzz target source code
            header_info: Header info dict with 'project_headers' and 'standard_headers'
            target_language: 'c' or 'c++'

        Returns:
            Code with project headers added if they were missing
        """
        import re

        if not code or not code.strip():
            return code

        project_headers = header_info.get('project_headers', [])
        if not project_headers:
            return code

        # Check which project headers are already included
        existing_includes = set()
        for match in re.finditer(r'#include\s*[<"]([^>"]+)[>"]', code):
            existing_includes.add(match.group(1))

        # Find missing project headers
        missing_headers = []
        for header in project_headers:
            # Check both bare name and common variations
            if header not in existing_includes:
                # Also check if it's included with a path
                header_basename = header.split('/')[-1] if '/' in header else header
                if header_basename not in existing_includes:
                    missing_headers.append(header)

        if not missing_headers:
            return code

        # Build header includes to add
        header_lines = []
        for header in missing_headers:
            # Use quotes for project headers (not angle brackets)
            header_lines.append(f'#include <{header}>')

        # Find the best place to insert headers (after existing includes)
        lines = code.split('\n')
        insert_idx = 0

        # Find last #include line or after any comment header
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#include'):
                insert_idx = i + 1
            elif stripped.startswith('/*') or stripped.startswith('//') or stripped.startswith('*'):
                if insert_idx == 0:
                    insert_idx = i + 1

        # Insert missing headers
        for j, header_line in enumerate(header_lines):
            lines.insert(insert_idx + j, header_line)

        result = '\n'.join(lines)
        logger.info(
            f'Added {len(missing_headers)} missing project headers: {missing_headers}',
            trial=self.trial)

        return result

    def _fix_common_header_issues(self, code: str) -> str:
        """Fix common header issues in LLM-generated code.

        This fixes issues like:
        - Missing FuzzedDataProvider include when the class is used
        - Wrong FuzzedDataProvider include path/case
        - Missing angle brackets for system headers

        Args:
            code: Generated fuzz target source code

        Returns:
            Code with header issues fixed
        """
        import re

        if not code or not code.strip():
            return code

        fixes_applied = []

        # Fix FuzzedDataProvider includes - common LLM mistakes:
        # - "fuzzed_data_provider.h" -> <fuzzer/FuzzedDataProvider.h>
        # - "FuzzedDataProvider.h" -> <fuzzer/FuzzedDataProvider.h>
        # - <FuzzedDataProvider.h> -> <fuzzer/FuzzedDataProvider.h>
        # - "fuzzer/fuzzeddataprovider.h" -> <fuzzer/FuzzedDataProvider.h>
        fdp_patterns = [
            (r'#include\s*"fuzzed_data_provider\.h"', '#include <fuzzer/FuzzedDataProvider.h>'),
            (r'#include\s*"FuzzedDataProvider\.h"', '#include <fuzzer/FuzzedDataProvider.h>'),
            (r'#include\s*<FuzzedDataProvider\.h>', '#include <fuzzer/FuzzedDataProvider.h>'),
            (r'#include\s*"fuzzer/fuzzeddataprovider\.h"', '#include <fuzzer/FuzzedDataProvider.h>'),
            (r'#include\s*"fuzzer/FuzzedDataProvider\.h"', '#include <fuzzer/FuzzedDataProvider.h>'),
            # Case-insensitive catch-all for fuzzed.*data.*provider patterns
            (r'#include\s*[<"](?:[^>"]*[/\\])?[Ff]uzzed[_]?[Dd]ata[_]?[Pp]rovider\.h[>"]',
             '#include <fuzzer/FuzzedDataProvider.h>'),
        ]

        for pattern, replacement in fdp_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                new_code = re.sub(pattern, replacement, code, flags=re.IGNORECASE)
                if new_code != code:
                    fixes_applied.append('FuzzedDataProvider include path')
                    code = new_code
                    break  # Only apply one FDP fix

        # Check if FuzzedDataProvider is used but no include exists at all
        # This is the most common issue: LLM uses the class but forgets the include
        fdp_include_correct = '#include <fuzzer/FuzzedDataProvider.h>'
        has_fdp_include = re.search(r'#include\s*[<"][^>"]*[Ff]uzzed[_]?[Dd]ata[_]?[Pp]rovider', code)
        uses_fdp = 'FuzzedDataProvider' in code

        if uses_fdp and not has_fdp_include:
            # Add the include after the last existing #include line
            lines = code.split('\n')
            last_include_idx = -1
            for i, line in enumerate(lines):
                if line.strip().startswith('#include'):
                    last_include_idx = i

            if last_include_idx >= 0:
                # Insert after the last include
                lines.insert(last_include_idx + 1, fdp_include_correct)
            else:
                # No includes found, add at the beginning
                lines.insert(0, fdp_include_correct)

            code = '\n'.join(lines)
            fixes_applied.append('added missing FuzzedDataProvider include')

        if fixes_applied:
            logger.info(
                f'Fixed common header issues: {fixes_applied}',
                trial=self.trial)

        return code
