"""
LangGraphEnhancer agent for LangGraph workflow.
"""
from typing import Any, Dict
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from agent_graph.prompt_loader import get_prompt_manager


class LangGraphEnhancer(LangGraphAgent):
    """Enhancer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("enhancer")
        super().__init__(
            name="enhancer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Fix compilation errors."""
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        build_errors = state.get("build_errors", [])
        workflow_phase = state.get("workflow_phase", "compilation")

        language = benchmark.get('language', 'C++')
        error_text = "\n".join(build_errors[:10])
        code_context = self._generate_code_context(current_code, build_errors)

        function_analysis = state.get("function_analysis", {})
        header_info = function_analysis.get("header_information", {})
        header_hints = self._format_header_hints(header_info, build_errors)
        api_warnings = state.get("api_validation_warnings", "")

        additional_context_parts = []
        if header_hints:
            additional_context_parts.append(header_hints)
        if api_warnings:
            additional_context_parts.append("\n---\n\n# ⚠️  API Validation Warnings\n\n" + api_warnings)
        
        additional_context = "\n".join(additional_context_parts)

        prompt_manager = get_prompt_manager()
        base_prompt = prompt_manager.build_user_prompt(
            "enhancer",
            project_name=benchmark.get('project', 'unknown'),
            language=language,
            current_code=code_context,
            build_errors=error_text,
            additional_context=additional_context
        )

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

        state_update = {
            "fuzz_target_source": fuzz_target_code,
            "previous_fuzz_target_source": current_code,
            "compile_success": None,
            "build_errors": [],
            "session_memory": updated_session_memory
        }

        if workflow_phase == "compilation":
            compilation_retry_count = state.get("compilation_retry_count", 0)
            state_update["compilation_retry_count"] = compilation_retry_count + 1
            logger.info(f'Compilation retry count: {compilation_retry_count + 1}', trial=self.trial)
        else:
            retry_count = state.get("retry_count", 0)
            state_update["retry_count"] = retry_count + 1

        self._langgraph_logger.flush_agent_logs(self.name)
        
        return state_update
    
    def _generate_code_context(self, current_code: str, build_errors: list) -> str:
        """
        Generate code context for enhancer based on diff strategy.

        Strategy: Extract only the error-relevant parts of code to reduce token usage.

        Args:
            current_code: Current fuzz target code
            build_errors: List of build errors

        Returns:
            Code context string (diff or relevant sections)
        """
        if not current_code:
            return ""

        error_lines = set()
        for error in build_errors:
            import re
            matches = re.findall(r':(\d+):', error) or re.findall(r'line (\d+)', error)
            for match in matches:
                try:
                    line_num = int(match)
                    for i in range(max(1, line_num - 10), line_num + 11):
                        error_lines.add(i)
                except (ValueError, IndexError):
                    continue

        if error_lines:
            code_lines = current_code.split('\n')
            relevant_lines = []
            last_included = -100

            for line_num in sorted(error_lines):
                if line_num <= len(code_lines):
                    if line_num - last_included > 1 and last_included != -100:
                        relevant_lines.append("// ... (lines omitted) ...")
                    relevant_lines.append(f"/* Line {line_num} */ {code_lines[line_num - 1]}")
                    last_included = line_num

            if relevant_lines:
                context = "**Code sections relevant to errors:**\n```cpp\n" + "\n".join(relevant_lines) + "\n```"
                logger.debug(f'Extracted {len(relevant_lines)} relevant lines from {len(code_lines)} total lines',
                            trial=self.trial)
                return context

        if len(current_code) < 5000:
            return current_code

        code_lines = current_code.split('\n')
        if len(code_lines) > 100:
            first_50 = '\n'.join(code_lines[:50])
            last_50 = '\n'.join(code_lines[-50:])
            return f"{first_50}\n\n// ... (middle section omitted) ...\n\n{last_50}"
        
        return current_code
    
    def _format_header_hints(self, header_info: dict, build_errors: list) -> str:
        """
        Format header information as hints for the Enhancer to fix header-related errors.

        Provides priority-ordered header guidance to prevent LLM from using
        internal headers extracted from source code.
        """
        if not header_info:
            return ""

        has_header_errors = any(
            'file not found' in error.lower() or 
            'no such file' in error.lower() or
            '#include' in error.lower()
            for error in build_errors
        )
        
        if not has_header_errors:
            return ""
        
        hint_lines = [
            "",
            "# ⚡ Known Header Information (STRICT PRIORITY ORDER)",
            "",
            "⚠️  **CRITICAL**: Use headers in this STRICT priority order. Lower priority sources may contain",
            "INTERNAL implementation headers that WILL FAIL to compile in OSS-Fuzz fuzz targets.",
            ""
        ]
        
        # ANTI-PATTERN: Show what was FILTERED OUT first (negative examples)
        definition_headers = header_info.get('definition_file_headers', {})
        filtered_headers = definition_headers.get('filtered_headers', [])
        
        if filtered_headers:
            hint_lines.extend([
                "## ⛔ FILTERED HEADERS (DO NOT USE - WILL FAIL)",
                "",
                "The following headers were REMOVED because they cause compilation errors in fuzz targets.",
                "These are INTERNAL implementation details, NOT public API:",
                ""
            ])
            for item in filtered_headers[:10]:  # Show up to 10 examples
                hint_lines.append(f"  ❌ `{item['header']:40}` ← {item['reason']}")
            hint_lines.extend([
                "",
                "**If you see build errors mentioning these headers:**",
                "  1. ❌ DO NOT add them back - they are internal-only",
                "  2. ✅ Use the PUBLIC headers below instead",
                "  3. ✅ Public headers expose all necessary functionality",
                "",
                "---",
                ""
            ])
        
        # Priority 0: Headers from existing fuzzers (HIGHEST PRIORITY - PROVEN)
        existing_headers = header_info.get('existing_fuzzer_headers', {})
        existing_standard = existing_headers.get('standard_headers', [])
        existing_proj = existing_headers.get('project_headers', [])
        
        if existing_standard or existing_proj:
            hint_lines.extend([
                "## 🥇 PRIORITY 1: Headers from Working Fuzzers (COPY THESE)",
                "",
                "✅ **These headers are PROVEN to compile in OSS-Fuzz. USE EXACTLY AS SHOWN:**",
                ""
            ])
            
            if existing_standard:
                hint_lines.append("**Standard headers (from working fuzzers):**")
                for h in sorted(set(existing_standard))[:12]:
                    hint_lines.append(f"  #include <{h}>")
                hint_lines.append("")
            
            if existing_proj:
                hint_lines.append("**Project headers (from working fuzzers):**")
                for h in sorted(set(existing_proj))[:12]:
                    hint_lines.append(f'  #include "{h}"')
                hint_lines.append("")
            
            hint_lines.extend([
                "**WHY THIS IS PRIORITY 1**: These patterns are extracted from existing fuzzers that",
                "successfully compile in OSS-Fuzz. Copy these patterns for maximum success rate.",
                "",
                "---",
                ""
            ])
        
        # Priority 1: Public API headers from definition file
        if definition_headers:
            def_file = definition_headers.get('definition_file', 'unknown')
            std_headers = definition_headers.get('standard_headers', [])
            proj_headers = definition_headers.get('project_headers', [])
            
            if proj_headers or std_headers:
                hint_lines.extend([
                    "## 🥈 PRIORITY 2: Public API Headers (SAFE TO USE)",
                    "",
                    f"✅ From function definition file: `{def_file}`",
                    "✅ These passed internal/third-party filtering - safe for fuzz targets",
                    ""
                ])
                
                if proj_headers:
                    hint_lines.append("**Project public API headers:**")
                    for h in sorted(set(proj_headers))[:12]:
                        hint_lines.append(f"  {h}")
                    hint_lines.append("")
                
                if std_headers:
                    hint_lines.append("**Standard library headers:**")
                    for h in sorted(set(std_headers))[:12]:
                        hint_lines.append(f"  {h}")
                    hint_lines.append("")
                
                hint_lines.extend([
                    "---",
                    ""
                ])
        
        # Priority 2: FuzzIntrospector inferred headers (LOWEST PRIORITY)
        func_header = header_info.get('function_header')
        related_headers = header_info.get('related_headers', [])
        
        if func_header or related_headers:
            hint_lines.extend([
                "## 🥉 PRIORITY 3: FuzzIntrospector Suggestions (USE WITH CAUTION)",
                "",
                "⚠️  These are inferred by static analysis and may not always be correct.",
                ""
            ])
            
            if func_header:
                hint_lines.append(f"**Primary header:** `{func_header}`")
                hint_lines.append("")
            
            if related_headers:
                hint_lines.append("**Related headers:**")
                for h in related_headers[:8]:
                    hint_lines.append(f"  - {h}")
                hint_lines.append("")
            
            hint_lines.extend([
                "---",
                ""
            ])
        
        # Add explicit usage guidance
        hint_lines.extend([
            "## ⚡ How to Fix Header Errors (STRICT RULES)",
            "",
            "### Rule 1: Start with existing fuzzer headers (🥇 Priority 1)",
            "```c",
            "// ✅ CORRECT: Copy exact patterns from working fuzzers",
            "#include <igraph/igraph.h>",
            "#include <stdio.h>",
            "```",
            "",
            "### Rule 2: Add public API headers (🥈 Priority 2) if needed",
            "```c",
            '// ✅ CORRECT: Use filtered public headers',
            '#include "libraw/libraw.h"',
            "```",
            "",
            "### Rule 3: NEVER add filtered headers",
            "```c",
            "// ❌ WRONG: Filtered headers will fail!",
            '#include "../../internal/libraw_cxx_defs.h"  // FILTERED!',
            "#include <cs/cs.h>                           // THIRD-PARTY!",
            "```",
            "",
            "### Rule 4: When you see 'file not found' errors",
            "",
            "**DO:**",
            "  ✅ Check if the missing header is in FILTERED list → Remove it",
            "  ✅ Replace with equivalent from PUBLIC headers (Priority 1 or 2)",
            "  ✅ Use headers that match working fuzzer patterns",
            "",
            "**DON'T:**",
            "  ❌ Add headers from error messages without checking if they're filtered",
            "  ❌ Try variations like `internal/xxx.h`, `../private/xxx.h`, etc.",
            "  ❌ Add third-party dependency headers (`<cs/cs.h>`, `<boost/...>`, etc.)",
            "",
            "### Common Mistakes to Avoid:",
            "",
            "```c",
            "// ❌ WRONG (blindly adding from error messages):",
            '#include "internal/libraw_cxx_defs.h"',
            "",
            "// ✅ CORRECT (using public API):",
            '#include "libraw/libraw.h"',
            "```",
            "",
            "```c",
            "// ❌ WRONG (using internal dependency):",
            "#include <cs/cs.h>",
            "",
            "// ✅ CORRECT (use project's public API instead):",
            "#include <igraph/igraph.h>",
            "```",
            ""
        ])
        
        return "\n".join(hint_lines)
    

