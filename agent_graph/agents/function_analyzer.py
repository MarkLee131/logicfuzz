"""
LangGraphFunctionAnalyzer agent for LangGraph workflow.
"""
from typing import Any, Dict, List, Optional, Tuple
import argparse
import os
import re
import json

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.utils import parse_tag
from agent_graph.prompt_loader import get_prompt_manager


class LangGraphFunctionAnalyzer(LangGraphAgent):
    """Function analyzer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")
        
        super().__init__(
            name="function_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
        
        # Configuration for iterative analysis
        # Limit the number of refined call-site examples we analyze.
        # 3 examples captures most useful usage patterns while keeping latency
        # and token cost reasonable. Can be overridden via CLI.
        self.max_examples = getattr(args, 'max_function_examples', 3)
        self.convergence_threshold = getattr(args, 'convergence_threshold', 3)
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze the target function."""
        import os
        from data_prep import introspector
        from agent_graph.session_memory_injector import (
            build_prompt_with_session_memory,
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        from agent_graph.api_context_extractor import get_api_context, format_api_context_for_prompt
        
        benchmark = state["benchmark"]
        project_name = benchmark.get('project', 'unknown')
        function_signature = benchmark.get('function_signature', 'unknown')
        function_name = benchmark.get('function_name', 'unknown')
        
        # ========================================================================
        # DATA EXTRACTION: Get from context (prepared once at startup)
        # ========================================================================
        # Philosophy: No fallbacks. If context is missing, something is wrong upstream.
        context = state.get('context', None)
        
        if not context:
            # This should NEVER happen if run_single_fuzz.py did its job
            error_msg = (
                f'❌ FATAL: No fuzzing context in state!\n'
                f'This means data preparation failed but error was hidden.\n'
                f'Check run_single_fuzz.py::_prepare_shared_data_for_benchmark().'
            )
            logger.error(error_msg, trial=self.trial)
            raise RuntimeError(error_msg)
        
        logger.info(f'Using fuzzing context (prepared in {context.get("preparation_time", 0):.2f}s)', trial=self.trial)
        
        # Extract data from context - all guaranteed to exist
        func_source = context.get('source_code', '')
        
        # ========== PGFilter: Filter function source code if enabled ==========
        if getattr(self.args, 'enable_source_filter', False) and func_source:
            from agent_graph.source_code_filter import SourceCodeFilter
            
            # Calculate source code line count, only filter large functions
            min_lines = getattr(self.args, 'source_filter_min_lines', 50)
            line_count = len(func_source.splitlines())
            
            if line_count >= min_lines:
                filter_tool = SourceCodeFilter()
                
                # Extract parameter names from function signature
                function_signature = benchmark.get('function_signature', '')
                target_params = self._extract_params_from_signature(function_signature)
                
                # If no parameters extracted from signature, try to extract from function source first line
                if not target_params and func_source:
                    import re
                    lines = func_source.splitlines()
                    if lines:
                        # Extract from function definition line (first line)
                        func_def_line = lines[0]
                        func_def_params = self._extract_params_from_signature(func_def_line)
                        if func_def_params:
                            target_params = func_def_params
                
                # Log extracted parameters
                logger.info(
                    f'🔍 PGFilter: Extracted initial parameters from signature: {target_params}',
                    trial=self.trial
                )
                
                # Log original source code (before filtering)
                logger.info(
                    f'📄 PGFilter: Original source code ({line_count} lines):\n'
                    f'```c\n{func_source}```',
                    trial=self.trial
                )
                
                # Filter source code
                filtered_source, filter_metadata = filter_tool.filter_function_source(
                    func_source,
                    target_params=target_params
                )
                
                # Log expanded parameters
                initial_params = filter_metadata.get('initial_params', target_params)
                expanded_params = filter_metadata.get('expanded_params', filter_metadata.get('target_params', []))
                
                logger.info(
                    f'🔍 PGFilter: Initial parameters: {initial_params}',
                    trial=self.trial
                )
                logger.info(
                    f'🔍 PGFilter: Expanded parameters ({len(expanded_params)}): {expanded_params}',
                    trial=self.trial
                )
                
                # Log filtered source code (after filtering)
                logger.info(
                    f'📄 PGFilter: Filtered source code ({filter_metadata["filtered_line_count"]} lines):\n'
                    f'```c\n{filtered_source}```',
                    trial=self.trial
                )
                
                logger.info(
                    f'📉 Source code filtered: {filter_metadata["original_line_count"]} → '
                    f'{filter_metadata["filtered_line_count"]} lines '
                    f'({filter_metadata["reduction_ratio"]:.1f}% reduction)',
                    trial=self.trial
                )
                
                func_source = filtered_source
            else:
                logger.debug(
                    f'⏭️  Skipping filter for small function ({line_count} lines < {min_lines})',
                    trial=self.trial
                )
        # ========== PGFilter: End ==========
        # 2025-11: API 组合信息分析已在数据准备阶段移除，仅使用数据准备阶段构造的轻量级 api_dependencies。
        api_dependencies = context["api_dependencies"]
        # 对分析逻辑本身，仅使用轻量级 api_context。
        api_context = api_dependencies.get('api_context', {})
        header_info = context.get('header_info', {})
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})
        
        # Update header_info to include existing fuzzer headers
        if header_info is None:
            header_info = {}
        header_info["existing_fuzzer_headers"] = existing_fuzzer_headers
        
        # Log data summary (works for both shared_data and fallback paths)
        if api_context:
            param_count = len(api_context.get('parameters', []))
            init_pattern_count = len(api_context.get('initialization_patterns', []))
            example_count = len(api_context.get('usage_examples', []))
            related_func_count = len(api_context.get('related_functions', []))
            typedef_count = len(api_context.get('type_definitions', {}))
            
            logger.info(
                f'📊 API context available: {param_count} parameters, '
                f'{init_pattern_count} init patterns, {example_count} usage examples',
                trial=self.trial
            )
            
            # Log detailed context information
            logger.info(
                f'📊 Detailed API Context Information:\n'
                f'  ├─ Parameters ({param_count}):\n' +
                '\n'.join([f'  │   • {p.get("name", "?")} ({p.get("type", "?")})' 
                          for p in api_context.get('parameters', [])[:10]]) +
                ('\n  │   • ... (more parameters)' if param_count > 10 else '') +
                f'\n  ├─ Type Definitions ({typedef_count}):\n' +
                '\n'.join([f'  │   • {name}' 
                          for name in list(api_context.get('type_definitions', {}).keys())[:5]]) +
                ('\n  │   • ... (more types)' if typedef_count > 5 else '') +
                f'\n  ├─ Initialization Patterns ({init_pattern_count}):\n' +
                '\n'.join([f'  │   • {p.get("parameter", "?")} ({p.get("type", "?")}) -> {p.get("method", "?")[:50]}...' 
                          for p in api_context.get('initialization_patterns', [])]) +
                f'\n  ├─ Related Functions ({related_func_count}):\n' +
                '\n'.join([f'  │   • {f.get("name", "?")} [{f.get("type", "?")}]' 
                          for f in api_context.get('related_functions', [])[:10]]) +
                ('\n  │   • ... (more functions)' if related_func_count > 10 else '') +
                f'\n  └─ Usage Examples ({example_count}):\n' +
                '\n'.join([f'  │   • {e.get("function", "?")} @ {e.get("file", "?")[:50]}...' 
                          for e in api_context.get('usage_examples', [])]),
                trial=self.trial
            )
        else:
            logger.warning(f'⚠️ No API context available for {function_signature}', trial=self.trial)
        
        # Log header information
        if header_info:
            std_count = len(header_info.get("existing_fuzzer_headers", {}).get('standard_headers', []))
            proj_count = len(header_info.get("existing_fuzzer_headers", {}).get('project_headers', []))
            logger.info(
                f'📚 Header information available:\n'
                f'  Definition headers: {header_info.get("definition_headers", [])}\n'
                f'  Required type headers: {header_info.get("required_type_headers", [])}\n'
                f'  Existing fuzzer headers: {std_count} standard, {proj_count} project headers',
                trial=self.trial
            )
        
        if not func_source:
            logger.warning(
                f'No source code found in FuzzIntrospector for project: {project_name}, '
                f'function: {function_signature}. Using fallback guidance.',
                trial=self.trial
            )
            # Provide a structured fallback that guides the LLM
            func_source = f"""// Source code not available in FuzzIntrospector database for:
// Function: {function_signature}
// Project: {project_name}
//
// NOTE: Please analyze this function conservatively based on:
// 1. The function signature and parameter types
// 2. Common patterns for similar functions in {project_name}
// 3. Standard practices for the involved data types
// 4. Typical constraints that real callers would respect
//
// Avoid making assumptions about internal implementation details.
// Focus on what can be inferred from the signature and common usage patterns."""
        else:
            logger.info(f'Source code found ({len(func_source)} chars)', trial=self.trial)
        
        # Use stateless iterative analysis - explicit SRS knowledge state
        logger.info('Using stateless iterative analysis (no conversation history)', trial=self.trial)
        response = self._execute_stateless_iterative_analysis(
            state, project_name, function_signature, function_name, func_source, api_context
        )
        
        # 从响应中提取session_memory更新（archetype、初始API约束等）
        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        
        # 合并更新到session_memory
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)
        
        # Extract SRS JSON from response
        srs_data = self._extract_srs_json(response)
        
        # Parse response and create structured output
        analysis_result = {
            "summary": response[:500],  # First 500 chars as summary
            "raw_analysis": response,
            "analyzed": True,
            "header_information": header_info,  # Include header info for Prototyper
            "srs_data": srs_data,  # Include structured SRS data
            "api_context": api_context,  # Include API context for downstream agents
            "api_dependencies": api_dependencies  # Include API dependency graph
        }
        
        # Write requirements to file (matching original FunctionAnalyzer behavior)
        requirements_path = ""
        if response:
            try:
                # Get work_dirs from state
                work_dirs_dict = state.get("work_dirs", {})
                requirements_dir = work_dirs_dict.get("requirements", "")
                
                if requirements_dir:
                    os.makedirs(requirements_dir, exist_ok=True)
                    requirements_path = os.path.join(requirements_dir, f'{self.trial:02d}.txt')
                    
                    with open(requirements_path, 'w') as f:
                        f.write(response)
                    
                    logger.info(f'Requirements written to {requirements_path}', trial=self.trial)
                    analysis_result["requirements_path"] = requirements_path
                        
            except Exception as e:
                logger.warning(f'Failed to write requirements file: {e}', trial=self.trial)
        
        # Flush logs for this agent after completing execution
        self._langgraph_logger.flush_agent_logs(self.name)
        
        return {
            "function_analysis": analysis_result,
            "session_memory": updated_session_memory
        }
    
    def _execute_stateless_iterative_analysis(
        self,
        state: FuzzingWorkflowState,
        project_name: str,
        function_signature: str,
        function_name: str,
        func_source: str,
        api_context: Optional[Dict] = None
    ) -> str:
        """
        Execute stateless iterative analysis using explicit SRS knowledge state.
        
        This method replaces conversation history with structured knowledge,
        reducing token consumption by ~87% while maintaining analysis quality.
        """
        from agent_graph.prompt_loader import get_prompt_manager
        from data_prep import introspector
        from agent_graph.srs_knowledge import (
            SRSKnowledge,
            parse_srs_json_from_response,
            parse_incremental_updates_from_response
        )
        from agent_graph.state import add_api_constraint, set_archetype
        from agent_graph.memory import add_agent_message
        
        # Phase 1: Initial analysis (stateless)
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 1: Initial analysis (stateless)', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        prompt_manager = get_prompt_manager()
        
        # Build initial prompt
        from agent_graph.api_context_extractor import format_api_context_for_prompt
        api_context_text = format_api_context_for_prompt(api_context) if api_context else ""
        if api_context_text:
            logger.info(f'📝 API context: {len(api_context_text)} chars', trial=self.trial)
        
        initial_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_initial",
            FUNCTION_SIGNATURE=function_signature,
            FUNCTION_SOURCE=func_source,
            API_CONTEXT=api_context_text
        )
        
        logger.info(f'📤 Initial call: {len(initial_prompt)} chars', trial=self.trial)
        initial_response = self.call_llm_stateless(initial_prompt, state, "INITIAL")
        
        # Parse SRS knowledge
        initial_srs_json = parse_srs_json_from_response(initial_response)
        if initial_srs_json:
            # ✅ Preferred path: INITIAL response already returned SRS JSON
            knowledge = SRSKnowledge.from_json(initial_srs_json)
            knowledge.target_function = function_name
            logger.info('✅ Parsed initial SRS knowledge', trial=self.trial)
        else:
            # Fallback: start from empty SRSKnowledge and try to at least recover archetype
            knowledge = SRSKnowledge()
            knowledge.target_function = function_name

            # Try to infer archetype directly from INITIAL response (JSON or text)
            try:
                inferred_arch = self._infer_archetype_from_initial_response(initial_response)
            except Exception as e:
                inferred_arch = None
                logger.warning(f'Failed to infer archetype from INITIAL response: {e}', trial=self.trial)

            if inferred_arch:
                # Seed archetype in knowledge state
                knowledge.archetype["primary_pattern"] = inferred_arch
                knowledge.archetype["confidence"] = "MEDIUM"
                knowledge.archetype["evidence_count"] = 1
                logger.info(f'Inferred archetype from INITIAL analysis: {inferred_arch}', trial=self.trial)

                # Also write into session_memory so downstream components (including
                # archetype knowledge injection in Phase 4) can immediately use it.
                try:
                    set_archetype(
                        state,
                        archetype_type=inferred_arch,
                        lifecycle_phases=[],
                        source=self.name,
                        iteration=state.get('current_iteration', 0)
                    )
                    logger.info(f'Session memory archetype set to: {inferred_arch}', trial=self.trial)
                except Exception as e:
                    logger.warning(f'Failed to set archetype in session_memory: {e}', trial=self.trial)

            logger.warning('⚠️ Using minimal SRS structure', trial=self.trial)
        
        stats = knowledge.get_stats()
        logger.info(f'📊 Initial: {stats["total_preconditions"]} pre, {stats["total_constraints"]} con',
                   trial=self.trial)
        
        # Phase 2: Query call sites
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 2: Querying call sites', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        # Note: call_sites API 在这里是合理使用场景
        # 因为这个 agent 需要：
        #  1. 迭代式学习（从多个调用示例中逐步提取知识）
        #  2. 精细控制（参数设置、返回值使用的上下文分析）
        #  3. 元数据（文件名、行号用于日志）
        # 对于一般的 driver 生成，应该使用 test_xrefs + sample_xrefs
        call_sites = introspector.query_introspector_call_sites_metadata(project_name, function_signature)
        examples_analyzed = 0
        
        if call_sites:
            logger.info(f'🔍 Found {len(call_sites)} call sites (max: {self.max_examples})', trial=self.trial)
            call_sites = call_sites[:self.max_examples]
            
            # Phase 3: Stateless refinement
            logger.info('=' * 80, trial=self.trial)
            logger.info('🔬 Phase 3: Stateless refinement', trial=self.trial)
            logger.info('=' * 80, trial=self.trial)
            
            for i, call_site in enumerate(call_sites, 1):
                logger.info(f'📍 Example {i}/{len(call_sites)}', trial=self.trial)
                
                context = self._extract_call_context(call_site, project_name, function_signature)
                if not context:
                    logger.warning(f'   ⚠️ No context, skipping', trial=self.trial)
                    continue
                
                # Build refine prompt with embedded knowledge
                refine_prompt = prompt_manager.build_user_prompt(
                    "function_analyzer_incremental_refine",
                    FUNCTION_SIGNATURE=function_signature,
                    CURRENT_SRS_KNOWLEDGE=knowledge.to_compact_text(max_items_per_section=10),
                    EXAMPLES_ANALYZED=examples_analyzed,
                    EXAMPLE_NUMBER=i,
                    CALLER_NAME=context.get('caller_name', 'unknown'),
                    CALL_LINE_NUMBER=context.get('call_line_number', '?'),
                    CONTEXT_BEFORE=context.get('context_before', ''),
                    CALL_STATEMENT=context.get('call_statement', ''),
                    CONTEXT_AFTER=context.get('context_after', ''),
                    PARAMETER_SETUP=context.get('parameter_setup', 'N/A'),
                    RETURN_USAGE=context.get('return_usage', 'N/A')
                )
                
                try:
                    refine_response = self.call_llm_stateless(refine_prompt, state, f"REFINE_{i}")
                    updates = parse_incremental_updates_from_response(refine_response)
                    changed = knowledge.merge_updates(updates, iteration=i)
                    
                    if changed:
                        examples_analyzed += 1
                        logger.info(f'   ✅ Updated', trial=self.trial)
                    else:
                        logger.info(f'   📥 No new info', trial=self.trial)
                except Exception as e:
                    logger.error(f'   ❌ Error: {e}', trial=self.trial)
                    continue
                
                if knowledge.has_converged(threshold=self.convergence_threshold):
                    logger.info(f'🎯 Converged after {examples_analyzed} examples', trial=self.trial)
                    break
        else:
            logger.warning(f'⚠️ No call sites found', trial=self.trial)
        
        # Phase 4: Generate final SRS
        logger.info('=' * 80, trial=self.trial)
        logger.info('🔬 Phase 4: Final SRS', trial=self.trial)
        logger.info('=' * 80, trial=self.trial)
        
        archetype_knowledge = self._retrieve_archetype_knowledge(state)
        final_prompt = prompt_manager.build_user_prompt(
            "function_analyzer_final_summary",
            FUNCTION_SIGNATURE=function_signature,
            EXAMPLES_COUNT=examples_analyzed,
            ARCHETYPE_KNOWLEDGE=archetype_knowledge
        )
        
        # Embed accumulated knowledge
        final_prompt_full = f"""{final_prompt}

---

# ACCUMULATED KNOWLEDGE ({examples_analyzed} examples):

{knowledge.to_compact_text(max_items_per_section=20)}

Generate complete SRS incorporating all knowledge above.
"""
        
        final_response = self.call_llm_stateless(final_prompt_full, state, "FINAL")
        logger.info(f'📥 Final SRS: {len(final_response)} chars', trial=self.trial)
        
        # Update session_memory
        final_srs = parse_srs_json_from_response(final_response)
        if final_srs:
            archetype_data = final_srs.get('archetype', {})
            primary_pattern = archetype_data.get('primary_pattern')
            # 不再使用 'unknown' 等回退值；只有明确识别的 archetype 才会写入 session_memory。
            if primary_pattern:
                set_archetype(
                    state,
                    archetype_type=primary_pattern,
                    lifecycle_phases=archetype_data.get('lifecycle_phases', []),
                    source=self.name,
                    iteration=state.get('current_iteration', 0)
                )
            
            # Add top constraints to session_memory
            for pre in final_srs.get('preconditions', [])[:5]:
                if pre.get('priority') in ['MANDATORY', 'RECOMMENDED']:
                    add_api_constraint(
                        state,
                        constraint=pre.get('requirement', ''),
                        source=self.name,
                        confidence="high" if pre.get('priority') == 'MANDATORY' else "medium",
                        iteration=state.get('current_iteration', 0)
                    )     
        logger.info(f'📊 Stateless analysis complete: {examples_analyzed} examples processed', trial=self.trial)
        return final_response
    
    def _validate_and_extract_metadata(
        self,
        analysis_output: str,
        function_name: str
    ) -> tuple[bool, list[str], dict]:
        """
        Validate function analysis output and extract metadata.
        
        Returns:
            (is_valid, missing_items, extracted_metadata)
        """
        import re
        
        required_tags = [
            "@target_function:",
            "@must_call_target:",
            "@category:",
            "@complexity:",
            "@state_model:",
            "@recommended_approach:"
        ]
        
        missing = []
        metadata = {}
        
        # Check for required tags
        for tag in required_tags:
            if tag not in analysis_output:
                missing.append(f"Missing tag: {tag}")
            else:
                # Extract value
                tag_clean = tag.rstrip(":")
                pattern = rf"{re.escape(tag)}\s*[`]?([^`\n]+)[`]?"
                match = re.search(pattern, analysis_output)
                if match:
                    value = match.group(1).strip()
                    metadata[tag_clean.lstrip("@")] = value
        
        # Check for "Recommended Test Vectors" section
        if "Recommended Test Vectors" not in analysis_output and "**Recommended Test Vectors**" not in analysis_output:
            missing.append("Missing section: Recommended Test Vectors")
        
        is_valid = len(missing) == 0
        return is_valid, missing, metadata
    
    def _extract_call_context(
        self,
        call_site: dict,
        project: str,
        function_signature: str,
        context_lines: int = 15
    ) -> Optional[dict]:
        """
        Extract the context around a function call without loading the entire caller function.
        
        This is much more token-efficient than loading full source code.
        
        Args:
            call_site: Call site metadata dict with keys: src_func, src_file, src_line
            project: Project name
            function_signature: Full signature of the function being called (callee)
            context_lines: Number of context lines to extract around the call
        """
        from data_prep import introspector
        
        src_func = call_site.get('src_func')
        if not src_func:
            logger.debug('Call site has no src_func, skipping', trial=self.trial)
            return None
        
        # Try to get the source code of the calling function
        caller_sig = introspector.query_introspector_function_signature(project, src_func)
        if not caller_sig:
            logger.debug(f'Could not get signature for caller function: {src_func}', trial=self.trial)
            return None
        
        # Get the full source of the calling function
        caller_source = introspector.query_introspector_function_source(project, caller_sig)
        if not caller_source:
            logger.debug(f'Could not get source for caller function: {caller_sig}', trial=self.trial)
            return None
        
        # ========== PGFilter: Caller source code filtering disabled ==========
        # Note: We keep the full caller source code for better context analysis.
        # PGFilter is only applied to the target function, not to caller functions.
        # ========== PGFilter: End ==========
        
        lines = caller_source.splitlines()
        
        # Extract callee function name from function_signature

        callee_name = self._extract_function_name_from_signature(function_signature)
        logger.debug(
            f'Searching for callee function: {callee_name} (from signature: {function_signature[:80]}...)',
            trial=self.trial
        )
        
        # Priority 1: Use src_line if available (most reliable)
        call_line_idx = None
        src_line = call_site.get('src_line')
        if src_line and isinstance(src_line, int):
            # src_line is 1-indexed, convert to 0-indexed
            call_line_idx = src_line - 1
            if call_line_idx < 0 or call_line_idx >= len(lines):
                logger.warning(
                    f'src_line {src_line} out of range (function has {len(lines)} lines), '
                    f'falling back to search', trial=self.trial
                )
                call_line_idx = None
            else:
                logger.info(
                    f'Using src_line {src_line} from call_site metadata (0-indexed: {call_line_idx})',
                    trial=self.trial
                )
        
        # Priority 2: Search for the callee function call in source code
        if call_line_idx is None:
            logger.debug(
                f'Searching for callee function call in {len(lines)} lines of caller function',
                trial=self.trial
            )
            call_line_idx = self._find_call_in_source(lines, callee_name, function_signature)
            if call_line_idx is not None:
                logger.info(
                    f'Found callee call at line {call_line_idx + 1} (0-indexed: {call_line_idx})',
                    trial=self.trial
                )
        
        if call_line_idx is None:
            # 不要瞎编"调用行"——找不到就老老实实说找不到，跳过这个样本。
            logger.warning(
                f'Could not locate call to {callee_name} in caller {src_func}, '
                f'skipping this call site',
                trial=self.trial
            )
            return None
        
        # ========== PGFilter: Caller source code filtering disabled ==========
        # Note: We keep the full caller source code for better context analysis.
        # PGFilter is only applied to the target function, not to caller functions.
        # The caller_source and lines remain unchanged (full source code).
        # ========== PGFilter: End ==========
        
        # Extract context
        start_idx = max(0, call_line_idx - context_lines)
        end_idx = min(len(lines), call_line_idx + context_lines + 1)
        
        context_before = '\n'.join(lines[start_idx:call_line_idx])
        call_statement = lines[call_line_idx] if call_line_idx < len(lines) else ''
        context_after = '\n'.join(lines[call_line_idx + 1:end_idx])
        
        # Extract parameter setup
        parameter_setup = self._extract_parameter_setup(lines, call_line_idx, call_statement)
        
        # Extract return value usage
        return_usage = self._extract_return_usage(lines, call_line_idx, call_statement)
        
        context_dict = {
            'caller_name': src_func,
            'caller_signature': caller_sig,
            'call_line_number': call_line_idx + 1,  # 1-indexed for display
            'context_before': context_before,
            'call_statement': call_statement,
            'context_after': context_after,
            'parameter_setup': parameter_setup,
            'return_usage': return_usage,
            'full_context': f"{context_before}\n{call_statement}\n{context_after}",
        }
        
        # Log extracted context for debugging and analysis
        logger.info(
            f"📋 Extracted API usage context from FuzzIntrospector:\n"
            f"  Caller: {src_func}\n"
            f"  Line: {call_line_idx + 1}\n"
            f"  Call statement: {call_statement.strip()}\n"
            f"  Parameter setup: {parameter_setup[:100]}{'...' if len(parameter_setup) > 100 else ''}\n"
            f"  Return usage: {return_usage[:100]}{'...' if len(return_usage) > 100 else ''}",
            trial=self.trial
        )
        
        # Log the full context in debug mode
        logger.debug(
            f"Full context extracted:\n"
            f"--- Context Before ({len(context_before)} chars) ---\n"
            f"{context_before}\n"
            f"--- Call Statement ---\n"
            f"{call_statement}\n"
            f"--- Context After ({len(context_after)} chars) ---\n"
            f"{context_after}",
            trial=self.trial
        )
        
        return context_dict
    
    def _extract_function_name_from_signature(self, function_signature: str) -> str:
        """
        Extract function name from full signature.
        
        Examples:
            "CURLMcode curl_multi_socket_action(CURLM *, curl_socket_t, int, int *)"
            -> "curl_multi_socket_action"
            
            "void sam_hrecs_remove_ref_altnames(sam_hrecs_t *, int, const char *)"
            -> "sam_hrecs_remove_ref_altnames"
        """
        # Match pattern: return_type function_name(params)
        # Extract the part between return type and opening parenthesis
        match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', function_signature)
        if match:
            return match.group(1)
        
        # Fallback: try to extract last word before '('
        parts = function_signature.split('(')
        if len(parts) > 1:
            # Get the last identifier before '('
            before_paren = parts[0].strip()
            # Split by whitespace and take the last part
            name_parts = before_paren.split()
            if name_parts:
                return name_parts[-1]
        
        return ""
    
    def _find_call_in_source(
        self, 
        lines: List[str], 
        callee_name: str,
        function_signature: str
    ) -> Optional[int]:
        """
        Try to find where a function is called in the source code.
        
        Args:
            lines: Source code lines of the calling function
            callee_name: Name of the function being called (e.g., "curl_multi_socket_action")
            function_signature: Full signature for additional matching context
        
        Returns:
            Line index (0-based) where the call is found, or None
        """
        import re
        
        # Extract simple name (without namespaces/classes)
        simple_name = callee_name.split('::')[-1].split('.')[-1]
        
        # Try multiple matching strategies
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Strategy 1: Look for function call pattern with parentheses
            # Must have the function name and opening parenthesis on the same line
            if simple_name in stripped and '(' in stripped:
                # Avoid matching function declarations/definitions
                # (they usually have return type before function name)
                if re.search(r'\b' + re.escape(simple_name) + r'\s*\(', stripped):
                    # Check if it's likely a call (not a declaration)
                    # Calls usually don't have return type immediately before
                    # (this is heuristic, but works for most cases)
                    if not re.search(r'\b(static|inline|extern)\s+\w+\s+' + re.escape(simple_name), stripped):
                        return i
            
            # Strategy 2: For C APIs with underscore naming, also check for
            # patterns like "result = function_name(" or "function_name("
            if simple_name.count('_') >= 2:  # Likely C API
                if re.search(r'\b' + re.escape(simple_name) + r'\s*\(', stripped):
                    # Make sure it's not a declaration
                    if '=' in stripped or stripped.startswith(simple_name) or ';' in stripped:
                        return i
        
        return None
    
    def _extract_parameter_setup(self, lines: List[str], call_idx: int, call_stmt: str) -> str:
        """
        Extract code that sets up parameters for the call.
        
        Improved version that:
        1. Extracts parameter variables more accurately
        2. Searches in a wider context window
        3. Handles different assignment patterns
        """
        import re
        setup_lines = []
        
        # Try to find variable names in the call statement
        if '(' in call_stmt and ')' in call_stmt:
            param_part = call_stmt.split('(', 1)[1].rsplit(')', 1)[0]
            
            # Extract identifiers (variable names, not keywords)
            # Filter out common keywords and types
            keywords = {'if', 'for', 'while', 'return', 'static', 'const', 'void', 'int', 
                       'char', 'long', 'short', 'unsigned', 'signed', 'struct', 'enum'}
            potential_vars = []
            for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', param_part):
                var = match.group(1)
                if var not in keywords and len(var) > 1:  # Skip single letters and keywords
                    potential_vars.append(var)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_vars = []
            for var in potential_vars:
                if var not in seen:
                    seen.add(var)
                    unique_vars.append(var)
            
            # Search backwards for declarations/assignments of these variables
            # Use a wider search window (30 lines instead of 20)
            search_start = max(0, call_idx - 30)
            found_vars = set()
            
            for i in range(search_start, call_idx):
                line = lines[i].strip()
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                for var in unique_vars:
                    if var in found_vars:
                        continue
                    
                    # Look for variable assignment or initialization
                    # Patterns: "var =", "var =", "type var =", "var->", "var.", etc.
                    var_pattern = r'\b' + re.escape(var) + r'\b'
                    
                    # Check for assignment
                    if re.search(var_pattern + r'\s*=', line):
                        setup_lines.append(f"Line {i+1}: {line}")
                        found_vars.add(var)
                        break
                    # Check for pointer/struct member access (likely setup)
                    elif re.search(var_pattern + r'\s*[-.>]', line):
                        setup_lines.append(f"Line {i+1}: {line}")
                        found_vars.add(var)
                        break
                    # Check for function call that might initialize
                    elif re.search(var_pattern + r'\s*\(', line):
                        setup_lines.append(f"Line {i+1}: {line}")
                        found_vars.add(var)
                        break
            
            # If we found some setup, return it
            if setup_lines:
                return '\n'.join(setup_lines[:10])  # Limit to 10 lines
        
        return "No clear parameter setup found"
    
    def _extract_return_usage(self, lines: List[str], call_idx: int, call_stmt: str) -> str:
        """
        Extract code that uses the return value from the call.
        
        Improved version that:
        1. Better extracts the variable name from assignment
        2. Handles different assignment patterns
        3. Searches in a wider context window
        """
        import re
        usage_lines = []
        
        # Check if return value is assigned to a variable
        if '=' in call_stmt:
            # Extract variable name from left side of assignment
            # Handle patterns like: "result =", "CURLMcode code =", "int ret ="
            left_side = call_stmt.split('=', 1)[0].strip()
            
            # Extract the last identifier (variable name)
            # Split by whitespace and take the last part
            parts = left_side.split()
            if parts:
                var_name = parts[-1]
                # Remove any trailing operators
                var_name = re.sub(r'[\[\]().,;]+$', '', var_name)
                
                if var_name and len(var_name) > 1:  # Valid variable name
                    # Search forward for usage of this variable
                    search_end = min(len(lines), call_idx + 30)
                    for i in range(call_idx + 1, search_end):
                        line = lines[i].strip()
                        if not line or line.startswith('//') or line.startswith('/*'):
                            continue
                        
                        # Look for variable usage (not just mention in comments)
                        # Use word boundary to avoid partial matches
                        if re.search(r'\b' + re.escape(var_name) + r'\b', line):
                            usage_lines.append(f"Line {i+1}: {line}")
                            # Stop after finding a few uses
                            if len(usage_lines) >= 5:
                                break
        
        # Also check for direct return value usage (not assigned)
        # Pattern: "if (function_call(...))" or "while (function_call(...))"
        if not usage_lines:
            # Check if return value is used directly in control flow
            next_line_idx = call_idx + 1
            if next_line_idx < len(lines):
                next_line = lines[next_line_idx].strip()
                # Look for patterns like "if (", "while (", "switch ("
                if re.search(r'\b(if|while|switch|for)\s*\(', next_line):
                    usage_lines.append(f"Line {next_line_idx + 1}: {next_line}")
        
        return '\n'.join(usage_lines) if usage_lines else "No clear return value usage found"
    
    def _retrieve_archetype_knowledge(self, state: FuzzingWorkflowState) -> str:
        """
        Retrieve relevant archetype knowledge from long-term memory.
        
        仅在明确识别出 archetype 的情况下注入知识；否则返回空字符串，不做任何回退。
        """
        try:
            from long_term_memory.retrieval import KnowledgeRetriever
            
            retriever = KnowledgeRetriever()
            
            # Try to extract archetype from conversation history
            archetype = self._infer_archetype_from_history(state)
            
            if archetype and archetype in retriever.list_archetypes():
                logger.info(f'Inferred archetype: {archetype}, retrieving knowledge', trial=self.trial)
                bundle = retriever.get_bundle(archetype)
                
                # Format knowledge for injection
                knowledge = f"""
# Relevant Pattern Knowledge

## Archetype: {archetype}

{bundle['archetype']}

## Common Pitfalls
"""
                for pitfall_name, pitfall_content in bundle['pitfalls'].items():
                    knowledge += f"\n### {pitfall_name}\n{pitfall_content[:500]}...\n"
                
                return knowledge
            else:
                # 不再提供“所有 archetype 列表”的回退，只在识别出明确 archetype 时注入知识。
                logger.info('No clear archetype inferred; skipping archetype knowledge injection', trial=self.trial)
                return ""
        except Exception as e:
            logger.warning(f'Failed to retrieve archetype knowledge: {e}', trial=self.trial)
            return ""
    
    def _infer_archetype_from_history(self, state: FuzzingWorkflowState) -> Optional[str]:
        """
        Try to infer archetype from session memory.
        Looks for archetype in session_memory or API constraints.
        """
        # OPTIMIZATION: Changed to use session_memory instead of agent_messages
        # See CONVERSATION_HISTORY_DISABLED.md for details
        
        # First check if archetype is already identified in session_memory
        session_memory = state.get("session_memory", {})
        if archetype := session_memory.get("archetype"):
            return archetype.get("type")
        
        # If not, try to infer from API constraints and decisions
        api_constraints = session_memory.get("api_constraints", [])
        decisions = session_memory.get("decisions", [])
        
        archetype_keywords = {
            "object_lifecycle": ["create", "destroy", "lifecycle", "init", "free", "stateless", "parse", "single call", "no state"],
            "event_driven_state_machine": ["state machine", "multi-step", "sequence", "configure"],
            "iterative_processing": ["stream", "chunk", "incremental", "loop"],
            "round_trip_testing": ["round-trip", "encode", "decode", "compress"],
            "temporary_file": ["file path", "filename", "temp file"],
            "one_time_initialization": ["LLVMFuzzerInitialize", "global init", "one-time setup", "initialize once"],
            "stateful_context": ["static context", "reuse context", "static variable", "context reset", "stateful"]
        }
        
        # Count keyword matches in session_memory
        scores = {arch: 0 for arch in archetype_keywords}
        
        # Check API constraints
        for constraint in api_constraints:
            content = constraint.get("constraint", "").lower()
            for arch, keywords in archetype_keywords.items():
                for keyword in keywords:
                    if keyword in content:
                        scores[arch] += 1
        
        # Check decisions
        for decision in decisions:
            content = (decision.get("decision", "") + " " + decision.get("reason", "")).lower()
            for arch, keywords in archetype_keywords.items():
                for keyword in keywords:
                    if keyword in content:
                        scores[arch] += 1
        
        # Return archetype with highest score (if > 0)
        if scores:
            max_arch = max(scores, key=scores.get)
            return max_arch if scores[max_arch] > 0 else None
        
        return None

    def _infer_archetype_from_initial_response(self, response: str) -> Optional[str]:
        """
        Infer archetype directly from the INITIAL analysis response.
        
        This is a robustness fallback for cases where the INITIAL prompt
        returns a lightweight JSON summary (behavior/function_type/archetype)
        instead of a full SRS JSON in <srs_json> tags.
        """
        if not response:
            return None
        
        import json
        import re
        
        # Normalization map shared with Prototyper-style archetype extraction
        mapping = {
            "stateless parser": "object_lifecycle",
            "object lifecycle": "object_lifecycle",
            "state machine": "event_driven_state_machine",
            "stream processor": "iterative_processing",
            "round-trip": "round_trip_testing",
            "round trip": "round_trip_testing",
            "file-based": "temporary_file",
            "file based": "temporary_file",
            "global initialization": "one_time_initialization",
            "global init": "one_time_initialization",
            "stateful fuzzing": "stateful_context",
            "stateful": "stateful_context",
        }
        
        text = response.strip()
        
        # 1) Try to parse response as pure JSON (common for INITIAL)
        try:
            data = json.loads(text)
            cand = None
            
            arch_field = data.get("archetype")
            if isinstance(arch_field, str):
                cand = arch_field
            elif isinstance(arch_field, dict):
                cand = arch_field.get("primary_pattern") or arch_field.get("type")
            
            if isinstance(cand, str):
                norm = cand.strip().lower()
                if norm in mapping:
                    return mapping[norm]
        except Exception:
            # Not pure JSON – fall back to regex extraction below
            pass
        
        # 2) Look for JSON-like `"archetype": "State Machine"` inside text
        m = re.search(r'"archetype"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
        if m:
            norm = m.group(1).strip().lower()
            if norm in mapping:
                return mapping[norm]
        
        # 3) Reuse textual patterns used by Prototyper (_extract_archetype_from_analysis)
        # Pattern A: "Primary pattern: State Machine"
        m = re.search(r"Primary pattern:\s*([A-Za-z\-\s]+?)(?:\n|$)", text, re.IGNORECASE)
        if m:
            norm = m.group(1).strip().lower()
            if norm in mapping:
                return mapping[norm]
        
        # Pattern B: "Archetype: State Machine"
        m = re.search(r"Archetype:\s*([A-Za-z\-\s]+?)(?:\n|$)", text, re.IGNORECASE)
        if m:
            norm = m.group(1).strip().lower()
            if norm in mapping:
                return mapping[norm]
        
        return None
    
    def _extract_header_information(
        self,
        project_name: str,
        function_signature: str
    ) -> dict:
        """
        Extract header information from FuzzIntrospector.
        
        Returns:
            dict with keys:
                - function_header: Primary header file for the function
                - related_headers: List of related project headers
                - definition_file_headers: Headers extracted from function definition file (NEW)
                - is_c_api: Whether the function is a C API (based on naming convention)
        """
        from data_prep import introspector
        from agent_graph.header_extractor import get_function_definition_headers
        
        header_info = {
            "function_header": None,
            "related_headers": [],
            "definition_file_headers": None,
            "is_c_api": False
        }
        
        try:
            # ===== STEP 0: Detect if this is a C API function =====
            # C API characteristics:
            # 1. Function name uses underscore_style (e.g., ada_can_parse_with_base)
            # 2. No namespace prefix (e.g., no ada::parse)
            # 3. Often has C-style types (char*, size_t) without std::
            function_name = function_signature.split('(')[0].strip().split()[-1]
            is_c_api = self._detect_c_api(function_name, function_signature)
            header_info["is_c_api"] = is_c_api
            
            if is_c_api:
                logger.info(
                    f'Detected C API function (underscore naming): {function_name}',
                    trial=self.trial
                )
            # ======================================================
            
            # ===== STEP 1: Query FI for header files (HIGHEST PRIORITY for C APIs) =====
            logger.info(f'Querying FI header files for {function_signature}', trial=self.trial)
            all_headers = introspector.query_introspector_header_files_to_include(
                project_name, function_signature
            )
            
            if all_headers:
                logger.info(f'Found {len(all_headers)} headers from FI', trial=self.trial)
                
                # Filter project headers (exclude standard library)
                project_headers = []
                for header in all_headers:
                    # Keep headers that are in project source (/src/PROJECT_NAME/...)
                    if f'/src/{project_name}/' in header or '/src/' in header[:20]:
                        # Convert to include format
                        include_path = self._convert_to_include_path(header, project_name)
                        if include_path:
                            project_headers.append(include_path)
                
                if project_headers:
                    # First header is usually the function's declaration
                    header_info["function_header"] = project_headers[0]
                    header_info["related_headers"] = project_headers[1:5]  # Up to 4 more
                    logger.info(f'Primary header from FI: {project_headers[0]}', trial=self.trial)
            else:
                logger.debug(f'No headers returned from FI for {function_signature}', trial=self.trial)
            # ==========================================================================
            
            # ===== STEP 2: Extract headers from function definition file (fallback for C++) =====
            logger.info(f'Extracting headers from function definition file', trial=self.trial)
            definition_headers = get_function_definition_headers(
                project_name, function_signature
            )
            
            if definition_headers:
                header_info["definition_file_headers"] = definition_headers
                logger.info(
                    f'Extracted {len(definition_headers.get("standard_headers", []))} standard '
                    f'and {len(definition_headers.get("project_headers", []))} project headers '
                    f'from definition file: {definition_headers.get("definition_file", "unknown")}',
                    trial=self.trial
                )
            else:
                logger.debug(f'No definition file headers found', trial=self.trial)
            # ==================================================================================
            
        except Exception as e:
            logger.warning(f'Failed to extract header information: {e}', trial=self.trial)
        
        return header_info
    
    def _detect_c_api(self, function_name: str, function_signature: str) -> bool:
        """
        Detect if a function is a C API based on naming conventions.
        
        C API characteristics:
        - Underscore naming (e.g., ada_can_parse, json_parse_string)
        - No namespace prefix (no ::)
        - Typically 2+ underscores in name
        
        Args:
            function_name: Extracted function name (e.g., 'ada_can_parse_with_base')
            function_signature: Full signature for additional context
        
        Returns:
            True if likely a C API function
        """
        # C++ API indicators (negative signals)
        if '::' in function_name:
            return False  # C++ namespace
        
        # Remove common prefixes to get pure name
        name_parts = function_name.split('::')[-1]  # Get last part after ::
        
        # C API naming pattern: lowercase_with_underscores
        # Require at least 2 underscores and all lowercase (except for specific prefixes)
        underscore_count = name_parts.count('_')
        
        if underscore_count >= 2:
            # Check if it's all lowercase (C API convention)
            # Allow numbers and underscores
            clean_name = name_parts.replace('_', '').replace('0', '').replace('1', '').replace('2', '').replace('3', '').replace('4', '').replace('5', '').replace('6', '').replace('7', '').replace('8', '').replace('9', '')
            if clean_name.islower():
                return True
        
        return False
    
    def _convert_to_include_path(self, absolute_path: str, project_name: str) -> str:
        """
        Convert absolute path to include format.
        e.g., /src/mosh/src/terminal/terminal.h -> "src/terminal/terminal.h"
        """
        if not absolute_path:
            return ""
        
        # Try to extract the part after /src/PROJECT_NAME/
        if f'/src/{project_name}/' in absolute_path:
            parts = absolute_path.split(f'/src/{project_name}/', 1)
            if len(parts) > 1:
                return parts[1]
        
        # Fallback: extract after any /src/
        if '/src/' in absolute_path:
            parts = absolute_path.split('/src/', 1)
            if len(parts) > 1:
                subparts = parts[1].split('/', 1)
                if len(subparts) > 1:
                    return subparts[1]
        
        # Last resort: return filename only
        return absolute_path.split('/')[-1]
    
    def _extract_existing_fuzzer_headers(
        self,
        project_name: str
    ) -> dict:
        """
        Extract actual include statements from existing fuzzers.
        These headers are proven to work and should be prioritized.
        
        Args:
            project_name: Name of the project
            
        Returns:
            dict with keys:
                - standard_headers: List of standard library includes (e.g., ["cstddef", "cstdint"])
                - project_headers: List of project-specific includes (e.g., ["src/terminal/parser.h"])
        """
        from data_prep import introspector
        import re
        
        result = {
            "standard_headers": [],
            "project_headers": []
        }
        
        try:
            # 1. Get all fuzzers for the project
            logger.info(f'Querying existing fuzzers for {project_name}', trial=self.trial)
            harnesses = introspector.query_introspector_for_harness_intrinsics(project_name)
            
            if not harnesses:
                logger.warning(f'No existing fuzzers found for {project_name}', trial=self.trial)
                return result
            
            all_includes = {"standard": set(), "project": set()}
            
            # 2. Analyze each fuzzer (limit to first 10 for efficiency)
            for harness in harnesses[:10]:
                fuzzer_path = harness.get('source', '')
                if not fuzzer_path:
                    continue
                
                logger.debug(f'Analyzing fuzzer: {fuzzer_path}', trial=self.trial)
                
                # 3. Get fuzzer source code
                fuzzer_source = introspector.query_introspector_source_code(
                    project_name, fuzzer_path
                )
                
                if not fuzzer_source:
                    continue
                
                # 4. Parse includes from source
                # Pattern for #include <...> (standard library)
                standard_includes = re.findall(r'#include\s+<([^>]+)>', fuzzer_source)
                for inc in standard_includes:
                    # Filter common fuzzer-only headers
                    if inc not in ['fuzzer/FuzzedDataProvider.h']:
                        all_includes["standard"].add(inc)
                
                # Pattern for #include "..." (project headers)
                project_includes = re.findall(r'#include\s+"([^"]+)"', fuzzer_source)
                for inc in project_includes:
                    # Filter out fuzzer-specific and test files
                    inc_lower = inc.lower()
                    if 'fuzzer' not in inc_lower and 'test' not in inc_lower and 'mock' not in inc_lower:
                        all_includes["project"].add(inc)
            
            result["standard_headers"] = sorted(list(all_includes["standard"]))
            result["project_headers"] = sorted(list(all_includes["project"]))
            
            total_count = len(result["standard_headers"]) + len(result["project_headers"])
            logger.info(f'Extracted {total_count} includes from existing fuzzers '
                       f'({len(result["standard_headers"])} standard, {len(result["project_headers"])} project)',
                       trial=self.trial)
            
        except Exception as e:
            logger.warning(f'Failed to extract existing fuzzer headers: {e}', trial=self.trial)
        
        return result
    
    def _extract_srs_json(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse SRS JSON from the response.
        
        Args:
            response: The LLM response containing SRS specification
            
        Returns:
            Parsed SRS JSON data or None if not found/invalid
        """
        import json
        import re
        
        try:
            # Look for <srs_json>...</srs_json> tags
            match = re.search(r'<srs_json>\s*(\{.*?\})\s*</srs_json>', response, re.DOTALL)
            if match:
                json_str = match.group(1)
                srs_data = json.loads(json_str)
                logger.info(f'Successfully extracted SRS JSON data', trial=self.trial)
                return srs_data
            else:
                logger.warning(f'No <srs_json> tags found in response', trial=self.trial)
                return None
        except json.JSONDecodeError as e:
            logger.warning(f'Failed to parse SRS JSON: {e}', trial=self.trial)
            return None
        except Exception as e:
            logger.warning(f'Error extracting SRS JSON: {e}', trial=self.trial)
            return None
    
    def _extract_params_from_signature(self, function_signature: str) -> List[str]:
        """
        Extract parameter names from function signature.
        
        Example:
            "int foo(int a, char *b)" -> ["a", "b"]
            "void bar(int, char *)" -> [] (no parameter names)
        
        Args:
            function_signature: Full function signature
        
        Returns:
            List of parameter names (empty if no names found)
        """
        import re
        
        # Match function parameters: (param1, param2, ...)
        param_pattern = re.compile(r'\(([^)]*)\)')
        match = param_pattern.search(function_signature)
        
        if not match:
            return []
        
        params_str = match.group(1).strip()
        if not params_str:
            return []
        
        # Split by comma and extract variable names
        params = []
        for param in params_str.split(','):
            param = param.strip()
            # Extract all identifiers from the parameter
            # Handle: "int a", "char *b", "const char *c", "XML_Parser parser"
            identifiers = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', param)
            
            if not identifiers:
                continue
            
            # If there are multiple identifiers, the last one is usually the parameter name
            # If there's only one identifier, check if it's likely a type name
            if len(identifiers) > 1:
                # Multiple identifiers: last one is the parameter name
                params.append(identifiers[-1])
            elif len(identifiers) == 1:
                # Single identifier: check if it's likely a type name
                identifier = identifiers[0]
                # Skip if it starts with uppercase (likely a type like XML_Parser, int, char, etc.)
                # or is a known type keyword
                if identifier[0].isupper() or identifier in ['int', 'char', 'void', 'float', 'double', 'long', 'short', 'unsigned', 'signed', 'const', 'struct', 'enum']:
                    # This is likely a type name, not a parameter name, skip it
                    continue
                else:
                    # Single lowercase identifier, likely a parameter name
                    params.append(identifier)
        
        return params

