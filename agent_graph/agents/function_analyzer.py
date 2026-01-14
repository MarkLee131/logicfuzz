"""
LangGraphFunctionAnalyzer agent for LangGraph workflow.

This agent performs project-level API analysis using data from Liberator.
It does NOT target a single API - instead it analyzes all project APIs
and their sequences to guide driver generation.
"""
from typing import Any, Dict, List, Optional
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.prompt_loader import get_prompt_manager


class LangGraphFunctionAnalyzer(LangGraphAgent):
    """
    Project-level function analyzer agent for LangGraph.

    Analyzes project APIs and sequences from Liberator to provide
    guidance for driver generation. Does NOT focus on a single API.
    """

    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")

        super().__init__(
            name="function_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Analyze project APIs and sequences for driver generation.

        Uses project-level data from Liberator (via FuzzingContext) to analyze
        API sequences, dependencies, and constraints.
        """
        import os
        from agent_graph.session_memory_injector import (
            extract_session_memory_updates_from_response,
            merge_session_memory_updates
        )
        
        benchmark = state["benchmark"]
        project_name = benchmark.get('project', 'unknown')

        context = state.get('context', None)
        if not context:
            error_msg = (
                f'❌ FATAL: No fuzzing context in state!\n'
                f'This means data preparation failed but error was hidden.\n'
            )
            logger.error(error_msg, trial=self.trial)
            raise RuntimeError(error_msg)
        
        logger.info(f'✅ Using project-level fuzzing context (prepared in {context.get("preparation_time", 0):.2f}s)', trial=self.trial)

        project_apis = context.get('project_apis', [])
        api_sequences = context.get('api_sequences', [])
        dependency_graph = context.get('dependency_graph', {})
        api_dependencies = context.get('api_dependencies', {})
        header_info = context.get('header_info', {})
        existing_fuzzer_headers = context.get('existing_fuzzer_headers', {})

        if header_info is None:
            header_info = {}
        header_info["existing_fuzzer_headers"] = existing_fuzzer_headers

        api_count = len(project_apis)
        sequence_count = len(api_sequences)
        dep_nodes = dependency_graph.get('num_nodes', 0)
        
        logger.info(
            f'📊 Project-level API data available: {api_count} APIs, '
            f'{sequence_count} sequences, {dep_nodes} dependency nodes',
            trial=self.trial
        )
        
        # Log detailed project API information
        logger.info(
            f'📊 Project API Information:\n'
            f'  ├─ Total APIs ({api_count}):\n' +
            '\n'.join([f'  │   • {api.get("function_name", "?")} ({api.get("return_type", "?")})' 
                      for api in project_apis[:15]]) +
            ('\n  │   • ... (more APIs)' if api_count > 15 else '') +
            f'\n  ├─ API Sequences ({sequence_count}):\n' +
            '\n'.join([f'  │   Sequence {i+1}: {" → ".join(seq[:5])}' + (' ...' if len(seq) > 5 else '')
                      for i, seq in enumerate(api_sequences[:5])]) +
            ('\n  │   • ... (more sequences)' if sequence_count > 5 else '') +
            f'\n  └─ Dependency Graph: {dep_nodes} nodes',
            trial=self.trial
        )

        if header_info:
            std_count = len(header_info.get('standard_headers', []))
            proj_count = len(header_info.get('project_headers', []))
            logger.info(
                f'📚 Header information available: {std_count} standard, {proj_count} project headers',
                trial=self.trial
            )

        response = self._execute_project_level_analysis(
            state, project_name, project_apis, api_sequences, dependency_graph
        )

        session_memory_updates = extract_session_memory_updates_from_response(
            response,
            agent_name=self.name,
            current_iteration=state.get("current_iteration", 0)
        )
        updated_session_memory = merge_session_memory_updates(state, session_memory_updates)

        srs_data = self._extract_srs_json(response)

        analysis_result = {
            "summary": response[:500],
            "raw_analysis": response,
            "analyzed": True,
            "header_information": header_info,
            "srs_data": srs_data,
            "api_dependencies": api_dependencies
        }

        requirements_path = ""
        if response:
            try:
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

        self._langgraph_logger.flush_agent_logs(self.name)
        
        return {
            "function_analysis": analysis_result,
            "session_memory": updated_session_memory
        }
    
    def _execute_project_level_analysis(
        self,
        state: FuzzingWorkflowState,
        project_name: str,
        project_apis: List[Dict[str, Any]],
        api_sequences: List[List[str]],
        dependency_graph: Dict[str, Any]
    ) -> str:
        """
        Execute project-level analysis using API sequences from Liberator.
        
        This method analyzes the project's API sequences and generates
        requirements for driver generation based on the dependency graph.
        """
        logger.info('🔬 Project-level API sequence analysis', trial=self.trial)

        sequences_text = '\n'.join([
            f'  Sequence {i+1}: {" → ".join(seq)}'
            for i, seq in enumerate(api_sequences[:10])
        ])

        apis_text = '\n'.join([
            f'  • {api.get("function_name", "?")}({", ".join([arg.get("name", "?") for arg in api.get("arguments", [])[:3]])})'
            for api in project_apis[:20]
        ])

        analysis_prompt = f"""Analyze the following project APIs and sequences for fuzzing driver generation.

Project: {project_name}
Total APIs: {len(project_apis)}
API Sequences: {len(api_sequences)}

API Sequences (from Liberator grammar):
{sequences_text}

Project APIs:
{apis_text}

Dependency Graph: {dependency_graph.get('num_nodes', 0)} nodes

Please analyze:
1. Common API usage patterns
2. Initialization requirements
3. Resource management (cleanup)
4. Parameter constraints
5. Recommended driver structure

Generate a structured analysis that will guide driver generation."""
        
        logger.info(f'📤 Project-level analysis call: {len(analysis_prompt)} chars', trial=self.trial)
        response = self.call_llm_stateless(analysis_prompt, state, "PROJECT_LEVEL")
        
        logger.info(f'📊 Project-level analysis complete', trial=self.trial)
        return response

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

