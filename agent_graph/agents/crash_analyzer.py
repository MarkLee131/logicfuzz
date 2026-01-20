"""
LangGraphCrashAnalyzer agent - analyzes crashes using GDB.
"""
import argparse
import os
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.agents.base import LangGraphAgent
from agent_graph.agents.tool_calling_mixin import ToolCallingMixin
from agent_graph.prompt_loader import get_prompt_manager
from agent_graph.tools.langchain_adapters import BashExecuteTool, GDBExecuteTool
from experiment.workdir import WorkDirs


class LangGraphCrashAnalyzer(LangGraphAgent, ToolCallingMixin):
    """Crash analyzer using ReAct-style tool calling with GDB."""

    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        super().__init__(
            name="crash_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=prompt_manager.get_system_prompt("crash_analyzer")
        )
        self.gdb_tool = None
        self.bash_tool = None
        self.gdb_tool_used = False

    def get_langchain_tools(self) -> List[BaseTool]:
        return [
            GDBExecuteTool(executor=self._execute_gdb),
            BashExecuteTool(executor=self._execute_bash)
        ]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse crash analysis response."""
        result = {'true_bug': None, 'insight': content, 'analyzed': True}
        content_lower = content.lower()

        # Parse true/false
        if m := re.search(r'conclusion:\s*(true|false)', content_lower):
            result['true_bug'] = m.group(1) == 'true'
        elif 'true bug' in content_lower or 'project bug' in content_lower:
            result['true_bug'] = True
        elif 'false positive' in content_lower or 'driver bug' in content_lower:
            result['true_bug'] = False

        # Extract insight
        if m := re.search(r'analysis:\s*(.+)', content, re.IGNORECASE | re.DOTALL):
            result['insight'] = m.group(1).strip()

        return result

    def _execute_gdb(self, command: str) -> str:
        self.gdb_tool_used = True
        proc = self.gdb_tool.execute_in_screen(command)
        lines = proc.stdout.strip().splitlines()
        if lines and lines[-1].strip().startswith("(gdb)"):
            lines.pop()
        if lines:
            lines[0] = f'(gdb) {lines[0].strip()}'
        return self.truncate_tool_output("\n".join(lines))

    def _execute_bash(self, command: str) -> str:
        proc = self.bash_tool.execute(command)
        parts = [f"$ {command}", f"exit={proc.returncode}"]
        if proc.stdout:
            parts.append(proc.stdout.strip())
        if proc.stderr:
            parts.append(f"STDERR: {proc.stderr.strip()}")
        return self.truncate_tool_output("\n".join(parts))

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        from tool.container_tool import ProjectContainerTool
        from tool.gdb_tool import GDBTool
        from experiment import benchmark as benchmarklib
        from experiment import evaluator as evaluator_lib
        from experiment import oss_fuzz_checkout

        benchmark = benchmarklib.Benchmark.from_dict(state["benchmark"])
        crash_info = state.get("crash_info", {})
        fuzz_target_source = state.get("fuzz_target_source", "")
        build_script_source = state.get("build_script_source", "")
        run_log = state.get("run_log", "")

        # Check for false positive first
        fp_result = self._check_false_positive(run_log)
        if fp_result["is_false_positive"]:
            logger.info(f'False positive: {fp_result["reason"]}', trial=self.trial)
            return {"crash_analysis": {
                "root_cause": fp_result["description"],
                "true_bug": False,
                "false_positive_type": fp_result["fp_type"],
                "severity": "low",
                "analyzed": True,
                "gdb_used": False
            }}

        artifact_path = crash_info.get("artifact_path", "")
        if not artifact_path or not os.path.exists(artifact_path):
            return {"errors": [{"node": "CrashAnalyzer", "message": f"Artifact not found: {artifact_path}"}]}

        work_dirs = WorkDirs.from_dict(state.get("work_dirs", {}))

        # Setup GDB project
        target_name = os.path.basename(benchmark.target_path)
        sample_id = os.path.splitext(target_name)[0]
        project_name = oss_fuzz_checkout.rectify_docker_tag(f'{benchmark.id}-{sample_id}-gdb-{self.trial:02d}')

        fuzz_target_path = os.path.join(work_dirs.base, 'fuzz_targets', f'{self.trial:02d}.fuzz_target')
        os.makedirs(os.path.dirname(fuzz_target_path), exist_ok=True)
        with open(fuzz_target_path, 'w') as f:
            f.write(fuzz_target_source)

        build_script_path = ''
        if build_script_source:
            build_script_path = os.path.join(work_dirs.base, 'fuzz_targets', f'{self.trial:02d}.build_script')
            with open(build_script_path, 'w') as f:
                f.write(build_script_source)

        class MockRunResult:
            def __init__(self, b, a):
                self.benchmark, self.artifact_path = b, a

        mock_result = MockRunResult(benchmark, artifact_path)
        evaluator_lib.Evaluator.create_ossfuzz_project_with_gdb(
            benchmark, project_name, fuzz_target_path, mock_result, build_script_path, artifact_path)

        self.gdb_tool = GDBTool(benchmark, result=mock_result, name='gdb', project_name=project_name)
        self.gdb_tool.execute('apt update && apt install -y gdb screen 2>/dev/null')
        self.gdb_tool.execute('export CFLAGS="$CFLAGS -g -O0" && export CXXFLAGS="$CXXFLAGS -g -O0" && compile > /dev/null')
        self.gdb_tool.execute(f'screen -dmS gdb_session -L -Logfile /tmp/gdb_log.txt gdb /out/{benchmark.target_name}')

        self.bash_tool = ProjectContainerTool(benchmark, name='check', project_name=project_name)
        self.bash_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        self.gdb_tool_used = False

        prompt_manager = get_prompt_manager()
        user_prompt = prompt_manager.build_user_prompt(
            "crash_analyzer",
            CRASH_INFO=crash_info.get("error_message", ""),
            STACK_TRACE=crash_info.get("stack_trace", ""),
            FUZZ_TARGET_CODE=fuzz_target_source,
            ADDITIONAL_CONTEXT=f"Project: {benchmark.project}\nFunction: {benchmark.function_name}"
        )

        try:
            result, _ = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=self.args.max_round,
                log_prefix="CRASH"
            )
        finally:
            if self.gdb_tool:
                self.gdb_tool.terminate()
            if self.bash_tool:
                self.bash_tool.terminate()

        self._langgraph_logger.flush_agent_logs(self.name)
        return {"crash_analysis": {
            "root_cause": result.get("insight", "No analysis"),
            "true_bug": result.get("true_bug", False),
            "severity": "high" if result.get("true_bug") else "low",
            "analyzed": True,
            "gdb_used": self.gdb_tool_used
        }}

    def _check_false_positive(self, run_log: str) -> Dict[str, Any]:
        """Check for common false positive patterns."""
        if 'AddressSanitizer: SEGV on unknown address' in run_log:
            return {"is_false_positive": True, "fp_type": "NULL_DEREF", "reason": "Null deref", "description": "Null pointer dereference"}
        if 'fuzz target exited' in run_log:
            return {"is_false_positive": True, "fp_type": "EXIT", "reason": "Target exited", "description": "Fuzz target exited"}
        if 'out-of-memory' in run_log or 'out of memory' in run_log:
            return {"is_false_positive": True, "fp_type": "OOM", "reason": "OOM", "description": "Out of memory"}
        if 'ERROR: libFuzzer: deadly signal' in run_log:
            return {"is_false_positive": True, "fp_type": "SIGNAL", "reason": "Signal", "description": "Assertion failure"}

        # Check for early crash
        for line in run_log.split('\n'):
            if line.startswith('#'):
                if m := re.match(r'^#(\d+)', line):
                    if int(m.group(1)) <= 3:
                        return {"is_false_positive": True, "fp_type": "EARLY_CRASH", "reason": "Early crash", "description": "Crash in first few rounds"}

        return {"is_false_positive": False, "fp_type": "NONE", "reason": "Potential bug", "description": "Needs analysis"}
