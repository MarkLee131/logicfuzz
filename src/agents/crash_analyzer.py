"""
LangGraphCrashAnalyzer agent - analyzes crashes using GDB.
"""
import argparse
import os
import re
from typing import Any, Dict, List, Optional

import logger
from langchain_core.tools import BaseTool
from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent
from src.agents.tool_calling_mixin import ToolCallingMixin
from src.utils.prompt_loader import get_prompt_manager
from src.tools.langchain_adapters import BashExecuteTool, GDBExecuteTool
from experiment.workdir import WorkDirs


class LangGraphCrashAnalyzer(LangGraphAgent, ToolCallingMixin):
    """Crash analyzer using ReAct-style tool calling with GDB."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        prompt_manager = get_prompt_manager()
        super().__init__(
            name="crash_analyzer",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=prompt_manager.get_system_prompt("crash_analyzer"))
        self.gdb_tool = None
        self.bash_tool = None
        self.gdb_tool_used = False

    def get_tools(self) -> List[BaseTool]:
        return [
            GDBExecuteTool(executor=self._execute_gdb),
            BashExecuteTool(executor=self._execute_bash)
        ]

    def parse_response(self, content: str) -> Dict[str, Any]:
        """Parse crash analysis response using XML tags."""
        result = {'true_bug': None, 'insight': content, 'analyzed': True}
        content_lower = content.lower()

        # XML format: <conclusion>true/false</conclusion>
        if m := re.search(r'<conclusion>\s*(true|false)\s*</conclusion>',
                          content_lower):
            result['true_bug'] = m.group(1) == 'true'
        else:
            logger.warning(
                'No <conclusion> tag found in crash analyzer response',
                trial=self.trial)

        # XML format: <root_cause>...</root_cause>
        if m := re.search(r'<root_cause>(.*?)</root_cause>', content,
                          re.DOTALL | re.IGNORECASE):
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

        # Check for false positive first (with full context)
        fp_result = self._check_false_positive(
            run_log=run_log,
            crash_info=crash_info,
            fuzz_target_source=fuzz_target_source,
            project_name=benchmark.project
        )
        if fp_result["is_false_positive"]:
            logger.info(f'False positive: {fp_result["reason"]}',
                        trial=self.trial)
            return {
                "crash_analysis": {
                    "root_cause": fp_result["description"],
                    "true_bug": False,
                    "false_positive_type": fp_result["fp_type"],
                    "severity": "low",
                    "analyzed": True,
                    "gdb_used": False
                }
            }

        artifact_path = crash_info.get("artifact_path", "")
        if not artifact_path or not os.path.exists(artifact_path):
            return {
                "errors": [{
                    "node": "CrashAnalyzer",
                    "message": f"Artifact not found: {artifact_path}"
                }]
            }

        work_dirs = WorkDirs.from_dict(state.get("work_dirs", {}))

        # Setup GDB project
        target_name = os.path.basename(benchmark.target_path)
        sample_id = os.path.splitext(target_name)[0]
        project_name = oss_fuzz_checkout.rectify_docker_tag(
            f'{benchmark.id}-{sample_id}-gdb-{self.trial:02d}')

        fuzz_target_path = os.path.join(work_dirs.base, 'fuzz_targets',
                                        f'{self.trial:02d}.fuzz_target')
        os.makedirs(os.path.dirname(fuzz_target_path), exist_ok=True)
        with open(fuzz_target_path, 'w') as f:
            f.write(fuzz_target_source)

        build_script_path = ''
        if build_script_source:
            build_script_path = os.path.join(work_dirs.base, 'fuzz_targets',
                                             f'{self.trial:02d}.build_script')
            with open(build_script_path, 'w') as f:
                f.write(build_script_source)

        class MockRunResult:

            def __init__(self, b, a):
                self.benchmark, self.artifact_path = b, a

        mock_result = MockRunResult(benchmark, artifact_path)
        evaluator_lib.Evaluator.create_ossfuzz_project_with_gdb(
            benchmark, project_name, fuzz_target_path, mock_result,
            build_script_path, artifact_path)

        self.gdb_tool = GDBTool(benchmark,
                                result=mock_result,
                                name='gdb',
                                project_name=project_name)
        self.gdb_tool.execute(
            'apt update && apt install -y gdb screen 2>/dev/null')
        self.gdb_tool.execute(
            'export CFLAGS="$CFLAGS -g -O0" && export CXXFLAGS="$CXXFLAGS -g -O0" && compile > /dev/null'
        )
        self.gdb_tool.execute(
            f'screen -dmS gdb_session -L -Logfile /tmp/gdb_log.txt gdb /out/{benchmark.target_name}'
        )

        self.bash_tool = ProjectContainerTool(benchmark,
                                              name='check',
                                              project_name=project_name)
        self.bash_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
        self.gdb_tool_used = False

        prompt_manager = get_prompt_manager()
        user_prompt = prompt_manager.build_user_prompt(
            "crash_analyzer",
            CRASH_INFO=crash_info.get("error_message", ""),
            STACK_TRACE=crash_info.get("stack_trace", ""),
            FUZZ_TARGET_CODE=fuzz_target_source,
            ADDITIONAL_CONTEXT=
            f"Project: {benchmark.project}\nFunction: {benchmark.function_name}"
        )

        try:
            result, _ = self.run_tool_calling_loop(
                initial_prompt=user_prompt,
                state=state,
                max_rounds=self.args.max_round,
                log_prefix="CRASH")
        finally:
            if self.gdb_tool:
                self.gdb_tool.terminate()
            if self.bash_tool:
                self.bash_tool.terminate()

        self._langgraph_logger.flush_agent_logs(self.name)
        return {
            "crash_analysis": {
                "root_cause": result.get("insight", "No analysis"),
                "true_bug": result.get("true_bug", False),
                "severity": "high" if result.get("true_bug") else "low",
                "analyzed": True,
                "gdb_used": self.gdb_tool_used
            }
        }

    def _check_false_positive(self,
                               run_log: str,
                               crash_info: Optional[Dict[str, Any]] = None,
                               fuzz_target_source: str = "",
                               project_name: str = "") -> Dict[str, Any]:
        """
        Check for common false positive patterns.

        IMPORTANT: This function should be conservative - when in doubt,
        return is_false_positive=False to let LLM analyze with GDB.

        Args:
            run_log: Fuzzing log output
            crash_info: Crash details including stack trace
            fuzz_target_source: Source code of fuzz target (to identify driver functions)
            project_name: Name of the project being fuzzed
        """
        crash_info = crash_info or {}
        stack_trace = crash_info.get("stack_trace", "")

        # === Definite false positives ===

        # 1. Fuzz target explicitly called exit()
        if 'fuzz target exited' in run_log:
            return {
                "is_false_positive": True,
                "fp_type": "EXIT",
                "reason": "Fuzz target called exit()",
                "description": "Fuzz target exited unexpectedly - driver bug"
            }

        # 2. Out of memory - typically fuzzer/driver issue
        if 'out-of-memory' in run_log.lower() or 'out of memory' in run_log.lower():
            return {
                "is_false_positive": True,
                "fp_type": "OOM",
                "reason": "Out of memory",
                "description": "Memory exhaustion - likely driver allocates too much"
            }

        # 3. Timeout - not a crash
        if 'timeout' in run_log.lower() and 'ERROR: libFuzzer: timeout' in run_log:
            return {
                "is_false_positive": True,
                "fp_type": "TIMEOUT",
                "reason": "Execution timeout",
                "description": "Timeout - may indicate infinite loop but not a crash"
            }

        # === Crashes that need careful analysis ===

        # 4. NULL pointer dereference - NEEDS CONTEXT
        # This could be a real bug if it happens inside project code!
        if 'AddressSanitizer: SEGV on unknown address' in run_log:
            # Check if crash is in driver code (LLVMFuzzerTestOneInput) or project code
            crash_location = self._analyze_crash_location(stack_trace,
                                                          fuzz_target_source,
                                                          project_name)
            if crash_location["in_driver"]:
                return {
                    "is_false_positive": True,
                    "fp_type": "DRIVER_NULL_DEREF",
                    "reason": f"NULL deref in driver code ({crash_location['function']})",
                    "description": "NULL pointer dereference in fuzz driver - driver did not check API return value"
                }
            else:
                # Crash in project code - could be a real bug!
                return {
                    "is_false_positive": False,
                    "fp_type": "PROJECT_NULL_DEREF",
                    "reason": f"NULL deref in project code ({crash_location['function']})",
                    "description": "NULL pointer dereference in project code - needs LLM analysis"
                }

        # 5. Assertion failure / deadly signal - could be either
        if 'ERROR: libFuzzer: deadly signal' in run_log:
            # Check location - assertions in driver are false positives
            crash_location = self._analyze_crash_location(stack_trace,
                                                          fuzz_target_source,
                                                          project_name)
            if crash_location["in_driver"]:
                return {
                    "is_false_positive": True,
                    "fp_type": "DRIVER_SIGNAL",
                    "reason": f"Signal in driver code ({crash_location['function']})",
                    "description": "Deadly signal in fuzz driver code"
                }
            # In project code - needs analysis
            return {
                "is_false_positive": False,
                "fp_type": "PROJECT_SIGNAL",
                "reason": "Deadly signal in project code",
                "description": "Signal received - needs LLM analysis to determine root cause"
            }

        # 6. Early crash detection - check fuzzing iterations, not stack frames
        early_crash = self._check_early_crash(run_log)
        if early_crash["is_early"]:
            # Early crashes are often driver bugs, but let LLM verify
            return {
                "is_false_positive": False,  # Changed to False - let LLM analyze
                "fp_type": "EARLY_CRASH",
                "reason": f"Crash at iteration {early_crash['iteration']}",
                "description": f"Very early crash (iteration {early_crash['iteration']}) - likely driver issue but needs verification"
            }

        return {
            "is_false_positive": False,
            "fp_type": "NONE",
            "reason": "Potential bug",
            "description": "Needs analysis"
        }

    def _analyze_crash_location(self,
                                 stack_trace: str,
                                 fuzz_target_source: str = "",
                                 project_name: str = "") -> Dict[str, Any]:
        """
        Analyze stack trace to determine if crash is in driver or project code.

        Returns:
            Dict with:
                - in_driver: bool - True if crash is in fuzz driver code
                - function: str - Name of function where crash occurred
                - frame: int - Stack frame number
        """
        # Driver function patterns
        driver_patterns = [
            r'LLVMFuzzerTestOneInput',
            r'FuzzerDriver',
            r'fuzzer::Fuzzer',
            r'__sanitizer',
            r'__asan',
            r'__interceptor',
        ]

        # Extract functions from each frame
        # Stack trace format: "#0 0x... in function_name file:line"
        frame_pattern = re.compile(
            r'#(\d+)\s+0x[a-fA-F0-9]+\s+in\s+(\S+)'
        )

        frames = []
        for match in frame_pattern.finditer(stack_trace):
            frame_num = int(match.group(1))
            func_name = match.group(2)
            frames.append((frame_num, func_name))

        if not frames:
            # Can't parse stack trace - assume not in driver (conservative)
            return {"in_driver": False, "function": "unknown", "frame": -1}

        # Check first few frames for crash location
        for frame_num, func_name in frames[:5]:
            # Skip sanitizer/interceptor frames
            if any(p in func_name for p in ['__sanitizer', '__asan', '__interceptor']):
                continue

            # Check if this is a driver function
            is_driver_func = any(re.search(p, func_name) for p in driver_patterns)

            # Also check if function is defined in fuzz target source
            if fuzz_target_source and not is_driver_func:
                # Extract function definitions from source
                func_def_pattern = rf'\b{re.escape(func_name)}\s*\('
                if re.search(func_def_pattern, fuzz_target_source):
                    is_driver_func = True

            if is_driver_func:
                return {"in_driver": True, "function": func_name, "frame": frame_num}
            else:
                # First non-driver, non-sanitizer frame is likely the crash location
                return {"in_driver": False, "function": func_name, "frame": frame_num}

        # Default: assume not in driver
        return {"in_driver": False, "function": "unknown", "frame": -1}

    def _check_early_crash(self, run_log: str) -> Dict[str, Any]:
        """
        Check if crash happened very early in fuzzing (few iterations).

        Early crashes (< 10 iterations) are often driver bugs because:
        - The fuzzer hasn't had time to generate interesting inputs
        - Simple/empty inputs shouldn't crash well-written code

        Returns:
            Dict with:
                - is_early: bool
                - iteration: int - Number of executed units when crash occurred
        """
        # Look for libFuzzer stats
        # Format: "stat::number_of_executed_units: 5"
        # Or: "#12345 ... units: 5"

        iteration = -1

        # Pattern 1: stat::number_of_executed_units
        stat_match = re.search(
            r'stat::number_of_executed_units:\s*(\d+)',
            run_log
        )
        if stat_match:
            iteration = int(stat_match.group(1))

        # Pattern 2: Last progress line before crash
        # Format: "#1234    NEW    cov: 100 ft: 50 corp: 10/1000b"
        progress_matches = list(re.finditer(
            r'#(\d+)\s+(?:NEW|REDUCE|pulse)',
            run_log
        ))
        if progress_matches and iteration < 0:
            # Use the last progress indicator
            iteration = int(progress_matches[-1].group(1))

        # Pattern 3: "Done X runs"
        done_match = re.search(r'Done\s+(\d+)\s+runs', run_log)
        if done_match and iteration < 0:
            iteration = int(done_match.group(1))

        # Early crash threshold: less than 10 iterations
        EARLY_CRASH_THRESHOLD = 10

        if iteration >= 0 and iteration < EARLY_CRASH_THRESHOLD:
            return {"is_early": True, "iteration": iteration}

        return {"is_early": False, "iteration": iteration}
