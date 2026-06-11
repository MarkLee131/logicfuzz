"""State management for LangGraph-based fuzzing workflow."""

from typing_extensions import TypedDict, NotRequired
from typing import List, Dict, Any, Optional


class FuzzingWorkflowState(TypedDict):
    """
    LangGraph state schema for the fuzzing workflow.
    
    This state schema is designed to be compatible with the original
    Result object hierarchy while providing structure for LangGraph.
    """

    # === Core Information (Required) ===
    benchmark: Dict[
        str,
        Any]  # Benchmark dict (serialized from experiment.benchmark.Benchmark)
    trial: int  # Trial number
    work_dirs: Dict[
        str,
        Any]  # WorkDirs dict (serialized from experiment.workdir.WorkDirs)

    # === Fuzzing Context (Single Source of Truth) ===
    # All data needed for fuzzing, prepared once at the start
    # Philosophy: Nodes read from context, never extract data themselves
    context: NotRequired[Dict[
        str, Any]]  # FuzzingContext.to_dict() - immutable data

    # === Function Analysis (from FunctionAnalyzer) ===
    function_analysis: NotRequired[Dict[str, Any]]

    # === Context Analysis (from ContextAnalyzer) ===
    context_analysis: NotRequired[Dict[str, Any]]

    # === Build Results (from Prototyper/Fixer) ===
    fuzz_target_source: NotRequired[str]
    build_script_source: NotRequired[str]
    compile_success: NotRequired[bool]
    build_errors: NotRequired[List[str]]
    compile_log: NotRequired[str]
    binary_exists: NotRequired[bool]
    is_function_referenced: NotRequired[bool]
    # Set by execution_node when post-run total_pcs falls below the stub
    # threshold — the binary was built and executed but exercised only
    # trivial stub code. Routed by the supervisor to the prototyper for
    # regeneration; distinct from compile_success which stays strictly
    # about compilation. See 2026-05 workflow refactor.
    is_stub_binary: NotRequired[bool]

    # Keep-best (all paths): the highest coverage + its source seen this trial,
    # so a regressing iteration (fixer re-gen) never ships a worse driver than
    # the trial already achieved.
    best_coverage: NotRequired[float]
    best_source: NotRequired[str]

    # Multi-hop reasoning chain summary (2026-05-12, opt-in via
    # --multihop-prototyper). Per-hop character counts for the Hop 1-4
    # tagged sections in the Prototyper LLM response. Full content is
    # dumped per-trial to logs/trial_NN/reasoning_chain.json. Empty
    # dict when the LLM didn't follow the directive (or single-shot
    # mode). See docs/multihop_reasoning_design_proposal_2026_05.md.
    reasoning_chain_summary: NotRequired[Dict[str, int]]

    # === Execution Results (from ExecutionStage) ===
    run_success: NotRequired[bool]
    run_error: NotRequired[str]
    run_log: NotRequired[str]
    artifact_path: NotRequired[str]
    crash_func: NotRequired[Optional[Dict[str, Any]]]
    crashes: NotRequired[bool]
    crash_info: NotRequired[Dict[
        str,
        Any]]  # Detailed crash information including artifact_path, stack_trace, etc.
    reproducer_path: NotRequired[str]

    # === Coverage Results ===
    coverage_summary: NotRequired[str]
    coverage_percent: NotRequired[float]
    line_coverage_diff: NotRequired[float]
    coverage_report_path: NotRequired[str]
    cov_pcs: NotRequired[int]
    total_pcs: NotRequired[int]
    no_coverage_improvement_count: NotRequired[
        int]  # Track consecutive iterations without coverage improvement

    # === Analysis Results (from Analyzers) ===
    crash_analysis: NotRequired[Dict[str, Any]]

    # === Crash-fix retry tracking (supervisor → fixer, crash-FP path) ===
    # MUST be declared: LangGraph silently DROPS writes to undeclared state
    # keys, which disabled the crash-fix retry cap (the reader always saw 0)
    # and starved the fixer of crash context (it "fixed" a crash with an EMPTY
    # error prompt, and the crash fix corrupted the compile-retry budget).
    # 2026-06 semantic review.
    crash_fix_retry_count: NotRequired[int]
    crash_fix_info: NotRequired[Dict[str, Any]]

    # === Workflow Control ===
    next_action: NotRequired[str]  # For supervisor routing
    node_visit_counts: NotRequired[Dict[
        str, int]]  # Per-node visit counter (loop prevention)
    workflow_phase: NotRequired[
        str]  # Current workflow phase: "compilation" or "optimization"
    compilation_retry_count: NotRequired[
        int]  # Separate counter for compilation retries
    total_build_failure_count: NotRequired[
        int]  # Total build failures across all phases (prevents infinite loops)
    prototyper_regenerate_count: NotRequired[
        int]  # Counter for prototyper regenerations

    # === Error Handling ===
    errors: NotRequired[List[Dict[str, Any]]]
    warnings: NotRequired[List[str]]

    # === Error Triage (from Supervisor) ===
    # Compilation error triage result passed from supervisor to fixer
    # Contains: primary_category, recommended_strategy, fix_guidance, categorized_errors
    error_triage: NotRequired[Dict[str, Any]]

    # === Configuration (from agent_test.py compatibility) ===
    pipeline: NotRequired[List[str]]  # Agent pipeline
    use_context: NotRequired[bool]  # Whether to use context
    prompt_file: NotRequired[str]  # Path to prompt file
    additional_files_path: NotRequired[str]  # Path to additional files
    run_timeout: NotRequired[int]  # Execution timeout
    current_iteration: NotRequired[int]  # Current workflow iteration
    max_iterations: NotRequired[int]  # Maximum workflow iterations
    workflow_status: NotRequired[str]  # Workflow status
    active_containers: NotRequired[List[str]]  # Active container list
    crash_results: NotRequired[List[Dict[str, Any]]]  # Crash results list

    # === Token Usage Statistics ===
    token_usage: NotRequired[Dict[str, Any]]  # Token consumption statistics

    # === Session Memory (Consensus Constraints) ===
    # Current consensus constraints established by agents during this task
    # Supervisor should always inject this consensus to downstream agents instead of full message history
    session_memory: NotRequired[Dict[str, Any]]

    # === Session Memory Toggle ===
    # Controls whether session memory (short-memory) is enabled for cross-agent consensus sharing
    # When disabled, agents won't see consensus constraints from previous iterations
    use_session_memory: NotRequired[bool]

    # === Target API Validation (AST-based) ===
    # Result of AST-based validation checking if driver actually calls target APIs
    # Set by build_node after successful compilation
    # Contains: success, actual_called_apis, missing_apis, coverage_ratio, validation_method, report
    target_api_validation: NotRequired[Dict[str, Any]]

    # Pre-build hallucination / fake-definition warnings from
    # UnifiedCodeValidator, surfaced to the fixer. Declared so the write
    # persists (LangGraph was silently dropping it — 2026-06 review).
    api_validation_warnings: NotRequired[List[str]]

    # === Build attempt telemetry ===
    # Append-only list, one record per build_node invocation. Used to derive
    # per-error-class fixer success curves so retry budgets can be calibrated
    # from data instead of priors. See run_single_fuzz._fuzzing_pipeline for
    # the dump to trial_NN/build_attempts.json.
    build_attempts: NotRequired[List[Dict[str, Any]]]


def create_initial_state(
        benchmark,  # experiment.benchmark.Benchmark object
        work_dirs,  # experiment.workdir.WorkDirs object
        trial: int = 0,
        max_round: int = 10,
        run_timeout: int = 300,
        pipeline: Optional[List[str]] = None,
        use_context: bool = False,
        prompt_file: str = "",
        additional_files_path: str = "",
        initial_prompt: str = "",
        model=None,
        use_session_memory: bool = True,
        **kwargs) -> FuzzingWorkflowState:
    """Create an initial state for the fuzzing workflow with full parameter support."""

    # Serialize objects to dicts for msgpack compatibility
    benchmark_dict = benchmark.to_dict()
    work_dirs_dict = work_dirs.to_dict()

    return FuzzingWorkflowState(
        benchmark=benchmark_dict,
        trial=trial,
        work_dirs=work_dirs_dict,
        # agent_messages=agent_messages,  # DISABLED: conversation history storage
        current_iteration=0,
        max_iterations=max_round,
        workflow_status="initialized",
        errors=[],
        warnings=[],
        # Loop prevention counters
        node_visit_counts={},
        # Workflow phase control
        workflow_phase="compilation",  # Start with compilation phase
        compilation_retry_count=0,  # Track compilation retries separately
        build_attempts=[],  # Append-only telemetry for retry-budget calibration
        prototyper_regenerate_count=0,  # Track prototyper regenerations
        # Store additional configuration
        pipeline=pipeline or [],
        use_context=use_context,
        prompt_file=prompt_file,
        additional_files_path=additional_files_path,
        run_timeout=run_timeout,
        build_errors=[],
        crash_results=[],
        active_containers=[],
        # Initialize token usage statistics
        token_usage={
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "by_agent": {}
        },
        # Initialize session memory (consensus constraints storage)
        session_memory={
            "api_constraints": [],  # API usage constraints list
            "archetype": None,  # Identified architecture pattern
            "known_fixes": [],  # Known error fixes
            "decisions": [],  # Key decision records
            "coverage_strategies": [],  # Coverage optimization strategies
        },
        # Session memory toggle
        use_session_memory=use_session_memory,
    )


def update_token_usage(state: FuzzingWorkflowState, agent_name: str,
                       prompt_tokens: int, completion_tokens: int,
                       total_tokens: int) -> None:
    """
    Update token usage statistics in state.
    
    Args:
        state: The workflow state
        agent_name: Name of the agent making the call
        prompt_tokens: Number of prompt tokens used
        completion_tokens: Number of completion tokens used
        total_tokens: Total tokens used
    """
    if "token_usage" not in state:
        state["token_usage"] = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "by_agent": {}
        }

    # Update totals
    state["token_usage"]["total_prompt_tokens"] += prompt_tokens
    state["token_usage"]["total_completion_tokens"] += completion_tokens
    state["token_usage"]["total_tokens"] += total_tokens

    # Update per-agent statistics
    if agent_name not in state["token_usage"]["by_agent"]:
        state["token_usage"]["by_agent"][agent_name] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "call_count": 0
        }

    agent_stats = state["token_usage"]["by_agent"][agent_name]
    agent_stats["prompt_tokens"] += prompt_tokens
    agent_stats["completion_tokens"] += completion_tokens
    agent_stats["total_tokens"] += total_tokens
    agent_stats["call_count"] += 1


def get_token_usage_summary(state: FuzzingWorkflowState) -> str:
    """Get a formatted summary of token usage."""
    token_usage = state.get("token_usage", {})
    if not token_usage:
        return "No token usage data available"

    summary = f"\n{'='*60}\n"
    summary += "Token Usage Summary\n"
    summary += f"{'='*60}\n"
    summary += f"Total Prompt Tokens:     {token_usage.get('total_prompt_tokens', 0):,}\n"
    summary += f"Total Completion Tokens: {token_usage.get('total_completion_tokens', 0):,}\n"
    summary += f"Total Tokens:            {token_usage.get('total_tokens', 0):,}\n"

    by_agent = token_usage.get("by_agent", {})
    if by_agent:
        summary += f"\n{'-'*60}\n"
        summary += "By Agent:\n"
        summary += f"{'-'*60}\n"
        for agent_name, stats in sorted(by_agent.items()):
            summary += f"\n{agent_name}:\n"
            summary += f"  Calls:             {stats.get('call_count', 0)}\n"
            summary += f"  Prompt Tokens:     {stats.get('prompt_tokens', 0):,}\n"
            summary += f"  Completion Tokens: {stats.get('completion_tokens', 0):,}\n"
            summary += f"  Total Tokens:      {stats.get('total_tokens', 0):,}\n"

    summary += f"{'='*60}\n"
    return summary


# ==================== Session Memory Management ====================


def add_api_constraint(state: FuzzingWorkflowState,
                       constraint: str,
                       source: str,
                       confidence: str = "medium",
                       iteration: int = None) -> None:
    """
    Add API constraint to session_memory.
    
    Args:
        state: Workflow state
        constraint: Constraint description
        source: Source agent name
        confidence: Confidence level (high/medium/low)
        iteration: Iteration where this constraint was found
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": []
        }

    api_constraints = state["session_memory"].get("api_constraints", [])

    # Deduplication: Check if the same constraint already exists
    for existing in api_constraints:
        if existing["constraint"] == constraint:
            # Update if new constraint has higher confidence
            if confidence == "high" and existing["confidence"] != "high":
                existing["confidence"] = "high"
                existing["source"] = source
            return

    # Add new constraint
    api_constraints.append({
        "constraint":
        constraint,
        "source":
        source,
        "confidence":
        confidence,
        "iteration":
        iteration if iteration is not None else state.get(
            "current_iteration", 0)
    })

    state["session_memory"]["api_constraints"] = api_constraints


def add_known_fix(state: FuzzingWorkflowState,
                  error_pattern: str,
                  solution: str,
                  source: str,
                  iteration: int = None) -> None:
    """
    Add known error fix to session_memory.
    
    Args:
        state: Workflow state
        error_pattern: Error pattern description
        solution: Solution description
        source: Source agent name
        iteration: Iteration where this fix was discovered
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": [],
        }

    known_fixes = state["session_memory"].get("known_fixes", [])

    # Deduplication
    for existing in known_fixes:
        if existing["error_pattern"] == error_pattern:
            # Update solution if different
            if existing["solution"] != solution:
                existing["solution"] = solution
                existing["source"] = source
            return

    # Add new fix
    known_fixes.append({
        "error_pattern":
        error_pattern,
        "solution":
        solution,
        "source":
        source,
        "iteration":
        iteration if iteration is not None else state.get(
            "current_iteration", 0)
    })

    state["session_memory"]["known_fixes"] = known_fixes


def add_decision(state: FuzzingWorkflowState,
                 decision: str,
                 reason: str,
                 source: str,
                 iteration: int = None) -> None:
    """
    Add key decision to session_memory.
    
    Args:
        state: Workflow state
        decision: Decision content
        reason: Decision reason
        source: Source agent name
        iteration: Iteration where this decision was made
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": [],
        }

    decisions = state["session_memory"].get("decisions", [])

    decisions.append({
        "decision":
        decision,
        "reason":
        reason,
        "source":
        source,
        "iteration":
        iteration if iteration is not None else state.get(
            "current_iteration", 0)
    })

    # Limit decisions to keep only the most recent 10
    state["session_memory"]["decisions"] = decisions[-10:]




def add_coverage_strategy(state: FuzzingWorkflowState,
                          strategy: str,
                          target: str,
                          source: str,
                          iteration: int = None) -> None:
    """
    Add coverage optimization strategy to session_memory.
    
    Args:
        state: Workflow state
        strategy: Strategy description
        target: Target/expected effect
        source: Source agent name
        iteration: Iteration where this strategy was proposed
    """
    if "session_memory" not in state:
        state["session_memory"] = {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": [],
        }

    strategies = state["session_memory"].get("coverage_strategies", [])

    # Deduplication
    for existing in strategies:
        if existing["strategy"] == strategy:
            return

    strategies.append({
        "strategy":
        strategy,
        "target":
        target,
        "source":
        source,
        "iteration":
        iteration if iteration is not None else state.get(
            "current_iteration", 0)
    })

    # Limit strategies to keep only the most recent 10
    state["session_memory"]["coverage_strategies"] = strategies[-10:]


def format_session_memory_for_prompt(state: FuzzingWorkflowState,
                                     max_items_per_category: int = 3) -> str:
    """
    Format session_memory as readable text for injection into agent prompts.
        
    Args:
        state: Workflow state
        max_items_per_category: Maximum items to show per category (default: 3)
    
    Returns:
        Formatted session_memory text
    """
    session_memory = state.get("session_memory", {})

    if not session_memory:
        return "*No consensus constraints for this task yet*"

    parts = []

    # Helper function to prioritize and limit items
    def get_top_items(items, max_count):
        """Get top items based on priority (HIGH > MEDIUM > LOW) and recency."""
        if not items:
            return []

        # Sort by confidence/priority (if exists) and iteration (recency)
        def sort_key(item):
            confidence = item.get('confidence', 'medium').lower()
            priority_score = {
                'high': 3,
                'medium': 2,
                'low': 1
            }.get(confidence, 2)
            iteration = item.get('iteration', 0)
            return (-priority_score, -iteration
                    )  # Negative for descending order

        sorted_items = sorted(items, key=sort_key)
        return sorted_items[:max_count]

    # 1. Format API constraints (top N by priority)
    if api_constraints := session_memory.get("api_constraints", []):
        top_constraints = get_top_items(api_constraints,
                                        max_items_per_category)
        if top_constraints:
            parts.append("## API Usage Constraints")
            for c in top_constraints:
                confidence_level = c.get("confidence", "medium").upper()
                # Compact format: one line per constraint
                parts.append(f"- [{confidence_level}] {c['constraint']}")

    # 2. Format archetype pattern (always show if exists)
    if archetype := session_memory.get("archetype"):
        parts.append("\n## Identified Architecture Pattern")
        parts.append(f"- **Type**: {archetype['type']}")
        parts.append(
            f"- **Lifecycle**: {' → '.join(archetype['lifecycle_phases'])}")

    # 3. Format known fixes (top N most recent)
    if known_fixes := session_memory.get("known_fixes", []):
        top_fixes = known_fixes[-max_items_per_category:]  # Most recent N
        if top_fixes:
            parts.append("\n## Known Error Fixes")
            for fix in top_fixes:
                # Compact format: combine error and solution on fewer lines
                parts.append(f"- **Error**: {fix['error_pattern']}")
                parts.append(f"  **Solution**: {fix['solution']}")

    # 4. Format decision records (top N most recent)
    if decisions := session_memory.get("decisions", []):
        top_decisions = decisions[-max_items_per_category:]  # Most recent N
        if top_decisions:
            parts.append("\n## Key Decisions")
            for d in top_decisions:
                # Compact format: one line per decision
                parts.append(f"- {d['decision']} (Reason: {d['reason']})")

    # 5. Format coverage strategies (top N most recent)
    if strategies := session_memory.get("coverage_strategies", []):
        top_strategies = strategies[-max_items_per_category:]  # Most recent N
        if top_strategies:
            parts.append("\n## Coverage Optimization Strategies")
            for s in top_strategies:
                # Compact format: one line per strategy
                parts.append(f"- {s['strategy']}")

    if not parts:
        return "*No consensus constraints for this task yet*"

    return "\n".join(parts)


def consolidate_session_memory(state: FuzzingWorkflowState) -> Dict[str, Any]:
    """
    Consolidate and clean session_memory with deduplication and length limits.
    
    This function should be called in the Supervisor node to keep session_memory tidy.
    
    Args:
        state: Workflow state
    
    Returns:
        Cleaned session_memory
    """
    session_memory = state.get("session_memory", {}).copy()

    if not session_memory:
        return {
            "api_constraints": [],
            "archetype": None,
            "known_fixes": [],
            "decisions": [],
            "coverage_strategies": [],
        }

    # 1. Deduplicate API constraints
    if api_constraints := session_memory.get("api_constraints", []):
        # Deduplicate by constraint content, keep the one with highest confidence
        unique_constraints = {}
        for c in api_constraints:
            key = c["constraint"]
            if key not in unique_constraints:
                unique_constraints[key] = c
            elif c["confidence"] == "high" and unique_constraints[key][
                    "confidence"] != "high":
                unique_constraints[key] = c
        session_memory["api_constraints"] = list(unique_constraints.values())

    # 2. Deduplicate known_fixes
    if known_fixes := session_memory.get("known_fixes", []):
        unique_fixes = {}
        for fix in known_fixes:
            key = fix["error_pattern"]
            unique_fixes[key] = fix  # Later ones override earlier ones
        session_memory["known_fixes"] = list(
            unique_fixes.values())[-10:]  # Keep only the most recent 10

    # 3. Limit decisions length
    if decisions := session_memory.get("decisions", []):
        session_memory["decisions"] = decisions[-10:]

    # 4. Deduplicate coverage_strategies
    if strategies := session_memory.get("coverage_strategies", []):
        unique_strategies = {}
        for s in strategies:
            key = s["strategy"]
            unique_strategies[key] = s
        session_memory["coverage_strategies"] = list(
            unique_strategies.values())[-10:]

    return session_memory
