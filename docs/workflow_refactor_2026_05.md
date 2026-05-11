# workflow refactor — 2026-05

Eleventh in the 2026-05 refactor series. Audit of `src/workflow/`
covering everything but the Supervisor (reviewed in
`supervisor_validator_refactor_2026_05.md`):
`workflow.py`, `state.py`, `adapters.py`, `nodes/execution.py`, and
the per-agent node wrappers.

Two clusters surfaced: dead-code accretion (W/S/E1 series) and a
tangled `compile_success` / `is_function_referenced` contract that
both lied about and patched over the truth. User confirmed scope:
"Direction A — real `is_function_referenced` check + separate
`is_stub_binary` flag" + all dead-code cleanups + E3 TODO marker.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### Direction A — real `is_function_referenced` + `is_stub_binary` separation

**Symptom.** Two intertwined lies:

  1. **`is_function_referenced`** was set to `True` unconditionally in
     `build_node` (`execution.py:569`, comment "real check happens
     during execution"), but no check ever ran. `Result.success =
     compiles AND binary_exists AND is_function_referenced`
     (`results.py:115`) — the third conjunct was a permanent True,
     making `success` weaker than its definition.
  2. **`compile_success`** was conflated with stub-detection.
     `execution_node:333-355` returned `compile_success = False` when
     `total_pcs < 10`, even though the binary had compiled and run
     fine — supervisor then routed to the fixer (wrong tool for a
     stub-only binary; fixer patches compile errors, doesn't
     regenerate). And `StateAdapter.state_to_result_history` patched
     `compile_success` back to True for the RunResult based on
     indirect signals (`workflow_phase == optimization` or
     `total_pcs > 0`). Two-layer band-aid.

**Fix.**

  - **`is_function_referenced`**: real nm-based check now lives in
    `experiment/evaluator.build_only` via the new module-level helper
    `_check_libfuzzer_entry_symbol(binary_path)`. After build, query
    the binary's symbol table; the entry point must appear with type
    `T` (global text) or `W` (weak defined). Stripped binaries fall
    back to `nm -D` (dynamic); if `nm` is unavailable or the binary
    is fully stripped, the function returns `True` so the absence of
    the tool doesn't pretend to be a missing symbol. `build_only`
    folds this into `overall_success` and surfaces a new
    `is_function_referenced` key in its return dict.
    `build_node` reads the new key and writes it to state; the
    "assume True" line is gone.
  - **`is_stub_binary`**: new dedicated state field
    (`state.py`). `execution_node`'s stub-detection branch now sets
    `is_stub_binary=True` + `run_success=False` instead of
    `compile_success=False`. The supervisor's
    `_handle_optimization_phase` checks `is_stub_binary` first and
    routes to `prototyper` for full regeneration — bypassing the
    fixer, which has the wrong bias for stub regeneration.
  - **`StateAdapter.state_to_result_history`**: the
    `compile_success_final` patch (AD1 band-aid) is removed.
    `RunResult.compiles` now reads directly from
    `state["compile_success"]`. With the contract untangled,
    no patching is needed.

**Files.**
  - `experiment/evaluator.py` (new `_check_libfuzzer_entry_symbol` +
    `build_only` integration)
  - `src/workflow/nodes/execution.py` (`build_node` reads new key;
    `execution_node` stub-detection rewrite)
  - `src/workflow/state.py` (new `is_stub_binary` field)
  - `src/workflow/nodes/supervisor.py` (route on `is_stub_binary`;
    drop the dead `termination_reason` write)
  - `src/workflow/adapters.py` (drop the AD1 patch)

### W1+W2+W3 — Dead workflow factories + `self.config` + ConfigAdapter

**Symptom.** `workflow.py` carried two top-level factory functions
(`create_fuzzing_workflow`, `create_simple_workflow`) and two unused
`workflow_type` variants (`simple`, `test`). Only the `full` variant
is invoked anywhere. The top-level factories were also outdated —
they didn't include `improver`, `coverage_analyzer`, or
`crash_feasibility_analyzer` nodes — so even if someone called them,
the workflow would be broken.

`FuzzingWorkflow.__init__` also called
`ConfigAdapter.create_config(...)` and stored the result on
`self.config`, which was never read; the actual LangGraph config
dict is built inline at the `invoke()` site (`workflow.py:135-144`).

**Fix.** Deleted:

  - Top-level `create_fuzzing_workflow` / `create_simple_workflow`
    (~120 LOC) and their re-exports in `__init__.py`.
  - `_create_simple_workflow` / `_create_test_workflow` and the
    `workflow_type` argument to `create_workflow` / `run`.
  - `self.config` assignment + `ConfigAdapter` class (only used by
    that dead assignment; now a comment marker).
  - `argparse` import in `adapters.py` (no longer needed without
    ConfigAdapter).

Updated `run_single_fuzz.py` and `src/runner.py` to drop the now-
illegal `workflow_type='full'` kwarg.

**Files.**
  - `src/workflow/workflow.py`, `src/workflow/__init__.py`,
    `src/workflow/adapters.py`, `run_single_fuzz.py`, `src/runner.py`.

### S1+S2 — Dead `is_terminal_state` + `termination_reason`

**Symptom.** `state.py:227-245` defined `is_terminal_state()` reading
two non-schema fields (`termination_reason`, `coverage_results`) —
the only writer of `termination_reason` was the supervisor's
`_end_workflow` helper, and the only reader of `termination_reason`
was the dead `is_terminal_state`. Both ends of a never-routed
surface.

**Fix.** Deleted `is_terminal_state`. Dropped the
`termination_reason` write in supervisor's `_end_workflow` — the
reason now flows out via the assistant message (`[{reason}]
{message}`) which the trial logs already capture.

**Files.** `src/workflow/state.py`, `src/workflow/nodes/supervisor.py`.

### E1 — `validate_target_api_calls` `cgprocessor_path` pass-through

**Symptom.** `execution.py:28, 40, 88-89` propagated an optional
`cgprocessor_path` argument all the way to `UnifiedCodeValidator(...)`.
The 2026-05 supervisor/validator refactor (V1) replaced CGProcessor
with libclang-Python `FunctionBodyWalker`; the validator's
`cgprocessor_path` arg has been an explicit no-op since then. The
execution-node pass-through was misleading documentation.

**Fix.** Dropped the parameter from `validate_target_api_calls`'s
signature, body, and docstring.

**File.** `src/workflow/nodes/execution.py`.

### E3 — `crash_info` field duplication TODO

**Symptom.** `execution.py:394-397` populates
`crash_info["error_message"]` and `crash_info["stack_trace"]` from
the same `run_result.crash_info` value. Downstream consumers see
identical strings in both fields. The fix needs `run_result` to
expose a separate `stacktrace` carved out of the libFuzzer stderr.

**Fix.** Added an inline TODO comment with a pointer to this doc.
No semantic change — splitting the fields requires domain context
on what each should contain.

**File.** `src/workflow/nodes/execution.py`.

---

## §2. Deferred — with rationale

### Per-node wrapper duplication

The six LLM-node wrappers (`prototyper_node`, `fixer_node`,
`improver_node`, `crash_analyzer_node`, `coverage_analyzer_node`,
`crash_feasibility_analyzer_node`) share the same 7-line skeleton —
extract `configurable["model_name"]` + `args`, instantiate the
agent, call `execute(state)`, return the result. ~30 LOC of
duplication.

**Why not factor now.** Each wrapper is the natural place to look
when debugging a specific agent's wiring. A shared
`_run_agent(state, config, agent_cls)` helper would save LOC but
add an extra indirection on a heavily-traced hot path. Defer until
the wrappers diverge enough to justify the indirection cost.

### E3 — `crash_info` field plumbing

Documented in §1 as a TODO marker; the semantic split between
`error_message` and `stack_trace` needs a `run_result` schema
change, which sits below the workflow layer. Defer to a
`run_result` refactor pass.

---

## §3. Empirical validation — to be filled in

After the 17-benchmark dynamic run:

### Real `is_function_referenced` surfacing failures

Hypothesis: at least one trial logs the new error message
("Built binary X does not define LLVMFuzzerTestOneInput as a global
text symbol...") for a build that previously slipped through.
Pre-fix: every binary was marked True; post-fix: a link-time silent
failure surfaces as a real `compile_success=False`.

If zero trials hit this, the symbol check is well-aligned with
existing link behaviour — still a confidence-builder.

### `is_stub_binary` routing

Stub-only binary path:
  - Pre-fix: stub detection → `compile_success=False` → supervisor
    routes to fixer → fixer tries to patch a non-error → trial dies
    via MAX_FIXER_INVOCATIONS or MAX_COMPILATION_RETRIES.
  - Post-fix: stub detection → `is_stub_binary=True` →
    `_handle_optimization_phase` routes to prototyper → fresh
    regeneration → real coverage.

Spot-check: grep trial logs for `"Stub binary detected, routing to
prototyper"` (new log line). Verify the trial proceeds via
prototyper rather than fixer.

### Dead-code removal regression check

After deletion of `create_fuzzing_workflow`,
`create_simple_workflow`, `_create_simple_workflow`,
`_create_test_workflow`, `is_terminal_state`, `ConfigAdapter`:
no external caller should break. Confirmed via grep at refactor
time; verify on dynamic run that no `ImportError` / `AttributeError`
appears in trial logs.

### AD1 removal: `RunResult.compiles` accuracy

Hypothesis: with `compile_success_final` patch removed,
`RunResult.compiles` reads the post-fix execution_node value
truthfully. Spot-check trial summaries where the binary stubbed-out
but ran: pre-fix would show `compiles=True` (via patch), post-fix
shows `compiles=True` AND `is_stub_binary=True` separately. Both
truthful; downstream code consuming `compiles` only sees compile
status.

---

## §4. Rollback recipe

If Direction A regresses (e.g., the nm check rejects too many
binaries):

  1. In `experiment/evaluator.py`:
     - Remove `_check_libfuzzer_entry_symbol`.
     - Restore `build_only` to its pre-fix shape: drop the
       `is_function_referenced` key and the
       `is_function_referenced` conjunct in `overall_success`.
  2. In `src/workflow/nodes/execution.py`:
     - `build_node`: restore `is_function_referenced: True` literal.
     - `execution_node`: restore the
       `compile_success: False, build_errors: [stub message]`
       branch.
  3. In `src/workflow/state.py`: drop `is_stub_binary` field.
  4. In `src/workflow/nodes/supervisor.py`: drop the
     `is_stub_binary` route at the top of
     `_handle_optimization_phase`.
  5. In `src/workflow/adapters.py`: restore the
     `compile_success_final` patch block.

If the dead-code removals need to come back:

  - Restore the top-level factories + `_create_simple_workflow` +
    `_create_test_workflow` + `workflow_type` argument from this
    commit's git diff.
  - Restore `ConfigAdapter` class.
  - Restore `is_terminal_state` + `termination_reason` write.

Each rollback is self-contained; pick the narrowest one that
addresses the regression.
