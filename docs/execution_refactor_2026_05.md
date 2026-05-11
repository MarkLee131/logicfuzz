# execution.py refactor — 2026-05

Ninth in the 2026-05 refactor series. `src/tools/execution.py` itself is
a 63-LOC LangChain BaseTool wrapper — the interesting defects all live
in the four agent-side executor implementations (Fixer,
CoverageAnalyzer, CrashAnalyzer, CrashFeasibilityAnalyzer) that wire
the tool's `executor` field.

Six findings (E1–E6) surfaced. User confirmed scope: fix E1+E2
(consolidate the four implementations into one shared helper) and add
the E3 async-fallback TODO note. Defer E4. E5/E6 are intentional.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### E1+E2 — Consolidate `_execute_bash` behind `format_bash_result`

**Symptom.** Four near-duplicate implementations of "render a
CompletedProcess as an LLM-facing tool reply" lived in four agent
files, with three different truncation behaviours:

  - **Silent slice** (Fixer, CoverageAnalyzer): `stdout[:8000]` — the
    LLM sees a clipped output indistinguishable from a complete one.
  - **Joined-message cap** (CrashAnalyzer): `truncate_tool_output(joined)`
    — one giant stdout could eat the whole 8KB budget before the
    stderr was rendered. For crash triage, where the stderr tail is
    usually the load-bearing signal, this was actively harmful.
  - **Per-stream cap + indicator** (CrashFeasibilityAnalyzer): the
    most informative shape — each stream gets its own budget and a
    `... (truncated N chars)` suffix when clipped.

Two additional minor inconsistencies: CrashFeasibilityAnalyzer used
`Command: {args}` / `STDOUT:\n{...}` instead of the dominant `$ cmd` /
`exit=N` format the other three used; and CrashFeasibilityAnalyzer
duck-typed on `hasattr(result, 'stdout')` while the others assumed
the attribute existed.

**Fix.** New module-level helper `format_bash_result(command, result,
max_per_stream=8000)` in `src/tools/execution.py`:

  - Per-stream cap (mode 3, the CrashFeasibilityAnalyzer pattern).
    Each stream that exceeds the cap surfaces
    `... (truncated N chars)`. Total output budget is now 16KB
    (8KB stdout + 8KB stderr), matching what was already implicit in
    the cluster-A 2026-05 Agent review — the joined cap had been an
    accidental halving of the budget when both streams were busy.
  - Uniform `$ cmd` / `exit=N` shape across all four agents.
  - Duck-types on `getattr(result, 'stdout', '')` etc., so a test
    double or future executor swap that omits attributes degrades to
    empty/`?` rather than raising.

Each agent's `_execute_bash` collapses to:

```python
def _execute_bash(self, command: str) -> str:
    return format_bash_result(command, self.inspect_tool.execute(command))
```

CrashFeasibilityAnalyzer's now-unused `_format_bash_result` method is
deleted. Net diff: −~50 LOC across the four agents.

**Behavioural change for CrashAnalyzer.** The previous joined-message
cap is replaced with the per-stream cap. CrashAnalyzer's stderr is no
longer clipped by a long stdout. This is a deliberate uplift — call it
out in dynamic-run validation when the first crash is triaged.

**Files.**
  - `src/tools/execution.py` — added `format_bash_result`, added
    `_DEFAULT_PER_STREAM_CAP` constant, updated module docstring.
  - `src/agents/fixer.py` — `_execute_bash` one-liner; import update.
  - `src/agents/coverage_analyzer.py` — same.
  - `src/agents/crash_analyzer.py` — same; comment noting the
    behavioural change for the cap.
  - `src/agents/crash_feasibility_analyzer.py` — same; deleted
    `_format_bash_result`.

### E3 — Async wrapper TODO note

**Symptom.** `_arun` is defined as `return self._run(command)` —
synchronous fall-through. Latent: only matters if the tool is wired
into an async LangGraph runtime, at which point this serialises all
parallel tool calls instead of running them concurrently.

**Fix.** One-line TODO comment in each `_arun` body pointing at the
real solution (`asyncio.to_thread`). No code change; flagged so the
first reader who needs an async runtime knows exactly where to look.

**File.** `src/tools/execution.py` — comments inside both `_arun`
methods.

---

## §2. Deferred — with rationale

### E4 — Empty-command sentinel returns `"Error: …"` instead of raising

**Observation.** `_run(self, command: str = "", ...)` returns the
string `"Error: bash_execute requires 'command' argument"` when called
without a command. Pydantic's `args_schema=CommandInput` already makes
the arg required for well-behaved providers; the sentinel is
belt-and-suspenders for an LLM that bypasses the schema.

**Why not fix.** Two-line guard, low maintenance cost. Removing it
would expose a small surface to misbehaviour without measurable
upside. Keep until we see a real bug report from the sentinel.

### E5 — Description text "Avoid multi-command shells" is advisory only

**Observation.** Neither tool enforces "avoid multi-command shells or
long-running processes" — chained `cmd1 && cmd2 && cmd3` is allowed.

**Why not fix.** Intentional. The description nudges the LLM toward
simpler commands; the underlying `ProjectContainerTool.execute` has a
60-second timeout (`tool/container_tool.py:97`) which caps the
worst-case blast radius. Enforcing in-tool would require parsing the
command, which is fragile and a poor cost/benefit.

### E6 — No tool-side timeout control

**Observation.** Neither `_execute_bash` nor `_execute_gdb` passes a
custom timeout to the underlying executor. They all inherit the
default 60s.

**Why not fix.** 60s is the right default for the read-files /
grep-patterns / inspect-build-artifacts usage the description
suggests. Per-call timeouts would add API surface and a knob to
mis-tune; no real call site needs longer.

---

## §3. Empirical validation — to be filled in

After the 17-benchmark dynamic run:

### E1+E2: per-stream truncation visibility

Hypothesis: at least one CrashAnalyzer trial logs a `... (truncated N
chars)` indicator on stderr where the pre-fix joined-cap would have
silently dropped that stderr. Spot-check by grepping
`results/*/trial_*/agent_logs/crash_analyzer.log` for the indicator
after the first run with a real crash.

Hypothesis: Fixer / CoverageAnalyzer trials no longer have silent
8KB-clipped outputs. If the LLM still struggles to find context in a
clipped output, at least it knows the data was clipped and can ask
for it differently.

### E3: async TODO

No functional change; verify only that
`docs/execution_refactor_2026_05.md` is the authoritative description
of why `_arun` is sync-fallback and where to look when wiring an
async runtime.

---

## §4. Rollback recipe

If E1+E2 needs to be rolled back (e.g. per-stream cap changes the
budget in a way that hurts a specific agent):

  - In `src/tools/execution.py`, delete `format_bash_result` and the
    `_DEFAULT_PER_STREAM_CAP` constant.
  - In each of the four agent files, restore the deleted local
    implementation:
    - `src/agents/fixer.py` — restore the inline `[:8000]` slice +
      format block.
    - `src/agents/coverage_analyzer.py` — restore the same with the
      cluster A comment.
    - `src/agents/crash_analyzer.py` — restore the joined
      `truncate_tool_output` block.
    - `src/agents/crash_feasibility_analyzer.py` — restore the
      `_format_bash_result` method.

If only the CrashAnalyzer behavioural change is the problem (stderr
no longer clipped by long stdout), the narrower rollback is to
restore just `crash_analyzer.py`'s `_execute_bash` to the
`truncate_tool_output(joined)` shape — the helper stays in place for
the other three agents.

If E3 needs to be rolled back: remove the TODO comments. No
functional impact.
