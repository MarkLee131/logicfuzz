# Agent subsystem refactor — 2026-05

Targeted improvements after the line-by-line review of
`src/agents/{base,tool_calling_mixin,utils,prototyper,fixer,
crash_analyzer,crash_feasibility_analyzer,coverage_analyzer,
improver,project_analyzer}.py` (~4300 LOC).

Verdict from the review: the biggest subsystem we've audited, and the
one with the most heterogeneity — every agent reimplemented bits of
the same patterns (tool output truncation, LLM-call error handling,
output validation) slightly differently. The fixes below align the
HIGH and MEDIUM clusters into a single consistent pattern. Cluster
D / E / G / H deferred with rationale.

The "empirical validation" section is intentionally blank — to be
filled after the 17-benchmark dynamic run.

---

## §1. What changed (per cluster)

### Cluster B — Prototyper validator dead code and silent fallback

**Symptom #1.** `_validate_skeleton_adherence` (60 LOC) and
`_get_generation_mode` were both **defined but never called**
from anywhere in the codebase. `llm_vs_traditional_choices.md`
§A described "validator re-checks the LLM output against the
skeleton" — that contract existed in the code but was unwired.

**Symptom #2.** `_validate_api_usage` (which IS called) wrapped
the validator in `try/except → return ""`. The empty string is the
sentinel for "validation passed", so a validator crash silently
shipped unvalidated code downstream. Same SSOT-violation pattern as
synthesis cluster-5.

**Fix.**
- Deleted both dead methods plus the c-ares-specific `unauthorized_apis`
  list they contained (project-specific hardcode, no benefit when dead).
- `_validate_api_usage` now returns `"validator_error: <type>: <msg>"`
  on crash so the Fixer downstream sees the failure mode in
  `state["api_validation_warnings"]` rather than treating it as a
  clean pass.

**File.** `src/agents/prototyper.py`.

### Cluster C — Improver skipped validator entirely

**Symptom.** Improver freely rewrites the driver based on coverage
suggestions and replaces `state["fuzz_target_source"]` with the new
code, but never runs the `UnifiedCodeValidator` check that Prototyper
runs on initial code. If the Improver re-introduces a hallucinated
or internal-API symbol, the Fixer downstream never sees a warning —
it just sees a build error that doesn't include the validator's
prose explanation.

**Fix.** Added a sibling `_validate_api_usage` method to Improver
that runs the same UnifiedCodeValidator check. Result goes into
`state["api_validation_warnings"]` for the Fixer to consume.

**File.** `src/agents/improver.py`.

### Cluster A — Tool-output truncation cap was three different values

**Symptom.** CLAUDE.md says "8KB output truncation". The actual
implementations:
- `base.truncate_tool_output` default: **10000**
- `tool_calling_mixin._truncate` default: **10000**
- `crash_feasibility._format_bash_result`: **10000**
- `fixer._execute_bash`: **8000** (matches CLAUDE.md)
- `crash_analyzer._execute_bash/_execute_gdb`: delegates to base (so 10000)
- `coverage_analyzer._execute_bash`: **no per-tool cap** (only the
  mixin's 10000 at the message boundary)

**Fix.** All three default constants → **8000** (matches CLAUDE.md).
Coverage analyzer gets a per-tool 8KB cap as well, so its output
doesn't dominate the message before the mixin truncates.

**Files.** `src/agents/base.py`,
`src/agents/tool_calling_mixin.py`,
`src/agents/crash_feasibility_analyzer.py`,
`src/agents/coverage_analyzer.py`.

### Cluster F — No retry on transient LLM network errors

**Symptom.** All six agents call `model.invoke(messages)` directly.
A `ConnectionError` / `TimeoutError` / socket-level `OSError`
propagates as an exception and burns a whole trial. LangChain
provider implementations handle rate-limit / auth-error retries
internally, but transient network blips passed through.

**Fix.** Added `_invoke_with_retry(model, messages, max_attempts=2)`
helper in `src/agents/base.py`. Wraps `model.invoke` with one retry
on `(TimeoutError, ConnectionError, OSError)` (network-level only),
exponential backoff starting at 1s. Does **not** retry on
RateLimitError / AuthenticationError / parse errors — those have
either provider-side handling or are genuine bugs.

All `model.invoke` call sites updated:
- `base.chat_llm` (line ~155)
- `base.ask_llm` (line ~225)
- `base.call_llm_stateless` (line ~290)
- `tool_calling_mixin.run_tool_calling_loop` ReAct loop (line ~204)

**Files.** `src/agents/base.py`, `src/agents/tool_calling_mixin.py`.

---

## §2. Deferred (with rationale)

### TODO — Truncation strategy beyond "head 8KB"

Cluster A aligned every truncate call to a flat 8000-char head cap.
That's the right floor (consistent with CLAUDE.md, fixes the cluster
inconsistency) but it's a blunt instrument. Things to think about
before the next refactor:

1. **Semantic-boundary truncation.** Cutting mid-character / mid-line
   forces the LLM to guess at the truncated token. Truncate at the
   nearest preceding newline so each line is intact.
2. **Head + tail keep.** For long compiler output, the *first* error
   and the *summary* (e.g. "N errors generated") are the highest-
   signal parts. Middle is usually duplicated cascading errors.
   Existing `_generate_code_context` in Fixer does head+tail for
   source code but not for tool output.
3. **Per-stream caps.** stdout and stderr each get 8KB separately
   (some agents already do this). For a build that fills stderr but
   produces little stdout, head-only stderr can elide the linker
   failure entirely. Stratified caps would let stderr get more
   budget on link errors.
4. **Tool-type-aware caps.** GDB session output is much sparser than
   build output. Same 8KB cap means GDB gets effectively unbounded
   while build output gets truncated.  Per-tool caps tuned to expected
   density would let each tool keep its informative tail.
5. **Compression / summarisation.** A real LLM-friendly truncator
   could ask a fast model (Haiku?) to *summarise* long output
   instead of cutting. Cost: another LLM call per round. Reward: the
   primary agent sees a tight summary rather than a head/tail
   fragment. Worth A/B-testing once we have baseline numbers.
6. **Drop redundant cascading errors.** A C++ template error often
   produces 50+ lines for one root cause. Detect repetition / shared
   prefix and dedupe before truncating.

For now: flat 8KB cap, document the limitations, revisit after the
17-benchmark dynamic run shows where truncation is actually biting.

### Cluster D — `max_rounds` policy heterogeneity

Three different conventions across the 6 agents (hardcoded 3 for
Fixer; hardcoded 5 for Prototyper / Improver but they have no tools
so it doesn't matter; `args.max_round` for the three tool-using
analyzers). Defer: not behaviourally wrong, just inconsistent.
Document at a later refactor.

### Cluster E — Three overlapping LLM-call methods in base.py

`chat_llm`, `ask_llm`, `call_llm_stateless` overlap heavily (the
first and third are functionally identical except log truncation).
Defer: pure refactor with no behavioural impact.

### Cluster G — c-ares-specific hardcode

The `unauthorized_apis = ['ares_parse_a_reply', ...]` list was
inside the now-deleted `_validate_skeleton_adherence`, so this
auto-resolved. Same pattern is also present in
`liberator_adapter/constraints/lifecycle_analyzer.py`
(`_discover_semantic_patterns`) and is deferred there too pending
generalisation to other DNS / parser projects.

### Cluster H — Implicit state mutation pattern

`add_coverage_attempt(state, ...)` mutates state by reference and
the caller picks the new value back out of state. Pattern is
consistent across the 3 callers (CoverageAnalyzer, Improver, the
supervisor), so it's idiomatic for this codebase even if not the
prettiest. Defer.

### Latent issue: circular import at `from src.agents import …`

Pre-existing before this commit (verified by `git stash` test):
direct `from src.agents import LangGraphPrototyper` triggers a
circular import chain through `src.workflow.state →
src.workflow → src.workflow.nodes.prototyper → src.agents`.
`pytest` doesn't hit this path (the test fixtures import classes
differently). Production uses the workflow module first, so this
also doesn't bite at runtime. Worth fixing later by breaking
either the `base.py:from src.workflow.state` or
`workflow.nodes.prototyper:from src.agents` edge.

---

## §3. Empirical validation — to be filled in

After running the 17-benchmark dynamic run, populate.

### Validator-warning visibility

Hypothesis: under the new validator fixes, every trial's
`state["api_validation_warnings"]` is either empty (validator
passed) or starts with `validator_error:` (crash) or contains
the formatted report (validation failed). The previous silent
fallback hid validator crashes; now they should appear at most
0 times in healthy runs.

| Run | api_validation_warnings: "" | starts with "validator_error:" | non-empty report |
|---|---|---|---|
| _TBD_ | _expect ~100%_ | _expect 0_ | _TBD_ |

### Improver-introduced hallucination rate

Hypothesis: with the new Improver validator, any LLM-introduced
hallucination during the Improver step is caught before it
reaches the Fixer. Measure: count of trials where the Improver
output triggered a non-empty api_validation_warnings *that the
Prototyper output did not*.

| Project | Prototyper warnings | Improver warnings (new) | Δ |
|---|---|---|---|
| _per project_ | _TBD_ | _TBD_ | _TBD_ |

### Network-retry effectiveness

Hypothesis: under the new retry policy, transient `ConnectionError`
/ `TimeoutError` failures get recovered. Measure: retry count from
the log.

| Run | Retries triggered | Retries succeeded | Failed-after-retry |
|---|---|---|---|
| _TBD_ | _TBD_ | _TBD_ | _TBD_ |

### Truncation alignment

Sanity: every tool output in the log either fits under 8KB or
shows the `[... truncated N chars]` marker with N reasonable.
Validation: a `grep -c "truncated"` should be comparable across
agents.

| Agent | Truncations in 24h run |
|---|---|
| _TBD_ | _TBD_ |

---

## §4. Rollback recipe

- Cluster B: restore `_validate_skeleton_adherence` and
  `_get_generation_mode` (their bodies are in this commit's diff;
  trivial to re-add).
- Cluster C: drop the `_validate_api_usage` method + call in
  `improver.py`.
- Cluster A: flip the three `8000` constants back to `10000`.
- Cluster F: drop the `_invoke_with_retry` helper and revert the
  call sites in `base.py` / `tool_calling_mixin.py` back to direct
  `model.invoke`.
