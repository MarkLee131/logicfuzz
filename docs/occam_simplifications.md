# Occam's-Razor Simplifications

Log of complexity-reduction changes made during the 2026-06 tool-code
review, and complexity-reduction *opportunities* deliberately **deferred**
because the regression risk outweighed the cleanup value.

Each entry records: what, why it's safe (or why deferred), and the blast
radius. "Applied" = landed in a commit; "Deferred" = recorded here for a
human to decide, not changed.

Guiding rule for this pass: remove only complexity that is *provably
equivalent* to the simpler form. Anything touching load-bearing invariants
(EDSM constructive merge, Z3 lifecycle validation, typestate) is deferred
unless a test pins the behavior.

---

## Applied

### A1. `extract_api_effects(is_handle_type=…)` dead injectable parameter
- **File:** `liberator_adapter/analysis/usedef.py` (+ 2 call sites:
  `project_automaton.py`, `constraints/entry_point_analyzer.py`)
- **Change:** removed the `is_handle_type` keyword parameter. It was accepted
  and documented as an injectable classifier override, and two callers passed
  it, but the function body never resolved or read it — it always used the
  module-level `is_handle_type` (via the `consumed_handle_keys` /
  `extract_produced_handles` callables). Both call-site classifiers
  (`classifier._is_handle_type`, `self._is_handle_type`) just delegate back to
  that same global, so the injected override was provably a no-op.
- **Equivalence:** behavior-preserving (the override equalled the global the
  body already used).

### A3. Dead filter-strategy enums (`LifecycleFilterStrategy`, `StateMachineFilterStrategy`)
- **Files:** `constraints/lifecycle_analyzer.py`, `constraints/state_machine_analyzer.py`,
  `constraints/__init__.py`
- **Change:** removed both `Enum` classes and their package re-exports. Neither
  had any member reference anywhere — `filter_sequences_*` compare against bare
  string literals (`'strict'` / `'auto_complete'` / `'fixable'` / …), so the
  enums were pure decoration.
- **Equivalence:** no member was ever read; string-literal comparisons unchanged.

### A4. `StateMachineAnalyzer.analyze(condition_info=…)` dead parameter
- **Files:** `constraints/state_machine_analyzer.py` (+ `analyze_state_machine`
  convenience fn), `src/context/data_context.py` call site
- **Change:** removed the `condition_info` parameter threaded through
  `analyze` → `analyze_state_machine` → the data_context call. Its only
  consumer (`_derive_from_condition_info`) was a no-op that was already deleted,
  so the value was carried but never read. The `condition_info` *variable* in
  data_context stays — it still feeds ConditionManager and the lifecycle
  analyzer; only the state-machine pass-through was dead.
- **Equivalence:** the parameter reached no live read.

### A5. `acceptance_rate` walk's dead `seen_traces` recursion parameter
- **File:** `liberator_adapter/analysis/project_automaton.py`
- **Change:** the inner `walk(node_id, path, seen_traces)` DFS threaded a
  `seen_traces` set (seeded `set()` at the call) that was never read or
  mutated. Dropped the parameter and the seed.
- **Equivalence:** the set was inert; traversal unchanged.

### A6. `n_unsatisfiable_targets` always-zero construct metric
- **Files:** `liberator_adapter/analysis/sequence_constructor.py`,
  `src/context/data_context.py` (log line), `tests/test_p1_sequence_constructor.py`
- **Change:** removed the `n_unsatisfiable` counter, the
  `n_unsatisfiable_targets` metric, the "(%d unsatisfiable)" log fragment, and
  the test key assertion. The drop-on-unsatisfiable behavior was removed long
  ago (targets always become holes now), so the counter was pinned at 0 and the
  log always printed "(0 unsatisfiable)".
- **Equivalence:** the value was a constant 0; nothing branched on it.

### A7. `LLMEquivalenceOracle(disable_llm=…)` dead config knob
- **File:** `liberator_adapter/analysis/llm_oracle.py`
- **Change:** removed the `disable_llm` constructor parameter, the field, and
  the `_get_model` early-out branch. Nothing in the repo ever passed it True,
  and `_get_model` already returns `None` on any import/construction failure, so
  the deferred-only mode it selected is reachable without the knob.
- **Equivalence:** the knob's only effect (return None) is the same path
  `_get_model` already takes when the model can't be built.

### A2. `_strip_function_bodies & 0` always-off toggle
- **File:** `liberator_adapter/analysis/static_trace.py`
- **Change:** removed a cryptic `PARSE_SKIP_FUNCTION_BODIES & 0` clang parse
  flag. `& 0` makes the term unconditionally 0; the walker needs function
  bodies, so skipping must stay off. Replaced with a plain comment.
- **Equivalence:** the OR-ed term was always 0 — identical parse options.

---

## Deferred (recorded, not changed)

### D1. `edsm.incremental_merge` ↔ `edsm.merge` shared core
- **File:** `liberator_adapter/analysis/edsm.py`
- **Opportunity:** `incremental_merge` (≈115 lines) is largely copy-pasted from
  `merge`: state-vector bucketing, oracle try/except + verdict tally,
  `_score_merge`, and the descending-score apply loop are near-identical; the
  only delta is the "at least one side is a new node" filter and cumulative
  counters. A shared private helper taking an optional `new_ids` filter would
  collapse the duplication.
- **Why deferred:** EDSM merging is the load-bearing *constructive* invariant
  ("every input trace stays accepted after every merge"). Refactoring the
  apply loop risks a subtle ordering/acceptance change, and there is no
  fine-grained test pinning the two paths' equivalence. Worth doing behind a
  dedicated regression test, not in a sweep.

### D3. `Conditions.is_compatible_with` unconditional `return True`
- **File:** `liberator_adapter/constraints/Conditions.py`
- **Observation:** the method short-circuits with `return True` after the
  file-path check, making ~100 lines of field-matching logic below it
  unreachable.
- **Why deferred:** this is a deliberate upstream-Liberator (FLAVIO) experiment
  and matches documented behavior (the binding-layer notes record
  "is_compatible_with returns True" as a known red herring). Excising the dead
  remainder or restoring the matching is a semantic decision about the upstream
  port, not a sweep cleanup. Left intact as a reversible toggle.

### D4. `DriverEnhancer` thin public accessors with no callers
- **File:** `liberator_adapter/driver/driver_enhancer.py`
- **Observation:** `get_loop_pattern`, `get_callback_infos`, and
  `is_structured_parser` are one-line pass-throughs to `self.cache` with zero
  callers in the repo or tests.
- **Why deferred:** `DriverEnhancer` is an adapter port and these read like an
  intended-stable external API surface. Left in place pending a decision on
  whether the accessor surface is contractual; the genuinely dead utilities and
  internals around them were removed.

### D5. `AutomatonAcceptanceGuard` auto-relax / automaton-prune machinery
- **File:** `liberator_adapter/constraints/z3_guided_synthesis.py`
- **Observation:** `admits()` is hardcoded to return True (the positive-only
  redesign), so the auto-relaxation path (`_consecutive_reject`, `n_relaxes`,
  threshold decay) and the `IncrementalZ3Solver.n_automaton_pruned` candidate
  block are unreachable, and `stats()` always reports zeros.
- **Why deferred:** CLAUDE.md documents the guard as "Phase H hard-pruning gate
  (currently positive-only)" — "currently" signals an intended reactivation
  point. Removing the relax/prune scaffolding now would make re-enabling
  rejection harder. Left as dormant machinery; revisit if the gate is declared
  permanently positive-only.

### D6. `is_z3_available()` / `Z3_AVAILABLE` always-true gate
- **File:** `liberator_adapter/constraints/z3_solver.py` (+ callers)
- **Observation:** `Z3_AVAILABLE = True` is a constant and `is_z3_available()`
  always returns True — the import-fallback it once guarded is gone (z3 is now a
  hard dependency). Callers in CBFactory / TypeDependencyGraphGenerator branch on
  a constant.
- **Why deferred:** collapsing the gate touches multiple call sites across the
  synthesis boundary and changes the "z3 optional" contract surface; better as a
  focused change than folded into a dead-code sweep.

### D2. `tools/p0_trace_survey/extract_traces.py` fork of `analysis/static_trace.py`
- **Opportunity:** the survey tool carries a 484-line older fork of
  `static_trace` (same `CallSite`/`StaticTrace`/`ProjectTraceReport`/
  `FunctionBodyWalker`/`extract_project_traces`) that lacks the token-fallback
  callee resolution, global-def pre-pass, and arg-path binding the canonical
  module gained. It will keep rotting.
- **Why deferred:** the duplicate lives in a standalone dev/survey tool with
  its own expectations; re-pointing it at `liberator_adapter.analysis.
  static_trace` could change survey output. A separate, verified change.
