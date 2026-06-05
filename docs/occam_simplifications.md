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

### D2. `tools/p0_trace_survey/extract_traces.py` fork of `analysis/static_trace.py`
- **Opportunity:** the survey tool carries a 484-line older fork of
  `static_trace` (same `CallSite`/`StaticTrace`/`ProjectTraceReport`/
  `FunctionBodyWalker`/`extract_project_traces`) that lacks the token-fallback
  callee resolution, global-def pre-pass, and arg-path binding the canonical
  module gained. It will keep rotting.
- **Why deferred:** the duplicate lives in a standalone dev/survey tool with
  its own expectations; re-pointing it at `liberator_adapter.analysis.
  static_trace` could change survey output. A separate, verified change.
