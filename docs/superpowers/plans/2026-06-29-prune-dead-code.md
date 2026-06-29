# Prune Dead Code (Plan 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete ~420 LOC of dead / default-off-opt-in code identified by the 2026-06-29 inventory, and correct the design spec's wrong "inert/delete" list (4 items are load-bearing).

**Architecture:** Plan 2 of the beat-PromeFuzz rebuild. These are DELETIONS — the TDD cycle is inverted: the "test" is **grep proves zero live references** + **the existing suite stays green** + **the touched module still imports**. No `pytest src/` semantics change. The blueprint's "~2000 LOC" was mostly already removed in prior commits (`4b593c64`, `12550e8c`, `e75c0cd3`, `7ed8e961`); this plan removes only the verified residual.

**Tech Stack:** Python 3, pytest, grep/ripgrep. No new deps. No docker required.

## Global Constraints

- **Zero behavior change for default runs.** Every deletion is either 0-caller-dead, hardwired-no-op residual, or a default-OFF opt-in (removing it changes only the opt-in-enabled path, which we are deliberately retiring).
- **DO NOT DELETE the 4 load-bearing items** the blueprint wrongly listed: (1) `AutomatonAcceptanceGuard` class + `is_strong`/`_compute_strength` (Comprehender-B prefilter, `comprehender.py:335,815`); (2) `IncrementalZ3Solver` + `Z3GuidedSynthesisController` + push/pop (live Z3 engine); (3) EDSM + PTA + `acceptance_score` (primary L4 sort axis, `coverage_ranker.py:163`); (4) the merge dominance gate (`_apply_dominance`/`dominance_filter`, active in default merge). Touching these is OUT OF SCOPE.
- **Locate by SYMBOL, re-grep at execution** — line numbers below are 2026-06-29 anchors and drift as deletions land. Each task re-greps before editing.
- **Verification gate per task:** `python3 -m pytest tests/ -q` shows **no NEW failures vs the Task 1 baseline** + `python3 -c "import <touched.module>"` succeeds.
- **DEFERRED (not this plan):** the dead automaton-guard arm inside `IncrementalZ3Solver` (`automaton_guard` ctor param, `n_automaton_pruned`, `get_automaton_stats`) — only ~15 LOC but it threads through `create_guided_controller` (`z3_guided_synthesis.py:906`) → `Z3GuidedSynthesisController` → `CBFactory.py:220`, adjacent to the load-bearing `AutomatonAcceptanceGuard`. Risk > reward for a "clean deletes" plan; revisit in the Z3-focused plan.

---

## File Structure

- **Modify:** `liberator_adapter/analysis/project_automaton.py` — remove dead `update_with_traces` + now-unused import.
- **Delete:** `tools/merge_drivers/llm_repair.py` — whole file (default-off, subsumed by `92d17830`).
- **Modify:** `tools/merge_drivers/pipeline.py` — remove the `LOGICFUZZ_MERGE_REPAIR` repair block.
- **Modify:** `liberator_adapter/analysis/sequence_constructor.py` — remove `_drop_unrunnable`/`_runnable` lever + 3 dead residuals (`generic_opaque_handles`, `_densify` `repeat`, `n_error_variants`).
- **Modify:** `CLAUDE.md` + `docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md` — doc/flag cleanup + reclassify the 4 load-bearing items as KEEP.

---

### Task 1: Delete dead `update_with_traces` + baseline the suite

**Files:**
- Modify: `liberator_adapter/analysis/project_automaton.py` (remove `update_with_traces` ~357-480; fix import ~26)

**Interfaces:** none produced; removes a 0-caller method.

- [ ] **Step 1: Baseline the test suite**

Run: `python3 -m pytest tests/ -q 2>&1 | tail -5`
Record the passed/failed counts. Any pre-existing failures are the baseline — later tasks must not ADD failures. (Write the numbers in the commit body of this task.)

- [ ] **Step 2: Confirm `update_with_traces` has zero callers**

Run: `grep -rn "update_with_traces" --include=*.py . | grep -v "def update_with_traces"`
Expected: only comments/docstrings (e.g. `data_context.py`, `run_single_fuzz.py`, in-file comments). NO call site (`.update_with_traces(`). If a real caller exists, STOP — it's not dead.

- [ ] **Step 3: Delete the method**

Delete the entire `def update_with_traces(self, ...)` method body (anchor `project_automaton.py:357-480`, ~124 LOC). Locate by `grep -n "def update_with_traces" liberator_adapter/analysis/project_automaton.py`.

- [ ] **Step 4: Drop the now-unused `incremental_merge` import**

Run: `grep -n "incremental_merge" liberator_adapter/analysis/project_automaton.py`
If the only remaining hit is the import (`~line 26`), remove `incremental_merge` from that `from ... import ...` line, keeping `merge`. If other live uses remain, leave it.

- [ ] **Step 5: Verify**

Run: `python3 -c "import liberator_adapter.analysis.project_automaton" && python3 -m pytest tests/ -q 2>&1 | tail -3`
Expected: import OK; no NEW failures vs Step 1 baseline.

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/analysis/project_automaton.py
git commit -m "refactor(prune): delete dead update_with_traces (0 callers, closed-loop residual)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

### Task 2: Delete the `LOGICFUZZ_MERGE_REPAIR` opt-in (llm_repair)

**Files:**
- Delete: `tools/merge_drivers/llm_repair.py`
- Modify: `tools/merge_drivers/pipeline.py` (remove repair block ~349-382; update docstring ~324-326; drop now-unused `model_name` param if applicable)

**Interfaces:**
- Consumes: nothing new. `_compile_validate_candidates(...)` keeps `repaired_recovered = 0` so downstream `merged/compile_validation.json` stays valid.

- [ ] **Step 1: Confirm repair is default-off and self-contained**

Run: `grep -rn "LOGICFUZZ_MERGE_REPAIR\|llm_repair\|repair_candidates" --include=*.py tools/ src/ run_single_fuzz.py`
Expected hits: only `pipeline.py` (the block) + `llm_repair.py` itself + CLAUDE.md docs. Confirms removal is contained.

- [ ] **Step 2: Remove the repair block in `pipeline.py`**

In `_compile_validate_candidates`, KEEP `repaired_recovered = 0` (anchor line 352) and DELETE the repair logic that follows it (anchor lines 353–382): the `_do_repair = os.environ.get('LOGICFUZZ_MERGE_REPAIR', ...)` read and the entire `if excluded and _do_repair and model_name and out_dir is not None:` block (the `try/except` that imports `repair_candidates`, builds the adapter, calls `repair_candidates`, and logs). The result: after `validate_compilable(...)`, `repaired_recovered` stays 0 and flow continues to the `if excluded:` logging at ~383.

- [ ] **Step 3: Update the docstring + drop now-unused params**

Remove the "Opt-in merge-gate LLM repair (...)" paragraph from the `_compile_validate_candidates` docstring (anchor lines 324–326).
Run: `grep -n "model_name\|out_dir" tools/merge_drivers/pipeline.py`
If `model_name` / `out_dir` now appear ONLY in the signature (no live use after the block is gone), remove them from the signature AND update the caller (find it: `grep -rn "_compile_validate_candidates(" tools/ src/ run_single_fuzz.py`). If still used elsewhere in the function, leave them.

- [ ] **Step 4: Delete the file**

```bash
git rm tools/merge_drivers/llm_repair.py
```

- [ ] **Step 5: Verify**

Run: `python3 -c "import tools.merge_drivers.pipeline" && python3 -m pytest tests/ -q 2>&1 | tail -3`
Expected: import OK; no NEW failures (esp. `tests/test_run_merge_pipeline.py`, `tests/test_pipeline_dominance_stage.py`).

- [ ] **Step 6: Commit**

```bash
git add -A tools/merge_drivers/
git commit -m "refactor(prune): remove LOGICFUZZ_MERGE_REPAIR opt-in (subsumed by 92d17830 lang fix)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

### Task 3: Delete the `_drop_unrunnable` opt-in lever

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` (remove `_drop_unrunnable` read + `_n_unrunnable` + `_runnable` + the `_add` guard + the metrics key)

**Interfaces:** removes the `n_dropped_unrunnable` metric key (telemetry only).

- [ ] **Step 1: Confirm the metric key has no external reader**

Run: `grep -rn "n_dropped_unrunnable\|_drop_unrunnable\|LOGICFUZZ_DROP_UNRUNNABLE" --include=*.py .`
Expected: only `sequence_constructor.py` (+ CLAUDE.md doc). If a test or telemetry consumer reads `n_dropped_unrunnable`, keep the key hardwired `0` instead of removing it.

- [ ] **Step 2: Remove the env read + counter**

Delete (anchor lines 1259–1262):
```python
    _drop_unrunnable = os.environ.get(
        "LOGICFUZZ_DROP_UNRUNNABLE", "0").strip().lower() in (
            "1", "true", "yes", "on")
    _n_unrunnable = [0]
```

- [ ] **Step 3: Remove the `_runnable` function**

Delete the entire `def _runnable(cleaned: Sequence[str]) -> bool:` (anchor lines 1264–1288, ending at `return False`).

- [ ] **Step 4: Remove the guard in `_add`**

Delete (anchor lines 1308–1310):
```python
        if _drop_unrunnable and not _runnable(cleaned):
            _n_unrunnable[0] += 1
            return
```

- [ ] **Step 5: Remove the metrics key**

Delete the metrics line (anchor line 1502): `        "n_dropped_unrunnable": _n_unrunnable[0],`

- [ ] **Step 6: Verify**

Run: `python3 -c "import liberator_adapter.analysis.sequence_constructor" && python3 -m pytest tests/ -q 2>&1 | tail -3`
Expected: import OK; no NEW failures.

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py
git commit -m "refactor(prune): remove _drop_unrunnable opt-in lever (default-off, orphan-keep is the design)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

### Task 4: Delete 3 dead residuals in `sequence_constructor.py`

**Files:**
- Modify: `liberator_adapter/analysis/sequence_constructor.py` (`generic_opaque_handles` field+compute; `_densify` `repeat`; `n_error_variants`)

**Interfaces:** removes the `n_error_variants` metric key (always 0); removes the unused `_Index.generic_opaque_handles` field.

- [ ] **Step 1: Confirm `generic_opaque_handles` has zero readers**

Run: `grep -rn "generic_opaque_handles\|n_error_variants" --include=*.py .`
Expected: only the definitions/writes in `sequence_constructor.py` (+ CLAUDE.md). No external read. If a reader exists, STOP.

- [ ] **Step 2: Remove the `generic_opaque_handles` field**

Delete the field + its comment from the `_Index` definition (anchor lines 616–622): the comment block and `generic_opaque_handles: FrozenSet[str] = frozenset()`.

- [ ] **Step 3: Remove its computation + constructor kwarg**

Delete the computation block (anchor lines 825–834): the comment, `_lib_prefix = _detect_lib_prefix(...)`, `generic_opaque: Set[str] = set()`, and the `for _t, _cands in recovered.items(): ...` loop. Then in the `return _Index(...)` (anchor line 840) remove the kwarg `generic_opaque_handles=frozenset(generic_opaque)`.

- [ ] **Step 4: Remove the `_densify` `repeat` param + dead branch**

In `def _densify(...)` (anchor line 843) remove the `repeat: bool,` parameter. Remove the dead branch (anchor lines 927–932):
```python
    if repeat:   # PF-style: re-call one CONFIG-bearing consumer/getter in a 2nd state
        for s in ordered:
            if s.role is not APIRole.MUTATOR and any(
                    a.role is ArgRole.CONFIG for a in s.args):
                extra.append(s.name)
                break
```
At the sole call site (anchor lines 1396–1397), remove the `False` positional arg so it reads `core = _densify(core, opened, idx, _dense_max_extra, _cooccur, sibling_rank=_rank_i)`. Confirm there is only one caller: `grep -n "_densify(" liberator_adapter/analysis/sequence_constructor.py`.

- [ ] **Step 5: Remove the `n_error_variants` residual**

Delete the assignment (anchor line 1491): `    n_error_variants = 0` and the metrics key (anchor line 1505): `        "n_error_variants": n_error_variants,`.

- [ ] **Step 6: Verify**

Run: `python3 -c "import liberator_adapter.analysis.sequence_constructor" && python3 -m pytest tests/ -q 2>&1 | tail -3`
Expected: import OK; no NEW failures (watch `tests/` touching sequence construction / densify).

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/analysis/sequence_constructor.py
git commit -m "refactor(prune): drop dead residuals (generic_opaque_handles, _densify repeat, n_error_variants)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

### Task 5: Doc + spec reconciliation

**Files:**
- Modify: `CLAUDE.md` (remove stale flag docs)
- Modify: `docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md` (reclassify load-bearing items)

**Interfaces:** none (documentation).

- [ ] **Step 1: Remove stale CLAUDE.md flag docs**

Remove the doc lines for the deleted/already-gone levers: `LOGICFUZZ_DENSE_REPEAT_CONSUMER` (~line 51), `LOGICFUZZ_ERROR_VARIANTS` (~line 77), `LOGICFUZZ_EXERCISE_OBJECT` (~line 94), the stale `TOP_K`/`PORTFOLIO=off` A/B note (~line 74), the `LOGICFUZZ_MERGE_REPAIR` entry (Task 2), and the `LOGICFUZZ_DROP_UNRUNNABLE` entry (Task 3). Locate each by name: `grep -n "DENSE_REPEAT_CONSUMER\|ERROR_VARIANTS\|EXERCISE_OBJECT\|MERGE_REPAIR\|DROP_UNRUNNABLE\|TOP_K" CLAUDE.md`.

- [ ] **Step 2: Correct the spec's "LEAVE BEHIND" section**

In the spec's "LEAVE BEHIND — ~2000 LOC inert/dead weight" section, ADD a correction note (verified 2026-06-29): the bulk was already removed in prior commits; the genuine residual was ~420 LOC (this plan). RECLASSIFY as **KEEP (load-bearing, NOT inert)**: `IncrementalZ3Solver` push/pop + controller (live Z3 engine — soft mode means no *reject*, but the SAT path still builds every skeleton); EDSM + `acceptance_score` (primary L4 sort axis + Comprehender prefilter); `AutomatonAcceptanceGuard` class (its `is_strong()` gates the Comprehender-B prefilter). Only their *prune/admits arms* were inert and are already gone. The merge dominance gate is also load-bearing (KEEP).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md
git commit -m "docs(prune): remove stale flag docs; reclassify 4 'inert' items as load-bearing KEEP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

## Self-Review

- **Spec coverage:** Implements the user-approved Plan-2 scope ("~420 LOC: truly-dead + opt-in levers"): `update_with_traces` (T1), `llm_repair` (T2), `_drop_unrunnable` (T3), `generic_opaque_handles`/`_densify repeat`/`n_error_variants` (T4), doc+spec reconcile (T5). The z3 guard-arm is explicitly DEFERRED (Global Constraints) with rationale. The 4 load-bearing items are explicitly protected.
- **Placeholder scan:** No "TBD"/vague steps. Surgical deletions show verbatim code; whole-symbol deletions name the symbol + a grep gate. The two threaded removals (`incremental_merge` import T1S4; `model_name`/`out_dir` params T2S3) carry an explicit grep-then-conditionally-remove instruction, not a guess.
- **Consistency:** Verification is uniform (grep-zero-refs → delete → import + `pytest tests/` no-new-failures → commit). Metric-key removals (`n_dropped_unrunnable`, `n_error_variants`) each have a grep gate that falls back to hardwired-`0` if an external reader exists. Line anchors are labeled drift-prone with symbol-based re-location.
- **TDD-adaptation note:** deletions invert the cycle — the gate is "grep proves dead + suite stays green + module imports," established against a Task-1 baseline so pre-existing failures don't masquerade as regressions.
