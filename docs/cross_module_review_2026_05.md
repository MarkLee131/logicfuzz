# Cross-module review of 2026-05 refactor commits

After three refactor commits (synthesis, L1–L5, automaton) and
~3.5k LOC of code change, this is the global consistency audit:
do the cluster-by-cluster fixes compose correctly when taken
together? Are there hidden cross-module dependencies a single-
cluster review missed?

The audit covers the three landed refactor commits:

  - `b117c28d` synthesis refactor (cluster 1–6)
  - `3224b748` L1–L5 filter refactor
  - `e4d754d3` automaton subsystem refactor

---

## §1. Invariants checked

| # | Invariant | Outcome |
|---|---|---|
| 1 | Synthesis-cluster-3 (B4 entry-API safety net) ↔ L1-C5 (admit non-const buffer entries): the safety net is *only* reachable if L1 admits the API. Both must be landed together. | ✅ Both landed. End-to-end path verified by grep — non-const buffer APIs flow L1 → L4 → synthesis. |
| 2 | Silent-fallback policy consistency: synthesis cluster-5 *removed* fallbacks, but L4 / EDSM / LLM-oracle paths *kept* them with louder logs. Reasoned distinction or unintentional? | ✅ Reasoned: synthesis-side fallbacks were masking our own encoding bugs (Z3); L4 / EDSM / oracle fallbacks protect against artifact-side bugs where crashing the whole pipeline is the wrong trade. Both policies documented in respective refactor docs §1 and §2. |
| 3 | HoleFiller deletion: every hole type the deleted infrastructure used to fill must now be filled somewhere else, *or* explicitly accepted as going to the LLM. | ✅ `_infer_paired_destroy` covers RESOURCE_CLEANUP; numeric literal inlining covers LOOP_BOUND; DriverEnhancer covers CALLBACK_IMPL (was already the live source); BUFFER_SIZE / ARRAY_LENGTH / LOOP_CONDITION / INIT_VALUE explicitly accepted as LLM-fill. No orphan hole types. |
| 4 | **Factory.normalize_type SSOT-strict ↔ data_context.py Step ordering**: cluster-5 removed the silent fallback for an uninitialised DataLayout. Was DataLayout actually initialised before every normalize_type call site? | ⚠️ **Real regression found and fixed.** Step 4 grammar-gen called `Factory.normalize_type` via `GrammarGenerator.has_incomplete_type`, but DataLayout was initialised in former Step 5. Old try/except masked the AttributeError. After cluster-5 removal, Step 4 crashed on every non-primitive type. **Fix landed in this commit**: `build_data_layout` moved to Step 3.5, before grammar gen. |
| 5 | Automaton signal change (multi-handle graft) ↔ L4 consumer: does L4 handle a longer prepended creator chain correctly? | ✅ `graft_creator_prefix` still returns a single list; L4 just sees it as one more candidate. No L4-side changes needed. |
| 6 | `enable_llm_oracle` default change (True → False): are there callers other than `data_context.py:744` that omitted the parameter? | ✅ One live caller, passes False explicitly. The default change only affects new callers. |
| 7 | `SkeletonRenderer.render` signature change (removed `is_cpp_target`): are all callers updated? | ✅ Two live callers in `data_context.py`; both updated in the same commit. No other callers. |
| 8 | Closed-loop `_resynth` path: cluster-4 documented preserving both skeleton paths, but cluster-5 stricter Z3 may now raise from `create_random_driver` → does closed-loop tolerate that? | ✅ Per-iteration try/except in `_generate_cbfactory_drivers` line 2165 catches individual failures and `continue`s. Outer try/except at the closed-loop block (line 1137) catches catastrophic failures. The Z3 layer fixes (B1 / B3 / M1) should make the encoder correct in the first place. |
| 9 | Stale doc/comment references to "Step 5: build_data_layout" after the Step 3.5 reordering. | ⚠️ **Two stale references fixed in this commit**: `Factory.py:94` comment and `docs/synthesis_refactor_2026_05.md` cluster-5 entry. |
| 10 | Prototyper prompt still mentions `__CLEANUP_*__` and `__LOOPBOUND_*__` placeholders even though SkeletonGenerator no longer emits them. | ✅ Harmless residual. The fuzzy-match in Prototyper handles unknown placeholders gracefully; the unfilled-pattern regex includes them as defensive coverage in case `_infer_paired_destroy` returns None (which would re-emit a CLEANUP hole). |

---

## §2. The actual regression: Factory.normalize_type ↔ Step ordering

This is the one finding that required a code change beyond doc fixes.

### Symptom

```python
from liberator_adapter.driver.factory import Factory
Factory.normalize_type("cJSON", 0, "val", [False])
# AttributeError: 'DataLayout' object has no attribute 'layout'
```

### Why it happened

`DataLayout` is a singleton (auto-created via `cls.__new__` in
`instance()`). When `__init__` hasn't been called, `self.layout`,
`self.clang_to_llvm_struct`, `self.incomplete_types`,
`self.enum_type` are all unset. So:

  - `get_type_size("cJSON")` → `infer_type_size` doesn't recognise → fallback `self.layout[a_type]` → AttributeError
  - `is_incomplete("cJSON")` → `tmp_type in self.incomplete_types` → AttributeError
  - `is_a_struct("cJSON")` → `a_type not in self.clang_to_llvm_struct` → AttributeError

The old `Factory.normalize_type` had three nested try/except blocks
that swallowed all of these and defaulted to size=0,
incomplete=False, tag=PRIMITIVE. The cluster-5 fix removed those —
in the spirit of CLAUDE.md "No fallbacks — explicit failures" — on
the assumption that production *always* initialises DataLayout
before any `normalize_type` call.

That assumption was wrong: `data_context.py` Step 4 grammar gen
calls `normalize_type` via `GrammarGenerator.has_incomplete_type`,
and former Step 5 built data layout *after* grammar gen.

### How the pytest suite missed it

Tests don't exercise the full Step 4 → grammar_gen.create() → 
has_incomplete_type → normalize_type chain with non-primitive
arg types. They only test simpler paths. After this fix, an
explicit reproducer is documented above so a future test can
guard against re-regression.

### Fix

Moved `build_data_layout()` from former Step 5 position to a new
Step 3.5 (after dependency-graph, before grammar-gen). Only
prerequisite of `build_data_layout` is `self.extract_metadata` (set
in Step 2), so the move is safe.

### Validation

  - Pytest 54/54 pass after move
  - Direct `Factory.normalize_type` call without init still raises
    (intended SSOT behaviour) — confirms we haven't undone the
    cluster-5 strictness; we just gave it the initialisation order
    it needs

---

## §3. Verified-clean items (no fix needed)

These are findings from the audit that turned out to be fine
once traced through:

  - **Z3 strict mode propagation.** `CBFactory.validate_sequence_with_z3`
    can now raise under `z3_strict_mode=True` (default). Callers:
    `create_random_driver` (re-raises in a way that the outer
    per-iteration try/except catches) and `create_skeleton_for_sequence`
    (under strict_mode, the exception bubbles up; under non-strict,
    returns `(False, [...])`). Both call sites handle correctly.

  - **`render_skeleton` `is_cpp_target` removal.** Two callers in
    `data_context.py` both updated in the same commit. The 3 agents
    that have local `is_cpp_target = target_path.endswith(...)` are
    using a different variable with the same name — not related to
    the renderer parameter.

  - **`ApiCall`/`Buffer`/`Variable` `is None` checks.** No code
    relied on the old try/except guards being None-valued; grep
    finds no `is None` checks against these symbols.

  - **Two parallel skeleton paths (cluster 4).** Both
    `create_skeleton_for_sequence` (L4 path) and
    `create_random_driver_skeleton` (closed-loop path) still active.
    The two share `_create_skeleton_from_sequence` underneath, so
    the synthesis-side fixes (cluster-2 inline prefill, cluster-3
    B4 safety net) apply to both paths.

---

## §4. What this audit didn't cover

  - **End-to-end runtime.** All checks above are static (grep +
    code reading + one reproducer). The 17-benchmark dynamic run is
    the next stage; per-fix validation criteria live in
    `docs/review_and_fix_log_2026_05.md` §"Fix inventory".
  - **Performance regressions** beyond the one we accepted (Z3
    encoder is now stricter; some sequences that previously
    SAT-passed via the contradiction-bug-induced UNSAT-swallow may
    now legitimately fail. This is the *intent* of cluster-1.)
  - **LLM-side validation** (Prototyper / Fixer / Improver prompt
    quality). Those agents are next on the review queue.

---

## §5. Process note

This re-review was driven by the user's explicit request:
> 再review一遍，当前的修复，在全局是否合理。尤其是跨模块的影响

Pattern that worked: enumerate 10 cross-module invariants up
front, grep + read each, expect the first 9 to be fine, find one
that needs work. The Step-4-before-Step-5 regression would have
been caught at first benchmark run but at a much higher debug
cost (project failure with cryptic AttributeError, no obvious
link to our recent commits). Catching it statically saves that.

For future refactor commits, the recommendation is: include a
"cross-module audit" §3 in each per-cluster refactor doc that
explicitly enumerates which callers / call ordering / silent-
fallback removals interact with each other.
