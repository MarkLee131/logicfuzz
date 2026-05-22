# LogicFuzz 2026-05 review-and-fix log

Consolidated index of code review findings, applied fixes, and the
validation criteria that the *upcoming dynamic-run phase* should
exercise to confirm each fix had the intended effect.

This doc is the canonical hand-off from "static review" to "dynamic
A/B run". Each fix below has:

  - **Where**: file + symbol
  - **What**: the bug we believe was there
  - **Fix**: what changed
  - **Why it matters**: the symptom that should change under
    dynamic test if the fix is correctly placed
  - **How to validate**: a concrete observable (counter, ratio,
    coverage delta, log line) the dynamic run should record

Cross-refs to the deeper per-cluster docs:

  - `docs/synthesis_refactor_2026_05.md` (clusters 1–6, commit
    `b117c28d`)
  - `docs/filter_pipeline_refactor_2026_05.md` (L1–L5 fixes,
    commit `3224b748`)
  - `docs/llm_vs_traditional_choices.md` (per-call-site LLM
    justification)
  - `docs/upstream_liberator_diffs.md` (upstream-side bugs we
    fixed in the port)

When dynamic runs land, results should be filled into the matching
`§3. Empirical validation` section of the per-cluster doc, NOT here.
This doc remains a static index.

---

## Reviewed subsystems (read-through complete)

| Subsystem | LOC reviewed | Refactor commits | Status |
|---|---|---|---|
| IR layer (`driver/ir/*`) | ~600 (21 files) | none — clean port | ✅ no fix needed |
| Synthesis (`driver/synthesis/*`) | ~2200 | `b117c28d` | ✅ refactored + deleted dead code |
| `CBFactory.py` + `Factory.py` | 1628 | `b117c28d` | ✅ several fixes (B2 silent fallback, validators) |
| Z3 layer (`z3_solver` + `z3_guided_synthesis`) | 1695 | `b117c28d` | ✅ 4 correctness fixes (B1, B3, M1, M2) |
| `RunningContext` + L0-L5↔CBFactory boundary | — (boundary) | none | ✅ no internal fix needed |
| Prototyper LLM boundary | — (boundary) | none | ✅ no internal fix needed |
| L1 `entry_point_analyzer` | 1095 | `3224b748` | ✅ const-buffer policy + dead helpers |
| L2 `lifecycle_analyzer` | 637 | `3224b748` | ✅ auto_complete strictness |
| L3 `state_machine_analyzer` | 761 | `3224b748` | ✅ dead no-op method removed |
| L4 `coverage_ranker` | 603 | `3224b748` | ✅ fallbacks made loud |
| L5 `coverage_aware_filter` | 275 | none | ⏳ normalization deferred |
| `provenance_checker` | 250 | none | ⏳ permissiveness deferred |
| `special_patterns` | 1199 | none — structural only | ⏳ deep review pending |

**Two commits, four refactor docs.** Net: −1900 LOC dead/duplicate
code; 13 correctness fixes; 6 silent-fallback removals; 2 silent
fallbacks kept with louder logging.

---

## Fix inventory with dynamic-validation criteria

Use this table as the dynamic-run checklist. "✓ matches" means the
observable went the direction we expect; "× contrary" means it went
the other way; "─ inconclusive" means we cannot tell from the data.

### Cluster 1 — Z3 layer correctness (`b117c28d`)

| Fix | File:symbol | Validate by |
|---|---|---|
| B1: type-match contradiction | `z3_solver.py:add_type_match_constraint` | Z3-strict mode now flags some sequences as UNSAT that previously SAT-passed (the contradictory `expr ∧ ¬expr` had forced all type-mismatched pairs UNSAT, so the *whole solver* was UNSAT, which then got swallowed by B2). Expected: **non-zero UNSAT count attributable to type mismatches**, *not* a blanket-UNSAT pattern. |
| B3: lifecycle missed CREATE-before-USE | `z3_solver.py:_add_lifecycle_constraints` | Sequences with use-before-create (e.g. `[get_field, parse_data]`) should now be UNSAT-rejected. Expected: **L4 / Z3 rejection rate increases on projects with complex DAG**. |
| M1: unsat-core API-name parser | `z3_guided_synthesis.py:_extract_missing_resources` | `UnsatDiagnosis.missing_resources` log lines should now contain real type strings (e.g. `cJSON*`), not API-name fragments (e.g. `Print_void*`). Expected: **diagnosis log lines are interpretable**. |
| M2: exception vs timeout | `z3_guided_synthesis.py:check` | Log should distinguish `z3_exception:<TypeName>` (real bug) from `TIMEOUT` (genuine z3 timeout). Expected: **0 `z3_exception:` lines in healthy run; any occurrence pinpoints a real encoder bug**. |

### Cluster 2 — HoleFiller deletion + minimal pre-fill (`b117c28d`)

| Fix | File:symbol | Validate by |
|---|---|---|
| Delete `hole_filler.py` + `constraint_collector.py` + `test_synthesis.py` | — | API output spend should be ≈ unchanged (delta < 5%). Expected: **per-trial output tokens neutral; total prompt tokens unchanged**. If output tokens *spike*, the LLM is filling holes the deleted infra used to absorb. |
| Inline RESOURCE_CLEANUP via `_infer_paired_destroy` | `skeleton_generator.py:_generate_cleanup` + `_infer_paired_destroy` | Generated skeletons should have a concrete `if (var) destroy(var);` line per heap variable. Expected: **0 `__CLEANUP_*__` placeholders in rendered skeletons** for sequences whose APIs match the canonical pair patterns. |
| Inline LOOP_BOUND as numeric literal | `skeleton_generator.py:_generate_loop_call` | Generated loops should show `while (..., __iter_count++ < <integer>)` with no placeholder. Expected: **0 `__LOOPBOUND_*__` placeholders in rendered skeletons**. |

### Cluster 3 — B4 entry-point safety net (`b117c28d`)

| Fix | File:symbol | Validate by |
|---|---|---|
| Force FUZZ_INPUT for entry-API non-const non-char pointer | `skeleton_generator.py:_create_variable_for_param` | Skeletons for APIs like `parse(uint8_t* data, size_t)` should declare `arg0_parse` with `allocation=FUZZ_INPUT` and `init_value="(void*)data"`. Expected: **compile-rate ↑ on projects with non-const buffer entries** (mbedtls, libpcap; see L1 admit table). |

### Cluster 4 — Skeleton-path duality preserved (`b117c28d`)

Documentation-only change (no code). Validate that:

  - `_synthesize_skeletons_per_sequence` still drives the live
    Prototyper path
  - `create_random_driver_skeleton` is still called by Phase G
    closed-loop's `_resynth`
  - Both share the same `_create_skeleton_from_sequence` underlying
    flow

Expected: **closed-loop iterations continue to produce evidence
drivers** even when the random walk diverges from L4's top-K.

### Cluster 5 — Silent fallbacks removed (`b117c28d`)

| Fix | File:symbol | Validate by |
|---|---|---|
| `validate_sequence_with_z3` no longer swallows Z3 errors | `CBFactory.py:validate_sequence_with_z3` | When Z3 internal errors occur, now report `(False, ["z3_error: ..."])` instead of `(True, [])`. Expected: **0 `z3_error:` violation reports in healthy run** (this surfaces residual bugs in the Z3 encoding the silent fallback hid). |
| Conditions / ConditionManager stale guards removed | `Conditions.py`, `ConditionManager.py` | Imports always succeed; no `Variable = None` / `ApiCall = None` fallback. Expected: **no `AttributeError: 'NoneType' object has no attribute ...`** at run time. |
| Factory.normalize_type DataLayout try/except removed | `Factory.py` | If `DataLayout.instance()` isn't initialised before normalize_type, this now raises instead of silently emitting size=0. Expected: **AssertionError surfaces during a stale init order**; healthy run shows no exception. |

### Cluster 6 — Cleanups (`b117c28d`)

Mostly dead code; no behavioural validation. Just confirm imports
still work (54/54 tests pass already).

### L1 — Const-buffer policy + dead helpers (`3224b748`)

| Fix | File:symbol | Validate by |
|---|---|---|
| `c_buffer_must_be_const = False` (default) | `entry_point_analyzer.py:EntryPointPattern` | Per-project EP count should be ≥ pre-refactor count. **Δ should be ~0–15% depending on how many of the project's APIs use non-const pointers.** Empty Δ = project has no such APIs (cjson, libucl). |
| Non-const buffer entries get confidence 0.7 | `_check_entry_point`, `_check_indirect_consumer` | When BOTH const and non-const entry-point variants exist (e.g., a library exposes both signatures), L4's sort should pick the const one first. Validate: in selected top-K, **a const variant beats its non-const sibling**. |
| Activate cluster-3 safety net end-to-end | (combined) | A non-const buffer API admitted by L1, picked by L4, fed to synthesis, hits the cluster-3 path. Expected: **synthesis-time log shows `_create_variable_for_param` taking the entry-API fallback branch on at least one project**. |
| Remove 4 dead duplicated helpers | `_count_pointer_levels`, `_strip_one_pointer_level`, `_extract_return_type`, `_find_buffer_size_positions` | Verify by absence: `git grep -F _count_pointer_levels liberator_adapter/constraints/` returns nothing. |

### L2 — `auto_complete` strictness (`3224b748`)

| Fix | File:symbol | Validate by |
|---|---|---|
| `filter_sequences(strategy="auto_complete")` drops invalid-unfixable | `lifecycle_analyzer.py:filter_sequences` | Per-project `invalid_count` summary should be > 0 on projects where some sequences had no auto-completable cleanup. Compare to the pre-fix `keep anyway` count — expected: **L2 output sequences ↓ slightly, L4 input candidate pool slightly cleaner**. |

### L3 — Dead method removed (`3224b748`)

| Fix | File:symbol | Validate by |
|---|---|---|
| Remove `_derive_from_condition_info` (no-op) | `state_machine_analyzer.py` | Verify by absence. **No transitions previously came from this method**, so behaviour should be unchanged. |

### L4 — Silent fallbacks → louder logs (`3224b748`)

| Fix | File:symbol | Validate by |
|---|---|---|
| Automaton acceptance_fn exception now logs `warning` | `coverage_ranker.py:_score_sequence` | If the automaton artifact has a bug, log should now show `automaton acceptance_score raised ...` warnings. Expected: **0 such warnings in healthy run; any occurrence is an artifact-side bug to file**. |
| Automaton graft_fn exception now logs `warning` | `coverage_ranker.py:rank_and_select` | Same pattern. Expected: **0 graft warnings in healthy run**. |

### Automaton — A: EDSM oracle exception now visible (next commit)

| Fix | File:symbol | Validate by |
|---|---|---|
| `edsm.merge` + `incremental_merge` oracle exceptions log `warning` | `edsm.py:merge`, `edsm.py:incremental_merge` | If the oracle implementation has a bug, log shows `[EDSM] oracle raised ...` with node IDs. Expected: **0 such warnings with oracle disabled; any non-zero count with oracle enabled is an implementation bug**. |

### Automaton — B: Acceptance adjacency caching (next commit)

| Fix | File:symbol | Validate by |
|---|---|---|
| `acceptance_rate` caches `rep → outgoing` adjacency | `project_automaton.py:acceptance_rate` | After cache, repeat calls within the same PTA version are O(walk) not O(walk + adj-rebuild). Expected: **L4 wall-time on top-K=30+ candidates drops noticeably; project with smallest K shows smallest delta**. |
| `acceptance_score` caches adjacency analogously | `project_automaton.py:acceptance_score` | Same. L4 calls this per candidate during ranking. |

### Automaton — C2: Multi-handle graft (next commit)

| Fix | File:symbol | Validate by |
|---|---|---|
| `graft_creator_prefix` now prepends ONE creator per unmet handle (was: first unmet handle only) | `project_automaton.py:graft_creator_prefix` | On projects with multi-handle parsers (mbedtls ctx + config; nghttp2 session + frame), grafted candidates increase. Expected: **L4 admits more grafted candidates on mbedtls / nghttp2; healthy graft on these projects shows the creator chain prepended**. |

### Automaton — E: Default policy alignment (next commit)

| Fix | File:symbol | Validate by |
|---|---|---|
| `learn_project_automaton` default `enable_llm_oracle=False` (was: True) | `project_automaton.py:learn_project_automaton` | Live caller in `data_context.py:756` already passed `False` explicitly, so the production effect is zero. Validate by audit: any NEW caller of `learn_project_automaton` that omits the parameter gets the production-safe default. |

---

## Combined dynamic-run script template

Suggested log lines / metrics to capture during the 17-benchmark run
so we can mechanically verify the fixes:

```
# At the end of each project run, dump:
#   {
#     "project": "<name>",
#     "l1_ep_count": int,            # before vs after compare
#     "l1_non_const_admitted": int,  # new in this refactor
#     "l2_invalid_count": int,       # should be > 0 on some projects
#     "z3_unsat_count": int,         # cluster-1 effect
#     "z3_exception_count": int,     # MUST be 0 in healthy run
#     "z3_error_violations": int,    # MUST be 0 in healthy run
#     "automaton_warning_count": int,# MUST be 0 in healthy run
#     "compile_rate": float,         # cluster-3 effect
#     "rendered_skeleton_holes": {
#         "CLEANUP": int,            # MUST be 0 (cluster-2 inline)
#         "LOOP_BOUND": int,         # MUST be 0 (cluster-2 inline)
#         "BUFFER_SIZE": int,
#         "ARRAY_LENGTH": int,
#         "CALLBACK_IMPL": int,
#         "LOOP_CONDITION": int,
#     },
#     "skeleton_b4_safety_net_hits": int,  # > 0 on at least 1 project
#   }
```

The validation criteria embedded above translate directly to assertions
over this JSON.

---

## Components STILL pending review (2026-05-22 status)

Out of the original 11-item "Components NOT YET reviewed" list (kept
in git history at `15daf73b^:docs/review_and_fix_log_2026_05.md`), all
**11 have been reviewed** in the 2026-05-11 / 12 / 21 refactor wave
— see commits `5ef8e127` (DriverEnhancer), `aaad86e1` (Agent),
`e4d754d3` (Automaton), `0ea457e7` + `63fe5015` (UnifiedCodeValidator
+ Supervisor), `a1246373` (data_context + LFBackendDriver +
merge_drivers), `82e277cf` (Workflow), `de9357ca` (Tools layer),
plus the comprehender-paired review and `8e5ddbe5` (L2/L3 typestate
migration).

The remaining ⏳ items are the **three deferred** entries from the
"Reviewed subsystems" table at the top of this doc:

| Component | File | LOC | Why it matters | Why deferred |
|---|---|---|---|---|
| **L5 `coverage_aware_filter`** | `liberator_adapter/constraints/coverage_aware_filter.py` | 275 | Pre-L4 novelty gate against existing OSS-Fuzz coverage. Controls how aggressively we skip "redundant" sequences. Threshold normalization affects whether we're too strict on small projects. | Normalization deferred — needs A/B on production-eval vs paper-eval profiles before deciding the right shape (currently `--no-coverage-filter` toggles a hard on/off). |
| **`provenance_checker`** | `liberator_adapter/constraints/provenance_checker.py` | 250 | L0 type-DAG admit/reject gate. Permissiveness directly determines L0 pool size; too strict drops legitimate creator/consumer links. | Permissiveness rules deferred — current heuristics work on the 5 test projects; tweaking risks unintended ripple in L0 candidate set without bench data. |
| **`special_patterns`** | `liberator_adapter/constraints/special_patterns.py` | 1199 | VarLenAnalyzer + special-case patterns for non-standard `(buf, size)` signatures (e.g. iov, callback-with-userdata). Affects which APIs L1 admits as indirect entry points. | Deep review pending — largest unreviewed unit (1199 LOC); structural-only check done. Real audit needs a benchmark exercising VarLen patterns (libpcap, mbedtls iov APIs) which the current 5-project bench doesn't include. |

All three are **non-blocking** — their current implementation works
on the 5 reference benchmarks (cjson, c-ares, lcms, libucl, ffjpeg).
Review is on the back-burner until a benchmark surfaces a concrete
failure mode in one of them.

### What's freshly under reconsideration (not the same as "unreviewed")

- **§10B v1/v2** (`src/workflow/nodes/execution.py` baseline-regression
  alert + `src/workflow/nodes/baseline_diff_analyzer.py` recovery
  loop). Code shipped (commits `9b2cf883`, `f6dd60b6`), but the
  2026-05-21 A/B run revealed the design is built on the wrong
  evaluation granularity (per-trial line_diff rather than post-merge
  ratio). See `docs/knowledge_layer_design_proposal_2026_05.md` §10B
  for the empirical findings; the architectural critique is in the
  pub-llm working notes and will likely lead to revert or substantial
  scope reduction once the 2026-05-22 `--eval` A/B finishes.

- **Multi-hop reasoning Mode A** (`src/agents/prototyper.py`,
  commit `64599154`). Single-arm data only; needs 4-arm
  (multihop × §10B) A/B to isolate the contribution. Pending.
