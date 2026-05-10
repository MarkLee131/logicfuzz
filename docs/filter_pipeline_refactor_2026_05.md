# L1–L5 filter pipeline refactor — 2026-05 (sequel)

Follow-up review of the Progressive Filter Pipeline (L1 entry point,
L2 lifecycle, L3 state machine, L4 coverage ranker, L5 coverage-aware
pre-filter, plus the provenance checker and special-patterns
analyzers). 7 implicit clusters were identified across ~4800 LOC; this
commit lands the high-priority cluster fixes.

The post-run measurements section at the bottom is intentionally
blank — to be filled after running the 17-benchmark A/B once the
refactor is in.

---

## §1. What changed (per cluster)

### Cluster L1-C5 — `c_buffer_must_be_const` was masking the synthesis-side B4 fix

**Symptom.** The 2026-05 synthesis refactor added a B4 safety net in
`_create_variable_for_param`: when the entry API has a non-const
pointer that isn't `char*`, force the FUZZ_INPUT branch. The corpus
study showed ~5–10% of OSS-Fuzz entry-point APIs need this path.

**But that path was never reached** because L1's
`EntryPointPattern.c_buffer_must_be_const = True` rejected the same
APIs at the L1 stage. They never appeared in `entry_point_names`,
never reached L4 ranking, never entered the CBFactory pool. The
synthesis fix was load-bearing on a code path that L1 had pre-emptively
killed.

**Fix.** `c_buffer_must_be_const` default changed to `False`. When a
non-const buffer is admitted, `EntryPointInfo.confidence` drops from
`1.0` to `0.7` (direct EP) or from `0.9` to `0.7` (indirect EP), so
L4's hierarchical sort still picks const variants first when both
exist.

**Files.** `liberator_adapter/constraints/entry_point_analyzer.py`:
`EntryPointPattern` default, `_check_entry_point` non-const branch,
`_check_indirect_consumer` confidence adjustment.

### Cluster L2-C2 — `auto_complete` filter strategy kept invalid sequences

**Symptom.** `filter_sequences(strategy="auto_complete")` (the
default) had three branches: (a) valid → keep, (b) invalid with
auto-completion → keep + append cleanup, (c) **invalid without
auto-completion → keep anyway**. The third branch made the strategy
operationally identical to `permissive`; downstream stages received
sequences L2 had ostensibly rejected.

**Fix.** Branch (c) now drops the sequence and increments
`invalid_count`. `auto_complete` and `permissive` are now distinct;
`auto_complete` only retains sequences that pass validation OR can be
patched up.

**Files.** `liberator_adapter/constraints/lifecycle_analyzer.py:filter_sequences`.

### Cluster L3-C4 — `_derive_from_condition_info` was a no-op

**Symptom.** The method existed, took two parameters, was called in
`analyze()`, but its body was just a `pass`-bodied for loop. Same
pattern as the synthesis-side `_collect_dependency_constraints` we
removed earlier this month.

**Fix.** Method removed; call site removed. The signature of
`StateMachineAnalyzer.analyze` retains its `condition_info` parameter
for caller-API stability (callers still pass it, callers don't see
that we no longer consume it).

**Files.** `liberator_adapter/constraints/state_machine_analyzer.py`.

### Cluster L1-C1+C6 — Four duplicated helpers, no callers

**Symptom.** `_count_pointer_levels`, `_strip_one_pointer_level`,
`_extract_return_type`, `_find_buffer_size_positions` lived in
`entry_point_analyzer.py` as copies of the same functions in
`analysis/usedef.py`. A comment claimed "lifted to usedef.py as the
single source of truth", but only the four *handle-classification*
helpers became thin delegating wrappers — the *four other* helpers
were just duplicated, and not called from anywhere in the file.

**Fix.** Four duplicates removed. Replaced by a 6-line comment
pointing at `analysis/usedef.py`. The handle-classification wrappers
(`_is_handle_type`, `_normalize_handle_type`,
`_extract_produced_handles`, `_consumed_handle_keys`) remain — they
are still actually called.

**Files.** `liberator_adapter/constraints/entry_point_analyzer.py`.

### Cluster L4-C4 — Silent fallbacks kept, logging improved

**Symptom.** `_score_sequence` and `rank_and_select` both wrap
automaton method calls in `except Exception: ... = None` so a bug in
the project-learned automaton artifact doesn't crash the filter
pipeline. The synthesis-side review had us remove similar silent
fallbacks under the "No fallbacks — explicit failures" CLAUDE.md
principle.

**Decision.** Keep the fallbacks here. The automaton artifact is
learned per-project and may have edge cases (mid-merge state, novel
sequence shapes, oracle disagreement) that legitimately produce
exceptions. Crashing the whole 17-benchmark run because one project's
artifact has a hot path bug is the wrong tradeoff.

**Fix.** Logging promoted from silent / debug to `warning` with the
sequence and exception type included so bugs are *visible* even if
not fatal. Future bugs will show up in log review rather than
disappearing.

**Files.** `liberator_adapter/constraints/coverage_ranker.py`.

---

## §2. Deferred (not in this commit)

### L5 novelty normalization murky

`coverage_aware_filter.calculate_novelty_score`'s normalization is
algebraically odd (`max_possible = len(seq) * 2.5`,
`shift = +len(seq) * 0.5`). Mixed-coverage sequences settle around
score ~0.2, which happens to be the `min_novelty=0.2` threshold —
making the threshold mean "must beat the all-mid baseline". This
*works* operationally but is hard to reason about.

**Why deferred.** Rewriting the normalization requires re-picking the
threshold. Risk of regression on benchmarks. Better to land after
the upcoming A/B run gives us a baseline.

### Duplicated typestate walker (L2 + L3 vs `Typestate.check`)

Both `lifecycle_analyzer.validate_sequence` and
`state_machine_analyzer.validate_sequence` are parallel encodings of
`analysis/usedef.py:Typestate.check`. All three are correct;
unification reduces maintenance burden but doesn't change behaviour.
CLAUDE.md TODO already tracks this.

### L2 c-ares-specific semantic patterns

`_discover_semantic_patterns` hardcodes
`{prefix}_parse_*_reply → {prefix}_free_data` and
`{prefix}_dns_parse → {prefix}_dns_record_destroy`. These work for
c-ares but don't generalize. Lower priority because c-ares is in our
suite and the patterns are additive (don't hurt other projects).

### `provenance_checker.is_compatible` overly permissive

Only 2 forbidden rules; everything else `return True`. Combined with
`check_api_compatibility`'s OR-semantics over multiple access types,
the filter rarely rejects anything. Tightening would require a study
of which dependencies we want to prune — defer until empirical data
shows the looseness costs coverage.

---

## §3. Empirical validation — to be filled in

After running the 17-benchmark suite end-to-end with this refactor,
populate the table below.

### L1 admit rate (non-const buffer entries)

Hypothesis: with `c_buffer_must_be_const=False`, ~5–10% more APIs
will pass L1 on average across the suite. Projects with more
non-const entry-point APIs (mbedtls, libpcap?) should see larger
admit-rate increases.

| Project | L1 EP count before | L1 EP count after | Δ |
|---|---|---|---|
| c-ares | _TBD_ | _TBD_ | _TBD_ |
| cjson | _TBD_ | _TBD_ | _TBD_ |
| ...rest of 17 | _TBD_ | _TBD_ | _TBD_ |

### Compile-rate effect (combined with synthesis B4 safety net)

Hypothesis: the synthesis-side B4 safety net now *actually* runs on
the non-const APIs L1 now admits. Projects where L1's admit rate
increased should also show improved first-trial compile rate.

| Project | Compile-rate before | Compile-rate after | Δ |
|---|---|---|---|
| _per project, run baseline + this refactor_ | _TBD_ | _TBD_ | _TBD_ |

### L2 strictness effect

Hypothesis: `auto_complete` no longer keeps invalid-unfixable
sequences. Should see L2 rejection count go up. Whether L4 output
changes meaningfully depends on whether the dropped sequences would
have been picked anyway — i.e., did they rank high enough to enter
top-K?

| Project | L2 invalid before | L2 invalid after | L4 top-K δ |
|---|---|---|---|
| _TBD_ | _TBD_ | _TBD_ | _TBD_ |

### Automaton-artifact warning rate

Hypothesis: with the new explicit warnings, we should see exactly 0
"automaton acceptance_score raised" / "automaton graft raised"
messages in a healthy run. Non-zero = a bug in the artifact code path
that the old silent fallback hid.

| Run | acceptance warnings | graft warnings |
|---|---|---|
| _TBD_ | _TBD_ | _TBD_ |

---

## §4. Rollback recipe

If a benchmark regresses:

  - `c_buffer_must_be_const = False` → revert to `True`. This
    disables L1 admit of non-const buffer entries; the synthesis-side
    B4 safety net stops being exercised (silently — no error).
  - L2 `auto_complete` keep-anyway → restore the third branch in
    `filter_sequences`. Note that this re-introduces the
    indistinguishable-from-`permissive` semantics.
  - L3 `_derive_from_condition_info` → restore the no-op method (the
    one with the `pass`-bodied for loop). The signature was a no-op,
    so re-adding doesn't change behaviour.
  - L1 4-helper deletion → restore from `git show HEAD~1`. Same
    canonical implementations remain available in `analysis/usedef.py`.
  - L4 warning logging → revert to silent fallback. Bugs in the
    automaton artifact become invisible again.
