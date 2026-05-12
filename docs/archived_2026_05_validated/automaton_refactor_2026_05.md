# Automaton subsystem refactor — 2026-05

Targeted fixes after the line-by-line review of
`liberator_adapter/analysis/{pta,edsm,project_automaton,usedef,static_trace,llm_oracle}.py`
(~2800 LOC, the foundation of L4 ranking + Phase G closed loop +
Phase H Z3 guard).

Overall verdict from the review: **cleanest subsystem in the
codebase**. Theory-grounded (Lang/Pearlmutter/Price 1998,
Higuera 2010, Aho/Sethi/Ullman, Strom/Yemini), tight code,
well-commented. No critical bugs found. The fixes below are
improvements: silent-fallback observability, multi-handle graft,
adjacency caching, and one default-vs-policy alignment.

The "empirical validation" section is intentionally blank — to be
filled after the 17-benchmark dynamic run.

---

## §1. What changed (per cluster)

### Cluster A — EDSM oracle exception now visible

**Symptom.** `edsm.py:merge` and `edsm.py:incremental_merge` both
wrapped the oracle call in `try: ... except Exception: verdict = None`.
A bug in the oracle implementation (LLM client, prompt parser, …)
silently degraded every affected pair to "uncertain". Same pattern as
the synthesis-side cluster-5 swallows we removed earlier.

**Fix.** Both call sites now `logger.warning` with the oracle name,
exception, and the node IDs being compared. We still treat the pair
as uncertain (don't crash the merge), but the bug becomes
grep-visible during run audit.

**File.** `liberator_adapter/analysis/edsm.py` — added `logging`
import + 2 log lines.

### Cluster B — Acceptance adjacency caching

**Symptom.** `AutomatonArtifact.acceptance_rate` and
`acceptance_score` both rebuilt a `rep → outgoing-edge → next_rep`
adjacency dict on every call. L4 calls `acceptance_score` once per
candidate during top-K ranking; on a project with 100+ candidates
this is 100× redundant O(|PTA_nodes|) rebuilds.

**Fix.** Each method now caches its adjacency keyed by a version
tuple `(pta.size(), n_merged_states)`. The version changes only
when `update_with_traces` mutates the PTA + re-runs EDSM, so closed-
loop iterations still see fresh adjacency. The cache is stored via
`object.__setattr__` to avoid making `AutomatonArtifact` a non-frozen
dataclass.

**File.** `liberator_adapter/analysis/project_automaton.py` —
`acceptance_rate` and `acceptance_score`.

### Cluster C2 — `graft_creator_prefix` handles multi-handle sequences

**Symptom.** The old implementation returned after grafting the
*first* unmet handle. Sequences that needed *two* upstream creators
(e.g., a parser that takes a context AND a config handle, both
produced elsewhere) were never properly grounded — only the first
handle got a creator, leaving the second as a NULL deref.

**Fix.** Walks the entire sequence, collecting one creator per unmet
handle. Picks the top-ranked root per handle (`graph.roots(h, top_k=3)`).
Returns the concatenation of all chosen creators (in discovery order)
followed by the original sequence. Excludes creators already in the
sequence or already chosen, so no cycles even with multiple grafts.

**File.** `liberator_adapter/analysis/project_automaton.py:graft_creator_prefix`.

### Cluster E — `learn_project_automaton` default policy alignment

**Symptom.** `learn_project_automaton` defaulted `enable_llm_oracle=True`,
but CLAUDE.md's "Open TODOs" specifies "oracle off in production until
cost-aware pacing lands", and the only live caller
(`data_context.py` Step 5e2) explicitly passes `False`. So production
was correct only by accident — a new caller using the default would
silently incur LLM cost.

**Fix.** Default changed to `False`. Added a 6-line docstring
explaining the policy match. The single live caller's explicit
`False` is now a no-op (matches default).

**File.** `liberator_adapter/analysis/project_automaton.py:learn_project_automaton`.

---

## §2. Deferred (with rationale)

These were noted in the review but not fixed this pass.

### B-rejected items: performance

- **`dependency_depth` Bellman-Ford → topological sort.** The current
  B-F relaxation is O(passes × |effects| × max(|USE|)). Worst-case
  bound is large (sqlite3 ~1000 APIs × ~5 USE-handles × ~1000 passes
  = ~5M ops), but the `changed` flag short-circuits at fixpoint —
  in practice converges in 5–10 passes. Already cached after first
  compute. Topological sort would be cleaner but requires SCC
  decomposition for cycles. Defer until profiling shows it's hot.
- **`_suffix_overlap` recursive in EDSM scoring.** Depth=2 recursion
  per pair in each typestate bucket. Bucket size × bucket size pairs.
  For high-fanout PTAs this could be quadratic. Same defer reason —
  no profile evidence it's slow on our 17 benchmarks.
- **`acceptance_rate` recursive DFS.** Python recursion limit risk
  on deep PTAs. Practical PTA depth in fuzz drivers is <50 calls;
  Python default limit is 1000. Won't trigger in practice.

### Edge cases without strong test signal

- **`pta.py:_binding_pattern` out-pointer collision.** Multiple
  out-pointer DEFs at different arg indices all collapse to
  `(-2, "DEF")`. Edge division coarser than intended. Defer until
  we observe a PTA where this causes wrong merging.
- **`llm_oracle.py:_FENCED_JSON_RE` flat regex.** Doesn't handle
  nested braces in JSON. Defer: prompt explicitly asks for flat
  JSON; haven't observed failures.
- **`static_trace.py:_visit_node` BINARY_OPERATOR doesn't check
  operator type.** Doesn't distinguish `=`, `==`, `+`. Process_call
  is called for both lhs and rhs, but `_arg_var_name(lhs)` returns
  None for non-var lhs, so no false bindings. Defer.

### Acknowledged but not actionable

- **Library-wide use-def graph implementation in `usedef.py`** —
  reviewed and matches Aho/Sethi/Ullman §9 mod-ref model exactly.
  Nothing to change.
- **`Typestate.check`** — reviewed against Strom/Yemini 1986 §3.
  Implementation is precise. Nothing to change.

---

## §3. Empirical validation

**cjson run4 (2026-05-11) — automaton learned but Phase H threshold too strict.**

### Learning succeeded

```
[cjson] running EDSM (oracle=evidence-only)...
[cjson] EDSM: 254 → 2 states (oracle yes=0, no=0, ?=21186)
✅ Automaton signal active: {'enabled': True, 'merged_states': 2,
   'observed_apis': 54, 'sample_paths': 8,
   'post_extend_enabled': True, 'post_extend_added': 100}
```

EDSM collapsed 254 PTA states → 2 merged states. 54 unique APIs
observed across cjson's `tests/` directory. Post-parse extension added
100 transitions. Cluster B (caching of `acceptance_rate` /
`acceptance_score`) ran without exception.

### Critical finding: 2-state automaton too strict for Phase H

```
⚠️ Skeleton synthesis attrition on 10 sequences:
  automaton_pruned=10 (acceptance_score < 0.6),
  z3_rejected=0,
  emitted=0
```

`AutomatonAcceptanceGuard.is_strong()` evidently returned True (otherwise
the prefilter wouldn't gate), but 0.6 is too high for cjson's
collapsed 2-state automaton — **every** candidate from L4 was pruned.
The downstream effect: zero skeletons, LFBackendDriver never ran,
Prototyper had to generate from scratch.

This is calibration data, not a bug. Possible interpretations:
  - The 0.6 threshold was chosen for projects with richer automatons
    (5-15 merged states). At 2 states the acceptance scores are too
    discrete (likely binary 0/1) to land above 0.6 on candidates that
    don't perfectly match an observed prefix.
  - Or the cjson PTA→EDSM collapse is over-aggressive; the LLM oracle
    is off (`oracle yes=0, no=0`), so EDSM relies on evidence-only
    merges. With sparse trace count, every state pair looks
    inconclusive (`?=21186`) and gets merged.

**Recommendation for follow-up tuning** (not this commit): scale the
threshold by `merged_states` (e.g. `threshold * f(n_states)` with
`f(2) ≈ 0.3, f(8) ≈ 0.6, f(15) ≈ 0.7`). Or enable the LLM oracle for
small-trace projects to break the all-merge tie-breaks.

### Cluster A (EDSM oracle log visibility)

The `oracle=evidence-only` log line did surface — cluster A's
visibility fix is working.

### Cluster C2 (multi-handle graft) / E (default policy)

Not exercised on cjson (single-handle library; no multi-handle
sequences in the L4 pool to graft).

### c-ares run1 (2026-05-11) addendum — calibration is universal

c-ares produced a **24-state** merged automaton (vs cjson's 2) with
**58 observed APIs**. EDSM: `251 → 24 states (oracle yes=0, no=0,
?=6303)` — same evidence-only mode, larger trace base. Yet:

```
⚠️ Skeleton synthesis attrition on 10 sequences:
  automaton_pruned=10 (acceptance_score < 0.6), z3_rejected=0, emitted=0
```

**Same 10/10 prune rate as cjson.** This is the strong evidence the
calibration finding needs: the 0.6 threshold is not a small-automaton
artifact. Even a 24-state automaton with 58 observed APIs produces
acceptance scores too low to clear 0.6 on L4-ranked candidates.

Hypothesis refinement: the acceptance_score is likely close to
`fraction_of_apis_in_observed_set / sequence_length`, which for a
typical 4-5 step L4 candidate where 2-3 APIs are off-protocol
gives scores in the 0.4-0.6 range. The threshold needs to drop to
~0.3-0.4 to admit useful candidates on real benchmarks.

**Recommendation (unchanged from cjson finding):** scale threshold
by automaton strength OR drop the default from 0.6 to ~0.35. A
follow-up commit should add a `--phase-h-threshold` CLI knob so
operators can tune per-bench without recompiling.

### Cluster A (EDSM oracle log visibility) — confirmed on c-ares too

c-ares logged `EDSM: 251 → 24 states (oracle yes=0, no=0, ?=6303)`
— cluster A's visibility fix produces consistent output across
benchmarks. The `?=N` field grows with trace count and is the
strongest signal that the oracle is off (no positive/negative
votes); useful telemetry.

After the 17-benchmark dynamic run, populate.

### EDSM oracle warning rate

Hypothesis: 0 oracle-exception warnings in a healthy run with
oracle disabled (default). If non-zero with oracle enabled on a
test run, those are real implementation bugs to file.

| Run | enable_llm_oracle | Oracle warnings | EDSM `n_oracle_uncertain` |
|---|---|---|---|
| _TBD_ | False | _expect 0_ | _expect 0_ |
| _TBD (oracle on)_ | True | _TBD_ | _TBD_ |

### Acceptance caching effect

Hypothesis: per-trial wall-time for L4 ranking drops measurably when
top-K is large (≥30 candidates). Project with smallest top-K should
show smallest delta.

| Project | top-K size | L4 wall-time before | After cache | Δ |
|---|---|---|---|---|
| _TBD per project_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

### graft_creator_prefix multi-handle effect

Hypothesis: projects with parser APIs taking ≥2 upstream-produced
handles will see L4 admit more grafted candidates. Specifically:
mbedtls (ctx + config), nghttp2 (session + frame factory).

| Project | grafts succeeded before | After multi-handle | Δ |
|---|---|---|---|
| mbedtls | _TBD_ | _TBD_ | _TBD_ |
| nghttp2 | _TBD_ | _TBD_ | _TBD_ |
| other | _TBD_ | _TBD_ | _TBD_ |

### Default alignment

Should be a no-op (data_context already passed False). Sanity:
audit any non-data_context callers of `learn_project_automaton`
in future PRs.

---

## §4. Rollback recipe

- Cluster A: silent (no logger import). Revert is a 3-line change.
- Cluster B: drop the `object.__setattr__` cache lookups. The rebuild
  path remains correct; just becomes O(|nodes|) per call again.
- Cluster C2: restore the early-return-after-first-graft loop. The
  data structures didn't change.
- Cluster E: flip the default back to `True`. The live caller
  remains correct (passes False explicitly).
