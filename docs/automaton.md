# Project-Adaptive Automaton & Knowledge Layer

> **Status**: automaton + comprehender (PromeFuzz Tier-1 (A)) shipped to
> production. Default-off when `src_ossfuzz/{project}/` is absent
> (graceful degrade — no automaton ⇒ no signal ⇒ ranker + comprehender
> behaviour identical to pre-automaton). ConstraintLearner (Tier-1 (B))
> is design-only, see § 12.
>
> **Headline outcome (manual A/B, Top-12 selected sequences)**:
> **+58% / +217% / +17%** unique-API coverage for libucl / sqlite3 /
> c-ares vs. baseline; 25–58% of Top-12 are acc=1.0 (project-witnessed)
> protocol shapes. Comprehender token cost is **~70× lower** than
> PromeFuzz's default (§ 11).

This doc consolidates the project-adaptive automaton (PTA + EDSM,
shipped via P0–P3) and the PromeFuzz-derived knowledge layer
(comprehender + ConstraintLearner port) into a single source of truth.
They are tightly coupled — the comprehender's per-sequence semantic
check uses `acceptance_score` as a positive-only LLM-skip prefilter,
and the future ConstraintLearner will share its closed-loop refinement
pathway with the automaton's negative-example feedback. The
implementation history lives in `git log liberator_adapter/analysis/`
and `git log src/knowledge/`.

---

## 1. Problem statement

Each library has a *de facto* protocol — an order in which APIs may be
called for the result to be defined. The protocol is implicit in real
consumer code (tests, examples, OSS-Fuzz drivers, doc snippets). We
*learn* a per-project automaton over that protocol and use it to
ground driver synthesis, replacing or supplementing the symbolic
constraints in L0–L3.

## 2. Pipeline (production)

```
multi-source observation                         (shipped)
  consumer_paths/*.{c,cc,cpp}
        │
        ▼  libclang AST walk
  ordered API call sites + value-flow bindings
  (struct fields, TU globals, parameter implicit DEFs)
        │
        ▼  build_pta()
  Prefix Tree Acceptor (PTA) + typestate vectors
  (state = frozenset[(handle_type, lifecycle_state)])
        │
        ▼  edsm_merge()      (LLM oracle wired but throttled off)
  merged automaton — ~95% compression typical
        │
        ▼  AutomatonArtifact
        ├─ acceptance_score(seq)            ──► L4 ranker PRIMARY axis (G3)
        ├─ sample_accepting_paths(8)        ──► prototyper <protocol_templates>
        ├─ graft_creator_prefix(seq)        ──► L4 candidate variant (ranking signal)
        ├─ observed_apis()                  ──► comprehender prefilter
        └─ post_parse_extensions(seq)       ──► extend parse→get_object prefixes
```

> Note (post-redesign G3): `acceptance_score` is now the **primary** L4 sort
> axis (diversity demoted to tiebreak). `sample_accepting_paths` are a
> *ranking/template* signal, **not** a candidate source — raw paths are
> mid-stream fragments that fail lifecycle yet score ≈1.0 (see
> `generation_stage_redesign.md` §8). `graft_creator_prefix` survives only as
> an L4 ranking variant; the Phase A repair engine that also consumed it was
> deleted in G2.

All five points of contact are wired in `FuzzingContext.prepare()`
Step 5e2 → Step 5f → Step 6b → prototyper.

## 3. Theoretical reframing

The earlier "exploit/explore split" was a heuristic. The principled
formulation is **budgeted maximum coverage with feasibility constraint**:

```
maximise   |⋃_{s ∈ S} cov(s)|
subject to |S| ≤ K
           every s in S is L_A-grounded:
              s ∈ L_A, or
              s can be transformed (creator-grafting) into a
              sequence in L_A by prepending a project-known root producer
```

This is NP-hard (Khuller/Moss/Naor 1999). Our greedy in
`coverage_ranker._greedy_select` is the (1−1/e)-approximation. The
change relative to pre-automaton ranking is *what's in the candidate
set*: synthetic L0–L4 sequences ∪ automaton-sampled paths ∪ grafted
versions of unaccepted L0–L4 candidates — all L_A-grounded by
construction.

No 50/50 quota. No bandit framing. Coverage objective is
deterministic and static; we don't need exploration *strategy*, we
need exploration *supply* (the augmented candidate pool).

## 4. Production status

| Layer | What | Status | Pointer |
|-------|------|--------|---------|
| Observation | libclang trace extraction with struct-field + global tracking | shipped | `liberator_adapter/analysis/static_trace.py` |
| Value-flow PTA | typestate-vector PTA over public-API traces | shipped | `liberator_adapter/analysis/pta.py` |
| EDSM merge | evidence-driven state merging (Lang/Pearlmutter/Price 1998) | shipped | `liberator_adapter/analysis/edsm.py` |
| LLM oracle (per-merge) | wired, default off — cost throttling unsolved | partial | `liberator_adapter/analysis/llm_oracle.py` |
| Artifact + persistence | merged automaton + per-project disk cache | shipped | `liberator_adapter/analysis/project_automaton.py` |
| L4 ranker integration | acceptance + path injection + creator-grafting | shipped | `liberator_adapter/constraints/coverage_ranker.py` |
| Comprehender prefilter | acc=1.0 sequences skip LLM | shipped | `src/knowledge/comprehender.py` |
| Prototyper templates | `<protocol_templates>` prompt section | shipped | `src/agents/prototyper.py` |
| **Z3 hard pruning** | unsat-core feedback into merge proposals | future | entry: `liberator_adapter/driver/factory/constraint_based/z3_solver.py` |
| **Closed-loop refinement** | CBFactory build/crash failures → automaton negative examples | future | entry: supervisor crash path |
| **A2DG sequence generator** | full automaton → driver compositional generator | partial future | `sample_accepting_paths()` is the seed; full generator not built |
| **LLM oracle at scale** | proposal throttling for paid runs | future | `edsm.py:merge` candidate scoring |

## 5. Architecture: five points of contact

```
FuzzingContext.prepare()
  Step 5e2 (NEW): learn_project_automaton(project, src_root, consumer_paths)
                  → AutomatonArtifact  (cached at results/{p}/automaton/)
  Step 5f:        select_top_k_sequences(..., automaton_artifact=art)
                  ├─ pool augmented with art.sample_accepting_paths(8)
                  ├─ unaccepted candidates passed to art.graft_creator_prefix()
                  ├─ scored with art.acceptance_score as 2nd sort axis
                  └─ greedy max-coverage on the unified pool
  Step 6b:        comprehender.comprehend_sequences(..., automaton_acceptance_fn=art.acceptance_score)
                  └─ acc=1.0 sequences skip LLM (positive-only prefilter)
  Step 7+:        FuzzingContext.automaton = {summary, sample_paths, observed_apis}
                  └─ exposed to all downstream agents

prototyper_node:
  Reads ctx.automaton.sample_paths → renders <protocol_templates> section
  with explicit "template, not constraint" framing in the LLM prompt.
```

### Concrete code touches (from production rollout)

| file | change |
|------|--------|
| `liberator_adapter/analysis/project_automaton.py` | `AutomatonArtifact` carries `graph` + `project_apis`; `observed_apis()`, `sample_accepting_paths()`, `graft_creator_prefix()` methods |
| `liberator_adapter/constraints/coverage_ranker.py` | `rank_and_select` accepts `automaton_acceptance_fn`, `automaton_graft_fn`, `automaton_sample_paths`; pool augmented before scoring; acceptance promoted to secondary sort axis when present |
| `liberator_adapter/constraints/coverage_ranker.py` | `select_top_k_sequences(..., automaton_artifact=)` derives all three signals from the artifact |
| `src/context/data_context.py` | new Step 5e2 learns automaton; FuzzingContext gains `automaton: Dict` field; passed to ranker + comprehender |
| `src/knowledge/comprehender.py` | positive-only prefilter on acceptance |
| `src/agents/prototyper.py` | `_format_protocol_templates()` + `<protocol_templates>` section in prompt |

Net: ~295 LOC across 6 files. Zero changes to L0–L3, L5, CBFactory,
agents besides prototyper, or any prompt other than `<protocol_templates>`.

## 6. Design contracts (stable, code-checked)

### 6.1 `AutomatonArtifact`
- `acceptance_score(seq) -> float` in `[0.0, 1.0]`. `1.0` iff `seq` is a
  complete accepting walk in the merged automaton; partial walks score
  by deepest reachable prefix.
- `sample_accepting_paths(k) -> list[list[str]]`. Deterministic
  deepest-first traversal, deduplicated.
- `graft_creator_prefix(seq) -> list[str] | None`. For an `seq` whose
  first API consumes a handle the project never produces in `seq`, look
  up a project-witnessed creator from `UseDefGraph.roots` and prepend.
- `observed_apis() -> set[str]`. The public-API set that any trace
  ever called.

### 6.2 PTA / EDSM
- State vector = `frozenset[(handle_type, lifecycle_state)]`. Anything
  not derivable from L2 lifecycle pairs defaults to `INITIALIZED`.
- Acceptance is *constructive*: every input trace remains accepted
  after every merge step. If oracle vetoes a merge, the merge is
  skipped — never weakened.

### 6.3 Persistence layout

```
results/{project}/automaton/
  traces.json        # raw value-flow traces from static_trace
  pta.json           # pre-merge prefix tree
  merged.json        # post-merge automaton
  metadata.json      # run summary, n_traces, n_merged_states, source SHA
  oracle_cache.json  # per-merge LLM oracle decisions (off in prod)
```

## 7. Empirical justification (PromeFuzz benchmark survey)

> **Question**: is the static-trace material on PromeFuzz's 25-project
> benchmark suite *enough* to feed PTA + EDSM without runtime
> instrumentation? **Answer**: yes, for ≥57% of projects with
> conservative counting; ≥78% after fixing C++ method-call counting
> (already done in production via libclang).

### Headline numbers (across PromeFuzz's 25 benchmarks)

- **25 / 25 (100%)** projects declare non-empty `consumer_case_paths` in
  their `lib.toml` — i.e. PromeFuzz authors themselves needed static
  trace material on every benchmark.
- **23 / 25** measurable in our survey (cre2 path mismatch; libpng's
  `contrib/oss-fuzz` not in upstream).
- **Median per project**: 296 API call sites, 638 function bodies —
  well above the L\* / EDSM convergence threshold (~50–100 traces).
- **57% (13/23)** are trace-rich (≥200 API calls); **70–75%** become
  *learnable* once C++ method-call counting is fixed.

### Distribution

```
rich    (≥1000 API calls):    6/23  (26%)
medium  (200–1000):           7/23  (30%)
low     (50–200):             1/23   (4%)
sparse  (<50, hand-pick area):8/23  (35%)  — many underestimated
unmeasured:                   2/25
```

The "sparse" bucket breaks into 4 patterns:
1. **C++ header-only** (rapidcsv, tinygltf, svgpp): tests are
   `Class obj(...); obj.method(...);`. Underestimated by prefix-regex;
   real signal is high. Fixed in production via libclang AST walk.
2. **C++ namespace-heavy** (exiv2, loguru): qualified `Exiv2::Image`
   calls underestimated. Same fix.
3. **Genuinely thin tests** (ffjpeg, libmagic, ngiflib): PromeFuzz
   authors hand-picked individual `.c` files because the project
   itself ships minimal tests. Yield is genuinely low.
4. **Build-script / configure tests** (libjpeg-turbo `fuzz/`): listed
   path is purely for harness scaffolding, not example-of-use.

### Comparison to Rubick's threshold

Rubick (USENIX Sec'23) uses 100+ Maven-crawled consumer JARs per
library to learn its automaton. Our equivalent yield from static
source extraction:

| Yield bucket | Sufficient for L\* / EDSM? | # projects |
|------|---|------:|
| ≥1000 API calls / 1000 funcs | comfortably | 6 |
| 200–1000 calls | sufficient with LLM oracle | 7 |
| 50–200 calls | marginal; LLM oracle critical | 1 |
| <50 calls (after fixing C++ undercount) | requires doc-block fallback | ~3–6 |

**Even conservative reading puts ≥13/23 = 57% of projects in the
"comfortably learnable" zone using only static source.**

## 8. Quantitative outcomes (P3-full A/B, real candidate pools)

```
project    pool  A_topk B_topk  A_uniqAPI B_uniqAPI  B_acc=1  sample_paths
libucl       12      12     12         12        19    3/12          8
sqlite3      12      12     12         12        38    7/12          8
c-ares       12      12     12         12        14    5/12          8
```

A = baseline (no automaton). B = with automaton.

### Why diversity goes up

The augmented pool includes 8 `sample_paths` per project — accepting
walks through the merged automaton. Many are EDSM-merged combinations
not in any single trace (e.g. sqlite3's `open_v2 → close → open` chain
spans multiple test bodies). These bring APIs that no L0–L4 candidate
covered.

### Top-3 inspection (manual review)

**libucl**:
- A: 3 isolated single-API calls (no protocol shape)
- B: `parser_new → add_chunk` (canonical), `parser_new → add_chunk_full`,
  plus an 8-API EDSM-merged combo

**sqlite3** (most dramatic):
- A: `bind_blob`, `bind_blob64`, `bind_text` — three bare consumers, all NULL-deref
- B: 8-API real protocol (`open_v2 → close → open` chain), `bind_text`
  (now top because the augmented pool has its grounded form), `bind_text64`

**c-ares**:
- A: 3 type-only-feasible sequences with low diversity
- B: canonical `create_query → free_string`, `mkquery → free_string`,
  plus an 8-API real test protocol

## 9. Future work (condensed)

Speculative extensions, not yet built. Each is independently sequenced;
detailed sketches in git history if revived.

- **Z3 hard pruning of merge candidates.** EDSM's evidence score is *soft*;
  high-scoring state pairs can have contradictory typestate once unfolded.
  Push the merged-state assertions through the existing `IncrementalZ3Solver`
  (`push`/`pop`), skip UNSAT pairs before scoring. Z3 is cheaper than and
  strictly sound vs. the LLM oracle; expected to drop oracle call rate by an
  order of magnitude. Needs a typestate→Z3 translator.
- **LLM oracle proposal throttling.** Evidence-only EDSM is what ships;
  oracle-on-every-pair costs ~$40 (gpt-4o-mini, sqlite3, 44k merges). Plan:
  Z3-prune first, then consult oracle only on the uncertain evidence band,
  cap calls per project, cache by `(project, state_pair_signature)`.
- **Closed-loop negative refinement.** A build/crash failure is a *negative*
  example: the driver's actual call sequence is not in the protocol language.
  Feed those back into EDSM as explicit-negative traces (veto merges that
  would accept them). Symbolic counterpart of PromeFuzz's ConstraintLearner
  (§12).
- **A2DG (Automaton → Driver Generator).** Today `sample_accepting_paths`
  seeds `<protocol_templates>` for the prototyper. A full A2DG would
  compositionally enumerate driver templates from the automaton, parameterised
  over fuzzer-data consumption sites, falling back to LLM only when no path
  satisfies a desired constraint. Open: non-fuzzer arg parameterisation;
  witness-covering K paths into one driver (the §3 max-coverage formulation).

## 10. Open questions / non-goals

- **Inter-procedural value flow**: the static trace extractor is
  intra-TU. Cases like sqlite3 vtab handlers (handle arrives via
  library callback) are out of reach for static analysis alone — the
  LLM oracle is the intended catch.
- **C++ method-call traces**: `static_trace.py` does not yet propagate
  the `this`-pointer typestate across method calls.
- **Multi-version libraries**: persistence keys on `(project, source_sha)`;
  cross-version reuse is a non-goal — protocols drift between major
  versions and re-learning is cheap.
- **Beyond C/C++**: the PTA + EDSM machinery is language-agnostic;
  rebinding the extractor to Tree-sitter would unlock Rust / Go.
  Non-goal for current evaluation scope.
- **`ucl_object_unref` KILL not picked up**: L2 LifecycleAnalyzer
  naming-pattern miss; fix in L2.
- **Two grafted edge cases** in libucl smoke test produced acc=0
  results (graft picked the wrong creator for ambiguous handles like
  `int64_t`-returning extractors). Doesn't affect the canonical case;
  ranker drops them naturally.

## 11. Knowledge layer — Comprehender (PromeFuzz Tier-1 (A), shipped)

PromeFuzz (CCS'25) introduced a per-API "usage" knowledge layer fed to
the prototyper. We adopt the *idea* but reformulate it on top of our
existing static-analysis pipeline so the LLM cost drops by ~70×.

### 11.1 Why the reformulation

PromeFuzz default: `LibraryComprehension(purpose, functions: dict[api → usage_text])`.
One LLM call per API, RAG-fed; for 100–500 API libraries this is
50–200K tokens per project, **regardless of which APIs the driver
will actually use**. The wasted tokens are the entire point of attack.

LogicFuzz already has six "free" knowledge sources that PromeFuzz
doesn't have:

| Source | File | What PromeFuzz pays an LLM call for |
|--------|------|-------------------------------------|
| `existing_driver_knowledge.driver_sources` | `src/context/data_context.py` | Real OSS-Fuzz harness code — the *live* usage |
| `ConditionManager` (SOURCE/SINK/INIT/SETBY) | `liberator_adapter/constraints/ConditionManager.py` | API role tags |
| L2 `LifecycleAnalyzer` (init/destroy) | `liberator_adapter/constraints/lifecycle_analyzer.py` | Resource lifecycle |
| L3 `StateMachineAnalyzer` (pre/postcond) | `liberator_adapter/constraints/state_machine_analyzer.py` | Call preconditions |
| Header doxygen / `///` comments (libclang) | `liberator_adapter/extractors/hybrid_extractor.py` | Same source as PromeFuzz's RAG, more precise |
| Project-adaptive automaton acceptance | `liberator_adapter/analysis/project_automaton.py` | Sequence-level "actually used in this project" — PromeFuzz has no equivalent |

### 11.2 Four-layer token reduction (in production)

**Layer 1 — deterministic short-circuit (zero LLM)**: per-API,
fall through in order:
1. API appears in `existing_driver_knowledge` → extract ±5 lines around
   the call site + surrounding comments.
2. libclang has a doxygen / `///` comment on the API's header → use
   it (strip `*` prefix).
3. API has a `ConditionManager` role tag → templated synthesis from
   L2/L3 facts, e.g.
   `"[INIT] Resource constructor; pairs with {destroy_api}; preconditions: ..."`.

These three steps typically cover 60–80% of "important APIs" (the
ones that actually enter selected sequences).

**Layer 2 — on-demand + localised (the core optimisation)**: PromeFuzz
runs comprehend on the *raw* API space. We compress first, then
comprehend:

```
LogicFuzz:    [APICollection N=500]
                ├─L0 type DAG ──► [reachable API ~100]
                ├─L1 entry point ──► [~30]
                ├─L2 lifecycle ──► [~10 sequences]
                ├─L3 state machine ──► [~10 sequences]
                ├─L4 ranking ──► [Top-K=12 sequences]
                │                  └─ unique API ~60
                ▼
              comprehend ←─── only these ~60 ★
                │
                ▼
              prototyper (with usage context)
```

Insertion: `FuzzingContext.prepare()` step 5g (after `select_top_k_sequences`,
before prototyper).

### 11.3 Type-feasible ≠ semantically valid

L0–L3 are structural / typing constraints; they cannot answer "is this
sequence semantically meaningful". Counter-examples:
- `ucl_parser_new() → ucl_parser_get_object()`: type OK, lifecycle
  OK; but `add_chunk` is missing, so `get_object` returns NULL.
- `cJSON_Parse(s) → cJSON_GetArrayItem(obj, 0)`: type OK, but
  undefined behaviour if `obj` isn't an array.
- `parse_a → parse_a → parse_a`: types OK; semantically redundant.

The comprehender's true job is therefore redefined:

| Aspect | PromeFuzz | LogicFuzz |
|--------|-----------|-----------|
| Input | All N APIs in isolation | L0–L3-filtered K *candidate sequences* (5–7 APIs each) |
| Output | per-API description dict | per-sequence `(semantic_valid, repaired_seq, usage_with_invariants)` |
| Task | "what does this API do" | "is this *combination* semantically OK; do we need to insert/swap/reorder" |

### 11.4 Two-stage comprehender (production)

```
            L0–L3 filters
                │
                ▼
            ~10 candidate sequences
                │
                ▼
   ┌─────────────────────┐
   │  Comprehender-A     │   per-API usage (lightweight, parallel,
   │                     │   layer 1+2 short-circuit)
   └─────────┬───────────┘
             ▼
   ┌─────────────────────────────────┐
   │  Comprehender-B                 │   sequence-level semantic check
   │  in: sequence + per-API usage   │   + automaton.acceptance prefilter:
   │  out: {valid, fix_hints, ...}   │     acc=1.0 sequences skip LLM
   └─────────┬───────────────────────┘
             │
        ┌────┴─────┐
        ▼          ▼
   L4 ranking   sequence
   (with sem.   repair queue
    score)
        │
        ▼
   prototyper (sequences arrive semantically grounded)
```

**Comprehender-B output schema**:

```python
{
    "semantic_status": "INVALID" | "VALID" | "SUBOPTIMAL",
    "diagnosis": "get_object before any add_chunk → returns NULL",
    "repair": {
        "action": "INSERT" | "REORDER" | "REPLACE" | "DROP",
        "patched_sequence": ["ucl_parser_new", "ucl_parser_add_chunk", "ucl_parser_get_object"],
        "rationale": "..."
    },
    "invariants_for_prototyper": [
        "fuzzer data must be passed to add_chunk",
        "check parser->err.code before get_object"
    ]
}
```

### 11.5 Token budget (200-API library, ballpark)

| Approach | Calls | Tokens |
|----------|-------|-------:|
| PromeFuzz default | 1 (purpose) + 200 (excerpts) + 200 (usage) + ~9×200 (relevance) | **~120K** |
| Layer 2 only | 1 + 60 + 60 + 0 | ~25K |
| Layer 1+2+3 (batched, 10/call) | 1 + ~6 + 0 + 0 | **~5K** |
| Layer 1+2+3 + automaton-prefilter + cache hit | 1 + 0–2 + 0 + 0 | **~0.5K** |

**Core savings sources**:
- 500 API → 60 API → ~7 API per actual driver: ~70× reduction.
- automaton prefilter skips LLM entirely for acc=1.0 sequences: ~⅓ of
  Comprehender-B calls eliminated.
- Cache key `(project, api_name, sha256(api_source_slice))` makes
  re-runs free across same-version benchmarks.

### 11.6 PromeFuzz parts we do NOT port

- `ValuableExcerptsPrompter` ("is this RAG excerpt relevant"). Replaced
  with substring heuristic: if `func_name` appears in the excerpt, use
  it; otherwise skip.
- `FuncRelevanceComprehender`. We already have 4 relevance signals
  (type / lifecycle / state-machine / coverage-diversity) from
  Liberator static analysis.
- 24 of PromeFuzz's 27 prompts. Kept: `deduce_library_purpose`,
  `deduce_func_usage_from_src` (batched), optional `deduce_func_usage_from_doc`.

---

## 12. Knowledge layer — ConstraintLearner (PromeFuzz Tier-1 (B), design only)

PromeFuzz's crash-driven learner (`reference/promefuzz` `generator/learner.py`):
bucket crashes by ASan signature; when a signature accumulates ≥3 crashes, an
LLM call extracts a constraint and **appends it to
`comprehension.functions[api]`**, so subsequent generation reads usage already
augmented with the rule (knowledge persists). Not yet ported here.

It is the **natural-language counterpart** of the automaton's closed-loop
negative refinement (§9): both feed the same crash signal, but the
ConstraintLearner grounds the LLM fixer (prose constraint) while the automaton
grounds the L4 ranker (symbolic negative example). Both should eventually
coexist. PromeFuzz's Tier-2/3 scheduler machinery (complexity score, multi-axis
relevance, TempBanAPIs) is **not** ported — our L4 ranker + static-analysis
relevance signals already cover it.

---

## References

- Strom & Yemini, "Typestate", IEEE TSE 1986
- Lang/Pearlmutter/Price, "Results of the Abbadingo One DFA learning
  competition and a new evidence-driven state merging algorithm", 1998
- Khuller/Moss/Naor, "The budgeted maximum coverage problem", 1999
- Wang et al., "PromeFuzz" (CCS 2025) — knowledge-driven fuzzing,
  source of comprehender + ConstraintLearner. Upstream code reference:
  `/home/likaixuan/fuzzing/promefuzz_ref/` (out-of-tree).
- Rubick (USENIX Sec'23) — comparison baseline for consumer-mining
  automaton learning.
