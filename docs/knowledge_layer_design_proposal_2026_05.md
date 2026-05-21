# Knowledge layer — design proposal (2026-05)

**Status:** proposal only. No code changes in this commit.
**Decision needed before implementation.**

This document is the design output of the 2026-05 cross-cutting
review of how LogicFuzz consumes project knowledge. It surveys
PromeFuzz's architecture for comparison, argues against a
hierarchical knowledge graph (a candidate that came up during the
review), and proposes a tiered migration plan starting from the
highest-ROI items.

---

## §1. What LogicFuzz consumes today

| Source | Where ingested | Consumer | Coverage |
|---|---|---|---|
| Project headers | Step 7 `public_headers.txt` (Clang extractor) | LFBackendDriver `#include`; Prototyper include hints | Full |
| Project source (in `consumer_paths`) | Step 5e2 libclang walk of `tests/ test/ examples/ samples/ unittests/ unit/ testbed/` | Automaton training (PTA → EDSM); L4 acceptance signal | Sequence-level only — Prototyper never sees the literal test code |
| Existing OSS-Fuzz fuzz drivers | Step 8 + 12 corpus walk filtered by `LLVMFuzzerTestOneInput` content | Prototyper `<reference_drivers>` (max 3); Fixer header/linker hints; LLM pattern analysis | Max 3 drivers; filename pattern misses tests |
| Project API signatures | Step 2 HybridAPIExtractor (Clang + LLVM) | Whole pipeline | Full |
| Per-API usage notes | Step 6b Comprehender-A (LLM, signature-only prompt) | Prototyper / Fixer / Improver | **LLM-invented, no priors** |
| Library purpose | Step 6b Comprehender purpose (LLM, project-name prompt) | Prototyper preamble | **LLM-invented** |
| OSS-Fuzz existing coverage | Step 5f L5 FuzzIntrospector | Coverage-aware novelty filter | Full |

**Highlighted: two of the most influential fields the LLM sees
(`library_purpose` and per-API `usage`) are fabricated by the LLM
from sparse priors.** Improving the *content* of these fields has
strictly more leverage than reorganizing the *structure* of what we
already have.

---

## §2. What we do NOT consume

| # | Missing source | Why it matters |
|---|---|---|
| **G1** | README / docs in project repo | Library README typically describes the canonical workflow in 1-3 paragraphs. Replaces LLM-from-project-name guess for `library_purpose` |
| **G2** | Doxygen `/** */` comments in headers | Per-API semantics (lifecycle, ownership, "caller must free with X") — highest-fidelity API documentation, currently fabricated by Comprehender |
| **G3** | Test files as literal reference code for Prototyper | Today tests feed only the automaton (abstract sequences). A 15-LOC `test_parse.c` is a richer anchor than the abstract sequence it produced |
| **G4** | OSS-Fuzz `build.sh` / `Dockerfile` flags | The exact `-I`, `-D`, link order that we know works. Fixer guesses these from build errors today |
| **G5** | OSS-Fuzz `*.dict` files | libFuzzer dictionaries with magic numbers / format tokens for corpus generation |
| **G6** | Existing-driver count cap | `_extract_existing_driver_knowledge(max_drivers=3)` — libxml2/openssl have 10+ existing fuzzers; we use 3 |

---

## §3. PromeFuzz architecture survey

PromeFuzz lives in `reference/promefuzz` branch. Despite reading
like a "knowledge graph" project, its design has **no single graph**
— it has 4 orthogonal data structures:

| PromeFuzz module | Shape | Purpose |
|---|---|---|
| `preprocessor/information.py` `InfoRepository` | **Flat directed graph** of `FunctionInfo` / `CompositeInfo` / `ClassInfo` / `TypedefInfo` nodes with reference edges | Index of all language objects; nodes know what they reference |
| `preprocessor/consumer.py` `CallGraph` | **Flat call graph** built from consumer cases (tests) | (a) Extract calling orders, (b) compute call-scope relevance via shortest path |
| `preprocessor/relevance.py` `{Type,ClassScope,CallScope}Relevance` | **Pairwise scoring matrices** | Rank which APIs to combine in a driver |
| `comprehender/knowledge.py` + `llm/rag.py` | **RAG vector index** (Chroma + Ollama/OpenAI embeddings) over README/doxygen/web URLs | Semantic retrieval for LLM-augmented comprehension |
| `generator/learner.py` | **Incremental crash-keyed log** | Repeated crash → LLM extracts constraint → adds to comprehension DB |

The module docstring of `InfoRepository` is explicit:

> "the `info` module is designed as a directed graph which stores
> all used objects and their reference relationships."

Not hierarchical. The reason becomes obvious once you look at the
relations PromeFuzz exploits: type compatibility, call order, scope,
semantic similarity, learned constraints — all fundamentally
peer-to-peer.

---

## §4. Why not a hierarchical knowledge graph

The hierarchical-KG idea came up as a candidate during the 2026-05
review. After examining what relations actually drive our pipeline,
we argue **against** it.

1. **Our load-bearing relations are not hierarchical.** Type
   compatibility, call order, lifecycle pairing, producer→consumer
   wiring, typestate transitions — all peer-to-peer. A hierarchy
   would encode them as cross-links anyway, defeating the structural
   advantage of a tree.

2. **We already have ≥5 graphs in the system.** `DependencyGraph`
   (type-flow), `PTA + EDSM` (typestate), `UseDefGraph`
   (USE/DEF/KILL), L2 lifecycle pairs, `APIEffect`. Stacking a
   hierarchy over them is a redundant index, not new information.

3. **Many APIs belong to multiple natural groups.** `cJSON_Parse`
   is both "parser" AND "memory-managing". `ucl_parser_add_chunk`
   is both "indirect entry point" AND "lifecycle-bound". Single-
   parent forces an arbitrary choice; multi-parent makes it a DAG
   → back to graph.

4. **PromeFuzz solved a similar problem without a hierarchy.** Their
   `InfoRepository` is explicitly a flat reference graph. The team
   considered the design space and didn't pick a hierarchy.

5. **The bottleneck is content quality, not structural cleverness.**
   Today our `library_purpose` and per-API `usage` are LLM-invented
   from project name and signature respectively. No structural
   reorganization helps that. Adding doxygen + README ingestion
   does.

**Conclusion:** flat typed graph (or even just typed dataclasses)
over multiple specialized indexes, mirroring PromeFuzz's choice.
Hierarchy is a lossy projection of the data we actually have.

---

## §5. Proposed design — flat `APIKnowledge` index over existing structures

Per-API typed record assembled from current and new sources. The
index **does not own data** — it points back to each source, so
updates flow naturally as the underlying structures change.

```python
@dataclass
class APIKnowledge:
    # Identity
    name: str
    signature: str

    # NEW — doc-derived (tier 1)
    docstring: Optional[str]            # doxygen via libclang cursor.brief_comment
    readme_mentions: List[str]          # excerpts from project README mentioning this API

    # NEW — code-derived (tier 2)
    test_examples: List[Path]           # 1-2 test files exercising this API

    # Existing — code-derived
    use_def_effect: APIEffect           # usedef.py USE/DEF/KILL summary
    typestate_states: Set[str]          # automaton observed_apis
    lifecycle_paired_with: List[str]    # L2 init/destroy partners
    callers_in_consumers: List[str]     # consumer call-graph (NEW or existing static_trace)

    # Existing — LLM-derived
    llm_usage_summary: Optional[str]    # Comprehender-A output (now augmented by doc/test)

@dataclass
class LibraryKnowledge:
    project_name: str
    purpose: str                        # NOW from README excerpt, not LLM-invented
    apis: Dict[str, APIKnowledge]
    # Pointers to live data, not copies:
    dependency_graph: Any               # ref to existing DependencyGraph
    automaton: Any                      # ref to AutomatonArtifact
```

**Properties of this design:**

- **Single query surface.** Prototyper / Fixer / Improver query
  `LibraryKnowledge.apis[name]` instead of reaching into 5 different
  subsystems (DependencyGraph, automaton, lifecycle pairs, usedef,
  comprehender).

- **Source attribution.** Each field knows where it came from.
  Debugging "why did the LLM hallucinate X?" becomes traceable
  ("`llm_usage_summary` was generated without `docstring` available
  for this API; doxygen extraction failed for header Y").

- **Phased population.** Tier 1 adds `docstring` + `readme_mentions`
  + `purpose` from README. Tier 2 adds `test_examples` +
  `callers_in_consumers`. Existing fields stay where they are.

- **No new structure invented.** This is an *index* over data we
  already produce or could produce trivially. Not a new graph.

---

## §6. Migration roadmap (ROI-ordered)

| Tier | Item | Source | Cost | Value | Trigger |
|---|---|---|---|---|---|
| **T1** | Doxygen comment extraction → `APIKnowledge.docstring` | libclang `cursor.brief_comment` / `cursor.raw_comment` — already in toolchain | Low | High: replaces LLM-from-signature fabrication for per-API usage | Always — lowest-effort wins |
| **T1** | README ingestion → `LibraryKnowledge.purpose` + per-API mentions | parse `src_ossfuzz/<proj>/README*` for the first non-boilerplate paragraph | Trivial | High: today's `purpose` is LLM-invented from project name | Always |
| **T2** | `APIKnowledge` / `LibraryKnowledge` index class | Assembly over existing sources + T1 outputs | Medium (~300 LOC) | Medium: cleaner query surface for agents; foundation for T3+ | After T1 lands and we have ≥2 sources to integrate |
| **T2** | Test files as Prototyper reference (G3) | Extend `_iter_driver_source_files` to keep test files (≥2 project APIs called) | Low | Medium: more reference patterns for libs with few existing fuzzers | After T2 index lands; surface via `APIKnowledge.test_examples` |
| **T2** | Raise `max_drivers` cap (G6) | Tune `_extract_existing_driver_knowledge`; sort by API diversity | Trivial | Low-medium: one-line; helps libs with 10+ fuzzers | Bundle with T2 |
| **T3** | RAG over project docs | Lightweight: chunk README + doxygen, embed via `sentence-transformers`; retrieve top-K per query. **Avoid** PromeFuzz's `langchain_chroma` + `OllamaEmbeddings` heavy stack | High (real vector-store infra) | Conditional: only earns its cost if doxygen + README turn out rich enough during T1 | After T1 reveals that doc content is actually substantial. Skip if most projects ship sparse doxygen |
| **T4** | Crash-driven constraint learner | Extend `crash_analyzer` to write back into `APIKnowledge.docstring` (or a new `learned_constraints` field) | High (needs dynamic baseline) | Conditional: helps only when crash patterns recur. Premature until dynamic-run baseline | After we have ≥10 trials of dynamic baseline data showing recurring crash classes |

---

## §7. What NOT to migrate from PromeFuzz

| Item | Why skip |
|---|---|
| Full RAG stack (`langchain_chroma`, `OllamaEmbeddings`, `OpenAIEmbeddings`) | Heavy deps, slow setup, embedding-model choice has long lead time. T1 may obviate the need entirely |
| Pickle serialization for comprehension DB | We use JSON consistently; mixing pickle introduces forward-compat issues across Python versions |
| 5-subclass `Prompter` hierarchy (`LibPurposePrompter`, `FuncUsageFromDocPrompter`, etc.) + 3-tier `Comprehender` ABC | Overengineered for our 2-stage A/B comprehender. The current shape is cleaner and already extends via dataclasses |
| Pairwise `Relevance` matrices (TypeRelevance / ClassScopeRelevance / CallScopeRelevance) | We already have L4 coverage + acceptance score + sample_paths + L2 lifecycle pairing. Adding pairwise scores is redundant unless we observe a specific ranking failure they'd fix |
| `Incidentals` (transitive caller-callee closure: "A calls B internally, any A-call counts as B-call") | Conceptually clean but we have direct call edges already via static_trace. Transitive closure would add noise without clear ranking gain |
| The Knowledge class's URL-document ingestion (`WebBaseLoader`) | We operate on the OSS-Fuzz project's source repo — there's no upstream URL we'd add beyond what's already in the repo |

---

## §8. Non-goals

- **Hierarchical taxonomy of APIs.** Argued against in §4.
- **Project-specific schema overrides.** Some projects classify
  their own APIs differently (e.g. cJSON internally distinguishes
  "creators / accessors / mutators"). The knowledge layer
  *exposes* these via `APIKnowledge` but doesn't *enforce* a global
  taxonomy.
- **Knowledge-driven L4 ranking changes.** The ranker stays
  coverage-driven (greedy max-coverage). Knowledge is an LLM-prompt
  input, not a ranking criterion.
- **Replacing the Comprehender.** The Comprehender stays as the
  LLM-augmentation layer. T1+T2 give it better priors; it still
  generates the final per-API summary string the Prototyper
  consumes.

---

## §9. Decision triggers for tier escalation

| From | To | Trigger |
|---|---|---|
| nothing | T1 | Always — lowest-effort, highest-content win. Implement after dynamic-run baseline confirms the rest of the pipeline is stable |
| T1 | T2 (index) | After T1: if Prototyper / Fixer / Improver logs show ≥2 distinct subsystem reads per agent invocation for the same API, build the typed index |
| T2 | T2 (test files) | After T2 index: if Prototyper trial-diversity is still low, add test files as reference |
| T2 | T3 (RAG) | After T1+T2: if measured doxygen + README content covers <50% of APIs, OR if Comprehender-A still shows >20% hallucination rate on per-API usage, build RAG. Otherwise skip — RAG is heavy infrastructure for diminishing returns |
| T3 | T4 (learner) | After dynamic baseline accumulates ≥10 trials with crashes: if ≥2 crash classes recur >3× across trials, implement the learner |

---

## §10. Effort estimates and staged rollout

These estimates assume one developer working full-time on this, with
my-style implementation (defensive contracts, explicit failures,
unit tests on a few benchmarks before full validation). Numbers are
deliberately on the realistic side; double them for first-time
infrastructure work.

### Per-component effort

| Tier | Component | Coding | Testing | Calendar |
|---|---|---|---|---|
| T1 | Doxygen extraction (libclang `cursor.raw_comment`, hook into HybridAPIExtractor, prompt integration) | 1.5-2 days | 1 day | ~3 days |
| T1 | README ingestion (locate `README*`, strip markdown, extract purpose paragraph, prompt integration) | 0.5-1 day | 0.5 day | ~1.5 days |
| **T1 total** | | | | **~1 week** |
| T2 | `APIKnowledge` / `LibraryKnowledge` index (dataclass, assembly from 6 existing sources, cache file, FuzzingContext wiring) | 3-4 days | 1 day | ~5 days |
| T2 | Test files as Prototyper reference (extend `_iter_driver_source_files`, ≥2-API filter, new prompt section) | 1-2 days | 0.5 day | ~2 days |
| T2 | Raise driver cap + diversity sort | 0.5 day | — | ~0.5 day |
| **T2 total** | | | | **~1.5 weeks** |
| T3 | Lightweight RAG (`sentence-transformers` + numpy/FAISS, **NOT** langchain stack) | 1.5-2 weeks | 0.5-1 week (chunking + top-K tuning) | **~2-3 weeks** |
| T4 | Crash-driven learner (dedup, LLM extraction, storage, feedback loop, validation) | 2-3 weeks | 1-2 weeks | **~3-5 weeks** plus 1-2 weeks waiting for crash data |

### Calendar — solo, realistic

| Scope | Total |
|---|---|
| T1 only | ~2 weeks (1 week coding + 1 week validation) |
| T1 + T2 | ~5 weeks (3 weeks coding + 2 weeks validation overlap) |
| T1 + T2 + T3 (if T1 justifies it) | ~10 weeks |
| All four tiers | **~13-16 weeks (3-4 months)** |

### Risk factors that can blow the estimate

1. **Doxygen quality is project-dependent.** zlib / libxml2 have
   rich docs; libucl / ffjpeg have almost none. If T1 shows <50%
   API doc coverage on our benchmark set, T3 (RAG) becomes
   mandatory rather than conditional. Adds 2-3 unbudgeted weeks.
2. **README format heterogeneity.** Some libraries have 50-line
   READMEs, others 5000-line build/install guides where the
   purpose paragraph is buried. Robust extraction is harder than
   it sounds.
3. **Prompt regression risk.** Adding priors to the Comprehender
   prompt may cause the LLM to over-trust incomplete docs and miss
   real semantic info. T1 needs strict A/B against baseline before
   defaults flip on.
4. **Cache invalidation.** Per-source caching is necessary
   (re-extracting doxygen every run is wasteful). Invalidation
   rules must be designed per source — easy to get wrong.
5. **Empirical validation is the bottleneck, not coding.** A full
   24h × 17-benchmark run is ~17 GPU-days sequential or ~1 week
   parallelized. Three validation cycles eats 3-4 weeks of calendar
   regardless of coding speed.

### Recommended staged rollout

Do **not** commit to the full plan upfront. Ship in milestones,
decide at each gate.

| Milestone | Scope | When |
|---|---|---|
| **M1** | Run current dynamic baseline on 3-4 benchmarks (cjson + c-ares + libucl + libxml2). Populate §3 validation sections across the 14 existing refactor docs. No code changes — just empirical baseline. | ~1 week |
| **M2** | Ship T1 behind `--use-doxygen-priors` and `--use-readme-purpose` flags (both OFF by default). A/B vs M1 baseline on the same 4 benchmarks. Decide: flip defaults ON, keep opt-in, or revert. | ~2-3 weeks after M1 |
| **M3** | Based on M2 signal — three branches: (a) T1 helped and Prototyper/Fixer logs show ≥2 subsystem reads per agent → ship T2 (index + test files + driver cap). (b) T1 doxygen turned out sparse on a majority of benchmarks → skip T2, build T3 (lightweight RAG). (c) T1 saturated the gains → stop here, defer T2-T4 indefinitely. | ~4-6 weeks after M2 |
| **M4 (conditional)** | T4 learner. Only after dynamic baseline accumulates ≥10 trials with crashes AND ≥2 crash classes recur >3× across trials. | post-M3 territory |

**Realistic calendar to the M3 decision gate: ~7-10 weeks.**

If M3 ends in branch (c) — stop — the total effort is ~5-6 weeks
for a measurable content-quality improvement that closes the
"library purpose + per-API usage is LLM-invented" gap.

If M3 ends in branch (a) or (b), expect another 4-6 weeks to a full
T1+T2 or T1+T3 architecture, on top of the M1+M2 4 weeks. Plan for
**~3 months calendar** in those branches.

T4 sits firmly in the "wait until we have data" bucket and should
not be budgeted in any plan tighter than 6 months.

---

## §10B. Emergency-mode on baseline regression (v1 LANDED 2026-05-12; v2 LANDED 2026-05-12)

User observation (2026-05-12, post cjson/c-ares/lcms runs):

> 如果遇到对项目的driver，coverage甚至不如现有driver，我们需要开启紧急
> 提升模式去思考为啥。 这意味着，我们可能丢弃了很重要的上下文信息

**Principle**: the project's existing OSS-Fuzz driver is the gold
standard — hand-written by library experts who know the project's
real entry points, formats, and required state setup. When LogicFuzz's
generated driver covers **less** than that baseline, the gap is not
acceptable as "we're doing different work"; it means we **dropped
context** the existing driver had.

Empirical motivation (preliminary):

  - c-ares trial 01: 11.17% PC iter1, 8.07% PC iter2, **line_diff=2.01%**
    (only 2% new coverage relative to baseline). Most coverage is just
    re-covering what the existing fuzzer already does.
  - lcms trial 01: 0.99% PC. Existing lcms fuzzer covers much more.
    Our driver is exploring a tiny corner.
  - cjson trial 01 (run4): 25.76% PC, **line_diff=0.00%**. We re-covered
    only what the existing fuzzer covers — added nothing new.

The current workflow has **no automatic alarm** when this happens. We
silently report "successful" trials that contributed zero new
coverage.

### v1 (LANDED 2026-05-12)

Detection + alert only:

  - `execution_node` computes `line_coverage_diff` (already had this).
    When `baseline_textcov` is non-empty AND `line_coverage_diff <
    0.005` (0.5%), it sets the new state field
    `baseline_regression_alert` with `{reason, line_diff, threshold,
    coverage_percent, baseline_compared, trial, iteration}`.
  - A clear warning is logged with the 🚨 prefix so operators can
    grep trial logs for the alert.
  - State surfaces the alert through to `StateAdapter.state_to_result_history`
    so per-trial summaries include it.

Threshold rationale: across cjson run4/run5, c-ares run1/run2, lcms
run1 — 4 of 5 had `line_diff` at or below 0.5%. The threshold
catches the dominant failure mode without over-firing on rare
high-novelty trials.

### v2 (LANDED 2026-05-12)

Closes the loop from "alert → operator-visibility" to "alert →
auto-recover". Implementation:

  - **`LangGraphBaselineDiffAnalyzer`** (`src/agents/baseline_diff_analyzer.py`):
    stateless single-LLM-call agent. Inputs: our driver source, the
    baseline driver source (from `existing_driver_knowledge.driver_sources[0]`),
    the regression-alert payload, and the project API list.
    Outputs structured XML tags:
      - `<missing_apis>` — APIs in baseline absent from ours
      - `<missing_patterns>` — structural patterns dropped
      - `<input_encoding_gaps>` — how baseline derives input from
        `data, size` vs how we do
      - `<suggested_constraints>` — actionable, library-specific
        imperatives for the re-prototype
      - `<verdict>` — `recover | baseline_too_narrow | inconclusive`
    Verdict gates the directive level in the recovery prompt; the
    baseline is allowed to be the wrong target.

  - **Supervisor wiring** (`src/workflow/nodes/supervisor.py`):
    `_handle_coverage_improvement` consults `baseline_regression_alert`
    BEFORE the standard `coverage_analyzer → improver → END` path.
    If alert is set, the project has an OSS-Fuzz baseline, AND
    `baseline_diff_retry_count < MAX_BASELINE_DIFF_RETRIES` (=1):
      1. First pass: route to `baseline_diff_analyzer`. Agent writes
         `baseline_diff_analysis` and returns to supervisor.
      2. Second pass: supervisor sees the diff is present and routes
         to `prototyper`, simultaneously incrementing
         `baseline_diff_retry_count`. The counter lives in the
         routing layer, not the analyzer agent, so the budget is
         single-source-of-truth.
    On the third loop (after the regenerated driver builds+runs
    again), if the alert STILL fires, retry_count is now 1 so the
    branch falls through to the normal coverage_analyzer/improver
    path. Hard ceiling: one diff loop per trial.

  - **Prototyper consumption** (`src/agents/prototyper.py`):
    `_format_baseline_recovery` renders the analyzer's output as a
    `<baseline_regression_recovery>` block. The block sits FIRST
    inside `<reference_information>` so it visibly dominates the
    same priors that produced the regression. Empty string when
    `baseline_diff_analysis` is absent — preserves the unchanged
    first-pass generation path.

**State surface**:
  - `baseline_diff_analysis: Dict` — analyzer output (see above)
  - `baseline_diff_retry_count: int` — capped at 1 per trial

**Rationale for routing the recovery via Prototyper, not Improver**:
the improver tweaks the existing driver locally; the alert says
the local minimum is bad, so a global re-prototype is the
higher-value first move. The Improver remains in the workflow but
runs only if the diff-recovery exhausts its budget and coverage
still hasn't improved.

**Why this is worth doing**:

  - It's the natural empirical floor — we should never *regress* vs
    what the library author shipped.
  - The signal is cheap to compute (we already have baseline cov).
  - The recovery loop reuses existing machinery (Prototyper) with
    one new analyzer node.

### Empirical validation (2026-05-21 v2 A/B run)

3-bench run (cjson + c-ares + lcms), v2 enabled, single trial each,
2-iteration cap. `--multihop-prototyper`, `--use-doxygen-priors`,
`--use-readme-purpose`. Baseline-driver corpus extracted via
`data_prep/extract_all_fuzz_drivers.py` (cjson 2, c-ares 3, lcms 15).

| Project | iter1 PC | line_diff | alert? | verdict | iter2 PC | line_diff | net Δ |
|---------|----------|-----------|--------|---------|----------|-----------|-------|
| cjson   | 25.76%   | 0.00%     | ✅     | recover           | 24.12% | 0.00% | −1.64% PC |
| c-ares  |  8.63%   | 0.09%     | ✅     | recover           |  8.37% | 0.13% | −0.26% PC / **+0.04% line_diff** |
| lcms    |  0.97%   | 0.00%     | ✅     | baseline_too_narrow |  0.97% | 0.00% | 0 |

**What works as designed.** Mechanism fires end-to-end on every alert:
execution → supervisor (§10B v2 routing) → BaselineDiffAnalyzer (verdict
extracted) → prototyper regeneration → re-execution. Retry counter caps
at 1/1 — second alert in the same trial falls through to coverage_analyzer
(see `logs/ab_2026_05_21_v2/{cjson,c-ares,lcms}.log`).

Verdict distribution: 2× recover, 1× baseline_too_narrow. The
baseline_too_narrow on lcms is *correct* — the lcms baseline is the
union of 15 hand-written fuzzers covering different lcms entry points
(`cms_cgats`, `cms_devicelink`, `cms_md5`, `cms_postscript`,
`cms_transform_*`…) at 63.67% line coverage; our single auto-generated
driver caught one entry point at 1.77%. No single-driver regeneration
can close that gap; this needs `--merge-drivers` and multiple trials.

**What didn't.** PC coverage *fell* on cjson (−1.64%) and c-ares
(−0.26%) after recovery. Two factors:

1. The BaselineDiffAnalyzer's `verdict=recover` is over-confident.
   On cjson we already match baseline within 1.03% line coverage
   (998/2321 = 43.00% vs 1022/2321 = 44.03%); the analyzer should
   have output `baseline_too_narrow` like it did for lcms but
   instead suggested regeneration that lost lines.
2. The regenerated driver doesn't reuse the structural pieces of the
   prior driver that were already paying off — the recovery prompt
   adds *new* suggestions but the prototyper still starts from the
   skeleton, not from the prior trial's source.

c-ares is the one mild positive: `line_diff` ticked up 0.09 → 0.13%
(novel lines beyond baseline), even though PC dipped. So the recovery
*did* steer the driver toward un-baseline-covered code, just not enough
to dominate the regression of the dropped lines.

**Comparison to baseline driver coverage (line-level, OSS-Fuzz bucket):**

| Project | Our line cov | Baseline line cov | Gap |
|---------|-------------|-------------------|-----|
| cjson   | 998/2321 = 43.00%   | 1022/2321 = 44.03%  | −1.03% (parity) |
| c-ares  | 1959/17916 = 10.93% | 7019/18076 = 38.83% | −27.90% |
| lcms    | 302/17100 = 1.77%   | 13139/20636 = 63.67% | −61.90% |

The two large gaps are **single-driver vs N-driver-union** by
construction — the OSS-Fuzz baseline numbers are unions of all
hand-written fuzzers, not a single-driver benchmark.

**Open follow-ups (not blockers for shipping v2):**

- Tighten BaselineDiffAnalyzer's verdict cutoff so `recover` only
  fires when there's genuine missing structural context, not when
  we're already at parity with baseline (cjson case).
- Pass the prior trial's source into the diff-aware regeneration
  prompt so the prototyper *extends* the working driver instead of
  rebuilding from scratch.
- Re-test §10B v2 under `--merge-drivers` so multi-driver runs (lcms)
  can actually exercise the recovery — current single-driver harness
  caps coverage at one entry point regardless of v2 behaviour.

Tracked alongside §10A operator-doc-prep — both are knowledge-
augmentation directions for the case where T1's automatic
extraction is insufficient.

---

## §10A. Future direction — operator-prepared documentation pages (2026-05 followup)

User note (2026-05-11, after first dynamic run): the tool can be
augmented further by **operator-curated documentation pages** rather
than relying solely on whatever README / doxygen the upstream
project ships. The workflow shape:

  1. Operator hand-prepares 1-3 page bundles per target library
     covering: library purpose, primary parser entry point(s), key
     ownership rules, typical usage example. Format TBD —
     markdown most likely; could include extracted-and-curated
     doxygen too.
  2. Tool ingests these as a **higher-priority prior** than raw
     README / doxygen (which are currently T1's sources).
  3. Comprehender's per-API usage layering becomes:
     cache → deterministic → **operator-doc** → doxygen → README →
     LLM-from-signature.

Trade-offs vs T3 (RAG):
  - **Pro**: operator already understands the library; the
    extracted content is by-design fuzz-driver-relevant, not
    incidentally so. T3 RAG retrieves *whatever the docs say*,
    which may or may not be useful.
  - **Pro**: lower runtime cost (no embedding, no vector store).
  - **Con**: human curation per benchmark doesn't scale. T1
    auto-extraction works on 100 benchmarks; this requires
    1-2 hours of operator time per benchmark.
  - **Con**: introduces a "preparation step" before the tool
    runs, breaking the current zero-touch "run on a yaml" UX.

**Decision deferred until after c-ares analysis** (the doc-sparse
counterpoint to cjson). If c-ares shows that T1's README + doxygen
priors are insufficient on a sparse-doc benchmark, this becomes
the next investment. If T1 works fine on c-ares too, operator-doc
preparation is overkill.

Tracking: implement after the c-ares + libucl A/B completes (per
§10 M3 plan).

---

## §11. Rollback / kill-switch

This is a proposal; nothing is implemented yet. If T1 ships and
turns out to add noise rather than signal:

- Doxygen extraction: gate behind a `--use-doxygen-priors` CLI flag
  defaulting OFF. Comprehender-A continues to invent usage from
  signatures as today.
- README ingestion: same gate via `--use-readme-purpose` defaulting
  OFF. `library_purpose` falls back to the current LLM-from-project-
  name path.

Both should be opt-in for the first 17-benchmark validation run.
After empirical results, the defaults flip on (or the feature is
removed).

---

## §12. Why this proposal stops here

We deliberately **do not** propose:

- Schema for a knowledge cache file (defer until T2 lands and we
  see what fields are actually queried)
- Embedding model choice (defer to T3 trigger)
- Prompt-engineering details for doc-augmented Comprehender (defer
  to T1 implementation)
- Multi-language knowledge merging (we are C/C++ only today; revisit
  if/when Java/Go/Rust support is on the roadmap)

These are tier-implementation decisions, not architecture decisions.
The architecture commitment here is: **flat typed index over multiple
specialized data structures, populated from doc/test/code sources,
queried by agents via a single per-API surface.**
