# Knowledge Layer — Comprehender + Project-Adaptive Automaton

> **Status**: shipped. Two-stage, deterministic-first; last A/B comprehension
> run hit `LLM_calls=0`. Cached at `results/{project}/comprehension/`.

SSOT for **(1)** the per-project comprehender and **(2)** the project-adaptive
automaton it consumes. (Pitch vs PromeFuzz lives in
`docs/contributions_and_related_work.md`; pipeline integration in
`docs/generation.md`; the flag list in `CLAUDE.md`.)

The comprehender is LogicFuzz's per-project knowledge extraction. It is
adapted from PromeFuzz (CCS'25) but reformulated on top of our static-analysis
pipeline so LLM cost drops ~70×. It is tightly coupled to the **project-
adaptive automaton** (mechanics in the section below); the one fact the
comprehender depends on is that the automaton supplies `acceptance_score(seq)`,
used here as a positive-only LLM-skip prefilter. (The EDSM LLM oracle is wired
but throttled off — evidence-only merging is what ships.)

---

## Why reformulate PromeFuzz's knowledge layer

PromeFuzz feeds the prototyper a per-API "usage" layer: one LLM call per API,
RAG-fed → 50–200K tokens/project **regardless of which APIs the driver
actually uses**. That waste is the entire point of attack. We adopt the *idea*
(give the prototyper grounded usage knowledge) but compute it from sources we
already have for free, on the *compressed* API set, not the raw one.

## Two-stage, deterministic-first

**Stage A** — library purpose + per-API usage notes (`LibraryComprehension`;
`comprehend_purpose` + `comprehend_apis`). A sibling LLM call, `classify_roles`,
produces the role+arg-role classification the `APISemanticModel` folds in (the
role authority; see `docs/generation.md` G1). **Stage B** — per-sequence
semantic verdict: the job L0–L3 structurally *can't* do ("is this combination
meaningful?").
E.g. `ucl_parser_new → ucl_parser_get_object` is type- and lifecycle-OK but
returns NULL without an intervening `add_chunk`; `cJSON_Parse(s) →
cJSON_GetArrayItem(obj,0)` is type-OK but UB if `obj` isn't an array.

The per-API usage step (`Comprehender.comprehend_apis`) short-circuits through
free deterministic sources **before** any LLM call, per API, in this 4-layer
order (`src/knowledge/comprehender.py:599-657`):

1. **Layer 1 — cache hit.** API already in the on-disk `api_usage.json` →
   reuse (`KnowledgeCache.load_api_usages`).
2. **Layer 2 — deterministic synthesis from static IR facts**
   (`_deterministic_usage`): role + lifecycle pairing. The role authority is
   the reconciled `APISemanticModel` verdict (`api_roles`, CREATOR / MUTATOR /
   CONSUMER / DESTROYER → `_MODEL_ROLE_USAGE` text); `ConditionManager`'s
   IR-only SOURCE/SINK/INIT (`_condition_role`) is the demoted fallback when the
   model is unavailable. Appends the verified init↔destroy partner from L2
   lifecycle pairs (`_lifecycle_pair`).
3. **Layer 3 — doxygen-derived usage** (`_doc_derived_usage`, opt-in T1 prior
   via `--use-doxygen-priors`): a substantive libclang docstring
   (`src.knowledge.project_docs.extract_doxygen_comments`, ≥`_DOXYGEN_MIN_USEFUL_CHARS`
   = 40 chars) composed with the signature; short / vacuous docs fall through.
4. **Layer 4 — batched LLM fallback** (`_llm_fill_api_usages`) for the residual,
   signature + static-facts only, `API_BATCH_SIZE`=10 per call.

There is **no `existing_driver_knowledge` short-circuit and no ±5-line
call-site windowing** in the comprehender — the per-API method does not
reference `existing_driver_knowledge` at all. (Whole-harness driver sources are
built separately by `data_context._extract_existing_driver_knowledge` as full
`driver_sources` text and consumed by the **Prototyper / Fixer / idiom
distiller**, not by the comprehender.)

These layers cover most of the APIs that actually enter selected sequences. The
comprehension also runs on the **compressed** set — L0→L4 reduce ~500 APIs to
the ~60 unique APIs across the Top-K sequences (`unique_apis_in_sequences`), so
we comprehend ~60, not 500. For Stage B, the automaton prefilter then skips the
LLM entirely for `acc≥0.999` sequences (when the automaton is strong); the
residual is one LLM call per remaining sequence. Results are cached: per-API
usage keyed by **API name** (`api_usage.json`); per-sequence verdicts keyed by
`sha256("seq" + "|".join(seq))` (`KnowledgeCache.sequence_key`, in
`sequences.json`). Project scoping is via the cache directory
(`results/{project}/comprehension/`), not part of the key → free re-runs.

Combined: ~500 API → ~60 → ~7 per actual driver ≈ 70× reduction.

## Comprehender-B output

```python
{
  "semantic_status": "VALID" | "SUBOPTIMAL" | "INVALID",
  "diagnosis": "get_object before any add_chunk → returns NULL",
  "repair": {"action": "INSERT|REORDER|REPLACE|DROP", "patched_sequence": [...]},
  "invariants_for_prototyper": ["fuzzer data must reach add_chunk", ...],
}
```

Note: `repair` / `patched_sequence` is now a **downstream ranking/prompting
signal only**. Generation is valid-by-construction (see `docs/generation.md`),
so the verdict feeds selection and the prototyper prompt — it does **not** drive
a repair pass (the old Phase A / F1–F4 repair stage was deleted).

## Preflight smoke-fuzz as a Liberator seed oracle

A second deterministic knowledge signal lives in the merge path, not the
comprehender. Preflight smoke-fuzzes each generated driver for 15s and records
`edges_15s` — a driver that *produces seeds* in 15s is interacting with the
library, which is precisely Liberator's (FSE-2025) "positive" driver signal
(0-edge drivers are already dropped). That signal now **weights the merged-harness
CDF dispatch** (`run_single_fuzz._edges_weights_for` →
`SynthesizedDriver.from_paths(mode=CDF, weights=…)`) so high-interaction
sub-drivers earn a larger share of the fuzzer's per-input budget (was uniform
`selector % N`). It is a single-run signal; the full cross-round "driver history"
Liberator builds needs cross-round state and is not yet done.

## Project-Adaptive Automaton (mechanics)

Per-project typestate automaton learned from the library's own tests/examples
— the domain knowledge that *bottom-up type-walking cannot infer* and *generic
LLM priors do not carry*.

Pipeline (all in `liberator_adapter/analysis/`):
`extract_project_traces` → `extract_api_effects` → `build_pta` →
`edsm.merge` → `learn_project_automaton() → AutomatonArtifact`.
State vector = `frozenset[(handle_type, lifecycle_state)]`. EDSM merging is
*constructive*: every input trace stays accepted after every merge; an
oracle-vetoed merge is skipped, never weakened. Selection over the
automaton-augmented pool is budgeted max-coverage ((1−1/e) greedy).

`AutomatonArtifact` surface (consumers in parens):
- `acceptance_score(seq)` — L4 **primary** sort axis (G3; diversity demoted to tiebreak when an automaton is present), Comprehender-B positive-only prefilter, Phase H guard
- `sample_accepting_paths(n)` — L4 pool augmentation, Prototyper `<protocol_templates>`
- `graft_creator_prefix(seq)` — L4 candidate variants (Phase A repair, its other consumer, was deleted in G2)
- `post_parse_extensions(seq)` — extends `parse → get_object` prefixes via `extend_post_def`
- `update_with_traces(traces)` — Phase G incremental EDSM merge

Persistence: `results/{project}/automaton/`. Comprehender output:
`results/{project}/comprehension/`. Phase A/B/C/D state: `results/{project}/state/`.

### Closed-loop synthesis (Phase G)

Distinct from the proposed Phase C CEGAR loop (cross-iteration coverage
feedback; `generation.md` §6 F6). Phase G grows the automaton each round using
the current viable Z3 skeletons' API sequences as evidence (incremental EDSM
merge). Skeletons drive the LLM; closed-loop's value is the in-place mutation of
`automaton_artifact` preserved through `persist_dir`. Entry:
`src/closed_loop.py:run_closed_loop`, wired into `data_context.py` Step 11. CLI:
`--closed-loop`, `--closed-loop-iters N`, `--closed-loop-early-stop K`.

## What we do NOT port from PromeFuzz

- `ValuableExcerptsPrompter` ("is this RAG excerpt relevant") → replaced by a
  substring heuristic (func name appears in excerpt → use it).
- `FuncRelevanceComprehender` → we already have type / lifecycle / state /
  automaton relevance from static analysis.
- 24 of 27 prompts. Kept: `deduce_library_purpose`,
  `deduce_func_usage_from_src` (batched), optional `deduce_func_usage_from_doc`.
- The crash-driven **ConstraintLearner** (`generator/learner.py`) — the
  natural-language counterpart of the automaton's negative-refinement closed
  loop. **Not yet ported** (design-only).

---

## References

- Wang et al., "PromeFuzz", CCS 2025 — comprehender + ConstraintLearner source
- Strom & Yemini, "Typestate", IEEE TSE 1986
- Lang/Pearlmutter/Price, EDSM (Abbadingo One), 1998
