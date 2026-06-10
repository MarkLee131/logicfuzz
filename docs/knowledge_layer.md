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

**Stage A** — per-API usage notes. **Stage B** — per-sequence semantic verdict:
the job L0–L3 structurally *can't* do ("is this combination meaningful?").
E.g. `ucl_parser_new → ucl_parser_get_object` is type- and lifecycle-OK but
returns NULL without an intervening `add_chunk`; `cJSON_Parse(s) →
cJSON_GetArrayItem(obj,0)` is type-OK but UB if `obj` isn't an array.

Both stages short-circuit through free deterministic sources **before** any
LLM call, per API, in order:

1. API appears in `existing_driver_knowledge` (real OSS-Fuzz harness code) →
   extract ±5 lines around the call site + surrounding comments.
2. libclang has a doxygen / `///` comment on the API's header → use it.
3. API has a `ConditionManager` role tag → templated synthesis from L2/L3
   facts (`"[INIT] constructor; pairs with {destroy}; preconditions: …"`).

These cover 60–80% of the APIs that actually enter selected sequences. The
comprehension also runs on the **compressed** set — L0→L4 reduce ~500 APIs to
the ~60 unique APIs across the Top-K sequences, so we comprehend ~60, not 500.
The automaton prefilter then skips the LLM entirely for `acc=1.0` sequences
(~⅓ of Stage-B calls); the residual is one *batched* call; the result is
cached (`(project, api, sha256(source_slice))` key) → free re-runs.

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
