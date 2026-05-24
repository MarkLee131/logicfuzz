# Generation-Stage Redesign — Root Cause + MVP Fix Plan

Status: **active design** (2026-05-23). This is the canonical plan for the
**driver-generation stage**. Scope excludes re-generation / feedback loops
(Phase C/G, crash learning) — those are deliberately out of scope until
generation is right.

Development context: **agile, MVP, no backward compatibility required.** We
delete and replace freely. 删繁就简 — fewer passes, one model, construction
over filtration.

---

## 0. The spine (one root cause)

Every generation-stage problem is a projection of a single inversion:

> **We classify APIs, generate sequences, and select candidates *before* we
> have built a reconciled semantic model of the APIs — then we correct the
> consequences downstream (Phase A repair, F1–F4, L5, reranks).**

The fix is to **invert the inversion**: build one **API Semantic Model**
up front by fusing all evidence sources, then *construct* sequences from it
and *select* on it. Downstream correction layers become dead code and are
deleted.

```
   today:   extract → classify(IR only) → random-walk seqs → filter ×5
            → Z3 → repair(Phase A/F1-F4) → rerank → skeleton
                              ▲ correct the model's absence downstream

   target:  extract → BUILD API SEMANTIC MODEL (IR ⊕ doc ⊕ usage)
            → construct seqs FROM model → rank by reachability
            → Z3 confirms (type/var only) → skeleton carries arg-semantics
                              ▲ model is right, nothing to repair
```

---

## 1. Root-cause diagnosis (4 classes, 11 problems)

### Class I — Characterization is single-source and downstream-corrected

The model that drives everything is built from IR alone; doc/usage knowledge
arrives later and can only patch.

- **P-gen-1** Role labels single-source (IR mod/ref). IR conflates *mechanism*
  with *intent*: `cmsFreeToneCurveTriple` allocates-then-frees internally →
  mod/ref sees DEF → labeled CREATE, though the doc says "Frees…".
- **P-gen-4** Arg semantics single-source (type + heuristic). Doc `@param data
  the input buffer / @param size length of data` is not fused → wrong
  entry-point detection and unconstrained hole values.
- **P-gen-6** Z3 lifecycle validation is sound but consumes IR-derived
  lifecycle pairs — a sound checker over an unsound model.
- **P-gen-2** Comprehender-A, idioms, automaton each compute a partial view and
  write separate artifacts; nothing reconciles them into the role/arg model.
- **P-gen-3** Phase A repair + F1–F4 are *symptoms* — they exist only to undo
  the wrong upstream labels.

Owner files today: `liberator_adapter/constraints/ConditionManager.py`,
`liberator_adapter/analysis/usedef.py`, `liberator_adapter/analysis/candidate_repair.py`.

### Class II — Candidates are generated-then-filtered, not constructed-from-model

- **P-gen-5** Step 4 grammar **random-walks** the type-compatible space before
  classification and before any semantic knowledge ("structure-naive random
  walk"). High-value sequences may never be sampled; budget burns on
  type-valid-but-meaningless sequences. (c-ares cache vs no-cache emit
  variance = sampling noise.)
- **P-gen-10** Comprehender-B's verdict + `patched_sequence` arrive *after*
  filtering → can only patch single candidates downstream (F4 wired it, 0
  success), never reshape the candidate set.
- **P-gen-11** `driver_size` is a global constant; correct length is a function
  of the sequence's semantic role.

Owner files today: `src/context/data_context.py` Step 4,
`liberator_adapter/constraints/coverage_ranker.py`, `src/knowledge/comprehender.py`.

### Class III — Selection optimizes proxies, not predicted reachability

- **P-gen-7** L4 ranks by type-diversity, L5 drops by novelty-vs-baseline —
  neither predicts coverage. A/B proof: F1–F4 raised emitted count (c-ares
  6→7) while total coverage **dropped** (412→81). The automaton's
  `acceptance_score` is computed but positive-only / uncalibrated / unused in
  selection.

Owner files today: `liberator_adapter/constraints/coverage_ranker.py`,
`liberator_adapter/constraints/coverage_aware_filter.py` (L5),
`liberator_adapter/analysis/project_automaton.py` (`acceptance_score`).

### Class IV — The skeleton under-constrains the LLM on values and input format

- **P-gen-8** Holes carry type but not semantic intent (an `int` index hole
  doesn't know "sometimes in-range to hit found, sometimes out-of-range to hit
  not-found"). Arg semantics (P-gen-4) are not attached to holes.
- **P-gen-9** The fuzz-input→arg mapping is unconstrained by format knowledge.
  Parser bytes must form a structure that survives front-gate validation to
  reach deep code; protocol/format knowledge exists but isn't compiled into a
  structured input decoder. (Root of lcms deep-path coldness; the "TLV-aware
  seed" TODO is this hole.)

Owner files today: `liberator_adapter/driver/synthesis/skeleton_generator.py`,
`src/agents/prototyper.py`.

### Mapping to the two tool goals

- **(a) Match baseline** blocked mainly by Class II + III — we can't construct
  or select the high-value sequences hand-written drivers use.
- **(b) Novel paths / bugs** blocked mainly by Class I + IV — wrong
  characterization zeroes out lcms-class libs; weak input constraint leaves
  deep error-handling code cold.

---

## 2. The fix — one upstream artifact: `APISemanticModel`

### 2.1 Data model

Built once, before sequence construction. Per-API reconciled record:

```python
@dataclass(frozen=True)
class ArgSemantics:
    index: int
    role: ArgRole          # INPUT_BUFFER | LENGTH | NULLABLE_HANDLE
                           # | OUTPUT | CONFIG | HANDLE_IN
    nullable: bool
    pairs_with: Optional[int] = None   # LENGTH pairs with which buffer index

@dataclass(frozen=True)
class APISemantics:
    name: str
    role: APIRole          # CREATOR | MUTATOR | CONSUMER | DESTROYER
    role_confidence: float
    args: Tuple[ArgSemantics, ...]
    produces: Optional[TypeId]     # what resource/handle it creates (CREATOR)
    requires: Tuple[TypeId, ...]   # preconditions: handles needed before call
    destroys: Optional[TypeId]     # what it frees (DESTROYER)
    evidence: Tuple[Evidence, ...] # provenance + conflict log (auditable)
```

`evidence` records *which source said what and who won* — so the model is
debuggable and the reconciliation is falsifiable.

### 2.2 Reconciliation principle (the first-principles core)

Each source is authoritative only for what it can actually witness:

| Question | Authoritative source | Supporting |
|----------|---------------------|-----------|
| Role / intent (creates? frees?) | **doc** (`@brief`, `@return`, verbs) + **usage** evidence | IR as tiebreak |
| Memory mechanism (what's read/written/allocated/freed) | **IR** mod/ref + use-def | — |
| Arg = buffer / length / output | **doc `@param`** + **usage** + type | IR for written-through pointers |
| Composition (A's output → B's input) | **usage** (tests, existing drivers, automaton paths) | type compatibility |

When IR and doc disagree on role, **doc wins for role, IR wins for
mechanism** — recorded in `evidence`. This single rule dissolves P-gen-1/4/6.

### 2.3 Reordered pipeline

```
extract APIs + signatures (Clang/LLVM)
        ↓
collect evidence in parallel (no ordering dependency between them):
    • IR mod/ref + use-def          (mechanism)
    • doc: doxygen @brief/@param/@return, README, man   (intent)
    • usage: tests / existing drivers / OSS-Fuzz         (composition)
        ↓
RECONCILE  → APISemanticModel              ← NEW, single artifact
        ↓
CONSTRUCT sequences from the model:
    creator(produces T) → mutator(T)* → consumer(T) → destroyer(T)
    seeded by automaton accepting paths + idiom chains
        ↓
RANK by reachability (calibrated automaton acceptance + novelty signal)
        ↓
Z3 CONFIRM (type-match + var-availability only — lifecycle is correct
            by construction, so Z3 stops being a lifecycle gate)
        ↓
SKELETON carrying ArgSemantics into every hole
        ↓
Prototyper fills holes (unchanged role: values only)
```

---

## 3. What gets DELETED (enabled by no-backward-compat)

删繁就简. These exist only to compensate for the missing model:

| Delete / collapse | Why |
|-------------------|-----|
| `analysis/candidate_repair.py` (Phase A) + **F1, F2, F4** | Repair is the symptom of wrong upstream labels. Correct model → nothing to repair. |
| Random-walk grammar sequence gen (Step 4) | Replaced by model-driven construction. Generate-then-filter → construct-valid. |
| L5 `coverage_aware_filter.py` (novelty pre-filter) | Proxy that suppresses total coverage; selection moves to reachability ranking. |
| ConditionManager as the **authority** for roles | Demoted to one IR-evidence source feeding the reconciler. |
| L1/L2/L3 as **separate sequential filters** | Their analyses (entry-point, lifecycle pairing, state) become *evidence into the model* / *construction rules*, not three re-derivation passes. |

What is **kept and folded in** (not deleted): IR use-def (mechanism evidence),
Comprehender-A (doc-intent evidence — moved BEFORE construction), idiom
distiller (usage evidence), project automaton (composition evidence + ranking
signal), Z3 (demoted to type/var confirmation).

F3 (single distillation pass) survives — it was a pure-efficiency fix,
orthogonal to the inversion.

---

## 4. What gets BUILT (minimal)

1. `APISemanticModel` + `reconcile()` — fuse IR ⊕ doc ⊕ usage (§2.1, §2.2).
2. Doc-evidence extractor — doxygen/README → per-API role/arg hints (the
   doc-intent source that today only exists as free-text Comprehender output;
   make it structured).

> **Token-budget invariant (non-negotiable for G1).** Knowledge extraction is
> **deterministic-first**; the LLM is a last-resort, *batched* tiebreaker, never
> a per-function call. PromeFuzz spends O(2N) LLM calls (per-function
> excerpt-select + usage-generate) + pairwise relevance + RAG embeddings — we do
> not. Our current comprehender already layers cache → deterministic (
> ConditionManager role + lifecycle) → doxygen → batched-LLM-residual; the last
> A/B run hit `LLM_calls=0` for comprehension. G1 must **keep** this and extend
> it to structured role/arg. Structured extraction is *more* deterministic than
> free-text (parsing `@brief Creates`/`@param data the input buffer` and naming
> `_new/_create/_destroy` and type patterns `const uint8_t* + size_t` needs no
> LLM), so done right G1 is **cheaper** than today, not dearer. Determinism
> sources for each field are tabulated below; the LLM only sees the residual
> where IR and doc *conflict* or both are silent, and those are batched into one
> call. The model is cached (`api_semantic_model.json`) → 0-token re-runs.

Deterministic sources per field (LLM only on the residual):

| Field | 0-token source |
|-------|----------------|
| role creator/destroyer | doxygen `@brief` verb (Creates/Frees/Init); naming `_new/_create/_destroy/_free/_init` |
| arg = input_buffer / length | type pattern `const uint8_t* + size_t`; doxygen `@param` text |
| arg = output | `void**` / `T** out` |
| arg = nullable_handle | IR + type `T* ctx` |
| mechanism (alloc/free) | IR mod/ref |
| composition (A→B) | automaton accepting paths + type match |
3. Model-driven sequence constructor — grow creator→…→destroyer chains from the
   model, seeded by automaton paths + idiom chains (replaces Step 4).
4. Reachability ranker — calibrate `acceptance_score` against observed
   coverage; rank candidates by it (replaces L4 diversity + L5 novelty).
5. Semantic holes — attach `ArgSemantics` to each hole; renderer emits the
   value-intent as a structured constraint for the LLM.

---

## 4b. Prior-art check — does PromeFuzz's code help? (verdict: barely)

Checked `reference/promefuzz` against G1–G4 (see `docs/logicfuzz_vs_promefuzz.md`).
Conclusion: **PromeFuzz offers almost nothing reusable for this redesign**, and
that confirms the direction is net-new rather than a reinvention.

- **Doc/usage extraction is free-text only.** `deduce_func_usage_from_{doc,src}`
  prompts ask for a ≤300-char usage string; output is `functions: dict[str,str]`.
  **No role (creator/destroyer), no arg semantics.** PromeFuzz has no analogue of
  the structured `APISemantics` G1 builds.
- **We already exceed it.** Our `src/knowledge/comprehender.py` has
  `_condition_role` + `_doc_derived_usage` + layered fallback (deterministic →
  doxygen → LLM); PromeFuzz has only the last (free-text) layer. G1 is therefore
  a *restructure* of what we already have — make it structured, fuse sources,
  move upstream — not a from-scratch build.
- **Relevance (type/scope/call) does not help G3.** It's symmetric function-pair
  similarity with no dataflow/composition; our automaton `acceptance_score` is
  the better reachability signal.
- **`consumer.py` OrderSet** (call-order from real consumer code, normalized to
  3–10 fns, Set-Cover-minimized) is the one piece adjacent to G2
  construct-from-usage — but our automaton `sample_accepting_paths` (PTA+EDSM) is
  a stronger version of the same idea. Don't port it; reuse the automaton.

PromeFuzz is *usage-first + reactive (learn-after-crash)*; this redesign is
*evidence-first + reconcile-up-front*. Opposite philosophies in the generation
stage. Do not re-investigate this — borrow the automaton, not PromeFuzz's
knowledge layer.

---

## 5. Sequenced fix plan (MVP phases)

Each phase is independently shippable and independently A/B-measurable.

| Phase | Fixes | Deletes | Ship test |
|-------|-------|---------|-----------|
| **G1** `APISemanticModel` + reconciler (IR ⊕ doc ⊕ usage), wired BEFORE construction | Class I (P-gen-1/2/4/6) | demote ConditionManager authority | lcms: `cmsFreeToneCurveTriple` role = DESTROYER, not CREATOR; evidence log shows doc>IR |
| **G2** Model-driven sequence constructor | Class II (P-gen-5/10/11) | random-walk grammar | sequences valid-by-construction; Phase A repair count → 0 (then delete it) |
| **G3** Reachability ranker | Class III (P-gen-7) | L5 novelty filter | selection correlates with coverage; "more emitted ≠ more coverage" inversion gone |
| **G4** Semantic holes | Class IV (P-gen-8/9) | — | hole carries in-range/out-of-range intent; structured input decoder for parsers |

**Ordering rationale:** G1 first — it's the spine; G2/G3/G4 all assume the
model exists. After G2, Phase A repair should report 0 repairs on all three
benches; that is the signal to delete it (don't delete before — keep it as the
falsifiable check that construction is actually correct).

---

## 6. Validation

Falsifiable, per phase, on the lcms / c-ares / cjson A/B harness:

- **G1**: emit an `api_semantic_model.json`; assert known mislabels are fixed
  (lcms free-functions not CREATOR). Manual spot-check evidence logs.
- **G2**: Phase A repair attempts → 0 (construction is correct). Candidate set
  no longer varies run-to-run from sampling noise (determinism).
- **G3**: rank-vs-coverage correlation > 0 (today it's ~0 or negative — the
  412→81 inversion). lcms total coverage ≥ pre-redesign.
- **G4**: branch coverage in accessor/parser functions increases vs G3;
  fewer fuzzer inputs rejected at the front gate (measure via early-return
  rate).

Overall success: **lcms moves off 0** (currently 1 skeleton, 0 coverage —
the canary that the whole inversion fails on complex libs).

---

## 7. Relationship to other docs

- `docs/system_design_status.md` — the 5-phase (A–E) roadmap predates this
  diagnosis. Phase A (repair) and the Tier-1 F1–F4 work are now **superseded**
  by G1/G2 (they're the band-aids this redesign deletes). That doc is being
  updated to defer to this one for the generation stage.
- `docs/phase_e_adaptive_shape.md` — Phase E (shape variety) is **downstream of
  G4**: shape variants only make sense once holes carry semantics. Keep, but
  sequence it after G1–G4.
- `docs/automaton.md`, `docs/logicfuzz_vs_promefuzz.md`,
  `docs/llm_vs_traditional_choices.md`, `docs/merge_drivers.md`,
  `docs/upstream_liberator_diffs.md` — unaffected (describe components that
  fold in or are orthogonal).

---

*This doc is the source of truth for generation-stage work. Update it as
phases land; do not re-litigate the inversion elsewhere.*
