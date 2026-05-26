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
| **G1 ✅ landed (2026-05-25)** `APISemanticModel` + reconciler (IR ⊕ doc/naming ⊕ usage), wired at Step 5g BEFORE construction; comprehender role-authority routed through it | Class I (P-gen-1/2/4/6) | ConditionManager demoted to one IR-evidence source (role authority moved to the model; CBFactory/RunningContext/L1–L3 still read it until G2) | **PASS** — lcms `cmsFreeToneCurveTriple` role = DESTROYER (was IR CREATOR); evidence log shows NAMING>IR. 47 IR-role overrides on lcms. `liberator_adapter/analysis/api_semantic_model.py`, tests in `tests/test_p1_api_semantic_model.py` (15). |
| **G2 ✅ landed (2026-05-25)** Model-driven sequence constructor (Step 5h: dependency-resolved creator→mutator*→consumer→destroyer chains, reachability-ranked) | Class II (P-gen-5/10/11) | random-walk grammar demoted to a **synthesizability floor** (constructed chains prepended, grammar guaranteed-retained, deduped) — `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1` for A/B | **PASS** — offline `tools/g2_viability/run.py`: lcms 1→**142** constructed, **100% ordering-fault-free by construction** on lcms/cjson/c-ares. **Live (gpt-5-mini, fresh prepare):** cjson 4 skeletons all `compiles:True` (~25% cov); lcms skeletons **1 (old) → 5 (G2)**. `liberator_adapter/analysis/sequence_constructor.py`, tests (10). **Live lessons (gpt-5-mini, fresh extraction):** (1) lifecycle-valid ≠ CBFactory-synthesizable — constructed chains can fail Z3 TYPE_MATCH/PROVENANCE/VARIABLE_AVAILABILITY (esp. lcms APIs with unbindable `void*` args), so we MERGE (not replace) with the L0-type-valid grammar floor; pure-replace regressed lcms to 0. (2) Raw `sample_accepting_paths` are NOT seeded as candidates (mid-stream fragments that fail lifecycle yet score acceptance≈1.0). (3) The model's `produces/requires` can diverge from raw `extract_api_effects` def/use on freshly-extracted accessors (lcms 142→109 after filter, was a 23% ordering-fault rate), so `construct_sequences` **self-filters through the shared `Typestate` oracle** (`project_apis` + `lifecycle_pairs`) → 100% ordering-clean by construction against the same walker CBFactory uses. |
| **G3 ✅ landed (2026-05-25)** Reachability ranker | Class III (P-gen-7) | **L5 novelty filter DELETED** (`coverage_aware_filter.py` removed) | ranking is now reachability-first: `automaton.acceptance_score` is the PRIMARY sort axis (diversity demoted to tiebreak) in `coverage_ranker.py`, and Step 5h ranks constructed candidates the same way. The proxy (diversity/novelty) no longer drives selection. Full coverage-correlation calibration needs a live fuzzing run. |
| **G4 ✅ landed (2026-05-25)** Semantic holes | Class IV (P-gen-8/9) | — | each skeleton carries per-arg **value intents** from the model (Step 10b): scalar config → in-range/out-of-range (P-gen-8), parser buffer → structured-input (P-gen-9), length-pairing, output, live-handle. Prototyper renders them into the hole-filling prompt. `liberator_adapter/analysis/hole_semantics.py`, tests `tests/test_p1_hole_semantics.py` (7). Coverage payoff measurable only via live fuzzing. |
| **G5 ✅ landed (2026-05-25)** Coverage-gap-directed generation | (NEW class V — valid≠novel) | — | the §10B finding: G1–G4 make drivers *valid* but they re-cover the baseline (cjson `line_diff=0`; lcms baseline `cms_gdb_fuzzer` touches only **5/297** APIs). G5 extracts **gap APIs** (baseline-uncovered) from the baseline textcov and directs construction + ranking *toward* them — the principled successor to deleted L5 (right target, positive signal not hard filter). `liberator_adapter/analysis/coverage_gap.py`, tests `tests/test_p1_coverage_gap.py` (5). **Offline PASS:** lcms construction reaches **236/292** gap APIs (was 0 gap-blind); Step 5h ranks gap-first then reachability. Coverage payoff pending live fuzzing. |

**Deletions done (2026-05-25):** Phase A repair engine (`candidate_repair.py`)
+ F1/F2/F4 wiring + its test removed — construction is lifecycle-complete by
construction (offline harness: 100% ordering-clean), so repair is dead code.
L5 (`coverage_aware_filter.py`) removed. Random-walk grammar is **retained as a
fallback only** (Step 5h replaces it as the primary source; kept for the
`LOGICFUZZ_DISABLE_G2_CONSTRUCT` A/B path and when construction yields nothing).

**Ordering rationale:** G1 first — it's the spine; G2/G3/G4 all assume the
model exists. Phase A repair was deleted on the strength of the offline
viability harness (100% ordering-clean construction) standing in for the
live "repair count → 0" gate, which is not runnable offline (the full LLM
pipeline is required; `--generate-drivers` bypasses `prepare()`).

---

## 6. Validation

Falsifiable, per phase, on the lcms / c-ares / cjson A/B harness:

- **G1 ✅**: emits `results/{project}/state/api_semantic_model.json`; the
  `cmsFreeToneCurveTriple` mislabel is fixed (DESTROYER, not CREATOR) and
  every role carries an auditable winner/loser evidence log. Step 5g logs the
  IR-override count (47 on lcms) — the band-aid surface G2 deletes; watch it
  trend down as construction takes over.
- **G2 ✅**: construction is ordering-fault-free by construction —
  `tools/g2_viability/run.py` validates every constructed sequence with the
  real `Typestate` checker and reports **100%** ordering-clean on lcms /
  cjson / c-ares (lcms 142 sequences vs the old path's 1 viable skeleton).
  Deterministic (no random walk → no run-to-run sampling noise). Remaining:
  confirm Phase A repair attempts → 0 on a live run, then delete it (the
  falsifiable check that construction is actually correct end-to-end).
- **G3 ✅ (structural)**: ranking is reachability-first
  (`acceptance_score` primary, diversity tiebreak) and L5 novelty is deleted.
  The proxy no longer drives selection. *Open:* rank-vs-coverage correlation
  must be confirmed > 0 on a live fuzzing run (offline we can't observe
  per-sequence coverage).
- **G4 ✅ (structural)**: every skeleton carries per-arg value intents
  (in-range/out-of-range for scalars, structured-input for parser buffers)
  and the Prototyper renders them. *Open:* the coverage payoff (more branch
  coverage in accessors/parsers, fewer front-gate rejections) is measurable
  only via live fuzzing.

Overall success: **lcms moves off 0** — ✅ at construction time (1 → 142
ordering-clean sequences). End-to-end coverage confirmation requires a live
LLM-pipeline + fuzzing run (the offline harness validates everything that
does not require executing the target).

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

## 8. Final design synthesis (思路) — 2026-05-25

The redesign started as *one* inversion (build a model, construct from it) but
the live runs forced a **second** inversion on top. The final generation-stage
design is the composition of both:

### Two inversions

1. **Correctness inversion (G1–G2): classify-then-repair → reconcile-then-construct.**
   Build one reconciled `APISemanticModel` up front (IR ⊕ doc/naming ⊕ usage),
   then *construct* dependency-resolved creator→mutator*→consumer→destroyer
   chains from it. Result: candidates are **valid by construction** (100%
   ordering-fault-free via the Typestate self-filter), so Z3 stops being a
   lifecycle gate and Phase-A repair becomes dead code (deleted). Verified live:
   lcms 1→5 compiling skeletons, no regression.

2. **Value inversion (G5): valid → novel.** The live §10B data exposed that a
   *valid* driver is worthless if it re-covers the baseline (cjson
   `line_diff=0`; lcms baseline covers **5/297** APIs). So generation must be
   **directed at the coverage gap** — the code the baseline misses. G5 extracts
   gap APIs from the baseline textcov and steers construction + ranking toward
   them (lcms: 236/292 gap APIs now reached, was 0).

### The pipeline, end to end

```
extract APIs
   │
   ▼  G1  reconcile IR⊕doc/naming⊕usage  ──►  APISemanticModel (role + arg semantics)
   │                                            (new role authority; ConditionManager demoted)
   ▼  G5  baseline textcov  ──►  gap APIs (what baseline never covers)
   │
   ▼  G2  construct creator→…→destroyer chains  ──►  lifecycle-complete sequences
   │       · gap APIs prioritized as targets (G5)
   │       · Typestate self-filter → 100% ordering-clean
   │       · MERGED with L0-type-valid grammar floor (synthesizability safety net)
   ▼  G3+G5  rank by (gap-hits, automaton-reachability)  ──►  top-K
   │
   ▼  Z3 CONFIRM (type / var / provenance only — lifecycle correct by construction)
   │
   ▼  G4  skeleton + per-arg value intents (in/out-of-range, structured-input)
   │
   ▼  Prototyper fills holes  ──►  driver  ──►  fuzz + coverage
```

### Three load-bearing lessons the live runs taught (don't re-learn them)

- **Lifecycle-valid ≠ CBFactory-synthesizable.** Constructed chains can pass the
  Typestate lifecycle oracle yet fail Z3 type/provenance/variable-binding (lcms
  APIs with unbindable `void*` args). ⇒ construction **merges with**, never
  *replaces*, the L0-type-valid grammar floor. Pure-replace regressed lcms 1→0.
- **The automaton is a ranking signal, not a candidate source.** Raw
  `sample_accepting_paths` are mid-stream trace fragments (consumer with no
  prior creator) that fail lifecycle yet score acceptance≈1.0 — seeding them as
  candidates poisons selection. Use `acceptance_score` to *rank*, not to
  *propose*.
- **Two kinds of coverage gap need two different levers.** Whole baseline-
  *uncovered APIs* (lcms: 98% of the surface) → **G5** API-level gap targeting.
  *Uncovered branches inside covered functions* (cjson: baseline already hits
  the public APIs, the gap is deep error/format paths) → **G4** structured
  input + in/out-of-range value intent. cjson won't move on G5 alone; lcms is
  where G5 pays off.

### What "done" means now

- Generation correctness: **done and verified** (valid-by-construction, no
  regression, more compiling drivers).
- Coverage value: **mechanism in place (G4+G5); live runs localized the true
  bottleneck below generation.**

### The bottleneck the live G5 run pinpointed (2026-05-25)

G5 works at the *sequence* level — on lcms it constructs sequences reaching
**239/297** baseline-uncovered APIs. But end-to-end it does **not** move lcms
coverage, and the live run shows exactly why:

- Step 5h ranks those 239 gap sequences first → Step 10 hands them to Z3 →
  **`z3_rejected=38`, all gap sequences fail** (`RunningContext has N unsat
  var(s)` — lcms APIs take `void*` contexts / opaque structs CBFactory cannot
  *materialize* an argument value for).
- Ranking gap-first ALONE then starved the few feasible candidates and
  emitted **0** skeletons (regression 5→0). Fixed with a **three-strand trial
  pool** — gap-first ⊕ acceptance-first ⊕ grammar floor — so feasible
  candidates are always tried; emission recovered to **4**, and the 4 emitted
  are `cmsCreateNULLProfile / cmsCreateXYZProfile / cmsCreate_sRGBProfile /
  cmsD50_XYZ` — all **gap APIs** (baseline covers none of them). So G5 *did*
  surface gap-targeting, synthesizable skeletons. (`10b 0/4` just means these
  particular APIs have no buffer/scalar holes for value-intent.)
- Yet total coverage stayed **~1%**: these are *shallow* gap APIs (profile
  constructors with fixed params — they execute only the ~80 lines of creation
  code). The *deep* gap APIs that hold lcms's bulk (`cmsDoTransform`,
  `cmsTransform2DeviceLink`, …) cover a lot but **fail Z3 binding** — they need
  a live profile handle PLUS unbindable non-handle args.

**Conclusion:** for complex libs the wall has two faces, both at the binding
layer, not sequence selection (G2/G3/G5 all succeed there):
1. *Shallow* gap APIs synthesize but cover little.
2. *Deep* gap APIs cover a lot but **CBFactory `RunningContext` can't
   synthesize values for their `void*`/opaque-struct non-handle params**, so
   they never become skeletons regardless of ranking.
The next investment is therefore *below* the generation redesign:

1. **Argument-value synthesis for opaque/`void*` params** (the binding layer)
   — make gap APIs synthesizable so G4/G5 actually apply to them. This is the
   single highest-leverage fix for lcms-class libraries.
2. **Format-aware input** (deepen G4) — for libs where the gap is deep
   *branches* inside already-bindable functions (cjson), not whole APIs.

Both are measurable only in the live fuzz loop, which is now wired and
working end-to-end (G1–G5 run live under gpt-5-mini with no crashes).

---

*This doc is the source of truth for generation-stage work. Update it as
phases land; do not re-litigate the inversion elsewhere.*
