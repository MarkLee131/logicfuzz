# Driver-Generation Stage

Source of truth for how LogicFuzz turns an extracted API set into
Z3-validated skeleton drivers. The pipeline below is **built and live**
(G1–G5 landed 2026-05); this doc describes the architecture as it stands
and the open work below it. Surrounding (non-generation) subsystems —
automaton, merge, knowledge layer — have their own docs.

> History: this stage was a "classify-then-repair" flow (Phase A repair +
> Tier-1 F1–F4) that band-aided a missing API semantic model downstream.
> It was replaced by reconcile-then-construct. The diagnosis, the deleted
> layers (Phase A `candidate_repair.py`, L5 `coverage_aware_filter.py`,
> F1/F2/F4), and the MVP phase plan live in git history
> (`git log --grep="redesign"` / `--grep="G2"`).

---

## The pipeline

```
extract APIs
   │
   ▼  G1  reconcile IR⊕doc/naming⊕usage  ──►  APISemanticModel (role + arg semantics)
   │                                            (role authority; ConditionManager demoted)
   ▼  G5  baseline textcov  ──►  gap APIs (what the baseline never covers)
   │
   ▼  G2  construct creator→mutator*→consumer→destroyer chains  ──►  lifecycle-complete seqs
   │       · gap APIs prioritized as targets (G5)
   │       · Typestate self-filter → 100% ordering-clean by construction
   │       · MERGED with the L0-type-valid grammar floor (synthesizability safety net)
   ▼  G3+G5  rank by (gap-hits, automaton-reachability)  ──►  top-K
   │
   ▼  Z3 CONFIRM (type / var / provenance only — lifecycle correct by construction)
   │
   ▼  G4  skeleton + per-arg value intents (in/out-of-range, structured-input)
   │
   ▼  Prototyper fills holes  ──►  driver  ──►  fuzz + coverage
```

The spine is **build one reconciled model up front, then *construct*
sequences from it** instead of generating-then-filtering. Candidates are
valid by construction, so Z3 is a type/var confirmer, not a lifecycle gate,
and there is no repair stage.

### G1 — `APISemanticModel` (`analysis/api_semantic_model.py`)

`reconcile()` fuses three evidence sources into one per-API verdict before
any sequence is proposed, deterministically (0 LLM):

| Question | Authoritative source | Supporting |
|----------|---------------------|-----------|
| Role / intent (creates? frees?) | doc verbs (`@brief`/`@return`) + naming (`_new`/`_free`) + usage | IR tiebreak |
| Memory mechanism (alloc/free/read/write) | IR mod/ref + use-def | — |
| Arg = buffer / length / output | type pattern (`const uint8_t* + size_t`) + `@param` + usage | IR for write-through ptrs |
| Composition (A's output → B's input) | automaton accepting paths | type match |

Rule: when IR and doc disagree on role, **doc wins for role, IR wins for
mechanism** — recorded in a per-API `evidence` log (auditable). This is the
role authority (demoting the heuristic `ConditionManager` to one IR-evidence
source). A typedef-handle recovery pass (`analysis/handle_typedef_recovery.py`)
restores opaque-handle identity the compiler IR collapses to `void*`/`i8*`
(re-typing back to `cmsHPROFILE` / `cmsHTRANSFORM` from public headers) so the
dependency graph is connected where a naive IR graph is empty and specific
where a void*-graph would over-connect. Built at Step 5g; writes
`state/api_semantic_model.json` (cached → 0-token re-runs).

### G2 — sequence constructor (`analysis/sequence_constructor.py`)

`construct_sequences(model)` grows dependency-resolved
creator→mutator*→consumer→destroyer chains, preferring the creator that
*ingests fuzzer bytes* (e.g. `cmsOpenProfileFromMem` over a synthetic
constructor) so input reaches real depth. Chains **self-filter through the
shared `Typestate` oracle** (same walker CBFactory uses) → ordering-clean by
construction. Step 5h **prepends** them to the L0–L4 grammar candidates and
**merges**, not replaces — the grammar floor is a guaranteed CBFactory-
synthesizability safety net. A/B via `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1`.

### G3 — reachability ranker (`constraints/coverage_ranker.py`)

`automaton.acceptance_score` is the **primary** sort axis (diversity demoted
to tiebreak); the L5 novelty pre-filter was deleted. Step 5h ranks constructed
candidates the same way.

### G4 — hole semantics (`analysis/hole_semantics.py`)

`annotate_skeletons(skeletons, model)` attaches per-arg **value intents** at
Step 10b: scalar config → in/out-of-range, parser buffer → structured-input,
length-pairing, output, live-handle. The Prototyper renders them into the
hole-filling prompt. Deterministic.

### G5 — coverage-gap targeting (`analysis/coverage_gap.py`)

`compute_gap_apis(...)` reads the OSS-Fuzz baseline textcov → APIs the
baseline never covers (lcms: 292/297). Step 5h directs construction (gap APIs
as targets) and ranking (gap-hits primary) **toward** the gap, so drivers add
new lines instead of re-covering the baseline. A three-strand trial pool —
gap-first ⊕ acceptance-first ⊕ grammar floor — keeps feasible candidates from
being starved by gap-first ranking.

---

## Three load-bearing lessons (don't re-learn them)

- **Lifecycle-valid ≠ CBFactory-synthesizable.** Constructed chains can pass
  the Typestate oracle yet fail Z3 type/provenance/variable-binding (lcms APIs
  with unbindable `void*` args). ⇒ construction **merges with**, never
  *replaces*, the L0-type-valid grammar floor. Pure-replace regressed lcms 1→0.
- **The automaton is a ranking signal, not a candidate source.** Raw
  `sample_accepting_paths` are mid-stream trace fragments (consumer with no
  prior creator) that fail lifecycle yet score acceptance≈1.0. Use
  `acceptance_score` to *rank*, not to *propose*.
- **Two kinds of coverage gap need two levers.** Baseline-*uncovered APIs*
  (lcms: 98% of the surface) → G5 API-level targeting. *Uncovered branches
  inside covered functions* (cjson: public APIs already hit, gap is deep
  error/format paths) → G4 structured input + in/out-of-range intent. cjson
  won't move on G5 alone; lcms is where G5 pays off.

---

## The open bottleneck — the binding layer

G2/G3/G5 succeed at sequence selection, but on complex libraries coverage is
walled **below** generation, at CBFactory's argument-value synthesis:

1. *Shallow* gap APIs (lcms profile constructors) synthesize but cover ~80
   lines each.
2. *Deep* gap APIs (`cmsDoTransform`, `cmsTransform2DeviceLink`, …) cover a
   lot but **CBFactory's `RunningContext` cannot synthesize values for their
   `void*`/opaque-struct non-handle params**, so they never become skeletons
   regardless of ranking (live G5 run: `z3_rejected=38`, all gap sequences
   fail with "RunningContext has N unsat var(s)").

The highest-leverage next investment is therefore **argument-value synthesis
for opaque/`void*` params** (make deep gap APIs synthesizable), followed by
**format-aware input** (deepen G4) for libraries whose gap is deep *branches*
inside already-bindable functions. Both are measurable only in the live fuzz
loop, which is wired end-to-end.

---

## Surrounding subsystems & remaining roadmap

Generation feeds, and is fed by, four subsystems with their own status:

| Subsystem | Status | Boundary |
|-----------|--------|----------|
| Phase B idiom distiller | landed — 10 L1 deterministic patterns, `idioms.json` into prototyper prompt | no L2 LLM-tier idioms (F7) |
| Phase C coverage memory | landed — `CoverageMemory` data model, post-merge `IterationSnapshot` | no loop driver; snapshot write-only (no reader) |
| Phase D path planner | landed — idiom-align rerank + `synthesize_missing` | stateless; no score→coverage calibration |
| Phase E adaptive shape | **deferred** | `driver_size` fixed; happy-path only; no error injection (see below) |

The next investments are the *feedback* and *binding* layers:

- **F5 — Phase E adaptive shape.** Today every skeleton is happy-path
  (`create → use(valid) → destroy`). Bug classes outside that shape
  (error-handling, use-after-free, double-destroy, NULL-as-handle) are
  unreachable. The non-negotiable: **the skeleton owns structure, the LLM
  owns leaf values** — shape is encoded in the skeleton (pinned NULL, wrapped
  loop, reordered destroy), never as a prompt directive. MVP = 2 shapes
  (HAPPY + NULL_INJECT), idiom-driven selection. Z3 runs on HAPPY only;
  non-HAPPY shapes are validated by shape-construction. **Prereq: G4** — the
  shape selector consumes the per-API arg-semantics G4 attaches to holes.
- **F6 — Phase C CEGAR loop driver** (multi-iter + frontier + saturation
  trigger). **Prereq: WorkingMemory** — a single `ProjectWorkingMemory` object
  to hold cross-iteration state (idiom confidence, frontier, score
  calibration), since today's JSON state files (`idioms.json`,
  `coverage_memory.json`, `plan_ledger.json`) are write-only with no
  cross-iteration consumer. Currently deferred → F6 deferred. F5 and F7 don't
  depend on it.
- **F7 — Phase B L2 LLM idioms** (MULTI_STAGE_PARSE / EDGE_CASE_TRICK) — L1
  only captures surface idioms.

The §10B baseline-regression alert (`BaselineDiffAnalyzer`) operated at the
wrong granularity (single trial; the proper unit is post-merge) and is to be
folded into the F6 CEGAR loop.
