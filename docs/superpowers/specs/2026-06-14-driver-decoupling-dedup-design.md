# Driver Decoupling & De-duplication — Design Spec

**Date:** 2026-06-14
**Status:** Approved (brainstorming, incl. doc/LLM integration) → ready for implementation plan
**Branch:** pub-llm

## Problem

The generated driver portfolio has too much inter-driver coverage overlap, so
merging the drivers yields little marginal coverage gain. We want to
systematically change driver generation — *especially API-sequence
construction* — so drivers are **decoupled** from one another and
**de-duplicated**, while staying *tightly integrated* with the tool's
doc/LLM-driven API-semantic understanding.

## Diagnosis (root cause, file:line grounded)

Overlap arrives through **two compounding channels**.

### Channel 1 — API-SET overlap (two drivers call nearly the same APIs)

Manufactured at construction, passed through by weak dedup, not penalized at
the selection path that actually ships drivers:

- **A1 — shared prefixes.** `sequence_constructor._build_prefix()`
  (`liberator_adapter/analysis/sequence_constructor.py:920`) is fully
  deterministic: a given handle type always resolves to the *same* producer.
  Every target consuming `cmsHTRANSFORM` gets the identical
  `cmsOpenProfileFromMem → cmsCreateTransform` prefix; only the single trailing
  target API differs (`core = prefix + [target.name]`, `:923`).
- **A2 — shared dense suffix (primary similarity source).** `_densify()`
  (`sequence_constructor.py:536-609`) draws extenders for each opened handle
  type from the *global* `idx.mutators[t] + idx.consumers_by_handle[t]` buckets
  (`:562`) and the global `cooccur` dict (`:571`), ranks by the *same*
  deterministic `_rank` (`:593-599`), truncates to the same `max_extra` (`:601`,
  default 8). Two chains sharing a handle type get the **same top-8 suffix**.
  Density (default-on) actively homogenizes.
- **A3 — shared destroyers.** `_closing_destroyers()` picks
  `sorted(dz, key=name)[0]` per handle type — identical closing list for all
  chains closing the same handle set.

Net shape of a typical sequence: `[shared prefix] + [1 unique target] +
[shared dense suffix] + [shared destroyer]` — the unique fraction can be a
single API.

- **B — dedup only removes exact-tuple twins.** `_add()` keys on
  `tuple(api_names_in_order)` (`sequence_constructor.py:847`); the post-merge
  dedup keys on `tuple(seq)` too (`data_context.py:1374-1384`). Near-twins
  (differ by 1 API), subsets, and reorderings all survive.
- **C — the shipping selector is NOT marginal.** Two selectors diverge:
  - `coverage_ranker._coverage_complete_select` (`coverage_ranker.py:464`) is
    genuinely marginal (selects on new clusters / `max(len(set(seq) -
    covered_apis))`) — **but it is not the path that ships drivers.**
  - The actual shipping path `data_context.py:1972-2014`: Phase 1 dedups by
    *first cluster only* (`_dcl`, `:1981`); **Phase 2 depth is plain
    round-robin** (`:1996-2014`) that appends "any driver not yet used" with
    **zero marginal-coverage computation**. Depth contributes `0.5×` of the
    portfolio by default (`LOGICFUZZ_PORTFOLIO_DEPTH=0.5`). **~half the
    portfolio is selected with no overlap check at all** — the headline defect.

### Channel 2 — VALUE/PATH overlap (same APIs → same branches)

Invisible to the whole selection layer because every representation it uses
(API-name tuple, cluster label, `binding_pattern_hash` at `pta.py:23-24`)
abstracts away the filled values that decide which branch runs.

- `FUZZABLE_HOLES` (default-on, `hole_semantics.py:75-94`) injects value
  diversity only at *runtime per driver*, never differentiates two drivers at
  selection. With it off (the A/B control) or for non-tunable args, CONFIG
  holes collapse to constant `0` → same-API drivers hit identical branches.
- The only dynamic signal that exists, `edges_15s` (preflight), is computed
  *after* selection and used only for merge CDF dispatch weighting — it never
  feeds back into *which* drivers ship.

### Why existing dedup/diversity is insufficient

| Mechanism | Misses |
|---|---|
| OrderSet + SetCover (`order_sets.py`, `LOGICFUZZ_ORDERSETS`, default OFF) | Off by default; only minimizes automaton-trace *inputs*, never reaches the constructed sequences that become drivers; re-deduped downstream by weak `tuple()` key. |
| Exact-tuple dedup (`:847`, `:1374`) | Near-twins, subsets, reorderings. |
| diversity tiebreak `unique_apis/length` (`coverage_ranker.py:57-58`) | Measures a sequence *in isolation*; never *inter-sequence* similarity. |
| subsystem cover (`subsystem_clusters.py`, `_dcl`) | Guarantees breadth, not non-overlap; clusters are coarse (5–50+ APIs); `_dcl` keys on the *first* cluster only. |
| coverage_gap / G5 (`coverage_gap.py`) | Set difference, no intra-gap ranking; biases *generation input*, never post-selection overlap. |
| FUZZABLE_HOLES (`hole_semantics.py`) | Runtime/per-driver only; nothing at selection. |

**Core gap:** dedup is done on the wrong object (trace inputs, not shipped
sequences) at the wrong granularity (API-name, not edge/path); and the one
truly-marginal selector is not the one that ships.

## Decisions (locked)

- **Intervention locus:** both layers — construction-time decoupling AND
  selection-time marginal dedup.
- **Diversity signal:** static structural fingerprint first; add a dynamic
  edge-coverage signal as a later phase, gated, after the static layer's A/B
  proves its gain.
- **Doc/LLM integration:** tightly coupled — the doc/LLM semantic layer is
  *upstream* of every dedup decision; it **defines the fingerprint content and
  the partition keys** the dedup levers enforce (see next section).
- **Scope:** all levers below are in scope.

## Doc/LLM integration — no conflict (orthogonal axes)

The dedup spec and the doc/LLM semantic layer operate on orthogonal axes of the
same object:

- **Dedup levers** answer *"are two drivers redundant?"* — a question about the
  structural fingerprint (Layer C).
- **Doc/LLM layer** answers *"what does each API mean and which compositions are
  coherent?"* — it **defines the content of that fingerprint** and **proposes
  the partitions** the dedup levers enforce.

No architectural conflict exists: the doc/LLM layer is upstream of every dedup
lever's decision. There are exactly **two genuine tensions**, both resolved by
routing the doc/LLM signal *into* the partition key and the fingerprint:

1. **A-2 blind partitioning vs doc-coherent workflows.** `_densify`'s
   `cooccur` pool (`sequence_constructor.py:568-571`) already carries a semantic
   signal — APIs used together in real workflows. A naive index round-robin
   partition would split a doc-coherent workflow (lcms `buildToneCurve +
   makeDeviceLink + closeProfile`) across two drivers, producing two *incoherent*
   halves. **Fix:** partition by **`workflow_id` cluster** (keep co-occurrence
   clusters intact, assign whole clusters to siblings) — see A-2b.
2. **B-2/B-3 API-set-only fingerprint kills doc-distinct value-diverse
   drivers.** Two `cmsBuildParametricToneCurve` drivers — one sweeping
   gamma∈[0.1,5] (doc `@param`-derived), one sweeping the legal type-index enum —
   are a distinction the doc layer (G4 value intents, `hole_semantics.py:353-405`)
   deliberately created; an API-set fingerprint is blind to it. **Fix:** revised
   Layer C includes the value-domain signature — see C.

### The keystone: doc value-domain computed once, consumed twice

`value_intents_for_sequence` (`hole_semantics.py:353-405`) is computed **once**
(doc `@param` ranges + `named_constants` enum legal-sets) and serves
**both** integration patterns the design targets:

- **Pattern (b) — doc drives diverse sequences:** sibling chains sweep
  *different* value domains (boundary / mid-range / full-legal-enum) — the depth
  PromeFuzz gets from LLM judgment, here doc-deterministic.
- **Pattern (a) — symbolic partition first, doc refines:** the *same*
  value-intent records become the fingerprint's value-domain signature, so the
  dedup gates keep doc-meaningful look-alikes apart.

They read the same output → cannot drift. This is the tight coupling.

### LLM vs deterministic — where each is worth its cost

Applying "Z3 for hard constraints, LLM for soft", "empirical before
parametric", and valid-by-construction:

- **Pure-symbolic (no LLM, deterministic):** fingerprint construction; B-1
  marginal selection; A-2 partition *mechanics*; `_rank` keeps `sat` strictly
  ahead of any affinity term (lifecycle-satisfiability is a hard constraint a
  soft signal must never reorder past); the Typestate self-filter.
- **Doc-deterministic (parse doc, no LLM call):** the value-domain signature;
  the `workflow_id` clusters (`idiom_chains` + automaton `accepting_paths`);
  role-authoritative root/destroyer diversity at `APIRole` confidence ≥ 0.7.
- **LLM (worth it at exactly one dedup seam, zero new calls):** the Comprehender
  Stage-B `VALID/SUBOPTIMAL` verdict (`comprehender.py:736-865`) — *already
  computed* — used as a **guard**: never drop a Stage-B-VALID sequence in favor
  of a SUBOPTIMAL near-duplicate. Deciding which of two near-twins is the
  redundant one is a semantic-coherence call the symbolic layer cannot make, and
  consuming the existing verdict adds no new LLM calls.
- **Non-negotiable invariants:** `_LLM_OVERRIDE_BELOW=0.7`
  (`api_semantic_model.py:92`) stays hardcoded; the fingerprint reads the
  *reconciled* role (the dedup layer can never silently flip a confident role);
  valid-by-construction (no repair stage); the default path stays deterministic
  and offline-reproducible.

## Design — unifying principle

> Make "what code this driver *newly* exercises" the first-class object the
> pipeline reasons about, end to end, replacing the `tuple(api_names)` key.
> Construction must not *manufacture* twins; selection must not *ship* the
> twins that slip through. The doc/LLM layer supplies the partition keys and
> fingerprint content.

Every lever is a `LOGICFUZZ_*` gate, default-OFF, A/B-validated, default-on
only after the portfolio-redundancy telemetry (Layer E) proves the gain. All
construction-side changes are **deterministic** (no RNG).

### Layer A — Construction-time decoupling (`sequence_constructor.py`)

Break each shared component of `[prefix] + [target] + [suffix] + [destroyer]`.

- **A-1 — diversify producers / roots** (`LOGICFUZZ_DIVERSIFY_PRODUCERS`).
  In `_build_prefix()` (`:920`), when a handle type has >1 producer, assign
  different producers to sibling chains sharing that handle, *deterministically*
  (by stable hash of the chain's target name, or coordinated round-robin).
  Single-producer handles unchanged. Must still pass Z3 and be reproducible.
  - **A-1b — doc-confidence-weighted root diversity.** Prefer CREATORs whose
    `APIRole` confidence ≥ 0.7 (`api_semantic_model.py:92`); widen the producer
    set via `recovered_producers` (`sequence_constructor.py:654`). Deterministic.

- **A-2 — densifier suffix decoupling** (the biggest change, primary root fix).
  - **A-2a — coordinated pass** (`LOGICFUZZ_DENSE_PARTITION`). Refactor
    `_densify()` (`:536-609`) from per-chain-independent to a **coordinated,
    sibling-aware** pass so chains sharing a handle take *disjoint* densifier
    slices. Same density (~`max_extra` per chain); portfolio-union of densifier
    APIs rises, pairwise suffix overlap falls. Preserve validity
    (`requires ⊆ opened`). In-place coordinated `_densify` vs post-construction
    re-balancing — chosen in the plan.
  - **A-2b — partition by `workflow_id` cluster, not index** (resolves tension
    1; gate folded under `LOGICFUZZ_DEDUP_WORKFLOW_PARTITION`). Build
    `workflow_id` from `_cooccur` clusters (`construct_sequences:794-798`) tagged
    by `idiom_chains` provenance; assign **whole clusters** to siblings so each
    gets a *distinct coherent* workflow. `_rank` (`:593-599`) gains a
    `workflow_affinity` element **strictly after `sat`** (lifecycle wins).
    **Wiring prerequisite (verified gap):** `data_context.py:1258-1265` does not
    pass `idiom_chains=` to `construct_sequences` though the param (`:759`) and
    seeding (`:878-879`) exist — wire the Phase-B distiller's semantic chains in.

- **A-3 — diversify destroyers** (folded under `LOGICFUZZ_DIVERSIFY_PRODUCERS`).
  Rotate `_closing_destroyers()` choice across siblings. Low value; destroyer
  identity is doc/naming-role-authoritative. Included for completeness.

### Layer B — Selection-time marginal + pairwise dissimilarity

- **B-1 — unify on one marginal selector** (`LOGICFUZZ_MARGINAL_DEPTH`) —
  the headline fix. Replace the round-robin Phase 2 depth pass
  (`data_context.py:1996-2014`) with marginal-coverage selection by calling
  `coverage_ranker._coverage_complete_select` (`coverage_ranker.py:464`)
  directly, so the two selectors stop diverging. Pure wiring; the correct
  algorithm already exists and inherits the doc-defined cluster partition.

- **B-2 — pairwise dissimilarity gate over the full fingerprint**
  (`LOGICFUZZ_PAIRWISE_DEDUP` + `LOGICFUZZ_PAIRWISE_TAU`, default τ≈0.8). Before
  admitting candidate `s`, reject/demote if
  `max over selected d of similarity(fingerprint(s), fingerprint(d)) > τ`,
  where `fingerprint` is the **full revised Layer C** (incl. value-domain), so a
  value-distinct near-twin is NOT dropped.
  - **VALID-protect guard** (`LOGICFUZZ_DEDUP_SEMANTIC_GUARD`): never drop a
    sequence whose Comprehender Stage-B `semantic_status==VALID`
    (`comprehender.py:736-865` → `sequence_semantics`) in favor of a
    SUBOPTIMAL/INVALID near-duplicate. Consumes existing verdicts; no new LLM.

- **B-3 — subset elimination on the shipped pool over the full fingerprint**
  (`LOGICFUZZ_SUBSET_ELIM`). Replace the weak `tuple()` dedup at
  `data_context.py:1374-1384` with `order_sets.minimize_traces`
  (`order_sets.py:133-173`) operating on the constructed sequences that become
  drivers. Test subset over the **full fingerprint** (API-set ∧ value-domain ∧
  root-producer), so a value-distinct or error-shape-distinct (T11) subset
  survives. Ordered as a pre-filter *before* B-1, removing **strict subsets
  only**, so cluster-cover drivers are not over-stripped.

### Layer C — Structural fingerprint (doc-aware; keystone for B-2/B-3)

Replace `tuple(api_names)` as the identity/similarity representation:

```
fingerprint = (
    api_set,                      # pairwise Jaccard / near-twin detection
    root_producer_set,           # A-1's distinct roots are distinguishable
    dependency_subchain_shape,   # structural shape of the handle dep graph
    value_domain_signature,      # doc-deterministic — the integration anchor
)
value_domain_signature = stable_hash(value_intents_for_sequence(...))
                         restricted to CONFIG / enum / range intents
                         (hole_semantics.py:353-405)
```

Two drivers with identical API structure but distinct doc-derived value domains
are **non-redundant**. Deterministic; no LLM. Used by exact dedup (replaces the
tuple key), subset elimination (B-3), and pairwise similarity (B-2).

### Layer D — Dynamic edge-coverage signal (Phase 2, after static A/B)

- **D-1 — edge-set marginal selection** (`LOGICFUZZ_EDGE_MARGINAL`). Extend the
  preflight that already records `edges_15s`
  (`run_single_fuzz._edges_weights_for`) to capture the **edge set** (not just
  count), feed it into selection as the marginal unit:
  `len(edges(s) − covered_edges)`. Closes the VALUE/PATH channel and the
  "30% API overlap / 90% edge overlap" case. Keep D as a tiebreak/weight, **not
  a hard gate** — never override a doc-distinct driver with low early edges
  (consistent with how `edges_15s` already weights CDF dispatch, not drops
  drivers). Requires a new feedback edge (preflight → pre-merge selection) that
  does not exist today; related to the unbuilt F6 CEGAR loop. Opt-in, built only
  after the static layer is validated.

### Layer E — Portfolio-redundancy + doc-interaction telemetry (build first)

Emit to `results/<project>/`:

- **Static redundancy:** mean pairwise API-set Jaccard of selected drivers;
  `union_apis / Σ per_driver_apis` (1.0 = fully disjoint).
- **Dynamic (post-preflight):** `union_edges / Σ per_driver_edges`; count of
  drivers whose marginal-edge contribution is 0.
- **Doc/dedup interaction (the integration A/B oracle):**
  - `dedup_value_domain_saves` — pairs kept apart *only* by the value-domain
    signature (proves C's value-domain slot earns its keep).
  - `dedup_semantic_guard_saves` — drops vetoed by the Stage-B VALID guard.
  - `workflow_partition_split_clusters` — workflow clusters A-2b kept intact vs
    split (proves the `workflow_id` partition beats blind round-robin).

Telemetry is always-on and cheap; it is the measurement, not a behavior change.

## Implementation order (by leverage)

1. **B-1** (headline, pure wiring) **+ Layer E telemetry** (so we can measure).
2. **Layer C fingerprint** (doc-aware, incl. value-domain) **+ A-2a/A-2b**
   (root fix; needs the `idiom_chains` wiring) **+ B-2** (incl. VALID guard).
3. **B-3 + A-1/A-1b + A-3**.
4. **D-1** (dynamic edge layer) — last, gated, after static A/B.

## Gates summary

| Gate | Lever | Default |
|---|---|---|
| `LOGICFUZZ_MARGINAL_DEPTH` | B-1 unify depth selector | OFF (A/B) |
| `LOGICFUZZ_DEDUP_FINGERPRINT_VALUE_DOMAIN` | C value-domain signature | OFF (A/B) |
| `LOGICFUZZ_DENSE_PARTITION` | A-2a coordinated densifier | OFF (A/B) |
| `LOGICFUZZ_DEDUP_WORKFLOW_PARTITION` | A-2b `workflow_id` partition (+ `idiom_chains` wiring) | OFF (A/B) |
| `LOGICFUZZ_PAIRWISE_DEDUP` / `_TAU` | B-2 pairwise gate | OFF (A/B) |
| `LOGICFUZZ_DEDUP_SEMANTIC_GUARD` | B-2 Stage-B VALID-protect guard | OFF (A/B) |
| `LOGICFUZZ_SUBSET_ELIM` | B-3 subset elimination | OFF (A/B) |
| `LOGICFUZZ_DIVERSIFY_PRODUCERS` | A-1/A-1b/A-3 producer/destroyer rotation | OFF (A/B) |
| `LOGICFUZZ_EDGE_MARGINAL` | D-1 dynamic edge-set selection | OFF (Phase 2) |
| `LOGICFUZZ_LLM_DENSIFY_AFFINITY` | deferred LLM post-construction reorder | OFF (build-only-if-needed) |

(Redundancy/interaction telemetry: always-on, cheap.)

## Ordering constraints (make integration first-class)

- Fingerprint computation (C) runs **after** `annotate_skeletons()`
  (`data_context.py:2094-2096`) so the value-domain signature is available.
- Dedup gates (B-2/B-3) run **after** Comprehender Stage B so the semantic
  guard has verdicts.
- In `_rank`, the `sat` term is **strictly ahead** of any `workflow_affinity` /
  semantic term — lifecycle-satisfiability always wins.

## Risks & guardrails

- **A-1/A-2 determinism:** no RNG; assignment by stable hash / coordinated
  round-robin; new params immutable. Must pass Z3 and be reproducible
  (regression test: same input → same output).
- **A-2b partition vs breadth:** preserve gap-first ranking
  (`data_context.py:1322-1324`) and a per-tier handle-type diversity sort, so
  workflow partitioning augments — never replaces — gap-novelty (RISK-2/RISK-5
  from the integration analysis).
- **`idiom_chains` quality:** if the Phase-B distiller emits chains with unmet
  deps, the self-filter (`:968+`) catches ordering faults but unmeetable handle
  deps surface only at Z3 time; add a pre-flight `_runnable`/Typestate check on
  idiom chains if needed.
- **B-2/B-3 over-stripping:** operate over the full fingerprint; B-3 removes
  strict subsets only and runs before B-1; B-2's VALID guard protects
  semantically-distinct near-twins.
- **No-LLM / symbolic-first preserved:** all static levers deterministic; the
  only LLM touch is *consuming* an existing Stage-B verdict (no new calls). The
  deferred `LOGICFUZZ_LLM_DENSIFY_AFFINITY` hook stays OFF until a deterministic
  A/B proves the `workflow_id` partition insufficient.
- **Authority invariants:** `_LLM_OVERRIDE_BELOW=0.7` stays hardcoded; the
  fingerprint reads the reconciled role; valid-by-construction (no repair).
- **Reuse over rewrite:** B-1 reuses `_coverage_complete_select`; B-3 reuses
  `order_sets.minimize_traces`; C reuses `value_intents_for_sequence`; A-2b
  reuses `idiom_chains`/`cooccur`; the semantic guard reuses Stage-B verdicts;
  D-1 reuses the `edges_15s` preflight. New code: the fingerprint, the pairwise
  gate, the densifier-partition refactor, the `workflow_id` tagging, and the
  telemetry.
- **Regression:** full pytest suite (375+ tests) green with all gates off (no
  behavior change when gated off) and with each gate on.

## Acceptance criteria

- With gates off: behavior and tests unchanged (true A/B control).
- With static gates on (lcms reference): measurable drop in mean pairwise
  Jaccard and rise in `union_apis / Σ per_driver_apis`, positive
  `dedup_value_domain_saves` / `workflow_partition_split_clusters`, AND a real
  increase in merged-harness branch coverage vs the gates-off baseline.
- D-1 (when built): measurable drop in `union_edges / Σ per_driver_edges`
  redundancy and further merged-coverage gain.
