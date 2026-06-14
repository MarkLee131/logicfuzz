# Driver Decoupling & De-duplication — Design Spec

**Date:** 2026-06-14
**Status:** Approved (brainstorming) → ready for implementation plan
**Branch:** pub-llm

## Problem

The generated driver portfolio has too much inter-driver coverage overlap, so
merging the drivers yields little marginal coverage gain. We want to
systematically change driver generation — *especially API-sequence
construction* — so drivers are **decoupled** from one another and **de-duplicated**.

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
  deterministic `_rank` (`:593`), truncates to the same `max_extra` (`:601`,
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
- **Scope:** all levers below are in scope.

## Design — unifying principle

> Make "what code this driver *newly* exercises" the first-class object the
> pipeline reasons about, end to end, replacing the `tuple(api_names)` key.
> Construction must not *manufacture* twins; selection must not *ship* the
> twins that slip through.

Every lever is a `LOGICFUZZ_*` gate, default-OFF, A/B-validated, default-on
only after the portfolio-redundancy telemetry (Section E) proves the gain —
per project convention. All construction-side changes are **deterministic** (no
RNG) to preserve reproducibility and the symbolic-first principle.

### Layer A — Construction-time decoupling (`sequence_constructor.py`)

Break each shared component of `[prefix] + [target] + [suffix] + [destroyer]`.

- **A-1 — diversify producers / roots** (`LOGICFUZZ_DIVERSIFY_PRODUCERS`).
  In `_build_prefix()` (`:920`), when a handle type has >1 producer
  (`cmsCreateTransform` vs `cmsCreateProofingTransform` vs recovered
  factory creators), assign different producers to sibling chains sharing that
  handle, *deterministically* (by hash of the chain's target name, or
  coordinated round-robin). Single-producer handles unchanged. Must still pass
  Z3 and be reproducible.

- **A-2 — densifier suffix partitioning** (`LOGICFUZZ_DENSE_PARTITION`) —
  the biggest change and the primary root fix. Refactor `_densify()`
  (`:536-609`) from per-chain-independent to a **coordinated, sibling-aware
  pass**: partition/rotate the per-handle-type candidate pool across the chains
  that share that handle, so chain #1 gets extenders `{e1..e8}`, chain #2 gets
  `{e9..e16}`, etc. Each sibling exercises a *different* slice of the handle's
  mutators/consumers. Same density (still ~`max_extra` per chain), but the
  portfolio-union of densifier APIs rises and pairwise suffix overlap falls.
  Preserve validity (`requires ⊆ opened`). Implementation may be either an
  in-place coordinated `_densify` or a post-construction re-balancing pass over
  the grouped pool — chosen in the plan.

- **A-3 — diversify destroyers** (folded under `LOGICFUZZ_DIVERSIFY_PRODUCERS`
  or its own minor flag). Rotate `_closing_destroyers()` choice across siblings.
  Low value; included for completeness.

### Layer B — Selection-time marginal + pairwise dissimilarity

- **B-1 — unify on one marginal selector** (`LOGICFUZZ_MARGINAL_DEPTH`) —
  the headline fix. Replace the round-robin Phase 2 depth pass
  (`data_context.py:1996-2014`) with marginal-coverage selection by calling
  `coverage_ranker._coverage_complete_select` (`coverage_ranker.py:464`)
  directly, so the two selectors stop diverging. Pure wiring; the correct
  algorithm already exists.

- **B-2 — pairwise dissimilarity gate** (`LOGICFUZZ_PAIRWISE_DEDUP` +
  `LOGICFUZZ_PAIRWISE_TAU`, default τ≈0.8). In the selection loop, before
  admitting candidate `s`, reject/demote if
  `max over selected d of similarity(fingerprint(s), fingerprint(d)) > τ`.
  Catches "differ by 1 API / 95% redundant" near-twins that pass a marginal-API
  filter. O(selected × candidates) set ops.

- **B-3 — subset elimination on the shipped pool** (`LOGICFUZZ_SUBSET_ELIM`).
  Replace the weak `tuple()` dedup at `data_context.py:1374-1384` with
  `order_sets.minimize_traces` (`order_sets.py:133-173`) **operating on the
  constructed sequences that become drivers**, not just trace inputs. Ordered
  as a pre-filter *before* B-1, removing **strict subsets only** (a sequence
  whose fingerprint-set ⊆ another's), so cluster-cover drivers are not
  over-stripped.

### Layer C — Structural fingerprint (connective tissue for B-2/B-3)

Replace `tuple(api_names)` as the identity/similarity representation. A
sequence fingerprint = :

1. **API set** — for pairwise Jaccard / near-twin detection.
2. **Dependency sub-chains + root producer** — so "same APIs, different
   producer root" sequences (A-1's output) are *distinguishable* and not
   wrongly deduped.
3. **Hole value-domain signature** — reuse
   `hole_semantics.value_intents_for_sequence` (`:359-405`): so deliberately
   different-config variants are kept distinct, while same-config twins ARE
   caught. This is what makes the VALUE/PATH channel *partially* visible
   statically (full visibility needs Layer D).

Used by: exact dedup (replaces tuple key), subset elimination (B-3), pairwise
similarity (B-2).

### Layer D — Dynamic edge-coverage signal (Phase 2, after static A/B)

- **D-1 — edge-set marginal selection** (`LOGICFUZZ_EDGE_MARGINAL`). Extend the
  preflight that already records `edges_15s`
  (`run_single_fuzz._edges_weights_for`) to capture the **edge set** (not just
  count), then feed it into selection as the marginal unit:
  `len(edges(s) − covered_edges)`. Closes the VALUE/PATH channel and the
  "30% API overlap / 90% edge overlap" case. Requires a new feedback edge
  (preflight → pre-merge selection) that does not exist today; related to the
  unbuilt F6 CEGAR loop. Opt-in, built only after the static layer is validated.

### Layer E — Portfolio-redundancy telemetry (build first; the A/B oracle)

Without a redundancy metric we cannot prove decoupling worked. Emit to
`results/<project>/`:

- **Static:** mean pairwise API-set Jaccard of selected drivers;
  `union_apis / Σ per_driver_apis` (1.0 = fully disjoint).
- **Dynamic (post-preflight):** `union_edges / Σ per_driver_edges`; count of
  drivers whose marginal-edge contribution is 0.

Each lever is A/B'd against these metrics with its gate off vs on.

## Implementation order (by leverage)

1. **B-1** (headline, pure wiring) **+ Layer E telemetry** (so we can measure).
2. **A-2** (root fix) **+ B-2** (near-twin gate) — needs Layer C fingerprint.
3. **B-3 + A-1 + A-3**.
4. **D-1** (dynamic edge layer) — last, gated, after static A/B.

## Gates summary

| Gate | Lever | Default |
|---|---|---|
| `LOGICFUZZ_MARGINAL_DEPTH` | B-1 unify depth selector | OFF (A/B) |
| `LOGICFUZZ_DENSE_PARTITION` | A-2 densifier partitioning | OFF (A/B) |
| `LOGICFUZZ_PAIRWISE_DEDUP` / `_TAU` | B-2 pairwise gate | OFF (A/B) |
| `LOGICFUZZ_SUBSET_ELIM` | B-3 subset elimination | OFF (A/B) |
| `LOGICFUZZ_DIVERSIFY_PRODUCERS` | A-1 (+A-3) producer/destroyer rotation | OFF (A/B) |
| `LOGICFUZZ_EDGE_MARGINAL` | D-1 dynamic edge-set selection | OFF (Phase 2) |

(Redundancy telemetry: always-on, cheap; it is the measurement, not a behavior change.)

## Risks & guardrails

- **A-1/A-2 determinism:** no RNG; assignment by stable hash / coordinated
  round-robin. Must still pass Z3 validation and be reproducible across runs.
  Add regression tests asserting same input → same output.
- **B-3 over-stripping:** must run *before* B-1 and remove **strict subsets
  only**, never near-twins (those are B-2's job under marginal+τ), so
  cluster-cover drivers survive.
- **No-LLM / symbolic-first preserved:** all static levers are deterministic
  symbolic logic; no new LLM calls.
- **Reuse over rewrite:** B-1 reuses `_coverage_complete_select`; B-3 reuses
  `order_sets.minimize_traces`; C reuses `value_intents_for_sequence`; D-1
  reuses the existing `edges_15s` preflight. New code is limited to the
  fingerprint, the pairwise gate, the densifier-partition refactor, and the
  telemetry.
- **Regression:** the full pytest suite (375+ tests) green with all gates off
  (no behavior change when gated off) and with each gate on.

## Acceptance criteria

- With gates off: behavior and tests unchanged (true A/B control).
- With static gates on (lcms reference): measurable drop in mean pairwise
  Jaccard and rise in `union_apis / Σ per_driver_apis`, AND a real increase in
  merged-harness branch coverage vs the gates-off baseline.
- D-1 (when built): measurable drop in `union_edges / Σ per_driver_edges`
  redundancy and further merged-coverage gain.
