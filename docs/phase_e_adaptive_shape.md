# Phase E: Adaptive Shape — DEFERRED

Status: **deferred** (2026-05-23). Sequenced **after** the generation-stage
redesign G1–G4 (`docs/generation_stage_redesign.md`). Do not start until G4
(semantic holes) lands — shape variants are meaningless until holes carry
arg-semantics. This doc records the design so it isn't re-litigated; it is not
the current priority.

---

## Problem (one paragraph)

Tool goal (b) is *find novel paths / deep bugs*. Today every emitted skeleton
is happy-path: `create → use(valid) → destroy`. The bug classes that live
structurally outside this shape — error-handling branches, use-after-free /
double-destroy, leak-under-repetition, NULL-as-handle — are unreachable. F5
makes the **skeleton itself** structurally varied, so the LLM still only fills
holes; it does not decide shape.

## The one non-negotiable decision

**Skeleton owns structure; LLM owns leaf values.** Shape is encoded *in the
skeleton* (pinned NULL, wrapped loop, reordered destroy), never as a "please
inject NULL" directive in the prompt. Rationale: the LLM is not a reliable
structural instrument; a skeleton-level shape is auditable, replayable, and
scales to harder shapes (REPEAT/DESTROY_EARLY) that a prompt can't reliably
produce.

## Model (when built)

One sequence → K' = K × S skeletons (S shape variants per sequence). Each
variant is a distinct fill problem → one trial each. Trial count scales with
skeletons, not with extra trials-per-skeleton.

- `SkeletonShape{ kind, null_inject_at_api_index, null_inject_arg_name, ... }`,
  frozen; `Skeleton.shape` defaults HAPPY.
- **MVP = 2 shapes**: HAPPY + NULL_INJECT. Reserve REPEAT / DESTROY_EARLY /
  TRUNCATE / CORRUPTED_BUF for later.
- Shape selection is **idiom-driven** (`context_null_pass` → NULL_INJECT,
  etc.); sequences with no matching idiom emit HAPPY only. No global cap —
  idiom selectivity is the cap.
- Z3 runs on HAPPY only; non-HAPPY shapes deliberately bend lifecycle and are
  validated by shape-construction, not Z3.
- `crash_feasibility_analyzer` reads `shape.is_intentional_crash_source()` so
  injected crashes aren't mistaken for real bugs.

## Why it depends on the redesign

The shape selector consumes per-API **arg-semantics** (which arg is the
nullable handle → where to inject NULL). That comes from the `APISemanticModel`
built in redesign **G1**, and is attached to holes in **G4**. Building F5 before
G1/G4 would reintroduce the single-source arg heuristic this redesign deletes.

## Validation (when run)

lcms / c-ares / cjson A/B. Success: lcms total coverage ≥ redesign baseline AND
≥1 real crash unreached pre-F5 within 24h. Failure: >5% coverage regression OR
crash queue >50% INTENTIONAL noise.

---

*Deferred. Prerequisites and current priority live in
`docs/generation_stage_redesign.md`.*
