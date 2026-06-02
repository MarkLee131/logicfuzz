# LogicFuzz — System Panorama + Non-Generation Status

> Snapshot of the **non-generation** subsystems (knowledge distillation,
> coverage feedback, merge) and the cross-phase information-flow problems.
> For the **driver-generation stage**, `docs/generation_stage_redesign.md`
> is the source of truth — it supersedes the old Phase A repair + Tier-1
> F1–F4 line that earlier lived here (those were the "classify-then-repair"
> band-aids the redesign deletes; do not develop against them).
>
> Historical diagnostics, proposals, and refactor logs live in git history
> (`git log --grep`). Subsystem deep-dives stay in their own docs
> (`automaton.md`, `merge_drivers.md`, `llm_vs_traditional_choices.md`,
> `contributions_and_related_work.md`).

---

## §1. Tool goal (the calibration anchor)

Auto-generate fuzz drivers for C/C++ libraries so that fuzzing:

- **(a) matches baseline** — complex libraries catch up to the total
  coverage of hand-written OSS-Fuzz drivers, and
- **(b) finds novel paths / bugs** — reaches corners the baseline never
  touches, triggering bugs deep in error-handling paths.

These two halves are the dual objective; **every design decision is
calibrated against both.** (a) is blocked mainly by sequence construction +
selection (generation redesign G2/G3/G5); (b) by API characterization +
input/value constraint (G1/G4 + the deferred adaptive-shape work).

---

## §2. 5-phase panorama (non-generation phases)

The generation pipeline (model → construct → rank → Z3 → skeleton → trials)
is documented in `generation_stage_redesign.md`. The surrounding phases:

| Phase | Status | Capability | Known boundary |
|-------|--------|-----------|----------------|
| B Distillation | ✓ landed | 10 L1 deterministic idiom patterns; persists `idioms.json`; fed into prototyper prompt | no L2 LLM-tier idioms; no confidence update |
| C Foundation | ✓ landed | `CoverageMemory` data model; post-merge `IterationSnapshot`; `is_saturated` | **no loop driver**; frontier compute unimplemented; snapshot is write-only (no reader) |
| D Planner | ✓ landed | idiom-alignment scoring + rerank + `synthesize_missing` (limited to `context_null_pass`) | stateless (ignores prior iters); doesn't read frontier; no score→coverage calibration |
| E Adaptive Shape | ✗ deferred | — | `driver_size` fixed; happy-path only; no error injection. Design in `phase_e_adaptive_shape.md`; sequenced after redesign G4 |

(Phase A repair engine was **deleted** in redesign G2 — construction is
lifecycle-complete by construction, so repair was dead code.)

---

## §3. Cross-phase information-flow problems (the standing debt)

The phases largely communicate through an unschematized in-memory
`existing_driver_knowledge` dict; the JSON state files are write-only.
These are the structural issues that any closed-loop (CEGAR) work must
resolve first.

### Severe — broken cross-phase communication

- **P1 — JSON state files are write-only.** `idioms.json`,
  `coverage_memory.json`, `plan_ledger.json` have no cross-iteration
  consumer. Real cross-phase comms is 100% the in-memory
  `existing_driver_knowledge` dict (no schema).
- **P3 — Planner scoring is stateless.** It reads neither prior repair
  logs nor `coverage_memory`; every iteration scores from scratch, with no
  calibration or accumulation.
- **P4 — Phase C snapshot can't see repair detail.** `trial_results` carry
  no sequence key to match repair traces → `skeleton_repair_applied` is
  always False (dead path).

### Medium — redundancy / structure

- **P6 — `distill_idioms` runs twice** (Step 10 for the Planner, Step 12
  to write `idioms.json`); same input, same output.
- **P7 — `existing_driver_knowledge` is a de-facto WorkingMemory with no
  schema.** Plain dict, each consumer `.get()`s ad hoc; new fields are
  invisible to other consumers.
- **P8 — Phase D `synthesize_missing` makes shape decisions** (fixes
  synthesized-candidate length to 1) that properly belong to Phase E.

### Edge — orphan signals

- **P9 — `AutomatonAcceptanceGuard.stats`** (n_pruned / n_passed /
  n_relaxes) collected but never reported.
- **P11 — `AutomatonArtifact.acceptance_score` was positive-only and
  unused in selection** — now promoted to the **primary** L4 sort axis by
  redesign G3 (this one is resolved at selection; calibration vs observed
  coverage still pending a live run).

---

## §4. Remaining roadmap (by value density)

The generation redesign (G1–G5) has landed. The next investments are the
*feedback* and *binding* layers — both measurable only in the live fuzz
loop, which is now wired end-to-end.

### Must-do for a real closed loop

| # | Action | Solves | Touches |
|---|--------|--------|---------|
| F5 | **Phase E Adaptive Shape** (incl. error injection) | single-shape happy-path can't reach deep bugs | prototyper template + skeleton_generator + planner shape API. **Prereq: redesign G4 (semantic holes).** See `phase_e_adaptive_shape.md` |
| F6 | **Phase C CEGAR loop driver** (multi-iter + frontier + saturation trigger) | no closed loop = no continuous learning | workflow orchestration + frontier extraction. **Prereq: WorkingMemory (below).** |
| F7 | **Phase B L2 LLM idioms** (MULTI_STAGE_PARSE / EDGE_CASE_TRICK) | L1 only captures surface idioms | `idiom_distiller` + LLM agent |

### Architectural prerequisite — WorkingMemory

Centralize the scattered write-only JSON state into one
`ProjectWorkingMemory` Python object that holds cross-iteration history
(idiom confidence, frontier, strategy success rate, score calibration).
**Without it, F6's CEGAR loop has nowhere to keep iteration state.**

Design sketch: single class, `mem.record_*` / `mem.get_*` interface;
existing JSON files retained as derived debug views; `begin_iteration` /
`end_iteration` lifecycle; query interface (`get_frontier`,
`get_idiom_confidence`, `is_saturated`, `should_pivot`).

**Current decision: WorkingMemory deferred** → F6 also deferred. F5 and F7
do not depend on it and can proceed.

### The binding-layer wall (pinpointed by the live G5 run)

For complex libraries the bottleneck is now **below** generation, at
CBFactory's argument-value synthesis:

1. *Shallow* gap APIs synthesize but cover little (lcms profile
   constructors: ~80 lines each).
2. *Deep* gap APIs (`cmsDoTransform`, …) cover a lot but **CBFactory's
   `RunningContext` cannot synthesize values for their `void*`/opaque-struct
   non-handle params**, so they never become skeletons regardless of
   ranking.

The single highest-leverage fix for lcms-class libraries is therefore
**argument-value synthesis for opaque/`void*` params** (the binding layer),
followed by **format-aware input** (deepen G4) for libraries whose gap is
deep *branches* inside already-bindable functions (cjson). Full analysis:
`generation_stage_redesign.md` §8.

### Explicitly not doing

| Item | Why |
|------|-----|
| §10B v1/v2 moved to post-merge | subsumed by F6 CEGAR loop |
| Phase A nullable_handle_fill strategy | absorbed by Phase B+D `context_null_pass` |
| IR-side role splitting (Liberator C++ change) | redesign G1's reconciler already overrides IR role mislabels |
