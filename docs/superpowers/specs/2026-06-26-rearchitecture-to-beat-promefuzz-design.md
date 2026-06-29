# LogicFuzz Re-Architecture to Beat PromeFuzz — Design (2026-06-26)

Driven by the 2026-06-25 source-grounded vs-PromeFuzz audit
([[project_logicfuzz_vs_promefuzz_source_audit]]). Fuses the 2026-06-25 architecture
cleanup blueprint (`2026-06-25-architecture-cleanup-blueprint.md`) and the
spec-guided LLM-render design (`2026-06-25-spec-guided-llm-render-design.md`) into one
re-prioritized program seen through a *competitive* lens.

## Goal

Systematically re-architect LogicFuzz to beat PromeFuzz on **both** axes,
**foundation-first**: (1) measured branch coverage on winnable libs, and (2)
design/realism + low-FP superiority (the threat-model pitch: the untrusted surface is
the DATA fed to entry APIs, not the API call order; coverage is trustworthy only when
drivers are valid).

## Decisions locked in brainstorm (2026-06-26)

1. **Win condition:** both axes, foundation-first. The shared foundation (trustworthy
   measurement + extraction robustness + family-binding generalization + LLM-render)
   serves coverage AND quality.
2. **Learning loop:** build the FULL post-merge CEGAR loop now (match PF's one clean
   win head-on), NOT the minimal FP-memory-only option.
3. **Scope:** minimal 3-lib **head-to-head bar** — libjpeg-turbo (flagship win),
   cjson + c-ares (parity). PLUS deep extraction-robustness for **sqlite3** (SVF
   crash) + **tinygltf** (header-only C++) as must-extract robustness targets. The
   architecture must be **general — validated on the 3, never over-fit** (over-fitting
   to lcms is the exact failure mode the audit flagged).
4. **Approach:** C — **big-bang re-architecture** (build the new 4-layer system as one
   coherent whole), with three NON-NEGOTIABLE guardrails that keep a big-bang
   falsifiable: (a) measurement built first as test infra; (b) the current pipeline
   frozen as the A/B control; (c) component-level tests during the build + a final
   breadth-matched A/B vs the control.
5. **Deterministic render → fallback-only** (SVF-failed / conformance-failed path);
   it stops being the default. Extraction fallback includes the deep blockers.

## Target architecture — 4 honest layers wrapped by the CEGAR loop

```
        ┌──────────────────── CEGAR LEARNING LOOP (NEW subsystem) ────────────────────┐
        │  ingests merged runtime coverage + library-wide crash-constraint/FP memory   │
        │  → re-plans toward uncovered APIs, bans FP-crash idioms, re-renders           │
        ▼                                                                              │
  use-def / typestate ─► APISemanticModel.reconcile ─► Sequence Constructor ─► full SPEC
   (KEEP — the moat)      roles + FAMILIES (NEW:        lifecycle-complete deep      (JSON call-spec;
        │                 generalized off lcms)         chains)                       promoted hole_semantics)
        │                                                                              ▲ gap-direction
        │   ┌─── EXTRACTION ROBUSTNESS (NEW) ───────────────────────────────┐         │
        └──►│ libjpeg lib-discovery · buffer-typedef→INPUT_BUFFER via SVF    │         │
            │ read/write · SVF-fail / header-only fallback (sqlite3,tinygltf)│         │
            └────────────────────────────────────────────────────────────────┘        │
        ▼                                                                              │
   symbolic VALIDATE   (position-indexed lifecycle walk + length-dependency Z3 SAT)    │
        ▼                                                                              │
   LLM RENDER   (Prototyper authors the FULL driver from the spec)                     │
        │        + MANDATORY plan-conformance check (terminal-consumer backbone)       │
        ▼                                                                              │
   A≡B compile-validate + crash-poison/orphan filter + merge (3 gates)                 │
        ▼                                                                              │
   reliable MEASURE   (profdata-first: per-input replay → llvm-profdata merge →        │
        │              llvm-cov export → totals; n_files<2 sanity gate)                │
        └──────────────────── feeds coverage-gap + FP memory back ─────────────────────┘
```

**Each competitive fix maps to the audit gap it closes:**

| New/fixed capability | Audit gap closed | Serves |
|---|---|---|
| Profdata-first MEASURE (#0) | every A/B unfalsifiable today | both (prerequisite) |
| Extraction robustness | D2/D4 — moat fails *worse* where headroom lives (libpng 8.8%, libjpeg blocked) | coverage |
| Family-binding generalization | D3 — valid-by-construction only real on lcms-shaped libs | quality/realism |
| Spec-guided LLM render + conformance | D4 — deterministic render → dead/shallow harnesses | both |
| CEGAR learning loop | D5 + D7 — PF's clean wins (library-wide FP suppression + coverage-feedback) | both |
| ~2000 LOC deletes | inert symbolic theater = paper liability | simplicity/credibility |

## CARRY FORWARD — the moat (off-limits, preserved intact)

- **use-def + typestate substrate** (`usedef.py`, 16 consumers) — flow-sensitive depth PF lacks.
- **Light SVF signal** (`_svf_writes` write/read/is_array/set_by).
- **G2 Sequence Constructor planner core** (`_build_prefix` / `_densify` /
  `repair_sequence_validity` / Typestate self-filter / cross-source) — the validated depth moat.
- **hole_semantics → promoted to the structured SPEC** (serialize the plan, not render C from it).
- **handle-aware role classifier**; **position-indexed lifecycle walk + length-dep Z3 SAT**.
- **A≡B compile-validate + orphan/crash-poison filter** + `traces.json` + `graft_creator_prefix`.
- **Ablation switches** (`DISABLE_*`, `REQUIRE_Z3`, `Z3_MODE`) — paper controls.

## LEAVE BEHIND — dead weight (zero behavior change)

**Correction (inventory-verified 2026-06-29):** the blueprint's "~2000 LOC" was mostly
ALREADY removed in prior commits (`4b593c64`, `12550e8c`, `e75c0cd3`, `7ed8e961`); the
genuine residual was **~420 LOC** (Plan 2, `docs/superpowers/plans/2026-06-29-prune-dead-code.md`).
Critically, several items the blueprint listed as "inert" are **LOAD-BEARING — KEPT, NOT deleted:**
- `IncrementalZ3Solver` push/pop + `Z3GuidedSynthesisController` — the LIVE Z3 synthesis
  engine (soft mode = no *reject*, but the SAT path still builds every skeleton).
- EDSM + PTA + `acceptance_score` — the **primary L4 sort axis** (`coverage_ranker.py`)
  + Comprehender-B prefilter signal; `learn_project_automaton` builds it by default.
- `AutomatonAcceptanceGuard` class — its `is_strong()` gates the Comprehender-B VALID
  prefilter (`comprehender.py`). Only its (already-gone) `admits`/prune arm was inert.
- merge dominance gate (`_apply_dominance`/`dominance_filter`) — drops dominated drivers
  when ≥2 measured reports exist ("0 drops" was a measurement, not a structural no-op).

**Plan 2 actually deleted (~420 LOC):** dead `update_with_traces` (0 callers); the
`LOGICFUZZ_MERGE_REPAIR` opt-in (`llm_repair.py` + wiring); the `_drop_unrunnable` lever;
dead residuals (`generic_opaque_handles`, `_densify` `repeat`, `n_error_variants`) + their
obsolete tests + orphaned imports. **DEFERRED:** the dead automaton-guard arm inside
`IncrementalZ3Solver` (threads through the live controller — revisit in the Z3 plan).

**Already removed in prior commits (do not re-plan):** `AutomatonAcceptanceGuard.admits`;
old per-trial closed-loop + `--closed-loop` CLI; dead `llm_tiebreak` hook; `_exercise_object`;
`_recover_init_handles` read; `ERROR_VARIANTS` emission; graduated/pruned `LOGICFUZZ_*` flag reads.
- **Deterministic `skeleton_generator` render body** (24 `SkeletonVariable` branches,
  no HEAP mode) → shrinks to **spec-emission only**; kept as the
  SVF-failed/conformance-failed fallback ONLY.

## The four foundation capabilities (non-CEGAR)

**① Profdata-first MEASURE** *(blueprint #0 — ALREADY SHIPPED in `ab55eae5`; this
refactor only TEST-LOCKS it)*
`run_extended_fuzzing._export_coverage_from_profdata` exports from the OSS-Fuzz-produced
`dumps/merged.profdata` via `llvm-cov export -summary-only` (`data[0].totals`) — the
primary path inside `_measure_coverage`, bypassing the HTML-report step that hangs on
merged multi-TU harnesses. Degeneracy gate is **empty-totals** (`lines.count==0 and
branches.count==0` → reject), deliberately NOT an `n_files<2` file-count floor (which
would false-reject a single-source lib like cJSON.c — `run_extended_fuzzing.py:1047-1052`).
Fails open to the live libFuzzer edge count. The only remaining work was **test lock-in**
(`tests/test_profdata_measurement.py`, 7 characterization tests). The per-input
`-runs=0` replay + explicit `llvm-profdata merge -sparse` the blueprint imagined are
unneeded — the OSS-Fuzz `coverage` command already produces the merged profdata.

**② Extraction robustness** *(audit-new)* — three fixes:
- **(a) buffer-typedef → INPUT_BUFFER via SVF read/write** — replace the name-match
  `_BUFFER_HINT_PATTERNS` (`usedef.py:108`, only `{char*,uint8_t*,unsigned char*,void*}`)
  with SVF read/write evidence + IR-lowered-type handling in `_find_buffer_size_positions`.
  The single biggest depth lever (turns libpng-class dead harnesses live).
- **(b) libjpeg lib-discovery** — locate `.a` in the versioned build dir (unblocks the flagship).
- **(c) SVF-fail / header-only graceful fallback** — no silent fail-open-to-0-skeletons;
  degrade to a consumer-AST / clang-only plan path. **Includes the deep blockers
  sqlite3 (SVF crash) + tinygltf (header-only C++ TU-synthesis)** as must-extract
  robustness targets.

**③ Family-binding generalization** *(audit-new)*
Derive handle *families* **structurally** from `handle_typedef_recovery`, NOT the
`"cms"` substring in `validity_contract._family`. Named-struct handles (`cJSON*`,
`ares_channel`, jpeg structs) get family-correct producer-prepend + type-exact binding
*generally*. Validated on all 3 libs (three different handle shapes).

**④ Spec-guided LLM RENDER + conformance check** *(blueprint #4 — greenlit by libpng
validation: 0 stack-overflows vs 19,946)*
Planner emits a JSON **call-spec** (promoted `hole_semantics`: ordered sequence +
per-arg intent + contracts). Prototyper authors the *complete* driver. **Mandatory
plan-conformance check** — the **terminal-consumer backbone** signal (prototyped,
`plan_conformance.py`, 6/6 tests): reject if the authored driver dropped the planned
deep terminal consumer (catches both shallow-bail and parser-revert) → regenerate ≤N →
fallback to deterministic render.

All four are **type/structure-driven, never keyed on library names** — the over-fit
guard, enforced by validating each on cjson+c-ares+libjpeg.

## The CEGAR learning loop (the biggest new subsystem)

Post-merge, cross-round, gap-directed — categorically different from the deleted
per-trial closed-loop (re-ran near-identical drivers, saturated in 1 iteration,
discarded output).

**Loop body (each round, after merge + trustworthy MEASURE):**
1. **MEASURE** merged coverage → covered-API set + uncovered-branch map + crash signatures.
2. **GAP** = uncovered public APIs + uncovered branches inside *reached* functions
   (reuses `coverage_gap.compute_gap_apis`, G5).
3. **FP MEMORY** — for each driver-bug/FP crasher (`crash_frame.classify_crash_frame`),
   extract the offending idiom → add to a **library-wide ban list** (e.g.
   consumer-on-NULL-handle, double-free of T). PF's library-wide crash-constraint
   suppression (D5). **Library-wide + persisted to `state/`** — carries across rounds
   AND across runs of the same lib.
4. **RE-PLAN toward the gap** — feed gap APIs to the Sequence Constructor as
   gap-directed targets; construct *new* sequences for uncovered APIs/subsystems,
   honoring the FP ban list.
5. **RE-RENDER (LLM, conformance-checked) + re-merge.**
6. **Terminate** when gap empty, OR K consecutive rounds add < ε new merged branches, OR
   budget exhausted.

**The honesty gate (why the OLD loop was a paper liability — fixed structurally):**
- Every round records **marginal new merged branches**; a <ε round is logged and ends
  the loop — no pretending it helped.
- The **entire loop is A/B'd**: 1-round vs N-round on the trustworthy #0 metric,
  breadth-matched. Ships **default-ON ONLY if N-round > 1-round on merged branches with
  recorded evidence**; otherwise opt-in + honest "it didn't help" report. Structural
  guard against shipping inert feedback machinery again.

**Reuse, not greenfield:** wires `coverage_gap.py`, `coverage_memory.py` (extended from
single-iter MVP to cross-round), `crash_frame.py`, and the Constructor's gap-directed
target path into a real loop. Genuinely new: the round orchestrator + FP ban-list
memory + marginal-gain termination/telemetry.

## Build structure (big-bang, but falsifiable)

- **Phase 0 — test infrastructure first (the only forced ordering).** #0 profdata-first
  measurement is ALREADY SHIPPED (`ab55eae5`); this phase only **verifies + test-locks**
  it (`tests/test_profdata_measurement.py`) and **freezes the current pipeline as the A/B
  control** (tag `pub-llm` HEAD). The rebuild is unmeasurable without a trustworthy metric
  and a baseline to beat — both now in hand.
- **Phase 1 — build the new architecture as one coherent whole:** 4 layers + deletes +
  4 foundation capabilities + CEGAR loop. **Component-level unit tests per unit** (spec
  emission; family-binding across 3 handle shapes; buffer-typedef→INPUT_BUFFER;
  plan-conformance; profdata measure; CEGAR orchestrator + FP memory + termination).
- **Phase 2 — validate:** final **breadth-matched A/B vs the frozen control** on
  cjson + c-ares + libjpeg-turbo (trustworthy metric); the **CEGAR 1-round-vs-N-round
  A/B**; **extraction-robustness verification** on sqlite3 + tinygltf (must produce
  skeletons, not 0).
- **Phase 3 — headline campaign:** matched 24h merged run on libjpeg-turbo (+ others)
  for the RQ1 comparison numbers.

## Success criteria — what counts as "beat PromeFuzz"

| Gate | Bar | Status |
|---|---|---|
| Measurement trustworthy | #0 already shipped (`ab55eae5`) + test-pinned; empty-totals reject (not n_files<2); A≡B preserved | done |
| **libjpeg-turbo (flagship WIN)** | merged > PF **4,274** under matched campaign (have 3,396 from one driver) | strong |
| **cjson (parity)** | within noise of PF **899** (tie at 886 today) | high |
| **c-ares (parity)** | substantial gap-closure under 24h toward PF **6,106** | ⚠️ STRETCH — hardest of the 3 (near-saturated); honest gap-report if not reached, do NOT block the rebuild on it |
| FP rate | ≤ PF on all 3 (crash-feasibility measured) | medium |
| No over-fit | family-binding + buffer-typedef fire on all 3 shapes; ZERO library-name keys | must-pass |
| CEGAR helps | default-ON only if N-round > 1-round; else opt-in + honest report | gated |

**Defensible headline:** libjpeg-turbo win + cjson parity + low-FP + general (no
over-fit) + working measurement. c-ares parity is an explicit stretch with an
honest-gap-report escape so the program doesn't quietly fail on an over-ambitious bar.

## Risks & mitigations

- **#0 measurement** already shipped (`ab55eae5`) and now test-pinned
  (`tests/test_profdata_measurement.py`); residual risk is a regression (e.g. someone
  re-adding a file-count floor), guarded by the single-source-library pin test.
  Fallback: surviving-`merged.profdata` export is the safety net.
- **LLM-render A-design revert** (validated risk: free LLM reverts deep
  object-construction to shallow parser-entry). Mitigation: mandatory
  terminal-consumer-backbone conformance check + deterministic-render fallback + gated
  A/B before default.
- **CEGAR loop = highest research risk** (the old one was inert). Mitigation: the
  honesty gate (marginal-gain telemetry + 1-vs-N A/B gates the default).
- **Big-bang risk** (nothing works until late). Mitigation: the 3 guardrails
  (measurement-first, frozen control, component tests + final A/B).
- **Over-fit to the 3 validation libs.** Mitigation: all fixes type/structure-driven,
  zero name-keys, validated across 3 distinct handle/buffer shapes; sqlite3/tinygltf
  extraction as additional generality probes.
- **Scope expansion** (deep extraction blockers added). Acknowledged cost: sqlite3 +
  tinygltf are distinct multi-day fixes beyond the 3-lib bar.

## Two non-code corrections to land alongside (paper credibility, from the audit)

- Retract the gcov-vs-llvm-cov "not comparable" caveat (both are llvm-cov covered
  branches); fix the lcms target (4,560 covered, not 9,040 total).
- Rewrite `docs/contributions_and_related_work.md:145/451/468` "PF has no dependency
  substrate" → "no symbolic handle-flow / produces→consumes dependency model" (PF's
  `InfoRepository` IS a dependency graph — the blanket claim is a strawman).

## Relations

[[project_logicfuzz_vs_promefuzz_source_audit]] (the driving audit),
[[project_promefuzz_table2_coverage_targets]] (the corrected targets),
[[project_architecture_cleanup_blueprint]] + `2026-06-25-architecture-cleanup-blueprint.md`,
`2026-06-25-spec-guided-llm-render-design.md` (parent #4),
[[project_input_buffer_ir_type_deadharness]] (the buffer-typedef root cause),
[[project_symbolic_overfit_audit]] (the family-generalization rationale).
