# Archived refactor docs — empirically validated (2026-05)

These refactor records describe fixes that have been **confirmed
working** on the 2026-05-12 dynamic-run pass (cjson run4/run5,
c-ares run1/run2, lcms run1). Each doc's §3 "Empirical validation"
section was populated with the actual observed signals. The fixes
are settled and no longer require follow-up runs to confirm.

Moved here on 2026-05-12 to declutter the active `docs/` directory
so unvalidated work-items remain visible.

| Doc | Headline validation |
|---|---|
| `data_context_refactor_2026_05.md` | F1 fail-fast triggered on cjson, exposed real upstream bug (ProjectDriverGenerator metadata overwrite); F4/F5 cleanup paths clean |
| `cross_module_review_2026_05.md` | Step 3.5 ordering (build_data_layout before Step 4 grammar) confirmed; no other invariant violations |
| `automaton_refactor_2026_05.md` | EDSM learning works on cjson (2 states) + c-ares (24) + lcms (26); cluster A oracle log visibility confirmed; cluster B caching ran without exception |
| `filter_pipeline_refactor_2026_05.md` | L1-L5 all cluster fixes ran cleanly; entry-point + lifecycle + state-machine analysis produced expected outputs |
| `comprehender_closedloop_refactor_2026_05.md` | Q2 strength gate validated on c-ares (8/10 prefilter VALID vs cjson 0/10 — gate calibration correct); cluster CL/C fixes ran without exception |
| `workflow_refactor_2026_05.md` | is_function_referenced wired through real nm check; AD1 compile_success patch removed and adapter still reports truthfully; UnifiedCodeValidator cgprocessor_path dead-arg dropped; **Improver rollback gate validated on c-ares run2 (gate PASSED — 8.81%→11.21% ratio=1.27 ≥0.85; would-rollback case backed by c-ares run1 0.72 ratio)** |
| `supervisor_validator_refactor_2026_05.md` | UnifiedCodeValidator V1 false-negative caught and fixed in-flight via AST+naive union (commit 21800838); cjson re-validated at 100% target-API coverage |
| `synthesis_refactor_2026_05.md` | Phase H positive-only redesign validated (commit 6c59206b — c-ares run2 emitted=5 / rejected=5 skeletons; cluster A silent-fallback removal confirmed by genuine 5/5 mix per Z3; cluster B HoleFiller deletion + skeleton_for_sequence path validated; cluster C Z3 correctness fixes validated indirectly by the 5 admissions) |

## Where to find updates

If any of these fixes regress in a future run, the per-doc §3
section is the authoritative spec for what should happen. Update
the §3 with new evidence and consider moving the doc back to
`docs/` if the regression is structural rather than transient.

The full per-fix design rationale + rollback recipe is in §1/§2/§4
of each doc. Those sections remain authoritative.

## What stayed in `docs/` (still pending validation)

  - `backend_merge_refactor_2026_05.md` — **LFBackendDriver still
    not invoked in default workflow**. The default skeleton path
    (`_synthesize_skeletons_per_sequence` → `render_skeleton` from
    `skeleton_generator.py`) bypasses LFBackendDriver entirely.
    LFBackendDriver is reachable only via `--generate-drivers` CLI
    (standalone CBFactory mode). To exercise the 6 latent-bug
    fixes (A1-A7), need a `--generate-drivers` run.
  - `ir_refactor_2026_05.md` — IR rendered by `render_skeleton`,
    not LFBackendDriver. The 5/9 IR fixes that depend on
    LFBackendDriver path remain untested empirically.
    `render_skeleton` path uses its own IR rendering subset.
  - `driverenhancer_refactor_2026_05.md` — Same as IR: callback
    stub generation lives inside LFBackendDriver. `render_skeleton`
    path has its own callback handling.
  - `execution_refactor_2026_05.md` — per-stream truncation never
    hit (no big-output trial yet)
  - `agent_refactor_2026_05.md` — 8KB cap never engaged
  - `knowledge_t1_2026_05.md` — T2/T3/§10A/multi-hop decisions
    pending; doxygen median <30% across 3/4 benches → T3-trigger
    fired
  - `knowledge_layer_design_proposal_2026_05.md` — proposal only,
    multiple tiers pending
  - `multihop_reasoning_design_proposal_2026_05.md` — proposal
    only, awaiting design review
  - `driver_vs_baseline_2026_05_12.md` — first §10B emergency-mode
    analysis; ongoing investigation
  - `review_and_fix_log_2026_05.md` — canonical hand-off log
    (kept active)
  - `upstream_liberator_diffs.md` — living
  - `llm_vs_traditional_choices.md` — living
  - `automaton.md`, `merge_drivers.md` — shipped-feature docs
    (not refactor records)
