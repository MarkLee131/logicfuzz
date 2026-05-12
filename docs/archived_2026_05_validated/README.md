# Archived refactor docs — empirically validated (2026-05)

These refactor records describe fixes that have been **confirmed
working** on the 2026-05-12 dynamic-run pass (cjson run4, c-ares
run1, lcms run1, cjson run5 post-Phase-H-fix). Each doc's §3
"Empirical validation" section was populated with the actual
observed signals. The fixes are settled and no longer require
follow-up runs to confirm.

Moved here on 2026-05-12 to declutter the active `docs/` directory
so unvalidated work-items remain visible.

| Doc | Headline validation |
|---|---|
| `data_context_refactor_2026_05.md` | F1 fail-fast triggered on cjson, exposed real upstream bug (ProjectDriverGenerator metadata overwrite); F4/F5 cleanup paths clean |
| `cross_module_review_2026_05.md` | Step 3.5 ordering (build_data_layout before Step 4 grammar) confirmed; no other invariant violations |
| `automaton_refactor_2026_05.md` | EDSM learning works on cjson (2 states) + c-ares (24) + lcms (26); cluster A oracle log visibility confirmed; cluster B caching ran without exception |
| `filter_pipeline_refactor_2026_05.md` | L1-L5 all cluster fixes ran cleanly; entry-point + lifecycle + state-machine analysis produced expected outputs |
| `comprehender_closedloop_refactor_2026_05.md` | Q2 strength gate validated on c-ares (8/10 prefilter VALID vs cjson 0/10 — gate calibration correct); cluster CL/C fixes ran without exception |
| `workflow_refactor_2026_05.md` | is_function_referenced wired through real nm check; AD1 compile_success patch removed and adapter still reports truthfully; UnifiedCodeValidator cgprocessor_path dead-arg dropped |
| `supervisor_validator_refactor_2026_05.md` | UnifiedCodeValidator V1 false-negative caught and **fixed in-flight** via AST+naive union (commit 21800838); cjson re-validated at 100% target-API coverage |

## Where to find updates

If any of these fixes regress in a future run, the per-doc §3
section is the authoritative spec for what should happen. Update
the §3 with new evidence and consider moving the doc back to
`docs/` if the regression is structural rather than transient.

The full per-fix design rationale + rollback recipe is in §1/§2/§4
of each doc. Those sections remain authoritative.

## What stayed in `docs/` (still pending validation)

  - `backend_merge_refactor_2026_05.md` — LFBackendDriver still
    not invoked (now blocked at Z3 layer after Phase H fix
    unblocked it; new finding under investigation)
  - `ir_refactor_2026_05.md` — IR unreachable (depends on
    LFBackendDriver being invoked)
  - `driverenhancer_refactor_2026_05.md` — DriverEnhancer
    unreachable (depends on skeleton emission)
  - `synthesis_refactor_2026_05.md` — Z3 correctness fixes
    unreachable; Phase H now passes candidates through but Z3
    rejects them with empty violations list (new finding)
  - `execution_refactor_2026_05.md` — per-stream truncation
    never hit (no big-output trial yet)
  - `agent_refactor_2026_05.md` — 8KB cap never engaged
  - `knowledge_t1_2026_05.md` — T2/T3/§10A decisions pending
  - `knowledge_layer_design_proposal_2026_05.md` — proposal only
  - `review_and_fix_log_2026_05.md` — canonical hand-off log
    (kept active)
  - `upstream_liberator_diffs.md` — living
  - `llm_vs_traditional_choices.md` — living
  - `automaton.md`, `merge_drivers.md` — shipped-feature docs
    (not refactor records)
