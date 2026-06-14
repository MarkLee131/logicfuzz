# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Knowledge-Driven Neuro-Symbolic Fuzz Driver Generation over Structured API Program Spaces.

**Generation stage**: see `docs/generation.md` (source of truth for driver
generation). The pipeline is reconcile-then-construct — build an
`APISemanticModel` first (IR ⊕ doc ⊕ usage), then *construct* lifecycle-
complete sequences from it, so candidates are valid by construction and there
is no repair stage. (The old "classify-then-repair" flow — Phase A repair +
Tier-1 F1–F4 — was deleted; it band-aided the missing model downstream.)

## Commands

```bash
# Run on a benchmark
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Extract APIs only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Generate drivers with CBFactory only (no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Phase G (existing): closed-loop CBFactory feedback (re-synthesise with grown automaton)
python3 run_logicfuzz.py -y comparison/cjson.yaml --closed-loop --closed-loop-iters 3 \
                        --closed-loop-early-stop 0

# A/B: disable G2 model-driven construction, fall back to random-walk grammar
LOGICFUZZ_DISABLE_G2_CONSTRUCT=1 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Generation features now DEFAULT-ON (gates removed 2026-06 — flag cleanup):
# factory chain (opaque void*-return producer recovery), density + hard NULL-guard
# (coupled; density-only is ablation-proven harmful), max-coverage diversity
# selection, real seed-corpus routing (*.icc/*.it8/… by parser-entry API + magic),
# deterministic lean crash triage + skip per-driver optimize, typedef-handle
# recovery. Measured lcms 30s (density+guard, now default): 66→206 br, FP 1→0.
#
# Remaining knobs — tuning values + A/B kill-switches (the only LOGICFUZZ_* left):
#   LOGICFUZZ_TOP_K=N             skeleton/driver count = the UNION-breadth lever
#                                 (default filter_top_k=10; needs NO_CACHE=1 to
#                                 regen skeletons). Target ≈ PromeFuzz drivers/2.5.
#                                 NOTE: under PORTFOLIO=complete (default) the fixed
#                                 top_k cap is SUPERSEDED by coverage-complete
#                                 selection — top_k only bounds the legacy
#                                 PORTFOLIO=off path.
#   LOGICFUZZ_PORTFOLIO=complete  Coverage-COMPLETE portfolio selection (DEFAULT-ON)
#                                 — the fundamental fix to the parser-entry-bias
#                                 root cause (lcms: global-rank→top_k let
#                                 parser-entry chains crowd out object-construction
#                                 subsystems; 93 creators → 17 anchored → 8 drivers,
#                                 Pipeline/MLU/NamedColor/ToneCurve 0-driver).
#                                 `subsystem_clusters` partitions the API surface by
#                                 primary handle type; Step-10 selection guarantees
#                                 >=1 lifecycle-valid driver PER subsystem cluster
#                                 (Phase 1 cover) + a bounded depth pass (Phase 2),
#                                 and Step-5h lets the full constructed pool through
#                                 (skeleton gen is Z3+render, no LLM → cheap; LLM
#                                 cost scales with KEPT drivers only). Offline sim
#                                 (real lcms model): 8 → ~48 drivers, every
#                                 object-construction subsystem covered. Modes:
#                                 complete (cover+depth) | minimal (cover only) |
#                                 off (legacy fixed top_k round-robin = A/B control).
#                                 `subsystem_clusters.py` + `coverage_ranker.
#                                 _coverage_complete_select` + data_context Step 5h/10.
#   LOGICFUZZ_PORTFOLIO_DEPTH=F   depth multiplier for PORTFOLIO Phase 2 (default
#                                 0.5 → depth drivers ≈ 0.5 × cover drivers).
#   LOGICFUZZ_DENSE_MAX_EXTRA=N   cap extra APIs appended per chain (default 8 →
#                                 ~7.7 APIs/seq lcms = PromeFuzz parity).
#   LOGICFUZZ_DENSE_COOCCUR=0     density extends ONLY handle-sharing (drop the
#                                 automaton-co-occurrence source; default on).
#   LOGICFUZZ_DENSE_REPEAT_CONSUMER=1   density also repeats a handle's CONSUMER
#                                 (default off) — thickens chains by re-invoking
#                                 consumers, not just appending new APIs.
#   LOGICFUZZ_STRICT_ORDERING=1   revert B graceful degradation (drop orphan
#                                 USE_BEFORE_INIT instead of keeping as a hole).
#   LOGICFUZZ_DISABLE_{G2_CONSTRUCT,DRIVER_TRACES,SEQFACTS,LLM_ROLES}=1
#                       A/B kill-switch for that default-on stage. (BASELINE_RECOVERY
#                       was removed with the §10B optimize subsystem —
#                       `prototyper.baseline_recovery_text` is now a permanently-empty
#                       slot, no env gate. TYPEDEF_RECOVERY's gate was also removed:
#                       typedef recovery is now unconditionally always-on
#                       (`data_context.py` Step 5g region), no kill-switch.)
# New opt-in (gated, A/B pending — start gated like factory/diversity/lean did,
# default-on once a coverage A/B proves the gain). FUZZABLE_HOLES + VALUE_FEEDBACK
# GRADUATED to default-on (Phase 1, 2026-06 — see their notes below):
#   LOGICFUZZ_ERROR_VARIANTS=1    T11: emit error-shape skeleton variants (double-
#                                 free / use-after-destroy / skip-init) so library
#                                 error branches become reachable (the LLM still
#                                 fills only leaf holes). Cap LOGICFUZZ_ERROR_VARIANTS_MAX.
#   LOGICFUZZ_VALUE_FEEDBACK       T12: capture filled hole values → coverage_memory,
#                                 then pin the deepest-coverage ones into the SAME
#                                 skeleton's holes on the NEXT run (cross-run). NOW
#                                 DEFAULT-ON (Phase 1; opt-out =0) — advisory, a
#                                 fresh project with no coverage_memory is a no-op.
#   LOGICFUZZ_FORMAT_INFER=1      T10 (opt-in; Phase 4.1 will default-on): when no
#                                 real seed matches a parser-entry driver, synthesize
#                                 front-gate-passing seed(s) from inferred magic.
#                                 Phase 1 wired seed-sample + project header #define
#                                 magics into infer_spec (generalises past the
#                                 5-format registry) + emits a DIVERSE corpus (k≥3
#                                 varied bodies), not one zero-body seed.
#   LOGICFUZZ_CROSS_PROJECT=1     T7: for a resource-thin library, retrieve
#                                 structurally-similar drivers (corpus
#                                 LOGICFUZZ_XPROJ_CORPUS, default
#                                 extracted_fuzz_drivers/; same-project first) and
#                                 inject compressed CALLSPEC-style hints.
#   LOGICFUZZ_SCOPED_GUARDS=1     B+D: render the creator NULL-guard PER dependency
#                                 COMPONENT (nested-if) instead of one whole-driver
#                                 `if(!parser)return0`. `sequence_constructor.
#                                 _dependency_components` partitions a sequence;
#                                 a producer's guard wraps ONLY its handle-consumers,
#                                 so an INDEPENDENT API (doesn't consume the parser's
#                                 handle) renders OUTSIDE the guard and runs even when
#                                 the parser returns NULL on random fuzz input.
#                                 Measured (controlled single-file): +523 br (12.6×)
#                                 when the parser fails; ≈0 when valid seeds let it
#                                 succeed (gain is conditional on parser-failure, the
#                                 common fuzz case). PromeFuzz has no dependency model.
#   LOGICFUZZ_FUZZABLE_HOLES=1    Tier 1: render tunable CONFIG holes (enum/scalar/
#                                 float) as FUZZ_DERIVE 'derive from the fuzz input'
#                                 directives instead of a hardcoded constant — so the
#                                 fuzzer SWEEPS the parameter, not one fixed value. The
#                                 symbolic layer exposes ONLY tunable DOFs (handles/
#                                 magic/length stay FIXED). Scalar/float holes invoke
#                                 the LLM's OWN value-domain judgement (choose a
#                                 SEMANTICALLY VALID range — chromaticity≈0..1,
#                                 gamma≈0.1..5, temp≈1000..25000 — then derive; do NOT
#                                 slap an arbitrary modulus); enum holes index a fuzz
#                                 byte into the legal constant set. This is PromeFuzz's
#                                 *automatic* depth mechanism (the LLM's trained
#                                 knowledge) made explicit — NOT hand-written per-lib
#                                 api_hints. Addresses the branch-DEPTH gap vs PromeFuzz
#                                 (confirmed: cmsBuildParametricToneCurve type+params
#                                 fuzz-derived → cmsgamma.c 84→121 br, +44%, same
#                                 budget). Mechanism is C/C++-aware: intent is
#                                 language-agnostic; C driver → index data[N] (NOT
#                                 FuzzedDataProvider, C++-only), C++ → FuzzedDataProvider
#                                 (prompt-side, prototyper_prompt{,_c}.txt + _system).
#                                 NOW DEFAULT-ON (Phase 1, 2026-06; opt-out
#                                 LOGICFUZZ_FUZZABLE_HOLES=0) — `_fuzzable_holes()`
#                                 default True, like factory/diversity/density. The
#                                 +44% is shipped; the coverage A/B uses =0 as the
#                                 control. `hole_semantics._arg_intent`.
#   --- Phase 1 knowledge levers (2026-06; gated default-OFF, A/B pending) ---
#   LOGICFUZZ_OBJCONSTRUCT_FIRST=1  L1: prefer object-construction (data_buildable)
#                                 chain roots over parser-entry roots (REBALANCES the
#                                 existing parser-first bias); keeps >=1 parser-rooted
#                                 driver per parser-only subsystem (cluster-cover
#                                 invariant). THE top coverage lever — lcms parser
#                                 drivers plateau ~79 edges vs PromeFuzz 83/141
#                                 object-construction. `sequence_constructor._root_kind`
#                                 + _creator_key/_recovered_key + data_context strand/
#                                 bucket order.
#   LOGICFUZZ_VALUE_DOMAINS=1      L6: knowledge DICTATES leaf-hole values — extend the
#                                 legal-constant mine to 4cc signature #defines + FORBID
#                                 `(Enum)(data%N)` arithmetic (index a fuzz byte into the
#                                 mined legal SET); carry documented @param ranges into
#                                 `_arg_intent` instead of LLM-guessing. `named_constants`
#                                 + `hole_semantics._arg_intent` + `api_semantic_model`.
#   LOGICFUZZ_ORDERSETS=1         L7: normalize+Set-Cover-minimize the raw consumer-trace
#                                 sequences (already extracted) before they seed
#                                 construction — pure-Python port of PromeFuzz
#                                 OrderSet/minimize. `liberator_adapter/analysis/order_sets.py`
#                                 wired at `data_context` (_accept).
#   LOGICFUZZ_API_FLOOR=1         L7: ALL-COVER floor — a greedy set-cover pass in
#                                 `coverage_ranker._coverage_complete_select` guarantees
#                                 every constructable API appears in >=1 selected sequence
#                                 (per-API, not just per-cluster); surfaces
#                                 `api_floor_residual_count` (the binding-layer tail).
#   LOGICFUZZ_SKIP_COMPILE_VALIDATE=1   opt OUT of the merge compile-validation gate
#                                 (default-on, fail-open): the merge ships only drivers
#                                 that compile under the real coverage-build flags
#                                 (`tools/merge_drivers/compile_validate.py`).
#   --- Driver DECOUPLING / DE-DUP levers (2026-06; gated default-OFF, A/B pending) ---
#   Spec: docs/superpowers/specs/2026-06-14-driver-decoupling-dedup-design.md
#   Plan: docs/superpowers/plans/2026-06-14-driver-decoupling-dedup.md
#   Motivation: generated drivers overlapped too much → merge gained little. Two
#   channels: API-SET overlap (shared prefix/densifier/destroyer manufactured at
#   construction, passed through by exact-tuple dedup, not penalized by the
#   ROUND-ROBIN depth selector that actually ships ~half the portfolio) and
#   VALUE/PATH overlap (selection blind to filled values). Fixes are deterministic
#   /symbolic; the one doc/LLM touch (B-2 VALID guard) CONSUMES an existing
#   Comprehender Stage-B verdict (no new LLM calls).
#   LOGICFUZZ_MARGINAL_DEPTH=1    B-1: the data_context Step-10 depth pass picks
#                                 drivers by MAX marginal new-API coverage (shared
#                                 `coverage_ranker.select_marginal`) instead of bucket
#                                 round-robin — the headline fix (round-robin chose
#                                 ~0.5× of the portfolio with NO overlap check).
#   LOGICFUZZ_DEDUP_FINGERPRINT_VALUE_DOMAIN  (reserved) Layer-C value-domain slot;
#                                 currently the value-domain signature is ALWAYS part of
#                                 the fingerprint (`driver_fingerprint.py`) so B-2/B-3
#                                 keep doc-distinct value variants apart by default.
#   LOGICFUZZ_DENSE_PARTITION=1   A-2a: sibling chains sharing a handle set take DISJOINT
#                                 ranked slices of the densifier candidate pool (rotate by
#                                 sibling_rank) → different suffixes, higher portfolio
#                                 breadth (`sequence_constructor._densify`).
#   LOGICFUZZ_DEDUP_WORKFLOW_PARTITION=1  A-2b: group densifier candidates by co-occurrence
#                                 workflow (`_workflow_clusters`, connected components of
#                                 the accepting-paths cooccur graph) and rotate WHOLE
#                                 clusters across siblings so a coherent workflow is never
#                                 split; `_rank` gains `workflow_affinity` AFTER `sat`
#                                 (lifecycle-satisfiability still wins). Workflow source =
#                                 accepting_paths (already wired); idioms.json is code
#                                 patterns, not API chains.
#   LOGICFUZZ_PAIRWISE_DEDUP=1 / LOGICFUZZ_PAIRWISE_TAU=0.8  B-2: drop a near-twin skeleton
#                                 whose full-fingerprint similarity to a kept one exceeds
#                                 tau (`driver_dedup.pairwise_dedup_skeletons`). Similarity
#                                 is value-domain-guarded (different value domain ⇒ 0.0 ⇒
#                                 never dropped).
#   LOGICFUZZ_DEDUP_SEMANTIC_GUARD=1  B-2 guard: never drop a sequence Comprehender Stage-B
#                                 marked VALID in favor of a SUBOPTIMAL near-twin (consumes
#                                 existing verdicts; no new LLM calls).
#   LOGICFUZZ_SUBSET_ELIM=1       B-3: drop a skeleton whose fingerprint is a strict
#                                 same-value-domain subset of another's, BEFORE B-2
#                                 (`driver_dedup.subset_eliminate_skeletons`).
#   LOGICFUZZ_DIVERSIFY_PRODUCERS=1  A-1/A-1b/A-3: when a handle has >1 creator/destroyer,
#                                 rotate which one each sibling chain uses (deterministic
#                                 per-handle round-robin in `_build_prefix` /
#                                 `_closing_destroyers`) so the portfolio exercises the full
#                                 producer/destroyer set.
#   (Always-on, cheap) Layer E redundancy telemetry → results/<project>/static_analysis/
#   `redundancy_telemetry.json` (`portfolio_redundancy`): mean pairwise API Jaccard +
#   disjointness (=union/total). The A/B oracle — lower jaccard / higher disjointness ⇒
#   better-decoupled portfolio. D-1 (dynamic edge-set marginal) is DEFERRED (needs a
#   preflight→selection feedback edge; see plan Phase 4).
#   LIBERATOR_SVF_TIMEOUT_SECS=N  SVF pointer-analysis WALL-TIME cap (default 1800s;
#                                 raised from 600). Measured 2026-06: libtiff/libvpx
#                                 are TIME-bound (timed out at 7200s, only 4.5/7.7GB
#                                 RAM) — set =14400 (4h) for those; one-time + disk-
#                                 cached on success.
#   LIBERATOR_SVF_MEM_GB=N        SVF MEMORY cap (RLIMIT_AS, GB; default 0=off) via
#                                 preexec_fn. A non-converging analysis fails its OWN
#                                 malloc → std::bad_alloc → clang-only fallback,
#                                 instead of OOM-ing a shared host. Validated on libucl
#                                 (=48 → bad_alloc at ~37GB RSS/virtual>48GB, graceful;
#                                 libucl is the pathological non-converging case).
#   LOGICFUZZ_{Z3_MODE,CONSTRUCT_MODE,NO_CACHE,TRIAGE_INCONCLUSIVE,
#              TRIAGE_PREFIX_LEN,DRIVERS_ROOT,FI_ENDPOINT,BINDING_TELEMETRY}   config values.
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_TOP_K=56 \
  python3 run_logicfuzz.py -y comparison/lcms.yaml --merge-drivers

# Synthesize a multi-task harness from successful trials at the eval tail
python3 run_logicfuzz.py -y comparison/cjson.yaml --merge-drivers

# Evaluation profile: bundles --closed-loop + --merge-drivers
python3 run_logicfuzz.py -y comparison/cjson.yaml --eval

# Multi-hop reasoning Mode A (Prototyper); opt-in
python3 run_logicfuzz.py -y comparison/cjson.yaml --multihop-prototyper

# Knowledge-layer priors (Phase B / T1) are now DEFAULT-ON — the former opt-in
# flags --use-doxygen-priors / --use-readme-purpose were REMOVED (behavior lives
# in FuzzingContext.prepare() defaults: use_doxygen_priors / use_readme_purpose).

# Control parallelism
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml

# Code quality
pylint src/ && pyright src/
pytest tests/   # 375 collected regression tests as of 2026-06-11

# Extended fuzzing evaluation (24h)
python scripts/run_extended_fuzzing.py -p re2 -f results/output-re2-project/fuzz_targets/02.fuzz_target -d 86400
```

`--num-samples` is auto-resolved at runtime to `len(skeleton_drivers)`
(one trial per Z3-validated skeleton). See `run_single_fuzz.py:_fuzzing_pipelines`.

## Docs

**Documentation map** — 5 docs, each the single source of truth (SSOT) for its
topic; everything else cross-references. Every other doc points here for these
topics, never re-explains them.

| Doc | SSOT for (owns) |
|-----|-----------------|
| `README.md` | User entry: what it is, install, quick-start, commands, supported projects, output. |
| `CLAUDE.md` (this file) | Agent operational guide: the `LOGICFUZZ_*`/`LIBERATOR_*` **flag/gate reference**, the **file/component map**, **design principles**, the **Implementation-Flow Step list**, **Open TODOs**, **Failed Attempts/Lessons**, and the high-level **architecture map**. |
| `docs/generation.md` | **Driver-generation pipeline.** G1–G5, the two handle-recovery passes, sequence construction, hole semantics, merge + coverage measurement (compile-validation gate, edge-weighted dispatch, cov-build fix), build-cache, honest verdicts, roadmap + open decisions. Start generation work here. |
| `docs/knowledge_layer.md` | **Comprehender + project-adaptive automaton.** Two-stage deterministic-first knowledge layer (~70× cheaper); automaton mechanics (state vector, EDSM merge, `AutomatonArtifact` surface, persistence, Phase G closed loop); preflight-as-Liberator-seed-oracle. |
| `docs/contributions_and_related_work.md` | **Innovations pitch + baseline comparison.** 3 innovations vs prior work, objective comparison vs PromeFuzz (neural) and Liberator (symbolic), attribute matrix, and the per-LLM-call-site rationale (where we use LLM, what we considered, why). |

Historical proposals and refactor logs live in git history (`git log --grep`).

## Architecture

```
run_logicfuzz.py → FuzzingContext (SSOT) → FuzzingWorkflow (LangGraph) → Evaluation
                         ↑                        ↓
              Static Analysis (Liberator)    Agent System
                         │
            ┌────────────┴────────────┐
            │                         │
   Project-Adaptive Automaton   Knowledge Layer
   (analysis/ static traces →   (knowledge/ comprehender +
    PTA → EDSM → Artifact)       Phase B idiom distiller)
            │                         │
            ▼                         ▼
   APISemanticModel (G1) ◀── reconcile IR⊕doc/naming⊕usage
            │
            ▼
   Sequence Constructor (G2)   ── creator→mutator*→consumer→destroyer
   (gap-directed targets, G5;      lifecycle-complete by construction
    prepend to grammar floor;      ranked by gap-hits then reachability
    Typestate self-filter)         (G3+G5)
            │
            ▼
       Z3 confirm (type/var only — lifecycle correct by construction)
            │
            ▼
       skeleton_drivers + value-intents (G4) → trials × N → merge_drivers
            │
            ▼
       Phase C IterationSnapshot → coverage_memory.json
```

### Workflow State Machine

```
COMPILATION:  prototyper → build → [fail] → fixer (×3) → END
                                 → [ok]  → OPTIMIZATION

OPTIMIZATION: execution → [crash] → crash_analyzer → feasibility → END/fixer
                        → [ok]    → END
```

(There is no per-driver coverage-optimize loop: the `coverage_analyzer` →
`improver` + §10B `baseline_diff_analyzer` subsystem was **removed** — breadth
comes from many-drivers + merge + gap-direction, not per-driver LLM refinement.
A clean build+run ends the trial. The *crash* LLM path is unaffected.)

Per-trial caps live as module constants at the top of
`src/workflow/nodes/supervisor.py` (compilation retries, fixer cap,
total build failures, node-visit loop detection). Read them there;
duplicating here just rots.

### Agent System (`src/agents/`)

| Agent | Tools | Purpose |
|-------|-------|---------|
| Prototyper | - (context pre-fetched) | Generate initial driver. Reads `library_purpose`, `protocol_templates`, `sequence_invariants`, `skeleton_drivers[(N-1) % K]`, **Phase B idioms** |
| Fixer | BashExecuteTool | Fix compilation errors with error triage |
| CrashAnalyzer | BashExecuteTool, GDBExecuteTool | Determine if crash is driver bug or real bug |
| CrashFeasibilityAnalyzer | - | Determine if crash is feasible/real |
| Comprehender (non-LangGraph stage) | LLM batched | A: per-API usage + library purpose. B: per-sequence semantic verdict |

(The per-driver optimize agents — CoverageAnalyzer / Improver / BaselineDiffAnalyzer
— were removed; see the state machine note above and Failed Attempts.)

**Tool Consolidation**: All introspector-derived context (signatures,
cross-refs, type defs, headers, tests, debug types) is pre-fetched
into `FuzzingContext` before agent turns. Remaining LangGraph tools:
- `BashExecuteTool` (`src/tools/execution.py`): unified bash, 8KB output truncation
- `GDBExecuteTool` (`src/tools/execution.py`): scripted GDB session for crash triage

### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| FuzzingContext | `src/context/data_context.py` | Immutable SSOT |
| Supervisor | `src/workflow/nodes/supervisor.py` | Agent routing, phase management |
| ToolCallingMixin | `src/agents/tool_calling_mixin.py` | ReAct loop |
| UnifiedCodeValidator | `src/utils/unified_validator.py` | Single-pass validator (fake-defs, internal APIs, language mismatch, hallucination) |
| Closed-loop (Phase G existing) | `src/closed_loop.py` | Re-runs L4+CBFactory with `update_with_traces` evidence |
| CBFactory | `liberator_adapter/driver/factory/constraint_based/` | Z3-guided driver synthesis |
| Use-def + typestate | `liberator_adapter/analysis/usedef.py` | `APIEffect` (USE/DEF/KILL), `UseDefGraph`, `Typestate` interpreter; **caller-alloc INIT producer channel** (`annotate_svf_writes` + `extract_produced_handles`) recovers in-place initializers (`deflateInit_(z_stream*)`) as creators, SVF-write-gated via `conditions.json`. Detail: `docs/generation.md` G1. |
| Project automaton | `liberator_adapter/analysis/project_automaton.py` | `AutomatonArtifact` |
| **APISemanticModel** (G1) | `liberator_adapter/analysis/api_semantic_model.py` | `reconcile()` → per-API role+arg semantics+evidence; role authority (demotes ConditionManager); 0 LLM; Step 5g. Detail: `docs/generation.md`. |
| **Sequence Constructor** (G2) | `liberator_adapter/analysis/sequence_constructor.py` | `construct_sequences()` builds lifecycle-complete chains, **merged with** the grammar floor at Step 5h. A/B: `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1`. B graceful degradation keeps orphan-handle sequences (kill-switch `LOGICFUZZ_STRICT_ORDERING`); `_densify()` thickens chains (**default-on**; tune via `LOGICFUZZ_DENSE_MAX_EXTRA`/`_COOCCUR`); factory-chain opaque-producer recovery (**default-on**). |
| **Hole Semantics** (G4) | `liberator_adapter/analysis/hole_semantics.py` | `annotate_skeletons()` attaches per-arg value intents at Step 10b (rendered into the hole prompt). `_hard_nullguard()` (**default-on**) escalates ret-contract to `MUST-GUARD` + opaque factory-chain hint. |
| **Crash-frame classifier** | `tools/merge_drivers/crash_frame.py` | `classify_crash_frame(asan_log, driver_basename)` → driver/library/unknown (deterministic ASan frame attribution; driver-bug FP vs real library bug). |
| **Pre-ship quarantine** | `run_single_fuzz.py:_is_immediate_crash_fp` + `_maybe_merge_drivers` | drops immediate-crash 0-coverage FP drivers from the merge (poison the fused harness); binary-free, uses the trial's own verdict. + dead-filter bugfix (`dead_on_empty`). |
| **Compile-validation merge gate** | `tools/merge_drivers/compile_validate.py:validate_compilable` + `run_single_fuzz.py:_compile_validate_candidates` | the merge includes ONLY drivers that COMPILE under the project's real OSS-Fuzz coverage-build flags (per-TU C/C++ language; `-Werror=implicit-function-declaration` re-promoted to catch the link-class failures `-fsyntax-only` misses), excluding the rest up front so the address build and the coverage build compile the IDENTICAL valid set (A≡B). Fail-open (no docker/image ⇒ keep all); opt-out `LOGICFUZZ_SKIP_COMPILE_VALIDATE=1`; writes `merged/compile_validation.json`. The `\|\|continue`+weak-stub in `merge.py` stay as a now-rarely-firing safety net. lcms: excluded 9/11 invalid drivers → merged harness llvm-cov 551/9590 br (no longer spurious 0). |
| **Edge-weighted CDF dispatch** | `run_single_fuzz.py:_edges_weights_for` + `SynthesizedDriver.from_paths(mode=CDF, weights=…)` | preflight already smoke-fuzzes each driver 15s and records `edges_15s` (a driver producing seeds = interacting with the library = Liberator "positive"); that signal weights the merged-harness CDF dispatch so high-interaction sub-drivers get a larger per-input share (was UNIFORM `selector % N`). Weights align to the merge's name-sorted order; missing ⇒ median, none ⇒ UNIFORM fallback. (Cross-round driver-history is NOT done — needs cross-round state.) |
| **Keep-best + file-restore** | `src/workflow/nodes/execution.py:_keep_best` | never ship a driver worse than the trial's peak (all paths); restores the kept source **to disk** on rollback (else merge ships the regressed file). |
| **Coverage Gap** (G5) | `liberator_adapter/analysis/coverage_gap.py` | `compute_gap_apis()` → baseline-uncovered APIs; directs Step 5h construction+ranking toward the gap. |
| Comprehender | `src/knowledge/comprehender.py` | Two-stage knowledge extraction. Detail: `docs/knowledge_layer.md`. |
| **Phase B Idiom Distiller** | `src/knowledge/idiom_distiller.py` | 10 L1 deterministic patterns; writes `state/idioms.json` |
| **Phase C Coverage Memory** | `src/state/coverage_memory.py` | `CoverageMemory` + `IterationSnapshot`; writes `state/coverage_memory.json` |
| **Phase D Path Planner** | `src/state/path_planner.py` | Idiom-align rerank + synthesize_missing; writes `state/plan_ledger.json` |

### Progressive Filter Pipeline (`liberator_adapter/constraints/`)

Multi-layer filtering: **Type compatibility ≠ Semantic validity ≠ High coverage**

```
All APIs (N) → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Reachability Ranking → Top-K
              (~1000)    (~100)      (~30)          (~10)            (acceptance_score-first)   (K=12)
                                                                                ↑
                                                          Project-adaptive automaton signal
```

This L0–L4 path now produces the **grammar floor** (a guaranteed
CBFactory-synthesizability safety net); the lead candidates are Step 5h
model-driven construction, merged onto that floor. (L5 was deleted in G3 — see
Failed Attempts.)

| Layer | File | Constraint |
|-------|------|------------|
| L0 | (implicit in grammar) | `API_A.arg.type == API_B.return_type` |
| L1 | `entry_point_analyzer.py` | Direct buffer + indirect `IndirectEntryPoint(creator, consumer)` pairs |
| L2 | `lifecycle_analyzer.py` | Resources have matching init/destroy pairs |
| L3 | `state_machine_analyzer.py` | API calls satisfy precondition/postcondition |
| L4 | `coverage_ranker.py` | **Reachability-first** (G3): `acceptance_score` primary sort, diversity tiebreak, greedy Top-K |

**Use-def + typestate substrate** (`liberator_adapter/analysis/usedef.py`):
`APIEffect` (USE/DEF/KILL) per API feeds L4, Prototyper (via automaton), and Comprehender.
L1 (handle classification) and L2/L3 (per-sequence validation) both delegate here.
L2/L3 build a per-analysis `UseDefGraph` from their domain model (lifecycle pairs / state constraints) and call `Typestate.check`. Domain-specific *discovery* still lives in each Lx file; the *walker* is shared.

### Z3-Guided Synthesis (`liberator_adapter/constraints/`)

| Component | File | Purpose |
|-----------|------|---------|
| `IncrementalZ3Solver` | `z3_guided_synthesis.py` | push/pop for decision guidance |
| `Z3GuidedSynthesisController` | `z3_guided_synthesis.py` | TYPE_MATCH, PROVENANCE, RESOURCE_LIFECYCLE, VARIABLE_AVAILABILITY |
| `AutomatonAcceptanceGuard` | `z3_guided_synthesis.py` | Phase H hard-pruning gate (currently positive-only) |
| `Z3SequenceValidator` | `z3_solver.py` | **Position-indexed** lifecycle validation (#4 fix, 2026-05-22) + LLVM-IR byte-buffer exemption (#73) |
| UnsatCoreDiagnoser | `z3_guided_synthesis.py` | Failure diagnosis |

### Liberator Static Analysis (`liberator_adapter/`)

| Problem | Solution |
|---------|----------|
| Type over-connection | `ProvenanceChecker` + LLM filter |
| Var-len params | `VarLenAnalyzer` in `special_patterns.py` |
| Callbacks | `CallbackAnalyzer` + stub templates |
| API lifecycle | L2 `lifecycle_analyzer.py` + shared `usedef.py` `Typestate` walker (the former `sequence_filter.py` / `LLMLifecycleValidator` was removed in the L2/L3 refactor — see `constraints/__init__.py`) |
| Type classification | `ConditionManager.py` (SOURCE/SINK/INIT/SETBY). **Demoted by G1** to one IR-evidence source feeding `APISemanticModel.reconcile`; no longer the role authority. |

## Project-Adaptive Automaton + Closed-Loop

Per-project typestate automaton learned from the library's own tests/examples
(`liberator_adapter/analysis/project_automaton.py`); the Phase G closed loop
(`src/closed_loop.py`, Step 11, `--closed-loop`/`--closed-loop-iters N`/
`--closed-loop-early-stop K`) grows it from Z3-viable sequences each round.
Mechanics — pipeline, state vector, EDSM merge, `AutomatonArtifact` surface,
persistence — are SSOT in `docs/knowledge_layer.md` (Project-Adaptive Automaton
section); not duplicated here. Persistence dirs: `results/{project}/automaton/`,
`.../comprehension/`, `.../state/` (Phase A/B/C/D).

## Design Principles

- **SSOT**: `FuzzingContext` prepared once, immutable. No fallbacks — explicit failures.
- **Symbolic vs Neural**: Z3 handles hard constraints, LLM handles soft constraints.
- **Error Triage**: Categorize build errors (link/header/type) for targeted fixing.
- **Token Efficiency**: Context prefetching, 8KB output truncation. Comprehender uses deterministic-first layering and automaton acceptance prefilter. Per-run LLM token cost is metered (`src/utils/token_meter.py`, fed by `state.update_token_usage` + `Comprehender._invoke`) and dumped to `results/<project>/token_summary.json` (+ a one-line total log) by `run_logicfuzz.run_experiments` — the empirical vs-PromeFuzz cost check.
- **Signal vs Filter**: The automaton produces *signals* (acceptance, sampled paths, grafting) that augment the candidate pool and bias ranking; the greedy max-coverage selection is unchanged.
- **Reuse upstream Liberator over reimplementation**: When fixing a synthesis-layer problem, first check whether `reference/liberator` already solves it. Adapt at the boundary; don't fork.
- **Coverage measurement (A≡B / valid-harness)**: the address build and the coverage build must compile the IDENTICAL harness (A≡B), else replayed coverage is spurious. Mechanism + the compile-validation gate that enforces it: `docs/generation.md` §6.

## Validation Pipeline

`UnifiedCodeValidator` (`src/utils/unified_validator.py`) replaces the former 4 validators (fake-defs, language mismatch, internal APIs, API hallucination). Build errors are then triaged by `src/utils/compilation_error_triage.py` into link/header/type buckets for the Fixer. Hallucinated defs and internal API calls are fatal; other issues pass to the Fixer.

## Implementation Flow

```python
# In FuzzingContext.prepare()  (src/context/data_context.py)
Step 1   ProjectDriverGenerator init
Step 2   Extract APIs
Step 3   Build dependency graph                  # L0: type compatibility
Step 3.5 Build data layout                        # moved up: must precede grammar gen
Step 4   Generate sequences (grammar)
Step 5b  Build ConditionManager
Step 5c  L1 Entry-point filter
Step 5d  L2 Lifecycle filter
Step 5e  L3 State-machine filter
Step 5f  L4 reachability ranker (grammar floor)
Step 5e2 learn_project_automaton                 (runs after 5f)
Step 5g  Build APISemanticModel                  (G1)
Step 5h  Construct sequences from model + merge onto floor   (G2+G5)
Step 6b  Comprehender A+B
Step 7   Header extraction
Step 8   Existing-fuzzer header extraction
Step 9   DriverEnhancer pattern analysis
Step 10  Phase D Planner + Z3-validated skeleton drivers
Step 10b Semantic value-intent on holes          (G4)
Step 11  Closed-loop iterations                  (Phase G, opt-in)
Step 12  Existing-driver knowledge extraction + Phase B idiom distillation
# Post-merge: Phase C IterationSnapshot persisted by run_single_fuzz.py
```

## Open TODOs

Generation (G1–G5) has landed; the live frontier is now **below** it. Start
new work from `docs/generation.md` (open bottleneck + roadmap):

- **✅ RESOLVED — orphaned optimize subsystem REMOVED.** The per-driver
  coverage-optimize loop (`coverage_analyzer` → `improver`) + §10B
  `baseline_diff_analyzer` regression recovery — 3 nodes + 3 agents +
  `supervisor._handle_coverage_improvement` + the execution-node improver-rollback
  / baseline-regression-alert + their state keys — were **deleted**. Rationale: it
  was *per-driver* LLM refinement (N× cost), mismatched with the breadth-via-merge
  design, and addressed **none** of the real bottlenecks (binding / input-seed /
  breadth-bound). The *crash* LLM path (crash_analyzer → crash_feasibility,
  unknown-frame fallback) is untouched. If cross-round coverage feedback is ever
  wanted, build it **fresh** as the **Phase C CEGAR loop** (`generation.md` F6,
  prereq WorkingMemory): portfolio/union-level + gap-directed (reuse G5
  `coverage_gap`) + cross-round (~1 pass/round, NOT per-trial) — do **not**
  resurrect the per-driver nodes; per-trial granularity was the mismatch. There is
  **no CEGAR loop today** (F6 is proposed-not-built); the only feedback loop that
  remains is Phase G closed-loop (automaton viability growth, opt-in).

- **Input/seed layer (NEW #1 below binding) — real-seed routing landed (gated).**
  Factory chain made `cmsDoTransform` constructable + compilable (lcms opaque args
  0→77/128), but a degraded-30s probe covered **0/799 of `cmsxform.c`**: random
  bytes never form a valid ICC profile → `cmsCreateTransform` NULL → guard →
  `cmsDoTransform` never runs. Real-seed routing (**default-on**, gate removed)
  routes the project's REAL format-matching seeds (`*.icc`/`*.it8`/…, by
  parser-entry API + file magic) into each driver's generation-phase corpus +
  the merged harness (`scripts/seed_discovery.py` `seed_corpus_for_driver` →
  `builder_runner._seed_corpus_dir`). Remaining: **measure** the cmsxform.c gain
  end-to-end, and synthetic seed generation from format analysis (still TODO).
  See `docs/generation.md` §6.
- **build-cache × llvm14 — RESOLVED by A1 (additive canonical base).** Cached runs
  used to silently degrade to Z3-OFF (reused non-clang-14 image → clang-only →
  empty `function_conditions`). Fix: `ensure_llvm14_base_builder()` builds the
  *additive* llvm14 image (clang-14 at /usr/lib/llvm-14; default `/usr/local` clang
  + libc++ untouched → fuzzers still link) and retags it onto
  `gcr.io/oss-fuzz-base/base-builder`, so every project + cache image inherits
  clang-14 — one image serves extraction + trials (no patch, no isolation, no
  bypass). Called before `prepare_cached_images`. **One-time deploy step:** OFG
  cache images are registry-hosted (pull-first) — rebuild + re-push the
  `*-ofg-cached-*` images on the additive base (or `OFG_USE_CACHING=0`) so cached
  eval is Z3-on. Memory `project_buildcache_llvm14_conflict`; `docs/generation.md` §4.
- **Binding layer (#14) — construction lifted, tail remains.** Factory chain
  recovers `cmsCreate*`-named opaque producers; remaining: residual
  non-`Create*`-named / no-in-project-producer tail + caller-alloc-init args beyond
  the SVF-INIT channel. See `docs/generation.md` §5/§6.
- **Feedback / input layers — T10/T11/T12 landed (gated, coverage A/B pending):**
  T11 error-shape variant skeletons (was F5; `LOGICFUZZ_ERROR_VARIANTS`), T10
  generalized format-entry → synthetic seed (`LOGICFUZZ_FORMAT_INFER`), T12 dynamic
  value feedback (`LOGICFUZZ_VALUE_FEEDBACK` — a *precursor* to F6, NOT the loop;
  keyed by api-sequence content hash). Still open: **F6 Phase C CEGAR loop** (prereq
  WorkingMemory), F7 L2 LLM idioms. See `docs/generation.md` §6.
- **T7 — cross-project driver retrieval — ✅ MVP implemented (gated
  `LOGICFUZZ_CROSS_PROJECT`, A/B pending).** `liberator_adapter/analysis/cross_project_retrieval.py`
  + `data_context` attach + prototyper render; 11 tests incl. a real-corpus
  experiment. Retrieve structurally-similar drivers for a resource-thin library
  and inject compressed CALLSPEC-style hints. **Design (as built):** structure-
  signature retrieval (API set / lifecycle-role + entry-type hints / call
  bigrams); **same-project drivers first**, cross-project only when own is thin
  (`is_resource_thin`); scope+threshold selection (score ≥ τ), best-1 fallback;
  trigger lives inline (no separate planner node — decision (a) → folded path).
  **Embedding fallback (unwired):** OpenAI `text-embedding-3-large` re-rank —
  build only if structure-sig precision proves insufficient. **Corpus:** MVP = local `extracted_fuzz_drivers/` (3 projects);
  **scale-up = ALL OSS-Fuzz drivers via the FuzzIntrospector (FI) API** (user
  direction; offline one-time index — `LOGICFUZZ_XPROJ_CORPUS` points the loader).
  **Precision finding (empirical):** raw call-extraction also caught comment words
  / macros — now filtered (strip comments, drop ALL-CAPS macros + `__`-builtins);
  residual project-local helpers are the precision ceiling that justifies the
  embedding fallback. **Open before default-on:** coverage A/B; the FI-API corpus
  scale-up; per-run information-budget scheduling (decision (c), deferred). (Was
  audit T7 / B1-①.)
- LLM equivalence oracle production throttling (`enable_llm_oracle=False` in `data_context.py:Step 5e2` until cost-aware pacing lands).
- libaom path resolution — `src_ossfuzz/libaom/` layout doesn't match the consumer-paths probe.
- Batch evaluation aggregator — auto-aggregate `scripts/batch_extended_fuzzing.sh` output into PromeFuzz Table 2 format.
- TLV-aware seed generation based on format analysis. (Done in part: `scripts/seed_discovery.py` feeds the project's REAL on-disk seeds — `*.icc`/`*.it8`/OSS-Fuzz `*_seed_corpus.zip` — into fuzzing; **T10** (`LOGICFUZZ_FORMAT_INFER`, gated) now also *synthesizes* a minimal front-gate-passing seed from inferred magic when no real seed ships. Full TLV-aware *structural* generation — a valid deep file, not just the leading gate — is still TODO.)
- Cross-phase information flow (write-only JSON state, WorkingMemory prereq for F6) — see `generation.md`.
- SVF big-lib cap — **LANDED + measured (2026-06).** Both knobs in place:
  `LIBERATOR_SVF_TIMEOUT_SECS` (wall-time) + `LIBERATOR_SVF_MEM_GB` (RLIMIT_AS,
  graceful clang-only on OOM). Measured peak RSS / failure mode: **libtiff 4.5GB
  + libvpx 7.7GB are TIME-bound** (both timed out at 7200s — need ≥4h timeout, NOT
  more RAM); **libucl is MEMORY-pathological** (std::bad_alloc in `ucl_parse_csexp`
  at ~37GB RSS / virtual>48GB under a 48GB cap — non-converging, practical outcome
  is clang-only). Open: a longer-timeout (≥4h) re-run of libtiff/libvpx would
  actually land their conditions.json (memory is a non-issue for them).
- Skeleton-rendering validity fix (void-array / opaque-type / internal-header) — **LANDED** (`skeleton_generator.py`, commit `777cef0c`): the renderer emits valid C/C++ *by construction* — void/`void*` array element → `uint8_t` byte buffer; opaque/non-scalar types → pointers (never value arrays of an incomplete type); struct values `{0}`-init (not `=0`/NULL-compared); internal opaque typenames (`_cmsContext_struct*`) → `void*`; `*_internal.h` filtered; cleanup only destroys declared `ret_<api>` handles. lcms re-render: void-arrays 6→0, opaque value-arrays 8→0, internal typenames 6→0, undeclared `ret_*` 8→0; previously-broken skeletons now compile (gcc c11 + g++ c++14). Complements the compile-validation gate — fewer invalid drivers to exclude → thicker merged portfolio.

## Failed Attempts / Lessons

Guardrails — read before re-litigating. Full detail in git history.

- **Don't reintroduce a novelty pre-filter as a hard gate** (the deleted L5
  `coverage_aware_filter.py`). Novelty-vs-baseline is a proxy that suppresses
  total coverage and doesn't predict reachability. Rank by reachability
  (`acceptance_score` primary, G3); target the gap positively via G5.
- **Lifecycle order constraints are position-indexed, not over the API-name
  set** (`Z3SequenceValidator._check_lifecycle_position_indexed`, resolved
  2026-05-22). All-pairs name-set quantification made chained-builder APIs
  (cjson `cJSON_Add*`) self-cyclic → all-UNSAT. Don't revert to set-based.
- **§10B baseline-regression recovery belonged post-merge, not per-trial**
  (`BaselineDiffAnalyzer`, now REMOVED with the optimize subsystem). Per-trial
  granularity wasted LLM calls; if revived, it belongs in the Phase C CEGAR loop
  (`generation.md` F6) — post-merge, cross-round, NOT a per-trial node.
