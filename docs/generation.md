# Driver Generation — Source of Truth

The built generation pipeline for LogicFuzz. **Reconcile-then-construct**: build
an `APISemanticModel` (IR ⊕ doc ⊕ usage) first, then *construct* lifecycle-
complete sequences from it, so candidates are valid by construction — no repair
stage. (The old classify-then-repair flow — Phase A repair + Tier-1 F1–F4 — was
deleted.)

This doc covers **(1)** the landed G1–G5 pipeline (brief — points to files),
**(2)** the breadth + low-FP optimization levers (flag, file, effect, measured
result), the build-cache, honest verdicts, and the roadmap. Honest verdicts are
measured caveats — do not read them as headline claims.

| Companion doc | Scope |
|---|---|
| `docs/contributions_and_related_work.md` | 3-innovation pitch + PromeFuzz/Liberator/PromptFuzz/CKGFuzzer comparison + per-LLM-call-site rationale |
| `docs/knowledge_layer.md` | comprehender / automaton mechanics |
| `CLAUDE.md` | flags table, Step 5x implementation flow, file map |

§6 is the SSOT for open items + roadmap.

---

## 1. The G1–G5 pipeline (landed)

Wired into `FuzzingContext.prepare()` (`src/context/data_context.py`); see
`CLAUDE.md` "Implementation Flow" for Step numbers.

| Stage | What it does | File | Step |
|---|---|---|---|
| **G1 APISemanticModel** | `reconcile()` fuses IR mechanism (use-def produces/requires/kills, SVF-gated) ⊕ doc/naming ⊕ automaton usage into one per-API role+arg-semantics verdict; **role authority** (demotes `ConditionManager`); 0 LLM | `liberator_adapter/analysis/api_semantic_model.py` | 5g |
| **G2 Sequence Constructor** | `construct_sequences()` builds creator→mutator\*→consumer→destroyer chains, lifecycle-complete by construction; merged onto the L0–L4 grammar floor | `liberator_adapter/analysis/sequence_constructor.py` | 5h |
| **G3 Reachability ranking** | L4 ranks `acceptance_score` primary, diversity as tiebreak, greedy Top-K | `liberator_adapter/constraints/coverage_ranker.py` | 5f |
| **G4 Hole Semantics** | `annotate_skeletons()` attaches per-arg value intents (typed context schema, §2) to each Z3-validated skeleton | `liberator_adapter/analysis/hole_semantics.py` | 10b |
| **G5 Coverage Gap** | `compute_gap_apis()` → baseline-uncovered API surface; directs G2 construction + ranking toward the gap | `liberator_adapter/analysis/coverage_gap.py` | 5h |

**Two deterministic handle-recovery passes** feed G1 (zero LLM) — these make
opaque-handle and caller-alloc-init libraries constructable:

| Pass | Restores | File | Note |
|---|---|---|---|
| Handle **identity** | re-types IR-collapsed `void*`/`i8*` back to `cmsHPROFILE`/`cmsHTRANSFORM` from headers | `liberator_adapter/analysis/handle_typedef_recovery.py` | dep-graph connected where Liberator's is empty, specific where naive void\* over-connects |
| Handle **production (a)** | SVF-write-gated INIT channel: `deflateInit_(z_stream*)` (single-ptr in-place init) recovered as a *creator* | `liberator_adapter/analysis/usedef.py` (`annotate_svf_writes` / `extract_produced_handles`) | zlib deflate/inflate **0 → 34/36 constructable**; one driver covers deflate.c+inflate.c+trees.c = 1874/3397 lines, all 0 before |
| Handle **production (b)** — factory chain | naming-based opaque-return producer recovery: a required non-pointer opaque handle whose creator-return the IR desugared to `void*` (`cmsHTRANSFORM`) is mapped to its `cmsCreate*Transform` factory and fed to the recursive prefix resolver (non-pointer test + camelCase word-boundary + deep-factory preference) | `liberator_adapter/analysis/sequence_constructor.py` (`_recover_opaque_producers`; always-on, monotone) | first dent in the binding-layer ceiling (#14): lcms recovered handle types 0→2, deep opaque args 0→**77/128**, `cmsDoTransform` chain constructs+compiles; 8 handle-struct libs byte-identical. Deep coverage is then won by the default-on builder levers (POPULATE_COLLECTIONS / FUZZ_BUFFERS / INPUT_SOURCE) feeding fuzz bytes into the chain's buffers/openers (lcms 300s edges 325→943, cov 0.86%→16.81%); the residual tail is deep structured-input validity (synthetic seed gen) |
| Per-arg **output-array role** | a struct-pointer arg the IR type-pattern reads as a handle (HANDLE_IN) but SVF proved is a *written array* whose element type has **no producer in the project** is reclassified **OUTPUT**. **Dual gate, sound where neither alone is:** `is_array` rules out a single in-out handle (`png_struct*`, is_array=False); *producer-absence* rules out a managed handle that is merely array-/link-accessed (`cJSON*` linked nodes, `gzFile` — both have a creator). The producer set = ∪ every API's IR `produces`. | `usedef.annotate_svf_writes` (`_svf_is_array`) + `api_semantic_model._reconcile_args` (`produced_bases` gate) | recovers libpng `png_build_grayscale_palette(png_color* palette)` → OUTPUT; **verified** no mis-promotion of `cJSON_DetachItemViaPointer` item / `gzFile` / `z_stream` (the is_array-only rule's regression). Render-neutral (struct-ptr render is type-decided) → no overflow regression; corrects binding + hole value-intents |

Closed-loop (Phase G) grows the automaton from Z3-viable sequences each round
(`src/closed_loop.py`, Step 11, opt-in `--closed-loop`).

### A/B kill-switches (G-pipeline)

| Flag | Effect |
|---|---|
| `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1` | drop G2 model-driven construction → random-walk grammar floor only |
| `LOGICFUZZ_DISABLE_DRIVER_TRACES=1` | T8: don't feed the project's own driver `.c` corpus into the automaton's consumer paths |

**Default-on (gates removed):** factory chain, density + hard NULL-guard,
max-coverage diversity selection, real seed-corpus routing, lean crash triage +
skip per-driver optimize, typedef-handle recovery, densifier partition +
producer/destroyer diversification, marginal-depth selection, subset-elimination,
scoped per-component NULL-guards, cross-source profile binding, FP-crasher merge
quarantine, value-domain leaf constraints, **validity contract** (valid-by-
construction opaque-handle binding I1/I2a/I2b/I3) + universal validity-repair at
skeleton synthesis, **populate-collections** (handle-collection arg → populated
producer array, not `{0}`/NULL), **fuzz-buffers** (scalar data-buffer arg →
`(T*)data` + paired length ⇒ seed-independent), **residual all-cover + API-floor**
(every reachable public API in ≥1 sequence), **input-source materialization**
(CREATOR `FILE*`/path arg ← fuzz bytes). (Full per-lever rationale + measured A/B:
`CLAUDE.md` flag reference + git history.) The graduated 2026-06-20 cohort
(VALIDITY_CONTRACT + POPULATE_COLLECTIONS + FUZZ_BUFFERS + RESIDUAL_ALLCOVER +
API_FLOOR) turned lcms drivers live: preflight-survived 1→14, merged distinct APIs
18→69, 300s-fuzz edges 325→943, coverage 0.86%→16.81%.

---

## 2. The typed LLM-context schema (②′, landed)

The neuro-symbolic boundary is a **typed, symbolically-grounded schema**, not a
prose dump: each LLM decision is decomposed into fixed slots, each populated by
the most authoritative source. Instantiated at the two generation-stage LLM
decision points. Full slot tables: `docs/contributions_and_related_work.md` §②′;
the source map below records what landed.

| Slot / feature | Source (file) | Landed |
|---|---|---|
| `library_constants` — legal enum/flag/format values | header enum + grouped-`#define` scan, `named_constants.py` | lcms 11 enums, zlib `Z_*` |
| per-API `ret_contract` — NULL/error guard | conditions.json return-provenance + doxygen `@return`, `error_contracts.py` | lcms 85 creators / c-ares 12 / cjson 18 → hole emits `⚠ returns NULL → NULL-check` |
| per-arg `populated_from` — which args fill this struct | SVF `set_by` (conditions.json) | lcms 75 edges |
| `handle_provenance` — producer of a required handle (or none → construct/NULL) | use-def `produces`/`requires` index | c-ares verified (`ares_cancel`→`ares_init`) |
| Comprehender-B `sequence_facts` — per-API USE/DEF/KILL + `Typestate.check` verdict | use-def `APIEffect` + `Typestate` (only this sequence's APIs) | kill-switch `LOGICFUZZ_DISABLE_SEQFACTS=1` |

**CALLSPEC** (one typed per-call row consolidating the hole slots; replaced 7
redundant prompt blocks) is the **default** Prototyper context. A/B that promoted
it: c-ares best **1440 > 804** branches; lcms **88 > 0** (CALLSPEC-off both
drivers SEGV'd). Doc priors (`@return`/`@retval` contracts, README purpose) are
default-on, not switchable (token cost net-negative — a substantive docstring
lets the comprehender skip that API's LLM call).

---

## 3. Breadth + low-FP optimization levers

**Motivation** (§6, contributions §3): the gap vs PromeFuzz/PromptFuzz/CKGFuzzer
is **API breadth × driver density**, not novelty — correct-by-construction
dropped every API the symbolic layer couldn't connect (≈302/452 gap APIs never
entered a candidate). The fix is **graceful degradation** — the symbolic layer
authors *structure*, the LLM fills *gaps it can't prove*, a separate quality layer
keeps the false-positive (FP) rate low. The neuro-symbolic split is preserved:
density only appends calls whose handle dependencies are *already symbolically
satisfied*; guards are IR-derived; the LLM still owns only leaf values.

### Levers (default-on; only tuning knobs + kill-switches remain as flags)

| Lever | Flag (default) | File | What it does | Measured |
|---|---|---|---|---|
| **B graceful degradation** | `LOGICFUZZ_STRICT_ORDERING` off = on | `sequence_constructor.py` (`construct_sequences` orphan-keep) | keep orphan-handle `USE_BEFORE_INIT` sequences → island/opaque APIs enter candidates; un-bindable arg stays a hole | ≈302/452 previously-dropped gap APIs enter the pool |
| **density** | default-on (tune `_DENSE_MAX_EXTRA`/`_DENSE_COOCCUR`) | `sequence_constructor.py:_densify` | append extenders that USE an already-open handle (`requires ⊆ opened`) → thicken thin chains | 2.5 → 4.3 calls/seq |
| **density co-occurrence** | `LOGICFUZZ_DENSE_COOCCUR` (1), `LOGICFUZZ_DENSE_MAX_EXTRA` (8) | `sequence_constructor.py` (`_cooccur`) | second `_densify` source: thicken along automaton accepting-path real co-occurrence (= PromeFuzz call-scope grouping) | lcms 6.6 → **7.7 APIs/seq, median 7 ≈ PromeFuzz 7.6** |
| **hard NULL-guard + opaque factory hint** | default-on | `hole_semantics.py:_hard_nullguard` | `ret_contract` → `MUST-GUARD: if(!x)return0;` + "build the opaque handle via its producer" hint; coupled with density | lcms combo FP 1→0 |
| **validity contract** | default-on (gate removed) | `validity_contract.py` + `sequence_constructor._validity_contract` | every `nullable=False` opaque-handle arg gets a type-matched producer with type-correct binding (I1/I2a/I2b/I3); universal validity-repair prepends missing handle creators at skeleton synthesis | lcms preflight-survived 1→14, merged distinct APIs 18→49 |
| **populate-collections** | default-on (gate removed) | `sequence_constructor._populate_collections` + `skeleton_generator` | a CREATOR's handle-collection arg (`cmsToneCurve* const []`) → a populated array of built producer handles, not degenerate `{0}`/NULL | lcms 300s-fuzz edges 325→943, cov 0.86%→16.81% |
| **fuzz-buffers** | default-on (gate removed) | `sequence_constructor._fuzz_buffers` + `skeleton_generator` | a builder's scalar data-buffer arg (`cmsUInt16Number *`) → `(T*)data` with paired length bound to `size/sizeof(T)` ⇒ drivers are SEED-INDEPENDENT | (combined with populate-collections, above) |
| **input-source materialization** | `LOGICFUZZ_INPUT_SOURCE` (on) | `analysis/input_source.py` + `skeleton_generator._input_source_enabled` | a CREATOR's `FILE*` (→`fmemopen`) or lone `const char*` path (→`mkstemp`+`write`, LOW-confidence ⇒ RefineHole) arg is materialized from the fuzzer's `data,size` instead of staying NULL; type-driven, library-agnostic, INPUT_BUFFER args excluded | drivers open from fuzz bytes (replaces NULL-guard short-circuit) |
| **residual all-cover + API-floor** | `LOGICFUZZ_RESIDUAL_ALLCOVER` / `LOGICFUZZ_API_FLOOR` (both on) | `data_context.py` (residual pass) + portfolio set-cover | append a single-API skeleton for every public API the symbolic constructor can't chain (validity-repair prepends its creators); greedy set-cover pulls every constructable API into ≥1 selected sequence; writes `breadth_residual.json` telemetry | cjson 75→78, lcms 149→297; merged distinct APIs 18→69 |
| **top_k breadth lever** | `LOGICFUZZ_TOP_K` (10; needs `LOGICFUZZ_NO_CACHE=1` to regen) | `data_context.py:316` | raise greedy max-coverage selection cap → more skeletons → more distinct APIs in merged union | top_k=100 → **c-ares 118 ≥ 113, zlib 95 ≥ 89** (PromeFuzz parity); lcms 100→136, 150→186 |
| **keep-best + file restore** | default | `src/workflow/nodes/execution.py:_keep_best` | never ship a driver worse than the trial's peak; write restored source back to disk (else merge ships the degraded driver) | — |
| **pre-ship quarantine + dead-filter** | default | `tools/merge_drivers/` | drop immediate-crash 0-coverage FP drivers before merge (else they poison the fused harness) | — |
| **crash-frame classifier** | reuses core | `tools/merge_drivers/crash_frame.py` | deterministic ASan frame attribution: driver-bug vs library-bug (symbolic, not LLM-judged) | — |

### Measured combo (30s A/B, single best driver — NOT 24h; do not compare to PromeFuzz Table 2)

| Project | baseline | combo (density+guard) | Δ cov | baseline FP | combo FP |
|---|---|---|---|---|---|
| lcms | 66 | **206** | **+212%** | 1 | **0** |
| c-ares | 1410 | 1412 | +0% | 4 | 4 |
| zlib | 515 | **545** | +6% | 0 | 3 (quarantined at merge) |

**Ablation:** density and the guard are **synergistic** — neither alone helps
(lcms density-only = 0, all SEGV; guard-only = 54 ≈ 66); only the combo reaches
206. The c-ares "regression" is **LLM n=1 sampling variance** (density is a no-op
on a handle-less pure parser), *not* systematic density harm.

**Cost (gpt-4o):** top_k=10 ≈ **\$0.5–0.9**; top_k=56 ≈ \$3–5. PromeFuzz spent
**\$15.89** for its entire 20-lib suite. Cost is a non-issue.

---

## 4. Build-cache (eliminate per-trial full library rebuild)

**Root cause of slow generation** (fixed for lcms): every trial re-ran the *full*
library build (`./configure && make`) inside `docker run --rm` with `/out`,`/work`
cleared — a 56-driver lcms run did ~57 full configure+make of liblcms2.
Parallelism (`LLM_NUM_EXP=6`) was *not* the bottleneck.

**Fix = one gate file, zero new code.** pub-llm already wires the OSS-Fuzz
`ofg-cache` (`prepare_cached_images`, `OFG_USE_CACHING=1` default); it only lacked
`fuzzer_build_script/<project>` for lcms. That file is an **existence gate** only —
its content is never applied as build.sh. Mechanism: the library is built into a
committed image ONCE, each trial `FROM`s it and re-runs the ORIGINAL build.sh, so
`make` becomes a no-op — the speedup depends on build.sh being **idempotent** on
the prebuilt image.

**Extension is per-project fork-idempotency** (open roadmap): lcms's
`./configure && make` re-runs cleanly; **c-ares FAILS** (`mkdir build` → "File
exists") until the OSS-Fuzz fork's build.sh is made idempotent (`mkdir -p`, fork =
github.com/MarkLee131/oss-fuzz). NB: do not reimplement a build-cache layer or
branch from `main` (broke pub-llm once → reverted; memory
`feedback_efficiency_and_simplicity`).

> **⚠ Build-cache silently disabled Z3 — RESOLVED by A1.** With cache on, the
> reused image had no clang-14 → SVF extraction fell back to clang-only →
> `function_conditions` empty → **Z3 OFF for the whole run**.
> *Fix (`ensure_llvm14_base_builder`):* build the llvm14 image **additively**
> (clang-14 at /usr/lib/llvm-14; default OSS-Fuzz clang untouched so fuzzers still
> link) and retag onto the canonical base-builder — one image serves both fuzzer
> builds and extraction, no Dockerfile patch, no cache bypass.
> *One-time deploy:* rebuild + re-push the `*-ofg-cached-*` images on the additive
> base (or run `OFG_USE_CACHING=0`). Recipe: memory `project_buildcache_llvm14_conflict`.

---

## 5. Honest verdicts (do not oversell)

Measured caveats — every breadth/density claim above is bounded by them.

- **Density's union-marginal is weaker than the optimistic estimate.** lcms56:
  56 drivers → union **92 distinct APIs = 1.64 new APIs/driver**, vs PromeFuzz's
  358/140 = 2.56/driver. Dense drivers **overlap** (co-occurrence pulls in the
  same popular APIs), so the union **saturates fast**. Density raises APIs/*driver*
  (6.9 ≈ PromeFuzz 7.8) but **not** the union-marginal — "fewer drivers for the
  same breadth" is *not* substantiated.

- **coverage-diff is a proof-of-concept, NOT a contribution.** lcms56 merge vs the
  human OSS-Fuzz `fuzzers.c` (30 min each, driver TU excluded): we cover **876 lcms
  lines the human driver covers zero of** (the whole IT8/CGATS parser `cmscgats.c`
  723 + `cmsmd5` 153) but it is **complementary** — the human covers 596 lines we
  miss (PostScript `cmsps2.c`, our binding-layer blind spot), and our 5953 < human
  7346. To become a real claim this needs **(a)** multi-project reproducibility and
  **(b)** evidence we fill *more* existing-driver gap than PromeFuzz/CKGFuzzer.

- **The opaque / no-producer tail is the binding-layer ceiling (#14) — now
  *partially* lifted.** top_k reaches PromeFuzz parity on c-ares/zlib but **not**
  lcms's 358 APIs (100→136, 150→186, never 358): ~half of lcms's APIs are opaque or
  have no in-project producer, so `RunningContext.try_to_get_var` can't synthesize
  their args. The **factory chain** (always-on, channel b) is the first dent: opaque
  handles whose creator the IR hid behind a `void*` return are recovered by naming
  and chained — lcms deep opaque args 0→77/128, `cmsDoTransform` constructable+
  compilable. **Status (updated 2026-06-20):** (i) the *deep coverage* the factory
  chain alone could not win (a degraded-30s probe once covered **0/799 of
  `cmsxform.c`** — `cmsCreateTransform` NULL → guard → `cmsDoTransform` never runs)
  is now reached by the default-on builder levers: POPULATE_COLLECTIONS +
  FUZZ_BUFFERS render collection/data-buffer args from the fuzz bytes so drivers are
  seed-independent (lcms 300s-fuzz edges **325→943, coverage 0.86%→16.81%**), and
  INPUT_SOURCE materializes a creator's `FILE*`/path arg from the fuzz bytes. (ii) the
  residual no-producer / non-`Create*`-named tail still drops to NULL holes. (iii) a
  clean Z3-on confirm was blocked by build-cache×llvm14 (§4, now resolved). So #14 is
  **"construction + builder input wiring lifted; deep structured-input validity
  (synthetic seed gen) is the residual tail."**

- **Coverage is breadth-bound, not time-bound (at this scale).** The lcms56 merged
  harness plateaus at **~1424 branches in ~30 min**. More fuzz time does not close
  the gap; more reachable API surface (binding layer) does.

- **30s/30min A/B numbers are not 24h-union numbers.** The headline test — 24h
  `--merge` union vs PromeFuzz Table 2 (lcms ~13k, c-ares 6,106) — is still pending
  (cost is fine; deferred).

---

## 6. Open frontier

The live frontier is **below** the G1–G5 pipeline. This section is the SSOT for
open items + roadmap. Short list:

| Item | Why it's the lever |
|---|---|
| **Input/seed layer — builder input wiring landed (default-on); residual = deep structured-input validity** | factory chain made `cmsDoTransform` constructable+compilable but covered 0/799 of `cmsxform.c` on random bytes. Now dented by the default-on builder levers (POPULATE_COLLECTIONS / FUZZ_BUFFERS / INPUT_SOURCE: seed-independent drivers, lcms 300s edges 325→943, cov 0.86%→16.81%) + real-seed routing (copies the project's REAL format-matching seeds into each corpus + merged harness, no-op when none). **Next:** synthetic seed gen for a *valid* deep file (a valid ICC profile from random bytes) — still TODO |
| **build-cache × llvm14 — RESOLVED by A1** | `ensure_llvm14_base_builder` (see §4). **One-time deploy:** rebuild + re-push `*-ofg-cached-*` (or `OFG_USE_CACHING=0`) |
| **merged-harness coverage validity — RESOLVED** | the merged harness used to read spurious 0 coverage: a compile-INVALID driver was KEPT then silently stubbed, so address + coverage builds compiled DIFFERENT TU sets (A≢B). **Fix:** the **compile-validation merge gate** (`compile_validate.py`) includes ONLY drivers that compile under real coverage-build flags, so both builds compile the IDENTICAL set (lcms: excluded 9/11 → llvm-cov 551/9590 br). Plus a coverage-instrumented LIBRARY rebuild (`git clean -dxf` + `--sanitizer coverage --clean`) and a renderer that emits valid C/C++ by construction (`skeleton_generator.py`), so fewer drivers reach the gate invalid |
| **merge stock-target language — RESOLVED (deterministic)** | the compile-validation gate used to content-sniff the extensionless `NN.fuzz_target` for its language; libpng's stock target is `.cc` (C++) but the sniff guessed C → 34/110 dropped as bogus C-vs-C++ errors (A≢B vs the per-trial build). **Fix:** thread the STOCK target's language (`benchmark.file_type` from its path extension) through the gate + merge + build (`compile_validate._resolve_lang`), so all 34 recover **deterministically, zero LLM/FP/cost** (commit `92d17830`) |
| **merge-gate LLM repair (`LOGICFUZZ_MERGE_REPAIR`) — PROTOTYPE, opt-in, A/B pending** | the compile-validation gate DROPS non-compiling drivers (fail-open). When set, each excluded TU gets ONE LLM rewrite RE-VALIDATED through the same gate; kept only if it now compiles (fail-closed ⇒ A≡B preserved). `tools/merge_drivers/llm_repair.py`; records `repaired_recovered` in `merged/compile_validation.json`. **Now largely subsumed** — the libpng 34/110 it targeted are recovered deterministically by the stock-target-language fix above; its honest residual is genuinely-malformed drivers only. **Next:** ≥2-project A/B before default-on (low priority — keep as fallback) |
| **Binding layer (#14) — construction lifted, tail remains** | factory chain (channel b) recovers opaque `void*`-return producers; **next:** the residual non-`Create*`-named / no-in-project-producer tail + caller-alloc-init args beyond the SVF-INIT channel |
| **Multi-project coverage-diff validation** | turn the lcms PoC into a claim: reproduce across projects + show we fill more existing-driver gap than PromeFuzz/CKGFuzzer |
| **24h union real run** | the actual headline vs PromeFuzz Table 2 absolute coverage (cost OK, deferred) |
| **Verify lean-mode savings** | lean mode is default (deterministic `crash_frame.py` triage + no per-driver optimize; optimize/improver/§10B nodes were **removed**); the ~8.5 → ~3 LLM-calls/driver figure is *projected* — confirm on a real eval run |
| **Extend build-cache** | per-project fork-idempotency (lcms ✓, c-ares ✓); remaining: cjson/zlib/libpng |

Feedback / input layers — **T10 / T11 / T12 implemented (all gated, coverage A/B
pending — start gated like factory/diversity/lean did):**

- **T10 — generalized format-entry → synthetic seed** (`LOGICFUZZ_FORMAT_INFER`):
  when no real seed matches a parser-entry driver, synthesize a minimal
  front-gate-passing seed from an inferred FormatSpec. *Scope (honest):*
  deterministic *constant* inference, NOT symbolic execution — clears the *leading
  magic gate*, not deep parser validation. Real-seed routing still preferred.
- **T11 — error-shape skeleton variants** (`LOGICFUZZ_ERROR_VARIANTS`): emit
  guard-testing shapes (SKIP_INIT / DOUBLE_DESTROY; USE_AFTER_DESTROY behind
  `_AGGRESSIVE`) for **gap-touching** sequences so library error branches become
  reachable. LLM fills only leaf holes; crashes triaged by the crash-frame classifier.
- **T12 — dynamic value feedback** (`LOGICFUZZ_VALUE_FEEDBACK`): capture a trial's
  filled hole values, pin the deepest-coverage ones into the SAME API-sequence's
  holes next run (matched by sequence content hash, not positional name). Cross-run;
  the "read" side of Phase C.
- **B+D scoped NULL-guards** (always-on, gate removed): render the creator
  NULL-guard **per dependency component** (nested-if) instead of the whole-driver
  `if(!parser)return0`, so an INDEPENDENT API runs even when the parser returns NULL
  on random input. Measured: **+523 br (12.6×)** when the parser fails; ≈0 when valid
  seeds let it succeed (gain conditional on parser-failure, the common fuzz case).
- **Tier-1 fuzzable-holes value-domain** (`LOGICFUZZ_FUZZABLE_HOLES`): scalar/float
  CONFIG holes emit a FUZZ_DERIVE intent invoking the LLM's value-domain judgement
  (semantically VALID range, then derive from the fuzz input); enum holes index a
  byte into the legal set. PromeFuzz's *automatic* depth mechanism made explicit,
  NOT hand-written per-lib `api_hints`. Confirmed: cmsBuildParametricToneCurve →
  cmsgamma.c 84→121 br (+44%).

Still open: **F6 Phase C CEGAR loop** (prereq WorkingMemory — T12 is a precursor,
not the principled loop). The T7 cross-project driver-retrieval runtime path was
removed (judged not-a-fit); the corpus/embedding dataset facts below are retained
for the paper's data-section. **Rejected (do not re-litigate):** T9 static CFG
reachability weighting — dependency graphs are too flat (max depth 1–3) and planner
blind spots are depth-independent, so reranking can't recover them; root cause is
the binding layer, not ranking.

### T7 cross-project corpus + embedding index (built; runtime path removed)

Dataset facts retained for the paper's data-section / threats-to-validity.

**Corpus** (`data_prep/extract_all_fuzz_drivers.py`, from GCS
`oss-fuzz-llm-public/human_written_targets/`, anonymous, $0): **484 projects / 4757
C/C++ harnesses**; after dedup (SOURCE-embedding cosine > 0.97 collapses 2508
vendored near-copies + 32 stubs) **2217 unique**.

**Embedding index** (`results/xproj_index/`, OpenAI `text-embedding-3-large`,
3072-dim, one-time $0.315; comment-stripped, token-truncated at 8000 — affects
0.29% genuinely, tolerable because it's a re-rank fallback over the full
untruncated structure-sig).

**Construction-template re-rank axis.** Raw-source embedding ranks by DOMAIN;
reference value = transferable CONSTRUCTION shape. Each driver is also distilled
into a library-agnostic construction template (input-wiring + role sequence +
resource shape) and embedded. Leave-one-out: template-embedding beats source on
**cross-domain-transferable@5 = 35.5% vs 14%** and construction@5 (43% vs 26%);
source wins domain@5 (orthogonal axes). **Rejected: RRF fusion** (domain@5 40% <
46.5% embedding-alone). Decisive test remains the end-to-end hint A/B; @K are proxies.

### Roadmap & open decisions

**Audit scope:** the *driver-generation* stage; the question — feeding the LLM the
*right* info, not the *most*. **Core judgment (holds):** Z3 ⊕ use-def ⊕ typestate
own program *structure* (lifecycle, handle wiring, call order); the LLM owns *soft*
decisions (values, semantics, hole-filling). This round plugged most "information
leaks at every boundary" (schema-feeding, deterministic extraction of constants/
contracts/producers). Remaining items: (1) cross-project knowledge + new techniques
(needs a decision); (2) the binding layer + multi-project validation.

**The unified abandonment-point fix.** Wherever the symbolic layer "can't give a
certain answer and gives up," it hands the LLM the *known half* as a structured
`value_intent` slot, so the LLM completes from evidence rather than guessing blind.
Three symbolic abandonment points addressed this way:

| # | Where symbolic gives up | What the LLM was forced to guess | Landed as |
|---|---|---|---|
| 2 | how to construct parser-entry bytes | how to assemble bytes that pass the front-gate into deep code | **T10** (`LOGICFUZZ_FORMAT_INFER`) |
| 4 | only happy-path skeletons generated | — (error branches were unreachable by construction) | **T11** (`LOGICFUZZ_ERROR_VARIANTS`) |
| 5 | the working runtime values are discarded | re-guesses the deep-branch-reaching value from scratch next round | **T12** (`LOGICFUZZ_VALUE_FEEDBACK`) |

**Open experimental validation (each gated feature needs a docker coverage A/B
before default-on):**

- **Multi-project end-to-end A/B of the CALLSPEC schema.** CALLSPEC is default + the
  redundant prompt blocks were cut (§2), but a prompt-schema refactor changes LLM
  behavior in ways unit tests can't catch — needs a larger-sample, multi-project
  end-to-end A/B (old vs new prompt on cjson/zlib/lcms; coverage + tokens). What ran
  is smoke-level (c-ares 1440 > 804; lcms 88 > 0).
- Multi-project coverage-diff validation, the 24h union real run, and per-gated-
  feature coverage A/Bs (T7/T10/T11/T12, scoped-guards, fuzzable-holes) — see the
  short-list table.

**B2 static-analysis residue (open):** (i) **no true CFG reachability** — L4's
"reachability" is automaton protocol-acceptance, not "how many uncovered blocks
does this API gate." T9 (static CFG reachability weighting) was measured and
**rejected** (graphs too flat, max depth 1–3; blind spots depth-independent; root
cause is the binding layer, #14). (ii) `set_by` write-mask / `len_depends_on`
overlap with the existing LENGTH/OUTPUT intent — deferred (split only when
downstream needs it).

**Deferred methodology fixes (recorded for later):**

- **Funnel fault-tolerance** — recover compile failures via the LangGraph fixer,
  loss-tolerant like PromeFuzz.
- **Per-subsystem multi-driver generation** — cluster drivers by subsystem (lcms
  postscript / tag / optimizer) so each deep subsystem gets dedicated drivers.
- **Relax correctness to let the LLM attempt hard APIs** — *in tension* with the
  correct-by-construction, no-repair mainline; graceful degradation already buys
  breadth without sacrificing the mainline, so this is a **needs-a-decision** item.

**TLR (FSE'26) — reference value (bounded).** Its formalism differs in domain
(memory-error typestate vs our API-protocol typestate) and stage (post-hoc replay
of known traces vs our forward synthesis). The one solid principle — *typestate-
selective context feeding > dumping everything* — is the direction our ②′ typed-
context schema takes, so it stays a related-work citation + design sanity-check.
The only reusable trick: its "snapshot only at typestate transition points" could
keep T12's runtime traces lean if/when T12 grows a richer trace.
