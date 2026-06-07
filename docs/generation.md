# Driver Generation — Source of Truth

The built generation pipeline for LogicFuzz. **Reconcile-then-construct**: build
an `APISemanticModel` (IR ⊕ doc ⊕ usage) first, then *construct* lifecycle-
complete sequences from it, so candidates are valid by construction — there is no
repair stage. (The old classify-then-repair flow — Phase A repair + Tier-1
F1–F4 — was deleted.)

This doc consolidates **(1)** the landed G1–G5 pipeline (brief — points to the
files) and **(2)** the 2026-06 breadth + low-FP optimization round (each lever:
flag, file, what it does, measured result), plus the build-cache. Honest verdicts
are preserved as written — do not read them as headline claims.

| Companion doc | Scope |
|---|---|
| `docs/contributions_and_related_work.md` | the 3-innovation pitch + PromeFuzz/Liberator/PromptFuzz/CKGFuzzer comparison |
| `docs/generation_information_audit.md` | **open** decision items + future roadmap only (this round's *changelog* moved here) |
| `docs/knowledge_layer.md` | comprehender / automaton mechanics |
| `CLAUDE.md` | flags table, Step 5x implementation flow, file map |

---

## 1. The G1–G5 pipeline (landed)

Wired into `FuzzingContext.prepare()` (`src/context/data_context.py`); see
`CLAUDE.md` "Implementation Flow" for the Step numbers.

| Stage | What it does | File | Step |
|---|---|---|---|
| **G1 APISemanticModel** | `reconcile()` fuses IR mechanism (use-def produces/requires/kills, SVF-gated) ⊕ doc/naming ⊕ automaton usage into one per-API role+arg-semantics verdict; **role authority** (demotes `ConditionManager`); 0 LLM | `liberator_adapter/analysis/api_semantic_model.py` | 5g |
| **G2 Sequence Constructor** | `construct_sequences()` builds creator→mutator\*→consumer→destroyer chains, lifecycle-complete by construction; merged onto the L0–L4 grammar floor | `liberator_adapter/analysis/sequence_constructor.py` | 5h |
| **G3 Reachability ranking** | L4 ranks `acceptance_score` primary, diversity as tiebreak, greedy Top-K | `liberator_adapter/constraints/coverage_ranker.py` | 5f |
| **G4 Hole Semantics** | `annotate_skeletons()` attaches per-arg value intents (the typed context schema, §3) to each Z3-validated skeleton | `liberator_adapter/analysis/hole_semantics.py` | 10b |
| **G5 Coverage Gap** | `compute_gap_apis()` → baseline-uncovered API surface; directs G2 construction + ranking toward the gap | `liberator_adapter/analysis/coverage_gap.py` | 5h |

**Two deterministic handle-recovery passes** feed G1 (zero LLM) — these are what
make opaque-handle and caller-alloc-init libraries constructable:

| Pass | Restores | File | Anchor |
|---|---|---|---|
| Handle **identity** | re-types IR-collapsed `void*`/`i8*` back to `cmsHPROFILE`/`cmsHTRANSFORM` from headers | `liberator_adapter/analysis/handle_typedef_recovery.py` | dep-graph connected where Liberator's is empty, specific where naive void\* over-connects |
| Handle **production** | SVF-write-gated INIT channel: `deflateInit_(z_stream*)` (single-ptr in-place init) recovered as a *creator* | `liberator_adapter/analysis/usedef.py` (`annotate_svf_writes` / `extract_produced_handles`) | zlib deflate/inflate family **0 → 34/36 constructable**; one driver covers `deflate.c` 570 + `inflate.c` 551 + `trees.c` 387 = 1874/3397 lines (55%), all 0 before the fix (measured via per-driver `run_extended_fuzzing` cov build) |

Closed-loop (Phase G) grows the automaton from Z3-viable sequences each round
(`src/closed_loop.py`, Step 11, opt-in `--closed-loop`).

### A/B kill-switches (G-pipeline)

| Flag | Effect |
|---|---|
| `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1` | drop G2 model-driven construction → random-walk grammar floor only |
| `LOGICFUZZ_DISABLE_DRIVER_TRACES=1` | T8: don't feed the project's own driver `.c` corpus into the automaton's consumer paths |

---

## 2. The typed LLM-context schema (②′, landed)

The neuro-symbolic boundary is a **typed, symbolically-grounded schema**, not a
prose dump: each LLM decision is decomposed into fixed slots, each slot populated
by the most authoritative source. Instantiated at the **two** generation-stage
LLM decision points. Full slot tables live in
`docs/contributions_and_related_work.md` §②′; the source map below records what
landed this round.

| Slot / feature | Source (file) | Landed |
|---|---|---|
| `library_constants` — legal enum/flag/format values | header enum + grouped-`#define` scan, `named_constants.py` | lcms 11 enums, zlib `Z_*`; rendered into prompt |
| per-API `ret_contract` — NULL/error guard | conditions.json return-provenance + doxygen `@return`, `error_contracts.py` | lcms 85 creators / c-ares 12 / cjson 18 → hole emits `⚠ returns NULL → NULL-check` |
| per-arg `populated_from` — which args fill this struct | SVF `set_by` (conditions.json) | lcms 75 edges (`cmsAppendNamedColor.arg0`→arg2,3) |
| `handle_provenance` — producer of a required handle (or none → construct/NULL) | use-def `produces`/`requires` index | c-ares verified (`ares_cancel`→`ares_init`) |
| Comprehender-B `sequence_facts` — per-API USE/DEF/KILL + `Typestate.check` verdict | use-def `APIEffect` + `Typestate` (selective: only this sequence's APIs) | A/B (c-ares, gpt-4o-mini): 1/12 rescue (false `INVALID→SUBOPTIMAL`), 0 new false-kills; kill-switch `LOGICFUZZ_DISABLE_SEQFACTS=1` |

**CALLSPEC** (one typed per-call row consolidating the hole slots; replaced 7
redundant prompt blocks — two role classifications, raw driver dumps, overlapping
API views) is now the **default** Prototyper context (commit `615a6c1b`, gate
removed). A/B that promoted it: c-ares best **1440 > 804** branches; lcms **88 >
0** (CALLSPEC-off both drivers SEGV'd, CALLSPEC-on yielded a running 88-branch
driver). Doc priors (`@return`/`@retval` contracts, README purpose) are
default-on and not switchable (token cost verified net-negative — a substantive
docstring lets the comprehender skip that API's LLM call).

---

## 3. Breadth + low-FP optimization round (2026-06)

**Motivation** (audit §6, contributions §3): the gap vs PromeFuzz/PromptFuzz/
CKGFuzzer is **API breadth × driver density**, not novelty — correct-by-
construction dropped every API the symbolic layer couldn't connect (≈302/452 gap
APIs never entered a candidate). The fix is **graceful degradation** — the
symbolic layer authors *structure*, the LLM fills the *gaps it can't prove*, and
a separate quality layer keeps the false-positive (FP) rate low. The
neuro-symbolic split is preserved: density only appends calls whose handle
dependencies are *already symbolically satisfied*; guards are IR-derived; the LLM
still owns only leaf values.

### Levers (all gated, all kill-switchable)

| Lever | Flag (default) | File | What it does | Measured |
|---|---|---|---|---|
| **B graceful degradation** | `LOGICFUZZ_STRICT_ORDERING` **off** = on | `sequence_constructor.py:433` | keep orphan-handle `USE_BEFORE_INIT` sequences → island/opaque APIs enter candidates; unchecked-render leaves the un-bindable arg as a hole | ≈302/452 previously-dropped gap APIs now enter the pool |
| **density** | `LOGICFUZZ_DENSE_CONSTRUCT` | `sequence_constructor.py:297` | append extenders that USE an already-open handle (`requires ⊆ opened`: mutator\*→consumer\*→getter\*) → thicken thin chains | thin chain 2.5 → 4.3 calls/seq |
| **density co-occurrence** | `LOGICFUZZ_DENSE_COOCCUR` (default 1), `LOGICFUZZ_DENSE_MAX_EXTRA` (default 8) | `sequence_constructor.py:308` | second `_densify` source: thicken along automaton accepting-path *real co-occurrence* (= PromeFuzz call-scope grouping) | lcms candidate 6.6 → **7.7 APIs/seq, median 7 = PromeFuzz 7.6** |
| **hard NULL-guard + opaque factory hint** | **implied by density** (`LOGICFUZZ_HARD_NULLGUARD` OR `DENSE_CONSTRUCT`) | `hole_semantics.py:33` | `ret_contract` advisory → `MUST-GUARD: if(!x)return0;` + "build the opaque handle via its producer" hint; **density requires it** (ablation: density-only SEGVs) | lcms combo FP 1→0 |
| **top_k breadth lever** | `LOGICFUZZ_TOP_K` (default 10; needs `LOGICFUZZ_NO_CACHE=1` to regen) | `data_context.py:316` | raise the greedy max-coverage selection cap → more skeletons → more distinct APIs in the merged union | offline greedy: top_k=100 → **c-ares 118 ≥ 113, zlib 95 ≥ 89** (matches PromeFuzz #API); lcms 100→136, 150→186 |
| **keep-best + file restore** | default | trial loop / merge | never ship a driver worse than the trial's peak; write the restored source **back to disk** (else merge ships the degraded driver) | bugfix `cbf09411` |
| **pre-ship quarantine + dead-filter** | default | `tools/merge_drivers/` | drop immediate-crash 0-coverage FP drivers before the merge (poison the fused harness otherwise); preflight dead-code bugfix (`3de80550`) | — |
| **crash-frame classifier** | reuses core | `tools/merge_drivers/crash_frame.py` | deterministic ASan frame attribution: driver-bug vs library-bug (symbolic fact, not LLM-judged) | — |

### Measured combo (30s A/B, single best driver — NOT 24h; do not compare to PromeFuzz Table 2)

| Project | baseline | combo (density+guard) | Δ cov | baseline FP | combo FP |
|---|---|---|---|---|---|
| lcms | 66 | **206** | **+212%** | 1 | **0** |
| c-ares | 1410 | 1412 | +0% (best neutral) | 4 | 4 |
| zlib | 515 | **545** (trial01 85→399) | +6% | 0 | 3 (pre-ship quarantine drops these at merge) |

**Ablation:** density and the guard are **synergistic** — neither alone helps
(lcms density-only = 0, all SEGV; guard-only = 54 ≈ 66); only the combo reaches
206. The c-ares "regression" is **LLM n=1 sampling variance** (density is a
construction-level no-op on a handle-less pure parser — no extender attaches),
*not* systematic density harm; part of it was a keep-best file-restore bug since
fixed.

**Cost (measured, gpt-4o, eval24 report.json):** top_k=10 run ≈ **\$0.5–0.9**;
top_k=56 ≈ \$3–5. PromeFuzz spent **\$15.89 for its entire 20-lib suite**. Cost is
a non-issue.

---

## 4. Build-cache (eliminate per-trial full library rebuild)

**Root cause of slow generation** (diagnosed, fixed for lcms): every trial
re-ran the *full* library build (`./configure && make`) inside `docker run --rm`
with `/out`,`/work` cleared — so a 56-driver lcms run did ~57 full
configure+make of liblcms2. Parallelism (`LLM_NUM_EXP=6`) was *not* the
bottleneck.

**Fix = zero new code, one config file** (commit `b00b1e34`). pub-llm already has
the OSS-Fuzz `ofg-cache` fully wired (`prepare_cached_images` in
`run_logicfuzz.py`; `build_target_local` already does
`is_image_cached → rewrite_project_to_cached_project → prepare_build`;
`OFG_USE_CACHING=1` default). It only lacked a `fuzzer_build_script/<project>`
for lcms (18 other projects already ship one). The added file
(`fuzzer_build_script/lcms`) is the **incremental** build: skip `./configure &&
make` (the static lib `src/.libs/liblcms2.a` is already in the cached base image,
built once) and only compile + link the fuzz target against it.

**Docker-measured (lcms top_k=8):** 2 cached images built (address + coverage),
51 × "Using cached instance for lcms", 0 compile errors, trials build+run
normally. The image is built once and reused by every trial.

**Extends to cjson/zlib/c-ares/libpng** the same way — one file each (open
roadmap). NB a subagent earlier reimplemented a whole build-cache *layer* and
branched from `main` (broke pub-llm) → reverted; the correct fix was the one
config file (see memory `feedback_efficiency_and_simplicity`).

---

## 5. Honest verdicts (do not oversell)

These are the measured caveats — every breadth/density claim above is bounded by
them.

- **Density's union-marginal is weaker than the optimistic estimate.** Real run
  (lcms56): 56 drivers → union **92 distinct APIs = 1.64 new APIs/driver**, vs
  PromeFuzz's 358/140 = **2.56/driver**. Dense drivers **overlap** (co-occurrence
  pulls in the same popular APIs), so the union **saturates fast**. Density raises
  APIs/*driver* (6.9, ≈ PromeFuzz 7.8) but **not** the union-marginal — "fewer
  drivers for the same breadth" is *not* substantiated. (Don't repeat the earlier
  "≈2.5× more driver-efficient" subagent estimate; it was too optimistic.)

- **coverage-diff is a proof-of-concept, NOT a contribution.** lcms56 merge vs the
  human OSS-Fuzz `fuzzers.c` (30 min each, driver TU excluded): we cover **876 lcms
  library lines the human driver covers zero of** (the whole IT8/CGATS parser
  `cmscgats.c` 723 + `cmsmd5` 153). But it is **complementary** — the human covers
  596 lines we miss (PostScript `cmsps2.c`, our known binding-layer blind spot),
  and our total 5953 < human 7346. "A different driver covers different code" is
  *normal*. To become a real claim this needs **(a)** multi-project reproducibility
  and **(b)** evidence we fill *more* existing-driver gap than PromeFuzz/CKGFuzzer.
  Both untested.

- **The opaque / no-producer tail is the binding-layer ceiling (#14).** top_k
  reaches PromeFuzz parity on c-ares/zlib but **not** lcms's 358 APIs (100→136,
  150→186, never 358): roughly half of lcms's APIs are opaque or have no in-project
  producer, so CBFactory's `RunningContext.try_to_get_var` can't synthesize their
  args and they never become skeletons regardless of ranking. This is the **#1 open
  bottleneck**, not a tuning problem.

- **Coverage is breadth-bound, not time-bound (at this scale).** The lcms56 merged
  harness plateaus at **~1424 branches in ~30 min**. More fuzz time does not close
  the gap; more reachable API surface (binding layer) does.

- **30s/30min A/B numbers are not 24h-union numbers.** The headline test — 24h
  `--merge` union vs PromeFuzz Table 2 (lcms ~13k, c-ares 6,106) — is still
  pending (cost is fine; deferred).

---

## 6. Open frontier

The live frontier is **below** the G1–G5 pipeline. Decision items + full rationale
live in `docs/generation_information_audit.md`; the short list:

| Item | Why it's the lever |
|---|---|
| **Binding layer (#14, highest leverage)** | make opaque/`void*`/caller-alloc-init args synthesizable instead of dropping the API → unlocks the lcms 358 tail and deep gap APIs (`cmsDoTransform`, …) top_k can't reach |
| **Multi-project coverage-diff validation** | turn the lcms PoC into a claim: reproduce across projects + show we fill more existing-driver gap than PromeFuzz/CKGFuzzer |
| **24h union real run** | the actual headline vs PromeFuzz Table 2 absolute coverage (cost OK, deferred) |
| **Lean mode** | deterministic crash triage (`crash_frame.py`) replacing the LLM crash analyzer + skip per-driver optimize → ~8.5 → ~3 LLM calls/driver |
| **Extend build-cache** | one `fuzzer_build_script/<project>` each for cjson/zlib/c-ares/libpng |

Feedback layers (audit, deferred / pending approval): F5 adaptive-shape
(error-injection skeletons, T11), F6 Phase C CEGAR loop (prereq WorkingMemory),
T7 cross-project driver retrieval, T10 generalized format-entry decoder, T12
dynamic value-feedback. **Rejected (do not re-litigate):** T9 static CFG
reachability weighting — measured dependency graphs are too flat (max depth 1–3)
and planner blind spots are depth-independent, so reranking can't recover them;
the root cause is the binding layer, not ranking.
