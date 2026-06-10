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
| `docs/contributions_and_related_work.md` | the 3-innovation pitch + PromeFuzz/Liberator/PromptFuzz/CKGFuzzer comparison + per-LLM-call-site rationale |
| `docs/knowledge_layer.md` | comprehender / automaton mechanics |
| `CLAUDE.md` | flags table, Step 5x implementation flow, file map |

Open decision items + the future roadmap are folded into §6 below (this doc is
their SSOT).

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
| Handle **production (a)** | SVF-write-gated INIT channel: `deflateInit_(z_stream*)` (single-ptr in-place init) recovered as a *creator* | `liberator_adapter/analysis/usedef.py` (`annotate_svf_writes` / `extract_produced_handles`) | zlib deflate/inflate family **0 → 34/36 constructable**; one driver covers `deflate.c` 570 + `inflate.c` 551 + `trees.c` 387 = 1874/3397 lines (55%), all 0 before the fix (measured via per-driver `run_extended_fuzzing` cov build) |
| Handle **production (b)** — factory chain | naming-based opaque-return producer recovery: a required non-pointer opaque handle whose creator's return the IR desugared to `void*` (`cmsHTRANSFORM`) is mapped to its `cmsCreate*Transform` factory and fed to the recursive prefix resolver (non-pointer test + camelCase word-boundary + deep-factory preference) | `liberator_adapter/analysis/sequence_constructor.py` (gate `LOGICFUZZ_FACTORY_CHAIN`) | **first dent in the binding-layer ceiling (#14).** lcms (probe + live run): recovered handle types 0→2, deep opaque args 0→**77/128**, avg prefix 0.15→0.89, `cmsDoTransform` constructs full chain **and compiles in**; 8 handle-struct libs byte-identical (no regress). *But deep coverage NOT won:* degraded-30s probe = **cmsxform.c 0/799** (valid-ICC-profile input blocks the chain → next bottleneck is the **input/seed layer**, not construction). Clean Z3-on confirm blocked by build-cache×llvm14 (§4) |

Closed-loop (Phase G) grows the automaton from Z3-viable sequences each round
(`src/closed_loop.py`, Step 11, opt-in `--closed-loop`).

### A/B kill-switches (G-pipeline)

| Flag | Effect |
|---|---|
| `LOGICFUZZ_DISABLE_G2_CONSTRUCT=1` | drop G2 model-driven construction → random-walk grammar floor only |
| `LOGICFUZZ_DISABLE_DRIVER_TRACES=1` | T8: don't feed the project's own driver `.c` corpus into the automaton's consumer paths |

**Now default-on (gates removed 2026-06):** factory chain (opaque void\*-return
producer recovery), density + hard NULL-guard, max-coverage diversity selection,
real seed-corpus routing, lean crash triage + skip per-driver optimize,
typedef-handle recovery. Lean's deterministic crash triage falls back to the LLM
crash path on an `unknown` ASan frame.

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

**Motivation** (§6 roadmap, contributions §3): the gap vs PromeFuzz/PromptFuzz/
CKGFuzzer is **API breadth × driver density**, not novelty — correct-by-
construction dropped every API the symbolic layer couldn't connect (≈302/452 gap
APIs never entered a candidate). The fix is **graceful degradation** — the
symbolic layer authors *structure*, the LLM fills the *gaps it can't prove*, and
a separate quality layer keeps the false-positive (FP) rate low. The
neuro-symbolic split is preserved: density only appends calls whose handle
dependencies are *already symbolically satisfied*; guards are IR-derived; the LLM
still owns only leaf values.

### Levers (now default-on; only tuning knobs + kill-switches remain as flags)

| Lever | Flag (default) | File | What it does | Measured |
|---|---|---|---|---|
| **B graceful degradation** | `LOGICFUZZ_STRICT_ORDERING` **off** = on | `sequence_constructor.py:433` | keep orphan-handle `USE_BEFORE_INIT` sequences → island/opaque APIs enter candidates; unchecked-render leaves the un-bindable arg as a hole | ≈302/452 previously-dropped gap APIs now enter the pool |
| **density** | **default-on** (tune `_DENSE_MAX_EXTRA`/`_DENSE_COOCCUR`) | `sequence_constructor.py:_densify` | append extenders that USE an already-open handle (`requires ⊆ opened`: mutator\*→consumer\*→getter\*) → thicken thin chains | thin chain 2.5 → 4.3 calls/seq |
| **density co-occurrence** | `LOGICFUZZ_DENSE_COOCCUR` (default 1), `LOGICFUZZ_DENSE_MAX_EXTRA` (default 8) | `sequence_constructor.py:308` | second `_densify` source: thicken along automaton accepting-path *real co-occurrence* (= PromeFuzz call-scope grouping) | lcms candidate 6.6 → **7.7 APIs/seq, median 7 = PromeFuzz 7.6** |
| **hard NULL-guard + opaque factory hint** | **default-on** | `hole_semantics.py:_hard_nullguard` | `ret_contract` advisory → `MUST-GUARD: if(!x)return0;` + "build the opaque handle via its producer" hint; coupled with density (ablation: density-only SEGVs) | lcms combo FP 1→0 |
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

**Fix = zero new code, one gate file** (commit `b00b1e34`). pub-llm already has
the OSS-Fuzz `ofg-cache` fully wired (`prepare_cached_images` in
`run_logicfuzz.py`; `build_target_local` does
`is_image_cached → rewrite_project_to_cached_project → prepare_build`;
`OFG_USE_CACHING=1` default). It only lacked a `fuzzer_build_script/<project>`
for lcms (18 other projects ship one).

**How it actually works (verified empirically, NOT what it looks like):**
`fuzzer_build_script/<project>` is used at `oss_fuzz_checkout.py:235` ONLY as an
**existence gate** — its *content is never applied as build.sh* in pub-llm. The
mechanism is: (1) `prepare_cached_images` builds the library into a committed
image ONCE; (2) each trial `FROM`s that image and **re-runs the ORIGINAL
build.sh**. So the speedup depends on the project's build.sh being **idempotent**
on the prebuilt image — `make` becomes a no-op (lib already built), only the
driver recompiles.

**Docker-measured (lcms top_k=8):** 2 cached images built, 51 × "Using cached
instance for lcms", 0 errors — lcms's `./configure && make` re-runs cleanly
(make no-op) → partial speedup (skips the `make all` relink). The `fuzzer_build_script/lcms`
file's content is moot (gate only); an empty file would behave identically.

**Extension is NOT "one file each".** It needs each project's build.sh to be
idempotent on the cached image. **c-ares FAILS** (verified): its build.sh does
`cd $SRC/googletest; mkdir build` → "File exists" on re-run. Fix = make the
build.sh idempotent in the **OSS-Fuzz fork** (`mkdir build` → `mkdir -p build`,
etc.), a per-project ~1-line fork edit (fork = github.com/MarkLee131/oss-fuzz).
cjson is a cheap single-file lib (low value). So the cache extension is a
per-project fork-idempotency task, not a quick config drop — open roadmap.
NB a subagent earlier reimplemented a whole build-cache *layer*, branched from
`main` (broke pub-llm) → reverted (see memory `feedback_efficiency_and_simplicity`).

> **⚠ Build-cache silently disabled Z3 — RESOLVED by A1 (additive canonical base).**
> *The problem:* with the cache on, the reused `gcr.io/oss-fuzz/<proj>` image had
> **no clang-14** → LLVM/SVF extraction fell back to clang-only → `function_conditions`
> empty → **CBFactory degraded, Z3 OFF for the whole run** (skeletons via the
> no-Z3-gate model path). So every cached lcms eval before this ran Z3-off — the
> "Z3-validated skeleton" claim held only for non-cached runs. Tell-tale in old
> logs: `Reused existing image … (no rebuild)` + `clang-14 not found` + `CBFactory
> degraded mode`.
>
> *The fix (`ensure_llvm14_base_builder`):* build the llvm14 image **additively**
> (clang-14 at /usr/lib/llvm-14 for `wllvm`; the default `/usr/local` OSS-Fuzz clang
> + its libc++ are untouched, so fuzzers still link — the earlier "fuzzers don't
> link on llvm14" was a **misdiagnosis**; the real 0-drivers cause was a
> cache-rewrite that dropped the source) and **retag it onto the canonical
> `gcr.io/oss-fuzz-base/base-builder`**. Every project AND cache image built FROM it
> then carries clang-14 — one image serves both fuzzer builds and extraction; no
> Dockerfile patch, no separate extraction image, no cache bypass. Wired before
> `prepare_cached_images`. Validated: extract-only on the additive base → fresh
> 651KB `conditions.json`, no degraded/clang-only.
>
> *One-time deploy step:* OFG cache images are registry-hosted (`_prepare_image_cache`
> pulls before building), so a cache image pulled from the registry was built on the
> OLD base — rebuild + re-push the `*-ofg-cached-*` images on the additive base (or
> run `OFG_USE_CACHING=0`) to make cached eval Z3-on. Full diagnosis + recipes:
> memory `project_buildcache_llvm14_conflict`.

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

- **The opaque / no-producer tail is the binding-layer ceiling (#14) — now
  *partially* lifted.** top_k reaches PromeFuzz parity on c-ares/zlib but **not**
  lcms's 358 APIs (100→136, 150→186, never 358): roughly half of lcms's APIs are
  opaque or have no in-project producer, so CBFactory's
  `RunningContext.try_to_get_var` can't synthesize their args and they never become
  skeletons regardless of ranking. The **factory chain** (`LOGICFUZZ_FACTORY_CHAIN`,
  handle-production channel b) is the first dent: opaque handles whose creator the
  IR hid behind a `void*` return (`cmsHTRANSFORM` ← `cmsCreate*Transform`) are
  recovered by naming and chained — lcms deep opaque args satisfied 0→77/128,
  `cmsDoTransform` constructable **and compilable** (confirmed in a live run: the
  emitted skeletons include a wired `cmsCreate_sRGBProfile → cmsCreateTransform →
  cmsDoTransform → cmsDeleteTransform`, `n_factory_recovered=2`). **But three
  caveats:** **(i)** *deep coverage is not won* — a degraded-30s probe covered
  **0/799 of `cmsxform.c`** despite compiling it in: the opaque chain needs a
  *valid ICC profile* (`cmsOpenProfileFromMem`) that random bytes never form →
  `cmsCreateTransform` NULL → guard → `cmsDoTransform` never runs. **The next
  bottleneck is the input/seed layer, below the binding layer — not construction,
  not Z3.** **(ii)** the residual no-producer / non-`Create*`-named tail still
  drops to NULL holes. **(iii)** a clean Z3-on confirmation is blocked by a
  build-cache×llvm14 image-isolation bug (§4). So #14 is **demoted from "#1
  untouched" to "construction-lifted; input layer is the new ceiling"** — still
  top leverage, not a closed problem.

- **Coverage is breadth-bound, not time-bound (at this scale).** The lcms56 merged
  harness plateaus at **~1424 branches in ~30 min**. More fuzz time does not close
  the gap; more reachable API surface (binding layer) does.

- **30s/30min A/B numbers are not 24h-union numbers.** The headline test — 24h
  `--merge` union vs PromeFuzz Table 2 (lcms ~13k, c-ares 6,106) — is still
  pending (cost is fine; deferred).

---

## 6. Open frontier

The live frontier is **below** the G1–G5 pipeline. This section is the SSOT for
open items, decision items, and the roadmap (the audit doc was folded in here).
The short list:

| Item | Why it's the lever |
|---|---|
| **Input/seed layer (NEW #1 below binding) — real-seed routing landed (default-on), gain unmeasured** | factory chain made `cmsDoTransform` constructable+compilable, but it covers **0/799 of `cmsxform.c`** because random bytes never form a valid ICC profile to traverse the opaque chain. Real-seed routing (now default-on) copies the project's REAL format-matching seeds (`*.icc`/`*.it8`/…, classified by parser-entry API + file magic) into each driver's generation corpus + the merged harness (`scripts/seed_discovery.py:seed_corpus_for_driver` → `builder_runner._seed_corpus_dir`; additive, no-op when no seeds). **Next:** measure the cmsxform.c gain end-to-end; synthetic seed generation from format analysis still TODO |
| **build-cache × llvm14 — RESOLVED by A1 (additive canonical base)** | was: extraction (clang-14) and trials shared one `gcr.io/oss-fuzz/<proj>` tag → cached eval silently Z3-off. Fix (`ensure_llvm14_base_builder`): build the *additive* llvm14 image (clang-14 added; default `/usr/local` clang + libc++ untouched → fuzzers link — the "fuzzers don't link on llvm14" worry was a misdiagnosis) and retag it onto `gcr.io/oss-fuzz-base/base-builder`, so every project + cache image inherits clang-14. **One-time deploy:** rebuild + re-push the registry-hosted `*-ofg-cached-*` images on the additive base (or `OFG_USE_CACHING=0`). See memory `project_buildcache_llvm14_conflict` |
| **merged-harness coverage validity — RESOLVED (compile-validation gate + cov-build fix)** | the merged harness used to read spurious 0 coverage: a compile-INVALID driver was KEPT (preflight only vets RUN — "couldn't vet ⇒ keep"), then silently shadowed by `merge.py`'s `\|\|continue` skip + weak-stub no-op, so the address build and coverage build compiled DIFFERENT TU sets (A≢B) → a corpus input hit a real sub-driver in one and a stub in the other → 0 coverage. **Fix:** the **compile-validation merge gate** (`tools/merge_drivers/compile_validate.py:validate_compilable` + `run_single_fuzz._compile_validate_candidates`) includes ONLY drivers that compile under the real OSS-Fuzz coverage-build flags (per-TU C/C++; `-Werror=implicit-function-declaration` re-promoted to catch the link-class failures `-fsyntax-only` misses), so both builds compile the IDENTICAL valid set. Fail-open (no docker ⇒ keep all); opt-out `LOGICFUZZ_SKIP_COMPILE_VALIDATE=1`; writes `merged/compile_validation.json`. lcms: excluded 9/11 invalid drivers → llvm-cov 551/9590 br (no longer 0). Separately, `run_extended_fuzzing._build_coverage_image` now scrubs in-source artifacts (`git clean -dxf` per /src repo) + `build_fuzzers --sanitizer coverage --clean`, forcing the LIBRARY to rebuild WITH coverage instrumentation rather than reusing the ASan build — fixes the prior inconsistent denominators (22 vs 18797 instrumented lines). **Also landed (`skeleton_generator.py`, commit `777cef0c`):** the skeleton-rendering validity fix — the renderer now emits valid C/C++ *by construction* (void/`void*` array element → `uint8_t` buffer; opaque types → pointers not value-arrays-of-incomplete-type; struct values `{0}`-init; internal opaque typenames → `void*`; `*_internal.h` filtered; cleanup only on declared `ret_<api>`), so far fewer drivers reach the gate invalid (lcms: void-arrays 6→0, opaque value-arrays 8→0, internal typenames 6→0, undeclared `ret_*` 8→0; previously-broken skeletons now compile). The gate and the renderer are complementary — valid-by-construction up front + a fail-open safety gate at merge |
| **Binding layer (#14) — construction lifted, tail remains** | factory chain (channel b, `LOGICFUZZ_FACTORY_CHAIN`) recovers opaque `void*`-return producers; **next:** recover the residual non-`Create*`-named / no-in-project-producer tail, + caller-alloc-init args beyond the SVF-INIT channel |
| **Multi-project coverage-diff validation** | turn the lcms PoC into a claim: reproduce across projects + show we fill more existing-driver gap than PromeFuzz/CKGFuzzer |
| **24h union real run** | the actual headline vs PromeFuzz Table 2 absolute coverage (cost OK, deferred) |
| **Verify lean-mode savings** | lean mode is now the default (deterministic `crash_frame.py` triage + no per-driver optimize; the optimize/improver/§10B nodes were **removed**, not just orphaned); the ~8.5 → ~3 LLM-calls/driver figure is *projected* — confirm on a real eval run |
| **Extend build-cache** | per-project fork-idempotency (lcms ✓, c-ares ✓); remaining: cjson/zlib/libpng |

Feedback / input layers — **T10 / T11 / T12 implemented (all gated, coverage A/B
pending — start gated like factory/diversity/lean did):**

- **T10 — generalized format-entry → synthetic seed** (`LOGICFUZZ_FORMAT_INFER`;
  `liberator_adapter/analysis/format_inference.py` → `scripts/seed_discovery.py`):
  when no real seed matches a parser-entry driver, synthesize a minimal
  front-gate-passing seed from an inferred FormatSpec (sampled-seed prefix >
  known-magic registry > header `#define` magic). *Scope (honest):* deterministic
  *constant* inference, NOT full IR symbolic execution — the IR carries no branch
  predicates, so a synth seed clears the *leading magic gate*, not a complex
  parser's deep validation. Real seeds (routing) still preferred; synth is the
  no-seed fallback. 15 unit tests.
- **T11 — error-shape skeleton variants** (`LOGICFUZZ_ERROR_VARIANTS`;
  `sequence_constructor.error_shape_variants`): emit guard-testing shapes
  (SKIP_INIT / DOUBLE_DESTROY by default; USE_AFTER_DESTROY only behind
  `LOGICFUZZ_ERROR_VARIANTS_AGGRESSIVE`) for **gap-touching** sequences, so library
  error branches become reachable. The LLM still fills only leaf holes; any crash
  is triaged by the existing crash-frame classifier (driver-bug → merge
  quarantine). 13 unit + integration tests (through `construct_sequences`).
- **T12 — dynamic value feedback** (`LOGICFUZZ_VALUE_FEEDBACK`;
  `coverage_memory.{record_trial_hole_values,proven_hole_values,attach_proven_holes}`):
  capture a trial's filled hole values, then pin the deepest-coverage ones into the
  SAME API-sequence's holes on the NEXT run — matched by **sequence content hash**
  (`sequence_key`), NOT the positional `cbfactory_skeleton_{i}` name (which would
  mis-pin onto an unrelated chain). Cross-run; the "read" side of Phase C. 13 unit
  tests incl. the no-mis-pin regression.
- **B+D scoped NULL-guards** (`LOGICFUZZ_SCOPED_GUARDS`, default-OFF, coverage A/B
  pending; `sequence_constructor._dependency_components` + `skeleton_generator`):
  partition a sequence into dependency components and render the creator NULL-guard
  **per component** (B1 nested-if) instead of the legacy whole-driver
  `if(!parser)return0`. A producer's guard then wraps only its handle-consumers, so
  an INDEPENDENT API (one that doesn't consume the parser's handle) renders OUTSIDE
  the guard and runs even when the parser returns NULL on random fuzz input.
  Measured (controlled single-file): **+523 br (12.6×)** when the parser fails; ≈0
  when valid seeds let it succeed — the gain is conditional on parser-failure, the
  common fuzz case. PromeFuzz has no dependency model / no parser-vs-independent
  distinction → differentiator.
- **Tier-1 fuzzable-holes value-domain** (`LOGICFUZZ_FUZZABLE_HOLES`, coverage A/B
  pending; `hole_semantics._arg_intent`): scalar/float CONFIG holes emit a
  FUZZ_DERIVE intent that invokes the LLM's own value-domain judgement (choose a
  SEMANTICALLY VALID range — chromaticity≈0..1, gamma≈0.1..5, temp≈1000..25000 —
  then derive from the fuzz input; *not* an arbitrary `data[i]%65536` modulus); enum
  holes index a fuzz byte into the legal constant set. Language-agnostic intent;
  the mechanism is supplied by the language-split user prompt (C → index `data[N]`;
  C++ → `FuzzedDataProvider`). This is PromeFuzz's *automatic* depth mechanism (the
  LLM's trained knowledge) made explicit — NOT hand-written per-lib `api_hints`
  (PromeFuzz's manual cheat). Confirmed: cmsBuildParametricToneCurve type+params
  fuzz-derived → cmsgamma.c 84→121 br (+44%, same budget).

Still open: **F6 Phase C CEGAR loop** (prereq WorkingMemory — T12 is a *precursor*,
not the principled loop), **T7** cross-project driver retrieval (corpus + embedding
index now BUILT — see below; **dedup now wired** — `load_corpus` filters by
`results/xproj_index/dedup_keep.json`, corpus 4757→2217; embedding/distill scripts
added — re-rank wiring of the template embedding into `cross_project_retrieval` + the
coverage A/B remain). **Rejected (do not re-litigate):** T9 static CFG reachability
weighting — measured dependency graphs are too flat (max depth 1–3) and planner
blind spots are depth-independent, so reranking can't recover them; the root cause
is the binding layer, not ranking.

### T7 cross-project corpus + embedding index (built 2026-06-09)

Dataset facts for the paper's data-section / threats-to-validity.

**Corpus source (design correction).** The original plan said "all OSS-Fuzz drivers
via the FuzzIntrospector (FI) API," but FI only serves harness *paths/metadata*
(`/harness-source-and-executable`); `/source-code` and any all-projects listing
endpoint return 404. Built instead from the OSS-Fuzz-gen GCS bucket
`oss-fuzz-llm-public/human_written_targets/` (`data_prep/extract_all_fuzz_drivers.py`,
anonymous, $0): **484 projects / 4757 C/C++ harnesses** (pure driver source — no
`.h` in the bucket; the loader ext set must cover `.cxx`/`.c++` or 58 C++ harnesses
silently drop).

**Embedding index** (`results/xproj_index/`, `scripts/build_xproj_embeddings.py`,
5 parallel shards → merge): OpenAI `text-embedding-3-large` (3072-dim). Input is
comment-stripped first (reusing the structure-sig `_COMMENT_RE` — every driver's
identical license header would otherwise inflate pairwise cosine and dilute the
API-usage signal) then truncated by *actual* tokens (tiktoken cl100k_base, cap
8000). One-time cost **$0.315** (2,421,735 tok × $0.13/1M — far under a ~1k/file
estimate because drivers are small).

**Token distribution (post-strip):** median **239**, mean 573, p90 1000, p99 6571,
max 32946.

**Truncation reaches 0.95% (45/4757); the genuinely-affected share is 0.29%:**

| bucket | content | n | retrieval meaning |
|---|---|---|---|
| A | libFuzzer engine self-tests (`FuzzerUnittest.cpp`, `MultipleConstraintsOnSmallInputTest.cpp`) | 11 | noise, not a library driver → name-blacklist |
| B | vendored framework dispatchers (`entry.cpp` ×9 cryptofuzz, `ssl_ctx_api.cc` ×11 boringssl) | 20 | cross-project near-duplicates |
| C | genuine large single-library drivers (sqlite3 `fuzzcheck.c`, libxml2 `api.c`, njs `njs_shell.c`, nodejs `wasm-compile.cc`, msquic `spinquic.cpp`, …) | 14 | **the only real truncation loss = 0.29%**, most keep 60–97% (worst 24%) |

**Two buffers (why 0.29% truncation is tolerable):** the embedding is a *re-rank
fallback* over structure-sig, and structure-sig uses the FULL untruncated API-call
list (`extract_api_calls` over the whole file) — so a truncated driver keeps a
complete structural signature; only its embedding vector is partial.

**Corpus hygiene — DONE (`scripts/dedup_xproj_index.py`, wired into `load_corpus`).**
The corpus was **53% redundant**: of 4757 drivers, **2508 were vendored near-copies**
(same harness copied across projects — `fuzzer`/`onefile` ×11, `dtls_server`/`client`/
`driver`/`spki`/`dtls_client` ×10, …) + **32 libFuzzer-selftest/runner-stub noise**,
leaving **2217 unique**. Detection = SOURCE-embedding cosine > 0.97 (≈identical text)
— SOURCE, not template, embedding, so genuine "same-construction, different-library"
analogs are NOT collapsed. `load_corpus` auto-restricts to `dedup_keep.json` when
present (absent → whole corpus). This is why a query for a heavily-vendored library
(libpng) used to return its own driver's 9 copies — dedup collapses them to 1.

**Reference-value retrieval axis (the construction-template re-rank).** Raw-source
embedding ranks by DOMAIN (vocabulary), but reference value = transferable
CONSTRUCTION shape. So each driver is also distilled (gpt-4o-mini, one-time, grounded
on its actual extracted calls + regex-detected `entry_type`) into a library-agnostic
construction template (input-wiring idiom + role sequence `create→…→destroy` +
resource shape), and the TEMPLATE is embedded → `templates_embeddings.npy`. Leave-one-out
(offline probe, since removed): template-embedding beats source-embedding on
**cross-domain-transferable@5 = 35.5% vs 14%** (same construction, different domain —
the high-value references domain-clustering misses), and on construction@5 (43% vs 26%);
source-embedding wins domain@5 (the two are orthogonal axes). **Rejected (don't
re-litigate): RRF fusion** of embedding+role+api-set rankings LOST to embedding-alone
(domain@5 rrf 40% < emb 46.5%) — equal-weight fusion drags the strong signal toward the
weak literal ones; relevance is a semantic judgment for the LLM, not a hand-weighted sum.
**Caveat:** libpng was an unrepresentative worst case (9 self-copies); most libs have 0–3
(libtiff/tinygltf/sqlite3/lcms = 0), and for them retrieval surfaces genuine cross-project
analogs (re2→boost_regex, tinygltf→readstat parsers). The decisive test remains the
end-to-end hint A/B; same-domain/construction@K are proxies.

### Roadmap & open decisions (folded from the generation-information audit)

**Scope of the audit:** only the *driver-generation* stage. **Question it
answered:** are we feeding the LLM the *right* information or the *most*? **Core
judgment (still holds):** the division of labor is right at the large scale — Z3
⊕ use-def ⊕ typestate own program *structure* (lifecycle, handle wiring, call
order); the LLM owns the *soft* decisions (values, semantics, hole-filling).
This round plugged most of the "information leaks at every boundary"
(schema-feeding the LLM, deterministic extraction of constants/contracts/
producers). The remaining open items fall in two classes: (1) cross-project
knowledge + new techniques (needs a decision); (2) the binding layer + the
multi-project validation roadmap.

**The unified abandonment-point fix.** Wherever the symbolic layer "can't give a
certain answer and gives up," it can still hand the LLM the *known half* as a
structured `value_intent` slot in the schema, so the LLM completes from evidence
rather than guessing blind. The three symbolic abandonment points already
addressed this way:

| # | Where symbolic gives up | Information lost | What the LLM is forced to guess | Landed as |
|---|---|---|---|---|
| 2 | how to construct parser-entry bytes | entry **magic / length / version checks** (only ICC/IT8 hardcoded) | how to assemble bytes that pass the front-gate into deep code | **T10** (`LOGICFUZZ_FORMAT_INFER`) |
| 4 | only happy-path skeletons generated | (error shapes never told to the LLM) | — (error branches were unreachable by construction) | **T11** (`LOGICFUZZ_ERROR_VARIANTS`) |
| 5 | the working runtime values are discarded | the value that **actually reached a deep branch** in a trial (`coverage_memory.json` was write-only) | re-guesses from scratch next round | **T12** (`LOGICFUZZ_VALUE_FEEDBACK`) |

**Open experimental validation (each gated feature needs a docker coverage A/B
before default-on):**

- **Multi-project end-to-end A/B of the typed-context (CALLSPEC) schema.**
  CALLSPEC is now default + the redundant prompt blocks were cut (§2). But a
  prompt-schema refactor changes LLM behavior in ways unit tests can't catch — to
  confirm it raises coverage without regression needs a larger-sample,
  **multi-project** end-to-end A/B (old vs new prompt on cjson/zlib/lcms; compare
  coverage + tokens). What ran so far is smoke-level (c-ares best 1440 > 804;
  lcms 88 > 0); the full live-`prepare()` multi-project comparison is still owed.
- Multi-project coverage-diff validation, the 24h union real run, and per-gated-
  feature coverage A/Bs (T7/T10/T11/T12, scoped-guards, fuzzable-holes) — see the
  short-list table above.

**B2 static-analysis residue (still open):** (i) there is **no true CFG
reachability** — L4's "reachability" is automaton protocol-acceptance, not "how
many uncovered blocks does this API gate." **T9 (static CFG reachability weighting)
was measured and rejected** (dependency graphs are too flat, max depth 1–3; planner
blind spots are depth-independent → reranking can't recover them; root cause is the
binding layer, #14 above). (ii) `set_by` write-mask / `len_depends_on` overlap with
the existing LENGTH/OUTPUT intent — deferred (empirical-before-parametric: split
only when downstream genuinely needs it).

**Deferred methodology fixes (not yet walked; recorded for later):**

- **Funnel fault-tolerance** — recover compile failures via the LangGraph fixer,
  loss-tolerant like PromeFuzz (deferred).
- **Per-subsystem multi-driver generation** — cluster drivers by subsystem
  (lcms postscript / tag / optimizer) so each deep subsystem gets dedicated
  drivers (deferred).
- **Relax correctness to let the LLM attempt hard APIs** — this is *in tension*
  with the correct-by-construction, no-repair mainline; graceful degradation
  already buys breadth without sacrificing the mainline, so this is a **needs-a-
  decision** item (lean: symbolic guarantees the connectable core, gives island
  APIs the maximum hint for LLM best-effort, fails to the fixer — graceful
  degradation, not a hard drop).

**TLR (FSE'26) — reference value (bounded).** Its formalism differs in domain
(memory-error typestate vs our API-protocol typestate) and stage (post-hoc replay
of known traces vs our forward synthesis with no traces). The one solid principle
— ablation shows *typestate-selective context feeding > dumping everything* — is
exactly the direction our ②′ typed-context schema already takes (see
`contributions_and_related_work.md` §②′), so it stays a related-work citation +
design sanity-check. The only reusable engineering trick: its "snapshot only at
typestate transition points" idea could keep T12's runtime traces lean if/when
T12 grows a richer trace.
