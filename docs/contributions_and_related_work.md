# LogicFuzz — Contributions & Related-Work Comparison

What problems in fuzz-driver generation LogicFuzz solves, the **three
innovations** that distinguish it from prior work, and an objective,
component-level comparison against the two systems it is closest to:

- **PromeFuzz** (`reference/promefuzz`) — the LLM-driven driver generator our
  knowledge layer is derived from. The representative *neural* baseline.
- **Liberator** (`reference/liberator`, HexHive) — the constraint-based driver
  synthesizer our backend is adapted from. The representative *symbolic*
  baseline.

This doc is the single source for the "what's new vs prior work" pitch and the
descriptive baselines behind it. For the generation pipeline see
`docs/generation.md`; for the comprehender/knowledge layer see
`docs/knowledge_layer.md` (automaton mechanics: `CLAUDE.md`).

---

## 1. The problem, and why prior work plateaus

A fuzz driver must call a *meaningful, lifecycle-correct sequence* of library
APIs and feed fuzzer bytes into the one that parses untrusted input. Two
families of prior tools each get one half right and pay for the other:

| Failure mode | Where it bites |
|---|---|
| **P1 — LLM decides program structure** | The LLM picks the API set, the call order, the arg wiring, and the input derivation in one shot. It hallucinates APIs, mis-orders lifecycles (use-before-init, missing destroy), and fakes types. Validity is recovered *after the fact* by build/run + crash learning, burning tokens on repair. *(PromeFuzz)* |
| **P2 — pure symbolic types over-connect, and lose handle structure** | Type compatibility ≠ semantic validity, so a type-driven graph proposes nonsense chains; and the compiler IR collapses every opaque handle (`typedef void* cmsHPROFILE`) to `void*`/`i8*`, so the handle dependency graph for such a library is *empty* — deep creator→consumer→destroyer chains can never form. A second blind spot has the same effect: the production model recognizes only *return-value* and *out-pointer* (`T**`) creators, so a **caller-allocated struct initialized in place** (`deflateInit_(z_stream*)` — single pointer, indistinguishable by arity from a plain consumer) appears to have *no producer*, and the whole stateful family (zlib deflate/inflate) is unconstructable. *(Liberator)* |
| **P3 — coverage saturates on the shallow surface** | Without library-specific usage knowledge and without aiming at code the existing corpus misses, drivers re-cover the easy entry points and never reach deep subsystems (parsers, serializers, optimizers). |

Empirically, P2/P3 are not hypothetical: on lcms every opaque handle is
`void*`, so the un-recovered dependency graph yields a driver portfolio
dominated by the one self-contained subsystem with a direct byte entry (IT8/
CGATS), and a 4-hour fuzzing campaign saturates at ~27–29% line coverage —
**the 3,386-line tag-deserializer (`cmstypes.c`, the richest attack surface)
gains +9 lines in 4 hours** because no driver ever reaches it. The ceiling is
structural, not a matter of fuzz time.

---

## 2. Three innovations vs prior work

### ① A reconciled neuro-symbolic API semantic model — *reconcile, don't guess; identify, don't over-connect*

LogicFuzz builds an `APISemanticModel` (`analysis/api_semantic_model.py`, G1)
that **deterministically fuses three evidence sources** into one per-API verdict
before any sequence is proposed:

- **IR mechanism** — produces/requires/kills handle types from a use-def walker
  (`analysis/usedef.py`), gated by **SVF per-argument read/write value-flow**
  (`conditions.json`) to tell an *initializer* from a same-struct *mutator*;
- **doc/naming intent** — role verbs, doxygen/README priors;
- **usage composition** — accepting paths from the project automaton.

This model is the **role authority** (demoting the heuristic
`ConditionManager`), and it is recovered to be *correct* by **two orthogonal
recovery passes** that restore handle relations the raw IR view drops:

1. **Handle *identity*** — a typedef-handle recovery pass
   (`analysis/handle_typedef_recovery.py`) restores the opaque-handle identity
   the compiler IR discards (re-typing collapsed `void*`/`i8*` slots back to
   `cmsHPROFILE` / `cmsHTRANSFORM` from the public headers), so the dependency
   graph is *connected where Liberator's is empty* and *specific where a naive
   void*-graph would over-connect* (`cmsHPROFILE` ≠ `cmsHTRANSFORM`).
2. **Handle *production*** — a caller-allocated, in-place-initialized struct
   (`z_stream` ← `deflateInit_(z_stream*)`) is restored as a *producer* via an
   **SVF-write-gated INIT channel** (`analysis/usedef.py`): an init-named
   single-pointer struct counts as creating that struct unless SVF's value-flow
   positively observed the parameter read-only — which correctly rejects
   same-arity *consumers* like `pthread_create(attr*)` (reads the attr) while
   accepting true initializers. Without it the deflate/inflate family has no
   creator and never forms a chain; with it the lifecycle prefix
   (`deflateInit_` → `deflate` → `deflateEnd`) constructs.

Both passes are deterministic — zero LLM, zero token cost.

> **Empirical anchor (zlib, validated 2026-06):** with the production-recovery
> channel the deflate/inflate family goes from **0 → 34 of 36 constructable**,
> and a single generated driver covers **`deflate.c` (570 lines) + `inflate.c`
> (551) + `trees.c` (387)** — *all 0 before the fix* — for 1,874/3,397 lines
> (55%) in that driver's own coverage build. Without the recovery no chain forms
> for `z_stream`, so none of that code is reachable by any driver. (Measured via
> the per-driver `run_extended_fuzzing` build; the project's *eval* coverage
> build is degenerate for zlib — it re-measures the baseline `checksum_fuzzer`,
> so cov-diff over it understates every zlib driver.)

> **vs prior work:** PromeFuzz has no dependency substrate at all (the LLM
> infers relationships); Liberator has a type substrate that both
> over-connects (type ≠ semantics) and collapses handle identity. We reconcile
> mechanism, intent, and usage into a substrate that is both connected and
> precise.

### ② Correct-by-construction, gap-directed synthesis — *Z3 owns hard constraints, the LLM owns soft ones*

Sequences are **constructed** from the semantic model
(`analysis/sequence_constructor.py`, G2), not generated-then-repaired and not
random-walked over a grammar:

- chains are **lifecycle-complete by construction** (creator → mutator\* →
  consumer → destroyer), preferring the creator that *ingests fuzzer bytes*
  (e.g. `cmsOpenProfileFromMem` over a synthetic constructor) so fuzz input
  reaches real depth;
- they are **gap-directed** (G5, `analysis/coverage_gap.py`): the
  baseline-uncovered API surface is targeted first, so drivers add *new* lines
  instead of re-covering the corpus;
- they are **self-verified** by an independent typestate oracle and confirmed by
  Z3 (`TYPE_MATCH` / `PROVENANCE` / position-indexed lifecycle) *before the LLM
  is invoked*, emitting a **skeleton with typed holes**;
- the **LLM fills only the holes** (`analysis/hole_semantics.py`, G4: per-arg
  value intents — scalar in/out-of-range, parser buffer, length-pairing,
  output, live-handle) under a locked structure.

This is a clean neuro-symbolic split: **Z3 decides what must be provably correct
(types, lifecycle order, dependency wiring); the LLM decides only what is a
matter of soft semantic judgment (leaf values).**

> **vs prior work:** PromeFuzz lets the LLM decide structure and repairs on
> crash (band-aid); Liberator renders a complete driver with no
> "structurally-correct, holes-for-the-LLM" intermediate, so LLM refinement
> either regenerates from scratch (losing symbolic guarantees) or post-edits
> (losing the holes signal). We removed our own earlier classify-then-repair
> stage (Phase A / F1–F4) entirely — construction is correct by construction.

### ③ Project-adaptive usage knowledge + a closed loop — *learn how THIS library is actually used*

LogicFuzz learns a **typestate automaton from the library's own tests and
examples** (PTA + EDSM, `analysis/project_automaton.py`; mechanics in
`CLAUDE.md`) and uses it as a first-class signal — `acceptance_score`
for L4 ranking, accepting-path samples for construction/prompting, and a
hard-pruning acceptance gate (Phase H). It then **grows the automaton from the
sequences that proved Z3-viable** (Phase G closed loop, incremental EDSM merge),
so each round encodes more of the library's real compositional grammar.

This injects domain knowledge that *bottom-up type-walking cannot infer* (the
"how is this library actually used" that a human driver-author has) and that
*generic LLM priors do not carry* (library-specific idioms), at roughly **70×
lower token cost** than re-deriving it per call.

> **vs prior work:** PromeFuzz's cross-round channel is crash-constraint
> learning (avoid what crashes); ours is *viability learning* (reinforce what
> composed correctly) anchored in a learned, library-specific typestate model.

---

## 3. Comparison vs PromeFuzz (neural baseline)

Both systems share the outer shape (preprocess → comprehend → generate → fix →
merge → analyze) and **diverge entirely inside "generate."**

**One-line difference:** *PromeFuzz lets the LLM decide program structure;
LogicFuzz fixes structure symbolically and lets the LLM decide leaf values.*

### Generate stage, side by side

| | PromeFuzz | LogicFuzz |
|---|---|---|
| Unit of generation | function set (~8, weighted score) | one Z3-validated API sequence per skeleton |
| Structure decided by | **LLM** (free-form full driver) | **symbolic** (Z3 + automaton); LLM fills holes |
| API/seq selection | `scheduler.py` score `(3·(1−Cov)+2·Complexity+Relevance)/6`, no solver | construct-from-model + L0–L4 filter floor + reachability rank + planner rerank |
| Ordering | optional consumer order, else LLM | Z3 position-indexed lifecycle (intrinsic) |
| Arg type validity | LLM, then build-error → LLM fix | L0 + Z3 `TYPE_MATCH` *before* LLM |
| Lifecycle validity | LLM + crash learning | L2 + Z3 + valid-by-construction |
| "Meaningful combo?" | scheduler relevance + LLM | comprehender-B verdict + `acceptance_score` |
| Where validity comes from | **post-hoc** (sanitizer loop, ≤5) | **pre-hoc for structure**, post-hoc for the filled body (LangGraph fixer, ≤3) |
| Cross-round learning | crash → LLM constraint → enrich comprehension | automaton growth (viability); Phase C snapshots |
| Bad-sequence handling | LLM fix on crash | valid-by-construction (no repair stage) |
| Knowledge artifacts | purpose, per-API usage, relevance, RAG store | + typestate automaton, distilled idioms, sequence verdicts, semantic model |

### Source map

| Concern | PromeFuzz | LogicFuzz |
|---|---|---|
| Generation entry | `generator.py:Generator.generate` | `prototyper.py` + `data_context.py` skeleton synthesis |
| Selection | `scheduler.py:Scheduler` | `coverage_ranker.py` + `path_planner.py` |
| Constraint validity | (none) | `constraint_based/z3_solver.py`, `z3_guided_synthesis.py` |
| Skeleton/holes | (none) | `synthesis/skeleton_generator.py` |
| Semantic model | (none) | `analysis/api_semantic_model.py` (G1) |
| Construction | (none) | `analysis/sequence_constructor.py` (G2/G5) |
| Automaton | (none) | `analysis/project_automaton.py` |
| Crash learning | `generator/learner.py` | `agents/crash_*` (per-trial) |
| Harness merge | `generator/synthesizer.py` | `tools/merge_drivers/` |

### What each does *not* do (today)

- **PromeFuzz:** no SMT/Z3, no typestate automaton, no sequence pre-validation,
  no skeleton/holes, no symbolic dependency resolution.
- **LogicFuzz:** no crash-constraint memory banning APIs across rounds (crash
  handling is per-trial); no RAG vector store (uses doxygen/README priors); no
  fully-wired CEGAR loop (Phase C data only); happy-path driver shape only
  (variety deferred — `docs/generation.md` F5).

### Harness merge — four optimisations beyond PromeFuzz

After per-driver generation, `tools/merge_drivers/` fuses N drivers into one
multi-task OSS-Fuzz binary (the O1 preflight → O2 select → O3 merge → O4 corpus
chain; wired via `run_logicfuzz.py --merge-drivers`). **Why merge at all:**
per-driver runs fragment the exec budget and share nothing across drivers;
folding them into one binary that dispatches on a discriminator word lets the
fuzzer's mutator implicitly schedule across sub-harnesses — an interesting input
for harness A transfers to B with a single-byte mutation. We adopt PromeFuzz's
multi-TU + entry-dispatcher structure, then add four optimisations:

| # | LogicFuzz | PromeFuzz baseline | Why |
|---|---|---|---|
| 1 | Multi-TU, only the public symbol renamed (`…_<id>`) | single-file flatten | flattening link-fails on duplicate `static` symbols / macro clashes |
| 2 | Selector at input **tail** | selector at offset 0 | mutators are prefix-biased; a head selector churns sub-harness routing on every front-byte flip — tail keeps the body locally stable for deep exploration |
| 3 | **Coverage-aware** O2 pre-prune (max-coverage greedy on reached-functions) | include all drivers | drops drivers whose coverage is subsumed |
| 4 | **CDF** weighted dispatch (bucket width ∝ marginal coverage) | uniform `selector % N` | high-overlap drivers don't waste equal budget |

(CDF-vs-uniform on real 24h campaigns is empirically untested; both modes are
exposed — `--mode cdf` / `uniform` — so the complexity can be A/B'd before being
kept. Implementation lives in `tools/merge_drivers/{preflight,select,merge,corpus}.py`.)

---

## 4. Comparison vs Liberator (symbolic baseline)

LogicFuzz's backend is adapted from upstream Liberator. Innovation ② above is
built *on top of* Liberator's constraint-based synthesis; the conceptual
additions, then the robustness fixes that made the upstream code usable in
production, are below. (The adapter does not track adapter-side bugs here — only
upstream divergences, so future upstream ports don't reintroduce them.)

### Conceptual additions on top of the symbolic base

| Capability | Upstream Liberator | LogicFuzz adapter |
|---|---|---|
| Feasibility check | Python-symbolic only (`RunningContext.try_to_get_var` vs hand-coded conditions) | **+ SMT layer**: `IncrementalZ3Solver` (push/pop), `Z3SequenceValidator` (position-indexed lifecycle), unsat-core diagnosis |
| Usage/typestate gate | none | **project automaton acceptance gate** (Phase H hard-prune below threshold) |
| Skeleton-with-holes | none — only a fully-rendered `Driver` | **net-new**: Z3-validated skeleton, producer→consumer wiring rendered as `ret_<api>`, only callbacks/buffer-sizes/loops left as `__HOLE_*__` for the LLM |
| Unsat source API | one source; unsat → fatal IPython trap | `_try_all_source_apis` ranks all sources (Z3-guided) + `_try_find_init_chain` prepends producers (bounded, Z3-checkpointed) |
| Callbacks | single generic stub (`get_function_pointer`) | `_get_enhanced_function_pointer` → `DriverEnhancer` classifies (comparator/handler/reader) → typed stub via `CallbackStubLibrary` |
| Var-len buffers | static `len_depends_on` only; decoupled when analysis misses it | falls back to `DriverEnhancer.get_buffer_size_constraint` (`VarLenAnalyzer` name/type heuristics) |
| Dependency graph | inverts the dep-graph, **drops the original direction** (no "who produces type T?") | keeps both directions + `_build_type_producer_map` (return-type → APIs), loose pointer-suffix matching |
| Handle identity | collapsed to `void*`/`i8*` by IR (see Innovation ①) | recovered from headers/exported-functions (`handle_typedef_recovery.py`) |
| Handle production channels | return-value + out-pointer (`T**`) creators only; a caller-allocated struct initialized in place (`z_stream` ← `deflateInit_(z_stream*)`, single pointer) has no producer → the stateful family is unconstructable | **+ SVF-write-gated caller-alloc INIT channel** (`usedef.py:annotate_svf_writes` / `extract_produced_handles`): an init-named single-pointer struct is recovered as a creator when SVF value-flow shows it *writing* the param (not read-only), with naming anti-stems + demotion when a real return/out-ptr creator already exists |

### Robustness hardening (upstream latent bugs the adapter fixed)

Upstream had **fatal `IPython embed; exit(1)` traps in the production hot path**
(four in `CBFactory`, one in `Buffer.get_allocated_size`) that abort an entire
campaign on a single problematic API → replaced with `warning + raise` /
backtracking / partial-driver return. The **backend renderer**
(`LFBackendDriver`) and the **Statement IR** (`framework/driver/ir/`) each
shipped ~6–7 latent crashes (alloctype fall-through, broken `__hash__`,
off-by-one bounds, non-deterministic include order) — all masked in production
by a call-site bug that left the renderer dead, and all fixed in the 2026-05
backend/IR refactors.

> Full per-fix detail + rollback recipes live in git history
> (`git log --grep="backend"` / `--grep="IR refactor"` in `liberator_adapter/`).
> One open caveat: a `DataLayout` `try/except → 0/False/PRIMITIVE` fallback in
> `Factory.py` violates the "no fallbacks" principle and is a tightening TODO.

---

## 5. Attribute matrix (all three)

| Attribute | PromeFuzz | Liberator | LogicFuzz |
|---|---|---|---|
| Driver creation | LLM free-form | symbolic full render | Z3 skeleton + LLM hole-fill |
| Structure decided by | LLM | symbolic | symbolic (Z3 + automaton) |
| Dependency substrate | none (LLM) | type-only, handles collapsed | reconciled IR⊕doc⊕usage, handles recovered (void\*-identity + caller-alloc init) |
| Feasibility check | none (relevance) | Python-symbolic | SMT (Z3) + typestate |
| Usage knowledge | RAG + LLM relevance | none | learned project automaton |
| Coverage targeting | weighted score | none | gap-directed (baseline-uncovered) |
| Pre-LLM validity | none | full symbolic render | type+lifecycle+state+automaton |
| Post-LLM validity | sanitizer loop | n/a (no LLM) | LangGraph build/fix |
| Cross-round learning | crash → constraint | none | automaton viability growth |
| Bad-seq handling | LLM fix on crash | fatal trap (upstream) | valid-by-construction |

---

*Descriptive baselines current as of 2026-06. Pipeline and open gaps:
`docs/generation.md`.*
