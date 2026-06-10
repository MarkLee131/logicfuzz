# LogicFuzz — Contributions & Related-Work Comparison

What problems in fuzz-driver generation LogicFuzz solves, the **three
innovations** that distinguish it from prior work, **why a constraint-based
synthesis core is the objectively-right paradigm for this problem** (the
method-fit argument closing §2), and an objective, component-level comparison
against the two systems it is closest to:

- **PromeFuzz** (`reference/promefuzz`) — the LLM-driven driver generator our
  knowledge layer is derived from. The representative *neural* baseline.
- **Liberator** (`reference/liberator`, HexHive) — the constraint-based driver
  synthesizer our backend is adapted from. The representative *symbolic*
  baseline.

This doc is the SSOT for the "what's new vs prior work" pitch, the descriptive
baselines behind it, and the **per-LLM-call-site rationale** (§6 — where we use
the LLM, the symbolic alternative considered, and why the LLM won). For the
generation pipeline see `docs/generation.md`; for the comprehender + automaton
mechanics see `docs/knowledge_layer.md`.

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
`ConditionManager`), and it is recovered to be *correct* along **two orthogonal
recovery axes** that restore handle relations the raw IR view drops — handle
*identity* and handle *production* (the latter via two channels):

1. **Handle *identity*** — a typedef-handle recovery pass
   (`analysis/handle_typedef_recovery.py`) restores the opaque-handle identity
   the compiler IR discards (re-typing collapsed `void*`/`i8*` slots back to
   `cmsHPROFILE` / `cmsHTRANSFORM` from the public headers), so the dependency
   graph is *connected where Liberator's is empty* and *specific where a naive
   void*-graph would over-connect* (`cmsHPROFILE` ≠ `cmsHTRANSFORM`).
2. **Handle *production*** — a required handle whose creator the raw IR drops is
   restored as a *producer*, via **two deterministic channels** that both feed
   the (already recursive) prefix resolver so the recovered creator chains
   transitively to the byte leaf:
   - **(a) SVF-write-gated caller-alloc INIT** (`analysis/usedef.py`): a
     caller-allocated, in-place-initialized struct (`z_stream` ←
     `deflateInit_(z_stream*)`) is restored as a producer — an init-named
     single-pointer struct counts as creating that struct unless SVF's value-flow
     positively observed the parameter read-only, which correctly rejects
     same-arity *consumers* like `pthread_create(attr*)` (reads the attr) while
     accepting true initializers. Without it the deflate/inflate family has no
     creator and never forms a chain; with it `deflateInit_ → deflate →
     deflateEnd` constructs.
   - **(b) Naming-based opaque-return producer recovery**
     (`analysis/sequence_constructor.py`, gated `LOGICFUZZ_FACTORY_CHAIN`): when an
     opaque handle is *required* by an arg but its producer's **return type was
     desugared to `void*`** by the IR (`typedef void* cmsHTRANSFORM` — the param
     keeps the typedef so `requires` is right, but the return is collapsed, so
     `extract_produced_handles` misses it → the producer index has no entry → the
     prefix resolves empty → a NULL hole), the required *non-pointer* opaque type
     is mapped to its creator by handle naming convention (`cmsHTRANSFORM` → strip
     lib prefix `cms` + handle marker `h` → `transform` → match
     `cmsCreate*Transform*`). Three correctness levers keep it sound: the
     **non-pointer test** (a `*`-typed param is a caller-alloc leaf, not a factory
     target; a `void*` typedef handle has no `*`), a **camelCase word-boundary
     match** (rejects `handle ⊄ ErrorHandler`), and **producer preference** for a
     factory that itself requires another recoverable opaque handle (the true-deep
     one that chains to the byte opener). Without it 29/52 lcms creators have an
     empty `produces` set and every `cmsDoTransform`-class API resolves to a NULL
     hole.

All of these passes are deterministic — zero LLM, zero token cost.

> **Empirical anchor (zlib, validated 2026-06):** with the production-recovery
> channel the deflate/inflate family goes from **0 → 34 of 36 constructable**,
> and a single generated driver covers **`deflate.c` (570 lines) + `inflate.c`
> (551) + `trees.c` (387)** — *all 0 before the fix* — for 1,874/3,397 lines
> (55%) in that driver's own coverage build. Without the recovery no chain forms
> for `z_stream`, so none of that code is reachable by any driver. (Measured via
> the per-driver `run_extended_fuzzing` build; the project's *eval* coverage
> build is degenerate for zlib — it re-measures the baseline `checksum_fuzzer`,
> so cov-diff over it understates every zlib driver.)

> **Empirical anchor (lcms, channel 2b / factory chain, 2026-06):** the
> opaque-handle dependency comes back — recovered handle types **0 → 2**, deep
> opaque args satisfied **0 → 77 of 128**, average resolved prefix length
> **0.15 → 0.89**, and `cmsDoTransform` — previously an all-NULL-arg dead end —
> constructs the full chain `cmsOpenProfileFromMem → cmsCreateProofingTransform →
> cmsDoTransform → cmsDeleteTransform`. Monotone: eight handle-struct libraries
> (c-ares / zlib / libpng / sqlite3 / nghttp2 / cjson / liblouis / libucl)
> recover nothing and are byte-identical (no misbinding, no regression). **This
> is the first dent in the binding-layer ceiling (#14) — the previously-#1 open
> bottleneck.** *Evidence level (2026-06-08):* **construction proven** — offline
> probe (since removed) *and* a live run: the emitted skeleton
> set contains a wired `cmsDoTransform` chain
> (`cmsCreate_sRGBProfile → cmsCreateTransform → … → cmsDoTransform →
> cmsDeleteTransform`, `n_factory_recovered=2`), and the driver **compiles** the
> transform TUs in. **Deep coverage is NOT yet won, and the blocker is below the
> binding layer:** a degraded-mode 30 s probe covered **0/799 lines of
> `cmsxform.c`** despite compiling it in — because the opaque chain needs a
> *valid ICC profile* (`cmsOpenProfileFromMem → cmsCreateTransform`) that random
> fuzzer bytes essentially never form, so `cmsCreateTransform` returns NULL, the
> NULL-guard fires, and `cmsDoTransform` never executes. So factory chain lifts
> the **construction** ceiling but exposes the **input/seed layer** (valid
> structured input to traverse a multi-hop opaque chain) as the next bottleneck —
> not construction, not Z3. The enabling fixes have since landed — the
> build-cache×llvm14 conflict is resolved (A1 additive canonical base → cached
> eval is Z3-on) and `LOGICFUZZ_SEED_CORPUS` routes real format-matching seeds
> (`*.icc`) into the opaque-chain driver's corpus — so the **end-to-end coverage
> measurement** (does the seeded `cmsDoTransform` driver now cover `cmsxform.c`?)
> is the one remaining step, not a missing capability (see `docs/generation.md` §4/§6).

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

#### ②′ The neuro-symbolic boundary is a *typed context schema*, not a prose dump

Innovation ② says the LLM "fills only the holes." The **interface across that
boundary** is itself a contribution. Rather than dump raw artifacts at the LLM
(the prevailing practice — whole driver files, full signature lists, prose
usage), we define a **typed, symbolically-grounded context schema**: each LLM
decision is decomposed into a fixed set of **slots ("key aspects")**; each slot
answers *one* semantic question a human driver-author would ask, and is
**populated by the most authoritative source available** — static analysis where
the answer is provable, the LLM only for the residual soft judgment. The LLM
receives a minimal, structured context, never the underlying analysis.

The schema is instantiated at the **two** generation-stage LLM decision points.

**A. Hole-filling context** — per Z3-validated skeleton → Prototyper (`analysis/hole_semantics.py`):

| Slot | Aspect it answers | Source | sym / LLM |
|---|---|---|---|
| `library_constants` | what are the legal enum/flag/format values? | header enum + grouped-`#define` scan (`named_constants.py`) | symbolic |
| per-API `role` | creator / consumer / mutator / destroyer? | `APISemanticModel` reconcile (IR ⊕ doc ⊕ usage) | symbolic |
| per-API `ret_contract` | does the return need a NULL/error guard? | conditions.json return-provenance + doxygen `@return` (`error_contracts.py`) | symbolic |
| per-API `handle_provenance` | which producer makes a required handle — or none, so construct/NULL? | use-def `produces`/`requires` index | symbolic |
| per-arg `role` (`ArgRole`) | input-buffer / length / output / handle / config? | reconcile + **SVF read/write veto** | symbolic |
| per-arg `pairs_with` | which length pairs with which buffer? | reconcile LENGTH pairing | symbolic |
| per-arg `populated_from` | which args carry the data that fills this one? | SVF `set_by` (conditions.json) | symbolic |
| per-arg `intent` | the value constraint (in/out-of-range, format-shape, enum set …) | derived from role + type + vocabulary | symbolic → LLM |

**B. Sequence-legality context** — per candidate sequence → Comprehender-B (`knowledge/comprehender.py`):

| Slot | Aspect | Source | sym / LLM |
|---|---|---|---|
| `static_facts` | project role mix, verified init/destroy pairs | condition_info + lifecycle | symbolic |
| per-API USE/DEF/KILL | what handle does each call consume / produce / destroy? | use-def (`APIEffect`) | symbolic |
| typestate verdict | does *this exact* sequence have a USE_BEFORE_INIT / UAF / unclosed …? | `Typestate.check` → (kind, handle, position) | symbolic |
| the ruling | is a flagged violation a real bug, or a legitimate direct-entry? | — | **LLM adjudicates** |

**Schema, DSL, or "key aspects"?** Precisely a **typed schema** (a structured
intermediate representation) whose fields *are* the key aspects of driver
correctness. It is **not a DSL** in the formal sense — no grammar, no
composition operators, no parser/evaluator; the rendered hints are
natural-language constraints *derived from* the schema. **CALLSPEC** (one typed
per-call row consolidating these slots — now the default Prototyper context, see
`docs/generation.md` §2) is the move toward a single compact *notation*, but it
stays a schema-rendering, not a language.

**Why it's a contribution, not prompt-engineering.** The schema operationalizes
the neuro-symbolic split *at the prompt boundary*: the same analyses that gate
and rank candidates (②) are reused to **specify the LLM's context slot-by-slot**,
so *"feed the LLM the right information, not the most"* becomes a **typed
contract** rather than a heuristic. The selective-context result TLR (FSE'26)
validates by ablation — typestate-guided minimal context beats dumping
everything, at a fraction of the tokens — is, in our setting, the **degenerate
one-slot case** (typestate verdict only); we generalize it to a multi-aspect,
multi-source, two-decision-point schema in which the symbolic layer authors the
context and the LLM is invoked only on the slots that remain genuinely soft.

### ③ Project-adaptive usage knowledge + a closed loop — *learn how THIS library is actually used*

LogicFuzz learns a **typestate automaton from the library's own tests and
examples** (PTA + EDSM, `analysis/project_automaton.py`; mechanics in
`docs/knowledge_layer.md`) and uses it as a first-class signal — `acceptance_score`
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

### Why constraint-based synthesis is the objectively-right core — a method-fit argument

All three innovations sit on one engine: the skeleton is produced by
**constraint-based (SMT-backed) component synthesis** — a goal-directed
backtracking search over a typed API-component library, with Z3 guiding each
decision and unsat-core-driven backtracking, init-chain backward-chaining to
recover producers (`constraint_based/CBFactory.py`, `z3_guided_synthesis.py`;
adapted from Liberator). This is **classic symbolic program synthesis — no LLM in
the skeleton at all**; the neural layer enters only afterward (hole-filling, ②).
That paradigm choice is not incidental: it is the one that objectively fits this
problem's **four defining traits**, where every classical alternative mismatches
at least one.

| Scenario trait | What it demands of the synthesizer |
|---|---|
| Spec = crisp **relational structure** (type ⊕ provenance ⊕ lifecycle order ⊕ var-availability), *not* behavior | express *global* relational constraints natively |
| **No I/O examples** of "the driver" | rules out example-driven induction as the engine |
| Behavioral oracle (build+fuzz) is **expensive + noisy** | per-candidate verification must be *avoided*, not iterated — validity must be a-priori & cheap |
| Large library, **valid solutions sparse**; we want **many diverse valid** drivers | strong pruning + cheap enumeration of *distinct* valid solutions, not one optimum |

**Objective paradigm fit** for this skeleton-synthesis subproblem:

| Paradigm | Fatal mismatch *here* | Where it would win instead |
|---|---|---|
| Enumerative (SyGuS, bottom-up + OE) | valid space sparse in a huge library → blowup; *local* enumeration can't hold *global* lifecycle/provenance invariants (generate-then-filter, wasteful); OE pruning needs a cheap executable oracle we lack | small grammar + cheap test oracle |
| Stochastic / search (genetic, STOKE) | fitness = coverage = build+run → prohibitive oracle cost; no validity-by-construction → most evaluations wasted on invalid drivers | cheap / fast / differentiable fitness |
| PBE / inductive (VSA, FlashFill) | no I/O examples of the target driver exist | abundant I/O examples |
| Deductive / type-directed (Synquid) | needs a *complete* formal spec (refinement types) we cannot write for a C library — only *partial* contracts are recoverable | full formal specs available |
| Neural / LLM (PromeFuzz) | no guarantee on *hard* structure → plausible-but-broken drivers, repair cost, hallucination | soft/semantic leaf decisions, repair budget |
| **Constraint-based (ours)** | **only as good as the encoded model; cannot express *semantic-value / input-data* validity** | **crisp relational spec + expensive oracle + sparse-valid large library** ✓ |

**Advantages it buys.** Validity *by construction* (no repair stage; the
expensive oracle is never spent on a structurally-invalid driver); solver pruning
(unsat-core + incremental push/pop) makes the sparse-valid large-library search
tractable; *global* invariants (lifecycle order, provenance) handled natively;
backward-chaining init-chains directly attack the binding bottleneck (to obtain an
opaque handle, recursively synthesize its producer); and cheap **diverse** valid
output (randomized/biased choice among satisfiable candidates) to feed the
breadth-via-merge strategy — all **decoupled from the expensive build+fuzz
oracle**.

**Honest disadvantage — and it is exactly our current ceiling.** A constraint
method is only as good as the constraints it can encode: it expresses crisp
structure but **cannot express semantic-value / data validity** (SMT can say "this
arg is typed `cmsHPROFILE`"; it cannot say "these bytes are a *valid* ICC
profile"). Both top open bottlenecks are this one disadvantage made concrete — the
**binding layer** (an opaque arg with no recoverable producer → UNSAT → no driver,
#14) and the **input/seed layer** (`cmsCreateTransform(random bytes)` → NULL →
`cmsxform.c` 0/799 despite a correctly constructed, compiling chain).

**Objective verdict.** For the *structural* skeleton, constraint-based is the
clear best fit — its strengths map one-to-one onto the four scenario traits, and
each alternative fails at least one. The theoretically-closest competitor is
**deductive / type-directed** synthesis (our init-chain backward-chaining is
already deductive in spirit), but it presumes specifications we cannot obtain for
real C libraries; **constraint-based is precisely its realizable relaxation under
partial contracts.** Crucially, *no single traditional paradigm suffices*: the
very thing constraints cannot express (semantic values, valid structured input) is
what the **neural** layer (LLM hole-filling, ②) and the **seed** layer (real
format-matching corpora) are added for. **The objectively-correct design is
therefore not "pick one synthesis method" but a layered split — constraint-based
for the hard structure it provably owns, neural + seed for the soft/data residual
it provably cannot — which is the root justification for LogicFuzz being
neuro-symbolic rather than either pure-symbolic (Liberator) or pure-neural
(PromeFuzz).**

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
  handling is per-trial; the lean-mode path triages it *deterministically* via
  `crash_frame.py` instead of two LLM calls — see below); no RAG vector store
  (uses doxygen/README priors); no fully-wired CEGAR loop (Phase C data only);
  happy-path driver shape only (variety deferred — `docs/generation.md` F5). The
  opaque / no-in-project-producer **binding-layer tail** is only *partially*
  recovered — the factory chain (①·2b) reaches `cmsCreate*`-named opaque
  producers, but the remaining no-producer APIs still drop to NULL holes
  (`docs/generation.md` #14).

### Harness merge — optimisations beyond PromeFuzz

After per-driver generation, `tools/merge_drivers/` fuses N drivers into one
multi-task OSS-Fuzz binary (the O1 preflight → O2 select → O3 merge → O4 corpus
chain; wired via `run_logicfuzz.py --merge-drivers`). **Why merge at all:**
per-driver runs fragment the exec budget and share nothing across drivers;
folding them into one binary that dispatches on a discriminator word lets the
fuzzer's mutator implicitly schedule across sub-harnesses — an interesting input
for harness A transfers to B with a single-byte mutation. We adopt PromeFuzz's
multi-TU + entry-dispatcher structure, then add these optimisations:

| # | LogicFuzz | PromeFuzz baseline | Why |
|---|---|---|---|
| 1 | Multi-TU, only the public symbol renamed (`…_<id>`) | single-file flatten | flattening link-fails on duplicate `static` symbols / macro clashes |
| 2 | Selector at input **tail** | selector at offset 0 | mutators are prefix-biased; a head selector churns sub-harness routing on every front-byte flip — tail keeps the body locally stable for deep exploration |
| 3 | **Coverage-aware** O2 pre-prune (max-coverage greedy on reached-functions) | include all drivers | drops drivers whose coverage is subsumed |
| 4 | **Compile-validation** gate (`compile_validate.py`) — merge only TUs that compile under the real coverage-build flags | silently stub non-compilers | a non-compiling sub-driver is lost from the portfolio AND breaks coverage replay (see below) |
| 5 | **Edge-weighted CDF** dispatch (bucket width ∝ preflight `edges_15s`, Liberator's seed-producing signal) | uniform `selector % N` | high-interaction sub-drivers earn a larger per-input budget; low-interaction ones don't waste equal budget |

(Implementation lives in `tools/merge_drivers/{preflight,select,merge,corpus,compile_validate}.py`;
dispatch modes `--mode cdf` / `uniform` are both exposed. The full cross-round
"driver history" — Liberator's whole idea — is NOT done; #5 uses only the
single-run preflight signal, which needs cross-round state to extend.)

**Coverage-measurement soundness (the A≡B principle).** The OSS-Fuzz model —
fuzz on the address binary, replay the corpus on a *separate* coverage binary —
is sound and standard (PromeFuzz uses it too); it requires only that the two
builds be the SAME harness (A≡B). Our merged harness used to violate that: a
compile-INVALID driver was KEPT (preflight only vets RUN, and "couldn't vet ⇒
keep"), then silently shadowed by the merge's `||continue` skip + a weak-stub
no-op, so the address build and the coverage build skipped DIFFERENT non-compiling
TU sets → a corpus input hit a real sub-driver in one and a no-op stub in the
other → A≢B → spurious 0 coverage. **Compile-validation restores A≡B** — both
builds compile the identical valid set (lcms: excluded 9/11 invalid drivers →
merged-harness llvm-cov 551/9590 br, no longer 0). We therefore **exceed
PromeFuzz's merge on three axes:** (a) compile-validation = a valid-by-construction
merge (PromeFuzz silently stubs non-compilers, losing them *and* their coverage);
(b) tail selector (PromeFuzz's head-offset selector corrupts every sub-driver's
format-magic seed on a front-byte flip); (c) edge-weighted CDF dispatch (PromeFuzz
uniform).

### Breadth + low-FP: borrow PromeFuzz's reach, keep our precision (2026-06)

The honest gap analysis (`docs/generation.md` §6) found PromeFuzz's
edge is **API breadth × driver density**, not novelty — our correct-by-
construction stance dropped every API the symbolic layer couldn't connect
(≈302/452 gap APIs never entered a candidate). The fix is *graceful degradation*,
not abandoning the substrate: the symbolic layer authors **structure**, the LLM
fills the **gaps it can't prove** — and a separate quality layer keeps the FP
rate low (our actual differentiator: when our drivers crash, is it a real bug or
a driver bug?).

| lever (all gated) | borrowed-from-PromeFuzz / ours | what it does |
|---|---|---|
| **B graceful degradation** | ours (symbolic) | keep orphan-handle `USE_BEFORE_INIT` sequences → island/opaque APIs enter candidates; the unchecked render path leaves the un-bindable arg as a hole |
| **B+D scoped NULL-guards** (`LOGICFUZZ_SCOPED_GUARDS`) | ours (differentiator) | render the creator NULL-guard PER dependency component (`_dependency_components`), so an INDEPENDENT API runs even when the parser returns NULL on random bytes — instead of the legacy whole-driver `if(!parser)return0` that gated *everything* after it. **PromeFuzz has no dependency model / no parser-vs-independent distinction.** Measured (controlled single-file): +523 br (12.6×) when the parser fails; ≈0 when valid seeds let it succeed |
| **Tier-1 fuzzable-holes value-domain** (`LOGICFUZZ_FUZZABLE_HOLES`) | ours (automatic depth) | scalar/float CONFIG holes emit a FUZZ_DERIVE intent invoking the LLM's OWN value-domain judgement (a semantically-valid range — chromaticity≈0..1, gamma≈0.1..5 — then derive from the fuzz input; enum holes index a byte into the legal set). This is PromeFuzz's *automatic* depth mechanism (the LLM's trained knowledge) **made explicit — NOT hand-written per-lib `api_hints`** (PromeFuzz's manual cheat). Confirmed: cmsBuildParametricToneCurve fuzz-derived → cmsgamma.c 84→121 br (+44%) |
| **density** (`_densify`) | PromeFuzz reach | append extenders that USE an already-open handle (`requires ⊆ opened`) → thin `create→use→destroy` chains thicken toward PromeFuzz's 5.6–7.6 calls/driver |
| **hard NULL-guard + opaque factory hint** | ours (low-FP) | `MUST-GUARD` creator returns + "build the opaque handle via its producer"; density *requires* it (ablation: density-only SEGVs) |
| **pre-ship quarantine + keep-best** | ours (low-FP) | drop immediate-crash 0-coverage FP drivers from the merge; never ship a driver worse than the trial's peak |

**Neuro-symbolic split is preserved**: density only appends calls whose handle
dependencies are *already symbolically satisfied*; the guard wording is driven by
IR-derived `ret_contract` + the use-def producer index; the scoped guard is
partitioned by the dependency graph; the LLM still owns only the leaf values.
**Measured (30s A/B, single best driver — not yet the 24h union):** lcms
**66→206 br (+212%)**, FP 1→0; zlib +6%; c-ares neutral. Density and the guard
are *synergistic* (neither alone helps — density-only = 0). The 24h `--merge`
union vs PromeFuzz Table 2 (lcms ~13k, c-ares 6,106) is the pending headline test.

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
| Handle production channels | return-value + out-pointer (`T**`) creators only; a caller-allocated struct initialized in place (`z_stream` ← `deflateInit_(z_stream*)`, single pointer) has no producer, **and an opaque creator whose return type the IR desugared to `void*`** (`cmsCreate*Transform`) is invisible to the producer index → both stateful families are unconstructable | **+ two recovered channels**: (a) **SVF-write-gated caller-alloc INIT** (`usedef.py:annotate_svf_writes` / `extract_produced_handles`) recovers `deflateInit_`-style in-place initializers when SVF shows the param *written* (anti-stems + demotion when a real return/out-ptr creator exists); (b) **naming-based opaque-return producer recovery** (`sequence_constructor.py`, `LOGICFUZZ_FACTORY_CHAIN`) maps a required non-pointer opaque handle to its `cmsCreate*`-style factory by handle naming, feeding the recursive prefix resolver (non-pointer test + camelCase word-boundary + deep-factory preference keep it sound) |

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
| Dependency substrate | none (LLM) | type-only, handles collapsed | reconciled IR⊕doc⊕usage, handles recovered (void\*-identity + caller-alloc init + opaque-return factory chain) |
| Feasibility check | none (relevance) | Python-symbolic | SMT (Z3) + typestate |
| Usage knowledge | RAG + LLM relevance | none | learned project automaton |
| Coverage targeting | weighted score | none | gap-directed (baseline-uncovered) |
| LLM context model | raw artifacts + RAG retrieval | n/a (no LLM) | **typed, symbolically-grounded schema** (slot-per-aspect, source-per-slot; ②′) |
| Pre-LLM validity | none | full symbolic render | type+lifecycle+state+automaton |
| Post-LLM validity | sanitizer loop | n/a (no LLM) | LangGraph build/fix |
| Cross-round learning | crash → constraint | none | automaton viability growth |
| Bad-seq handling | LLM fix on crash | fatal trap (upstream) | valid-by-construction |

---

## 6. Per-LLM-call-site rationale — where we use LLM, what we considered, why

This is the method-fit argument at the call-site granularity: every place
LogicFuzz invokes an LLM, the symbolic alternative considered first, and why the
LLM won — so the design is defensible (every LLM call points to a specific
limitation of the deterministic alternative, not "LLM seemed easier"). Each item
ends with a **falsifiable measurement** — the experiment that would prove the LLM
choice wrong; observe that result, revisit the decision. (Mechanism detail for
each component lives in `docs/generation.md`; this section keeps only the
*why-LLM* argument.)

### A. Prototyper — initial driver synthesis from the skeleton

**File:** `src/agents/prototyper.py` · once per trial, after CBFactory emits a
Z3-validated skeleton with `__HOLE_*__` placeholders.

**LLM job:** fill holes (callback bodies, buffer-size expressions, loop
conditions, error handling) and any "glue" the symbolic skeleton can't
prescribe (e.g. `cJSON_PrintBuffered(json, 1, formatted)` where `1` is a
corner-case prebuffer the rule layer would have written as `1024`).

**Symbolic alternative:** pure-symbolic rendering (upstream Liberator's
`LFBackendDriver`) — generic `return 0;` callback stubs, var-len-derived buffer
sizes, ConditionManager-paired init/destroy, no loops.

**Why LLM:** three deficits observed across the 17-benchmark suite —
1. **Loop conditions are LLM-only.** `while (sf_readf_float(sndfile, buf, 1))`
   terminates on an API return; deciding "use this API's return as the loop
   condition" needs API semantics. Corpus study: 19 LOOP_CONDITION positions
   across 70 fuzzers, 0% rule-fillable.
2. **Non-generic callback bodies.** A `qsort` comparator is generic-stubbable;
   a `libsndfile` VIO `get_filelen` tracking the fuzz buffer position is
   library-specific glue. DriverEnhancer covers ~8 common shapes; novel shapes
   need LLM.
3. **Bug-finding "tricks."** `data[0]`-as-buffer-size (zlib), `prebuffer=1`
   (cjson), magic-byte patterns (c-ares). ~15% of "rule-equivalent" holes had
   expert tricks the rule would miss.

**Cost of reverting:** loop-driven targets (libsndfile, libpcap, chunked
libxml) run zero loops → coverage collapses to first-frame; lose the ~15%
expert-tricks uplift.

**Falsifiable:** A/B compile rate + 24h coverage of the full pipeline vs
symbolic-only rendering (no prototyper). If symbolic reaches ≥95% on every
project, the LLM is overkill.

### B. Fixer — compile-error recovery

**File:** `src/agents/fixer.py` · on compile failure, ≤3 retries/trial.

**LLM job:** map a free-text compiler error to a code change (missing header,
wrong link target, `extern "C"` wrapping, version-renamed API).

**Symbolic alternative:** the rule-based triager
(`src/utils/compilation_error_triage.py`, which runs *before* the Fixer)
buckets errors into link / header / type / language / api_hallucination and
emits a per-bucket fix template.

**Why LLM:** triage handles ~70% cleanly; the rest need cross-error reasoning —
1. **Multi-error interactions.** One missing header → 6 "undeclared identifier"
   errors; the LLM recognises the single root fix instead of 7 separate ones.
2. **Project-specific naming.** mbedtls renamed `mbedtls_ssl_init` →
   `_setup`; the LLM picks the right replacement by reading arg signatures.
3. **Type-ambiguous fixes.** "expected X, got Y" is fixable by cast / decl
   change / different API; the triager defaults to cast, the LLM picks right.

**Cost of reverting:** each multi-error case becomes 6+ fix attempts, blowing
the 3-attempt cap. Pure-triager mode took ~2.5× more compile attempts per
successful driver in early development.

**Falsifiable:** per-trial compile-attempts-to-success, triager-only vs
default. If the gap is < 1.5×, the LLM fixer is over-engineered.

### C. CrashAnalyzer & CrashFeasibilityAnalyzer

**File:** `src/agents/crash_analyzer.py`,
`src/agents/crash_feasibility_analyzer.py` · on a libfuzzer crash, before
reporting upstream. (In lean mode the deterministic `crash_frame.py` triages the
common driver-vs-library frame attribution; the LLM path is the
`unknown`-frame fallback — see §3 "What each does not do".)

**LLM job:** decide *driver bug* (our setup) vs *real library bug*; for real
bugs, classify feasible (reachable from end-user input) vs infeasible (only via
contract-violating values the driver passed).

**Symbolic alternative:** static rule — faulting frame inside
`LLVMFuzzerTestOneInput` → driver bug, else real; fuzz-derived arg → feasible,
synthesised field → infeasible.

**Why LLM:**
1. **Inlining fools the stack-frame heuristic.** Optimised OSS-Fuzz builds
   inline the driver call site into the library; the faulting frame "looks
   like" a library frame even for our bug. The LLM reads both sides (~90%).
2. **Feasibility is a contract question.** "Can this crash happen in
   production?" depends on documented preconditions living in prose docs.
3. **Volume.** A pure-rule classifier flags ~3× more "real bug" false
   positives — each costs maintainer trust.

**Cost of reverting:** ~3× more spurious reports. Early rule-only versions drew
several "you're calling our API wrong" rejections from maintainers.

**Falsifiable:** maintainer accept rate (merged vs rejected) under rule-only vs
LLM-classified. Within 10% → LLM is wasted.

### D. (REMOVED) CoverageAnalyzer & Improver — per-driver optimize

The per-driver coverage-optimize subsystem (`coverage_analyzer.py` +
`improver.py` + the §10B `baseline_diff_analyzer` regression recovery) was
**removed** — it was *per-driver* LLM refinement (N× cost), mismatched with the
breadth-via-merge design, and addressed none of the real bottlenecks (binding /
input-seed / breadth-bound). See `CLAUDE.md` Failed Attempts.

The one load-bearing job it did — *coverage-gap targeting* ("which API branches
stayed uncovered, and why") — was **re-homed to deterministic mechanism, not
deleted**: sequence selection now targets uncovered code via **reachability-first
ranking (G3) + G5 gap targeting** (`coverage_gap.py`), and the residual
soft "why didn't this arg reach this branch?" reasoning (magic bytes, structure
match — e.g. libpng's `89 50 4E 47…` PNG signature, cjson's `{` switch) is what
the Prototyper's hole-fill (§A) and the value-feedback / fuzzable-holes intents
(`docs/generation.md` §6 T12 / fuzzable-holes) now carry. If cross-round coverage
feedback is ever wanted, it belongs in the Phase C CEGAR loop
(`docs/generation.md` §6 F6) — portfolio-level, cross-round, NOT a per-trial node.

### E. Comprehender (knowledge layer A + B)

**File:** `src/knowledge/comprehender.py` · once per project (Step 6b).

**LLM job:** Stage A — per-API usage notes (signature + comments + a few usage
sites → one sentence). Stage B — per-sequence semantic verdict ("meaningful
protocol? object used or wasted? missing init?").

**Symbolic alternative:** PromeFuzz's ConstraintLearner (mines invariants from
the test suite via symbolic execution + invariant inference) — ported as
design-only, not shipped (`docs/knowledge_layer.md`).

**Why LLM:**
1. **The signal is in prose.** Header comments / README / man pages encode
   protocol semantics in English; symbolic execution gives statistical
   patterns, the LLM gives *intent*.
2. **Stage B compares intent to implementation** — a teleological question
   ("what is this sequence trying to do?") pure analysis can't answer.
3. **Cost is bounded** — per-project, not per-trial; cached to
   `results/{project}/comprehension/`.

**Cost of reverting:** Stage A degrades to signature-only (what the prototyper
already sees); Stage B disappears, so sequences rank by L4 coverage with no
semantic filter — empirically ~30% nonsense ("compiles but does nothing")
sequences.

**Falsifiable:** 24h coverage with Stage B disabled. Within 5% → overkill.

### F. ProjectAnalyzer (pre-prototyper)

**File:** `src/agents/project_analyzer.py` · once per benchmark, derives
`project_understanding` before the prototyper.

**LLM job:** read README + a representative source file → a paragraph the
prototyper sees as `<library_purpose>` (e.g. "streaming parser; consumers must
`_init`/`_finalize` around all `_update` calls").

**Symbolic alternative:** hand-curated `purpose` field in the benchmark YAML.

**Why LLM:** hand-curation doesn't scale past the 17-suite — adding a project
would mean writing the paragraph, defeating "drop in any OSS-Fuzz project".

**Cost of reverting:** new-project onboarding goes from one YAML line to a
hand-written paragraph; blocks scaling.

**Falsifiable:** prototyper output quality on a project with a manual
`library_purpose` vs the analyzer's. If manual is consistently better, the
analyzer is too generic.

### G. Where we deliberately did **not** use LLM

Places where LLM was tempting but the deterministic alternative was clearly
enough — all share one property: the deterministic result is *verifiable* (you
can audit the pairing and see why), whereas the LLM-required cases need prose /
open-ended inference / project-specific docs.

- **Skeleton wiring (producer→consumer)** — Liberator's
  `RunningContext.try_to_get_var` + Z3 `add_resource_*`, 100% deterministic
  from the dependency graph. LLM would be non-reproducible across trials.
- **CLEANUP pre-fill (paired destroy)** — `_infer_paired_destroy`; corpus study
  showed 100% rule-equivalence with experts.
- **Type compatibility (L0)** — type-string matching + `Factory.normalize_type`.
- **Lifecycle pairs (L2)** — name/type/semantic patterns find ~95%; the exotic
  5% wouldn't reliably improve under LLM.
- **State-machine constraints (L3)** — `ConditionManager` pre/postconditions.
- **EDSM / PTA learning** — pure algorithm over observed traces; LLM oracle
  wired as an optional extension, default off.

### H. Decision rule going forward

Add an LLM call **only** when both hold:

1. **A symbolic alternative exists and was tried** — in the codebase already,
   or the tradeoff was empirically measured.
2. **The signal needed is in prose / non-mechanical inference** — magic bytes
   from docs, semantic intent, multi-error reasoning. If the answer is in code
   that constant-folds / pattern-matches / typestate-checks, the symbolic layer
   owns it.

When evaluating a new "let's use LLM here" proposal, write the A–F template
above BEFORE implementing. If the "cost of reverting" line is empty or
hand-wavy, the LLM call probably isn't justified.

---

*Descriptive baselines current as of 2026-06. Pipeline and open gaps:
`docs/generation.md`.*
