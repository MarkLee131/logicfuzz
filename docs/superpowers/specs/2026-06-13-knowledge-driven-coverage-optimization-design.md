# Knowledge-Driven Coverage Optimization — Design Spec

- **Date:** 2026-06-13
- **Status:** Draft (awaiting user review → writing-plans)
- **Owner:** MarkLee131
- **Headline framing (decided):** *Knowledge-driven.* The reconciled
  `APISemanticModel` (IR ⊕ doc ⊕ usage/examples ⊕ header-naming ⊕ mined-constants)
  is the **authority that DICTATES** (1) *which objects to construct*, (2) *with
  what values*, (3) *in what order*. Coverage levers A/B/D (parser-entry bias,
  breadth cap, value/handle correctness) are framed as **downstream of better
  knowledge use**, not independent hacks. `reconcile-then-construct` stays the
  spine — example/order/value signal is *evidence feeding the model*, never an
  LLM decision.

---

## 1. Problem & evidence-grounded diagnosis

Our merged-harness coverage trails PromeFuzz (lcms: PF 4,560 br / 358 APIs / 141
drivers vs ours ~33.8% / 49 merged APIs / 20 drivers). A 6-investigator +
adversarial-verification study (2026-06-13) established the causal chain. The
user's original hypothesis — *"we under-exploit API docs"* — is **partially
right but mis-located**:

- For the flagship lib (lcms) there is almost **no machine-readable API doc**:
  `lcms2.h` has 0 doxygen blocks across 305 decls; the API reference ships as
  **PDF** (extractor can't read it); `docs_priors.json api_docstrings = {}`
  (0/297 APIs). So *direct prose-doc use cannot be the dominant cause there.*
- The verified dominant causes (ranked):
  1. **Parser-entry bias (self-inflicted).** 10–13/20 lcms drivers root on
     `cmsOpenProfileFromMem(data,size)` → NULL on random bytes → guard → return.
     All accepted drivers plateau at an **identical ~79 edges / 1.8% lines**. Our
     prompt literally says *"PRIORITIZE Parser APIs."* PF inverts this: ≥83/141
     object-construction, only ~6/141 parser-gated.
  2. **Tooling gates zeroing whole projects.** c-ares generated **19 strong
     drivers (1,028–1,280 edges)** → all dropped by `ares_build.h not found` at the
     compile-validation gate. zlib: 0 drivers (glibc 2.35↔2.38 ABI mismatch +
     NULL `z_stream*`). libpng: 0 merged.
  3. **Binding/render defects in our own innovation channels.** caller-alloc INIT
     producer renders `z_stream*` as **NULL** (deflate/inflate dead); handles typed
     by underlying `void*` so `cmsContext` binds to a `cmsHPROFILE` arg.
  4. **Breadth-selection cap** (49 vs 358 APIs), partly downstream of 1/2/3.
  5. **Documented value-domain underuse** (the *one* concretely-right part of the
     hypothesis): scalar/enum holes are LLM-guessed or filled with broken
     `(Enum)(data%N)` arithmetic on non-contiguous 4-char-code signatures.
- **Token note (measured 2026-06-13, corrects an earlier claim):** the current
  prototyper prompt is **~7K tokens/call** (local tiktoken 6,958 ≈ API billed
  6,981; `gpt-4o-2024-08-06`, no hidden preamble). The 36.3K in the stale
  `token_summary.json` reflects an older/heavier run state the current
  skeleton-path + blanking wiring no longer produces. **Per-call prompt bloat is
  NOT a real problem** — token efficiency is already a *selling point* (symbolic
  does structure → LLM fills ~52–113 leaf tokens into a constrained prompt; PF
  spends 80% of tokens on O(N²) LLM relevance). See
  `memory/project_prototyper_prompt_token_reality.md`.

**Reframed thesis:** convert the structured project knowledge we *already have or
can deterministically derive* (creator kind, mined legal constants, example call
orders, documented value domains where present) into **constraints that dictate
construction, values, and order** — raising coverage AND keeping driver quality
stable without leaning on the LLM. Prose API docs are *one* knowledge source on a
priority ladder (§6), not the headline mechanism.

## 2. Goals / Non-goals

**Goals**
- G1. Make the knowledge model *dictate object-construction-first* chain roots
  (L1) → break the 79-edge parser-NULL ceiling on lcms-class libs.
- G2. Make the knowledge model *dictate leaf values* from mined/example/documented
  domains (L6) → constructed objects validate; kill broken enum arithmetic.
- G3. Make the knowledge model *dictate call order* from consumer/example
  evidence + an ALL-COVER breadth floor (L7).
- G4. Recover the drivers tooling currently zeroes (L2/L3/L5) so cross-project
  numbers are honest and A/Bs are attributable.
- G5. Token: prove + slightly strengthen the existing efficiency advantage (L4,
  reframed to small polish).

**Non-goals (this round)**
- PDF/HTML/man doc extraction (deferred behind a gated A/B — §6).
- Phase-C CEGAR cross-round coverage loop (F6 — remains proposed-not-built).
- Resurrecting any per-driver optimize subsystem (removed; do not revive).
- Re-architecting the prototyper prompt to "cut 36K" (measurement says no 36K).

## 3. Design principles (carried from CLAUDE.md)

- **Preserve the 3 innovations**, and have each lever *strengthen* one:
  handle/typedef recovery (L3 fixes a defect in it), coverage-complete
  portfolio-merge (L1/L7 feed it), reconcile-then-construct (L1/L6/L7 feed the
  model; construction stays valid-by-construction).
- **Deterministic over LLM** wherever a traditional method suffices (creator
  classification, legal-constant indexing, call-order extraction, symbol/arity
  checks). LLM kept only for genuinely-uncertain soft judgement.
- **No silent caps**: when breadth/selection bounds coverage, `log()` what was
  dropped.
- **A≡B coverage measurement** unchanged (compile-validation gate stays).

## 4. Architecture — the model as dictating authority

```
  Static (IR/SVF) ─┐
  Headers/naming ──┤
  doc (.md/doxygen)┼─► APISemanticModel.reconcile() ──► per-API:
  examples/tests ──┤        (G1, Step 5g)                role + root_kind +
  mined constants ─┘                                     arg value-domains +
                                                         error/ret contracts
                                                              │
        ┌───────────────────────────┬───────────────────────┴────────────┐
        ▼ (what to construct)        ▼ (what values)          ▼ (what order)
   L1 root_kind ranking        L6 value-domain holes     L7 OrderSets + ALL-COVER
   in sequence_constructor     in hole_semantics          in sequence_constructor
   + coverage_complete_select  ._arg_intent               + coverage_ranker floor
        └───────────────────────────┴────────────────────────┴────────────┘
                                     ▼
                       Z3 confirm → skeletons → holes (LLM leaf-fill)
                                     ▼
              Phase-0 enablers (L2/L3/L5) ensure these RUN & SHIP
```

New first-class concept added to the model: **`root_kind`** per API, derived
deterministically from signature + existing `ArgRole`:
- `data_buildable` — constructs the central handle from scalars/enums/sub-handles
  (e.g. `cmsCreate_sRGBProfile`, `cmsBuildGamma`, `cmsStageAlloc*`). No valid
  formatted input needed.
- `caller_alloc_init` — in-place initializer of a caller-allocated struct
  (`deflateInit_(z_stream*)`); already recovered by the SVF-INIT channel.
- `parser_entry` — takes a raw byte buffer + length as primary input and returns
  the central handle (`cmsOpenProfileFromMem(data,size)`); needs valid input.

## 5. Phases & levers

### Phase 0 — Tooling enablers (deterministic; do FIRST; re-measure after)

Rationale: c-ares/zlib/libpng are zeroed for non-quality reasons, so no Phase-1
A/B is attributable until these land.

- **L2 — compile-validation pipeline.**
  - *What:* run the compile-validation gate *after* the project's `configure`/cmake
    step (or stage configure-generated headers like `ares_build.h`); pin the
    preflight host to the container glibc/ABI so built binaries can run.
  - *Where:* `tools/merge_drivers/compile_validate.py:validate_compilable`;
    `run_single_fuzz.py:_compile_validate_candidates` + preflight build env
    (`builder_runner`).
  - *Measure:* c-ares merged drivers 0 → ~19; zlib binaries run (no `GLIBC_2.38`
    loader error). Keep fail-open.
- **L3 — INIT-render + handle-typing defect.**
  - *What:* (a) caller-alloc INIT producer → stack-allocate the recovered struct
    `{0}`-init and pass its **address** (not NULL); fill known scalar args from
    header facts (`deflateInit_(&s, level, ZLIB_VERSION, sizeof(z_stream))`).
    (b) Type holes by typedef **name**, not underlying `void*`, so `cmsContext`
    cannot bind to a `cmsHPROFILE` arg.
  - *Where:* `skeleton_generator.py` render path (the f866db1c value-struct→stack
    fix that did **not** fire for the INIT channel); `usedef.py`
    `extract_produced_handles`/`annotate_svf_writes`; handle typing in
    `api_semantic_model.py` / `hole_semantics.py`.
  - *Measure:* zlib deflate/inflate drivers live (≥1 real `z_stream`, `ZLIB_VERSION`
    set); lcms wrong-handle FP-crashes drop.
- **L5 — pre-build symbol/arity check + triage.**
  - *What:* before any build+fixer round, reject/auto-drop hole-fill output that
    calls undeclared/hallucinated APIs or wrong arity, using the known API set;
    map link/header/implicit-decl errors to deterministic fix strategies.
  - *Where:* `src/utils/unified_validator.py` (+ `apis_clang.json` arity);
    `src/utils/compilation_error_triage.py`.
  - *Measure:* fewer fixer calls; fewer merge-time quality exclusions (lcms 3/23).

### Phase 1 — Knowledge levers (the headline contribution)

- **L1 — Knowledge dictates *which objects* (root_kind ranking). [NEW contribution
  — PromeFuzz has no construct-vs-parser root notion; its root is pure
  coverage-greedy, verified `scheduler.py:474-525`.]**
  - *What:* prefer `data_buildable` (then `caller_alloc_init`) over `parser_entry`
    as chain roots; **keep ≥1 parser-rooted driver per genuinely parser-only
    subsystem**; raise portfolio budget ~30%; gap-direct to 0-driver subsystems
    (Pipeline/MLU/NamedColor/ToneCurve).
  - *Where (this is a REBALANCE of an existing explicit parser-first bias, not just
    a new preference):* counterbalance `data_context.py:1308-1318` (the
    `_buffer_ranked` strand that ranks buffer/parser-entry sequences FIRST —
    "parsers are coverage goldmines") and `sequence_constructor._build_prefix`
    (~`:591-617`, currently prefers an INPUT_BUFFER-ingesting creator); root
    selection in `sequence_constructor.py:construct_sequences` (target/root loop
    ~`:804-829`); selection in `liberator_adapter/constraints/coverage_ranker.py:
    _coverage_complete_select`; `subsystem_clusters.py`;
    `coverage_gap.py:compute_gap_apis`.
  - *A/B gate:* `LOGICFUZZ_OBJCONSTRUCT_FIRST` (default-off until A/B), control =
    current parser-first ranking.
  - *Measure:* lcms parser-gated driver ratio ↓; per-driver edges break past 79;
    distinct deep-subsystem APIs ↑.
- **L6 — Knowledge dictates *what values* (value-domain holes).**
  - *What:* (a) extend the legal-constant mine to **4-char-code signature enums**
    and **forbid `(Enum)(data%N)` arithmetic** — always index a fuzz byte into the
    mined legal *set*; (b) **pin `@param.text` as a per-arg value-domain hint**
    instead of discarding it (see §6.3 adopt-#1): keep the prose, regex-mine
    numeric/enum ranges from it ("between 0 and 1", "must be ≥ `PCAP_ERRBUF_SIZE`")
    and feed it to `_arg_intent`; add canonical example constants (gamma 2.2,
    5000 K, `TYPE_RGB_8`, `INTENT_PERCEPTUAL`); (c) header-fact fills
    (`ZLIB_VERSION`, `sizeof`). LLM kept only for genuinely uncertain domains, and
    only to *derive within* a documented range (preserve FUZZABLE_HOLES diversity —
    never a single fixed constant).
  - *Where:* `named_constants.py:extract_constant_vocabulary`;
    `hole_semantics.py:_arg_intent` (CONFIG/enum paths ~181-191),
    `enum_members_for_type` (~155); skeleton renderer (forbid enum arithmetic);
    `api_semantic_model.py:collect_doc_evidence` (**stop discarding `@param.text`
    at `:468-475`** — mirror the working `@return → error_contracts` template at
    `error_contracts.py:284-299`); **verify `extract_error_contracts(doc_signals=…)`
    actually receives the freshly-mined markdown signals at `data_context.py:2060`**
    (today it can fall back to cached `docs_priors.json`); widen the doc sweep in
    `project_docs.py` to `man/*.3` / top-level `USAGE` / `.adoc` (§6.3 adopt-#2).
  - *A/B gate:* graduate within existing `LOGICFUZZ_FUZZABLE_HOLES` machinery;
    new sub-gate `LOGICFUZZ_VALUE_DOMAINS`.
  - *Measure:* constructed objects validate (fewer early-return paths); enum-arg
    correctness (1/21 → target ≥ all); chromaticity/gamma branches reached.
- **L7 — Knowledge dictates *what order* (OrderSets + ALL-COVER floor). [~70%
  wiring of what we already have + one small pure-Python port — NOT a new
  extractor.]**
  - *What (a) OrderSets:* we ALREADY extract ordered per-caller call sequences
    (`static_trace.py:extract_project_traces` → `StaticTrace.api_calls`, richer
    than PromeFuzz `cgprocessor` — we also capture arg-bindings) and ALREADY feed
    them to `construct_sequences` (`data_context.py:1233-1251` → `accepting_paths`)
    — but **un-normalized and un-minimized** (a 30-call test becomes one giant
    30-API seed). **Port (verbatim-ish, zero deps):** `OrderSet.from_order_list`
    (size-bounded split, `consumer.py:375-441`) + `OrderSetCollection.minimize`
    (Set-Cover, `consumer.py:514-566`), parameterized over API-name `str`, into a
    new `liberator_adapter/analysis/order_sets.py`; map MIN/MAX size to our density
    band (`LOGICFUZZ_DENSE_MAX_EXTRA`). Do **NOT** build a new call-graph extractor
    (ours wins) or port `relevance.py` (Z3/typestate/automaton are order-aware and
    stronger; their `RelevanceCalculator` weighted-sum is the empirical-weights
    anti-pattern we reject).
  - *What (b) ALL-COVER floor:* ours guarantees ≥1 driver per *cluster*; PromeFuzz
    guarantees ≥1 per *API* (its ~95.4%). Add an offline **Phase-1b API-floor pass**
    in `_coverage_complete_select` (greedy set-cover over the *ranked* pool so every
    constructable API appears in ≥1 selected sequence; APIs with no Z3-viable
    sequence remain the binding-layer tail — surface as `api_floor_residual`).
    This removes the per-API top_k cap PromeFuzz lacks; pair with L1 so floor
    drivers aren't all parser-gated. (Skip their *online* iterative
    loop/deprecation — that's F6 territory; we add the floor as one batch pass.)
  - *What (c):* either **wire** Step-9 `pattern_analysis` (varlen/loop/callback/tlv
    → hole rendering) **or delete it** (computed, persisted, 0 consumers).
  - *Where:* new `liberator_adapter/analysis/order_sets.py`; wire the normalize+
    minimize at `data_context.py:1233-1251` (before `construct_sequences`);
    Phase-1b floor in `liberator_adapter/constraints/coverage_ranker.py:
    _coverage_complete_select` (~after `:509`, before the depth pass);
    `data_context.py:1745` (`pattern_analysis`). (Order-set-FIRST scheduling is
    ALREADY-HAVE: acc=1.0 witnessed paths sort first under the acceptance-primary
    key, `coverage_ranker.py:307-313`.)
  - *A/B gate:* `LOGICFUZZ_ORDERSETS`, `LOGICFUZZ_API_FLOOR`.
  - *Measure:* distinct APIs scheduled ↑ toward full surface (`api_floor_residual`
    = the binding tail); order-correctness of multi-API chains; no subsystem
    silently dropped (logged).

### Phase 2 — Token polish + selling-point proof (reframed; small)

- **L4 (reframed).** Per-call prompt is already ~7K. Do only: (a) enable
  prompt-prefix caching — reorder so the stable ~5K prefix (system, template,
  library_purpose, `<library_constants>`, project-stable signature/role table)
  comes first and the variable per-skeleton CALLSPEC/skeleton/holes come last
  (`cached_tokens=0` today confirms it's off); (b) compute `<library_constants>`
  once per project instead of re-attaching to each of N skeletons
  (`hole_semantics.py:461-470`). (c) Document the *measured* efficiency advantage
  vs PromeFuzz (lean constrained prompt + symbolic structure vs PF O(N²)
  comprehension) as a paper selling point.
  - *A/B gate:* `LOGICFUZZ_PREFIX_CACHE`.
  - *Measure:* `cached_tokens` > 0 on calls after the first; tokens/run ↓ modestly.

## 6. API-doc handling: PromeFuzz baseline, our ladder, and what we adopt

### 6.1 How PromeFuzz acquires / organizes / structures API docs (reference)

Verified against the PromeFuzz source (`/tmp/promefuzz_ref`) + paper Appendix I.

- **Acquisition.** `document_paths` + `document_has_api_usage` per lib in `lib.toml`
  (e.g. `database/libucl/lib.toml:4-8` lists `README.md` + `doc/api.md`,
  `document_has_api_usage=false`). Accepts `.md/.txt/.html/.htm/.pdf/.adoc/.rst`,
  whole directories, and **website URLs** (real HTTP fetch, spoofed `USER_AGENT`)
  — `libraries.template.toml:19-26`, `src/comprehender/knowledge.py:106`,
  `src/llm/rag.py:108-168`. PDF→`UnstructuredPDFLoader`, HTML→`UnstructuredHTMLLoader`,
  URL→`WebBaseLoader`.
- **Organization.** A **Chroma RAG vector DB** (`knowledge.py:75-78`); embeddings
  `nomic-embed-text`/`ada-002`; `RecursiveCharacterTextSplitter(chunk_size=1000,
  overlap=200)` (`rag.py:128-132`); `retrieve_top_k=3`. Doc↔API binding is a
  **name-only NL query** `"usage of function {name}"` (`comprehender.py:294`), then
  an LLM "valuable-excerpts" filter (`comprehender.py:413-421`). Their own code
  notes this can't disambiguate overloads (`comprehender.py:458-461`).
- **Schema (the crux): there is NONE.** The per-API artifact is a single
  **free-text string ≤300 chars**: `LibraryComprehension.functions: dict[str,str]`
  (`comprehender.py:58-69`), produced by a "summarize the usage, be concise under
  300 characters" LLM call (`prompt/deduce_func_usage_from_doc.sys`). No
  params/returns/ownership typing. The *only* JSON the LLM ever emits is the
  crash-constraint map `{api: free_text_suggestion}`, which is then **concatenated
  back into that same usage string** (`generator/learner.py:339-351`). At
  generation time the string is dropped verbatim into the prompt
  (`generate_c_driver.sub`, `prompter.py:221`); raw chunks are never injected.
- **`document_has_api_usage=false` (default; lcms/cjson/libpng/… 10/23 libs)** ⇒
  the doc-retrieval path is skipped and *all* usage is inferred **source-only**
  (`comprehend.py:78-80`, `comprehender.py:444`). Paper Appendix I: only **20.5%**
  of APIs are documented; documented APIs 97.27% gen-success vs 94.94% undocumented
  — and **"misleading documentation may increase the cost of generation"** (p.20).

### 6.2 Our multi-source knowledge priority ladder (doc-source decision)

The model reconciles signal in this priority (higher wins; lower fills gaps) —
so lcms (no machine-readable docs) is fully served by 1–3:

1. **Header naming + IR/SVF** — `root_kind`, roles, creators, INIT producers.
2. **Mined legal-constant sets** — enum/`#define` groups → exact value domains.
3. **Example/consumer code** — call orders (L7) + canonical constants (L6).
4. **Prose docs where machine-readable** — `.md`/`.rst`/doxygen `@param`/`@return`
   (`project_docs.py:extract_markdown_api_docs` / `extract_doc_signals`).
5. **PDF/man/HTML** — **DEFERRED**, build only behind a quality A/B if 1–4 prove
   insufficient on doc-rich libs.

### 6.3 What we adopt / deliberately don't (grounded in 6.1)

**Key finding: PromeFuzz has no richer doc schema than ours — it has essentially
none.** Our `{brief, params:[{index,name,text,role}], returns}` record
(`project_docs.py:_parse_doxygen_structured`) is *strictly* more structured. The
real gap is that `collect_doc_evidence` collapses each `@param`→an `ArgRole` enum
and **discards `param.text`** (`api_semantic_model.py:468-475`), while
`hole_semantics` then asks the LLM to *guess* the value range
(`hole_semantics.py:181-188`). So the fix is **stop discarding the structured doc
we already mine**, not imitate PromeFuzz.

| Mechanism | PromeFuzz | Ours |
|---|---|---|
| Acquisition | .md/.txt/.html/.pdf/.rst + dirs + **URLs** via RAG; gated, **default source-only** | `project_docs.py`: README + header doxygen + `.md`/`.rst` under `doc/`; **no PDF/HTML/URL**, always-on |
| Storage / bind | Chroma embeddings, name-only query, top-3 + LLM filter | Deterministic name→record dict, exact heading match (no recall miss, no overload bug) |
| Per-API schema | **free-text `str` ≤300 chars** | **typed `{brief, params[{text,role}], returns}`** (richer) |
| Survives to model | whole string passthrough | `@param.text` **discarded**; `brief`→APIRole, `returns`→`may_return_null` only |
| Gen-time injection | free-text usage + signature + `A→B` order | per-arg intent directives + ret-contract note |

**Adopt (deterministic, no added LLM cost):**
1. **Pin `@param.text` → per-arg value-domain hint** instead of dropping it
   (`api_semantic_model.py:468-475` → `hole_semantics._arg_intent`); regex-mine
   numeric/enum ranges from the prose ("between 0 and 1", "must be ≥
   `PCAP_ERRBUF_SIZE`"). This is the one place doc text can *dictate values* with
   no LLM call — folded into **L6** below.
2. **Widen the deterministic doc sweep** to PromeFuzz's accepted set we lack —
   `man/*.3`, top-level `USAGE`, `.adoc` — cheap, raises the 20.5%-documented base.
3. **Verify the `returns`→`error_contracts` channel actually receives the
   freshly-mined markdown signals** (`extract_error_contracts(doc_signals=…)`,
   `data_context.py:2060`) instead of falling back to cached `docs_priors.json` —
   folded into **L6**.

**Do NOT adopt:** RAG/Chroma/embeddings (our exact-name match wins, no overload
bug, no embedding dependency); the free-text `dict[str,str]` artifact + the
"summarize ≤300 chars" per-API LLM call (lossier than our typed record, +1 LLM
call/API); PDF/HTML/URL scraping (high cost for the long tail; PromeFuzz's own
caveat that misleading docs raise generation cost argues against uncurated
intake).

### 6.4 Concrete reuse map from the `reference/promefuzz` SOURCE (port / adapt / already-have / skip)

Studied at `/tmp/promefuzz_ref` (= `reference/promefuzz` worktree). Verdicts are
implementation-level (function@line → our target), per the reuse-over-reimplement
principle. The headline: **almost everything is already-have or skip; the single
genuinely portable artifact is the pure-Python `OrderSet` + Set-Cover (L7).**

| PromeFuzz source (file:line) | What it is | Our target | Verdict |
|---|---|---|---|
| `consumer.py:OrderSet.from_order_list` (375-441) + `OrderSetCollection.minimize` (514-566) | size-bounded order-sequence split + Set-Cover minimization — **pure list/set, zero deps** | NEW `liberator_adapter/analysis/order_sets.py`, wired at `data_context.py:1233-1251` | **PORT (verbatim-ish)** — the one real port |
| `scheduler.py` ALL-COVER per-API floor (473-494, 340-350) | guarantee every API scheduled ≥1 | Phase-1b in `constraints/coverage_ranker.py:_coverage_complete_select` (~after :509) | **ADAPT** — as one offline pass (per-API, not per-cluster) |
| `consumer.py` call-graph builder / `cgprocessor.cc` | clang LibTooling caller→callee extraction | `static_trace.py:extract_project_traces` | **ALREADY-HAVE (ours better** — adds arg-bindings) |
| `scheduler.py:schedule_order` order-sets-first (398-432) | schedule witnessed orderings before synthesized | acceptance-primary sort, `coverage_ranker.py:307-313` | **ALREADY-HAVE** |
| `scheduler.py` FUNCTION_SET_SIZE 6/8 (129) | APIs per driver | `_densify` `LOGICFUZZ_DENSE_MAX_EXTRA=8` | **ALREADY-HAVE** |
| `relevance.py` Type/ClassScope/CallScope (148-291) | deterministic pairwise API affinity (for LLM grouping) | type graph (L0) + `subsystem_clusters` + automaton acceptance | **SKIP / ALREADY-HAVE (stronger, order-aware)** |
| `relevance.py:RelevanceCalculator` weighted sum (294-331) | empirical-weighted affinity scalar | — | **SKIP** (empirical-weights anti-pattern we reject) |
| `scheduler.py` online loop + deprecation (311-338) | feedback-driven per-driver scheduling | F6 CEGAR (deferred) | **SKIP this round** (online; = F6) |
| `generator/{sanitizer,learner}.py` crash→constraint→knowledge | runtime feedback refining the per-API knowledge DB | F6 Phase-C CEGAR design reference | **DEFER** (the design reference for F6; T12 is our precursor) |
| `generator/synthesizer.py` synthesize_into_one | merge many drivers → one harness + input dispatch | `tools/merge_drivers/` + `run_single_fuzz` merge | **ALREADY-HAVE** (we cite it; + compile-validation gate they lack) |

**Two facts worth carrying to the paper:** (1) L1 (object-construction-first root)
is **not in PromeFuzz at all** — a clean novel lever, not a port. (2) Even this
"neural" baseline keeps its Scheduler + 3/4 relevance signals **deterministic**
(LLM only for semantic-relevance, usage prose, code synthesis); our edge is
pushing that boundary further (Z3/typestate relevance + a typed knowledge schema),
which directly supports the knowledge-driven headline.

## 7. Measurement & A/B plan

- **Metrics:** per-driver preflight `edges_seen`; merged-harness branch coverage
  (llvm-cov, A≡B); distinct invoked API count; FP/crash count
  (crash_feasibility); tokens/run + `cached_tokens`.
- **Controls:** every lever ships behind a `LOGICFUZZ_*` kill-switch (above),
  default-off until its own A/B proves the gain (factory/diversity/lean
  precedent). Graduate to default-on per coverage A/B.
- **Order of evaluation:** Phase 0 lands first → re-measure c-ares/zlib/libpng to
  get an honest baseline → then Phase-1 A/Bs are attributable (a quality change
  vs a pipeline loss is no longer confounded).
- **Primary success target:** merged-union coverage on lcms-class libs (L1/L6 +
  Phase-0) + breadth-to-PF via the ALL-COVER floor (L7).

## 8. Risks & mitigations

- *L1 over-constructs objects that still need a valid sub-component* → pair with
  L6 valid value-domains; keep ≥1 parser-rooted driver/subsystem.
- *L6 over-pins to canonical constants, killing fuzz diversity* → derive *within*
  the documented range (FUZZABLE_HOLES), not a fixed value.
- *L7 consumer extraction catches comment-words/macros* → reuse existing
  comment-strip + macro/`__`-builtin filter.
- *L3 typedef-name typing over-constrains genuinely interchangeable `void*`
  user-data* → only tighten where the typedef denotes a distinct opaque handle.
- *Phase-0 ABI pin breaks the coverage build's own toolchain* → pin preflight
  only; leave the cov build's flags intact (A≡B preserved).

## 9. Deferred / out-of-scope

PDF/HTML/man extractor (gated A/B); F6 Phase-C CEGAR loop; libucl/libtiff/libvpx
Z3-on runs need `LIBERATOR_SVF_TIMEOUT_SECS≥14400` (time-bound SVF — orthogonal,
tracked in `memory/project_libucl_comparison.md`); per-run information-budget
scheduling (T7 decision c).
