# Generation-Stage Information Audit (2026-06)

Scope: the **driver-generation** stage only (repair / optimize / root-cause are
deferred). Question: is the tool squeezing the valuable information out of its
inputs and its own analyses, feeding the LLM the *right* (not the *most*)
information, and dividing labor between symbolic methods and the LLM the way a
human expert would?

Method: a 4-axis adversarial audit (input sources, static analysis, LLM input
diet, symbolic↔LLM synergy), each grounded in file:line.

---

## Thesis

The **division of labor is correct in principle** — Z3 + use-def + typestate
own program *structure* (lifecycle, handle wiring, call order); the LLM owns
*soft* decisions (values, semantics, hole-fill). The problem is **information
loss at every boundary**: rich signals are computed and then thrown away before
they reach the decision that needs them, while the LLM is simultaneously
*over*-fed low-signal, redundant text. The tool dumps everything it computed and
loses everything it should have distilled.

A human expert does the opposite: reads a *few* precise facts (header enums, the
parser's front-gate bytes, @return NULL-contracts, the sibling driver's call
chain) and writes a tight driver. The gap between the two is this audit.

---

## The convergent finding: information leaks at 5 boundaries

### B1. Input sources → knowledge (Axis 1) — massively under-extracted
- **Cross-project transfer is entirely absent.** Generation for project X reads
  ONLY X's own drivers (`_resolve_drivers_root(project_name)` keys strictly on
  the name, `data_context.py:2157`); grep for retrieval/transfer/similar finds
  nothing. The repo already has a corpus (`extracted_fuzz_drivers/`, and the GCS
  puller grabs "all projects"). A new/thin library gets nothing, even when a
  structurally-near library (another JSON/image/codec parser) has a battle-tested
  driver showing the exact creator→parse→consume→free idiom. **Biggest free,
  high-signal source, 100% unused.**
- **The existing driver's call SEQUENCE + arg-provenance is discarded.** Only 3
  verbatim sources + 10 regex idioms survive (`idiom_distiller.py`); the
  authoritative API n-gram + which-return-feeds-which-arg graph is never
  reconstructed. The automaton learns sequences from tests/examples but
  *pointedly not from the driver sources* — the single most authoritative valid
  fuzz-entry example.
- **Doc priors default OFF** (`--use-doxygen-priors` / `--use-readme-purpose`).
  Default runs fabricate library purpose from the project name and never read
  `@param` ownership or `@return`/`@retval` NULL-contracts — exactly the signal
  the "generated drivers miss NULL-checks on creator returns" memory note needs.
- README **Quick-Start code blocks** (a free worked example) are explicitly
  stripped; **seed corpus** (real input format/magic bytes) is fuzz-time only,
  invisible to generation; **build.sh/.dict/.options** (required -D defines,
  format dictionary, max_len) unmined.

### B2. Static analysis → model (Axis 2) — rich SVF data destroyed at the boundary
- **The whole per-param `access_type_set` is reduced to ONE boolean.**
  `usedef.py:363` collapses ~969 field-level struct accesses + create/delete
  provenance + per-field write masks (per lcms) into `_svf_writes`. Everything
  else is dropped.
- **`set_by` (param→param init-dependency graph, ~75 edges on lcms)** is not
  lifted into `APISemanticModel`/the constructor — the model's requires/produces
  is purely handle-type-keyed and cannot express "arg0 struct is populated by
  param_2/param_3".
- **No error-return / NULL postconditions** extracted from the IR (`if (p==NULL)
  return; if (rc<0) goto err`) — recoverable from the bitcode the extractor
  already loads. This *is* the NULL-check bug.
- **No real CFG reachability.** L4 "reachability-first" is automaton *acceptance*
  (protocol-order fit), not static reachability of uncovered blocks; the gap
  signal is flat function presence/absence.
- **No enum/value domains** for CONFIG scalar args (switch tables, enum defs,
  equality guards bound which values reach interesting code).

### B3. Model → LLM (Axis 3) — over-fed, redundant, stale
- **Two redundant role taxonomies** both injected (the demoted name-heuristic
  `classify_project_apis` AND the reconciled `APISemanticModel` roles).
- **3 FULL existing driver source files** dumped (the single biggest token sink)
  overlapping with `<library_idioms>`/`<code_patterns>` that already distilled
  them.
- **System prompt advertises a REMOVED tool**: `fuzz_introspector_query` +
  "Query source code"/"Query usage examples" directives in 4 places, but
  `get_tools()==[]` → phantom tool calls, wasted attention.
- Overlapping API views (`<api_sequences>`/`<sequence_api_signatures>`/
  `<project_apis>`/`<dependency_graph>`), duplicated skeleton renderings, the
  "call more APIs" rule restated 3–4×, no global token budget.

### B4. Symbolic gives up where the LLM is then left to guess (Axis 4)
- **CONFIG/enum args** get only `VARY_RANGE: cover in-range and out-of-range`
  (`hole_semantics.py:96`); the LLM *guesses* legal values (e.g. lcms
  `TYPE_RGB_8`, intent 0–3; zlib level 0–9). A trivial header enum/#define scan
  keyed to the arg typedef would supply these deterministically.
- **Format front-gate hardcodes only 2 formats** (ICC `acsp@36`, IT8);
  everything else gets a vague header/body hint → parsers stay shallow (the
  "uncovered branches inside covered functions" lesson).
- **Binding-failure REASON dies as telemetry.** When `try_to_get_var` raises
  `ConditionUnsat` (incomplete_opaque / struct_needs_init / has_source), the
  reason — now recorded by `_record_binding_rejection` (new) — never reaches the
  hole annotation on the `create_skeleton_unchecked` path, so the LLM doesn't
  learn "this arg needs an init chain / is opaque".
- **Happy-path-only skeletons** (create→use(valid)→destroy) make error/UAF/
  NULL-as-handle/reordered-destroy branches unreachable *by construction*.
- **No dynamic value feedback.** Phase C `coverage_memory.json` is write-only;
  when a trial reaches a deep branch, the working value is lost.

### B5. The human-expert contrast (unified)
An expert writing a high-coverage driver for lcms `cmsDoTransform` / a zlib
deflate chain: (1) reads header **enums** for legal constants; (2) reads the
parser **source/IR** for the front-gate byte predicate (magic / length-prefix /
version); (3) reads **@return** for NULL-contracts; (4) **copies** the existing
or sibling driver's call sequence + input demux; (5) knows from the **call graph**
which API gates the most uncovered code. The tool is strong on (lifecycle +
handle wiring) but skips most of (1)–(5).

---

## Prioritized plan

### Tier 1 — deterministic, low-risk, high-leverage (no new technique; do first)
Each plugs a boundary leak using data the tool already has or can get cheaply:

| # | Change | Boundary | Leverage / effort |
|---|--------|----------|-------------------|
| T1 | **Stop collapsing SVF to one bit.** Lift per-arg field-write masks + `set_by` init-dep edges + `len_depends_on`/`is_array` from conditions.json into `APISemanticModel` and the G4 hole value-intents. | B2 | high / med |
| T2 | **Symbolic enum/#define extractor for CONFIG args.** Scan public headers for the arg typedef's legal enum/constant set; replace the generic `VARY_RANGE` string with the actual value set. | B4 | high / med |
| T3 | **Extract error-return / NULL postcondition per API** from the IR; emit as a mandatory hole/guard constraint (fixes the NULL-check-creator bug). | B2 | high / med |
| T4 | **LLM diet surgery → one typed CALLSPEC DSL table.** Cut the 3 verbatim driver dumps + one role taxonomy + the stale fuzz_introspector directives; collapse the overlapping API/skeleton views into one per-call tuple `step | api | role | ret | args=[(i,type,argrole,pairs_with)] | needs | precond/cleanup | value_intent`; add a global token-budget arbiter. | B3 | high / small |
| T5 | **Surface binding-failure REASON + the producer the analyzer found** into the hole annotation on the unchecked-skeleton path (data already computed by the new telemetry + `find_producer_apis`). | B4 | high / small |
| T6 | **Doc priors ON by default**; parse `@return`/`@retval` into a structured error/ownership contract; capture the README's first usage **code block** as a few-shot. | B1 | high / small |

### Tier 2 — larger or needs a NEW technique (flagging for your go-ahead)
| # | Change | Why it needs sign-off |
|---|--------|------------------------|
| T7 | **Cross-project driver retrieval**: index `extracted_fuzz_drivers/` (+ pull the broader OSS-Fuzz corpus), inject k-NN sibling drivers for thin-artifact libraries (similarity by API-shape signature: creator/parser entry types, opaque-handle catalogue, return-on-error pattern). | Biggest input signal, but needs a corpus + a retrieval/embedding component. |
| T8 | **Mine call-sequence + arg-provenance from the project's OWN drivers** into the automaton/constructor (reuse `static_trace.extract_project_traces` on driver `.c`, not just tests). | Medium build; changes what the automaton learns from. |
| T9 | **Static CFG reachability weight** for gap APIs into L4 (count transitively-reachable uncovered blocks from the bitcode). | Needs a call-graph pass over the bitcode. |
| T10 | **Generalize the format front-gate decoder** via symbolic constant-propagation into the parser's entry check (replace the 2 hardcoded formats). | **NEW TECHNIQUE: lightweight symbolic execution / value-constraint pass.** |
| T11 | **Symbolic shape-variant skeletons** (NULL_INJECT / double-free / reordered-destroy) so error-path branches become reachable (LLM still only fills leaves). | Medium; structural change to the skeleton emitter (generation.md F5). |
| T12 | **Dynamic value-feedback loop**: compile-and-run a micro-probe (or mine surviving values from a trial) and pin the working leaf value / init-chain into the next skeleton's hole (read side of Phase C). | **NEW TECHNIQUE: lightweight dynamic running.** |

### Recommended start
T2 + T4 + T5 are the best first cut — highest leverage, low risk, and they
compose: T2 gives the LLM the real legal values, T5 tells it which args are
hard and why, and T4 stops drowning both signals in redundant text. T1/T3/T6
follow (all deterministic). T7 (cross-project) is the highest-ceiling Tier-2
item. T10/T12 are the two places a **new technique (symbolic exec / dynamic
running)** would clearly earn its keep — proposed, not assumed.
