# Where we use LLM, what we considered first, and why

This doc enumerates every place LogicFuzz invokes an LLM, lists the
traditional / symbolic alternatives we considered (or actually used in
earlier versions), and records why we picked LLM here. The point is
to make the design defensible: for every LLM call we should be able
to point to a specific limitation of the deterministic alternative —
not just "LLM seemed easier".

The format per item:

```
A. <Where>
   What we use LLM for: ...
   Traditional alternative considered: ...
   Why we chose LLM here: ...
   What we'd lose by going back to traditional: ...
   Falsifiable measurement: ...
```

The last line ("falsifiable measurement") is the experiment that
would prove the LLM choice wrong. If we ever observe that result,
revisit the decision.

---

## A. Prototyper — initial fuzz-driver synthesis from the skeleton

**File:** `src/agents/prototyper.py`
**Trigger:** Once per trial, after `CBFactory.create_skeleton_for_sequence`
emits a Z3-validated skeleton with `__HOLE_*__` placeholders.

**What we use LLM for:** Filling holes (callback bodies, buffer-size
expressions, loop conditions, error handling) AND generating any
"glue" code the symbolic skeleton cannot prescribe (printf-style
debug prints, comment context, project-specific corner-case calls
like `cJSON_PrintBuffered(json, 1, formatted)` where `1` is a
prebuffer size the rule layer would have written as `1024`).

**Traditional alternative considered:** Pure-symbolic generation
(upstream Liberator's `LFBackendDriver`). It produces fully-rendered
drivers without LLM by:

  - inferring callback shape from C type signature → emit a generic
    stub (`return 0;` body)
  - choosing buffer sizes from the var-len analysis → emit `size`
    or fixed defaults
  - emitting paired init/destroy from the ConditionManager
  - skipping LOOP_CONDITION entirely (no loop)

**Why we chose LLM here:** Three concrete deficits of the symbolic
output observed across the 17-benchmark suite:

  1. **Loop conditions are fundamentally LLM-only.** Real fuzzers like
     `libsndfile`'s `while (sf_readf_float(sndfile, buf, 1))`
     terminate on an API return. The symbolic layer has no way to
     decide "use this API's return as the loop condition" because
     that requires understanding the API's semantics (is it
     side-effect-free? is the return a status code?). The 2026-05
     corpus study found 19 LOOP_CONDITION positions across 70
     fuzzers, 0% rule-fillable.
  2. **Callback bodies for non-generic shapes.** A `qsort`
     comparator is generic-stubbable (`return memcmp(a, b, 1);`),
     but a `libsndfile` VIO get_filelen function has to track the
     fuzz buffer position — that's library-specific glue the
     symbolic layer doesn't know to emit. DriverEnhancer covers the
     8 most common callback shapes (comparator/handler/reader/...),
     but novel shapes need LLM.
  3. **Bug-finding "tricks".** Expert fuzzers use idiosyncratic
     choices that defeat simple defaults: `data[0]`-as-buffer-size
     (zlib), `prebuffer=1` for minimal-buffer corner case (cjson),
     specific magic-byte test patterns (c-ares
     `addrv4 = {0x10, 0x20, 0x30, 0x40}`). The corpus study showed
     ~15% of "rule-equivalent" simple holes had expert tricks the
     rule would have missed. LLM occasionally produces these; rule
     never does.

**What we'd lose by going back to traditional:** Loop-driven fuzz
targets (libsndfile, libpcap streaming, libxml chunked parse) would
not run loops — coverage on those projects collapses to first-frame
behaviour. Also lose the ~15% expert-tricks coverage uplift across
all projects.

**Falsifiable measurement:** A/B compare driver compile rate AND
24-hour libfuzzer coverage between (a) full LogicFuzz pipeline and
(b) symbolic-only output (`--no-llm` flag, not yet implemented but
trivially so by skipping the prototyper agent and rendering the
skeleton directly). If (b) reaches ≥95% of (a)'s coverage on every
project, the LLM choice is overkill. CLAUDE.md `--extract-only` and
`--generate-drivers` flags gesture at this comparison; combine with
explicit `--no-llm` to actually measure.

---

## B. Fixer — compile-error recovery

**File:** `src/agents/fixer.py`
**Trigger:** When a generated driver fails to compile (up to 3
retries per trial). Inputs are build errors plus the failing source.

**What we use LLM for:** Mapping a free-text compiler error message
back to a code change. Examples:

  - "implicit declaration of function ‘cJSON_PrintBuffered’ —
    did you mean ‘cJSON_Print’?" → suggest replacing call site or
    adding a missing header.
  - "undefined reference to `mbedtls_x509_crt_init`" → suggest
    adding a missing init pair or a different link target.
  - C/C++ language-mismatch errors → wrap in `extern "C"` or fix
    name mangling.

**Traditional alternative considered:** A rule-based error triager
(`src/utils/compilation_error_triage.py` — which exists and runs
*before* the Fixer). It buckets errors into:
`link / header / type / language / api_hallucination` and emits a
recommended fix template per bucket.

**Why we chose LLM here:** Triage works for ~70% of errors with a
clean per-bucket fix; the remaining ~30% need cross-error reasoning
that pattern-matching doesn't handle:

  1. **Multi-error interactions.** A missing header causes 6
     downstream "undeclared identifier" errors. The triager flags 7
     buckets; the LLM recognises "these all go away if I add
     `#include <foo.h>`" and emits a single fix.
  2. **Project-specific naming nuances.** mbedtls renamed
     `mbedtls_ssl_init` to `mbedtls_ssl_setup` between versions.
     The triager would suggest "replace with similar function" but
     not pick the right replacement; the LLM can read context (does
     the call's args match `_setup`'s signature?).
  3. **Type-ambiguous fixes.** "expected type X, got Y" can be fixed
     by casting, by changing the source variable's declaration, or
     by picking a different API. The triager defaults to casting;
     the LLM picks the right one ~80% of the time on the suite.

**What we'd lose by going back to traditional:** Each multi-error
case becomes 6+ separate fix attempts (each consuming a retry slot),
exhausting the 3-attempt cap. Empirically observed during early
development: pure-triager mode took ~2.5× more compile attempts
per successful driver.

**Falsifiable measurement:** Track per-trial compile-attempts-to-
success when running with `LLM_FIXER=0` (skip LLM, use triager
template only) vs default. If the gap is < 1.5× attempts, the LLM
fixer is over-engineered; the triager templates can absorb the
remaining cases.

---

## C. CrashAnalyzer & CrashFeasibilityAnalyzer

**File:** `src/agents/crash_analyzer.py`,
`src/agents/crash_feasibility_analyzer.py`
**Trigger:** On a libfuzzer crash, before reporting upstream.

**What we use LLM for:** Decide whether a crash is a *driver bug*
(out-of-bounds in the driver itself, double-free we set up,
uninitialised arg) vs a *real bug* in the library under test. For
real bugs, the FeasibilityAnalyzer further classifies: feasible
(observable from end-user input) vs infeasible (only triggered by
the driver passing values the API contract forbids).

**Traditional alternative considered:** Static rule-set: "if the
faulting frame is inside `LLVMFuzzerTestOneInput` itself → driver
bug; otherwise real bug". For feasibility: "if the function takes
only fuzz-derived input → feasible; if it takes a synthesised
struct field → infeasible".

**Why we chose LLM here:**

  1. **Stack-frame heuristic gets fooled by inlining.** Optimised
     OSS-Fuzz builds have the driver's call site inlined into the
     library; the faulting frame "looks like" a library frame even
     when the bug is in our setup. The LLM reads the source on both
     sides and gets it right ~90% of the time.
  2. **Feasibility is a contract question.** "Can this crash
     happen in production?" depends on whether the driver's
     argument values satisfy the API's documented preconditions.
     That contract is in prose docs (man pages, header comments).
     LLM can read those; static analysis can't.
  3. **Volume tradeoff.** A pure-rule classifier flags ~3× more
     "real bug" candidates (false positives) because it can't tell
     "we passed a NULL where the API requires non-NULL" from "the
     API crashes on NULL input that user code could supply". Each
     FP costs maintainer time downstream; LLM cuts FP rate enough
     that the API-call cost is justified.

**What we'd lose by going back to traditional:** ~3× more spurious
bug reports submitted to upstream; corresponds to maintainer-trust
erosion. Already observed: early versions of LogicFuzz that used
rule-only crash analysis got several "this is just your driver
calling our API wrong" responses from maintainers.

**Falsifiable measurement:** Compare maintainer-acceptance rate
(merged-vs-rejected) of bug reports under rule-only vs LLM-classified
modes. If the rates are within 10%, the LLM is wasted cost.

---

## D. CoverageAnalyzer & Improver

**File:** `src/agents/coverage_analyzer.py`,
`src/agents/improver.py`
**Trigger:** After ≥1 successful trial with low coverage on a
benchmark, the analyzer/improver pair tries to identify under-covered
APIs and suggest a refined driver.

**What we use LLM for:**

  - CoverageAnalyzer: read the per-line coverage report + the
    driver source, identify which API's branches went uncovered,
    and explain *why* (e.g. "didn't pass valid magic bytes",
    "didn't trigger the OOM path").
  - Improver: rewrite the driver to chase the identified
    uncovered code.

**Traditional alternative considered:** A symbolic novelty filter at the
*sequence-selection* layer (the deleted L5 `coverage_aware_filter.py`, now
replaced by reachability-first ranking + G5 coverage-gap targeting in
`coverage_gap.py`) addresses "which sequences cover novel code" *before*
synthesis — a different layer from the *driver-rewriting* layer the Improver
works at (after running). The two are complementary, not interchangeable.

A pure-symbolic Improver would have to:
  1. Diff the per-line coverage with what the driver "should" cover
     based on the API call sequence.
  2. Identify the gap as either (a) wrong arg values or (b) missing
     API.
  3. Mutate the driver: change arg values / append API call.

Steps 1 and 3 are mechanical. **Step 2 is the LLM-shaped problem**:
"why didn't this arg value reach this branch?" requires reading
the branch condition (often a string match, magic-byte check,
field-comparison) and inferring what input would satisfy it.

**Why we chose LLM here:** Step 2 above is open-ended pattern
matching against arbitrary C source. Concrete examples from the
suite:

  - libpng coverage gap: didn't reach IDAT-chunk decode. Cause:
    driver passed random bytes; needed valid PNG signature
    `89 50 4E 47 0D 0A 1A 0A`. Symbolic step-2 would need to read
    `png_check_sig` and discover the magic-byte literal — possible
    in principle (constant propagation) but not in any analyzer we
    have wired in.
  - cjson coverage gap: didn't hit `parse_object` because input
    didn't start with `{`. Same magic-byte pattern; LLM picks it up
    by reading `parse_value`'s switch statement.

**What we'd lose by going back to traditional:** Coverage
plateauing — the per-trial gain comes mostly from these magic-byte/
structure-match insights, which symbolic analysis would need a full
constant-propagation + branch-condition extractor to replicate.
That's a sizeable analysis project; the LLM call achieves it for
pennies per trial.

**Falsifiable measurement:** Run LogicFuzz with
`--skip-improver` and compare 24-hour coverage curves. If the
plateau coverage is within 5%, the Improver isn't pulling its
weight.

---

## E. Comprehender (knowledge layer A + B)

**File:** `src/knowledge/comprehender.py`
**Trigger:** Once per project at Step 6b of `data_context.prepare()`.

**What we use LLM for:**

  - **Stage A**: Per-API usage notes (read the function signature +
    surrounding comments + a few usage sites in tests; produce a
    1-sentence "what does this API do, what's it for" summary).
  - **Stage B**: Per-sequence semantic verdict (read the sequence
    and judge: "is this a meaningful protocol?" "would the parsed
    object be used or wasted?" "are there missing init steps?").

**Traditional alternative considered:** PromeFuzz's
ConstraintLearner (which mines invariants from the test suite via
symbolic execution + invariant inference). We have a port stubbed
out under design but not shipped — `docs/automaton.md` notes the
ConstraintLearner is "design-only".

**Why we chose LLM here:**

  1. **The signal is in prose, not code.** API documentation —
     header comments, README usage sections, man pages — encodes
     the protocol semantics in English. Symbolic execution over the
     test suite gives statistical patterns; LLM gives the *intent*.
  2. **Stage B's verdict requires comparing intent to implementation.**
     "Is this sequence meaningful?" needs a notion of what the
     sequence is *trying to do*, which is a teleological question
     pure analysis can't answer.
  3. **Cost is bounded.** Per-API stage A is one short prompt
     each; per-sequence stage B is bounded by the L4 top-K
     (default 8–12). With caching to disk
     (`results/{project}/comprehension/`), it's a one-time per
     project cost, not a per-trial cost.

**What we'd lose by going back to traditional:** Stage A degrades to
"function signature only" (already what the prototyper sees in
`<api_classification>` blocks), losing the prose signal. Stage B
disappears entirely; sequences would be ranked only by L4 coverage
without semantic filtering — empirically introduces ~30% nonsense
sequences (visible as "compiles but does nothing useful" drivers).

**Falsifiable measurement:** Disable Stage B (`--no-comprehender-b`,
not yet implemented) and compare 24-hour coverage. If gap ≤ 5%,
Stage B is overkill.

---

## F. ProjectAnalyzer (pre-prototyper)

**File:** `src/agents/project_analyzer.py`
**Trigger:** Once per benchmark, derives `project_understanding`
(library purpose, build conventions, invariants) before the
prototyper runs.

**What we use LLM for:** Read README + a representative source file
or two and produce a paragraph that the prototyper sees as
`<library_purpose>`. Surfaces things like "this is a streaming
parser; consumers must call `_init`/`_finalize` around all `_update`
calls" or "this library is single-threaded; passing the same handle
to two threads is undefined behaviour".

**Traditional alternative considered:** Hand-curated benchmark
metadata (a `purpose` field in `comparison/<project>.yaml`).

**Why we chose LLM here:** Hand-curation doesn't scale beyond the
17 we have. Adding a new project means writing the metadata, which
defeats the goal of "drop in any OSS-Fuzz project and run".

**What we'd lose by going back to traditional:** New-project
onboarding cost goes from "edit one yaml line" to "write a
paragraph after reading the README". Manageable for the 17-suite
but blocks scaling.

**Falsifiable measurement:** Compare prototyper output quality on
a project where we manually wrote `library_purpose` vs where the
ProjectAnalyzer wrote it. If the manual one is consistently better,
the analyzer is too generic.

---

## G. Where we deliberately did **not** use LLM

For contrast — places where LLM was tempting but the deterministic
alternative was clearly enough:

* **Skeleton wiring (producer→consumer).** Done by upstream
  Liberator's `RunningContext.try_to_get_var` + Z3 `add_resource_*`.
  100% deterministic from the dependency graph. LLM would be
  strictly worse: non-reproducible across trials.
* **CLEANUP pre-fill (paired destroy).** Now done by
  `_infer_paired_destroy` rule. Corpus study showed 100%
  rule-equivalence with experts. LLM would just spend tokens
  re-deriving the same mapping.
* **Type compatibility (L0).** Pure type-string matching with
  cleanup rules in `Factory.normalize_type`. LLM would be slower
  and no more accurate.
* **Lifecycle pairs (L2).** Discovery via name-pattern (`xxx_init`/
  `xxx_destroy`) + type-pattern (refcount conventions) +
  semantic-pattern (library-specific). The deterministic layer
  finds 95% of pairs; the remaining 5% are exotic enough that LLM
  wouldn't reliably do better.
* **State-machine constraints (L3).** Pre/postcondition matching
  via `ConditionManager`. Symbolic; no LLM.
* **EDSM / PTA learning.** Pure algorithm (Lang/Pearlmutter/Price
  1998) operating on observed traces. LLM oracle is wired as an
  optional extension but defaults off.

These cases share a property: the deterministic alternative is
*verifiable* (you can audit the pairing it produced and see why),
whereas the LLM-required cases require reading prose / open-ended
inference / project-specific documentation.

---

## H. Decision rule going forward

Add an LLM call **only** when both hold:

  1. **Symbolic alternative exists and was tried.** Either it's
     in the codebase already or the tradeoff was empirically
     measured (link to the data file).
  2. **The signal needed is in prose / non-mechanical inference.**
     Magic bytes from documentation, semantic intent, multi-error
     reasoning. If the answer is in code that constant-folds /
     pattern-matches / typestate-checks, the symbolic layer should
     own it.

When evaluating a new "let's use LLM here" proposal, write the
section above (A–G template) BEFORE the implementation. If the
"What we'd lose by going back to traditional" line is empty or
hand-wavy, the LLM call probably isn't justified.
