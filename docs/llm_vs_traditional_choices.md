# Where we use LLM, what we considered first, and why

This doc enumerates every place LogicFuzz invokes an LLM, the symbolic
alternative considered, and why LLM won — so the design is defensible: every
LLM call points to a specific limitation of the deterministic alternative, not
"LLM seemed easier". Each item ends with a **falsifiable measurement** — the
experiment that would prove the LLM choice wrong; observe that result, revisit
the decision.

---

## A. Prototyper — initial driver synthesis from the skeleton

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

---

## B. Fixer — compile-error recovery

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

---

## C. CrashAnalyzer & CrashFeasibilityAnalyzer

**File:** `src/agents/crash_analyzer.py`,
`src/agents/crash_feasibility_analyzer.py` · on a libfuzzer crash, before
reporting upstream.

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

---

## D. CoverageAnalyzer & Improver

**File:** `src/agents/coverage_analyzer.py`, `src/agents/improver.py` · after a
successful but low-coverage trial.

**LLM job:** read the per-line coverage report + driver, identify which API
branches stayed uncovered and *why* (wrong magic bytes, untaken OOM path), then
rewrite the driver to chase them.

**Symbolic alternative:** a pure-symbolic Improver would diff covered-vs-should,
classify the gap (wrong arg value / missing API), and mutate. Steps 1 and 3 are
mechanical; **step 2 — "why didn't this arg reach this branch?" — is the
LLM-shaped problem**: it requires reading the branch condition (string match,
magic-byte check) and inferring satisfying input. (Note: this is a *different*
layer from sequence-selection novelty — that job moved to reachability-first
ranking + G5 gap targeting in `coverage_gap.py`.)

**Why LLM:** concrete suite examples —
- libpng: didn't reach IDAT decode; needed the PNG signature
  `89 50 4E 47 0D 0A 1A 0A`. Symbolic would need constant-propagation into
  `png_check_sig` — no analyzer we have wired in.
- cjson: didn't hit `parse_object` because input didn't start with `{`; the LLM
  reads `parse_value`'s switch.

**Cost of reverting:** coverage plateaus — the per-trial gain comes mostly from
these magic-byte / structure-match insights, which symbolic would need a full
constant-propagation + branch-condition extractor to replicate.

**Falsifiable:** 24h coverage with vs without the Improver. Within 5% → it
isn't pulling its weight.

---

## E. Comprehender (knowledge layer A + B)

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

---

## F. ProjectAnalyzer (pre-prototyper)

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

---

## G. Where we deliberately did **not** use LLM

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

---

## H. Decision rule going forward

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
