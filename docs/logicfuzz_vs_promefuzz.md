# LogicFuzz vs PromeFuzz — Driver Generation, Objective Comparison

Status: descriptive (2026-05-23). No proposals, no value judgement — this doc
only states *how each system is built today*, with emphasis on **how a fuzz
driver is produced**.

- **LogicFuzz** = this repo, branch `pub-llm`.
- **PromeFuzz** = branch `reference/promefuzz` (the tool LogicFuzz's knowledge
  layer is derived from).

> For the generation stage's known design problems and the redesign plan, see
> `docs/generation_stage_redesign.md`. This doc is descriptive baseline only.

---

## 0. One-paragraph summary

PromeFuzz produces each driver by **free-form LLM generation**: a scheduler
picks ~8 functions by weighted score, a collector assembles their
signatures/usage/types/headers, and the LLM writes a complete
`LLVMFuzzerTestOneInput` from scratch. Validity is enforced *after the fact* by
a build/run sanitizer and a crash-driven constraint learner.

LogicFuzz produces each driver by **constraint-validated skeleton synthesis
followed by LLM hole-filling**: a multi-layer static filter + Z3 lifecycle
solver + project typestate automaton emit a *type-safe skeleton with holes*
for one validated API sequence, and the LLM is constrained to fill the holes
without changing the structure.

Sharpest difference: **PromeFuzz lets the LLM decide program structure;
LogicFuzz fixes structure symbolically and lets the LLM decide leaf values.**

---

## 1. Pipelines side by side

### PromeFuzz

```
preprocess (src/preprocessor/)   APIs, types, call graph, complexity, relevance
comprehend (src/comprehender/)   library purpose + per-fn usage + relevance (LLM+RAG)
generate   (src/generator/)
   ├ schedule  scheduler.py   pick 8 functions by weighted score
   ├ collect   collector.py   gather signatures/usage/types/headers
   ├ generate  generator.py   LLM writes full driver from scratch
   └ sanitize  sanitizer.py   build+run; LLM fixes build/ASan errors
learn      learner.py         repeated crash → LLM constraint → enrich comprehension
synthesize synthesizer.py     merge drivers into dispatcher harness
analyze    src/analyzer/      ASan crash triage
```

### LogicFuzz

```
static analysis (liberator_adapter/)  Clang/LLVM APIs, types, signatures
L0–L5 filter    (constraints/)         type→entry→lifecycle→state→novelty
L4 ranker       coverage_ranker.py     diversity-greedy top-K
automaton       analysis/              PTA+EDSM typestate from library tests
comprehend      knowledge/             A: per-API usage+purpose; B: per-seq verdict
Phase D Planner state/path_planner      idiom-align rerank + synthesize_missing
Phase A Repair  analysis/candidate_repair  graft creator prefix (idiom-guided)
Z3 synthesis    constraint_based/      position-indexed lifecycle → SKELETON w/ holes
Prototyper      agents/prototyper.py   LLM fills holes (structure locked)
workflow        workflow/ (LangGraph)  build→fixer→execute→coverage→improver
merge_drivers   tools/merge_drivers/   merge trials into dispatcher harness
Phase C memory  state/coverage_memory  post-merge IterationSnapshot
```

Both share the shape (preprocess → comprehend → generate → fix → merge →
analyze); they diverge entirely inside "generate."

---

## 2. How a driver is generated — core contrast

### 2.1 Unit of generation

| | PromeFuzz | LogicFuzz |
|---|-----------|-----------|
| Unit | function set (~8 functions) | validated API sequence (one per skeleton) |
| Picked by | `scheduler.py:Scheduler.schedule_normal` weighted score | `coverage_ranker.py` top-K, reranked by `path_planner.py` |
| Order constraint | optional (consumer order only) | intrinsic: Z3 position-indexed lifecycle |

### 2.2 What the LLM receives / emits

**PromeFuzz** (`llm/prompter.py:CGenPrompter.prompt`, prompts
`generate_c_driver.{sys,usr,sub}`): receives library name, 8 functions each
with signature + LLM-written usage string, type/typedef defs, headers,
optional call order. Emits a **complete** driver. The LLM decides which to
call, in what order, how to wire args, how to derive input from `Data/Size`.

**LogicFuzz** (`agents/prototyper.py`, "MANDATORY SKELETON MODE"): receives
purpose + API usage, the validated sequence, signatures, protocol templates
(automaton-sampled paths), invariants, dep graph, conditions, idioms, and a
**Z3-synthesized skeleton with holes** (`__HOLE_xxx__`, `__BUFSIZE_xxx__`).
Emits hole-fillings (or filled code) under *"Do NOT modify the skeleton
structure, API sequence, or variable declarations."* The LLM decides only
hole contents.

### 2.3 Where validity comes from

| Concern | PromeFuzz | LogicFuzz |
|---------|-----------|-----------|
| Arg type | LLM, then build-error→LLM fix | L0 + Z3 `TYPE_MATCH` before LLM |
| Lifecycle | LLM + crash learning | L2 + Z3 position-indexed validation |
| Ordering / state | optional consumer order; else LLM | L3 + automaton acceptance |
| Meaningful combo? | scheduler relevance + LLM | comprehender-B verdict + acceptance_score |
| Compile | sanitizer loop (5) | LangGraph fixer (3) w/ triage |

PromeFuzz validity is **post-hoc**; LogicFuzz is **pre-hoc for structure**,
post-hoc for the filled body.

---

## 3. API / sequence selection

**PromeFuzz** — weighted scoring, no solver (`scheduler.py:schedule_normal`):
`Score(f) = (3·(1−Cov) + 2·Complexity + 1·Norm(Relevance)) / 6`; set size 8;
>5 failures → deprecate; 10 stagnant rounds → stop. No dependency resolution,
no constraint solving.

**LogicFuzz** — filter cascade + solver + automaton: L0 type → L1 entry → L2
lifecycle → L3 state → L5 novelty → L4 diversity top-K, over a use-def/typestate
substrate (`analysis/usedef.py`); Z3 enforces TYPE_MATCH/PROVENANCE/
RESOURCE_LIFECYCLE/VARIABLE_AVAILABILITY. Selection is provability-gated.

---

## 4. Iteration / feedback

**PromeFuzz** — crash-constraint learning (`learner.py`): a crash repeating ≥3
triggers LLM constraint extraction + fix; cleared crashes append a constraint
to comprehension so future rounds avoid it. Only cross-round learning channel.

**LogicFuzz** — per-trial LangGraph workflow + Phase G closed-loop (viable Z3
sequences grow the automaton via incremental EDSM); Phase C records post-merge
snapshots (loop driver not yet wired). Learns from *which sequences proved
viable*, not from crashes.

---

## 5. Knowledge layer

| | PromeFuzz | LogicFuzz |
|---|-----------|-----------|
| Library purpose | RAG over docs | comprehender A |
| Per-API usage | doc/src comprehend | comprehender A |
| Relevance | pairwise LLM score | encoded in L0–L4 + automaton |
| Doc retrieval | RAG vector store (chroma) | doxygen/README priors (opt-in) |
| Distilled idioms | — | `knowledge/idiom_distiller.py` (10 L1) |
| Sequence verdict | — | comprehender B + `patched_sequence` |
| Typestate model | — | project automaton (PTA+EDSM) |

---

## 6. Multi-driver harness

Both merge into one dispatcher: **PromeFuzz** `synthesizer.py` renames
`LLVMFuzzerTestOneInput`→`_{id}`, reads leading bytes as index, switch-routes;
**LogicFuzz** `tools/merge_drivers/` merges successful trials (`--merge-drivers`).
Mechanically equivalent; over sanitizer-passed vs Z3-validated trials.

---

## 7. What each does NOT do (today)

**PromeFuzz**: no SMT/Z3, no typestate automaton, no pre-validation of
sequences, no skeleton/holes, no symbolic dependency resolution.

**LogicFuzz**: no crash-constraint memory banning APIs across rounds (crash
handling is per-trial); no RAG retrieval (uses doxygen/README priors); no fully
wired CEGAR loop (Phase C data only); no driver-shape variety (happy-path only,
see `docs/phase_e_adaptive_shape.md`).

---

## 8. Attribute matrix

| Attribute | PromeFuzz | LogicFuzz |
|-----------|-----------|-----------|
| Driver creation | LLM free-form, full | Z3 skeleton + LLM hole-fill |
| Structure decided by | LLM | symbolic (Z3 + automaton) |
| API set by | weighted score | filter + provability + rerank |
| Ordering | optional / LLM | Z3 position-indexed lifecycle |
| Pre-LLM validity | none (relevance) | type + lifecycle + state + automaton |
| Post-LLM validity | sanitizer loop | LangGraph build/fix |
| Cross-round learning | crash → constraint | automaton growth; Phase C |
| Knowledge artifacts | purpose, usage, relevance, RAG | + automaton, idioms, verdicts |
| Repair of bad seqs | LLM fix on crash | Phase A graft before LLM |
| Shape variety | LLM-dependent | fixed happy-path (Phase E pending) |
| Harness merge | synthesizer | merge_drivers |

---

## 9. Source map

| Concern | PromeFuzz | LogicFuzz |
|---------|-----------|-----------|
| Generation entry | `generator.py:Generator.generate` | `prototyper.py` + `data_context.py:_synthesize_skeletons_per_sequence` |
| Selection | `scheduler.py:Scheduler` | `coverage_ranker.py` + `path_planner.py` |
| Constraint validity | (none) | `constraint_based/z3_solver.py`, `z3_guided_synthesis.py` |
| Skeleton/holes | (none) | `synthesis/skeleton_generator.py` |
| Comprehension | `comprehender/comprehender.py` | `knowledge/comprehender.py` |
| Idioms | (none) | `knowledge/idiom_distiller.py` |
| Automaton | (none) | `analysis/project_automaton.py` |
| Crash learning | `generator/learner.py` | `agents/crash_*` (per-trial) |
| Repair | (LLM fix) | `analysis/candidate_repair.py` |
| Harness merge | `generator/synthesizer.py` | `tools/merge_drivers/` |
| Fix loop | `generator/sanitizer.py` | `workflow/nodes/supervisor.py` |

---

*Descriptive only; for the design roadmap and open gaps see
`docs/generation_stage_redesign.md` and `docs/system_design_status.md`.*
