# Idiom-Aware Recall + Repair (A-first) — Design

Date: 2026-06-19
Status: Design (awaiting review)
Branch: pub-llm

## 1. Problem

Our symbolic-first pipeline **generates** drivers for idiom-gated API families but ships
them **dead**. Measured on zlib: it built **7 of 22** drivers using the `gz*` file-I/O
family, but **0** survived into the merged harness — so zlib reached **916 library
branches** vs PromeFuzz's **~1400** (the gap *is* the `gz*` surface, ~480 branches).
The same idiom-gated pattern (file-I/O, caller-allocated structs) recurs on
libpng/lcms/c-ares.

Goal of this spec: the **fastest** coverage lever — recall the already-built degenerate
idiom-gated skeletons and repair them into live drivers, reusing existing machinery,
designed so the later "routed neural-author" (B) and "coverage-guided loop" (C) phases
generalize it rather than replace it.

## 2. Root cause (verified in code)

A generated `gz*` driver (`results/output-zlib-project/fuzz_targets/07.fuzz_target`):
```c
char * arg0_gzopen  = NULL;     // path  → NULL
arg1_gzdopen = __lf_str_buf;    // mode  → raw fuzz bytes (not "rb"/"wb")
ret_gzdopen = gzdopen(0, <fuzz>);   // fd=0, garbage mode → returns NULL
if (ret_gzdopen == NULL) return 0;  // exits immediately → 0 coverage
```
Two degeneracies, both already *detectable* by oracles we own:
- **Resource arg unbound** — `gzopen(const char* path)`'s `path` has no symbolic producer
  (it's a filename, not a handle), so it renders NULL. `validity_contract.check_sequence`
  flags this as **I2b** (NULL required non-handle) / **I2a** (orphan handle for the
  returned `gzFile`).
- **Value-domain miss** — `mode` is a string constant (`"rb"`/`"wb"`); `hole_semantics`
  has no intent for it, so it gets raw fuzz bytes.

The merge's **dead-driver filter** then correctly drops them (0 coverage). That filter is
load-bearing (removing it caused prior crash-poison/merge-corruption regressions) — so we
**recall around it** (make the driver live before it reaches the filter), never weaken it.

The missing capability is narrow: the renderer/LLM is never told the **file-I/O idiom**
("write the fuzz bytes to `./dummy_file`, pass that path") nor the **mode value-domain**.

## 3. Goals / Non-goals

**Goals**
- Convert degenerate idiom-gated skeletons (file-I/O, resource-from-path) into **live**
  drivers, lifting branch coverage on the idiom-gated surface (zlib `gz*` first).
- Reuse existing layers: `validity_contract` (oracle), `hole_semantics` value-intents
  (directive channel), the Prototyper (generator), `compile_validate` + dead-filter.
- Be the clean foundation B (routed neural-author) later generalizes.

**Non-goals**
- Do NOT weaken/remove the dead-driver filter (load-bearing).
- Do NOT switch to global neural free-write (A-design `LLM_REWRITE` — measured inert/worse).
- No coverage-feedback loop here (that is Phase C).
- No new standalone LLM call-site — repair flows through the existing Prototyper.

## 4. Design — small pieces on existing hooks

> **AS-BUILT NOTE (2026-06-19):** R0 and R1 were implemented **together inside the
> existing value-intent layer** — the value-intent channel *is* the recall router, so the
> separate `skeleton_recall.py` module, `validity_contract` I2a/I2b reconstruction, and the
> Step 10c hook described in the original design were **not built** (same behavior, far less
> glue). The as-built description below replaces them. `validity_contract` corroboration
> remains a deferred option if false-positives ever appear.

### 4.1 R0 — File-opener value-intent (`hole_semantics.py`)
New deterministic helper `file_opener_intents(sem) -> Dict[int, str]` (name-free,
library-agnostic — keys on **role + type only**, never on `gz`/zlib names):
- A `sem` whose `role is APIRole.CREATOR` (produces a fresh handle/resource) and that has a
  single-pointer `char*` arg is treated as a resource opener. The **first eligible** `char*`
  (eligible = role not in `{LENGTH, OUTPUT, INPUT_BUFFER}`) is the PATH → **`FILE_FROM_FUZZ`**
  directive: *"this is a filesystem PATH — write the fuzzer bytes to a UNIQUE temp file
  (`./lf_tmp_<pid>_<n>`) and pass THAT path; do NOT pass NULL or raw bytes."*
- A **second** eligible `char*` is the mode → a `FUZZ_DERIVE` over the legal mode set
  (`"rb"`,`"wb"`,…).
- **`INPUT_BUFFER` is excluded** (final-review fix): a memory-parser CREATOR's primary fuzz
  buffer is a `char*`+size pair classed `INPUT_BUFFER` — it must keep receiving the raw fuzz
  bytes, NOT be re-routed to a file. A genuine path is a lone `char*` (no size), classed
  CONFIG/UNKNOWN. Regression test: `test_parser_input_buffer_not_routed_to_file`.

### 4.2 R1 — Recall routing = emit the intent in `value_intents_for_sequence`
There is **no separate router module**. `value_intents_for_sequence` (`hole_semantics.py`,
Step 10b via `annotate_skeletons`) computes `file_opener_intents(sem)` **once per API**
(gated by `LOGICFUZZ_DISABLE_RECALL`) and, inside its per-arg loop, lets the file directive
**override** the default `_arg_intent` result for the path/mode args. The directive then
flows to the Prototyper through the *already-wired* `value_intents` → CALLSPEC path. This is
the "召回 not 替换": the symbolic skeleton + sequence are kept; we only add the missing
idiom directive so the generator can realize it. Every opener CREATOR receives it (broader
than a degeneracy-only trigger, but benign for genuine openers and gated for A/B).

### 4.3 R2 — Generation + repair loop (reuse Prototyper + Fixer + compile_validate)
The Prototyper already consumes `value_intents`; with the `FILE_FROM_FUZZ`/value-domain
directives present it writes the `tmpfile→gzopen` idiom and correct mode constant. The
existing **Fixer loop** (compile-error triage ×3) + **`compile_validate`** ($CXX) +
dead-filter are the validate/repair loop (our analog of PromeFuzz's 35 — generation + fix
rounds). No new LLM site.

### 4.4 Fallback (gated, optional)
If an IDIOM-DEGENERATE skeleton still renders dead after generation+fix, allow the
Prototyper's **A-design free-write** (existing `LLM_REWRITE` path) for *that skeleton only*,
seeded with the mined order-set + idiom — the narrow, justified use of free-write (not
global). Gated `LOGICFUZZ_RECALL_FREEWRITE=1`, default off for A.

## 5. Reuse map (what's new vs existing)

| Piece | Status (as built) |
|---|---|
| Opener detection | **new** `file_opener_intents(sem)` in `hole_semantics.py` (role+type; excludes INPUT_BUFFER/LENGTH/OUTPUT) |
| Directive channel to LLM | **reuse** `hole_semantics` value-intents → CALLSPEC → prompt |
| File-I/O + mode intent | **new** `FILE_FROM_FUZZ` + mode `FUZZ_DERIVE` in `file_opener_intents` |
| Recall routing | **reuse** — emitted inside `value_intents_for_sequence` (gated); no separate module |
| Ablation counter | **new** `count_file_idiom_skeletons` + `recall_ablation.json` dump (Step 10b) |
| Generation / repair loop | **reuse** Prototyper + Fixer + `compile_validate` + dead-filter |
| Pipeline hook | **reuse** existing Step 10b `annotate_skeletons` — no new step |
| `validity_contract` I2a/I2b routing | **deferred** (not built; corroboration option if FPs appear) |

## 6. Data flow (as built)
```
Step 10  skeletons
   → 10b annotate_skeletons → value_intents_for_sequence:
            file_opener_intents(sem) [gated LOGICFUZZ_DISABLE_RECALL] overrides path/mode args
            with FILE_FROM_FUZZ + mode domain;  dump recall_ablation.json
   → trial: Prototyper(reads value_intents) writes tmpfile→gzopen idiom + mode const
   → compile_validate ($CXX) + Fixer(×3)  → build/run
   → merge + dead-filter (UNCHANGED) → live gz* drivers survive
```

## 7. Error handling / safety
- Fail-open: any error in R0/R1 → the skeleton passes through unmodified (no regression).
- Dead-filter, symbolic construction, automaton: untouched.
- Gate `LOGICFUZZ_DISABLE_RECALL=1` (default-on, A/B switch) — so the ablation can isolate
  the lift.

## 8. Evidence / ablation (serves the paper)
Measure on **zlib + libpng + c-ares** (not just zlib — guard against over-fit), arms via
the gate:
- **off** (`DISABLE_RECALL=1`) vs **on** — report Δ **library branch coverage** (llvm-cov,
  library-only), # live idiom-gated drivers (gz* 0 → N), FP-crash rate (must stay ~0),
  compile/dead rate.
- Expected: zlib branch coverage rises toward the `gz*` surface (~916 → toward ~1400),
  FP unchanged (oracle + dead-filter intact). Written to `results/<proj>/recall_ablation.json`.

## 9. Testing
- Unit: `_arg_intent` emits `FILE_FROM_FUZZ` for a `const char* path` CREATOR arg; a
  mode arg gets the `"rb"/"wb"` value-domain; a normal buffer arg is unchanged.
- Unit: `skeleton_recall` classifies a NULL-path gzopen skeleton as IDIOM-DEGENERATE and
  attaches the directive; a valid deflate skeleton as LIVE (untouched).
- Integration (the proof): a zlib run with recall **on** ships ≥1 live `gz*` driver
  (non-zero coverage) that survives the merge; **off** ships 0. FP stays 0.

## 10. Risks
- **Over-fit to zlib `gz*`** — mitigated by measuring on libpng/c-ares + keeping R0 generic
  (any file-path/resource-from-path arg, not gz-specific names only).
- **`./dummy_file` collisions** under parallel fuzzing — use a per-process unique temp path
  (the idiom directive must specify a unique name, not a literal shared `./dummy_file`).
- **False "degenerate" flags** dragging valid skeletons into repair — gated on
  `validity_contract` I2a/I2b only (already conservative); fail-open.

## 11. Forward-compat (B/C — NOT committed, data-gated)
This spec covers **A only**. B ("routed neural-author + symbolic oracle") and C
("coverage-guided closed loop") are **not committed scope** — they are decided *after*
A's ablation: **B** only if a measurable breadth gap remains once the idiom-gated surface
is recovered; **C** only if the coverage ceiling / paper novelty warrants the build.
A is designed so neither is precluded: R0 (idiom value-intents) + R1 (degeneracy router)
are exactly the substrate B's capability-router would reuse (B would add a neural-author
branch for the *unrepairable-here* class), and the `recall_ablation.json` harness is the
same one B/C would extend. Deferring them costs nothing — nothing here is thrown away.
