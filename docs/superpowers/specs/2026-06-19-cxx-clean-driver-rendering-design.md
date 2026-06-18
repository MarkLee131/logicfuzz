# C++-Clean Driver Rendering + Validation — Design

Date: 2026-06-19
Status: Design (awaiting review)
Branch: pub-llm

## 1. Problem

A full cjson run with `-l deepseek-v4-flash` produced **0 / 33 compilable drivers**
(`compiles=False`, coverage 0 everywhere) despite healthy DeepSeek API calls and
correct-looking driver bodies. Root-caused by reproducing the exact trial build in
the cjson container.

## 2. Root cause (confirmed)

OSS-Fuzz compiles cjson's fuzz target with **`$CXX` (clang++) + `extern "C"`**, even
though `target_path` is `cjson_read_fuzzer.c` and `benchmark.language == "c"`
(`skeleton_generator.py:1985` already documents "OSS-Fuzz ALWAYS uses clang++ ... even
.c files"). The generated drivers are **not C++-compilation-clean**, so they fail under
`$CXX` while passing under `$CC`:

- **Unbalanced `extern "C"`** — the driver emits the guarded open
  (`#ifdef __cplusplus` / `extern "C" {` / `#endif`) but the closing guarded block is
  **missing**. The skeleton renderer is *balanced* (`skeleton_generator.py:1987-1989`
  open, `:2026-2030` close); the **LLM (DeepSeek) drops the close** when it
  generates/rewrites the body (measured: 11 / 33 cjson drivers). Invisible under `$CC`
  (`#ifdef` false), fatal under `$CXX` (`expected '}'`).
- **`const`-stripped pointer args** — the renderer strips `const` from pointer types
  (`.replace('const', '')` / `_public_pointer_type`, `skeleton_generator.py:~99/134/151`),
  so `cJSON_ParseWithOpts`'s `const char**` param is rendered as `char**`. A *warning*
  under `$CC`, a hard *error* under `$CXX` (`no matching function`). Affects the other
  ~22 / 33 cjson drivers.

**Why the existing language adaptation doesn't catch it:** `prototyper.py:514-520`
derives `target_language` from the **file extension** (`.c` → `'c'`), not the `$CXX`
toolchain. It correctly adds `extern "C"` for *name-mangling/linkage*
(`needs_extern = is_c_project`, `:525`) but then prompts/validates the driver as plain
**C**, so C++-only correctness (balanced wrapper, const-correctness) is never enforced.
The **first** real `$CXX` compile is the trial build → it fails → the Fixer mis-triages
the C++ errors (logged as `DECLARATION_MISSING`/`HEADER_NOT_FOUND` → wrong `ADD_INCLUDE`
strategy) and exhausts its 2 attempts → 0/33.

## 3. Blast radius

- 14 `language=c` projects in `comparison/`; **~10 have `.c` targets** → detected `'c'`
  but compiled by `$CXX` (the exposed set): c-ares, cjson, curl, ffjpeg, lcms, liblouis,
  libmagic, libucl, mbedtls, ngiflib. (4 C projects with `.cc` targets are already
  detected `c++`.)
- The failure is **largely model-driven**: under GPT these compiled fine (c-ares 39/43,
  lcms 117/123 ≈ 91-95%); under DeepSeek cjson = 0/33. DeepSeek's output is not
  C++-clean, in **multiple forms** (11/33 unbalanced `extern "C"`; 22/33 balanced but
  const/other C++ errors) — so a targeted 2-issue fix won't cover the tail.
- Conclusion: with DeepSeek, ~10 C projects are at risk of ~0 compiles. A general,
  in-pipeline fix is warranted; per-project `$CC` build edits are whack-a-mole, diverge
  the fork, and don't fix the merge/coverage builds (also `$CXX`).

## 4. Goals / Non-goals

**Goals**
- Generated drivers compile under `$CXX` (the OSS-Fuzz reality) for the ~10 exposed C
  projects, regardless of LLM (robust to DeepSeek's variable output quality).
- Fix at the generation + validation layers (no per-project fork build edits).
- Keep `$CC`-correctness intact (drivers still valid C).

**Non-goals**
- Do NOT force `$CC` per project in the fork (rejected: per-project, fork divergence,
  doesn't fix merge/coverage).
- Do NOT change `target_language` detection semantics globally (would alter prompts /
  FuzzedDataProvider behavior for all C projects — out of scope; the always-`$CXX`
  invariant makes "always C++-clean" the simpler contract).
- No change to the merge `compile_validate` gate's contract (C3 reuses it, see §5.3).

## 5. Design — three components

### 5.1 C1 — const-correct argument rendering (renderer)
**File:** `liberator_adapter/driver/synthesis/skeleton_generator.py`
The call-arg `SkeletonVariable.c_type` for a pointer parameter must carry the API
parameter's **const qualifier** (e.g. `const char **`), instead of being stripped to
`char **`. `get_declaration` (`:471`) already emits `self.c_type` verbatim, so the fix
is at the point where an arg Variable's `c_type` is derived from the API param type:
preserve `const` for the **call-argument declaration + binding** path. The existing
opaque-handle → `void *` mapping (`_public_pointer_type`, `:151`) is unchanged; const
preservation applies to non-opaque pointer params (`const char**`, `const T*`). General
— fixes const-mismatch for all APIs, not just `cJSON_ParseWithOpts`.

### 5.2 C2 — `extern "C"` balance repair (post-generation safety net)
**File:** `src/agents/prototyper.py` (post-process chain near `_ensure_project_headers`,
`~:997`). New pure helper `balance_extern_c(code: str) -> str`: if the code contains a
guarded `extern "C" {` (under `#ifdef __cplusplus`) with **no matching guarded close**,
append `#ifdef __cplusplus\n}\n#endif` after the final top-level `}`. Idempotent
(no-op when already balanced or no `extern "C"` present). Defensive — robust to **any**
LLM dropping the close (DeepSeek today), independent of A/B-design. Runs on the final
driver before it is written/validated.

### 5.3 C3 — `$CXX`-cleanliness validation gate + correct fixer routing
Since OSS-Fuzz **always** uses `$CXX`, validate generated drivers against `$CXX` *before*
the trial wastes its fix budget, and feed the real C++ errors to the Fixer.
- **Gate:** reuse the existing per-TU `$CXX -fsyntax-only` machinery in
  `tools/merge_drivers/compile_validate.py:validate_compilable` (already compiles with
  the project's `$CXX` + `extern "C"` + `-iquote` include flags for the merge). Extend it
  to validate the **per-trial generated driver** (pre-trial or as a validation step), so
  C++ errors surface with real compiler messages early.
- **Triage routing:** `src/utils/compilation_error_triage.py` already has the C++
  patterns (`no_matching_function` → `TYPE_ERROR` `:197`; `cpp_extern_c` `:225`;
  `LANGUAGE_MISMATCH` `:329/342`). Ensure these route to fix strategies that actually
  address const-mismatch / unbalanced-`extern "C"` (NOT `ADD_INCLUDE`), and that the
  Fixer receives the genuine `$CXX` errors (the cjson run mis-triaged to
  `DECLARATION_MISSING`/`HEADER_NOT_FOUND`). C1+C2 pre-empt the two known modes; C3 is the
  net for the long tail of DeepSeek C++-uncleanliness.

## 6. Architecture / data flow

```
skeleton render (C1: const-correct, already extern"C"-balanced)
  → LLM hole-fill / generate (DeepSeek may drop close / restripped const)
  → C2: balance_extern_c() post-repair
  → C3: $CXX -fsyntax-only validation gate
        ├─ clean → proceed to trial build
        └─ C++ errors → triage (correct categories) → Fixer (real messages)
  → trial build ($CXX) → compiles
```
Each layer is independently testable. C1 reduces what the LLM can break; C2 repairs the
one structural thing LLMs drop; C3 catches everything else before the trial.

## 7. Error handling
- C2 is idempotent and fail-safe (only appends a close when an unmatched open exists).
- C3 gate fails **open** on infra error (mirrors `compile_validate` fail-open), so a
  Docker/toolchain hiccup never silently drops a driver; it logs and proceeds.
- A driver that still fails `$CXX` after the Fixer is dropped as today (compiles=False),
  but now with correct C++ triage rather than wasted `ADD_INCLUDE` attempts.

## 8. Testing
- **C1 unit:** an API with a `const char**` param renders its arg decl as `const char**`
  (not `char**`); call binding type-checks. A non-const pointer param is unchanged.
- **C2 unit:** `balance_extern_c` turns an unbalanced driver (guarded open, no close) into
  a balanced one; is a no-op on already-balanced and on no-`extern "C"` inputs.
- **C3 unit:** triage maps `no matching function` / `extern "C"` errors to the C++
  categories (not `DECLARATION_MISSING`/`HEADER_NOT_FOUND`).
- **Integration (the repro):** the previously-failing cjson driver compiles under the real
  `$CXX` build (rc=0) after C1+C2.
- **Regression:** a fresh cjson run with `-l deepseek-v4-flash` yields **compiled > 0**
  (target: most of N), and a GPT run on c-ares/lcms stays ≥ its prior compile rate
  (no regression for the already-working path).

## 9. Risks
- **C1 const on output params:** an out-pointer rendered `const char**` must still be
  passable (you pass `&local`); verify the binding compiles under `$CXX` for out-params.
- **C3 cost:** one `$CXX -fsyntax-only` per generated driver (cheap, syntax-only); gate
  fails open so it never blocks on infra.
- **DeepSeek tail:** C1+C2 may not cover every C++-uncleanliness mode DeepSeek emits; C3 +
  the Fixer are the net, but some drivers may still be dropped (acceptable — better than
  0/33, and observable via the validation log).

## 10. Out of scope (follow-ups)
- Threading the Comprehender model to `-l` (separate, already identified).
- `target_language` detection reflecting `$CXX` (broader reframe; this spec achieves
  C++-cleanliness without it).
