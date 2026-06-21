# PromeFuzz Potential-Projects Sweep — Blocker Report (2026-06-21)

**Goal:** generate drivers with our tool for the CLAUDE.md "potential" projects
(libpng, sqlite3, curl, libjpeg-turbo, tinygltf) and long-fuzz them to compare
branch coverage vs PromeFuzz Table 2.

**Method:** `LOGICFUZZ_NO_CACHE=1 run_logicfuzz.py -y comparison/<p>.yaml --eval -l deepseek-v4-pro` per project, then `scripts/run_extended_fuzzing.py` on the merged harness.

**Outcome:** the sweep did NOT produce a valid PromeFuzz comparison. Generation
was **degenerate across every project tested this session**, each blocked by a
*distinct* root cause. The headline long-fuzz never got a non-dead harness.

## Per-project results

| Project | PF Table 2 (bc) | Generation result | Root cause |
|---------|-----------------|-------------------|------------|
| **libpng** | 1849 | compiles (build✓ 13→281 after fix) but **7 merged, 0% coverage** | drivers are NULL opaque-handle getters (`png_get_*(NULL,…)`) — shallow/dead; merge drops the rest |
| **cjson** (winnable) | 924 | **0/26 compile** | driver `#include "../cJSON.h"` (stock-fuzzer style) not resolved at trial build → `HEADER_NOT_FOUND` |
| **sqlite3** | 13041 | 0 skeletons | `libsqlite3.a` found, but **SVF extractor crashes** (`Doing: rtreeFreeCallback`) → clang-only → 0 conditions. Also public_headers grabbed `ext/*` not the build-generated `sqlite3.h` |
| **libjpeg-turbo** | 4975 | 0 skeletons | source-dir versioned (FIXED) + cmake `FUZZ_LIBRARY` (FIXED, stub-engine) + **lib `libjpeg.a`/`libturbojpeg.a` in versioned build dir not found** (open) |
| **tinygltf** | 1925 | 0 skeletons | **header-only C++** — no static `.a` exists; SVF has nothing to analyze |
| zlib, c-ares | (winnable) | aborted mid-gen | not completed (sweep stopped) |

## Fixes that DID land this session (committed, tested)

1. **Source-dir detection for versioned `/src` layouts** (`6e4dd3a3`) — `_pick_source_dir` lists directories only + rank-matches; fixes libjpeg-turbo picking `/src/afl_llvm22_patch.diff`. 5 unit tests; validated libjpeg-turbo→`libjpeg-turbo.main`, libaom→`aom`.
2. **Stub-engine retry** (`66a34383`→`db2faf7c`, spec/plan in `docs/superpowers/`) — when blanked `LIB_FUZZING_ENGINE` makes cmake configure abort (`FUZZ_LIBRARY must be specified`), retry the build with a stub `ar` archive. Fail-open + never-zero + `LOGICFUZZ_STUB_ENGINE_RETRY=0`. **Validated firing** on libjpeg-turbo (but insufficient alone — see lib-discovery gap).
3. **Private/contrib header filter** (`fff068e2`) — `_generate_public_headers_file` now excludes `contrib`/`samples`/`third_party`/… dirs and drops headers that self-declare private via `#error … must not be included by applications`. Fail-open + never-zero + `LOGICFUZZ_HEADER_FILTER=0`. **Validated:** libpng `public_headers.txt` 11→2 (`png.h`,`pngconf.h`); 0 false positives across 14 project sources. This is what raised libpng build success 13→281.

## The systemic finding

The build/extraction layer does **not generalize cleanly** to new OSS-Fuzz
projects — each needs bespoke handling (header-only, generated headers, SVF
crashes, nonstandard lib names, relative-include trial builds). More
fundamentally, the two strongest suspects for the *broad* degeneration:

1. **Model.** Every prior *good* result (cjson 78 APIs, libpng 76 merged) was
   produced with **GPT** models. This entire sweep used **deepseek-v4-pro**
   (the requested model). deepseek drivers were either non-compiling (cjson
   `../cJSON.h`) or shallow (libpng dead getters). This was **not isolated** —
   the decisive test (regenerate cjson with a GPT model) was not run.
2. **Driver quality / object construction.** Even where drivers compile
   (libpng), the merged harness is coverage-dead: drivers call getters on NULL
   opaque handles instead of building objects and feeding `data` into a real
   parse entry. This is the known object-construction-vs-parser-entry gap, not a
   build bug.

## Recommended next steps (not done — sweep stopped per direction)

1. **Isolate model vs pipeline:** regenerate cjson with `gpt-5.2`/`gpt-4o`. If it
   compiles+covers → deepseek driver-quality is the dominant issue. (~15 min, decisive.)
2. **Trial-build relative includes:** ensure the per-trial/preflight compile adds
   `-iquote dirname(target_path)` so stock-style relative includes (`../cJSON.h`)
   resolve (the documented merge-include fix, applied at trial stage).
3. **libjpeg-turbo lib-discovery** (task #17): broaden Strategy-2 to search
   `_bc_source_dir`/`/out`/`/work`/build subdirs for any `*.a` + add
   `libjpeg*`/`libturbojpeg*` patterns.
4. **sqlite3 SVF crash:** triage the extractor crash on `rtreeFreeCallback`
   (SVF robustness / mem-time caps); separately, detect the build-generated
   `sqlite3.h` instead of `ext/*`.
5. **libpng driver depth:** the header fix is necessary but not sufficient — the
   merged drivers must build real objects + feed `data` into PNG decode, not call
   getters on NULL handles.
6. **tinygltf:** out of scope for the symbolic core (header-only) — would need the
   fork `build.sh` fallback to synthesize a TU.
