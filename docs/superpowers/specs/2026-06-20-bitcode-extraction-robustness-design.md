# Bitcode-Extraction Robustness (stub-engine retry + fork fallback)

Date: 2026-06-20
Status: Design approved, pending spec review
Owner: kaixuan

## 1. Problem

Our symbolic core (SVF on LLVM-14 bitcode) only engages when the in-container
`compile_to_bitcode` step produces a findable static library `.a`. When it
can't, `hybrid_extractor.extract()` silently degrades to **clang-only** mode →
no `conditions.json` → `_synthesize_skeletons_per_sequence: No APIs have
conditions` → **0 skeletons** → the project yields no real driver portfolio.

Observed in the 2026-06-20 PromeFuzz sweep (deepseek-v4-pro, `--eval`):

- **libjpeg-turbo**: the bitcode `compile` aborts at cmake
  `FATAL_ERROR: FUZZ_LIBRARY must be specified`. Root cause is **ours**, not the
  OSS-Fuzz image: `llvm_extractor.compile_to_bitcode` exports
  `LIB_FUZZING_ENGINE=""` (to keep bitcode free of fuzzer/sanitizer
  instrumentation); the project's `fuzz/build.sh` passes that empty value to
  `cmake … -DFUZZ_LIBRARY=$LIB_FUZZING_ENGINE`, and its `fuzz/CMakeLists.txt`
  has `if(NOT FUZZ_LIBRARY) message(FATAL_ERROR …)`. Empty engine → configure
  aborts → no `.a` built. The **library itself** does not need the engine —
  only the fuzzer-link step does, and that runs *after* the library is built.
- **tinygltf**: header-only C++ → there is no `.a` at all (out of scope here;
  see §7).

We stay on **LLVM-14** deliberately (it predates opaque pointers; our type
recovery in `TypeMatcher`/`AccessTypeHandler` depends on typed pointers). This
work makes the **build** robust, not the LLVM version.

### Failure taxonomy (where SVF gets nothing)

| Class | Trigger | Example | In scope |
|------|---------|---------|----------|
| A1 | No static lib at all (header-only) | tinygltf | No (fork fallback, §7) |
| A2 | Build configure aborts from our env override (blanked `LIB_FUZZING_ENGINE`) | libjpeg-turbo | **Yes** |
| A3 | clang-14 can't compile the code | (latent) | No |
| A4 | lib built but not found (name/location) | (partly hit) | **Yes** (already improved) |
| C | SVF timeout / OOM | libtiff/libvpx | **Yes** (existing caps) |

## 2. Goals / Non-goals

**Goals**
- When a static lib *can* be built, make sure it **is** built and **found**, so
  SVF runs (A2 recovery + A4 robustness).
- Regression-safe: never degrade a project that works today.
- Fail-open: any error in the new path falls back to the current clang-only
  behavior; never a hard crash.
- Observable: record per-project whether recovery fired.

**Non-goals**
- Header-only support (A1) and clang-14 compile-compatibility (A3) — explicitly
  deferred. A1 is handled, if/when needed, by the fork fallback (§7).
- Any change to the LLVM/SVF version (decided: stay on LLVM-14).

## 3. Approach (decided: Approach 1 — stub-engine retry, tool-side default)

The library builds *before* the fuzzer link; only the fuzzer link needs a real
engine. So: on the first bitcode-build failure, retry the project's own build
with a **stub** fuzzing-engine archive so `cmake` configures and `make` builds
the library; the later fuzzer link fails harmlessly (the `.a` already exists,
and the extractor already tolerates a non-zero `compile` exit:
`"Compile script returned error, but library may still exist"`).

Rejected alternatives:
- **Always provide the stub** (first attempt for every project): single build,
  but changes the env for currently-working projects → regression risk.
- **Library-target-only build**: most "correct" but needs per-project build
  logic → brittle, not general.

## 4. Detailed design

All changes in `liberator_adapter/extractors/llvm_extractor.py:compile_to_bitcode()`
plus one telemetry field in `base_extractor.py`.

### 4.1 Control flow

Refactor the existing "run `compile` → find `.a`" block into a retriable helper:

```
_run_compile_and_find_lib(engine_path: str) -> tuple[Optional[str], str]
    # exports LIB_FUZZING_ENGINE=engine_path (rest of env unchanged:
    # SANITIZER=none, FUZZING_ENGINE=none), runs `compile`, then runs the
    # existing Strategy 1 + 2 lib search (unchanged). Returns
    # (lib_path_or_None, compile_stdout); the stdout feeds the retry decision.
```

**Note on scope:** the only *new* recovery mechanism is **A2** (stub-engine
retry) plus the telemetry field. **A4** (lib name/location discovery) is already
handled by the existing Strategy 1+2 search and this session's `_pick_source_dir`
fix, and **C** (SVF timeout/OOM) by the existing `LIBERATOR_SVF_TIMEOUT_SECS`/
`LIBERATOR_SVF_MEM_GB` caps — this spec adds no new code for A4/C; it only keeps
them working (covered by the regression tests in §7).

New `compile_to_bitcode` flow:

1. `lib, out = _run_compile_and_find_lib("")`  — current behavior.
2. If `lib is None` **and** `STUB_ENGINE_RETRY` enabled **and**
   `_should_retry_with_stub_engine(out)` → build a stub archive, then
   `lib, _ = _run_compile_and_find_lib(stub_path)`.
3. If `lib` → `extract-bc` as today (record recovery telemetry if the stub path
   produced it). If still `None` → `raise` → existing clang-only degradation
   (unchanged).

### 4.2 Stub archive

Built in-container with clang-14 so it's a valid, non-empty static archive:

```
echo 'static int _lf_stub;' > /tmp/_lf_stub.c \
  && /usr/lib/llvm-14/bin/clang-14 -c /tmp/_lf_stub.c -o /tmp/_lf_stub.o \
  && ar crs /tmp/logicfuzz_stub_engine.a /tmp/_lf_stub.o
```

`-DFUZZ_LIBRARY=/tmp/logicfuzz_stub_engine.a` satisfies `if(NOT FUZZ_LIBRARY)`
(non-empty, file exists). `SANITIZER`/`FUZZING_ENGINE` stay unchanged → bitcode
stays clean. The fuzzer link later fails on unresolved `main`/
`LLVMFuzzerTestOneInput` — *after* the library `.a` is on disk.

### 4.3 Retry trigger (pure, unit-testable)

```
_should_retry_with_stub_engine(compile_output: str) -> bool
    # True iff the failed compile output references the fuzzing engine config,
    # i.e. matches /FUZZ_LIBRARY|LIB_FUZZING_ENGINE|FUZZING_ENGINE/i.
    # Skips a wasted rebuild on genuinely lib-less cases (header-only) and on
    # unrelated failures.
```

The caller already gates on `lib is None`; this helper only decides whether a
retry could plausibly help.

### 4.4 Fail-open + kill-switch

- Any exception while building the stub or during the retry compile → caught,
  logged, fall through to the existing clang-only degradation. Never raises out.
- Kill-switch: `LOGICFUZZ_STUB_ENGINE_RETRY=0` disables the retry (default ON,
  opt-out — matches the repo's fail-open convention, e.g.
  `LOGICFUZZ_SKIP_COMPILE_VALIDATE`).

### 4.5 Telemetry

Add a `bitcode_recovery` field to the extraction summary metadata
(`"stub_engine"` when the retry produced the lib, else `None`), surfaced in the
project's `analysis_summary.json` alongside the existing `degraded_reason`. No
change to the `DegradedReason` enum semantics.

## 5. Hybrid strategy: fork build.sh fallback (documented, not implemented now)

For the cases Approach 1 cannot reach (header-only A1; genuinely hostile
builds), the principled escape hatch is the **`MarkLee131/oss-fuzz` fork**,
which `_clone_oss_fuzz_repo()` re-clones fresh on every run and whose
`projects/<project>/build.sh` the pipeline already uses (see
`fuzzer_build_script/c-ares` notes + `oss_fuzz_checkout.py:285`).

Rules for any such edit:
- **Minimal + additive** — add a bitcode-producing step (build the static lib,
  or a synthesized TU for header-only), do not rewrite the build.
- **A≡B guardrail (hard requirement)** — the edit must affect only the
  **analysis/extraction** build, **never** the coverage-measurement build. The
  headline coverage number must come from the *standard* OSS-Fuzz build, else
  the PromeFuzz comparison is invalid. Prefer a separate bitcode path
  (env-gated branch or `build_bitcode.sh`) over mutating the standard
  `build.sh`.
- **Operational note** — the bitcode `compile` runs the **image-baked**
  `build.sh`, so a fork edit takes effect only after the project image is
  rebuilt (`LOGICFUZZ_NO_CACHE` / cache invalidation).
- **Honest accounting** — the paper reports "k of N projects required a minimal
  additive bitcode-build step." This is methodologically comparable to the
  baseline: PromeFuzz also ships per-project build configs
  (`lib.toml`/`build.sh`).

YAGNI: no per-project fork scripts are written until a specific project in the
evaluation set demands one. Approach 1 remains the default so the "ingests
standard OSS-Fuzz projects, no target edits" generalization claim holds for the
common case.

## 6. Files touched

- `liberator_adapter/extractors/llvm_extractor.py` — refactor compile+find into
  `_run_compile_and_find_lib`; add stub-engine retry, `_should_retry_with_stub_engine`,
  stub-archive builder; kill-switch read.
- `liberator_adapter/extractors/base_extractor.py` — add `bitcode_recovery`
  telemetry field to the extraction status/summary.
- `tests/test_extraction_robustness.py` — unit tests (below).

## 7. Testing / verification

**Unit (no docker):**
- `_should_retry_with_stub_engine`: engine-signal → True; no signal → False;
  empty/None → False.
- stub-archive command builder (pure string) produces a sane `clang-14 … && ar crs …`.

**Integration (verify phase, multi-project per the "test across projects" rule):**
- **libjpeg-turbo**: reaches *full* extraction — `conditions.json` present,
  `skeleton_drivers > 0`, `bitcode_recovery == "stub_engine"`.
- **libpng + c-ares (regression)**: still reach full mode, `bitcode_recovery ==
  None` (first attempt succeeds; retry never fires).
- Confirm the stub-engine retry does NOT alter the coverage-measurement build.

## 8. Acceptance criteria

- libjpeg-turbo: 0 → >0 skeletons via stub-engine recovery, on LLVM-14, no fork
  edit.
- No regression on libpng/c-ares (full mode, retry not triggered).
- Fail-open verified (a deliberately unrecoverable project still degrades to
  clang-only without crashing).
- `bitcode_recovery` telemetry visible in `analysis_summary.json`.
