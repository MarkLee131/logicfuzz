# Robust, Observable LLVM-14 Extraction — Design

Date: 2026-06-18
Status: Design (awaiting review)
Owner: pub-llm branch

## 1. Problem

The bitcode-extraction pipeline (`clang-14` + `wllvm` → typed-pointer `.bc` → host
LLVM-14 SVF → `conditions.json` → Z3-guided synthesis) **silently degrades to
clang-only mode (Z3 OFF) on 5 of 10 benchmark projects**, and 3 more are degraded
for adjacent reasons. Degradation is invisible: a broad `except Exception → warning`
falls back to clang-only and nothing in the persisted artifacts records that the
project shipped drivers with **no symbolic lifecycle validation**.

The two-compile split is **load-bearing and stays**: the host SVF analyzer is built
against LLVM 14 and our opaque-handle recovery reads *typed* pointers
(`getPointerElementType`, 17 sites). The base-builder's default compiler is
`clang 22.0.0git`, which no released SVF supports. So we cannot unify toolchains;
we fix the defective **seams** and make degradation **loud**.

### Confirmed root causes (verified in-container, 2026-06-18)

| Class | Projects | Root cause | Stage |
|------|----------|-----------|-------|
| **A** | libpcap | `clang-14` rejects base CFLAG `-Wno-error=vla-cxx-extension`; cmake `CHECK_C_COMPILER_FLAG(-std=gnu99)` reads "unknown option" → configure aborts → no `.a` | P1 build |
| **C** | liblouis | `clang-14` **absent** from the (stale) project image → wllvm "Path to compiler /usr/lib/llvm-14/bin does not exist" | P1 build |
| **B1** | libucl, sqlite3 | bitcode builds fine; host SVF exhausts its wall-time/memory budget | P2 SVF |
| **B2** | nghttp2 (`IndexError`), libucl (`KeyError: operator>`) | SVF runs; the condition parser crashes building the `ConditionManager` | P2 parse |
| **(silent)** | all | failures caught by broad `except` → clang-only, **no persisted signal** | funnel |

### Adjacent degradations (surfaced by blast-radius probe — observability only this spec)

| Project | State | Disposition |
|---------|-------|-------------|
| re2 | `conditions.json` present but **empty** (`[]`, 2 B) — SVF ran, produced 0 conditions | Surface as `conditions_empty`; B-parser-class tolerance covers the crash side |
| curl | external `ossfuzz.sh` meta-build; wllvm bitcode never produced | **Deferred** (follow-up spec); surfaced as `compile_failed`/`extract_bc_failed` |
| pugixml | manual single-`clang` compile (no cmake/configure) | **Deferred** (follow-up spec); surfaced via observability |

## 2. Goals / Non-goals

**Goals**
- Make every degradation **observable and persisted** (the keystone).
- Recover the A/B/C classes so libpcap, liblouis, nghttp2, sqlite3 **and libucl** reach `extraction_mode=full`. libucl reaches full via big-budget flow-sensitive SVF (one-time, cached) or, if it still won't converge, a per-project **lite SVF mode** (drop `-do_indirect_jumps`). (Per user: libucl must use SVF+Z3; a manual one-time run to get there is acceptable.)
- Preserve SVF-cache determinism (a fixed, baked clang-14).
- Gate-off / already-full projects (cjson, zlib, lcms, c-ares, libpng) **byte-identical**.

**Non-goals**
- No toolchain unification / SVF LLVM upgrade (infeasible; separate research track).
- No new `extraction_env` module (YAGNI — fixes live inline in the 3 owning files).
- No curl meta-build / pugixml manual-compile bitcode integration (follow-up spec).
- `LOGICFUZZ_REQUIRE_Z3` is **off by default** — degraded mode stays load-bearing for `--eval`/`--merge`.

## 3. Architecture

Fixes are applied **inline at the file that owns each invariant** — no new module.
The only shared new symbol is a `DegradedReason` enum.

| Concern | Owning file | Why here |
|---------|-------------|----------|
| `DegradedReason` enum | `liberator_adapter/extractors/base_extractor.py` | already the shared extractor base; no circular-import risk |
| Flag strip (A) | `liberator_adapter/extractors/llvm_extractor.py` `compile_to_bitcode` | owns the extraction compile env |
| Reason capture / threading | `liberator_adapter/extractors/hybrid_extractor.py` | owns the fallback funnel |
| Stale-image detect/invalidate (C) | `experiment/oss_fuzz_checkout.py` | owns image prep + cache (`ensure_llvm14_base_builder`, cache invalidation) |
| clang-14 invariant guard (C) | `liberator_adapter/extractors/llvm_extractor.py` `_ensure_clang14_installed` | already the guard site |
| Parser hardening (B2) | `liberator_adapter/constraints/ConditionManager.py` | owns condition→model construction |
| SVF per-project values (B1) | per-project resource table (see §4.4) | values, not mechanism (knobs already exist) |
| Status persistence + `REQUIRE_Z3` | `src/context/data_context.py` | owns `analysis_summary.json` + degraded detection |

## 4. Components

### 4.0 Keystone — universal degradation observability
- Add `class DegradedReason(str, Enum)` in `base_extractor.py` with members:
  `COMPILE_FAILED, EXTRACT_BC_FAILED, SVF_TIMEOUT, SVF_OOM, CONDITIONS_EMPTY,
  CONDITIONS_MISSING, HOST_EXTRACTOR_MISSING, CONDITION_MANAGER_ERROR, NONE`.
- **Capture at throw sites** in `llvm_extractor.py`: the compile path (`COMPILE_FAILED`),
  `extract-bc` failure (`EXTRACT_BC_FAILED`, ~:211-213), host-extractor missing
  (`HOST_EXTRACTOR_MISSING`, ~:275-279), and distinguish SVF `TimeoutExpired`
  (`SVF_TIMEOUT`) vs `std::bad_alloc`/RLIMIT (`SVF_OOM`) — the code already separates
  these (~:350-363); propagate the distinction instead of collapsing.
- **Thread through** `hybrid_extractor.extract`: add `self._degraded_reason = None`
  (~:86); set it in the two `except` blocks (~:92, ~:129). In
  `_clang_only_extraction` metadata (~:349-368) add `extraction_mode='clang_only'`
  + `degraded_reason=<reason>`; in the success metadata (`_merge_apis`, ~:251-269)
  add `extraction_mode='llvm', degraded_reason=None`. `clang_only_mode` bool stays
  for back-compat.
- **Persist** in `data_context.save_intermediate_results`: add `extraction_mode` +
  `degraded_reason` to the `analysis_summary.json` summary dict (the dict written
  ~:4067-4087) and to the per-project result. `conditions.json` present-but-empty
  is detected at the existing `_degraded` site and recorded as `CONDITIONS_EMPTY`
  (distinct from `CONDITIONS_MISSING`).

### 4.1 Fix A — targeted flag strip (libpcap)
In `compile_to_bitcode` `compile_cmd` (`llvm_extractor.py:137-148`), strip
clang-14-incompatible tokens from the inherited `CFLAGS/CXXFLAGS` **before** the
existing exports run `compile`. Seed denylist: `-Wno-error=vla-cxx-extension`
(extensible list of known clang≥15-only tokens). Implementation: inject
`export CFLAGS="$(echo "${CFLAGS:-}" | sed -E 's/<tokens>//g')"` (and `CXXFLAGS`)
into the compound command. **Record** which tokens were present-and-stripped into the
status (`flags_stripped`). Rationale (per critique): a *blanket*
`-Wno-unknown-warning-option` would silently mask a genuinely-needed unsupported
flag and poison the `.bc`; a targeted strip lets a real unsupported flag still fail
loudly, and the recorded `flags_stripped` keeps it observable.

### 4.2 Fix C — image-side stale-image recovery (liblouis)
Root cause: liblouis's **project/cache image was built before** the clang-14
base augmentation, so it lacks `/usr/lib/llvm-14`. Runtime `apt install` is rejected
(non-reproducible, network-dependent, non-persistent, breaks the SVF cache
fingerprint). Instead:
- In `oss_fuzz_checkout.ensure_llvm14_base_builder` (and/or project-image prep),
  probe whether the **project/cache** image (not just `BASE_BUILDER`, ~:99) carries
  clang-14; if not, **invalidate that project's cache image** (reuse the existing
  stale-cache invalidation path, `_invalidate_stale_cache_dockerfiles`) so it
  rebuilds FROM the augmented base.
- `_ensure_clang14_installed` (`llvm_extractor.py:226-238`) **keeps raising** as the
  fail-closed invariant, but with an **actionable** message (which image tag, the
  exact rebuild command). The raise is captured as a fatal setup error, not a silent
  per-project degrade.

### 4.3 Fix B2 — condition-parser hardening (nghttp2, libucl) + root cause
`ConditionManager` indexes SVF-derived per-arg condition lists by the *clang*-derived
argument count; when those diverge it crashes. Two parts:
- **Safety guards (verified sites):**
  - `:247-248` `init_init`: `if arg_pos >= len(api_cond.argument_at): continue`
    before `cond = api_cond.argument_at[arg_pos]`.
  - `:255-257` setby-dependency: `if p_idx >= len(api_call.arg_types): continue`
    before `d_type = api_call.arg_types[p_idx]`.
  - `:87-89` `init_sinks`: also require `len(fun_cond.argument_at) >= 1` before
    `fun_cond.argument_at[0]`.
  - Operator-overload names (libucl `operator>`): guard the dict lookup that raises
    `KeyError` on C++ operator names (locate during implementation; treat unknown
    name as unclassified, not fatal).
  Guards **skip only args/dependencies for which SVF supplied no record** — no valid
  classification is lost; the parser's own fixup (`utils.py:526-528`, sets
  `params_at=[]` on count mismatch) already establishes this contract.
- **Root cause (separate work item, with fixtures):** determine *why* the clang vs
  SVF param counts diverge (variadic / callback / operator signatures) and align the
  counts in the parser where correct. Minimal `conditions.json` fixtures for nghttp2
  (IndexError), libucl (operator KeyError), re2 (empty). A guard alone does **not**
  close the ticket — guarded-but-degraded still reports via the keystone.

### 4.4 Fix B1 — per-project SVF resources + lite mode so libucl/sqlite3 reach full
Two existing knobs (`LIBERATOR_SVF_TIMEOUT_SECS` :29, `LIBERATOR_SVF_MEM_GB` :42) plus
**one new per-project knob** for a cheaper analysis. A per-project resource table
(project → `{timeout_secs, mem_gb, lite}`) in `llvm_extractor.py`, env-overridable.

- **sqlite3**: time-bound (large amalgamated TU) → raise `timeout_secs` (start 14400/4h,
  matching libtiff/libvpx precedent). No lite needed.
- **libucl**: flow-sensitive SVF with `-do_indirect_jumps` does not converge in a
  reasonable budget (the in-code comment + the 6h/140 GB characterization). Path to full:
  1. **Big-budget flow-sensitive first** — `timeout_secs` high, `mem_gb` generous (host
     has 188 GB). If it converges, libucl is full with **no code change** (cached forever).
  2. **Lite mode (primary code lever)** — if (1) still won't converge, mark libucl `lite`:
     **omit `-do_indirect_jumps`** from the host SVF command (`llvm_extractor.py`
     extract_apis_llvm_on_host, the cmd at ~:328-338; the flag is currently hardcoded but
     the binary **defaults it false** = a tested path). This prunes the per-function
     dominator/access-type fan-out across all type-compatible indirect targets — the
     realistic non-convergence cause for a callback-heavy lib — while still building the
     callgraph and emitting a valid `conditions.json`. Per-project knob:
     `_SVF_LITE_PROJECTS = os.environ.get('LIBERATOR_SVF_LITE','libucl').split(',')`;
     build the cmd without the flag and append it only when **not** lite. Gate-off
     (any non-lite project) is **byte-identical**.

  **Soundness:** every condition field our pipeline consumes (`access_type_set`
  CREATE/DELETE/write at root, `set_by`, `is_array`, `return_at`, per-arg source/sink/init)
  is an **existential mod/ref/reachability** query, not a flow-/path-sensitive one, so
  Andersen-grade points-to (and dropping indirect-jumps) still yields *usable* conditions —
  strictly better than clang-only (where all SVF evidence is absent). **Genuine correctness
  risk:** a creator/destroyer reached *only* via a dispatched callback inside an API body
  becomes invisible without `-do_indirect_jumps` → could be misclassified read-only. So the
  plan includes a **verification step**: after libucl lite extraction, assert its
  `conditions.json` yields non-trivial source/sink classification; if impoverished, re-add
  `-do_indirect_jumps` with the big budget instead.

  **Deferred (NOT this spec):** swapping flow-sensitive → Andersen (`extractor.cpp:503`
  `createSGWPA`). Andersen is the bigger convergence lever but downstream
  `buildFullSVFG` (:540) + `ProvenanceTracker` (:545) require the flow-sensitive SVFG, so it
  would break/degrade provenance unless those are adapted — a separate C++ task, last resort.

### 4.5 `LOGICFUZZ_REQUIRE_Z3` — opt-in strict mode (default OFF)
Read once in `data_context.prepare`. When set, raise at **all** degradation sites —
`build_condition_manager` except (~:526-530), the `_degraded` compute (~:3400-3413),
and the deeper guard (~:3684) — and **before** any LLM/portfolio spend. Default off:
existing `--eval`/`--merge`/`--ext` flows keep tolerating degraded mode; the keystone
signal + an eval-aggregator flag handle visibility without aborting.

## 5. Data flow

```
provision clang-14 (image-side; fatal+actionable if absent)
  → strip clang-14-incompatible CFLAGS (record flags_stripped)
  → wllvm build → extract-bc            [COMPILE_FAILED | EXTRACT_BC_FAILED]
  → host SVF (per-project timeout/mem)  [SVF_TIMEOUT | SVF_OOM | HOST_EXTRACTOR_MISSING]
  → conditions.json                     [CONDITIONS_MISSING | CONDITIONS_EMPTY]
  → ConditionManager (guarded parse)    [CONDITION_MANAGER_ERROR]
  → record extraction_mode + degraded_reason  → analysis_summary.json + per-project result
```
Every boundary records status; nothing degrades without a persisted enum reason;
`REQUIRE_Z3` promotes any degrade → early hard-fail.

## 6. Error handling
- `hybrid_extractor`'s two `except` blocks map the exception to a `DegradedReason` via the
  pure `classify_degraded_reason(msg)` helper (most-specific match first; the over-broad
  `"compile" in msg` heuristic is NOT used); `_clang_only_extraction` writes it; empty
  conditions are surfaced as `CONDITIONS_EMPTY` at summary assembly
  (`refine_status_for_empty_conditions`).
- **Degradation disposition (amended 2026-06-18, final review):** clang-14-missing /
  host-extractor-missing / any extraction failure are **swallowed to clang-only**
  (loud + persisted as the right `DegradedReason`), NOT run-fatal — degraded mode is
  load-bearing for the default `--eval`/`--merge`/`--generate-drivers` flows. The
  actionable Fix-C message is logged and the project's stale image is invalidated so it
  self-heals on the next run; `LOGICFUZZ_REQUIRE_Z3=1` is the explicit opt-in that
  promotes any degradation to an early hard-fail. Runtime apt-install is explicitly
  **not** used.

## 7. Testing
- **Unit:** flag-strip filter (token in/out, append-preserving); `DegradedReason`
  capture for each path; `ConditionManager` guards against IndexError/KeyError/empty
  fixtures (nghttp2/libucl/re2); `REQUIRE_Z3` raises iff set ∧ degraded.
- **Regression (automates the manual in-container checks):** extraction for
  libpcap (A), liblouis (C), nghttp2 (B2), sqlite3 (B1-time) → assert `conditions.json`
  non-empty ∧ `extraction_mode=full`. **libucl → `extraction_mode=full`** (via big-budget
  flow-sensitive if it converges, else lite mode) **and** a soundness check that its
  `conditions.json` has non-trivial source/sink classification (guards the callback-creator
  risk). re2 → `degraded_reason=CONDITIONS_EMPTY` surfaced.
- **Safety:** cjson/zlib/lcms/c-ares/libpng byte-identical (`extraction_mode=full`,
  no flags stripped); `REQUIRE_Z3` off → no behavior change.
- **Determinism:** clang-14 baked (not runtime-installed) keeps `_bitcode_fingerprint`
  stable; pin `PYTHONHASHSEED=0` for any extraction-mode A/B (per
  `project_generation_nondeterminism`).

## 8. Risks
- **Fix C rebuild cost:** invalidating a stale cache image triggers a one-time
  rebuild per affected project (minutes). Acceptable, one-time.
- **B1 libucl precision loss in lite mode:** dropping `-do_indirect_jumps` can hide a
  callback-mediated creator/destroyer (the one correctness, not just precision, risk).
  Mitigated by the soundness check (re-add indirect-jumps + big budget if conditions look
  impoverished) and by trying big-budget flow-sensitive *first*.
- **Flag denylist drift:** new clang-version flags may appear in base CFLAGS; mitigated
  by recording `flags_stripped` (observable) and a future allowlist/probe option.
- **Determinism:** any future runtime clang-14 install would have to be folded into
  `_bitcode_fingerprint`; avoided here by the image-side fix.

## 9. Deferred (follow-up spec)
- curl: intercept the `ossfuzz.sh` meta-build to emit wllvm bitcode.
- pugixml: wire wllvm into the manual single-`clang` compile path.
- libucl Andersen mode (`extractor.cpp:503` createSGWPA) — only if lite-mode (drop
  indirect-jumps) is insufficient; requires adapting `buildFullSVFG`/`ProvenanceTracker`.
- SVF LLVM upgrade / toolchain unification (research track).
