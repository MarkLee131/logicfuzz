# Closing the lcms merged-coverage gap vs PromeFuzz — Design

**Date:** 2026-06-16
**Goal:** merged-driver coverage catches PromeFuzz (lcms ≈ 4560 branches / ~3500 libFuzzer edges). Current best clean run: 2145 edges.

## Root causes (investigation `w6ziogsqf`, adversarially verified)

The gap is mostly **correctness defects masking real coverage**, not "too few drivers" or "too little time":

1. **Broken selection signal (binding).** The per-trial/preflight binaries are the stock `cms_gdb_fuzzer` (gamut-boundary fuzzer), NOT the generated driver — confirmed: all 63 `.blevers` preflight binaries collapse to 2 MD5 hashes, `preflight_bins/09`'s `LLVMFuzzerTestOneInput` calls `cmsGBDAlloc/cmsGDBAddPoint/...` not driver 09's `cmsCIECAM02Init`. The `no_progress` (15s edge-growth) gate drops **67% of drivers judging the wrong binary**. The MERGED harness (`synthesized/*.c`) IS real — so coverage numbers are valid, but selection is random-by-build-variant. The gate metric is *also* wrong in principle: a deterministic build+exercise driver adds its edges to the UNION regardless of 15s growth (PromeFuzz filters on COMPILE only).

2. **~69× exec-rate collapse.** Same-architecture control `merged27` ran at 2152 exec/s / 2.5M execs in 30 min; our clean run did 31 exec/s / 53K execs. Throttled by 71 fork-child crashes / 96 jobs (NULL-fed orphans + heap-UAF kill fork workers mid-job) and slow execs on 654 KB `.icc` seeds. NOT saturation — biggest +41-edge jump at minute 23, still hitting new functions at exit.

3. **Responsive-but-shallow drivers.** 17/25 drivers respond to input but all plateau at ~79 edges: random bytes never form a valid ICC profile → `cmsCreateTransform` NULLs → hard-guard short-circuits → deep path (`cmsxform`/`cmstypes`) never runs. 8/25 are fixed-coverage dead-weight.

4. **Untrustworthy branch metric.** llvm-cov replay times out / replays partial corpus → spurious low branches (550 < 1385 seed baseline); per-driver coverage build is degenerate (all 277 regions = stock fuzzer footprint).

## Fixes (prioritized by leverage; each measurable before the next)

### Fix 1 — Repair driver selection
- **1a (now):** drop the `no_progress` edge gate; merge filter = compile-validate + orphan-filter + immediate-crash-quarantine only (PromeFuzz-aligned). Keeps the ~9 distinct-value + non-redundant builders. Expected ~21 → ~30–40 merged.
- **1b:** root-cause + fix the per-trial/preflight build so the GENERATED driver is compiled (real per-driver coverage for dedup + the trustworthy metric). Verify: `preflight_bins/N` calls driver-N APIs; 63 binaries → ~63 hashes.

### Fix 2 — Recover exec-rate
Ensure orphan-filter + crash-quarantine fire end-to-end so the merged harness runs crash-clean; chase residual heap-UAF crashers; cap/limit pathologically slow large seeds so exec/s recovers toward the merged27 control. Expected: ~69× more execs → bursty late-jump coverage accrues.

### Fix 3 — Unlock depth (structured seeds)
Synthesize a minimal valid ICC/IT8 (`FORMAT_INFER` + TLV-aware) routed to each driver's specific parser-entry so `cmsDoTransform` runs; keep only DISTINCT gate-free builder subsystems (`cmssamp`/`cmspcs`/`cmscgats` + distinct `cmsvirt` functions); pair with `EXERCISE_OBJECT` + `CROSS_SOURCE_BIND` (measured +134% cross-profile).

### Fix 4 — Trustworthy branch metric
Crash-tolerant, no-timeout, full-corpus llvm-cov replay → real cumulative branches vs 4560; fix the per-driver coverage build (ties to Fix 1b).

**Sequence:** Fix 1 + Fix 4 → re-measure → Fix 2 verify → Fix 3 → final long run at recovered exec-rate.

**Primary metric:** libFuzzer edges (reliable, monotonic, crash-tolerant) for A/B; llvm-cov branches (after Fix 4) for the headline vs 4560.

## Already shipped this session (foundation)
LSan false-crash fix (`94cb7f79`); A→B-design default (`b81ca7b3`); orphan filter (`5a246ec9`); destroyer-hallucination fix (`457cdeec`).
