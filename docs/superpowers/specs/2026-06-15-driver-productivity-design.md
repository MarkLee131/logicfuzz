# Driver Productivity: close the merged-coverage gap to PromeFuzz

**Date:** 2026-06-15
**Goal:** raise generated-driver MERGED coverage on lcms from 1708 br (17.0%) toward
PromeFuzz 4560 br (47.6%), measured the SAME way (single merged harness).

## Verified diagnosis (the foundation)

Every claim below is measured, not assumed:

1. **The metric is apples-to-apples.** PromeFuzz `examples/lcms/synthesized/entry.cpp`
   merges 140 sub-drivers into ONE harness with `driverIndex=Data[0];
   switch(driverIndex%140){case k: return LLVMFuzzerTestOneInput_k(Data+1,Size-1);}` —
   the identical single-merged-harness + 1-selector-byte dispatch our merge uses. So
   comparing our merged coverage to 4560 is fair; per-driver-union would be unfair.

2. **Count and dilution are NOT the levers.** Our breadth run (138 selected → 34 merged)
   gave 557 br — WORSE than the 16-driver control's 1708. PromeFuzz has MORE dispatch
   dilution (1/140) yet covers 4560. So neither driver count nor CDF dilution is the gap.

3. **The lever is per-driver PRODUCTIVITY.** PromeFuzz's drivers turn fuzz bytes into
   VALID INTERMEDIATE OBJECTS and CHAIN them into deep constructors. `synthesized/100.cpp`:
   fill a 256-entry `cmsUInt16Number` table from `Data` → `cmsBuildTabulatedToneCurve16`
   ×3 → feed the 3 curves into `cmsCreateLinearizationDeviceLink(sig, curves)` → exercise
   (reverse/dup) → free. 131/140 PF drivers are object-construction-FROM-DATA; only 9
   parse ICC. OUR drivers fail here: object-construction renders DEGENERATE collection/
   struct args (`cmsToneCurve* curves[3] = {0}` → NULL → the deep constructor guards out),
   so 53/69 cover 0 edges.

4. **Measured proof of the lever** (instrumented lcms, same seed, 20s):
   - PF build-and-chain pattern: **334 edges**, corpus grew to 98 (fuzzing progresses).
   - Our degenerate pattern (`curves[3]={0}` into the same constructor): **194 edges**,
     corpus 1/1b (no progress).
   - +72% edges/driver and dead→progressing, purely from populating the handle-collection
     arg instead of `{0}`.

## Approach

Make the construction/render layer produce non-degenerate, chained drivers like PF's —
turning the `{0}`/NULL collection-and-struct constructor args into populated ones.

### Lever A — populate handle-collection constructor args (primary)

When a CREATOR takes an array/collection of a handle type `T` (`T* const []`, `T**`,
`T* arr[N]`) that the model can produce, the renderer must emit a populated array of
built producer handles instead of `{0}`:

```c
cmsToneCurve* curves[3];
curves[0] = ret_cmsBuildGamma_a; curves[1] = ret_cmsBuildGamma_b; curves[2] = ret_cmsBuildGamma_c;
cmsHPROFILE p = cmsCreateLinearizationDeviceLink(cmsSigRgbData, curves);
```

Two halves:
- **Construction** (`sequence_constructor`): when a target's arg is a handle-collection
  of `T`, ensure K producers of `T` are in the prefix (K default 3; reuse one producer
  K× when only one is available — a valid non-NULL array still runs the constructor).
- **Render** (`skeleton_generator`): for such an arg, declare the array and assign the
  available `ret_<producer>` handles into its slots, instead of `{0}`. Follows the
  existing `deep_fuzz_buffer` arg_info-flag pattern (skeleton_generator.py:870-912).

### Lever B — fill typed buffer/table constructor args from fuzz data (complement)

A constructor arg that is a sized typed buffer/table (the 256-entry `cmsUInt16Number`
table) currently renders `{0}`. Fill it from fuzz bytes (the existing `FUZZ_INPUT`/
`FUZZ_DERIVE` machinery) so the built object carries fuzzed state. Complements A: A gives
the handle chain, B gives non-degenerate leaf data.

### Why not the alternatives

- **C (idiom-learning)** — mine library build→consume idioms and prefer them. More
  general but indirect; deferred behind A+B (which are the precise inverse of the
  measured dead pattern).
- **Selection methods 1/2/3** — SECONDARY. Choosing which dead drivers to ship doesn't
  help if they're all degenerate. Fix productivity first; revisit selection after.

## Gating + A/B

Gate `LOGICFUZZ_POPULATE_COLLECTIONS` (A) and reuse `LOGICFUZZ_*` buffer flags (B),
default-OFF, gate-off byte-identical (golden net green). Oracle = **merged-harness branch
coverage** vs control 1708 (single merged harness, 12 real `.icc` seeds, same flags).
Per-driver sanity = the instrumented-lcms harness (334 vs 194 target shape). Hold all
other gates fixed; one variable.

## Risk / constraints

- Construction touches the chain-building (must keep lifecycle-valid by construction;
  reuse `_build_prefix` producer resolution, don't fork). Render must stay valid C
  (golden net guards this).
- Array size K is domain-specific; default 3 + reuse-one fallback is a safe heuristic,
  not per-lib hardcoding.
- Keep it in the construction/render layer; do NOT touch the fragile binding/selection
  layers for this.

## Testing

- TDD unit: a synthetic model with a CREATOR taking a `T*[]` arg + a producer of `T` →
  gate-on renders the array populated with `ret_<producer>`, gate-off renders `{0}`.
- Golden net byte-identical gate-off.
- Per-driver dynamic: regenerate one lcms collection-constructor driver, confirm it
  renders a populated array (not `{0}`) and covers > the degenerate baseline.
- End-to-end: regenerate lcms + measure merged coverage vs 1708 (the goal metric).
