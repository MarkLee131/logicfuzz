# Valid-by-Construction: enforce a Validity Contract at the construction gate — Design Spec

**Date:** 2026-06-16
**Goal:** Make "valid by construction" real. Today the constructor emits invalid sequences (73% of lcms drivers violate ≥1 lifecycle/nullability/type invariant) and a blunt downstream crash-filter (preflight) cleans up — wasting ~63% of builds and poisoning the coverage measurement. Replace that with a single explicit **Validity Contract**, enforced at construction by **consuming the APISemanticModel's per-arg `nullable`+`type_str` signal that the tool already extracts but never uses**.

**Architecture:** One contract, four invariants, enforced once at the construction/binding gate (proactive: build it right), with a reusable **contract validator** that is BOTH the gate and the regression oracle. Repair-not-reject (rejecting all-invalid would collapse breadth to 17/63 drivers).

---

## 1. Motivation — the architectural root (evidence-grounded)

This session landed 4 pipeline-infra fixes (stock-binary build, no_progress gate, crash-path merge exclusion), each peeling to the next bottleneck. That "every fix reveals a new problem" pattern is the architectural-problem signal (systematic-debugging Phase 4.5). The root, now quantified:

**The "valid by construction" promise (CLAUDE.md / `docs/generation.md`) is enforced NOWHERE.** The constructor over-produces (incl. invalid), the Z3 "confirm" gate checks only type/var (not lifecycle-order/nullability/type-correctness), the renderer mints `NULL` for unbound handles, and the blunt preflight crash-filter drops the wreckage.

**Quantified (63 lcms drivers, checked against the model's per-arg `nullable`+`type_str`):**

| Invariant | Violations | Drivers affected |
|---|---|---|
| **#2a orphan-handle** (`nullable=False` handle arg = NULL, no producer) | 164 | **38/63** |
| **#2b missing-value** (`nullable=False` string/config ptr = NULL) | 34 | 21/63 |
| **#3 type-confusion** (handle bound to wrong-type producer) | 29 | 12/63 |
| **#1 use-before-produce** (close-before-open) | 5 | 3/63 |
| **CLEAN (0 violations)** | — | **17/63 (27%)** |

This matches the crash evidence exactly: 33/38 preflight-dropped drivers crash on a NULL argument (23 SEGV-on-NULL-deref + 10 lcms `_cmsAssert(x!=NULL)` aborts), ~5 are type-confusion. **The dominant cause is #2a.**

**The recurring meta-pattern (the real architectural defect):** the knowledge model is rich, but each downstream consumer reads only a subset. The `nullable` field EXISTS on `ArgSemantics` and `type_str` carries the real type (cmsHPROFILE vs cmsHTRANSFORM). But `nullable` is populated by a **role HEURISTIC, not evidence** (`api_semantic_model.py:694`: `nullable = role in (NULLABLE_HANDLE, OUTPUT)`; HANDLE_IN defaults `False`) — and the doc `@param` text that says "must not be NULL" / "may be NULL" / "optional" **is extracted but discarded** (`project_docs.py:_param_role_from_text` maps to role only), while `NULLABLE_HANDLE` is **never assigned during reconciliation** (so a legally-nullable handle like `cmsContext`=global gets `nullable=False`, a false positive). The contract is only as accurate as `nullable`, so step 0 is to make `nullable` **evidence-based** (§3.0). Downstream, even this heuristic signal is then dropped:
- `sequence_constructor.py` has **zero** references to `.nullable` — it resolves only the IR-derived `requires` frozenset, which is **lossy** ("IR erases the inner handle", `sequence_constructor.py:169`).
- `skeleton_generator.py:1049-1070` reads `_role`/`_pairs` from `ArgSemantics` but **never reads `_as.nullable`**; line 1353-1359 unconditionally inits `HANDLE_IN` to `NULL`.
- `CBFactory._signature_handle_bindings` collapses opaque handles to `void*` → binds a consumer's `cmsHPROFILE` arg to the nearest `void*` (a transform) → #3.
- `hole_semantics._arg_intent` ALREADY emits "HANDLE_IN: never NULL" — never consumed by the renderer.

The fix is to **consume the signal the tool already produces**, at the construction/binding gate.

## 2. The Validity Contract

A constructed sequence S is VALID iff, reading the model's `args[i] = {nullable, type_str}` for every call:

- **(I1) Lifecycle order** — every handle variable is PRODUCED (by a creator/return) at a statement index strictly BEFORE any consumer/destroyer that reads it. (Kills close-before-open.)
- **(I2a) Non-NULL handle completeness** — for every arg with `nullable=False` whose `type_str` is an opaque handle type, the sequence contains a producer of a TYPE-COMPATIBLE handle, bound to that arg. No orphan NULL handles. (Kills the 164 orphans.)
- **(I2b) Non-NULL value completeness** — for every arg with `nullable=False` whose `type_str` is a non-handle required pointer/string (e.g. `char* FileName`), the arg is filled with a valid value, never `NULL`. (Kills the FileName-style asserts.)
- **(I3) Type-correct binding** — a consumer arg of handle type T binds only to a producer whose return handle type is T (matched by typedef NAME / handle family, not collapsed `void*`). (Kills cmsCloseProfile-on-transform.)

`nullable=True` args (OUTPUT, NULLABLE_HANDLE like `cmsContext`) are EXEMPT — NULL is legal for them.

## 3. Design

### 3.0 Nullability reconciliation — make `nullable` EVIDENCE-BASED (the foundation)
The contract is only as accurate as `ArgSemantics.nullable`. Today it's a role guess. Populate it by **reconciling three evidence sources by priority** (mirrors the model's `reconcile(IR ⊕ doc ⊕ usage)` design, which nullability currently skips):

1. **Doc `@param` cues (generalizes across projects, cheap).** Add `_param_nullability_from_text(text)` to `src/knowledge/project_docs.py` matching cues:
   - non-null: `must not be NULL`, `non-?null`, `required`, `[in]` on a pointer, `valid <type>`;
   - nullable: `may be NULL`, `can be NULL`, `optional`, `or NULL`, `NULL to <default>`, `[in,out]`/`[out]`.
   The param text is ALREADY extracted (`project_docs.py:405-407`) — it's just never inspected for this. Surface as `params[i]['nullable']`.
2. **IR non-null evidence (the high-value source for lcms).** Extend the condition extractor (`liberator_adapter/liberator/condition_extractor/`, `ProvenanceTracker.h`) to emit a per-arg `NON_NULL` provenance from: a library `_cmsAssert(arg != NULL)` / `assert(arg)`, `__attribute__((nonnull(i)))`, or an **unconditional dereference of arg i before any NULL check** in the callee. Persist into `conditions.json` per-arg (today `error_contracts.py` does this for RETURNS only — extend to ARGS).
3. **Role heuristic (fallback only).** Keep `HANDLE_IN → nullable=False`, but **assign `NULLABLE_HANDLE`** (→ `nullable=True`) when doc/IR evidence OR the known global-context/optional pattern says so — removing the `cmsContext` false positive.

Reconcile at `api_semantic_model.py` (`_reconcile_args`, ~597-700): **explicit doc/IR evidence OVERRIDES the role default**; conflicts resolve doc∧IR-non-null > role. Output: `ArgSemantics.nullable` is now evidence-backed, and `nullable=True` (legally optional) args are correctly EXEMPT from the contract (no wasted producer for `cmsContext`).

This is "fully use the API doc" (cue 1) **and** the library's own contract (cue 2) — the two real sources of non-NULL truth — instead of guessing from role.

### 3.1 Single source of truth
The model's per-arg `{nullable, type_str}` (`api_semantic_model.py` `ArgSemantics`) drives ALL four invariants. **Stop driving handle-resolution from the lossy `requires` frozenset; drive it from `nullable=False` + `type_str`.** `requires` becomes one input to producer-discovery, not the completeness oracle.

### 3.2 The contract validator (gate + oracle)
Productionize the prototype `/tmp/inv_check/checker.py` into `liberator_adapter/analysis/validity_contract.py`:
- `check_sequence(seq, model) -> ContractReport` (per-invariant violations with arg-level detail), operating on the STRUCTURED sequence (api list + arg bindings), not rendered C.
- Used (a) at the construction gate to drive repair/reject, and (b) as the **regression oracle** in tests and in telemetry (`results/<project>/static_analysis/contract_report.json`: violations before/after).

### 3.3 Enforcement = repair-not-reject (proactive construction)
Rejecting all 46 invalid → 17 drivers (breadth collapse). So the constructor must SATISFY the contract during construction, with a layered **unsatisfiable policy** per unmet arg:
1. **Bind** an existing in-sequence producer of the matching handle type (I2a/I3).
2. **Inject** a synthetic standalone producer for that type — reuse the EXISTING machinery (`sequence_constructor.py:312-336` no-requires producer injection; `_synthetic_producer` ~699-706). This is already "valid by construction."
3. **Drop the offending consumer** (keep the rest of the chain) if no producer (real or synthetic) exists for the type.
4. **Drop the chain** only if the dropped consumer WAS the chain's target/purpose.

Per invariant:
- **I1 (order):** topologically order producer-before-consumer during `_build_prefix`; never emit a consumer before its producer.
- **I2a (orphan):** for every `nullable=False` handle arg, run the layered policy (bind→inject→drop-consumer). This is the headline change — `_build_prefix` resolution iterates the model's non-NULL handle args, not just `requires`.
- **I2b (value):** for every `nullable=False` non-handle required arg, ensure a valid value-intent/hole (never NULL). For unfillable required strings (e.g. a real filename), drop the consumer (a fuzz driver opening a NULL/ないfile yields no coverage anyway).
- **I3 (type):** `CBFactory._signature_handle_bindings` binds a consumer arg of handle type T to a producer of type T, matched by **typedef name / handle family** (cmsHPROFILE↔profile producers, cmsHTRANSFORM↔transform producers), not nearest-`void*`. ADDITIVE: keep the legacy void* binding as fallback when typedef info is absent (so non-lcms/opaque-only libs are unaffected).

### 3.4 Defense-in-depth (the render-time guard is now SECONDARY)
A render-time `if(handle) consumer(handle)` guard remains, but ONLY as a thin net for the genuinely-runtime case the constructor can't know statically: **a creator that returns NULL at runtime on bad fuzz input** (e.g. `cmsOpenProfileFromMem` on random bytes). This is NOT the primary fix and does NOT excuse emitting static orphans.

## 4. Components / files

| File | Change |
|---|---|
| `liberator_adapter/analysis/validity_contract.py` (NEW) | The contract validator (`check_sequence`, `ContractReport`) — gate + oracle |
| `liberator_adapter/analysis/sequence_constructor.py` | `_build_prefix` resolution driven by model `nullable`+`type_str`; layered unsatisfiable policy (reuse `_synthetic_producer` / no-requires injection); I1 ordering |
| `liberator_adapter/driver/factory/constraint_based/CBFactory.py` | `_signature_handle_bindings` typedef-name/handle-family type-correct binding (additive, void* fallback) — I3 |
| `liberator_adapter/driver/synthesis/skeleton_generator.py` | consume `_as.nullable` (1049-1070); the render-time guard as defense-in-depth |
| `src/knowledge/project_docs.py` | `_param_nullability_from_text()` — mine `@param` cues for nullable/non-null (currently the param text is extracted but only used for ranges) — §3.0 cue 1 |
| `liberator_adapter/liberator/condition_extractor/` (`ProvenanceTracker.h`) | emit per-ARG `NON_NULL` provenance from `_cmsAssert(arg!=NULL)` / `nonnull` attr / unconditional deref-before-check — §3.0 cue 2 (C++ extractor change) |
| `liberator_adapter/analysis/api_semantic_model.py` | `_reconcile_args` populates `nullable` by reconciling doc ⊕ IR ⊕ role (evidence overrides heuristic); assign `NULLABLE_HANDLE`→`nullable=True` for optional handles (kills the cmsContext false positive) — §3.0 |
| telemetry | `contract_report.json` (violations before/after) — the A/B oracle |

## 5. Verification

- **Nullability accuracy (§3.0):** on a cached model, doc-cue + IR evidence flips known optional handles to `nullable=True` (cmsContext no longer forces a producer) and confirms `nullable=False` for required ones; A/B the doc-cue source vs the IR source to see which carries lcms (expect IR `_cmsAssert` dominant for lcms, doc dominant for doc-rich libs like c-ares).
- **Contract oracle (deterministic):** the validator reports **0 I1/I2a/I2b violations** on constructed lcms sequences post-fix (I3 → 0 where typedef info exists). Before/after counts in `contract_report.json`.
- **Valid-driver yield:** clean lcms drivers rise from **17/63 → target ≥50/63**; merged-driver count from 19 → target ≥45.
- **Coverage (the goal):** real `--merge-drivers` + 30-min measurement beats the fix1a 61-driver baseline (2092 edges) toward PromeFuzz (~3500). Per-driver depth preserved (EXERCISE/transform drivers now survive).
- **Multi-project (STANDING RULE — guard over-fit):** the contract is GENERIC (model `nullable`+`type_str` exists for every project). Run the validator on cjson / c-ares / zlib / libucl: confirm it (a) finds real violations where they exist, (b) is a no-op / byte-identical where the constructor was already valid, (c) the I3 typedef-binding is inert when handles aren't void*-collapsed. No lcms over-fit.
- **No regression:** full `pytest tests/` green; golden net unchanged with the gate OFF.

## 6. Risks / mitigations

- **Binding layer is the historically-fragile #1 bottleneck.** I3 is ADDITIVE (typedef-name match with void* fallback), gated, locked by cross-project predicate tests over cached models (lcms hits; cjson/zlib/c-ares no-op).
- **Breadth shrink from over-strict reject.** Mitigated by repair-not-reject + the layered unsatisfiable policy; the validator telemetry quantifies any drop, and a chain is dropped only as last resort.
- **Synthetic-producer correctness.** Reuse the existing no-requires injection (already "valid by construction"); don't invent new producers.
- **Over-fit.** The contract is driven by the generic model fields, not lcms names; multi-project validation is a gate.
- **C++ condition-extractor change (§3.0 cue 2)** is the heaviest piece and the one that can regress extraction. Mitigate: ship doc-cue mining (cue 1) + the NULLABLE_HANDLE fix FIRST (cheap, no C++); add the IR `NON_NULL` provenance as an ADDITIVE pass behind the same gate, with the role heuristic as fallback if the extractor lacks it — so the contract still works (less accurately) without the C++ change.

## 7. Gating & A/B
Behind `LOGICFUZZ_VALIDITY_CONTRACT=1` initially (default-off), like factory/diversity/density did, until a coverage A/B proves the gain on lcms AND no regression on cjson/c-ares/zlib; then default-on and the gate removed. `contract_report.json` is always-on (cheap telemetry) as the A/B oracle.

## 8. Implementation order (TDD; one invariant at a time, checker measures each)
1. **Contract validator** (`validity_contract.py`) + tests over cached `api_semantic_model.json` + sample sequences. Productionize the checker; it is the oracle for all subsequent steps.
2. **Nullability reconciliation** (§3.0) — evidence-based `nullable`: (a) doc-cue mining in `project_docs.py` + assign NULLABLE_HANDLE (cheap, generalizes); (b) IR per-arg `NON_NULL` provenance in the condition extractor; (c) reconcile in `_reconcile_args`. Verify on a cached model: known optional handles (cmsContext) → `nullable=True`; known required handles → `nullable=False`. The contract steps below depend on this being accurate FIRST.
3. **I2a orphan** (headline, 38 drivers) — constructor resolves all non-NULL handle args (bind→inject→drop-consumer). Validator: I2a → 0. Measure valid-driver yield.
3. **I1 order** — producer-before-consumer ordering. Validator: I1 → 0.
4. **I2b value** — fill non-handle required args; drop-consumer for unfillable strings. Validator: I2b → 0.
5. **I3 type** — CBFactory typedef-name binding (additive, fallback). Validator: I3 → 0 where typedef info exists; cross-project no-op tests.
6. **Defense-in-depth guard** (secondary) + CLAUDE.md gate doc + full suite + golden net + the real lcms merge coverage measurement.

## 9. Success criteria
0. `ArgSemantics.nullable` is **evidence-based** (doc `@param` ⊕ IR `_cmsAssert`/nonnull ⊕ role fallback): optional handles (cmsContext) are `nullable=True`, required ones `nullable=False` — the doc is fully used, not discarded.
1. Constructor emits sequences with **0 I1/I2a/I2b** contract violations (I3 → 0 where typedef info exists) on lcms — "valid by construction" is real, verified by the oracle.
2. Valid-driver yield 17→≥50 / merged 19→≥45; ~63% wasted builds eliminated (the optimization).
3. Real merged coverage beats 2092 toward ~3500.
4. Generic + multi-project: no-op / no regression on cjson / c-ares / zlib / libucl.
