# Spec-Guided LLM Render (REPLACE #4) — Design Sketch (2026-06-25)

The biggest single simplification in the architecture-cleanup blueprint, now **greenlit by
the libpng validation** ([[project_architecture_a_validated_libpng]]: LLM-render from the
symbolic plan = 0 stack-overflows vs 19,946, 488 vs 73 edges, 684/7350 br in 180s/3 drivers).
This replaces the brittle deterministic render layer (`skeleton_generator.py` body — 24
`SkeletonVariable` branches, fixed-size stack buffers, no HEAP mode) with the LLM authoring
the driver body from a symbolic spec. **Status: design for user review — NOT to be built
autonomously (highest-risk change per the blueprint; gated + A/B before default).**

## The division of labor (unchanged from approved direction a)
- **symbolic PLAN** (KEEP, the moat): use-def → role model → Sequence Constructor → a deep,
  lifecycle-complete API sequence + per-arg semantics. Decides *what* APIs, *what* order,
  *what* each arg means (handle / input-buffer / out / config).
- **LLM RENDER** (new): given that spec, author the *complete* driver C — buffer sizing from
  runtime dims, NULL guards, setjmp, seed feeding. The thing deterministic render can't do.
- **symbolic VALIDATE** (KEEP + extend): lifecycle walk + plan-conformance check + A≡B compile.

## 1. The spec the planner hands the LLM (promote `hole_semantics`)
A JSON/struct per driver, emitted by `hole_semantics.annotate_skeletons` (today it attaches
hole value-intents; promote it to a full call-spec):
```
{ driver_id, library, includes:[...],
  sequence: [ {api, role, args:[{name, type, intent}]} ... ],   # ordered lifecycle
  contracts: { handles:[{type, creator_api, must_null_guard}],
               input_buffers:[{api, arg, paired_len_arg}],       # bind data/size here
               runtime_sized:[{api, out_arg, size_from:"png_get_image_height×rowbytes"}],
               cleanup:[{api, frees}] },
  seed_hint: "treat data/size as <format>; setjmp on error" }
```
`intent` ∈ {HANDLE_IN, INPUT_BUFFER, RUNTIME_SIZED_OUT, CONFIG_SCALAR, FILE_OR_PATH}. The
planner already computes all of this (roles, handle_types, INPUT_BUFFER, runtime-size
relations) — the spec just *serializes* it instead of rendering C from it.

## 2. The render call (re-target Prototyper)
`src/agents/prototyper.py`: instead of filling leaf holes in a rigid skeleton, prompt the LLM
to **author the whole driver** from the spec: "call these APIs in this order; heap-size every
RUNTIME_SIZED_OUT from its size_from at runtime; bind data/size into INPUT_BUFFER args;
NULL-guard every handle; setjmp per seed_hint; free per cleanup." (This is exactly what the
validation agents did by hand and it worked.)

## 3. Plan-conformance check (MANDATORY — the A-design-revert guard)
The validated risk ([[project_llm_reverts_objconstruct_to_parser]]): a free LLM reverts the
deep object-construction chain to a shallow parser-entry driver (lcms 14 vs 21). Guard:
after render, **parse the authored driver's called-API set + order** (libclang / regex over
the spec's API names) and compare to the spec:
- REJECT if it drops > K of the planned APIs (lost depth), or
- REJECT if it reorders a lifecycle-critical pair (creator after consumer), or
- REJECT if it adds a parser-entry root not in the plan.
On reject → regenerate (≤ N retries) with the diff fed back; after N, fall back to the
deterministic render (kept ONLY as the SVF-failed/conformance-failed fallback). This makes
the LLM's freedom *bounded by the symbolic plan* — the missing middle between rigid holes
(brittle) and free rewrite (drifts).

## 4. Gating + A/B (before default)
- Gate behind `LOGICFUZZ_LLM_REWRITE` (already exists as the A-design switch — repurpose:
  =spec-guided-render, default off until A/B wins).
- A/B breadth-matched on **cjson + lcms + libpng** using the now-trustworthy #0 profdata-first
  metric: deterministic render vs spec-guided render, compare merged branches + crash count +
  compile rate. Flip default only if spec-guided ≥ deterministic on coverage AND ≤ on crashes.
- Keep deterministic render shipping until the A/B clears (fail-safe).

## 5. What gets DELETED once #4 lands (the payoff)
- `skeleton_generator.py` render body (24 `SkeletonVariable` branches, fixed-array/`{0}`/
  `(void*)data`, the unused HEAP mode) → shrinks to spec-emission only.
- The hole placeholder machinery (`__HOLE_*`/`__ARRLEN_*`/`__REFINE_*` + the floor + the
  prototyper hole-merge) → gone (the LLM authors closed code).
- The 48-commit render fix-chain (funcptr decl, hole-closedness, include-form, …) collapses
  to one conformance check.

## Risk / open questions for the user
1. **Conformance-check precision — RESOLVED (prototyped 2026-06-25).** `liberator_adapter/
   analysis/plan_conformance.py` + `tests/test_plan_conformance.py` (6/6 pass). Finding: the
   reliable signal is the lifecycle **BACKBONE** (a planned creator called AND the planned
   **terminal deep-consumer** called) — NOT kept-fraction, which is too noisy (good drivers
   legitimately drop 30–56% of the plan: write-side setters, deprecated re-initializers). The
   terminal-consumer presence cleanly separates good drivers (call it) from BOTH A-design
   failures: shallow (created handle, bailed → no terminal) and parser-revert (swapped the
   chain for an unplanned one-shot → planned terminal absent). Must strip comments first (an
   API named in prose else false-counts). The check is ready to wire as the #4 render gate.
2. **Token cost**: full-authoring is more tokens than hole-fill. Measure per-driver; the
   prototyper prompt is already ~7K ([[project_prototyper_prompt_token_reality]]), authoring
   adds the spec + retries.
3. **Determinism**: LLM-authored drivers vary run-to-run; the conformance check + A≡B gate +
   #0 metric are the stabilizers. Acceptable for a generator (PromeFuzz is also LLM-authored).
4. Build only after the user approves this design (brainstorm → plan → subagent-driven impl).

Relates to [[project_architecture_cleanup_blueprint]] (the parent #4), [[project_architecture_a_validated_libpng]] (the proof), [[project_render_wellformedness_fixes]] (the fix-chain this collapses).
