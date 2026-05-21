# Multi-hop reasoning — design proposal (2026-05-12)

**Status:** proposal only. No code changes in this commit.
**Decision needed before implementation.**

This proposal addresses a class of failures surfaced by the
2026-05-12 dynamic runs (cjson run4/run5, c-ares run1, lcms run1):
agents make structural decisions in a single LLM call without
exposing or justifying their weighting of competing priors. The
result: priors that should help get ignored (existing driver
structure), priors that should be rejected get blindly followed
(suggestions that degrade coverage), and the decision process is
unauditable.

The proposed remedy is **multi-hop reasoning** for the two agents
that make the heaviest structural decisions: **Prototyper** (initial
driver design) and **Improver** (driver rewrite for coverage).
Other agents stay single-shot.

This is a design doc. Implementation is gated on review + A/B
evaluation planning.

---

## §1. Problem framing

### What we observed

| Bench | Symptom | Root cause (suspected) |
|---|---|---|
| cjson run5 trial 01 | doxygen ownership rules transferred (✓ `cJSON_Delete` + `cJSON_free` emitted), baseline driver structure ignored (✗ no byte-toggle input encoding, only 1 of 4 print pathways) | LLM weights priors unevenly without explicit reasoning |
| c-ares run1 trial 01 | improver iter1 11.17% → iter2 8.07% (27% relative regression) | Improver rewrites without comparing new vs old structure |
| lcms run1 trial 01 | 0.99% PC vs lcms's real-world coverage; Prototyper deviated from suggested target API | Same as cjson — priors compete, the winning prior is essentially random |

### Why a single-shot prompt loses

The current Prototyper prompt assembles ~10 priors:

  - `library_purpose` (Comprehender-A)
  - `protocol_templates` (automaton sample paths)
  - `sequence_invariants` (Comprehender-B)
  - `project_understanding` (ProjectAnalyzer)
  - `skeleton_drivers[(N-1) % K]` (CBFactory, when available)
  - `existing_fuzzer_headers` (T1)
  - `existing_driver_knowledge` (T1, OSS-Fuzz baseline source)
  - `header_info`
  - `comprehension` (per-API usage notes, may include doxygen)
  - `api_sequences` (L4-ranked candidates)

— and asks the LLM to "generate a driver". The LLM internally
weights these priors but **the weighting is opaque** to us, to the
LLM itself in retrospect, and to anyone reviewing the run. The cjson
example shows that the LLM doesn't apply *any* consistent rule — it
picks doxygen text for memory rules but ignores the existing driver's
structural pattern.

**Forcing "must preserve baseline" via prompt edits** is the wrong
fix (and the trap §2 explicitly avoids). Some projects ship a
narrow / outdated / deprecated baseline; following it blindly would
*lower* quality on those.

### The correct generalization

The problem isn't "wrong default weighting"; it's **no explicit
weighting reasoning at all**. The LLM should be required to
**reason about which priors are useful for this specific synthesis
task** before committing to a design — and that reasoning should be
visible.

---

## §2. The four reasoning hops

For any agent that makes structural decisions across competing
priors, the LLM should be guided through:

### Hop 1: Assess relevance per prior

> For each prior available (existing driver, doxygen, README,
> automaton paths, skeleton, comprehender, ...), label it as:
> *useful for this task* / *not useful for this task* / *partially
> useful*. For "not useful" or "partially useful", state which
> aspect doesn't apply.

This is the **explicit-rejection gate**. Without it, the LLM
defaults to "use everything", which is exactly today's failure
mode. The output is auditable: we can see in trial logs that "the
LLM rejected the existing driver because [reason]" or "kept the
existing driver because [reason]".

### Hop 2: Extract usable aspects

> For each prior labeled *useful* or *partially useful* in Hop 1,
> what concrete patterns / facts can be borrowed? Be specific —
> name the API call, the input encoding, the ownership rule, etc.

This forces the LLM to **commit in writing** to what it will use,
before it generates code. Mismatch between Hop 2 outputs and final
code is a flag for review.

### Hop 3: Design structure

> Given the patterns from Hop 2, sketch the driver structure
> (pseudo-code, ~10-30 lines). Justify each branch: why is this
> structure better than alternatives?

This is the **architecture step**. The LLM commits to a high-level
plan before writing code. Skipping straight from priors to code is
where the freelance bias lives.

### Hop 4: Implement + self-verify

> Implement the driver per the Hop 3 design. After implementation,
> self-check: does the code preserve the patterns from Hop 2? Are
> any patterns from Hop 2 missing from the code?

This catches inconsistencies between plan and execution.

### Critical: Hops must allow REJECTION

The single most important invariant: **Hop 1 must allow the LLM to
say "this prior doesn't apply"**, with justification. If the prompt
forces the LLM to use every prior, we're back to the over-fitting
extreme this proposal exists to avoid.

Concrete test for the prompt design: the LLM should occasionally
output "existing driver is too narrow for this fuzz target;
discarding". When it does, we accept the design. When it does it
*too often* (e.g., always discards skeletons), we revisit the prompt
or the agent's priors.

---

## §3. Where to apply

| Agent | Multi-hop? | Reasoning |
|---|---|---|
| **Prototyper** | ✅ STRONG | Initial driver structure — most consequential single decision. Sets all downstream coverage. Currently freelancers. |
| **Improver** | ✅ STRONG | Rewrites driver for coverage — can degrade (c-ares 27%). Today it has no explicit "should I rewrite this part?" decision. |
| **CoverageAnalyzer** | ⚠️ DEFER | Multi-step (find gap → propose strategy), but the consequences are weaker (just suggestions, not driver code). Revisit if Prototyper+Improver multi-hop doesn't fix coverage. |
| ProjectAnalyzer | ❌ NO | Mostly factual extraction (library purpose, build conventions). Already one-pass. |
| Fixer | ❌ NO | Already iterative (compile error → patch → recompile). Tool-use loop handles iteration. |
| CrashAnalyzer | ❌ NO | Tool-driven (GDB / bash). Reasoning is short. |
| CrashFeasibilityAnalyzer | ❌ NO | Binary classification. Single hop adequate. |
| Comprehender | ❌ NO | Already two-stage (A/B), each stage is bounded factual extraction. |

**Order of implementation (if approved):** Prototyper first
(highest impact), Improver second.

---

## §4. Two implementation modes

### Mode A — CoT in a single LLM call

One prompt with structured response sections:

```xml
<hop1_assess>
existing_driver: useful (covers parse+print, but...)
doxygen: useful (ownership rules clear)
skeleton: not useful (rejected by Z3 upstream; absent)
automaton sample paths: partially useful (creator order)
</hop1_assess>

<hop2_extract>
From existing_driver: byte 0..3 toggle pattern, 4 print modes
From doxygen: cJSON_Delete pairs with cJSON_Parse; cJSON_free for cJSON_Print
From automaton: ucl_parser_new before ucl_parser_add_chunk (if applicable)
</hop2_extract>

<hop3_design>
Pseudo-code outline...
</hop3_design>

<hop4_implement>
Final C/C++ driver code
</hop4_implement>

<hop4_verify>
Each pattern from Hop 2 → which lines in Hop 4 implement it
</hop4_verify>
```

**Pros**: ~1.5x token cost vs current single-shot. No infrastructure
change (still 1 LLM call). Easy to A/B against single-shot by
comparing on the same benchmark.

**Cons**: Model may "go through the motions" — fill in the
hop sections without genuine reasoning, then generate the same
code it would have generated single-shot. Mitigation: parse the
Hop 1/2 sections and **require Hop 4 to reference Hop 2 entries by
name** (e.g., "implementing pattern from Hop 2 entry 'byte 0..3
toggles' — see line N"). Verifies via the self-verify Hop 4b.

### Mode B — Multi-call pipeline

Each hop is a separate LLM call. Previous hop's output is in the
next hop's context.

```
Hop 1 (LLM call) → priors_assessment.json
        ↓
Hop 2 (LLM call) → patterns_to_preserve.json
        ↓
Hop 3 (LLM call) → design_outline.md
        ↓
Hop 4 (LLM call) → driver_code.c
        ↓
Hop 4b verify (LLM call OR deterministic) → consistency_check.json
```

**Pros**: Each hop output is structured, queryable, loggable, and
re-runnable. Can re-do a single hop without re-doing the rest.
Reasoning chain becomes a first-class artifact.

**Cons**: 4-5x token cost. 4-5x latency. Requires new infrastructure:
state fields for each hop's output, new prompt templates per hop,
plumbing.

### Recommendation

**Start with Mode A** for Prototyper. Measure. If A's quality plateaus
or self-verify reveals systematic "going through motions" → escalate
to Mode B.

For Improver, Mode A is also the right starting point. Improver is
already a single LLM call; layering Hop 1-4 inside the same call is
~1.5x cost increase and addresses the degradation case directly.

---

## §5. State schema additions (if implemented)

```python
@dataclass
class ReasoningChain:
    agent_name: str             # "prototyper" or "improver"
    iteration: int              # trial-relative iteration
    hop1_assess: Dict[str, Any] # {prior_name: {label, reason}}
    hop2_extract: List[str]     # ["pattern: ...", ...]
    hop3_design: str            # pseudo-code outline
    hop4_implement: str         # generated driver source
    hop4_verify: Dict[str, str] # {hop2_pattern: source_line_ref}
    timestamp: float

# In FuzzingWorkflowState:
reasoning_chains: NotRequired[List[Dict[str, Any]]]  # append-only audit log
```

Dumped per-trial to
`results/{project}/output-{project}-project/logs/trial_NN/reasoning_chain.json`
for human review.

---

## §6. Evaluation methodology (mandatory before rollout)

**Baseline**: current single-shot Prototyper (+ single-shot Improver).
**Treatment**: multi-hop Mode A on Prototyper (Improver baseline first).

### Per-bench metrics

| Metric | Source | Direction |
|---|---|---|
| Trial-1 compile success rate | execution.py `build_result` | Higher is better |
| Final PC coverage | run summary | Higher is better |
| `line_coverage_diff` vs baseline | execution.py | Higher is better |
| Trial-1 driver source LOC | filesystem | Neutral; large delta suggests stylistic difference |
| Pattern-preservation rate | Hop 4b verify output | Higher is better (subjective until calibrated) |
| Total LLM token cost per trial | token_usage state | Lower is better; budget acceptable up to 2x |
| Per-trial wall time | workflow.run() | Lower is better; budget acceptable up to 2x |
| Human-readable reasoning quality | Manual rubric | Subjective, score 1-5 |

### Bench mix

cjson + c-ares + lcms (already have single-shot data from
2026-05-12 runs). Plus 1 more if doxygen-rich is needed for the
"does Hop 2 cite doxygen" check — libxml2 is a candidate if its
OSS-Fuzz project is available.

### A/B execution

Two runs per benchmark — same seed, same flags — with and without
the multi-hop flag. Persist per-trial reasoning_chain.json. Diff
the final driver sources and per-trial coverage.

### Decision gates

| Outcome | Action |
|---|---|
| Multi-hop **wins** on ≥2 of 3 benchmarks for coverage AND compile rate, token cost ≤ 2x | Ship Mode A for Prototyper. Apply same to Improver in next round. |
| Multi-hop **mixed** (wins on 1 of 3, neutral on others) | Investigate the loss case. May indicate Hop prompts need tuning. Re-run after tuning before deciding. |
| Multi-hop **strictly worse** (loses on ≥2 of 3) | Abort. Document why the reasoning chain didn't translate to better code. Revisit the design (maybe Mode B is needed, or the Hop structure is wrong). |
| Multi-hop **comparable** on coverage but reasoning_chain.json is much more useful for debugging | Ship behind opt-in flag `--multihop-prototyper`. Default off until more bench data accumulates. |

### First-run observations (2026-05-21, multihop ON only)

A/B not yet complete — we have the multihop-ON arm but no
multihop-OFF parallel run to compare against. Logged here as
single-arm data; the OFF arm + decision-gate evaluation follows.

Single trial per project, multihop ON + doxygen + readme priors,
2-iter cap. Logs: `logs/ab_2026_05_21_v2/{cjson,c-ares,lcms}.log`.

| Project | iter1 PC | iter2 PC | iter1 line_diff | final line_diff | trial-1 compile? |
|---------|----------|----------|-----------------|-----------------|------------------|
| cjson   | 25.76%   | 24.12%   | 0.00%           | 0.00%           | ✅ |
| c-ares  | 8.63%    | 8.37%    | 0.09%           | 0.13%           | ✅ |
| lcms    | 0.97%    | 0.97%    | 0.00%           | 0.00%           | ✅ |

Compile success rate trial-1: 3/3. (For comparison, the prior
2026-05-12 single-shot runs without multihop also compiled
trial-1 on all three; multihop doesn't appear to regress compile
rate.)

Coverage is dominated by §10B v2 recovery, not multihop (the
recovery loop re-prototypes between iter1 and iter2). To
isolate multihop's contribution we need:

  1. multihop ON, §10B v2 OFF (control: pure multihop)
  2. multihop OFF, §10B v2 OFF (baseline: vanilla)
  3. multihop ON, §10B v2 ON (this run — already collected)
  4. multihop OFF, §10B v2 ON

§10B v2 fires on the same trials regardless of multihop, so
arms 1+2 give us the per-bench multihop delta cleanly. Tracked
in §6 evaluation methodology — A/B not yet a decision point.

---

## §7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Hop 1 LLM "always says everything is useful" → no rejection, defeats the purpose | Prompt template explicitly says: "you MUST label at least one prior as 'not useful' when N priors are >5"; manually review on a few trials |
| Hop 4 "implementation" decoheres from Hop 3 "design" — code doesn't match outline | Hop 4b verify step (LLM or deterministic regex) flags inconsistencies; on flag, retry Hop 4 once |
| Token cost balloons on libraries with many priors | Cap each prior to a fixed snippet length before Hop 1; Hop 1 reads summaries, not full sources |
| Reasoning chain becomes another monolithic prompt people don't read | Trial-level summary stat: "n_priors_rejected", "patterns_preserved_count", "patterns_dropped_count" — surface in the trial-end summary |
| Over-fitting to current cjson/c-ares failure modes | The 4 hops are generic across priors; the prompt doesn't hardcode "must use baseline driver". Re-evaluate on a doc-rich + baseline-rich benchmark not currently in the bench set |
| Implementation complexity (state schema, prompt templates) drags refactor | Mode A keeps it to: 1 new prompt template + minor state field. Mode B is deferred. |

---

## §8. Non-goals

This proposal does **NOT**:

- Force the LLM to use any specific prior. Hop 1 explicitly admits
  rejection.
- Force a specific driver structure. Hop 3 design is free-form.
- Replace any existing agent. Multi-hop is internal to
  Prototyper / Improver.
- Add or change any L0–L5 filter logic. Operates above synthesis.
- Add new priors. Operates on the priors the agent already receives.
- Replace ToolCallingMixin or LangGraph orchestration. Each agent's
  external interface stays the same.

---

## §9. Decision triggers for tier escalation

(Mirrors the format of `docs/knowledge_layer_design_proposal_2026_05.md` §9.)

| From | To | Trigger |
|---|---|---|
| nothing | Mode A Prototyper | Approved by user + designed prompt template + eval plan |
| Mode A Prototyper | Mode A Improver | Mode A Prototyper passes §6 gates on ≥2 of 3 benches |
| Mode A | Mode B (per-hop separate calls) | Mode A reasoning_chain.json reveals systematic "going through motions" — code doesn't match Hops 1-3 despite verify pass |
| Mode A/B Prototyper+Improver | Apply to CoverageAnalyzer | Prototyper+Improver multi-hop has been the production default for ≥2 weeks AND coverage_diff remains < 5% AND CoverageAnalyzer is the next-highest-leverage agent |
| any state | Rollback | A/B shows strictly-worse coverage or compile rate on ≥2 benches |

---

## §10. Rollback recipe

Mode A rollback is single-prompt-template revert:

  - Revert the new Hop-structured prompt template
  - Drop the `reasoning_chains` state field
  - Existing single-shot Prototyper / Improver code paths are
    unchanged (Mode A only adds prompt structure, not code paths)

Mode B rollback (if reached):

  - Roll back the multi-call pipeline; restore Mode A
  - Drop the per-Hop state fields
  - The orchestration code is contained within the agent class
    (no workflow-graph changes), so rollback is local

---

## §11. Open questions for review

1. **Hop count.** 4 (assess/extract/design/implement) is a starting
   shape per user spec. Worth considering 3 (collapse design+implement)
   or 5 (separate self-verify). Decision: keep 4 for first pass; adjust
   after seeing reasoning_chain.json on real runs.

2. **Hop 1 prior catalog.** Which priors get reviewed? The full ~10
   from §1, or a reduced set? Reduced gives the LLM less to reason
   about; full is more honest. Default: full, but each prior summarized
   to ≤200 chars before Hop 1 to keep token cost down.

3. **Hop 4b verify step.** LLM call (more accurate, +1x cost) or
   deterministic (regex matching pattern names → source line presence,
   cheap but brittle). Default: deterministic for v1, escalate to LLM
   if too many false negatives.

4. **Failure mode when Hop 1 rejects ALL priors.** Edge case: what
   does the prompt do then? Probably emit a "no priors apply; use
   only signature + library purpose" plan. Need explicit prompt
   handling.

5. **Coverage tail.** Multi-hop may help trial-1; subsequent trials
   are already trial-aware (skeleton index, sequence index rotate
   per trial). Does multi-hop add value on trial 5/10? Eval should
   measure.

---

## §12. Estimated effort

For Mode A Prototyper:

  - Design Hop 1-4 prompt templates: ~1 day
  - Wire reasoning_chain output parsing into state: ~0.5 day
  - Per-trial dump to `reasoning_chain.json`: ~0.5 day
  - A/B run across cjson + c-ares + lcms: ~1 day (mostly waiting on
    runs)
  - Manual review of reasoning chains: ~0.5 day
  - Tune prompts based on review: ~1-2 days iterative
  - **Total: ~5-7 days** for Mode A Prototyper, ready for ship/abort
    decision

Mode A Improver adds another ~3-4 days (similar pattern, can reuse
the prompt-template structure once Prototyper is shaken out).

Mode B (if escalated) adds ~2-3 weeks (per-hop infrastructure).

---

## §13. Why this proposal exists

User direction (2026-05-12):

> 对于复杂的，需要多条思考和推理的部分，我们设计成多跳推理：也就是说，
> 不要一个prompt结束。而是循循善诱LLM去思考：1. 当前信息是否有用？
> 2. 有哪些用？可以借鉴哪些信息。 以及其他的需要重要思考的地方。
> 这个地方，你需要全局思考。不然我们又是一个过拟合：从一个极端到
> 另一个极端

Translated: don't swing from "LLM ignores priors" to "LLM forced to
use priors". Instead, **guide the LLM through explicit reasoning
about which priors apply and how** — and let it reject when priors
don't apply.

This proposal operationalizes that direction without committing to
implementation until eval design is reviewed.
