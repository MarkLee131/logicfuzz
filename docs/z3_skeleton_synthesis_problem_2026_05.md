# Z3-guided skeleton synthesis: 0-skeleton problem analysis

> **For expert discussion.** Written 2026-05-22, after the post-fix
> A/B run revealed cjson and lcms synthesize **0/10** Z3-validated
> skeletons each while c-ares synthesizes **5/5**. The num-samples
> fallback (commit `1f0438e3`) means the entire multi-trial × merge
> pipeline degenerates to a single freeform-LLM trial on these two
> projects.
>
> The author has read the relevant classical literature anchors
> (UNSAT cores, MaxSMT, CEGAR, SyGuS) but seeks expert opinion on
> the right intervention given the specific encoding shape and
> failure mode below.

---

## §1. Problem statement

LogicFuzz generates fuzz drivers via a multi-stage pipeline. The
stage in question is "skeleton synthesis":

```
L4-ranked API sequences  ──▶  CBFactory.create_skeleton_for_sequence(seq)
        (N sequences)                            │
                                                 ▼
                            validate_sequence_with_z3(seq)
                                                 │
                            ┌────────────────────┴──────────────────────┐
                            │                                           │
                          SAT                                         UNSAT
                            │                                           │
                            ▼                                           ▼
                  _create_skeleton_from_sequence              return None  ← reject
                  (renders a DriverSkeleton with                            (the source
                   variable bindings + holes)                                of the
                            │                                                0-skeleton
                            ▼                                                problem)
                  DriverSkeleton (LLM refines)
```

Each surviving skeleton becomes one trial in the per-project run.
Many trials × diverse skeletons × `--merge-drivers` is the intended
**evaluation unit**.

**Failure mode**: on cjson (78 APIs, 10 L4-ranked sequences) and
lcms (297 APIs, 10 L4-ranked sequences) the `validate_sequence_with_z3`
call returns `is_sat=False` for **all 10 inputs**. c-ares (138 APIs,
5 sequences) returns SAT for all 5. The 0-rate is uniform; not
"a few infeasible candidates" but "the encoding pathologically
rejects everything."

The downstream consequence: 0 skeletons → 0 multi-trial diversity →
no merge → coverage_diff vs baseline is structurally bounded by a
single freeform LLM driver. The §10B v1/v2 "baseline-regression
recovery" infrastructure built on top is downstream of this primary
bottleneck.

---

## §2. Current encoding

`liberator_adapter/constraints/z3_solver.py` — concise summary.

### 2.1 Variables

For each unique API name `f` in the sequence:

| Var | Sort | Meaning |
|---|---|---|
| `api_f` | `Bool` | "API `f` is called in the candidate driver" |
| `order_f` | `Int` | "Index at which `f` appears in the call sequence" |

For each type `T` ever referenced:

| Var | Sort | Meaning |
|---|---|---|
| `type_T` | `Int` | Synthetic type-ID, used by `add_type_match_constraint` |

**Critical property**: `order_f` is **keyed by API name**, not by
sequence position. A sequence `[f, g, f]` gets `order_f`, `order_g`
— two vars for three slots. The encoder's `add_api_sequence_constraint`
deals with this by **picking the first index for repeated APIs**:

```python
seen: Set[str] = set()
for i, api in enumerate(api_sequence):
    if api in seen:
        continue           # ← repeated APIs invisible to order
    seen.add(api)
    order_var = self._get_or_create_order_var(api)
    order_exprs.append(order_var == i)
```

This is the "papered over" mitigation documented in `CLAUDE.md`
"Failed Attempts / Lessons".

### 2.2 Constraint families

Four hard constraint families are added during validation:

**TYPE_MATCH** (`add_type_match_constraint`): when API `g`'s arg
depends on API `f`'s return:
- If types compatible: `type_T_f == type_T_g`
- If types incompatible: `¬(api_f ∧ api_g)`

**ACCESS_ORDER** (`add_access_order_constraint`): when `creator_c`
and `deleter_d` both touch type `T`:
```
delete_called → (create_called ∧ order_create < order_delete)
```
Similar for CREATE-before-USE, USE-before-DELETE.

**SEQUENCE_ORDER** (`add_api_sequence_constraint`): pins each
unique API to its first-occurrence index:
```
order_f == idx_first_occurrence(f)
```

**LENGTH_DEP** (`add_dependency_constraint`): from upstream
condition analysis, when arg `i` of `f` is the length of arg `j`.

All four are added via `solver.add(expr)` (hard). `get_unsat_core()`
is implemented but called **after** assertions without
`assert_and_track`, so it returns an empty list — there is no
working diagnostic surface today.

### 2.3 Where lifecycle roles come from

`_add_lifecycle_constraints` reads upstream Liberator's
`FunctionConditions`:

```python
for at in cond.return_at.ats:
    if at.access == Access.CREATE:
        creates.setdefault(at.type_string, []).append(api.function_name)

for arg_cond in cond.argument_at:
    for at in arg_cond.ats:
        if at.access == Access.DELETE:
            deletes.setdefault(type_str, []).append(api.function_name)
        elif at.access in (Access.READ, Access.WRITE):
            uses.setdefault(type_str, []).append(api.function_name)
```

The `Access` enum is computed by `ConditionManager` from LLVM IR
side-effect analysis (`bitcode/source/...`). It tags every return
position and every arg position with one of
{NONE, READ, WRITE, CREATE, DELETE, ...}.

---

## §3. Hypothesised failure mechanisms

Without working UNSAT cores I can only narrate the likely shapes.
The diagnostic in §4 will pin one or more of these.

### 3.1 Lifecycle CREATE-before-USE pinned to wrong slot

Take cjson sequence 8 (from `results/cjson/static_analysis/filtered_sequences.json`):

```
[cJSON_CreateNull, cJSON_Delete, cJSON_GetErrorPtr,
 cJSON_CreateString, cJSON_Parse, cJSON_Print,
 cJSON_CreateArray, cJSON_IsNumber]
```

Upstream `ConditionManager` likely marks all of `cJSON_Create*` and
`cJSON_Parse` as CREATE on type `cJSON*`. `cJSON_Delete` is DELETE
on the same type. `cJSON_Print` reads it.

Pinned orders:
```
order_cJSON_CreateNull   == 0
order_cJSON_Delete       == 1
order_cJSON_GetErrorPtr  == 2
order_cJSON_CreateString == 3
order_cJSON_Parse        == 4
order_cJSON_Print        == 5
order_cJSON_CreateArray  == 6
order_cJSON_IsNumber     == 7
```

ACCESS_ORDER for `(create, delete)` on `cJSON*`:
```
∀ c ∈ {CreateNull, CreateString, Parse, CreateArray}:
    delete_called → (c_called ∧ order_c < order_cJSON_Delete)
```

With pinned orders:
- `order_CreateNull (0) < order_Delete (1)` ✓
- `order_CreateString (3) < order_Delete (1)` ✗ **UNSAT**
- `order_Parse (4) < order_Delete (1)` ✗ **UNSAT**
- `order_CreateArray (6) < order_Delete (1)` ✗ **UNSAT**

The sequence is rejected, but it's a *legitimate fuzz target*:
the deleter at position 1 deletes the value created at position 0;
the deleter at the end of the sequence (implicit, not in seq) would
delete the rest. The encoding's "any creator must precede any
deleter (per type)" is **too coarse**: it conflates *resource
identity* across distinct instances of the same type.

### 3.2 First-occurrence dedup hides multiple lifecycles

cjson sequence 5: `[cJSON_Parse, cJSON_AddBoolToObject, cJSON_AddArrayToObject, cJSON_AddItemToArray]`.

`cJSON_AddItemToArray` is plausibly tagged READ+WRITE on `cJSON*`.
If the L4 sample ever emits a *repeated* `cJSON_AddItemToArray`
(it does on other sequences via random walk), the second occurrence
is invisible: `order_cJSON_AddItemToArray == 1` pins only the first.
A lifecycle constraint that depends on the second occurrence is
silently lost or contradicted.

### 3.3 ConditionManager over-tagging

If `cJSON_Free` is marked DELETE on **multiple** unrelated types
(because the upstream IR analysis sees it freeing a `void*` cast
of several distinct structs), then any sequence with a `cJSON_Free`
appearance pulls in lifecycle order constraints against every creator
of every type it might delete. Combined with §3.1, this cascades.

### 3.4 LENGTH_DEP across renamed args

If upstream's `len_depends_on` says `arg 1 of f` depends on `arg 0`,
but the dependency_constraint encoder uses different name conventions
(`param_0` vs `0`), the parser at `add_dependency_constraint` could
generate a contradictory or always-false constraint. Less likely
to be the dominant cause but worth ruling out.

### 3.5 cjson has 0 sources tagged CREATE

Alternative: if the upstream IR analysis returns **no** Access.CREATE
on cjson APIs (because the IR is missing or stripped for some
reason), then `creates` is empty, lifecycle constraints fire zero
times, and the failure mode must be elsewhere (TYPE_MATCH or
something not yet enumerated). cjson actually has clear creators
(`cJSON_Parse`, `cJSON_Create*`) so this is unlikely; lcms is more
plausible as a case where IR analysis is incomplete.

---

## §3.6. Confirmed root cause from cjson conditions.json (2026-05-22)

Inspecting `results/cjson/conditions.json` (re-extracted post-cache-wipe):

```
creates[%struct.cJSON*]: 30 APIs
  {cJSON_Parse, cJSON_ParseWithLength, cJSON_ParseWithOpts,
   cJSON_CreateObject, cJSON_CreateArray, cJSON_CreateNull,
   cJSON_CreateString, cJSON_CreateNumber, ..., cJSON_Duplicate,
   cJSON_AddBoolToObject, cJSON_AddArrayToObject,
   cJSON_AddObjectToObject, cJSON_AddNumberToObject, ...}

deletes[%struct.cJSON*]: 3 APIs
  {cJSON_Delete, cJSON_DetachItemViaPointer, cJSON_ReplaceItemViaPointer}

uses[%struct.cJSON*]: 54 APIs
  {cJSON_AddBoolToObject, cJSON_AddArrayToObject, cJSON_AddItemToArray,
   cJSON_AddItemToObject, cJSON_Compare, cJSON_GetArrayItem,
   ..., cJSON_Delete, cJSON_DeleteItemFromArray, ...}
```

**creates ∩ uses ≠ ∅** for cjson — by construction. `cJSON_AddBoolToObject`
is in **both** sets because:
- its return access on `cJSON*` is tagged `create` (it allocates a new
  child node and returns it)
- its arg-0 access on `cJSON*` is tagged `write` (it mutates the parent
  object passed in)

The IR analysis is correct about both effects. The bug is downstream.

### Why this makes the encoding pathologically reject

`_add_lifecycle_constraints` then quantifies over the **API name set**:

```python
for type_str in set(creates) & set(uses):           # cJSON* satisfies this
    for c in creates[type_str]:                     # 30 APIs
        for u in uses[type_str]:                    # 54 APIs
            if c != u:
                self.builder.add_access_order_constraint(c, u)
                # asserts: order_c < order_u
```

For cjson sequence 5 `[cJSON_Parse, cJSON_AddBoolToObject,
cJSON_AddArrayToObject, cJSON_AddItemToArray]` with pinned orders
`{Parse:0, AddBool:1, AddArray:2, AddItem:3}`, this generates 12
pair constraints, including:

- `order_cJSON_Parse (0) < order_cJSON_AddBoolToObject (1)` ✓
- `order_cJSON_AddBoolToObject (1) < order_cJSON_Parse (0)` ✗ **UNSAT**

(because both Parse and AddBool are in `creates` AND `uses`).

Once any single pair is UNSAT the whole sequence is rejected. This
happens **structurally on every cjson sequence with ≥2 cJSON*-touching
APIs** — i.e. all 10.

### The root semantic error

The constraint generator confuses **type-level** quantification with
**value-instance-level** quantification.

- **Intended semantics**: "the creator of *this particular cJSON\*
  value* must precede the user of *this particular value*."
- **Actual encoding**: "every API that *might* create *some* cJSON\*
  must precede every API that *might* use *some* cJSON\*."

For libraries where APIs are role-disjoint (`init` only creates, `use`
only reads, `destroy` only deletes) the two semantics coincide and
the encoding works (c-ares 5/5 SAT). For libraries with chained-builder
or in-place-transform APIs (cjson, plausibly lcms's `cms_transform_*`
family) they diverge and the encoding rejects everything.

This is exactly the failure mode position-indexed encoding (§5.2)
removes: by quantifying over *positions*, "creator-of-this-value"
becomes "the position immediately before the current position that
covers the required type", which doesn't depend on whether the same
API name appears elsewhere with a different role.

---

## §4. Diagnostic plan (best practice #1)

The existing `get_unsat_core()` returns `[]` because it doesn't use
`assert_and_track`. The diagnostic needs:

1. **Re-instrument** the `Z3ConstraintBuilder` so every `solver.add(expr)`
   becomes `solver.assert_and_track(expr, Bool(f"c_{tag}_{i}"))`.
2. **Re-run validation** on each of the 10 cjson + 10 lcms sequences.
3. **Capture** the unsat core's tracking literals, group by
   constraint type (`c_TYPE_MATCH_*`, `c_ACCESS_ORDER_*`, etc.).
4. **Report**: per-sequence, the minimal set of constraint types
   causing UNSAT. Aggregated, the family distribution
   (e.g. "9/10 cjson rejections are dominated by ACCESS_ORDER on
   `cJSON*`").

This is read-only (no encoding change), bounded scope (~50 LOC
diagnostic harness), and produces the empirical signal needed to
choose between interventions §5.{1-4}.

---

## §5. Interventions (anchored to classical best practices)

### 5.1 #2 — MaxSMT / soft constraints (recommended)

**Anchor**: Bjørner & Phan, *νZ - An Optimizing SMT Solver*, TACAS 2014.
Sketch / SyGuS competition tracks. Z3's `Optimize()` API.

**Move**: re-classify constraints by *semantic necessity*:

| Constraint | Reason | New role |
|---|---|---|
| TYPE_MATCH | Mismatch → compile error. Hard truth. | **Hard** |
| LENGTH_DEP | Wrong arg length → runtime crash. Buildable but unsafe. | **Soft, high weight** |
| ACCESS_ORDER (CREATE→USE) | Use before init → null deref. | **Soft, high weight** |
| ACCESS_ORDER (CREATE→DELETE) | Heuristic; library may auto-cleanup. | **Soft, medium weight** |
| ACCESS_ORDER (USE→DELETE) | Use after free → bad but fuzz-detectable. | **Soft, low weight** (we *want* fuzzer to find UAF) |
| SEQUENCE_ORDER | This is the input — caller decides order. | **Hard** (preserves caller's intent) |

Replace `solver.check()` with `Optimize` + `add_soft(expr, weight=w, id=tag)`.
The optimizer returns the max-weight partial satisfaction.

**Expected effect on §3.1 example**: SEQUENCE_ORDER stays hard
(caller-specified). ACCESS_ORDER becomes soft. The optimizer
returns SAT with some ACCESS_ORDER violations explicitly tagged
in the model. We accept the sequence with annotation "violates
CREATE→DELETE for `cJSON_Parse`→`cJSON_Delete`" — the downstream
LLM gets a hint to insert a `cJSON_Delete(parse_result)` cleanup,
not to reject.

**Risk**: weight tuning. The MaxSMT competition has decades of
work on this; pick a sane initial assignment (10:5:1 perhaps) and
calibrate empirically. Z3 `Optimize` supports lexicographic
optimization which may simplify the trade-off design.

**Estimated cost**: 2 days. Validator becomes more code (Optimize
vs Solver), needs new result type (`PartialSatResult` carrying
the violated-soft list).

### 5.2 #4 — Position-indexed encoding (recommended)

**Anchor**: SyGuS solvers (CVC4-SY, EUSolver). The standard
"unfolded" encoding where each call site is a fresh atom.

**Move**: replace `order_f` (per-name) with `order_i` for
`i ∈ [0, len(seq))`. Replace `api_f` with `called_i`. Lifecycle
constraints reference call sites directly.

```
called_i      ≡ Bool(f"called_{i}")
order_i       ≡ Int(f"order_{i}") ; order_i == i   (always pinned)
api_at_i      ≡ Function f → Int  ; api_at_i == hash(seq[i])  (constant)
```

CREATE-before-USE on type T becomes:
```
∀ i, j ∈ [0, len(seq)):
    i < j ∧ uses_T(seq[j]) →
        ∃ k < j: creates_T(seq[k])
```

This is **decoupled from name collisions**. Repeated APIs each
have their own atom. The §3.1 example becomes: at position 5
(`cJSON_Print` USE on cJSON*), is there some `k < 5` with
CREATE on cJSON*? Yes (positions 0, 3, 4). SAT.

**Bonus**: the `'named assertion defined twice'` exceptions in
CLAUDE.md "Failed Attempts" disappear entirely — there are no
name collisions to dedup at the boundary.

**Risk**: encoding size grows linearly in sequence length. For
`len(seq) = 12` and 4 constraint families, this is ~50 constraints
per sequence vs ~15 today. Still trivial for Z3.

**Estimated cost**: half day. Mechanical translation of the
existing constraint generators; SEQUENCE_ORDER drops out entirely
(orders are pinned by index).

### 5.3 Stack #2 + #4 (recommended path)

Independent fixes. Apply both:
1. #4 first — fixes the encoding shape, removes the dedup hack,
   produces *correct* hard-constraint behaviour.
2. Then re-evaluate #2 — with the correct encoding, some §3 failure
   modes may go away on their own. Soft-ify whatever still
   over-rejects.

### 5.4 Deferred: CEGAR (#3) and portfolio fallback (#5)

**CEGAR**: structurally heavier. Requires a "check whether the
candidate actually builds and runs" feedback loop *inside* synthesis.
Today's pipeline does this *after* synthesis (build-then-fixer).
Hoisting it into synthesis is the right design but a 1-week
refactor; defer until #2 + #4 are evaluated.

**Portfolio fallback**: we already have it implicitly (0 skeletons
→ freeform LLM trial). Adding explicit diagnostic logging on the
fallback path (so we know *why* it triggered) is cheap and worth
doing alongside #2 + #4.

---

## §6. Questions for the expert

1. **Soft-constraint weight calibration** — is there a standard
   recipe for ordering "compile-correctness > runtime-safety >
   library-convention" in MaxSMT, or is it always empirically
   tuned per domain? I've seen the SyGuS competition use
   lexicographic vs weighted-sum — which is more robust for our
   case where the candidate count is small (10 sequences) but
   each sequence is short (≤ 12 APIs)?
2. **CEGAR vs MaxSMT** for over-constrained synthesis — is there
   a known regime where one strictly dominates? My intuition: CEGAR
   wins when the *constraint set is correct but huge* (model
   checking); MaxSMT wins when the *constraint set is hand-encoded
   and possibly over-conservative* (our case). Confirm?
3. **UNSAT core minimisation** — Z3's default core is not minimal.
   For diagnostic purposes I want a minimal core (drop one
   tracking literal at a time, re-solve). Is there a standard
   library / Z3 tactic for this, or do I roll it by hand?
4. **Position-indexed encoding scaling** — at what `len(seq)` does
   the linear-in-position encoding start to hurt Z3 solve time?
   We're at `≤ 12` today; should I worry if we grow to 30?
5. **Alternative**: instead of fixing CBFactory's Z3 encoding, is
   there a case for replacing it entirely with a SyGuS-IF
   formulation (CVC4-SY, EUSolver) — given that we're effectively
   doing component-based synthesis with type + lifecycle predicates?

---

## §6.5. 2026-05-22 update: #4 implementation outcome

`Z3SequenceValidator.validate_sequence` was rewritten on 2026-05-22
(commit `f7001cf7`) to use position-indexed lifecycle semantics
(§5.2). The legacy code's `add_api_sequence_constraint`,
`add_access_order_constraint`, and `_add_lifecycle_constraints`
were deleted entirely — they had no callers outside the validator
itself once the position-indexed walker replaced them. Z3 is
retained only for the length-dependency family.

Empirical result on cjson's 10 L4-ranked sequences (the same set
that produced 0/10 SAT under the legacy encoding):

| Outcome | Legacy | Position-indexed |
|---|---|---|
| SAT (sequence admitted as buildable) | 0 | **7** |
| Rejected — true USE-before-CREATE | 0 | 3 |
| Rejected — cyclic over-constraint (false positive) | 10 | 0 |

The 3 remaining rejections are real null-deref hazards:

- **seq 3**: `[cJSON_IsArray, cJSON_ParseWithLength, ...]` — `IsArray`
  dereferences a `cJSON*` before any creator runs.
- **seq 6**: `[cJSON_DetachItemViaPointer, cJSON_CreateNumber, ...]` —
  `DetachItemViaPointer` mutates a `cJSON*` that doesn't exist yet.
- **seq 9**: `[cJSON_IsInvalid, cJSON_IsFalse, ...]` — same pattern,
  multiple `cJSON*` predicates fire before any creator.

These rejections are *correct* — L4's random-walk generator
occasionally emits genuinely broken orderings; rejecting them and
letting L4 retry is the right policy.

### What this means for §10B v1/v2 and the multi-trial story

With #4 landed, the chain that was previously broken:

```
L4 generates 10 candidates
     ↓
Z3 rejects 10 (cyclic over-constraint)
     ↓
0 skeletons in cache
     ↓
num_samples = 1 (fallback)
     ↓
1 trial / project
     ↓
merge has 1 driver to merge → no diversity
     ↓
§10B v1 fires per-trial, can't tell the difference between
"single-trial noise" and "real coverage gap"
```

is now:

```
L4 generates 10 candidates
     ↓
Z3 (lifecycle deterministic walk) admits 7 valid sequences
     ↓
7 skeletons in cache  
     ↓
num_samples = 7 (post 1f0438e3)
     ↓
7 trials × diverse skeletons / project
     ↓
merge combines 7 drivers → real diversity
     ↓
§10B v1 can fire on post-merge coverage (right granularity)
```

### Is #2 still needed?

The original case for #2 (MaxSMT / soft constraints) was: "the
hard-constraint encoding rejects too aggressively; switch to soft
to admit max-partial-sat." With #4 the rejection is no longer
aggressive — it's correct. The 3 remaining cjson rejections would
genuinely null-deref if admitted; admitting them with a soft penalty
would push broken drivers downstream into the LLM, costing tokens
and producing bad coverage.

There is still a future case for #2 — specifically for projects where
the length-dependency family produces UNSAT under legitimate inputs
— but the immediate "0-skeleton problem" that motivated this analysis
is **resolved by #4 alone** for cjson and (predicted, pending live
run) for lcms.

Recommendation: do not implement #2 immediately. Add it only if a
later A/B reveals length-dep over-rejection or another constraint
family hard-rejecting valid sequences. The expert discussion in §6
remains relevant for future calibration but is no longer time-
critical.

---

## §7. References

- Bjørner, N. & Phan, A.-D. (2014). νZ - An Optimizing SMT Solver. *TACAS*.
- Solar-Lezama, A. (2008). *Program Synthesis by Sketching* (PhD thesis, UC Berkeley).
- Lynce, I. & Marques-Silva, J. (2004). On Computing Minimum Unsatisfiable Cores. *SAT*.
- Clarke, E. M., Grumberg, O., Jha, S., Lu, Y. & Veith, H. (2000). Counterexample-Guided Abstraction Refinement. *CAV*.
- Lang, K. J., Pearlmutter, B. A. & Price, R. A. (1998). Results of the Abbadingo One DFA Learning Competition. *ICGI*. (EDSM oracle convention.)
- SyGuS-IF standard: https://sygus.org/

LogicFuzz internal:
- `liberator_adapter/constraints/z3_solver.py` — current encoder
- `liberator_adapter/constraints/z3_guided_synthesis.py` —
  `UnsatCoreDiagnoser` (broken — uses `get_unsat_core` without
  `assert_and_track`)
- `CLAUDE.md` "Failed Attempts / Lessons" — the existing
  "papered over" workaround narrative
- Cache locations: `results/<project>/static_analysis/filtered_sequences.json`
