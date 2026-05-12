# Driver-vs-baseline diff — cjson run5 (2026-05-12)

First emergency-mode analysis per §10B of
`docs/knowledge_layer_design_proposal_2026_05.md`. Compares our
LogicFuzz-generated driver to the existing OSS-Fuzz driver hand-
written by the cJSON maintainers. The existing driver is the gold
standard; coverage below it = dropped context.

---

## §1. Side-by-side

### Our driver (cjson run5, Prototyper-from-scratch, ~54 LOC)

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    char *endptr = NULL;
    struct cJSON *json = cJSON_ParseWithOpts(input, &endptr, 0);
    if (!json) {
        free(input);
        return 0;
    }
    cJSON_HasObjectItem(json, "key");

    struct cJSON *array = cJSON_CreateArray();
    if (array) {
        cJSON_AddItemToObject(json, "array", array);
    }
    cJSON_AddBoolToObject(json, "flag", 1);

    char *printed = cJSON_Print(json);
    if (printed) {
        free(printed);
    }
    cJSON_Delete(json);
    free(input);
    return 0;
}
```

### Baseline (`cjson_read_fuzzer.c`, written by cJSON authors)

```c
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    cJSON *json;
    size_t offset = 4;
    int minify, require_termination, formatted, buffered;

    /* Input shape contract */
    if (size <= offset) return 0;
    if (data[size-1] != '\0') return 0;
    if (data[0] != '1' && data[0] != '0') return 0;
    if (data[1] != '1' && data[1] != '0') return 0;
    if (data[2] != '1' && data[2] != '0') return 0;
    if (data[3] != '1' && data[3] != '0') return 0;

    /* First 4 bytes encode 4 binary toggles */
    minify              = data[0] == '1' ? 1 : 0;
    require_termination = data[1] == '1' ? 1 : 0;
    formatted           = data[2] == '1' ? 1 : 0;
    buffered            = data[3] == '1' ? 1 : 0;

    /* Parse rest as JSON; require_termination from byte 1 */
    json = cJSON_ParseWithOpts((const char*)data + offset, NULL, require_termination);
    if (json == NULL) return 0;

    /* Two print-mode branches based on `buffered` */
    if (buffered) {
        printed_json = cJSON_PrintBuffered(json, 1, formatted);
    } else {
        if (formatted) {
            printed_json = cJSON_Print(json);
        } else {
            printed_json = cJSON_PrintUnformatted(json);
        }
    }

    /* minify branch (skipped from excerpt) ... */
    cJSON_Delete(json);
    if (printed_json) free(printed_json);
}
```

---

## §2. Lost context (what we dropped vs baseline)

| Dimension | Baseline | Ours | Loss |
|---|---|---|---|
| **Input encoding** | First 4 bytes = binary toggles `minify/require_termination/formatted/buffered`; bytes 4+ = JSON | All bytes = JSON content | **Huge** — baseline fuzzes 4 independent control dimensions per parse; we test 1 dimension (raw JSON only) |
| **Null-termination contract** | `data[size-1] == '\0'` required (cJSON expects C strings) | We `malloc` + force-null-terminate (works but doesn't exercise the malformed-non-null path) | Medium — different stress on the parser |
| **Print mode coverage** | `cJSON_PrintBuffered` + `cJSON_Print` + `cJSON_PrintUnformatted` + `cJSON_PrintPreallocated` (minify branch) — 4 print pathways | `cJSON_Print` only | **Huge** — 3 of 4 print pathways untouched |
| **Parse option** | `require_termination` varies per input | Hardcoded `0` | Medium — baseline exercises both null-terminated and non-null-terminated parse semantics |
| **Driver shape** | Pure parse+print exerciser of the read path | Adds `HasObjectItem` + `CreateArray` + `AddBoolToObject` (write path) | Mixed — we test write path the baseline doesn't, but at the cost of the parse-read variants |

**Bottom line**: our driver and the baseline have **almost orthogonal**
coverage targets. We test write-after-parse; baseline tests parse-then-
print across 4 mode variations. This is why `line_diff ≈ 0%` despite
us reaching 25.84% PC — the 25.84% is mostly the parse path that
overlaps with the baseline's 80%+ on parse code.

---

## §3. Why did we drop the context?

The Prototyper has `existing_driver_knowledge` injected (Step 12) —
including the full `cjson_read_fuzzer.c` source. **The LLM saw it
and chose to ignore the binary-toggle pattern**, opting instead to
"design fresh" with HasObjectItem / CreateArray / AddBoolToObject
calls.

Possible reasons:
1. **Prompt weighting**: `<existing_driver_knowledge>` block in the
   Prototyper prompt is presented as *reference*, not as *constraint*.
   The LLM treats it as inspiration, not as "match this pattern".
2. **L4 sequence dominance**: the L4-ranked target sequence pool
   pushed Prototyper toward `cJSON_HasObjectItem` /
   `cJSON_AddArrayToObject` etc. (which appear in the suggested
   `api_sequences`). The LLM followed the L4 hint at the expense of
   the existing-driver template.
3. **"Improve on it" bias**: LLMs default to "make it better" when
   shown an example. The baseline driver is succinct; the LLM may
   have read "succinct = simple = needs more API coverage" and
   added write-path APIs the baseline didn't have.

---

## §4. Recommended interventions

In rough order of effort:

### A. Strengthen `<existing_driver_knowledge>` to a constraint, not a reference

Promote the existing driver from "reference patterns" to "structural
template" in the Prototyper prompt. Concretely:

  > **The generated driver MUST preserve the existing driver's
  > input-encoding contract (byte 0..3 = toggles, byte 4+ = JSON
  > content) and MUST exercise all `print` variants the existing
  > driver uses. You may ADD new API calls beyond the baseline, but
  > the baseline pattern is the floor.**

Currently the prompt says (per `prototyper.py:1226+`):
`<existing_driver_knowledge>Learn from N existing OSS-Fuzz fuzz drivers.`
— "learn from" is too weak. Should be "preserve and extend".

### B. Score-gate the Prototyper output against the baseline

After Prototyper emits its driver, structurally diff against
`existing_driver_knowledge.driver_sources[0]`. If the new driver:
- Drops APIs the baseline calls → flag as regression
- Drops input-shape constraints (e.g., the `data[size-1] == '\0'`
  guard) → flag as regression

Re-prompt with the diff as feedback if regressions detected. This
is similar to the Improver rollback gate but at the source-structure
level instead of post-execution coverage level.

### C. Inject baseline coverage delta into the workflow

Per §10B of the design proposal: compare `new_cov / baseline_cov`
after execution. If `< 0.9`, route to a diagnostic step that
specifically compares our driver to the baseline and re-prototypes
with structural constraints. Implementation cost: medium (new
agent + new state field).

---

## §5. Cross-bench validation needed

This finding (LLM ignores existing driver structure) is one cjson
data point. To know if it's a pattern:
- Look at c-ares trial 01: did the generated driver follow the
  existing `ares-test-fuzz.c` structure, or freelance?
- Look at lcms trial 01: similar question.

If all 3 benches show the same "freelance" pattern → systemic
prompt-weighting issue → fix via A above. If only cjson →
benchmark-specific quirk → defer.

---

## §6. Relation to other open issues

- **Z3 over-rejection (cjson run5 finding)**: even if Z3 stops
  rejecting all candidates, the skeletons would still need
  structural-template-respect from the LLM. Z3 → skeleton →
  Prototyper. The LLM's freelance bias undermines all three.
- **T1 doxygen on doc-sparse projects**: T1 is upstream of this;
  doxygen-priors → Prototyper context. If Prototyper ignores
  existing-driver, it may also ignore doxygen-priors. Worth
  spot-checking on a doc-rich benchmark (cjson) whether the
  doxygen-derived ownership rules transferred to the trial-01
  driver code.

  **Actually yes** — looking at trial 01 output: it has `cJSON_Delete(json)`
  + `cJSON_free(printed)` which exactly mirrors the doxygen rule for
  cJSON_Parse + cJSON_Print outputs. So **doxygen content DID
  transfer**, while existing-driver pattern did NOT. Suggests the
  problem isn't "LLM ignores all priors" but "LLM weights priors
  unevenly: doc text >>> reference code structure".

This last observation is the most actionable: **the Prototyper
prompt treats doxygen text as authoritative and reference code as
optional**. Flip that emphasis.
