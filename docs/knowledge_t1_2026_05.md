# Knowledge layer T1 — doxygen + README priors (2026-05)

Implementation of T1 from
`docs/knowledge_layer_design_proposal_2026_05.md`. Two ground-truth
sources we previously ignored are now extracted and fed to the
Comprehender as deterministic priors:

  - **README** of the target project → replaces the LLM-from-project-
    name fabrication in `Comprehender.comprehend_purpose`
  - **Doxygen `/** */` comments** above public API declarations →
    short-circuit the LLM-from-signature fabrication in
    `Comprehender.comprehend_apis` when a substantive doc is present

Both extractors are opt-in via CLI flags (default OFF). This is
deliberate: the first 17-bench validation run should A/B compare T1
priors against the existing LLM-only baseline before defaults flip.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### Component map

| File | Role |
|---|---|
| `src/knowledge/project_docs.py` (new) | `extract_readme_purpose` + `extract_doxygen_comments` |
| `src/knowledge/cache.py` | New `load_docs_priors` / `save_docs_priors` methods; cache file `comprehension/docs_priors.json` |
| `src/knowledge/comprehender.py` | New `_doc_derived_usage` helper; `comprehend_apis` extended with `api_docstrings` parameter; layer chain now cache → deterministic → **doxygen** → LLM |
| `src/context/data_context.py` | Step 6b reads `use_doxygen_priors` / `use_readme_purpose` params, extracts both sources before invoking Comprehender, persists to cache |
| `src/runner.py` + `run_single_fuzz.py` | Plumb flags through `prepare()` |
| `run_logicfuzz.py` | New CLI flags `--use-doxygen-priors` / `--use-readme-purpose` |

### README extractor (`extract_readme_purpose`)

Locates the first README under `results/<project>/src_ossfuzz/<project>/`
matching `README.md` / `README` / `README.rst` / `README.txt` and a
few common casings. Strips markdown formatting (badges, headings,
code fences, tables, lists) and returns the first non-boilerplate
paragraph of 3-15 lines that contains purpose-like vocabulary
(`library`, `parser`, `implements`, `provides`, etc.).

Returns `None` when no README is found or no paragraph matches the
heuristic — the Comprehender falls back to its existing LLM-from-
project-name path (which today often produces a generic "<name>: a
C/C++ library" fallback when the LLM is unreachable).

### Doxygen extractor (`extract_doxygen_comments`)

Uses libclang (already in the static_trace toolchain — no new
dependency) to walk each header in `public_headers.txt`. For every
`FUNCTION_DECL` / `CXX_METHOD` cursor whose name is in the
project's API set, extract `cursor.brief_comment` (preferred — the
descriptive lead) or normalised `cursor.raw_comment`. The
normaliser strips `/* */` markers, per-line `*` prefixes, and stops
at the first `@param` / `\param` block — the goal is the
descriptive paragraph, not the parameter table (which we have via
signatures anyway).

Returns a `Dict[api_name, docstring]` covering only APIs with a
present, non-trivial doc. APIs without docs fall through to the
LLM path unchanged.

### Comprehender integration

`comprehend_apis` now has 4 layers instead of 3:

```
Layer 1: cache hit                          → reuse
Layer 2: deterministic (role / lifecycle)   → use static facts
Layer 3: doxygen-derived (T1 prior, opt-in) → use doc directly
Layer 4: LLM batched                        → fabricate from signature
```

Layer 3 only fires when `api_docstrings` was passed AND the doc is
≥40 chars (configurable via `_DOXYGEN_MIN_USEFUL_CHARS`). Below
that threshold, the doc is usually a single-word stub like
"Initialize" that the deterministic role-based usage already
captures better; we fall through to LLM.

`comprehend_purpose` already accepted a `doc_excerpts` parameter
(unused before this commit). Now wired from `extract_readme_purpose`.

### Caching

T1 priors are cached to
`results/<project>/comprehension/docs_priors.json` with shape:

```json
{
  "readme_purpose": "cJSON is a lightweight JSON parser...",
  "api_docstrings": {
    "cJSON_Parse": "Parse a JSON object...",
    "cJSON_Delete": "Free a cJSON tree and all its children..."
  }
}
```

Cache lookup happens first; libclang re-walking the headers only
happens on cache miss. Reruns are cheap.

### CLI surface

```bash
# Default (T1 priors off — current baseline behaviour)
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# T1 enabled — opt-in for A/B against baseline
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o \
    --use-doxygen-priors --use-readme-purpose

# Either flag can be enabled independently
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o \
    --use-doxygen-priors
```

---

## §2. Deferred — with rationale

### rST README full rendering

The README extractor strips simple markdown but doesn't render rST
(`.rst`) properly — it just treats it as plain text with
inline-formatting stripping. Most OSS-Fuzz target libraries use
markdown; the few that ship pure rST (some Python-adjacent C libs)
will produce slightly noisier excerpts. Empirical question whether
this matters on the 17-bench set; defer until we see a benchmark
where rST quality blocks signal.

### Doxygen inheritance / `\copydoc`

Some C++ libraries use `\copydoc`, `\see`, or inherit comments
across virtual methods. libclang's `brief_comment` doesn't follow
those references. Implementing full doxygen resolution requires
non-trivial AST traversal. Defer — the typical OSS-Fuzz target is
plain C where this doesn't apply.

### Test-file ingestion (G3 from previous review)

Listed in §6 T2 of the design proposal as a separate work item.
T1 leaves test files where they are (automaton training only); T2
will surface them as literal reference code to the Prototyper.
Sequenced after T1 lands and we observe the empirical signal from
README + doxygen alone.

### `comprehend_sequences` (Comprehender-B) doc augmentation

T1 only feeds priors into Comprehender-A (per-API usage). The
sequence-level Comprehender-B doesn't see docstrings. Deferred to
avoid scope creep — sequences are a function of API combination
semantics, where doxygen-per-API is a weaker signal than the
sequence-level acceptance score we already have from the
automaton.

---

## §3. Empirical validation — to be filled in

After the first 17-benchmark A/B run (T1 off vs T1 on):

### M2.1: README purpose hit rate

Hypothesis: ≥70% of OSS-Fuzz target libraries ship a README with a
purpose-like paragraph that our extractor finds. Spot-check by
grepping `results/<project>/comprehension/docs_priors.json` for
non-empty `readme_purpose` values across the bench.

If <50%, the heuristic in `_is_purpose_paragraph` needs to be
relaxed or we need rST rendering.

### M2.2: Doxygen API coverage

Hypothesis: distribution of `len(api_docstrings) / len(api_names)`
per project. Expected range: 10-80% depending on project doc
culture (zlib / libxml2 high; libucl / ffjpeg low).

If median <30% across the bench, the T3 RAG escalation in
`docs/knowledge_layer_design_proposal_2026_05.md` §6 becomes more
likely.

### M2.3: LLM-call reduction

Hypothesis: Comprehender-A LLM batches drop by ~30-50% on
doxygen-rich projects (zlib, libxml2). Measurable via the
`Comprehender-A: N APIs resolved from doxygen (LLM saved on these)`
log line emitted by the new layer-3 path.

### M2.4: Prototyper trial-1 compile success

This is the load-bearing downstream metric. Pre-T1: Prototyper
sees `(no usage available)` or LLM-fabricated usage strings.
Post-T1: Prototyper sees ground-truth doxygen text.

Hypothesis: trial-1 compile success rate on the 17-bench rises by
≥5% absolute. Below that, T1's content win didn't transfer to
output quality, and we should investigate before T2.

### M2.5: Crash quality

Secondary signal: are the trials that DO compile finding more real
crashes (vs false-positive ASan / memory leaks from misused
APIs)? Doxygen often documents ownership ("caller must free with
X") that the LLM was guessing at — better ownership awareness
should reduce false-positive memory crashes.

### M2.6: A/B decision gates

Per `docs/knowledge_layer_design_proposal_2026_05.md` §9, the
post-M2 decision is:

  - **Flip defaults ON** if M2.1 ≥ 70% AND M2.4 ≥ +5% absolute.
  - **Keep opt-in** if M2.1 ≥ 50% AND M2.4 ≥ +2% — useful for
    doc-rich projects but not unconditional.
  - **Stop, defer T2** if M2.4 < +2% — content priors didn't move
    the needle; structural index won't help either.
  - **Skip to T3 RAG** if M2.1 < 50% AND/OR M2.2 median < 30% —
    the projects don't ship enough doc content for keyword
    extraction; semantic retrieval may help.

---

## §4. Rollback recipe

T1 is opt-in by default, so rollback is "don't pass the flags". If
the flags themselves need to be removed:

1. Revert the `comprehender.py` changes:
   - Drop `_doc_derived_usage` helper
   - Drop `api_docstrings` parameter from `comprehend_apis`; remove
     the Layer-3 doxygen block
2. Revert `data_context.py` Step 6b additions:
   - Drop `use_doxygen_priors` / `use_readme_purpose` parameters
   - Drop the T1-prior extraction block
   - Drop the `doc_excerpts=` argument from `comprehend_purpose`
3. Revert `cache.py`:
   - Drop `save_docs_priors` / `load_docs_priors` methods
   - Drop `docs_priors_path` initialisation
4. Delete `src/knowledge/project_docs.py`
5. Revert CLI flag additions in `run_logicfuzz.py`, `src/runner.py`,
   `run_single_fuzz.py`
6. Optionally: delete cached `results/<project>/comprehension/
   docs_priors.json` files

Each step is independent — partial rollbacks (e.g., keep README
purpose, drop doxygen) work.

---

## §5. Operator notes for M2 validation

To produce A/B data for the §3 questions:

```bash
# Baseline run (T1 off)
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
mv results/cjson results/cjson_baseline

# T1 enabled run
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o \
    --use-doxygen-priors --use-readme-purpose
mv results/cjson results/cjson_t1

# Compare comprehender outputs
diff results/cjson_baseline/comprehension/api_usage.json \
     results/cjson_t1/comprehension/api_usage.json
cat results/cjson_t1/comprehension/docs_priors.json
```

Repeat across cjson + c-ares + libucl + libxml2 (rich-doxygen +
sparse-doxygen + indirect-entry-point + heavyweight covers the
4-quadrant signal space).
