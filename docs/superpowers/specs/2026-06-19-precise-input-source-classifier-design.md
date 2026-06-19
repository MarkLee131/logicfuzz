# Precise Input-Source Classifier (Slice 1 correction) — Design

Date: 2026-06-19
Status: Design (awaiting review)
Branch: pub-llm
Corrects: `2026-06-19-refine-holes-slice1-design.md` (the InputSource classifier + binding)

## 1. Problem (measured)

The Slice-1 `classify_input_source` is too loose, so it can't ship default-on and it
doesn't deliver breadth either:

- Measured across all 10 benchmark libraries' real API models: it fires on **69 APIs**,
  of which **~40+ are false positives** on *content* parsers, not file openers —
  `cJSON_Parse`/`cJSON_ParseWithOpts` (JSON content), `ares_dns_pton`/`ares_expand_name`
  (DNS strings), `sqlite3_recover_init`, and `cmsCreateExtendedTransform`
  (`cmsHPROFILE *` — `"FILE" in t` matched **pro·FILE**).
- Two defects: `"char" in t` matches *any* `char*` (can't tell a filename from content);
  `"FILE" in t` is a case-sensitive substring (matches `cmsHPROFILE`).
- Default-**on** would re-route those core parsers to a temp-file path → regression.
  Default-**off** abandons the goal (breadth). Both are unacceptable.

The genuine file-openers are **~12-15** across all libs, but each is **high-leverage** — it
gates a whole subsystem: `gzopen` unlocks the entire `gz*` family (gzread/gzwrite/gzgets…,
~480 zlib branches); `pcap_open`/`pcap_*_offline` unlock libpcap parsing;
`cmsIT8LoadFromFile` unlocks lcms IT8. The breadth is real **iff** the classifier is precise.

## 2. Goal / Non-goals

**Goal:** a classifier precise enough to be **default-ON without regression** — it
materializes a file *only* on a positive file signal, and defaults to "content/no-op"
(the existing safe behavior) otherwise. Captures the genuine high-leverage openers.

**Hard constraint:** ship **default-ON**. A kill-switch exists only for A/B measurement;
"build it then default-off" is explicitly rejected.

**Non-goals:** socket/network sources; `int` fd unless a clear fd signal; any change to the
dead-driver filter / automaton.

## 3. Design — safe-by-default, three-layer judgment (symbolic⊕neural)

Invert the current logic: the default is **not a file**; only a positive signal upgrades an
arg to materialization.

### Layer 1 — `FILE *` (symbolic, certain)
Match the type as a **token**, not a substring: `FILE *` / `FILE*` where the bare type name
is exactly `FILE` (so `cmsHPROFILE *` does NOT match). → materialize `fmemopen`. A `FILE*`
arg cannot be content → always safe, default-on.

### Layer 2 — `char *` with a positive file-open signal (symbolic)
Materialize a `char*` path **only** when a file-open signal is present:
- the API **name** matches `(?i)(^|_)(f?open|load.*file|.*from_?file|add_file|.*cubefile|.*iohandler)\b`
  (covers `gzopen`, `gzopen64`, `pcap_open`, `pcap_dump_open`, `cmsIT8LoadFromFile`,
  `cmsOpenIOhandlerFromFile`, `cmsCreateDeviceLinkFromCubeFile`, `ucl_parser_add_file`), OR
- a `@param` doc for that arg contains `filename`/`file name`/`path`/`pathname`.
→ materialize `mkstemp`+write. Measured: every genuine opener matches; **no** measured
false positive (cJSON/ares/sqlite/cmsHPROFILE) matches.

### Layer 3 — `char *` residual ambiguity (neural)
For a CREATOR `char*` with **no** Layer-2 signal (the genuinely ambiguous case), consult the
**Comprehender**: it already does per-API LLM semantic extraction; add a per-pointer-arg
judgment `input_kind ∈ {FILE_PATH, CONTENT, OTHER}`. Carry it on `ArgSemantics`
(`input_kind`, default `OTHER`/absent). `classify_input_source` materializes **only** when
`input_kind == FILE_PATH`; otherwise → content (default-safe). This is the symbiosis: the
LLM resolves "filename vs content" (it knows `cJSON_Parse` is content, an unusually-named
opener is a path); the symbolic layer renders. Neural false-positive risk is bounded by
"default to content unless positively FILE_PATH," and measured by the oracle (§5).

### `classify_input_source` final shape
`(kind, confidence)` where:
- `FILE *` → `(FILE_STAR, HIGH)`
- `char*` + Layer-2 signal → `(PATH, HIGH)`
- `char*` + Layer-3 `input_kind==FILE_PATH` → `(PATH, MED)`
- else → `None` (content/no-op, the safe default)
Inputs: `(type_str, api_role, api_name, arg_doc, arg_input_kind, arg_role)`. Still keyed on
`APIRole.CREATOR`; INPUT_BUFFER arg-role still excluded.

## 4. Binding fix (so the materialized path actually reaches the call)
Even with a correct classifier, the materialized `src_path` must become the call arg. Today
the entry-buffer rebind (`__lf_str_buf`, `skeleton_generator.py:~864-905`) reassigns the
opener's `char*` to the raw fuzz buffer, overriding the materialization. Fix: when an arg is
input-source-materialized, **suppress the `__lf_str_buf` rebind for that arg** (the
materialized `bind_expr`/RefineHole wins), so `gzopen(src_path, "rb")` is what renders — not
`gzopen(__lf_str_buf)`.

## 5. Precision oracle (the test that justifies default-ON)
A cross-library unit test (`tests/test_input_source_precision.py`) drives the measurement as
an assertion, from the committed `results/*/state/api_semantic_model.json` fixtures (or
inline minimal API records):
- **MUST classify** (genuine openers): `gzopen`, `gzopen64`, `pcap_open`,
  `pcap_fopen_offline`, `cmsIT8LoadFromFile`, `cmsOpenIOhandlerFromFile`,
  `ucl_parser_add_file`.
- **MUST NOT classify** (content/handles): `cJSON_Parse`, `cJSON_ParseWithOpts`,
  `cJSON_CreateString`, `ares_dns_pton`, `ares_expand_name`, `cmsCreateExtendedTransform`
  (`cmsHPROFILE *`), `sqlite3_recover_init`, `inflateBackInit_`.
This is both the regression net and the evidence that default-on is safe.

## 6. Default-ON + measurement
`LOGICFUZZ_INPUT_SOURCE` and `LOGICFUZZ_REFINE_HOLES` default **ON**. The kill-switch stays
ONLY for A/B coverage measurement (off-arm = the inert baseline). No default-off ship state.

## 7. Error handling / safety
- Default-safe by construction: no positive signal → no materialization → existing behavior.
- Fail-open: classify/materialize/Comprehender error → treat as content (no materialization).
- Layer 3 (neural) absent (no Comprehender field) → Layers 1-2 still work (graceful
  degradation); the feature is useful symbolic-only and is *enhanced* by neural.
- Load-bearing dead-driver filter / automaton untouched.

## 8. Testing
- **Precision oracle** (§5) — the headline.
- **Layer 1 unit:** `FILE *`→FILE_STAR; `cmsHPROFILE *`→None (token, not substring).
- **Layer 2 unit:** name-signal openers→PATH; a CREATOR `char*` with no signal + no
  Comprehender verdict→None.
- **Layer 3 unit:** with `arg_input_kind="FILE_PATH"`→PATH; `"CONTENT"`/absent→None.
- **Binding unit:** an input-source-materialized arg is NOT also `__lf_str_buf`-rebound
  (assert the rendered skeleton binds the materialized expr, not the raw buffer).
- **Integration (generation-only, opt-in):** zlib gz\* drivers render `mkstemp+write →
  gzopen(src_path,"rb")` (path actually bound); cjson `cJSON_Parse` stays
  `cJSON_Parse(data-as-content)` (NOT a tmpfile) — the no-regression proof.

## 9. Risks
- **Name-signal misses an oddly-named opener** → Layer 3 (neural) is the backstop; worst
  case it stays content (no regression, just no breadth for that one).
- **Neural false-positive** (says FILE_PATH for content) → bounded: only fires for
  no-signal residual `char*`, default-to-content, and the oracle guards the known cases;
  measured per-lib.
- **Comprehender cost** — one extra per-arg judgment folded into the existing per-API LLM
  call (no new call site); Layer 1-2 need no LLM.

## 10. Relationship to Slice 1
Supersedes Slice-1's loose `classify_input_source` (Layers replace the `"char"/"FILE" in t`
rules) and adds the binding-suppression fix + the precision oracle. The `RefineHole` +
materializer + skeleton wiring from Slice 1 are reused unchanged. Net: the input-source
optimization becomes **default-ON, breadth-positive, regression-free** — the whole point.
