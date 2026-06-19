# InputSource Adapters — Symbolic Fuzz-Input Materialization — Design

Date: 2026-06-19
Status: Design (awaiting review)
Branch: pub-llm
Supersedes: the LLM-directive parts of `2026-06-19-idiom-aware-recall-repair-design.md`

## 1. Problem

Resource-opener APIs take an **input that is not a plain buffer** — a file path
(`gzopen(const char*)`), a `FILE*` (`png_init_io`), or an fd (`gzdopen(int)`). The
symbolic constructor can't bind these, so it renders them `NULL` → the driver exits
immediately (e.g. zlib: 7/22 gz\* drivers built, **0 live**; ~480 uncovered branches).

Two attempts to fix this by making the **LLM** render the `tmpfile→open` idiom both failed
(measured 2026-06-19, generation-only observation):
- **Hole-filling (R0/R1):** drivers came out **byte-identical to baseline** (`gzopen(NULL)`).
  The path arg renders as a fixed `= NULL` (no hole) and the idiom is multi-statement —
  hole-filling can't express it.
- **Free-write routing (R2):** fired 5×, but drivers were **still degenerate** (`gzopen(ret_gzerror, ret_gzerror)`, unfilled `HOLE[...]` markers). `has_skeleton_template=False`
  didn't produce clean free-write; the CALLSPEC still anchors the LLM to `arg0=NULL`, and the
  model ignored the directive.

**Root cause (the real lesson):** the file-I/O idiom is **structure**, not a leaf value.
This project's core division of labor is *"symbolic owns structure + construction; the LLM
fills leaf values only"* (the reason B-design beat A-design). Asking the LLM to author
multi-statement structure fights the architecture. And the prior fix was the **wrong
abstraction** — a gz-specific tmpfile render, not a reusable primitive.

## 2. The reframe

"Fuzz bytes → a resource" is **one general problem** with a few concrete target types, each
with a clean, deterministic, library-agnostic materialization. We render it **symbolically**
(valid-by-construction), keyed on the arg's **source type**:

| Source type (opener input arg) | Materialization |
|---|---|
| `FILE *` | `fmemopen((void*)data, size, "rb")` — in-memory, no disk, no cleanup |
| `const char *` path | unique `mkstemp` + `write(fd,data,size)` + `close` → pass the path |
| `int` fd | `memfd_create`/tmpfile fd + `write` + `lseek 0` → pass the fd |
| `void*/uint8_t* (+ size)` | pass `data,size` (existing buffer path — unchanged) |

One registry covers zlib `gz*`, `fopen`, libpng `png_init_io(FILE*)`, `fdopen`, … — not a
gz idiom.

## 3. Goals / Non-goals

**Goals**
- Symbolically materialize an opener's input-source arg (FILE\*/path/fd) from `data,size`,
  bind it, and register cleanup — valid-by-construction, no LLM.
- Reusable + type-driven (works across libraries; no per-idiom / per-name special cases).
- Revert the failed LLM-recall attempts; keep the ablation telemetry.

**Non-goals**
- No LLM rendering of the idiom (proven the wrong layer).
- No constraint-graph / producer-node surgery (standalone adapter consulted at render time;
  can graduate to a producer node later).
- Not plain buffer args (the existing INPUT_BUFFER path already handles those).
- No socket/network/callback sources (out of scope; the registry is extensible if needed).

## 4. Design — standalone symbolic adapter

### 4.1 `liberator_adapter/analysis/input_source.py` (new, pure)
- `classify_input_source(type_str: str, api_role, is_input_arg: bool) -> Optional[str]`
  Returns `"FILE_STAR"` / `"PATH"` / `"FD"` for an **opener/CREATOR input arg** of that
  type, else `None`. **Name-free, type-driven** (keys on `APIRole.CREATOR` + the type;
  never on `gz`/library names). Plain pointer+size buffers → `None` (existing path owns them).
- `materialize(kind: str, prefix: str) -> MaterializedSource` where `MaterializedSource` is a
  dataclass: `stmts: List[str]`, `bind_expr: str`, `cleanup: List[str]`, `includes: List[str]`.
  Per the §2 table. Each kind null-guards its result (e.g. `if (!{p}) return 0;` for fmemopen,
  `if ({p}_fd < 0) return 0;` for mkstemp).
- **Companion mode arg:** when the opener's source is `PATH`/`FILE_STAR` and a paired
  mode-string arg exists (`const char*` mode), `materialize` also returns its binding to a
  valid mode literal (`"rb"`) so the call is valid-by-construction (not raw fuzz bytes).

### 4.2 Integration in `skeleton_generator` (~ the `__lf_str_buf` rebind, lines 864-905)
When binding an arg that `classify_input_source` flags:
1. emit `materialize().stmts` as `BUFFER_DECL`/`BUFFER_INIT` statements **before** the call
   (same mechanism the `__lf_str_buf` entry-string rebind already uses);
2. set the arg's bound value to `bind_expr` (instead of `NULL`);
3. append `cleanup` to `skeleton.cleanup_statements`;
4. register `includes` on the skeleton.
Gated `LOGICFUZZ_INPUT_SOURCE` (default-on; A/B kill-switch).

### 4.3 Data flow
```
construct sequence → skeleton_generator binds args:
   classify_input_source(arg) ∈ {FILE_STAR, PATH, FD}?
     → materialize(): inject stmts (fmemopen | mkstemp+write | memfd) before call,
                      bind arg = bind_expr, add cleanup, register includes   [symbolic]
     → else: existing buffer/handle/NULL path (unchanged)
   → recall_ablation.json counts materialized args (telemetry kept)
```

## 5. Relationship to prior work (cleanup)
- **Supersede** `file_opener_intents` (R0): the `classify_input_source` type-detection
  replaces it. The `FILE_FROM_FUZZ` LLM value-intent + its emission in
  `value_intents_for_sequence` are **removed** (no longer an LLM directive).
- **Revert** R2 (the free-write routing in `prototyper.py`, commit `2a5a45ad`) — shown inert
  and harmful (unfilled-hole drivers).
- **Keep** `recall_ablation.json` + `count_*` telemetry (now counts input-source
  materializations) and the `tests/test_idiom_recall.py` scaffolding (repurposed).
- Net: the recall *idea* (target the idiom-gated openers) survives; the *mechanism* moves
  from "LLM directive" to "symbolic materialization."

## 6. Error handling / safety
- Fail-open: any `classify`/`materialize` error → fall back to the current `NULL` binding
  (no regression).
- Gated default-on with `LOGICFUZZ_INPUT_SOURCE=0` kill-switch (isolates the A/B lift).
- Load-bearing untouched: dead-driver merge filter, symbolic construction core, automaton.
- Cleanup is registered so tmpfiles are `unlink`ed and FILE\*/fd closed (no descriptor/disk
  leak under long fuzzing).

## 7. Testing
- **Unit** (`tests/test_input_source.py`):
  - `classify_input_source`: `FILE *`→FILE_STAR, `const char *`(opener)→PATH, `int`(opener
    fd)→FD; a `const uint8_t *`+size buffer→None; a non-CREATOR `const char *`→None.
  - `materialize`: FILE_STAR emits `fmemopen(...,"rb")` + null-guard + `fclose` cleanup +
    `<stdio.h>`; PATH emits `mkstemp`+`write`+pass-path + `unlink` cleanup; FD emits an fd
    materialization + `close` cleanup. Each `bind_expr` is non-NULL.
- **Integration (re-observe, generation-only, no fuzzing):**
  - zlib gz\* drivers come out with `mkstemp+write → gzopen(path,"rb")` (not `gzopen(NULL)`);
  - a `FILE*`-opener lib (libpng `png_init_io`) gets `fmemopen`.
  - `recall_ablation.json` materialized-count > 0 with the gate on, 0 with it off.

## 8. Risks
- **Portability of `fmemopen`/`memfd_create`** — both are glibc/POSIX; OSS-Fuzz builds are
  Linux/glibc, so available, but `materialize` must declare the exact includes (and
  `memfd_create` needs `<sys/mman.h>`; fall back to `mkstemp` fd if unavailable). The
  compile-validation gate ($CXX) catches any miss.
- **tmpfile churn under fuzzing** — `PATH`/`FD` write a temp file per input; mitigated by
  `unlink` cleanup + a unique per-driver name. `FILE_STAR` (fmemopen) avoids disk entirely —
  preferred whenever the API accepts `FILE*`.
- **Classifier false-positives** (a `const char*` that's really a string-to-parse, not a
  path) — gated on `APIRole.CREATOR` + opener shape, measured on zlib + libpng + c-ares to
  guard over-fit; fail-open.
- **Mode-arg pairing** — only emit the mode literal when a paired mode-string arg actually
  exists; otherwise leave the call as-is.

## 9. Forward-compat
The classifier + materializer are the substrate a future "synthetic producer node" version
(the deferred construction-graph integration) would reuse, and the registry is extensible to
new source kinds. Nothing here precludes that; the standalone render is the smallest correct
step.
