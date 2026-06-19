# Refine-Holes (Slice 1): Confidence-Routed Symbolic⊕Neural Construction — Design

Date: 2026-06-19
Status: Design (awaiting review)
Branch: pub-llm
Supersedes: `2026-06-19-idiom-aware-recall-repair-design.md` and
`2026-06-19-input-source-adapters-design.md` (both folded in as the first producer here).

## 1. Problem & principle

The tool's core is **strong-strong symbiosis of symbolic + neural** — each method on the
sub-problem it is best at. Two prior attempts mis-applied neural: they asked the LLM to
*render structure symbolic had already identified* (the gz\* file-I/O idiom) — once via
hole-filling (inert: `gzopen(NULL)`), once via free-write (degenerate + unfilled holes).
Lesson: **certain structure → symbolic; uncertain semantics → neural; and the hand-off must
preserve the symbolic backbone.**

The integration model: symbolic construction **over-approximates** (best-guess render for
every binding) and attaches a **per-decision confidence**. Confidence routes the
symbolic↔neural boundary *per instance*, and the boundary is **enforced by the existing hole
mechanism** (the prototyper merge already edits *only* holes):
- **HIGH confidence → no hole** — final symbolic render; neural never touches it.
- **LOW confidence → a refine-hole** — symbolic's best guess is the hole's *default*, with a
  `fill_reason` stating the doubt; the prototyper may **keep or replace** it, but *only*
  within the hole (backbone preserved by construction).

Slice 1 builds the framework core **plus the first producer (InputSource materialization)**,
which delivers the gz\* win and the reusable machinery slices 2–3 reuse.

## 2. Goals / Non-goals

**Goals**
- A **refine-hole**: a hole carrying symbolic's best-guess default + a doubt reason, edited
  only via the existing merge (structural "refine-only-here" guarantee).
- **Confidence routing** in `skeleton_generator`: high-confidence binding → final render;
  low-confidence → refine-hole.
- **First producer — InputSource materialization** (symbolic): `FILE*`→`fmemopen` (in-memory),
  `const char*` opener path→`mkstemp`+write, rendered valid-by-construction; the *ambiguous*
  cases become refine-holes for neural verification.
- Reusable + library-agnostic (type-driven, name-free).

**Non-goals (later slices)**
- Caller-alloc NULL structs (`z_stream`) — slice 2.
- General value-domain refine-holes — slice 2.
- **Neural discovery of missing workflows** (synthesize-regions, no structural evidence) —
  slice 3.
- `int` fd materialization unless a strong fd-signal exists (too ambiguous; see §4.3).

## 3. Design — framework core

### 3.1 Refine-hole (`liberator_adapter/driver/synthesis/hole.py`)
New `RefineHole(Hole)` (sibling of `ComplexHole`, which already means "needs LLM semantic
reasoning"):
- fields: base `kind = HoleKind.REFINE` (add to the enum), `name`, `default_value: str`
  (symbolic's best-guess code), `fill_reason: str` (the doubt), `code_context: str`.
- `get_placeholder() -> f"__REFINE_{self.name}__"`.
- Renders in the skeleton as the **default code immediately followed by the marker comment**
  so a non-refining pass still compiles:
  `"<default_value> /* __REFINE_<name>__: <fill_reason> */"`.

### 3.2 Confidence routing in `skeleton_generator`
A binding site computes a confidence; on LOW it creates a `RefineHole(default=<best-guess>,
fill_reason=<doubt>)` and registers it in the skeleton's `HoleSet` (instead of a silent NULL
or a fixed guess). HIGH → render final. The InputSource producer (§4) is the first caller.

### 3.3 Prototyper refine-merge contract (`src/agents/prototyper.py`)
Refine-holes are surfaced in the holes description as: *"This region already has a
best-effort value (shown). REASON FOR DOUBT: <fill_reason>. KEEP it if correct, or REPLACE
it (you may use multiple statements). Do NOT touch anything outside the marked region."*
The existing `_parse_hole_fillings` + `_merge_holes_into_skeleton` apply the filling **only**
to the hole's marker → the "refine only flagged regions" guarantee is by construction, not by
prompt. If the LLM returns no filling for a refine-hole, the **default stands** (fail-open).

## 4. Design — first producer: InputSource

### 4.1 `liberator_adapter/analysis/input_source.py` (new, pure)
- `classify_input_source(type_str, api_role, is_input_arg) -> Optional[Tuple[str, str]]`
  → `(kind, confidence)` where `kind ∈ {FILE_STAR, PATH, FD}`, `confidence ∈ {HIGH, LOW}`;
  `None` for plain buffers / non-openers. Name-free, type-driven:
  - `FILE *` on an opener/CREATOR → `(FILE_STAR, HIGH)` (type is unambiguous).
  - `const char *` on a CREATOR (not the INPUT_BUFFER) → `(PATH, LOW)` (path-vs-content
    ambiguous → refine).
  - `int` → only `(FD, LOW)` when a paired fd-signal exists (param doc/name); else `None`.
- `materialize(kind, prefix) -> MaterializedSource{stmts, bind_expr, cleanup, includes}`
  | kind | stmts | bind | cleanup | includes |
  |---|---|---|---|---|
  | FILE_STAR | `FILE* {p}=fmemopen((void*)data,size,"rb"); if(!{p}) return 0;` | `{p}` | `if({p})fclose({p});` | `<stdio.h>` |
  | PATH | `char {p}[]="/tmp/lf_XXXXXX"; int {p}_fd=mkstemp({p}); if({p}_fd<0) return 0; write({p}_fd,data,size); close({p}_fd);` | `{p}` | `unlink({p});` | `<stdlib.h>,<unistd.h>` |
  | FD | memfd/tmpfile fd + write + lseek 0 | `{p}_fd` | `close({p}_fd);` | `<unistd.h>` |
  - Paired mode-string arg (if any) bound to `"rb"`.

### 4.2 Wiring (mirror the `__lf_str_buf` rebind, `skeleton_generator.py:~864-905`)
For an arg `classify_input_source` flags:
- emit `materialize().stmts` as `BUFFER_DECL/INIT` statements before the call; bind the arg to
  `bind_expr`; add `cleanup`; register `includes`.
- **HIGH confidence (FILE_STAR):** render final (no hole).
- **LOW confidence (PATH/FD):** wrap the materialization as a `RefineHole` — default = the
  materialized stmts+bind, `fill_reason` = *"rendered arg as a temp-file path written from
  the fuzz bytes; verify this API takes a filename (not raw content); if it wants content,
  bind `data,size` directly."*

### 4.3 Confidence rationale
`FILE*` is type-certain → final. `const char*` could be a filename *or* a string to parse →
the LLM resolves it (neural's strength) but only verifies/edits the bounded hole. `int` fd is
the most ambiguous → off unless a fd-signal is present.

## 5. Data flow
```
construct sequence → skeleton_generator binds args:
   classify_input_source(arg) → (kind, conf)?
     HIGH → materialize() rendered FINAL (FILE*→fmemopen)            [pure symbolic]
     LOW  → RefineHole(default=materialize(), reason="path vs content") [symbolic best-guess]
     none → existing buffer/handle/NULL path (unchanged)
   → prototyper: refine-holes presented "keep or replace, bounded"; merge edits only holes
   → recall_ablation.json counts {final_materializations, refine_holes by reason}
```

## 6. Relationship to prior work (cleanup)
- **Supersede** `file_opener_intents` (R0 — replaced by `classify_input_source`); **remove**
  the `FILE_FROM_FUZZ` LLM value-intent emission in `value_intents_for_sequence`.
- **Revert** R2 free-write routing (`prototyper.py`, commit `2a5a45ad`) — replaced by the
  refine-merge contract.
- **Keep** `recall_ablation.json` + `tests/test_idiom_recall.py` scaffolding (repurposed to
  count materializations + refine-holes).

## 7. Error handling / safety
- Fail-open at every layer: classify/materialize error → current NULL binding; refine-hole
  with no neural filling → default stands; merge error → skeleton unchanged.
- Gated `LOGICFUZZ_INPUT_SOURCE` (default-on) + `LOGICFUZZ_REFINE_HOLES` (default-on) — A/B.
- Load-bearing untouched: dead-driver merge filter, symbolic construction core, automaton.
- Cleanup registered (unlink/fclose/close) → no fd/disk leak under long fuzzing.

## 8. Testing
- **Unit `tests/test_refine_hole.py`:** `RefineHole.get_placeholder` + render (default code +
  marker); a merge that fills the marker REPLACES only that region and leaves the rest
  byte-identical; a merge with no filling leaves the default.
- **Unit `tests/test_input_source.py`:** `classify_input_source` → `(FILE_STAR,HIGH)` for
  `FILE*`, `(PATH,LOW)` for a CREATOR `const char*`, `None` for a buffer/non-opener;
  `materialize` emits compilable stmts + bind + cleanup + includes per kind.
- **Integration (re-observe, generation-only, NO fuzzing):** zlib gz\* drivers come out with
  `mkstemp+write → gzopen(path,"rb")` wrapped in a refine-hole (default present); a `FILE*`
  opener (libpng `png_init_io`) gets a final `fmemopen`. `recall_ablation.json` shows
  materializations > 0 with the gate on, 0 off.

## 9. Risks
- **`fmemopen`/`memfd` portability** — glibc/POSIX; OSS-Fuzz is Linux/glibc. `materialize`
  declares exact includes; the $CXX compile-validation gate catches misses; FD falls back to
  `mkstemp`.
- **Refine-hole bypass** — the LLM editing outside the marker would break the backbone;
  mitigated because the merge only substitutes hole markers (a returned full-file is rejected
  by the hole-merge path). Unit-tested in §8.
- **Classifier false-positives** (a parse-string `const char*`) — that's *why* PATH is a
  refine-hole, not a final render: neural resolves it. Measured on zlib+libpng+c-ares.
- **tmpfile churn** — `unlink` cleanup + prefer `fmemopen` (no disk) whenever the API takes
  `FILE*`.

## 10. Forward-compat (slices 2–3)
The `RefineHole` + confidence-routing + refine-merge are the shared machinery. Slice 2 adds
producers (caller-alloc NULL structs, value-domains) that emit final renders or refine-holes
by the same rule. Slice 3 adds **synthesize-regions** (a hole kind with *no* default —
"neural, propose a driver for this uncovered API/workflow") validated by Z3/typestate. The
`fill_reason` telemetry already maps where symbolic is weak, seeding slice 3's targeting.
