# LFBackendDriver + merge_drivers refactor — 2026-05

Tenth in the 2026-05 refactor series. Paired audit of two related
surfaces:

  - **`liberator_adapter/backend/libfuzz/LFBackendDriver.py`** — the
    910-LOC C-fuzz-driver renderer, a near-clean fork of upstream
    `reference/liberator:framework/backend/libfuzz/LFBackendDriver.py`.
    Only 55 lines of real diff vs upstream (import rewiring +
    DriverEnhancer `stub_code` integration).
  - **`tools/merge_drivers/`** — the 1777-LOC PromeFuzz-style
    multi-task harness merger (purely adapter, no upstream
    equivalent).

The headline finding: **LFBackendDriver has been silently dead in
production**. The call site at `data_context.py:2339` read a never-set
attribute (`generator.public_headers_path`), the resulting `None`
crashed `LFBackendDriver.__init__` on every invocation, and the
surrounding `try/except` routed every CBFactory call to the
fallback renderer instead. The 910-LOC driver-emission machinery has
not actually run end-to-end since the rewire to
`extract_metadata['local']['public_headers']`. Once we fix the call
site, three latent bugs immediately become reachable — those are also
addressed here.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### A1 — `cleanbuffer_emit` GLOBAL fall-through (upstream-shared latent crash)

**Symptom.** `cleanbuffer_emit` only handled `AllocType.STACK` and
`AllocType.HEAP`. For any other allocation kind (`AllocType.GLOBAL`,
which `buffdecl_emit` happily admits), the function fell off the end
and returned `None`. Caller `stmt_emit` does
`"\t" + self.stmt_emit(stmt)` → `TypeError: can only concatenate str
(not "NoneType") to str`. Latent because LFBackendDriver was dead in
production.

**Fix.** `GLOBAL` shares HEAP's array-of-pointers layout (see
`buffdecl_emit`: both branches emit `T *token[1]...` + a `_shadow`
companion), so the cleanup shape is identical. Merged the branches.
Added an explicit `raise NotImplementedError(...)` on any unknown
`AllocType` so silent-None can't happen again.

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py`
`cleanbuffer_emit`.

### A2 — Resurrect LFBackendDriver in production (call-site rewire + Step 7 fail-fast + strict `__init__`)

**Symptom.** Three-layer failure:

  - **Layer 1** (`data_context.py:2339`): construction read
    `getattr(generator, 'public_headers_path', None)` — an attribute
    **never set anywhere** in the codebase. Always `None`.
  - **Layer 2** (`LFBackendDriver.__init__`): `with open(None, 'r')`
    raised `TypeError`.
  - **Layer 3** (`data_context.py:2342`): surrounding `try/except
    Exception` swallowed the crash with a debug log and silently set
    `backend = None`. Downstream emitted via
    `_render_driver_fallback`.

Net effect: every CBFactory-driven trial since the rewire to
`extract_metadata` has used the basic fallback renderer instead of the
real driver emitter. The dynamic-run validation for prior refactors
that touched `LFBackendDriver` (e.g. DriverEnhancer's
`stub_code` integration) was never actually exercised.

**Fix.** Three coordinated changes per the user's "root cause over
band-aid" directive (memory rule):

  1. **Step 7 fail-fast** (`data_context.py:903-960`). Replaced the
     silent-degrade-to-empty-list code with strict validation:
       - `generator.extract_metadata['local']['public_headers']` must
         be set.
       - The path must exist on disk.
       - The file must contain ≥1 non-empty entry.
     Any failure raises `ValueError` pre-LLM, pointing at the recovery
     path (re-run extraction or hand-populate the file).
  2. **Call-site rewire** (`data_context.py:2330-2350`). Now reads
     from the canonical `extract_metadata['local']['public_headers']`,
     drops the `try/except` swallowing. Step 7's fail-fast guarantees
     the path exists, so any subsequent `LFBackendDriver.__init__`
     failure is a real bug that surfaces.
  3. **Strict `__init__`**
     (`liberator_adapter/backend/libfuzz/LFBackendDriver.py:16-26`).
     Raises `ValueError` with a clear message on `public_headers=None`
     (defensive belt-and-suspenders — Step 7 should have caught it
     first; this catches programmatic callers that bypass Step 7).

The "public_headers must exist by this stage" contract is now
explicit at three points. There is no longer a code path where
LFBackendDriver receives `None` silently.

**Files.** `src/context/data_context.py` (Step 7 + Step 10 call
site), `liberator_adapter/backend/libfuzz/LFBackendDriver.py`
(`__init__`).

### A3 — Deterministic header walk

**Symptom.** `os.walk(headers_dir)` yields directory entries in
filesystem order, which differs across platforms / filesystems. The
resulting `#include` order in the synthesised driver was
non-deterministic per build. Repro-by-bytes for the synthesised
driver was unstable.

**Fix.** Wrap both `os.walk(...)` and the inner `f_names` with
`sorted(...)`. Headers are now emitted in lexicographic order.

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py:35`.

### A4 — `stmt_emit` raises with the unhandled type name

**Symptom.** Bare `raise NotImplementedError` told you nothing. Now
that LFBackendDriver is actually going to run, hitting an unhandled
Statement subclass will be common during early dynamic runs — the
error message needs to be actionable.

**Fix.** `raise NotImplementedError(f'stmt_emit: unhandled Statement
subclass {type(stmt).__name__}')`.

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py:367`.

### A5 — `emit_stub_functions` iterates list as if it were dict (upstream bug)

**Symptom.** `Driver.stub_functions` is typed `List[Function]`
(`liberator_adapter/driver/Driver.py:9`). `LFBackendDriver.
emit_stub_functions` iterated via `for _, f in stub_functions.items()`
— a dict-shaped iteration. On a list, that would raise
`AttributeError: 'list' object has no attribute 'items'`. The
dead-code status of the backend masked this. Both upstream and
adapter carried the same shape mismatch.

**Fix.** Iterate the list directly: `for f in stub_functions:`
(unused key dropped).

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py:103`.

### A6 — Remove dead `LFBackendDriver.drv` and `last_stmt` class attrs

**Symptom.** Two write-only class attributes — `last_stmt = None`
and `LFBackendDriver.drv = driver` (set in `emit_driver`) — were
never read anywhere in upstream or adapter. The `drv` write also
quietly retains the last emitted driver on the class for the
process lifetime; a mild memory hold-on.

**Fix.** Deleted both.

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py:147,
158` (both removed).

### A7 — `dyn{,dbl}arrinit_emit` error message wording

**Symptom.** `raise Exception(f"sizeof({buff_i}) is incomplete in
dyndblarrinit_emit!")` — but it's the *pointee type* that is
incomplete, not the value `buff_i`. Misleading when debugging.

**Fix.** Both error sites now spell out the incomplete pointee type
and which call site they came from.

**File.** `liberator_adapter/backend/libfuzz/LFBackendDriver.py:446,
652`.

### MM1 — `merge_drivers` dict-to-driver match uses exact stem only

**Symptom.** `__main__.py:286`: `p.name.startswith(d.driver_id)`. For
driver_id `"1"`, paths `10.dict`, `15.dict`, `100.dict` all match. The
first-hit `next(...)` returned an arbitrary collision-partner depending
on dict iteration order of the `user_dicts` set.

**Fix.** Match on `p.stem == d.driver_id` (exact) or
`p.stem == d.driver_path.stem` (exact). No prefix fallback.

**File.** `tools/merge_drivers/__main__.py:282-296`.

---

## §2. Deferred — with rationale

### MM2 — `select_top_k` tie-break clause-3 unreachable on first iteration

**Observation.** `best_name = ""` initial value makes `name < ""`
always False on first iteration, rendering the third tie-break clause
dead. Not a bug — the first iteration always updates via the
`gain > best_gain=-1` clause, so the third clause's first-call
unreachability doesn't change selection output. But the code is
hard to reason about.

**Why not fix.** Strictly cosmetic; rewrite would risk a subtle
behavioural shift in the tie-break order during dynamic runs. Defer
until we have a tie-break regression to motivate.

### P1 — `preflight` tempdir leak

**Observation.** `tempfile.mkdtemp(...)` is called without explicit
cleanup. Each `preflight()` invocation leaks `/tmp/merge_drivers_
preflight_*`.

**Why not fix.** Intentional per the module docstring — keeps the
preflight workspace around for inspection (`stderr.log`, `crashes/`,
`corpus/`). A real run on 17 benchmarks leaks ~17 dirs of a few MB
each, well below the system tmp budget. Defer.

---

## §3. Empirical validation — to be filled in

After the 17-benchmark dynamic run:

### A2: LFBackendDriver actually executing

  - **Without the fix**: every CBFactory trial used
    `_render_driver_fallback` — the simple libfuzzer skeleton that
    just rendered `// TODO: Add <project> headers` + `LLVMFuzzerTestOneInput`
    + statement-`str()` calls.
  - **With the fix**: trials should emit the real LFBackendDriver
    output — `#include` block, `emit_defines` macros, callback stubs
    via `emit_stub_functions`, `emit_driver` with the full statement
    machinery (BuffDecl → BuffInit → ApiCall → CleanBuffer chain).
  - **A/B win condition**: at least one project's first-trial driver
    differs from `_render_driver_fallback` output bytes — confirmable
    by grepping the generated driver for `MIN_SEED_SIZE` (a
    `emit_defines` macro that the fallback never emits).

### Step 7 fail-fast surfacing a previously-hidden failure

Run with `--disable-llvm-extraction` (or simulate by deleting the
generated `public_headers.txt`). Expected: prepare() raises
`ValueError("... no public_headers ...")` at Step 7. Pre-fix: ran to
completion with an empty `project_headers` list, downstream LLM saw
no `#include` hints, compilation always failed.

### A1: GLOBAL cleanup-buffer reachable now

If any benchmark has a GLOBAL-allocated buffer that needs cleanup,
pre-fix the synthesised driver would crash with `TypeError`. Now it
emits the `_shadow`-guarded cleanup. Spot-check via grep for
`_shadow` in driver output where the buffer was global.

### A5: stub_functions iteration

If any benchmark has callback stubs, pre-fix the renderer would crash
with `AttributeError` on `.items()`. Now it emits each stub via the
list iteration. Spot-check via grep for `// Default callback stub` or
`// Enhanced callback stub` in driver output.

### MM1: dict routing

Pass two dicts `1.dict` and `10.dict` to a pipeline with sub-drivers
`01` and `10`. Pre-fix: `10.dict` might be routed to sub-driver `01`
(startswith). Post-fix: each dict goes to its exact-stem partner.

---

## §4. Rollback recipe

If A2 needs to be rolled back (e.g. Step 7's strictness breaks a
project where public_headers can legitimately be empty):

  - Restore the soft-degrade behaviour in Step 7: replace the
    `raise ValueError(...)` blocks with the previous
    `if/elif` chain that fell back to an empty
    `project_headers` list.
  - Restore the call-site `getattr(generator, 'public_headers_path',
    None)` and re-wrap with `try/except Exception` at Step 10.
  - Optionally restore `__init__`'s tolerance of `None` (treat as
    empty header set).

If A1 needs to be rolled back: change the `elif` back to `elif
buff.alloctype == AllocType.HEAP:` and remove the `else: raise`.

If A3/A4/A5/A6/A7 need to be rolled back: each is a self-contained
edit; revert the specific hunk.

If MM1 needs to be rolled back: restore the `or p.name.startswith(d.driver_id)`
fallback clause. Note: the rollback re-introduces the `1` vs `10`
collision.
