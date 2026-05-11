# Upstream Liberator issues fixed in the adapter

Bugs / limitations that exist in upstream `reference/liberator`
(HexHive/liberator main) and that the adapter has fixed (or has a
clear path to fix). Each item documents what upstream does, why it's
wrong, and what the adapter port does instead.

Recorded so:
- We don't re-introduce these bugs when porting future upstream
  changes.
- Future audits / upstream PRs can be sourced from this list.

This file deliberately *does not* track adapter-side bugs (i.e. bugs
in code we wrote that has no upstream counterpart). Those are
work-in-progress fix items, not divergence notes.

---

### CBFactory had `IPython embed; exit(1)` traps in the production hot path

Upstream `framework/driver/factory/constraint_based/CBFactory.py` falls
into `print(...); from IPython import embed; embed(); exit(1)` from at
least four places: two inside `try_to_instantiate_api_call` on
`set_pos_arg_var` exceptions (var-len arg, and b_len arg), and two
inside `create_random_driver` ("[ERROR] Cannot instantiate the first
function ..."). Any of them aborts the whole campaign on a single
problematic API.

**Now (adapter):** the four fatal traps are replaced with
`logger.warning(...) + raise` (or backtracking). On total failure,
`create_random_driver` returns a *partial driver* with `len(drv)`
calls instead of crashing — letting the rest of the trial proceed.

### CBFactory: no rescue when a source API has unsat dependencies

Upstream picks one source API (`get_random_source_api()`); if
`try_to_instantiate_api_call` returns unsat vars, it goes to the
IPython trap above. There is no second source-API try, no init-chain
search.

**Now:** `_try_all_source_apis` ranks all sources (Z3-guided when
enabled) and picks the best. For the best candidate, it calls
`_try_find_init_chain`, which walks `_build_type_producer_map` to
prepend producers for unsatisfied opaque-pointer args. The search is
bounded (`max_depth=3`, `visited` cycle break) and Z3-checkpointed so
rejected sub-chains roll back cleanly.

### CBFactory: callbacks default to NULL / generic stubs

Upstream `try_to_instantiate_api_call` resolves
`PointerType.to_function` args via `rng_ctx.get_function_pointer(...)`
— a single generic stub. Real-world callbacks (qsort comparators,
libfuzzer reader/writer, allocator) need shape-correct stubs that
actually return useful values.

**Now:** `_get_enhanced_function_pointer` consults `DriverEnhancer`
first, which classifies the callback (comparator/handler/reader/...)
and emits a typed stub via `CallbackStubLibrary` (in
`liberator_adapter/driver/synthesis/hole_filler.py`). Falls back to
the upstream generic pointer only if DriverEnhancer is unavailable.
The new fields `Function.stub_code` and `Function.callback_type` (the
17-line delta over upstream `framework/driver/ir/Function.py`) carry
the resulting code through.

### CBFactory: VarLen relationship taken only from static analysis

Upstream uses `arg_cond.len_depends_on` (LLVM-derived). When the
analysis misses a relation (common for indirect entry-point APIs),
the buffer/length pair is decoupled and the generated driver passes
mismatched sizes.

**Now:** if `arg_cond.len_depends_on == ""`, `try_to_instantiate_api_call`
falls back to `DriverEnhancer.get_buffer_size_constraint(api, pos)`,
which runs `VarLenAnalyzer` heuristics (name patterns, type pairs).

### Factory.normalize_type aborts on C++ template-aliased pointer types

Upstream `framework/driver/factory/Factory.py` raises
`Type '<name>' seems a pointer while expecting a 'val'` whenever LLVM
reports `flag="val"` for a type whose textual form contains `*` (which
happens often for C++ STL aliases and template instantiations).

**Now:** the adapter logs at debug level and silently flips the flag
to `"ref"`. Ditto for `a_is_const` shorter than expected — out-of-range
indices fall back to `False` rather than `IndexError`. (See `Factory.py`
diff vs upstream — line ~52.) ⚠️ The DataLayout calls were also
wrapped in `try/except → 0/False/PRIMITIVE`; that one *does* violate
"No fallbacks" and should be tightened (open TODO).

### Upstream's `dgraph` is inverted before use; original direction is dropped

Upstream `__init__` only keeps the inverted dependency graph
("inv_dep_graph"). The original direction is lost, so backward search
("who produces a value of type T?") is impossible.

**Now:** the adapter keeps `self.original_dep_graph` *and*
`self.dependency_graph` (inverted), and `_build_type_producer_map`
indexes return-types → APIs separately. `find_producer_apis`
prioritises source APIs and supports "drop pointer suffix" loose
matching.

### No Z3 / no acceptance gate

Upstream is purely Python-symbolic: each candidate is checked by
`RunningContext.try_to_get_var` against a hand-coded condition
manager. There is no SMT layer, no global feasibility check, no
typestate gate.

**Now:** `liberator_adapter/constraints/z3_solver.py` adds
`IncrementalZ3Solver` (push/pop checkpointed) and
`Z3SequenceValidator` (post-hoc full-sequence check).
`z3_guided_synthesis.py` adds `Z3GuidedSynthesisController` for
candidate ranking with unsat-core diagnosis, plus
`AutomatonAcceptanceGuard` (Phase H) that hard-prunes proposals whose
project-automaton acceptance score falls below
`automaton_threshold`. See `docs/automaton.md`.

### Skeleton-with-holes path is net-new

Upstream's only output is a fully-rendered `Driver`. There is no
intermediate "structurally correct, holes for the LLM to fill"
artefact, which means LLM refinement either generates from scratch
(losing the symbolic guarantees) or post-edits a complete driver
(losing the holes signal).

**Now:** `create_skeleton_for_sequence` →
`_compute_arg_bindings_via_running_context` →
`SkeletonGenerator.generate(arg_bindings=...)`. The skeleton is
Z3-validated (so structurally feasible); producer→consumer wiring is
computed by upstream `RunningContext.try_to_get_var` and rendered as
`ret_<prev_api>` references; only callbacks / buffer sizes / loop
conditions remain as `__HOLE_*__` placeholders for the LLM. See
`liberator_adapter/driver/synthesis/`.

### Backend renderer (`framework/backend/libfuzz/LFBackendDriver.py`)

Upstream's `LFBackendDriver` carries several latent bugs that the
adapter has now fixed (2026-05 backend refactor). All shared
because the adapter is a near-clean fork of upstream's file (~55
lines of diff vs ~895 LOC):

  - **`cleanbuffer_emit` falls through on `AllocType.GLOBAL`** —
    returns `None`, which crashes the caller `stmt_emit`'s
    `"\t" + None` string concat with `TypeError`. Upstream
    `buffdecl_emit` admits GLOBAL buffers, so a `CleanBuffer` on a
    global buffer is a reachable code path that crashes the
    renderer. **Now:** GLOBAL is folded into the HEAP branch (same
    array-of-pointers + `_shadow` layout); unknown alloctypes raise
    explicitly.
  - **`emit_stub_functions` iterates a `List` as a `Dict`** —
    `Driver.stub_functions` is typed `List[Function]`, but the body
    does `for _, f in stub_functions.items()`, which raises
    `AttributeError` on a list. **Now:** iterates the list
    directly.
  - **`os.walk` non-deterministic order** — driver `#include` order
    depends on filesystem entry order, breaking
    repro-by-driver-bytes. **Now:** `sorted(os.walk(...))` +
    `sorted(f_names)`.
  - **Dead class attributes `last_stmt = None` and
    `LFBackendDriver.drv = driver`** — set but never read; the
    `drv` write also retains the most-recently-emitted driver on
    the class for the process lifetime. **Now:** removed.
  - **`stmt_emit` raises bare `NotImplementedError`** — no info on
    which `Statement` subclass was unhandled, expensive to debug.
    **Now:** `NotImplementedError(f'stmt_emit: unhandled {type(stmt).__name__}')`.
  - **`dyn{,dbl}arrinit_emit` error wording** — error message says
    `sizeof({buff_i}) is incomplete` but it's the *pointee type*
    that is incomplete. **Now:** the error spells out the incomplete
    pointee type.

These were all masked in production by the adapter's call-site bug
(reading a never-set attribute `generator.public_headers_path` → None
→ `LFBackendDriver.__init__` crash → silent fallback to
`_render_driver_fallback`). The 2026-05 backend refactor fixed the
call-site bug and the six latent upstream issues in the same commit;
see `docs/backend_merge_refactor_2026_05.md`.

### IR / Statement substrate (`framework/driver/ir/`)

Upstream Liberator's Statement IR ships several latent bugs that the
adapter fixes in the 2026-05 IR refactor. All masked in production
because LFBackendDriver was dead (caller bug on `public_headers_path`
attribute, fixed in the 2026-05 backend refactor):

  - **`Buffer.get_allocated_size` ships an uncommented IPython
    embed** for the `b_t.get_size() is None` path. OSS-Fuzz
    containers don't have IPython → ImportError; interactive runs
    block on the REPL waiting for human input. **Now:** explicit
    `Exception` naming the offending buffer, its type, and its
    alloctype.
  - **9 Statement subclasses have broken `__hash__`** referencing
    `self.token` — never set in `__init__`, which only sets
    `self.buffer`. Affects: `BuffDecl`, `BuffInit`, `AssertNull`,
    `FileInit`, `ConstStringDecl`, `DynDblArrInit`, `DynArrayInit`,
    `SetStringNull`, `SetNull`. **Now:** routed through
    `self.buffer.get_token()`.
  - **`Function.get_type` references non-existent `self.buffer`**
    even though `__init__` accepts a `type: PointerType` parameter
    that gets dropped on the floor. **Now:** `__init__` stores
    `self.type = type`; `get_type` returns it.
  - **`ApiCall.set_pos_arg_var` upper bound off-by-one**
    (`pos > len(arg_vars)` instead of `>=`); `pos == len(arg_vars)`
    passes validation but then IndexErrors at assignment. **Now:**
    `>=`, error message updated to half-open interval.
  - **`ApiCall.set_pos_arg_var` dead type check**
    `isinstance(var, Address) and not isinstance(arg_types[pos],
    Type)` — `PointerType` extends `Type`, so the negation never
    fires. **Now:** removed with comment.
  - **`Buffer.__getitem__/__setitem__` raise empty `KeyError`**
    without the key. **Now:** `raise KeyError(key)`.
  - **`Function.__init__` redundant `self.addr = None`** immediately
    overwritten. **Now:** removed.

Full per-fix detail + rollback recipe:
`docs/ir_refactor_2026_05.md`.

