# DriverEnhancer refactor — 2026-05

Targeted fixes after the line-by-line review of
`liberator_adapter/driver/driver_enhancer.py` (~430 LOC).

DriverEnhancer's importance increased sharply after the 2026-05
synthesis refactor (cluster 2) deleted `CallbackStubLibrary` from
`hole_filler.py`. CBFactory now consults DriverEnhancer as the
**sole** production source of callback stubs (and the
`get_buffer_size_constraint` VarLen fallback). Quality of generated
stubs directly determines whether libfuzzer can exercise APIs that
take callbacks — particularly libsndfile VIO callbacks, libpcap user
callbacks, qsort comparators, allocator hooks.

Verdict from the review: the integration layer is sound (correct
delegation from CBFactory → DriverEnhancer → CallbackAnalyzer +
templates → emitted stub_code), but the **fallback path was actively
worse than the safe default**. This commit lands the HIGH and
MEDIUM cluster fixes.

The "empirical validation" section is intentionally blank — to be
filled after the 17-benchmark dynamic run.

---

## §1. What changed (per issue)

### Issue #1 — Empty stub had wrong signature

**Symptom.** `_generate_empty_stub` returned literally
`void func(void) { ... }`, a zero-argument signature. CBFactory
attached this as `Function.stub_code`. `LFBackendDriver.emit_stub_functions`
detects a non-empty `stub_code` and emits it verbatim — overriding
the *signature-aware* default fallback at the same call site that
would have produced the correct `{ret_type} {name} {arg_types} { ... }`
from the Function's parsed type.

So a callback that CallbackAnalyzer failed to classify (e.g. a
custom `int(my_struct*, size_t, void*)` callback) ended up emitted
as `void f(void)` and the linker failed with a signature mismatch.

**Fix.** Both unclassified paths now return `""` for stub_code:

  - `callback_info is None` (analyzer returned no entry for this arg)
  - `_generate_from_template`'s default branch (unknown CallbackType)

Empty `stub_code` triggers LFBackendDriver's signature-aware default
fallback (`{ret_type} {name} {arg_types} { return ({ret_type})0; }`),
which always matches Function's parsed type. Safer than ever before.

**Files.** `liberator_adapter/driver/driver_enhancer.py`,
`generate_stub_for_api` and `_generate_from_template`.

### Issue #2 — READER template needed driver-side context that nobody emits

**Symptom.** The READER template defined a `FuzzReaderCtx_xxx` struct
and dereferenced `stream` as a pointer to it:

```c
FuzzReaderCtx_xxx* ctx = (FuzzReaderCtx_xxx*)stream;
size_t avail = ctx->size - ctx->pos;
```

For this to work, the driver caller must (a) declare a
`FuzzReaderCtx_xxx` variable, (b) initialise its fields from the
fuzz input, (c) pass its address as the `stream` argument to the
API that invokes the callback. **CBFactory does none of this** —
it just passes whatever variable `try_to_get_var` resolves for that
arg, often NULL. Result: callback dereferences NULL on first call.

**Fix.** Replaced the template body with a signature-correct
no-op variant that returns 0 (EOF marker per the standard
`fread`-style contract). Signature unchanged, so no link-time
break; runtime path no longer dereferences `stream`.

```c
size_t f(void* ptr, size_t size, void* stream) {
    (void)ptr; (void)size; (void)stream;
    return 0;
}
```

**Trade-off.** This loses the "feed fuzz data through the callback"
coverage signal. For libsndfile-style VIO callbacks, the API's read
path will see immediate EOF rather than fuzz bytes. Full restoration
requires CBFactory to (a) declare a `FuzzReaderCtx_xxx` typed
variable per callback, (b) wire its address as the stream arg.
**Tracked as TODO** in §2 below.

**Files.** `liberator_adapter/driver/driver_enhancer.py`,
`_generate_from_template` READER template.

### Issue #3 — `enhance_context_get_function_pointer` dead code

**Symptom.** A decorator that wraps `Context.get_function_pointer`
to consult DriverEnhancer. Was defined but never imported / called
anywhere in the codebase. CBFactory does the equivalent through
its own `_get_enhanced_function_pointer` (in 2026-05 synthesis
cluster-1 changes).

**Fix.** Decorator removed. Replaced with a comment pointing at the
actual production path. Same pattern as the Prototyper dead methods
we removed in the Agent refactor commit.

**Files.** `liberator_adapter/driver/driver_enhancer.py`.

---

## §2. Deferred (with rationale)

### Issue #2 follow-up — Restore READER's data-feeding path

The current fix is safe but coverage-limiting. To restore the
fuzz-data-through-callback path:

1. CBFactory needs to recognise when an API's signature includes a
   callback that the analyzer classified as READER.
2. Emit a typed `FuzzReaderCtx_<api>_<idx>` variable in the driver's
   variable-declaration block, initialised from `data` / `size`.
3. Wire its address as the `stream` arg of the API call.

This is a CBFactory-side change that crosses the synthesis layer's
abstraction boundary (currently CBFactory doesn't know callback
*types*, only that an arg is a function pointer). Defer until the
synthesis-side refactor has settled and we have benchmark data
showing READER callbacks are actually a coverage bottleneck (most
likely on libsndfile / libpng / libtiff).

### Issue #4 — Template signatures are hardcoded

COMPARATOR / HANDLER / READER / WRITER / ALLOCATOR / DEALLOCATOR /
VISITOR templates all have hardcoded C signatures. If
CallbackAnalyzer misclassifies a multi-arg HANDLER as HANDLER (which
only models single-arg), the emitted stub has the wrong signature
and the linker rejects.

A safer policy: gate template usage by
`callback_info.confidence > threshold`, fall through to `""`
(empty stub_code) below threshold so LFBackendDriver's
signature-aware default wins.

**Why deferred.** CallbackAnalyzer's confidence semantics are
under-documented; the threshold would need empirical tuning. The
current fix (issue #1) already covers the UNKNOWN-type case, which
is the most common failure mode. Misclassifications are rarer.

### Issue #5 — `_customize_stub_name`'s `break`

After finding the first old_pattern match, the loop breaks. For
LLM-returned stubs with multiple placeholder names, only one gets
replaced. Minor issue — most LLM-returned stubs have one identifier
to replace. Defer.

### Issue #6 — COMPARATOR `memcmp(a, b, 1)`

Returns -1/0/1 based on the first byte, so qsort terminates but
all entries effectively cluster as "equal". Doesn't trigger
sort-stability-sensitive bugs. Could improve to compare full
buffers with a documented size, but the *real* fix would be having
the comparator read from a shared fuzz-input cursor — same
"caller-side context" problem as issue #2. Defer.

### Issue #7 — `arg_name` empty-string edge case

If `callback_info.arg_name` is empty, `FuzzReaderCtx_` becomes a
bare prefix that could match unrelated tokens via `.replace()`.
Defer — `arg_name` is set by CallbackAnalyzer's signature parsing
and is empty only when parsing fails, which already returns an
empty-stub path now.

---

## §3. Empirical validation — to be filled in

After the 17-benchmark dynamic run:

### Stub-signature link errors

Hypothesis: zero "undefined reference" / "conflicting type"
linker errors related to `fuzz_cb_*` identifiers. The pre-fix
empty-stub path used to produce these on callback-heavy projects.

| Project | Linker errors involving fuzz_cb_* (before) | After fix |
|---|---|---|
| libsndfile | _TBD_ | _expect 0_ |
| libpng | _TBD_ | _expect 0_ |
| libtiff | _TBD_ | _expect 0_ |
| libpcap | _TBD_ | _expect 0_ |
| other | _TBD_ | _expect 0_ |

### Callback runtime crashes

Hypothesis: zero crashes on `fuzz_cb_*` callbacks deref-ing NULL
streams. The pre-fix READER template made this likely on
libsndfile.

| Project | NULL-deref crashes in fuzz_cb_* (before) | After fix |
|---|---|---|
| libsndfile | _TBD_ | _expect 0_ |
| other | _TBD_ | _expect 0_ |

### Coverage delta

Trade-off check: with the safer READER template, libsndfile's
read-via-VIO coverage may drop. The hypothesis is that
zero-bytes-into-read-callback is no worse than what NULL-deref
already produced (which was a crash, no coverage at all). But
worth measuring to know if Issue #2's TODO is high-priority.

| Project | Read-path coverage % (before) | After |
|---|---|---|
| libsndfile | _TBD_ | _TBD_ |

---

## §4. Rollback recipe

- Issue #1: restore `_generate_empty_stub` to its original body and
  the `templates.get(..., self._generate_empty_stub(func_name))`
  fallback. Will re-introduce signature-mismatch linker errors but
  matches pre-2026-05 behaviour.
- Issue #2: restore the READER template's typed-context body from
  `git show HEAD~1`. Will re-introduce NULL-deref runtime crashes.
- Issue #3: restore the `enhance_context_get_function_pointer`
  decorator. It was never called, so functionally a no-op restore.
