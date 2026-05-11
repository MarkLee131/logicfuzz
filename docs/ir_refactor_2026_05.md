# IR refactor — 2026-05

Twelfth in the 2026-05 refactor series. Audit of
`liberator_adapter/driver/ir/` — the 868-LOC Statement IR substrate
that LFBackendDriver renders into C source.

The IR is a near-clean fork of upstream
`reference/liberator:framework/driver/ir/` — only `Function.py` has
meaningful divergence (DriverEnhancer `stub_code` integration; the
2026-05 driverenhancer refactor). All defects below are
upstream-shared and were latent because LFBackendDriver was dead in
production until the 2026-05 backend refactor.

Five reachable bugs (IR1–IR5) plus two cleanups (IR6/IR7) fixed.
IR8 deferred.

The "empirical validation" section is intentionally blank.

---

## §1. Changes in this commit

### IR1 — Production-shipped IPython debug shim in `Buffer.get_allocated_size`

**Symptom.** Upstream Liberator's `Buffer.get_allocated_size` shipped:

```python
if b_t.get_size() is None:
    print("Is none?")
    from IPython import embed; embed(); exit(1)
```

In OSS-Fuzz build containers IPython is not installed, so the shim
raised `ImportError: No module named IPython` and crashed the synthesis
pipeline. Interactively it blocked the run waiting for human input on
an IPython REPL.

**Fix.** Replaced with an explicit `Exception` that names the
offending buffer, its type, and its alloctype, so the caller can
localise the failure.

**File.** `liberator_adapter/driver/ir/Buffer.py:73-86`.

### IR2 — 9 broken `__hash__` methods reference non-existent `self.token`

**Symptom.** Upstream wrote `__hash__` for 9 Statement subclasses as
`hash(self.token + str(self.__class__.__name__))`, but the
`__init__` of each only sets `self.buffer`, never `self.token`. Any
caller that hashes one of these (e.g., putting them in a set or
dict) hits `AttributeError: object has no attribute 'token'`.

Affected:

  - `BuffDecl`, `BuffInit`, `AssertNull`, `FileInit`,
    `ConstStringDecl`, `DynDblArrInit`, `DynArrayInit`,
    `SetStringNull`, `SetNull`

(Note: `CleanBuffer` and `CleanDblBuffer` correctly set
`self.token = buffer.token` in their constructors — those classes
were untouched.)

The bug was latent because LFBackendDriver was dead and Statements
were not put in sets/dicts on the live render path.

**Fix.** Routed each broken `__hash__` through
`self.buffer.get_token()` — the same attribute the `__str__` method
already uses. Semantic equality: two BuffDecls on the same buffer
hash equal, which matches what callers downstream would expect from a
declarations-on-same-buffer comparison.

**Files.** 9 Statement subclasses under
`liberator_adapter/driver/ir/`.

### IR3 — `Function.get_type` references non-existent `self.buffer`

**Symptom.** `Function.__init__` accepts a `type: PointerType`
parameter but never stores it. `Function.get_type` was defined as
`return self.buffer.get_type()` — `self.buffer` is never set
either. `AttributeError` on any call to `get_type()`.

**Fix.** Store the original `PointerType` as `self.type` in
`__init__`; `get_type()` returns it. The `Function: type:
PointerType` class-level annotation is now backed by a real
attribute.

**File.** `liberator_adapter/driver/ir/Function.py:17-50`.

### IR4 — `ApiCall.set_pos_arg_var` upper-bound off-by-one

**Symptom.** `if pos < 0 or pos > len(self.arg_vars):` — strict `>`
on the upper bound. `pos == len(arg_vars)` passes validation but the
assignment `self.arg_vars[pos] = var` then raises `IndexError`. The
inconsistency vs `has_max_value` / `get_max_value` (which use `>=`)
confirms `>=` is correct.

**Fix.** `pos > len(arg_vars)` → `pos >= len(arg_vars)`; error
message updated to half-open interval notation
`[0, len(arg_vars))`.

**File.** `liberator_adapter/driver/ir/ApiCall.py:43-46`.

### IR5 — `ApiCall.set_pos_arg_var` dead type-coherence check

**Symptom.** The mirror check
`if isinstance(var, Address) and not isinstance(self.arg_types[pos],
Type): raise ...` is unreachable. `PointerType` extends `Type`, so
every `arg_types[pos]` instance is `isinstance(..., Type)`. The
negation is always False; the check never fires.

**Fix.** Removed the dead block with a comment marker. Kept the
Variable-vs-PointerType check (which IS reachable: a bare
`Variable` value cannot satisfy a pointer-typed parameter — caller
needs to pass its `Address`).

**File.** `liberator_adapter/driver/ir/ApiCall.py:48-56`.

### IR6 — `Buffer.__getitem__`/`__setitem__` raise empty `KeyError`

**Symptom.** Out-of-range indexing raised `KeyError` with no value,
so the traceback didn't say which key was bad.

**Fix.** `raise KeyError(key)`.

**File.** `liberator_adapter/driver/ir/Buffer.py:26-38`.

### IR7 — `Function.__init__` redundant `self.addr = None`

**Symptom.** `self.addr = None` immediately followed by
`self.addr = Address.Address(token, self)` — first assignment
unreachable.

**Fix.** Removed the redundant initial assignment.

**File.** `liberator_adapter/driver/ir/Function.py`.

---

## §2. Deferred — with rationale

### IR8 — `Address` for callbacks uses type-string as token

**Observation.** When `Function.__init__` creates an `Address` for
the callback (`self.addr = Address.Address(token, self)` where
`token` is the function-pointer type string like `"int (*)(int,
int)"`), the resulting Address's `__hash__` is based on the
type-string + class name. Distinct callbacks with the same signature
would collide in a set keyed by `Address`.

**Why not fix.** The collision risk is theoretical — Address hashing
is not used on the render path. Fixing it requires a name-vs-type
disambiguation pattern that touches Variable as well (which uses
`token` consistently with the buffer name). Defer to a callbacks
pass when the collision surfaces in a real run.

### IR re-import timing fragility

**Observation.** `from . import Address` (and similar) in several
Statement files resolves to the *module* when imported during
`__init__.py` execution, but to the *class* once `__init__.py`
finishes. The code path `Address.Address(token, self)` then
silently flips meaning. Currently functional only because the import
order in `__init__.py` happens to land each subclass before the
class-rebind line.

**Why not fix.** A rewrite to `from .Address import Address as
_AddressClass` (or similar) touches every file and is mostly
cosmetic — the current behavior is correct as long as `__init__.py`
ordering is preserved. Flag for future tidy-up.

---

## §3. Empirical validation

**cjson run4 (2026-05-11) — all IR fixes unreachable on this trial.**

LFBackendDriver did not run (Phase H pruned all 10 candidates;
`skeleton_drivers=0`). The IR is only exercised by LFBackendDriver,
so IR1 (Buffer IPython embed), IR2 (broken `__hash__`), IR3
(`Function.get_type`), IR4 (`set_pos_arg_var` off-by-one), IR5
(dead Address check), IR6 (KeyError args), IR7 (dead `last_stmt`),
IR8 (Address token) are all **untested empirically on cjson**.

### Negative evidence (no failure modes surfaced)

run4 log shows **zero** occurrences of:
  - `AttributeError: 'BuffDecl' object has no attribute 'token'` (or
    any of the 9 patched classes)
  - `AttributeError: 'Function' object has no attribute 'buffer'`
  - `ImportError: No module named IPython`
  - `IndexError` in any `set_pos_arg_var`-style flow

This is consistent with LFBackendDriver not running (none of these
paths reachable) AND consistent with the fixes being correct. Cannot
distinguish from the cjson data alone.

### Required for IR validation

Need a benchmark where Phase H accepts at least 1 skeleton — likely a
benchmark with stronger automaton signal (more diverse trace
language). c-ares or libxml2 with rich `tests/` directories should
produce skeletons.

### Original hypothesis section — kept for future runs

### IR1: clean `Buffer.get_allocated_size` failure

If any benchmark hits a Buffer with `get_size() == None`, the new
explicit exception surfaces (with buffer name + type + alloctype) in
the trial logs. Pre-fix, this same path would have crashed with
`ImportError: No module named IPython` — confusing the operator into
thinking the container was missing a Python package.

Hypothesis: zero benchmarks hit this in practice. If one does, the
new message points directly at the buggy buffer type, which is the
real bug worth fixing upstream.

### IR2/IR3: AttributeError surfaces

Hypothesis: trial logs are free of `AttributeError: '<X>' object has
no attribute 'token'` / `'buffer'` for the 10 classes patched.

These were latent because LFBackendDriver was dead. Now that the
backend is reachable, any code path that hashes Statements (e.g.,
deduplication in CBFactory or skeleton synthesis) is exercised for
the first time.

### IR4/IR5: ApiCall.set_pos_arg_var

IR4 surfaces only at the boundary `pos == len(arg_vars)`. Pre-fix:
the validation passes, the assignment IndexError surfaces several
frames up with no context. Post-fix: clean Exception with the
position and range.

IR5 has no observable effect (dead code removal).

---

## §4. Rollback recipe

Each fix is self-contained; pick the narrowest rollback that
addresses any regression.

If IR1 needs rollback (an actual IPython-using developer relies on
the embed):

  - In `Buffer.py:73-86`, restore the original `print(...) + from
    IPython import embed; embed(); exit(1)` block.

If IR2 needs rollback (the new hash semantics collide unexpectedly):

  - In each of the 9 files, restore the original `hash(self.token +
    ...)` line. The fields don't exist, so callers will resume
    seeing AttributeError instead — restore only if the new semantic
    equality breaks a real downstream call.

If IR3 needs rollback:

  - In `Function.py`, remove `self.type = type` from `__init__` and
    restore `get_type` to `return self.buffer.get_type()`.

If IR4 needs rollback:

  - In `ApiCall.py:43`, change `>=` back to `>`. (Re-introduces the
    off-by-one but does not affect any current caller.)

If IR5 needs rollback:

  - Restore the `if isinstance(var, Address) and not isinstance(
    self.arg_types[pos], Type): raise ...` block. (Dead code — no
    observable effect either way.)

IR6 and IR7 are pure cosmetic — rollback is mechanical.
