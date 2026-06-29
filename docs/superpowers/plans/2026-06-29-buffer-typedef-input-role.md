# Buffer-Typedef → INPUT_BUFFER (Plan 3a) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `_find_buffer_size_positions` typedef-aware so a const byte-buffer behind a typedef (`png_const_voidp`, length `png_size_t`) is classified `INPUT_BUFFER` — fixing the dead-harness root cause where memory-parse args never get fuzz data bound.

**Architecture:** Plan 3a of the beat-PromeFuzz rebuild (spec capability ②(a), the *general* extraction fix — the only one that helps every library, not one). **One function, one file** (`liberator_adapter/analysis/usedef.py`), one new test. The consumer (`api_semantic_model.py:485-519`) and render (`hole_semantics.py:141-162`) are already correct — once `role == INPUT_BUFFER` the fuzz data flows `(void*)data` end-to-end.

**Tech Stack:** Python 3, pytest (`sys.path.insert` + direct import convention). No new deps. No docker.

## Global Constraints

- **Zero library-name keys.** The buffer rule is keyed on byte-family TYPE-spelling substrings (`void`/`byte`/`char`) — a structural property — never `"png"`/`"jpeg"`/`"cms"`. The length rule is a generic `_size_t`/`_len` suffix.
- **SVF is a write-VETO, not a trigger.** A read/write *trigger* would false-bind read-only fuzz data into the ~25 SVF-*written* libpng output buffers. Use `arg["_svf_writes"] is True` only to DEMOTE a matched pair. (`_svf_writes` ∈ {True=written, False=read-only, None=no data}; populated by `annotate_svf_writes` BEFORE reconcile — verified `usedef.py:338-384`.)
- **Do NOT add i8*/i64 IR-type handling.** Args reach this function already clang-typedef-spelled (`normalize_coerce_args` overwrites `arg.type`); IR types never arrive here. That clause of the spec is dead at this call site — skip it.
- **Keep the const gate.** It blocks most written buffers; the SVF veto covers the const-blind residual.
- **Determinism:** byte-family / length token sets are static tuples/frozensets (the repo has a known `PYTHONHASHSEED` non-determinism; the golden suite is the oracle).
- **Success = classification, not coverage.** 3a alone unblocks ~1 of 8 libpng drivers; the rest of libpng's dead harness is OTHER bugs (`__restrict` render, creator-prepend, `png_image.version`) — explicitly OUT OF SCOPE.

---

## File Structure

- **Modify:** `liberator_adapter/analysis/usedef.py` — add 2 module constants; rewrite `_find_buffer_size_positions` (lines 221-245). No other production file.
- **Create:** `tests/test_buffer_typedef_input_role.py` — unit tests for the function (mirrors `tests/test_callback_param_no_typedef_suffix.py`).

---

### Task 1: Typedef-aware buffer/length detection + SVF write-veto

**Files:**
- Create: `tests/test_buffer_typedef_input_role.py`
- Modify: `liberator_adapter/analysis/usedef.py` (constants near line 111; function 221-245)

**Interfaces:**
- `_find_buffer_size_positions(args: List[Dict[str, Any]]) -> Tuple[int, int]` — unchanged signature. Each `arg` is a dict with keys `type` (clang spelling), `is_const`/`const` (bool/list), and optional `_svf_writes` (bool|None). Returns `(buf_idx, size_idx)` or `(-1, -1)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_buffer_typedef_input_role.py
"""Unit tests for typedef-aware (buf, size) detection in _find_buffer_size_positions.
Library-agnostic: keyed on byte-family type-spelling substrings + _size_t/_len
length suffix + an SVF write-veto. No project-name special cases."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.usedef import _find_buffer_size_positions


def _arg(t, *, is_const=False, svf=None):
    a = {"type": t, "is_const": is_const}
    if svf is not None:
        a["_svf_writes"] = svf
    return a


def test_literal_const_void_buffer_still_detected():
    # Regression: the existing fast path must keep working.
    args = [_arg("const void *", is_const=True), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_const_voidp_typedef_with_size_t():
    # Buffer-gate fix: typedef spelling carries "void"; const is embedded.
    args = [_arg("png_const_voidp"), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_const_voidp_with_png_size_t_typedef_length():
    # Both gates fixed: typedef buffer + typedef length (the live libpng shape).
    args = [_arg("png_const_voidp"), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_const_void_with_png_size_t_length_typedef():
    # Length-gate fix in isolation.
    args = [_arg("const void *", is_const=True), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_png_bytep_buffer():
    # "byte" token; const embedded.
    args = [_arg("png_const_bytep"), _arg("png_size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_svf_written_buffer_is_vetoed():
    # An SVF-observed WRITE means output buffer, not fuzz input.
    args = [_arg("const void *", is_const=True, svf=True), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_svf_read_only_buffer_not_vetoed():
    # _svf_writes False (read-only) must NOT suppress the match.
    args = [_arg("const void *", is_const=True, svf=False), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (0, 1)


def test_non_byte_const_pointer_count_not_matched():
    # (const int* elems, int count) is NOT an input buffer — no over-broad match.
    args = [_arg("const int *", is_const=True), _arg("int")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_const_struct_pointer_not_matched():
    args = [_arg("const cmsHPROFILE *", is_const=True), _arg("int")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_lcms_uint8_buffer_unchanged_no_regression():
    # cmsUInt8Number* is handled by the separate FUZZ_BUFFERS path, NOT here;
    # it must stay unmatched so the fix doesn't shift lcms behavior.
    args = [_arg("const cmsUInt8Number *", is_const=True), _arg("cmsUInt32Number")]
    assert _find_buffer_size_positions(args) == (-1, -1)


def test_non_const_buffer_skipped():
    # Const gate preserved: a non-const png_voidp is not matched.
    args = [_arg("png_voidp"), _arg("size_t")]
    assert _find_buffer_size_positions(args) == (-1, -1)
```

- [ ] **Step 2: Run the tests — expect the typedef cases to FAIL**

Run: `python3 -m pytest tests/test_buffer_typedef_input_role.py -v`
Expected: the literal/non-match/non-const cases PASS; `test_png_const_voidp_*`, `test_const_void_with_png_size_t_length_typedef`, `test_png_bytep_buffer` FAIL (current code returns `(-1,-1)` for typedefs). This confirms the bug.

- [ ] **Step 3: Add the two module constants**

In `liberator_adapter/analysis/usedef.py`, immediately AFTER the `_BUFFER_HINT_PATTERNS` block (ends line 111), add:

```python
# Byte-buffer typedef tokens: a const pointer whose (lowercased) spelling
# CONTAINS one of these is a raw byte/char/void buffer regardless of typedef
# wrapping (``png_const_voidp`` → "void", ``png_bytep`` → "byte"). Keyed on the
# TYPE-spelling family — a structural property — never a library name.
_BYTE_BUFFER_TOKENS: Tuple[str, ...] = ("void", "byte", "char")

# Length-arg types: the fixed integer set PLUS typedef'd lengths whose bare name
# ends in ``_size_t`` / ``_len`` (e.g. ``png_size_t``).
_LENGTH_TYPES: frozenset = frozenset({
    "size_t", "ssize_t", "int", "long", "unsigned", "uint32_t",
    "uint64_t", "unsigned long", "unsigned int",
})
```

- [ ] **Step 4: Rewrite `_find_buffer_size_positions`**

Replace the function body (lines 221-245) with:

```python
def _find_buffer_size_positions(
    args: List[Dict[str, Any]],
) -> Tuple[int, int]:
    """Locate a ``(buf, size)`` arg pair if present; ``(-1, -1)`` otherwise.

    A buffer arg is a const pointer to a byte-ish type — a literal byte pointer
    (``const void *``) OR a typedef whose spelling carries a byte-family token
    (``png_const_voidp`` → "void") — whose successor is an integer length
    (``size_t``-family OR a ``_size_t``/``_len`` typedef). An SVF-observed WRITE
    on the buffer vetoes the match (output buffer, not fuzz input).
    """
    for i, arg in enumerate(args):
        atype = arg.get("type", arg.get("type_clang", "")) or ""
        norm = _normalize_type_str(atype)
        # Const gate — typedef-aware: the extractor's is_const flag OR a ``const``
        # embedded in the (typedef) spelling (``png_const_voidp`` is const-pointee).
        if not (_get_is_const(arg) or "const" in norm):
            continue
        if not (any(p in norm for p in _BUFFER_HINT_PATTERNS)
                or any(tok in norm for tok in _BYTE_BUFFER_TOKENS)):
            continue
        if i + 1 >= len(args):
            continue
        next_arg = args[i + 1]
        nnorm = _normalize_type_str(
            next_arg.get("type", next_arg.get("type_clang", "")) or "")
        nbare = nnorm.replace("const ", "").replace("*", "").strip()
        if not (nbare in _LENGTH_TYPES
                or nbare.endswith("_size_t") or nbare.endswith("_len")):
            continue
        # SVF write-veto: a buffer SVF saw WRITTEN is an output, not fuzz input.
        # None (no SVF data) / False (read-only) fall through to the match.
        if arg.get("_svf_writes") is True:
            continue
        return i, i + 1
    return -1, -1
```

- [ ] **Step 5: Run the unit tests — expect all PASS**

Run: `python3 -m pytest tests/test_buffer_typedef_input_role.py -v`
Expected: all 11 pass.

- [ ] **Step 6: Golden no-drift gate (the over-fit oracle)**

Run: `python3 -m pytest tests/ -q 2>&1 | tail -6`
Expected: **no NEW failures vs the 3 pre-existing golden-characterization failures** (`test_golden_characterization.py::...[lcms|cjson|c-ares]`, the `portfolio_mode` breakage). cjson/c-ares/zlib have no typedef'd byte buffers, so the golden output must be byte-identical there. **If a non-png golden shifts, the byte-token rule is too broad — tighten it** (e.g. require the token as a whole word, or drop `char`).

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/analysis/usedef.py tests/test_buffer_typedef_input_role.py
git commit -m "fix(extract): typedef-aware INPUT_BUFFER detection + SVF write-veto

_find_buffer_size_positions now matches const byte-buffer typedefs (png_const_voidp,
png_bytep) via byte-family spelling tokens and _size_t/_len length typedefs, and
demotes SVF-written (output) buffers. Library-agnostic (no project-name keys); IR
types never reach this call site so no i8*/i64 handling. Unblocks memory-parse APIs
that previously never got fuzz data bound (the libpng dead-harness root cause).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

## Validation beyond unit tests (fast — NOT `--eval`)

Per the avoid-e2e guardrail, validate with the construction-only signal, not a 3-4h run:
- Run `--extract-only` on **libpng** and confirm a `png_*_from_memory`-class buffer arg now appears as `INPUT_BUFFER` in `skeleton_drivers.json` (rendered `(void*)data`).
- Confirm `cjson` / `c-ares` / `lcms` skeleton breadth is unchanged (`breadth_residual.json` / INPUT_BUFFER counts) — the fix must be a no-op there.
- Success criterion: "typedef'd memory-buffer args classify INPUT_BUFFER across ≥3 libs with no regression." NOT merged-harness coverage (other libpng bugs dominate that and are out of scope).

## Self-Review

- **Spec coverage:** implements ②(a) — the typedef-aware buffer + length gates — and CORRECTS the spec's two errors (no IR-type handling; SVF as veto not trigger), per the inventory's verified findings.
- **Placeholder scan:** no TBD/vague steps; full function body + test code shown; the only conditional ("if a non-png golden shifts, tighten") is a rational fallback with a concrete action, not a gap.
- **Type/name consistency:** `_BYTE_BUFFER_TOKENS`, `_LENGTH_TYPES`, `_svf_writes`, `_get_is_const`, `_normalize_type_str`, `_BUFFER_HINT_PATTERNS` all match `usedef.py` (verified lines 108-111, 114, 151-156, 221-245, 338-384). Function signature unchanged → consumers (`api_semantic_model.py`) need no edit.
- **TDD:** genuine fail-first (typedef cases return `(-1,-1)` on current code); the golden gate is the over-fit guard.
