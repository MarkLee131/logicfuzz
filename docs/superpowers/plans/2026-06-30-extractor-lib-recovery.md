# Extractor Lib-Recovery (Plan 3-lib) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SVF get a static `.a` it currently can't find, for two same-call-site failure modes: libjpeg-turbo (lib named after the *API*, in a *versioned* build dir) and tinygltf (header-only — no `.a` exists at all). Both currently degrade to clang-only → empty `conditions.json` → 0 skeletons.

**Architecture:** Plan 3-lib of the beat-PromeFuzz rebuild (spec ②(b)+②(c), folded — both live in `liberator_adapter/extractors/llvm_extractor.py` at `compile_to_bitcode` / `_run_compile_and_find_lib`, same bug class "SVF can't locate a library"). Two recovery branches, mirroring the EXISTING `_should_retry_with_stub_engine` pattern (default-on env opt-out, fail-open, sets `self.bitcode_recovery`).

**Tech Stack:** Python 3, pytest (pure-helper unit tests). The in-container build branches are validated by a real `--extract-only` run (docker), NOT a unit test — per the avoid-e2e guardrail, the fast oracle is `conditions.json` non-empty / `skeleton_drivers.json` count > 0, NOT a full `--eval`.

## Global Constraints

- **Zero library-name keys.** No `"jpeg"`/`"tinygltf"`/`"png"` string special-cases. libjpeg's fix keys on "lib not named `{project}` → pick the largest archive in the project source subtree"; tinygltf's fix probes the header for its own `*_IMPLEMENTATION` macro. Both derive everything from the project/source structurally.
- **Fail-open + default-on opt-out**, mirroring `LOGICFUZZ_STUB_ENGINE_RETRY` (`llvm_extractor.py:272`): any error in a recovery branch leaves the existing `RuntimeError → clang-only` path intact; never blanks a project that already has a real `.a`.
- **No-regression on lib-having projects.** Both branches only fire when the standard `lib{project}*` discovery already MISSED, so c-ares/zlib/cjson/lcms/libpng (which have `lib{project}.a`) are byte-identical. Re-confirm with a cjson/c-ares `--extract-only`.
- **Validation is construction-only, not `--eval`** (`feedback_avoid_e2e_for_validation`): `--extract-only` + check `conditions.json` non-empty and `skeleton_drivers.json` > 0.
- **Determinism:** helper selection logic sorts deterministically (size desc, then path) — the repo has a known `PYTHONHASHSEED` non-determinism.

---

## File Structure

- **Modify:** `liberator_adapter/extractors/llvm_extractor.py` — add `_select_fallback_archive` (pure helper) + broaden Strategy-2 in `_run_compile_and_find_lib` (Task 1); add `_probe_implementation_macro` (pure helper) + `_try_header_tu_synthesis` + wire into `compile_to_bitcode` (Task 2).
- **Create:** `tests/test_extractor_lib_recovery.py` — unit tests for the two pure helpers.

---

### Task 1: libjpeg-turbo — largest-archive fallback in the project source subtree

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (`_run_compile_and_find_lib` ~319-367; add `_select_fallback_archive` near it)
- Test: `tests/test_extractor_lib_recovery.py`

**Interfaces:**
- `_select_fallback_archive(candidates: List[Tuple[str, int]], stub_path: str = STUB_ENGINE_PATH) -> Optional[str]` — pure; from `(path, size_bytes)` pairs, exclude the stub + zero-size, return the largest (tie-break by path). Used by `_run_compile_and_find_lib`'s Strategy-2.

- [ ] **Step 1: Write the failing test for the pure selector**

```python
# tests/test_extractor_lib_recovery.py
"""Unit tests for the pure helpers behind the extractor lib-recovery branches
(Plan 3-lib). The in-container build branches are validated by a real
--extract-only run, not here."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.extractors.llvm_extractor import (
    _select_fallback_archive, STUB_ENGINE_PATH,
)


def test_picks_largest_archive():
    cands = [("/src/p.main/build/libjpeg.a", 5000),
             ("/src/p.main/build/libturbojpeg.a", 4000),
             ("/src/p.main/third_party/libtiny.a", 50)]
    assert _select_fallback_archive(cands) == "/src/p.main/build/libjpeg.a"


def test_excludes_stub_engine():
    cands = [(STUB_ENGINE_PATH, 999999), ("/src/p/build/libjpeg.a", 4000)]
    assert _select_fallback_archive(cands) == "/src/p/build/libjpeg.a"


def test_excludes_zero_size_and_empty():
    assert _select_fallback_archive([("/src/x.a", 0)]) is None
    assert _select_fallback_archive([]) is None


def test_deterministic_tiebreak_by_path():
    cands = [("/src/b.a", 100), ("/src/a.a", 100)]
    assert _select_fallback_archive(cands) == "/src/a.a"
```

- [ ] **Step 2: Run — expect ImportError / fail**

Run: `python3 -m pytest tests/test_extractor_lib_recovery.py -q`
Expected: FAIL (`_select_fallback_archive` not defined).

- [ ] **Step 3: Add the pure helper**

In `liberator_adapter/extractors/llvm_extractor.py`, near the other module helpers (e.g. just above `class LLVMAPIExtractor`), add:

```python
def _select_fallback_archive(candidates, stub_path=STUB_ENGINE_PATH):
    """From a list of ``(path, size_bytes)`` static-archive candidates, pick the
    project's library when it is NOT named ``lib{project}.a`` (e.g. libjpeg-turbo
    builds ``libjpeg.a``/``libturbojpeg.a``). Excludes the synthesized stub engine
    and zero-size archives, then takes the LARGEST (the real library dwarfs
    vendored/object archives); ties broken by path for determinism. Pure /
    container-free → unit-testable. Returns the path or ``None``."""
    usable = [(p, s) for (p, s) in candidates
              if p and p != stub_path
              and not p.endswith("/logicfuzz_stub_engine.a")
              and isinstance(s, int) and s > 0]
    if not usable:
        return None
    usable.sort(key=lambda ps: (-ps[1], ps[0]))
    return usable[0][0]
```

- [ ] **Step 4: Run — expect PASS**

Run: `python3 -m pytest tests/test_extractor_lib_recovery.py -q`
Expected: 4 passed.

- [ ] **Step 5: Broaden Strategy-2 in `_run_compile_and_find_lib`**

Replace the current Strategy-2 fallback (anchor `llvm_extractor.py:360-366`):

```python
        if not lib_file:
            project_dir = f'/src/{project_name}'
            find_result = self.container.execute(
                f'find {project_dir} -name "*.a" -type f 2>/dev/null | head -1')
            if find_result.returncode == 0 and find_result.stdout.strip():
                lib_file = find_result.stdout.strip()
                logger.info(f"Found library in project dir: {lib_file}")
```

with (library-agnostic: only reached when the `{project}`-named patterns missed —
so lib-having projects never enter this branch):

```python
        if not lib_file:
            # Strategy 2: the static lib isn't named after the project (e.g.
            # libjpeg-turbo builds libjpeg.a/libturbojpeg.a) and/or lives in a
            # VERSIONED source dir (/src/libjpeg-turbo.main, not /src/libjpeg-turbo).
            # Discover the real source subtree(s) structurally, then pick the
            # largest *.a there (excludes the tiny stub engine). No project-name
            # string special-case; only fires after the {project} patterns missed.
            dir_res = self.container.execute(
                f'find /src -maxdepth 1 -type d -iname "{project_name}*" 2>/dev/null')
            src_roots = [d.strip() for d in (dir_res.stdout or "").splitlines()
                         if d.strip()] or ['/src']
            cands = []
            for root in src_roots:
                far = self.container.execute(
                    f'find {root} -name "*.a" -type f -printf "%s\\t%p\\n" 2>/dev/null')
                for line in (far.stdout or "").splitlines():
                    parts = line.split("\t", 1)
                    if len(parts) == 2 and parts[0].strip().isdigit():
                        cands.append((parts[1].strip(), int(parts[0].strip())))
            lib_file = _select_fallback_archive(cands)
            if lib_file:
                logger.info(
                    f"Found library via source-subtree largest-archive fallback: "
                    f"{lib_file} (from {len(cands)} candidate archive(s))")
```

- [ ] **Step 6: Suite no-regression**

Run: `python3 -m pytest tests/ -q 2>&1 | tail -3`
Expected: no new failures (the change is a pure-helper add + a fallback only reached on container searches; no unit test exercises the container path).

- [ ] **Step 7: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extractor_lib_recovery.py
git commit -m "fix(extract): largest-archive fallback for libs not named after the project

_run_compile_and_find_lib now discovers the real (possibly versioned) /src/{project}*
source subtree and, when the lib{project}* patterns miss, picks the largest *.a there
(excluding the stub engine) — recovering libjpeg-turbo's libjpeg.a/libturbojpeg.a under
/src/libjpeg-turbo.main/build. Library-agnostic (no 'jpeg' key); only fires when the
project-named discovery already missed, so lib{project}.a projects are byte-identical.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

- [ ] **Step 8: Integration validation (docker, the real oracle)**

Run: `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/libjpeg-turbo.yaml --extract-only` (background; needs docker). Success: `results/libjpeg-turbo/.../conditions.json` non-empty (was 0). Then re-run cjson `--extract-only` and confirm its lib is still found via Strategy-1 (no-regression). If libjpeg-turbo has no YAML, create `comparison/libjpeg-turbo.yaml` mirroring an existing C entry first.

---

### Task 2: tinygltf — header-only TU-synthesis recovery

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (add `_probe_implementation_macro`; add `_try_header_tu_synthesis`; wire into `compile_to_bitcode` after the stub-engine retry, before the `RuntimeError`)
- Test: `tests/test_extractor_lib_recovery.py` (extend)

**Interfaces:**
- `_probe_implementation_macro(header_text: str) -> Optional[str]` — pure; return the single-header lib's implementation macro (e.g. `TINYGLTF_IMPLEMENTATION`) by scanning for `#if[n]def <X>_IMPLEMENTATION` / `defined(<X>_IMPLEMENTATION)`. None if absent.
- `_try_header_tu_synthesis(self, prior_output: str) -> Optional[str]` — in-container; find the project single-header, synthesize+compile a `.cpp` TU defining the macro, `ar` it into `lib{project}.a`, return the path (sets `self.bitcode_recovery="header_tu"`). Fail-open → None.

- [ ] **Step 1: Write the failing test for the macro probe**

Add to `tests/test_extractor_lib_recovery.py`:

```python
from liberator_adapter.extractors.llvm_extractor import _probe_implementation_macro


def test_probe_ifdef_implementation_macro():
    hdr = "#ifndef TINY_GLTF_H\n#define TINY_GLTF_H\n#ifdef TINYGLTF_IMPLEMENTATION\nvoid f(){}\n#endif\n"
    assert _probe_implementation_macro(hdr) == "TINYGLTF_IMPLEMENTATION"


def test_probe_defined_form():
    hdr = "#if defined(STB_IMAGE_IMPLEMENTATION)\nint g;\n#endif\n"
    assert _probe_implementation_macro(hdr) == "STB_IMAGE_IMPLEMENTATION"


def test_probe_none_when_absent():
    assert _probe_implementation_macro("#pragma once\nint h;\n") is None


def test_probe_ignores_plain_define_guard():
    # The include guard (TINY_GLTF_H) is NOT an *_IMPLEMENTATION macro.
    assert _probe_implementation_macro("#ifndef TINY_GLTF_H\n#define TINY_GLTF_H\n#endif\n") is None
```

- [ ] **Step 2: Run — expect fail (not defined)**

Run: `python3 -m pytest tests/test_extractor_lib_recovery.py -q`
Expected: the 4 new tests FAIL (`_probe_implementation_macro` undefined).

- [ ] **Step 3: Add the pure macro probe**

```python
import re as _re

_IMPL_MACRO_RE = _re.compile(
    r'(?:#\s*if(?:n?def)\s+|defined\s*\(\s*)([A-Z_][A-Z0-9_]*_IMPLEMENTATION)\b')


def _probe_implementation_macro(header_text):
    """Recover a single-header lib's implementation-gate macro (e.g.
    ``TINYGLTF_IMPLEMENTATION``, ``STB_IMAGE_IMPLEMENTATION``) by scanning for an
    ``#ifdef X_IMPLEMENTATION`` / ``defined(X_IMPLEMENTATION)`` guard. Returns the
    first such macro or ``None``. Pure → unit-testable. Generic: keys on the
    ``*_IMPLEMENTATION`` convention, never a specific library name."""
    if not header_text:
        return None
    m = _IMPL_MACRO_RE.search(header_text)
    return m.group(1) if m else None
```

- [ ] **Step 4: Run — expect PASS**

Run: `python3 -m pytest tests/test_extractor_lib_recovery.py -q`
Expected: all 8 pass.

- [ ] **Step 5: Add the in-container synthesis method**

Add to `LLVMAPIExtractor` (model on `_stub_engine_build_cmd`, `llvm_extractor.py:137-149`). This branch is NOT unit-tested (in-container); it is fail-open and validated by the tinygltf `--extract-only` run in Step 7.

```python
def _try_header_tu_synthesis(self, prior_output):
    """Header-only recovery: when no static lib exists because the project is a
    single-header (STB-style) lib, synthesize one. Find the project's public
    single-header, probe its ``*_IMPLEMENTATION`` macro, compile a one-line TU
    that defines the macro and includes the header into an object, and ``ar`` it
    into ``lib{project}.a`` so the existing discovery + extract-bc flow proceeds.
    Returns the .a path (and sets ``self.bitcode_recovery='header_tu'``) or None.
    Fail-open: any miss/error → None → caller keeps the clang-only degradation.
    Generic: macro + header are derived structurally, never hardcoded."""
    try:
        project = self.benchmark.project
        src_dir = self._bc_source_dir or f'/src/{project}'
        # Find a project-named single header (prefer shallow, exclude test/ext).
        pstem = project.lower().replace('-', '').replace('_', '')
        find_hdr = self.container.execute(
            f'find /src -maxdepth 4 -type f \\( -name "*.h" -o -name "*.hpp" \\) '
            r"-not -path '*/test/*' -not -path '*/tests/*' -not -path '*/ext/*' "
            r"-printf '%d\t%p\n' 2>/dev/null | sort -n")
        header = None
        for line in (find_hdr.stdout or "").splitlines():
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            p = parts[1].strip()
            base = os.path.basename(p).lower().replace('-', '').replace('_', '')
            if pstem and (pstem in base or base.replace('.h', '').replace('.hpp', '') in pstem):
                # Confirm it carries an *_IMPLEMENTATION guard before committing.
                txt = self.container.execute(f'cat "{p}" 2>/dev/null').stdout or ""
                if _probe_implementation_macro(txt):
                    header, header_txt = p, txt
                    break
        if not header:
            return None
        macro = _probe_implementation_macro(header_txt)
        hdr_dir = os.path.dirname(header)
        tu = f'/tmp/logicfuzz_header_tu_{project}.cpp'
        obj = f'/tmp/logicfuzz_header_tu_{project}.o'
        lib = f'{src_dir}/lib{project}.a'
        build = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            f'printf "#define {macro}\\n#include \\"{os.path.basename(header)}\\"\\n" > {tu} && '
            f'wllvm++ {self._cxf_clean} -I"{hdr_dir}" -c {tu} -o {obj} 2>&1 && '
            f'ar crs {lib} {obj} 2>&1 && echo HEADER_TU_OK')
        res = self.container.execute(build, timeout=600)
        if 'HEADER_TU_OK' in (res.stdout or '') and self._file_exists_in_container(lib):
            self.bitcode_recovery = 'header_tu'
            logger.info("Header-TU synthesis recovered library: %s (macro %s, header %s)",
                        lib, macro, header)
            return lib
        logger.warning("Header-TU synthesis did not produce a lib (fail-open): %s",
                       (res.stdout or '')[-400:])
        return None
    except Exception as e:  # fail-open
        logger.warning("Header-TU synthesis errored (fail-open): %s", e)
        return None
```

- [ ] **Step 6: Wire it into `compile_to_bitcode`**

After the stub-engine retry block and before `if lib_file:` (anchor `llvm_extractor.py:288`), insert:

```python
            if (lib_file is None
                    and os.getenv("LOGICFUZZ_HEADER_TU_RETRY", "1") != "0"):
                logger.warning(
                    "No library after stub-engine retry; trying header-only "
                    "TU-synthesis (single-header lib path)")
                lib_file = self._try_header_tu_synthesis(out)
```

- [ ] **Step 7: Suite + integration validation**

Run: `python3 -m pytest tests/ -q 2>&1 | tail -3` (no new failures).
Then (docker): `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/tinygltf.yaml --extract-only` (background). Success: `results/tinygltf/.../conditions.json` non-empty AND `skeleton_drivers.json` count > 0 (was 0). Re-run cjson `--extract-only` → confirm byte-identical (header-TU never fires for a lib-having project).

- [ ] **Step 8: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extractor_lib_recovery.py
git commit -m "fix(extract): header-only TU-synthesis recovery (single-header C++ libs)

compile_to_bitcode now has a third recovery branch (after the stub-engine retry):
when no static lib exists because the project is a single-header STB-style lib, find
the project header, probe its *_IMPLEMENTATION macro, compile a one-line TU into an
object, and ar it into lib{project}.a so SVF gets bitcode. Unblocks tinygltf (636 APIs,
was 0 skeletons). Generic (macro+header derived structurally, no library-name key);
gated LOGICFUZZ_HEADER_TU_RETRY (default-on opt-out); fail-open → clang-only intact.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

## Self-Review

- **Spec coverage:** ②(b) libjpeg lib-discovery (Task 1) + ②(c) tinygltf header-only (Task 2), folded per the inventory (same call site, same bug class). Blockers 1+2 for libjpeg (source-dir pick, stub-engine retry) are ALREADY landed — out of scope, confirmed by inventory.
- **Placeholder scan:** no TBD/vague steps; both pure helpers have full code + tests; the in-container methods have full code. The integration-validation steps name the exact command + success signal (conditions.json non-empty / skeletons > 0), not "verify it works."
- **Type/name consistency:** `_select_fallback_archive`, `_probe_implementation_macro`, `STUB_ENGINE_PATH`, `_stub_engine_build_cmd`, `_run_compile_and_find_lib`, `compile_to_bitcode`, `self._bc_source_dir`, `self._cxf_clean`, `self.bitcode_recovery`, `_file_exists_in_container` all match `llvm_extractor.py` (verified 137-149, 236-367). New env gate `LOGICFUZZ_HEADER_TU_RETRY` mirrors `LOGICFUZZ_STUB_ENGINE_RETRY`.
- **Over-fit guard:** no library-name keys (libjpeg = largest-archive-in-source-subtree; tinygltf = `*_IMPLEMENTATION` probe). Both fire ONLY after standard discovery missed → byte-identical on lib-having projects (re-confirm via cjson/c-ares `--extract-only`).
- **Verification honesty:** the pure helpers are unit-tested; the two in-container branches CANNOT be unit-tested and are validated by `--extract-only` (the construction-only oracle, not `--eval`). This split is called out so an executor doesn't expect a unit test to cover the container build.
- **Risk:** Task 2's synthesized TU may fail to compile without the right `-I`/companion macros (single-header libs often pull in stb/json) — the in-container compile-check + `HEADER_TU_OK` sentinel + fail-open handle this; a TU that won't compile yields None → clang-only (no worse than today). C++ symbol mangling may yield fewer conditions than C — getting bitcode is necessary, downstream yield validated, not assumed.
