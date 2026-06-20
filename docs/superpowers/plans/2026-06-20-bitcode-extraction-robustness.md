# Bitcode-Extraction Robustness (stub-engine retry) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a project has a buildable static library but our bitcode-extraction env override (`LIB_FUZZING_ENGINE=""`) makes its cmake configure abort, retry the build with a stub fuzzing-engine archive so SVF gets real bitcode instead of degrading to clang-only.

**Architecture:** Tool-side change in the LLVM-14 bitcode extractor only. The library builds before the fuzzer link, and only the fuzzer link needs a real engine — so on the first build failure we retry the project's own `compile` with a stub `ar` archive at `$LIB_FUZZING_ENGINE`; cmake configures, `make` builds the library, the later fuzzer link fails harmlessly (the `.a` already exists and the extractor already tolerates a non-zero `compile` exit). Fail-open: any error falls back to today's clang-only degradation.

**Tech Stack:** Python 3, pytest, Docker (OSS-Fuzz images), clang-14/wllvm, SVF (host extractor).

## Global Constraints

- Stays on **LLVM-14** — no SVF/LLVM version change.
- **Regression-safe:** the retry fires only after the current (blank-engine) path already failed; currently-working projects (libpng/c-ares) must be untouched.
- **Fail-open:** any exception in the new path falls through to the existing clang-only degradation; never a hard crash.
- **Kill-switch:** `LOGICFUZZ_STUB_ENGINE_RETRY=0` disables the retry (default ON, opt-out).
- **A≡B:** this change touches only the analysis/extraction build, never the coverage-measurement build.
- Spec: `docs/superpowers/specs/2026-06-20-bitcode-extraction-robustness-design.md`.

---

### Task 1: Retry-decision helper (pure)

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (add module-level function near the other module-level helpers, e.g. after `sanitize_extraction_flags`)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `_should_retry_with_stub_engine(compile_output: str) -> bool`

- [ ] **Step 1: Write the failing test**

```python
from liberator_adapter.extractors.llvm_extractor import _should_retry_with_stub_engine


def test_retry_true_on_fuzz_library_error():
    out = "CMake Error at fuzz/CMakeLists.txt:18 (message):\n  FUZZ_LIBRARY must be specified."
    assert _should_retry_with_stub_engine(out) is True


def test_retry_true_on_lib_fuzzing_engine_mention():
    assert _should_retry_with_stub_engine("error: LIB_FUZZING_ENGINE is empty") is True


def test_retry_false_without_engine_signal():
    # e.g. header-only: no library target ever referenced the engine
    assert _should_retry_with_stub_engine("fatal error: 'foo.h' file not found") is False


def test_retry_false_on_empty():
    assert _should_retry_with_stub_engine("") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_extraction_robustness.py -k retry -v`
Expected: FAIL with `ImportError` / `cannot import name '_should_retry_with_stub_engine'`

- [ ] **Step 3: Write minimal implementation**

```python
import re

_STUB_ENGINE_SIGNAL = re.compile(
    r"FUZZ_LIBRARY|LIB_FUZZING_ENGINE|FUZZING_ENGINE", re.IGNORECASE)


def _should_retry_with_stub_engine(compile_output: str) -> bool:
    """True iff a failed bitcode compile references the fuzzing-engine config,
    i.e. the build aborted because we blanked LIB_FUZZING_ENGINE. Skips a wasted
    rebuild on genuinely lib-less cases (header-only) and unrelated failures."""
    if not compile_output:
        return False
    return bool(_STUB_ENGINE_SIGNAL.search(compile_output))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_extraction_robustness.py -k retry -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extraction_robustness.py
git commit -m "feat(extract): add stub-engine retry-decision helper"
```

---

### Task 2: Stub-archive command builder (pure)

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py` (module-level, beside Task 1's helper)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Consumes: nothing
- Produces: `STUB_ENGINE_PATH: str` constant; `_stub_engine_build_cmd(stub_path: str = STUB_ENGINE_PATH) -> str`

- [ ] **Step 1: Write the failing test**

```python
from liberator_adapter.extractors.llvm_extractor import (
    _stub_engine_build_cmd, STUB_ENGINE_PATH)


def test_stub_cmd_builds_valid_archive():
    cmd = _stub_engine_build_cmd("/tmp/x.a")
    # builds an object with clang-14 then packs it into a non-empty ar archive
    assert "/usr/lib/llvm-14/bin/clang" in cmd
    assert "ar crs /tmp/x.a" in cmd
    assert ".c" in cmd and "-c" in cmd  # compiles a stub TU, not an empty archive


def test_stub_cmd_default_path():
    assert STUB_ENGINE_PATH in _stub_engine_build_cmd()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_extraction_robustness.py -k stub_cmd -v`
Expected: FAIL with `cannot import name '_stub_engine_build_cmd'`

- [ ] **Step 3: Write minimal implementation**

```python
STUB_ENGINE_PATH = "/tmp/logicfuzz_stub_engine.a"


def _stub_engine_build_cmd(stub_path: str = STUB_ENGINE_PATH) -> str:
    """Shell command (run in-container) that builds a valid, non-empty static
    archive to stand in for LIB_FUZZING_ENGINE so cmake `if(NOT FUZZ_LIBRARY)`
    passes. The library builds before the fuzzer link, so the fuzzer link's
    later failure on this stub is harmless."""
    src = "/tmp/_lf_stub.c"
    obj = "/tmp/_lf_stub.o"
    clang = "/usr/lib/llvm-14/bin/clang"
    return (
        f"echo 'static int _lf_stub;' > {src} && "
        f"{clang} -c {src} -o {obj} && "
        f"ar crs {stub_path} {obj}"
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_extraction_robustness.py -k stub_cmd -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py tests/test_extraction_robustness.py
git commit -m "feat(extract): add stub-engine archive command builder"
```

---

### Task 3: `bitcode_recovery` telemetry field

**Files:**
- Modify: `liberator_adapter/extractors/base_extractor.py:57-65` (`extraction_status_fields`)
- Modify: `tests/test_extraction_robustness.py` (update the existing exact-dict assertions to include the new key)
- Test: `tests/test_extraction_robustness.py`

**Interfaces:**
- Produces: `extraction_status_fields(clang_only, reason, recovery=None) -> dict` now also returns key `"bitcode_recovery"`.

- [ ] **Step 1: Write the failing test + update existing assertions**

Add new test:

```python
def test_status_fields_full_with_recovery():
    from liberator_adapter.extractors.base_extractor import extraction_status_fields
    assert extraction_status_fields(False, None, recovery="stub_engine") == {
        "extraction_mode": "full", "degraded_reason": None,
        "bitcode_recovery": "stub_engine"}
```

Update the two existing exact-equality tests at the top of the file so they include the new key:

```python
def test_status_fields_full():
    assert extraction_status_fields(False, None) == {
        "extraction_mode": "full", "degraded_reason": None,
        "bitcode_recovery": None}

def test_status_fields_degraded_enum():
    assert extraction_status_fields(True, DegradedReason.SVF_TIMEOUT) == {
        "extraction_mode": "clang_only", "degraded_reason": "svf_timeout",
        "bitcode_recovery": None}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_extraction_robustness.py -k status_fields -v`
Expected: FAIL — `test_status_fields_full` and `test_status_fields_full_with_recovery` fail on the missing `bitcode_recovery` key / unexpected kwarg.

- [ ] **Step 3: Write minimal implementation**

Replace `extraction_status_fields` in `base_extractor.py`:

```python
def extraction_status_fields(clang_only, reason, recovery=None):
    """Single source of truth for the persisted extraction-status fields.

    recovery: name of the recovery path that produced usable bitcode
    (e.g. "stub_engine"), or None. Only meaningful in full mode."""
    if not clang_only:
        return {"extraction_mode": "full", "degraded_reason": None,
                "bitcode_recovery": recovery}
    if isinstance(reason, DegradedReason):
        reason = reason.value
    return {"extraction_mode": "clang_only",
            "degraded_reason": reason or DegradedReason.COMPILE_FAILED.value,
            "bitcode_recovery": None}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_extraction_robustness.py -v`
Expected: PASS (all — new + updated + the existing _pick_source_dir/sanitize tests)

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/extractors/base_extractor.py tests/test_extraction_robustness.py
git commit -m "feat(extract): add bitcode_recovery telemetry field"
```

---

### Task 4: Wire stub-engine retry into `compile_to_bitcode` + thread telemetry + doc the flag

**Files:**
- Modify: `liberator_adapter/extractors/llvm_extractor.py:182-291` (`compile_to_bitcode` body: factor out `_run_compile_and_find_lib`, add retry)
- Modify: `liberator_adapter/extractors/hybrid_extractor.py:256-275` (thread `bitcode_recovery` into full-mode `last_metadata`)
- Modify: `CLAUDE.md` (Flag Reference — add `LOGICFUZZ_STUB_ENGINE_RETRY`)

**Interfaces:**
- Consumes: `_should_retry_with_stub_engine`, `_stub_engine_build_cmd`, `STUB_ENGINE_PATH` (Tasks 1-2); `extraction_status_fields(..., recovery=...)` (Task 3).
- Produces: `LLVMAPIExtractor._run_compile_and_find_lib(self, engine_path: str) -> tuple[Optional[str], str]` (returns `(lib_path_or_None, compile_stdout)`); sets `self.bitcode_recovery: Optional[str]` (`"stub_engine"` when the stub retry produced the lib, else `None`).

> **Note:** this task is build-I/O orchestration (needs a container), so it has no standalone unit test. Its safety net is (a) the pure helpers already unit-tested in Tasks 1-3, (b) `import` + the full `pytest tests/test_extraction_robustness.py` still passing, and (c) the end-to-end verification in Task 5. Do NOT skip Task 5.

- [ ] **Step 1: Factor compile+search into a helper, store cleaned flags on self**

In `compile_to_bitcode`, after computing `_cf_clean`/`_cxf_clean` (the existing `sanitize_extraction_flags` block ~lines 216-223), store them and the source dir on `self` so the helper can use them:

```python
        self._cf_clean = _cf_clean
        self._cxf_clean = _cxf_clean
        self._bc_source_dir = source_dir
        self.bitcode_recovery = None
```

Add this new method to `LLVMAPIExtractor` (move the existing `compile_cmd` construction + the Strategy-1/Strategy-2 lib search verbatim into it, parameterized by `engine_path`):

```python
    def _run_compile_and_find_lib(self, engine_path):
        """Run the in-container `compile` with LIB_FUZZING_ENGINE=engine_path
        (rest of the extraction env unchanged), then search for the built static
        library. Returns (lib_file_or_None, compile_stdout)."""
        compile_cmd = (
            'export LLVM_COMPILER=clang && '
            'export LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin && '
            'export CC=wllvm && '
            'export CXX=wllvm++ && '
            'export SANITIZER=none && '
            f'export LIB_FUZZING_ENGINE="{engine_path}" && '
            'export FUZZING_ENGINE=none && '
            f'export CFLAGS="{self._cf_clean}" && '
            f'export CXXFLAGS="{self._cxf_clean}" && '
            'compile 2>&1'
        )
        compile_result = self.container.execute(compile_cmd, timeout=600)
        output = compile_result.stdout or ""
        if compile_result.returncode != 0:
            logger.warning("Compile script returned error, but library may still exist")
            output_lines = output.strip().split('\n')
            last_lines = '\n'.join(output_lines[-50:]) if len(output_lines) > 50 else output
            logger.info(f"Compile output (last 50 lines):\n{last_lines}")

        lib_file = None
        project_name = self.benchmark.project
        project_lib_patterns = [
            f'lib{project_name}*.a', f'lib{project_name}*.so',
            f'{project_name}*.a', f'{project_name}*.so',
        ]
        search_dirs = [f'/src/{project_name}', self._bc_source_dir, '/src', '/out', '/work']
        for search_dir in search_dirs:
            for pattern in project_lib_patterns:
                find_result = self.container.execute(
                    f'find {search_dir} -name "{pattern}" -type f 2>/dev/null | head -1')
                if find_result.returncode == 0 and find_result.stdout.strip():
                    lib_file = find_result.stdout.strip()
                    logger.info(f"Found project library: {lib_file}")
                    break
            if lib_file:
                break
        if not lib_file:
            project_dir = f'/src/{project_name}'
            find_result = self.container.execute(
                f'find {project_dir} -name "*.a" -type f 2>/dev/null | head -1')
            if find_result.returncode == 0 and find_result.stdout.strip():
                lib_file = find_result.stdout.strip()
                logger.info(f"Found library in project dir: {lib_file}")
        return lib_file, output
```

- [ ] **Step 2: Replace the inline compile+search in `compile_to_bitcode` with the helper + retry**

Replace the old inline block (the `compile_cmd = (...)` through the `if not output_bc: ... raise RuntimeError(...)` lib-search, ~lines 225-291) with:

```python
        if not output_bc:
            lib_file, out = self._run_compile_and_find_lib("")
            if (lib_file is None
                    and os.getenv("LOGICFUZZ_STUB_ENGINE_RETRY", "1") != "0"
                    and _should_retry_with_stub_engine(out)):
                logger.warning(
                    "No library after blank-engine compile; retrying with stub "
                    "fuzzing engine (LIB_FUZZING_ENGINE=%s)", STUB_ENGINE_PATH)
                try:
                    stub_res = self.container.execute(_stub_engine_build_cmd())
                    if stub_res.returncode == 0:
                        lib_file, _ = self._run_compile_and_find_lib(STUB_ENGINE_PATH)
                        if lib_file is not None:
                            self.bitcode_recovery = "stub_engine"
                            logger.info("Stub-engine retry recovered library: %s", lib_file)
                    else:
                        logger.warning("Stub-engine archive build failed: %s", stub_res.stdout)
                except Exception as e:  # fail-open
                    logger.warning("Stub-engine retry errored (fail-open): %s", e)
            if lib_file:
                output_bc = f'{lib_file}.bc'
            else:
                raise RuntimeError(
                    f"Could not find library file for project '{self.benchmark.project}'. "
                    f"Searched for lib{self.benchmark.project}*.a/.so")
```

Ensure `import os` is present at the top of the file (it is — used elsewhere).

- [ ] **Step 3: Thread `bitcode_recovery` into the full-mode metadata**

In `hybrid_extractor.py`, the full-mode `last_metadata` block (line ~274) currently ends with `**extraction_status_fields(False, None),`. Change it to read the recovery marker the llvm_extractor stashed:

```python
                **extraction_status_fields(
                    False, None,
                    recovery=getattr(self.llvm_extractor, "bitcode_recovery", None)),
```

(The clang-only metadata path is unchanged — `extraction_status_fields(True, reason)` defaults `recovery=None`.)

- [ ] **Step 4: Document the flag in CLAUDE.md**

Under "Flag / Gate Reference" → "Construction / depth / dedup levers" (or the extraction/SVF config block), add:

```
- `LOGICFUZZ_STUB_ENGINE_RETRY=0` — opt OUT of the bitcode-extraction stub-engine retry (default-on, fail-open): when the blank-engine `compile` builds no `.a` and the failure references the fuzzing engine (cmake `FUZZ_LIBRARY` etc.), retry the project's own build with a stub `ar` archive at `$LIB_FUZZING_ENGINE` so the library builds for SVF (`llvm_extractor._run_compile_and_find_lib` + `_should_retry_with_stub_engine`). Records `bitcode_recovery="stub_engine"` in the extraction summary. libjpeg-turbo-class fix; stays on LLVM-14.
```

- [ ] **Step 5: Verify imports + full unit suite still pass**

Run: `python3 -c "import liberator_adapter.extractors.llvm_extractor, liberator_adapter.extractors.hybrid_extractor"`
Expected: no error.
Run: `python3 -m pytest tests/test_extraction_robustness.py -v`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add liberator_adapter/extractors/llvm_extractor.py liberator_adapter/extractors/hybrid_extractor.py CLAUDE.md
git commit -m "feat(extract): stub-engine retry recovers SVF bitcode for cmake-fuzz-engine projects"
```

---

### Task 5: End-to-end verification (recovery + regression)

**Files:** none (verification only). Use `LOGICFUZZ_NO_CACHE=1` and the model the user is using (`-l deepseek-v4-pro`).

> Run these sequentially (no concurrent docker runs — the repo has a documented container-leak/host-flood risk). Each run can take minutes (extraction) to longer (full `--eval`). For verification, `--extract-only` is enough to confirm bitcode recovery without the full trial loop.

- [ ] **Step 1: libjpeg-turbo now reaches FULL extraction (the recovery case)**

Run: `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/libjpeg-turbo.yaml --extract-only -l deepseek-v4-pro 2>&1 | tee results/_genruns_deepseek/libjpeg-turbo.verify.log`
Expected in log: `Stub-engine retry recovered library: …`, then `Found project library`, no `falling back to clang-only`.
Check: `python3 -c "import json; d=json.load(open('results/libjpeg-turbo/static_analysis/analysis_summary.json')); print(d.get('extraction_mode'), d.get('bitcode_recovery'))"`
Expected: `full stub_engine` (and `results/libjpeg-turbo/conditions.json` exists / non-empty).

- [ ] **Step 2: libpng regression — still full mode, retry NOT triggered**

Run: `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/libpng.yaml --extract-only -l deepseek-v4-pro 2>&1 | tee results/_genruns_deepseek/libpng.verify.log`
Expected: `Found project library: /src/libpng/.libs/libpng16.a`, NO `Stub-engine retry` line.
Check: `extraction_mode == full` and `bitcode_recovery == None` in `results/libpng/static_analysis/analysis_summary.json`.

- [ ] **Step 3: c-ares regression — still full mode, retry NOT triggered**

Run: `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/c-ares.yaml --extract-only -l deepseek-v4-pro 2>&1 | tee results/_genruns_deepseek/c-ares.verify.log`
Expected: `extraction_mode == full`, `bitcode_recovery == None`, no `Stub-engine retry` line.

- [ ] **Step 4: Record the outcome**

If libjpeg-turbo recovered and libpng/c-ares are unchanged → success; note results in the task tracker and proceed to a full `--eval` libjpeg-turbo run for the PromeFuzz comparison. If libjpeg-turbo still fails → the stub didn't satisfy its build; fall back to the documented fork `build.sh` path (spec §5) for libjpeg-turbo specifically, with the A≡B guardrail.

---

## Self-Review

**Spec coverage:**
- A2 stub-engine retry → Tasks 1, 2, 4. ✓
- Fail-open + kill-switch → Task 4 Step 2 (`try/except`, `LOGICFUZZ_STUB_ENGINE_RETRY`). ✓
- Telemetry `bitcode_recovery` → Tasks 3, 4 Step 3. ✓
- A4/C "no new code, keep working" → covered by Task 5 regression (libpng/c-ares). ✓
- Fork fallback (§5) → documented decision point in Task 5 Step 4 (not implemented — YAGNI, matches spec). ✓
- Stay on LLVM-14 → no version change anywhere. ✓
- Testing: unit (Tasks 1-3) + multi-project integration (Task 5). ✓

**Placeholder scan:** No TBD/TODO; every code step has complete code; commands have expected output. ✓

**Type consistency:** `_should_retry_with_stub_engine(str)->bool`, `_stub_engine_build_cmd(str)->str`, `STUB_ENGINE_PATH:str`, `_run_compile_and_find_lib(str)->tuple[Optional[str],str]`, `extraction_status_fields(clang_only,reason,recovery=None)->dict`, `self.bitcode_recovery:Optional[str]` — names/types used consistently across Tasks 1-4. ✓
