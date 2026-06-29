# Profdata Measurement Lock-In — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin the already-shipped profdata-first coverage measurement (`_export_coverage_from_profdata`, commit `ab55eae5`) with regression tests, and reconcile the design spec so it stops describing #0 as unbuilt.

**Architecture:** This is the Phase-0 "make the linchpin trustworthy" step of the big-bang rebuild (`docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md`). The profdata-first path already works and is the primary measurement path; its only gap is **zero test coverage**. These are **characterization/regression tests** — they PIN existing behavior, so they PASS on first run. A failure means a real bug or a wrong behavioral assumption — investigate, do not "fix" the test to make it green.

**Tech Stack:** Python 3, pytest, `importlib` module loading, `monkeypatch` + `tmp_path` fixtures. No docker required (subprocess is faked). No new dependencies.

## Global Constraints

- **No docker / no real fuzz run in tests** — fake `subprocess.run` via `monkeypatch`; fabricate `build_out` files via `tmp_path`. (Established pattern: `tests/test_run_merge_pipeline.py`, `tests/test_pipeline_dominance_stage.py`.)
- **No library-name keys** — measurement logic is library-agnostic; tests must not special-case a library by name (the single-source test uses cjson only as a *shape* example: small non-zero totals).
- **Do NOT add an `n_files<2` / file-count floor** — `scripts/run_extended_fuzzing.py:1047-1052` deliberately uses an empty-totals gate instead, so a single-source library (cJSON.c) is not false-rejected. One test pins this decision.
- **Module load pattern:** `ext = importlib.import_module("scripts.run_extended_fuzzing")`; reach instance methods via `ext.ExtendedFuzzer.__new__(ext.ExtendedFuzzer)` + set only the attrs the method reads (`target_name`).

---

## File Structure

- **Create:** `tests/test_profdata_measurement.py` — characterization tests for `_export_coverage_from_profdata`. One responsibility: pin the profdata-first export contract (happy path, fail-open, garbage-reject, single-source pin, error handling).
- **Modify:** `docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md` — mark #0 done, drop the `n_files<2` gate + per-input replay, re-frame the Phase-0 "blocked until measurement" narrative.

---

### Task 1: Characterization tests for `_export_coverage_from_profdata`

**Files:**
- Create: `tests/test_profdata_measurement.py`
- Pins (does not modify): `scripts/run_extended_fuzzing.py:1014-1064` (`_export_coverage_from_profdata`)

**Interfaces:**
- Consumes: `ext.ExtendedFuzzer._export_coverage_from_profdata(self, build_out: Path) -> Optional[CoverageData]`; reads only `self.target_name`. Builds files at `build_out/dumps/merged.profdata` and `build_out/<target_name>`; runs `subprocess.run(...)` whose `.stdout` is an `llvm-cov export -summary-only` JSON (`data[0].totals.{lines,branches,functions}` with `count`/`covered`/`percent`).
- Produces: `CoverageData` dataclass (`run_extended_fuzzing.py:65-77`) with fields incl. `branches_covered`, `branches_total`.

- [ ] **Step 1: Write the characterization test file**

```python
# tests/test_profdata_measurement.py
"""Characterization/regression tests for the profdata-first coverage path
(scripts/run_extended_fuzzing.py:_export_coverage_from_profdata, shipped in
ab55eae5). These PIN existing behavior — they PASS against current code. A
failure indicates a real regression or a wrong assumption, not a test to relax."""
import importlib
import json
import types

ext = importlib.import_module("scripts.run_extended_fuzzing")


def _make_fuzzer(target_name="fuzz_target"):
    """A bare ExtendedFuzzer exposing only what the method under test reads."""
    obj = ext.ExtendedFuzzer.__new__(ext.ExtendedFuzzer)
    obj.target_name = target_name
    return obj


def _build_out(tmp_path, target_name="fuzz_target"):
    """Fabricate the build_out dir with the profdata + binary the guard requires."""
    (tmp_path / "dumps").mkdir(parents=True, exist_ok=True)
    (tmp_path / "dumps" / "merged.profdata").write_bytes(b"\x00")
    (tmp_path / target_name).write_bytes(b"\x7fELF")
    return tmp_path


def _totals_json(branches_covered, branches_count, lines_count=10, funcs_count=2):
    pct = (100.0 * branches_covered / branches_count) if branches_count else 0.0
    return json.dumps({"data": [{"totals": {
        "lines": {"count": lines_count, "covered": lines_count, "percent": 100.0},
        "branches": {"count": branches_count, "covered": branches_covered, "percent": pct},
        "functions": {"count": funcs_count, "covered": funcs_count, "percent": 100.0},
    }}]})


def _patch_run(monkeypatch, returncode=0, stdout=""):
    def fake_run(cmd, *a, **k):
        return types.SimpleNamespace(returncode=returncode, stdout=stdout)
    monkeypatch.setattr(ext.subprocess, "run", fake_run)


def test_profdata_returns_coverage_on_valid_totals(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(899, 924))
    cd = _make_fuzzer()._export_coverage_from_profdata(bo)
    assert cd is not None
    assert cd.branches_covered == 899
    assert cd.branches_total == 924


def test_profdata_none_when_profdata_missing(tmp_path, monkeypatch):
    (tmp_path / "fuzz_target").write_bytes(b"\x7fELF")  # binary present, profdata absent
    _patch_run(monkeypatch, 0, _totals_json(1, 1))
    assert _make_fuzzer()._export_coverage_from_profdata(tmp_path) is None


def test_profdata_none_when_binary_missing(tmp_path, monkeypatch):
    (tmp_path / "dumps").mkdir()
    (tmp_path / "dumps" / "merged.profdata").write_bytes(b"\x00")  # profdata present, binary absent
    _patch_run(monkeypatch, 0, _totals_json(1, 1))
    assert _make_fuzzer()._export_coverage_from_profdata(tmp_path) is None


def test_profdata_rejects_empty_totals_garbage(tmp_path, monkeypatch):
    # The deliberate degeneracy gate: an all-zero/un-instrumented profile is rejected.
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(0, 0, lines_count=0))
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None


def test_profdata_keeps_single_source_library(tmp_path, monkeypatch):
    # REGRESSION PIN (run_extended_fuzzing.py:1047-1052): a single-source lib
    # (cJSON.c shape) has small but NON-zero totals and must NOT be rejected.
    # This pins the decision to use empty-totals, NOT an n_files<2 file-count floor.
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, _totals_json(40, 80, lines_count=120))
    cd = _make_fuzzer()._export_coverage_from_profdata(bo)
    assert cd is not None
    assert cd.branches_covered == 40


def test_profdata_none_on_nonzero_returncode(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 1, "")
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None


def test_profdata_none_on_malformed_json(tmp_path, monkeypatch):
    bo = _build_out(tmp_path)
    _patch_run(monkeypatch, 0, "not json{{")
    assert _make_fuzzer()._export_coverage_from_profdata(bo) is None
```

- [ ] **Step 2: Run the tests — expect PASS (pins existing behavior)**

Run: `python3 -m pytest tests/test_profdata_measurement.py -v`
Expected: 7 passed. (These characterize shipped code; if any FAILS, investigate the discrepancy in `_export_coverage_from_profdata` — do NOT weaken the test. In particular `test_profdata_keeps_single_source_library` must pass: a failure means someone re-introduced a file-count floor.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_profdata_measurement.py
git commit -m "test(measure): characterize profdata-first coverage path (#0 lock-in)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

### Task 2: Reconcile the design spec with shipped reality

**Files:**
- Modify: `docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Update capability ① (MEASURE) to mark #0 done**

In the "① Profdata-first MEASURE" block, replace the `n_files<2` sanity-gate sentence and the per-input `-timeout=10 -runs=0` replay description with a note that the path is **already shipped (`ab55eae5`)**: it exports from the OSS-Fuzz-produced `dumps/merged.profdata` via `llvm-cov export -summary-only` → `data[0].totals`, uses an **empty-totals** reject gate (NOT a file-count floor — a single-source lib like cJSON must not be false-rejected), and fails open to the live libFuzzer edge count. The only remaining work was **test lock-in (Task 1 of the measurement plan)**.

- [ ] **Step 2: Re-frame the Phase-0 narrative + success-criteria row**

In "Build structure → Phase 0", change "Build #0 profdata-first measurement" to "**Verify + test-lock** the already-shipped profdata-first measurement; freeze the current pipeline as the A/B control." In "Risks", soften "#0 measurement is the linchpin — every A/B is unfalsifiable until it lands" to "#0 measurement already shipped (`ab55eae5`) + now test-pinned; the residual risk is regression, guarded by `tests/test_profdata_measurement.py`." In the success-criteria table, change the "Measurement trustworthy" status from "must-pass (to build)" framing to "**done + test-pinned**".

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-06-26-rearchitecture-to-beat-promefuzz-design.md
git commit -m "docs(spec): reconcile #0 measurement — already shipped (ab55eae5), drop n_files<2/replay

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018Zgv7UeDvvCdc2WeUwc7L5"
```

---

## Deferred (documented, NOT a placeholder)

- **Carry-forward / no-0.0-sawtooth test** for `_take_snapshot` (`run_extended_fuzzing.py:1328-1350`): pins that a `None` measurement carries forward the prior real coverage (with fresh `edge_coverage`) instead of fabricating 0.0. Deferred because it requires characterizing `_parse_fuzzer_stats`'s exact return-dict keys and `FuzzingSnapshot`'s required fields first — out of scope for a thin lock-in, and pulled into the later **A/B validation-harness plan** (where that snapshot machinery is exercised anyway). Tracked here so it is not lost.

## Self-Review

- **Spec coverage:** Plan covers the spec's capability ① (MEASURE) — pins it (Task 1) and reconciles the stale spec text (Task 2). No other spec section is in this plan's scope (this is Phase-0 measurement only; later subsystems get their own plans).
- **Placeholder scan:** No "TBD"/"add error handling"/"similar to". All test code is complete and runnable. The one deferral is explicitly rationale'd, not a hidden gap.
- **Type consistency:** `_export_coverage_from_profdata(self, build_out)` and `CoverageData.branches_covered/branches_total` match `run_extended_fuzzing.py:1014,1056-1064`. `ext.subprocess`/`ext.ExtendedFuzzer` match the module's globals. Fake `subprocess.run` returns `.returncode`/`.stdout` exactly as the code reads (lines 1040,1043).
- **TDD-adaptation note:** these are characterization tests for shipped code, so Step 2 expects PASS (not the usual fail-first), with explicit guidance to investigate rather than relax on failure — called out so an executor isn't confused by the inverted cycle.
