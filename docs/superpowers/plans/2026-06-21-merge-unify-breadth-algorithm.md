# Merge Unification + Measured Dominance-Filter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify the two merge orchestrations into one shared `run_merge_pipeline`, and add a measured dominance-filter selector (keep-all-non-dominated) that ships at merge time, directly integrated with no flag.

**Architecture:** Extract the production merge body (`run_single_fuzz._maybe_merge_drivers`) into `tools/merge_drivers/pipeline.py:run_merge_pipeline`; both entry points (production + manual CLI) become thin adapters. Add a pure, deterministic dominance-filter to `tools/merge_drivers/select.py` and run it once, after the compile-validation gate, on per-driver measured coverage.

**Tech Stack:** Python 3, pytest, existing `tools/merge_drivers/{merge,preflight,select,compile_validate,orphan_filter,corpus}.py`.

**Spec:** `docs/superpowers/specs/2026-06-21-merge-unify-breadth-algorithm-design.md`.

## Global Constraints

- **A≡B invariant:** the dominance-filter runs strictly AFTER `_compile_validate_candidates`, so the shipped set ⊆ the compile-validated set. Never select over a pre-validation set.
- **Distinct-API guarantee:** the dominance-filter may only drop a driver whose measured reached-function set is a (non-strict) subset of another KEPT driver. The union of reached functions over the kept set MUST equal the union over the full input pool. This is the formal safety net that replaces a feature flag.
- **No flag:** the dominance-filter is default behavior. The only fallback is a correctness one: when fewer than 2 drivers have real coverage data, it is a no-op (keep all).
- **Dispatch:** UNIFORM remains the default (CDF only under `LOGICFUZZ_CDF_DISPATCH=1`). Unchanged.
- **Determinism:** no result may depend on input order or `PYTHONHASHSEED`. Sort all iterations.
- **Fail-open:** any exception in the merge pipeline returns `None`/keeps-all, never raises into the main run (preserve current `try/except` envelope).
- **Multi-project:** validate on lcms, cjson, c-ares, libpng — not lcms alone.

---

### Task 1: Measured dominance-filter (pure function)

**Files:**
- Modify: `tools/merge_drivers/select.py` (add `DominanceResult` + `dominance_filter`)
- Modify: `tools/merge_drivers/__init__.py` (export the two new names)
- Test: `tests/test_dominance_filter.py` (create)

**Interfaces:**
- Consumes: `DriverCoverage` (existing, `select.py:38-105`) with `.reached_funcs: FrozenSet[str]`, `.edges_15s: int`, `.has_real_data: bool`, `.driver_path: Path`.
- Produces: `dominance_filter(coverages: Sequence[DriverCoverage]) -> DominanceResult` where `DominanceResult` has `.kept: List[DriverCoverage]` and `.dropped: List[DriverCoverage]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dominance_filter.py
from pathlib import Path
from tools.merge_drivers.select import DriverCoverage, dominance_filter


def _cov(name, funcs, edges=0, real=True):
    return DriverCoverage(
        driver_path=Path(f"/x/{name}.fuzz_target"),
        reached_funcs=frozenset(funcs),
        edges_15s=edges,
        has_real_data=real,
    )


def test_drops_strict_subset_keeps_partial_overlap():
    a = _cov("a", {1, 2})
    b = _cov("b", {2, 3})
    c = _cov("c", {1, 3})
    sub = _cov("sub", {2})           # strict subset of a and b
    res = dominance_filter([a, b, c, sub])
    kept = {d.driver_path.stem for d in res.kept}
    assert kept == {"a", "b", "c"}   # partial-overlap all kept; only the subset drops
    assert {d.driver_path.stem for d in res.dropped} == {"sub"}


def test_distinct_api_union_is_preserved():
    drivers = [_cov("a", {1, 2}), _cov("b", {2, 3}), _cov("c", {1, 3}), _cov("sub", {2})]
    res = dominance_filter(drivers)
    union_in = set().union(*(d.reached_funcs for d in drivers))
    union_kept = set().union(*(d.reached_funcs for d in res.kept))
    assert union_kept == union_in    # the dominance guarantee


def test_exact_duplicate_tiebreak_keeps_higher_edges_then_name():
    hi = _cov("zz", {1, 2}, edges=99)
    lo = _cov("aa", {1, 2}, edges=1)
    res = dominance_filter([lo, hi])
    assert [d.driver_path.stem for d in res.kept] == ["zz"]   # higher edges wins
    assert [d.driver_path.stem for d in res.dropped] == ["aa"]


def test_no_data_driver_always_kept():
    real = _cov("real", {1, 2, 3})
    fb = _cov("fb", {"__fallback__:fb"}, real=False)
    res = dominance_filter([real, fb])
    assert {d.driver_path.stem for d in res.kept} == {"real", "fb"}


def test_deterministic_under_input_reordering():
    drivers = [_cov("a", {1, 2}), _cov("b", {2, 3}), _cov("c", {1, 3}), _cov("sub", {2})]
    r1 = [d.driver_path.stem for d in dominance_filter(drivers).kept]
    r2 = [d.driver_path.stem for d in dominance_filter(list(reversed(drivers))).kept]
    assert sorted(r1) == sorted(r2)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_dominance_filter.py -q`
Expected: FAIL with `ImportError: cannot import name 'dominance_filter'`.

- [ ] **Step 3: Implement the dominance-filter**

Add to `tools/merge_drivers/select.py` (after `SelectionResult`, before `select_top_k`). Add `Sequence` is already imported; add nothing else.

```python
@dataclass
class DominanceResult:
    """Output of ``dominance_filter``: the kept (shipped) drivers and the
    fully-dominated ones removed (each dropped driver's reached set is a subset
    of some kept driver, so the union is unchanged)."""

    kept: List[DriverCoverage] = field(default_factory=list)
    dropped: List[DriverCoverage] = field(default_factory=list)


def dominance_filter(coverages: Sequence[DriverCoverage]) -> DominanceResult:
    """Keep every driver whose measured reached-function set is NOT fully
    contained in another KEPT driver; drop only fully-dominated drivers.

    Guarantee: the union of ``reached_funcs`` over ``kept`` equals the union over
    ``coverages`` — a dropped driver adds nothing the kept set does not already
    cover. So this cannot remove any distinct reached function (no breadth loss).

    - A driver with ``has_real_data == False`` is ALWAYS kept (its fallback
      singleton is unique, never a subset of a real set).
    - Exact duplicates (mutually-contained sets): the one with higher
      ``edges_15s``, then lexicographically smaller ``driver_path.name``, is
      kept; the other is dropped.
    - Deterministic and order-independent: candidates are processed
      largest-set-first (edges, then name as tie-breaks), so a dominator is
      always seen before any driver it dominates.
    """
    real = [c for c in coverages if c.has_real_data]
    nodata = [c for c in coverages if not c.has_real_data]

    order = sorted(
        real,
        key=lambda c: (-len(c.reached_funcs), -c.edges_15s, c.driver_path.name),
    )
    kept: List[DriverCoverage] = []
    dropped: List[DriverCoverage] = []
    for c in order:
        if any(c.reached_funcs <= k.reached_funcs for k in kept):
            dropped.append(c)
        else:
            kept.append(c)

    kept.extend(nodata)  # no-data drivers are never dominated
    return DominanceResult(kept=kept, dropped=dropped)
```

Then export in `tools/merge_drivers/__init__.py`: add `DominanceResult` and `dominance_filter` to both the `from tools.merge_drivers.select import (...)` block (lines 37-42) and the `__all__` list (lines 45-58).

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_dominance_filter.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add tools/merge_drivers/select.py tools/merge_drivers/__init__.py tests/test_dominance_filter.py
git commit -m "feat(merge): measured dominance-filter (keep-all-non-dominated) selector"
```

---

### Task 2: Extract `run_merge_pipeline` (behavior-preserving)

**Files:**
- Create: `tools/merge_drivers/pipeline.py`
- Modify: `run_single_fuzz.py` (move helpers + body out; `_maybe_merge_drivers` → adapter)
- Test: `tests/test_run_merge_pipeline.py` (create)

**Interfaces:**
- Produces: `run_merge_pipeline(candidates: List[Path], *, project: str, stock_lang: Optional[str], iquote_dirs: List[str], out_dir: Path, trial_verdicts: Optional[dict] = None, preflight_dir: Optional[Path] = None, cov_reports_dir: Optional[Path] = None, model_name: Optional[str] = None, cdf: bool = False) -> Optional[str]`. Returns the merged output dir path, or `None` when <2 survive (unchanged contract). `trial_verdicts` maps `candidate Path -> (crashes: bool, real_bug: bool)` for the quarantine stage; `None` skips quarantine (CLI has no verdicts).
- Consumes: the existing leaf primitives + the merge-only helpers, now living in `pipeline.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_run_merge_pipeline.py
import importlib


def test_pipeline_module_exposes_run_merge_pipeline():
    mod = importlib.import_module("tools.merge_drivers.pipeline")
    assert hasattr(mod, "run_merge_pipeline")
    assert hasattr(mod, "MergeResult") or callable(mod.run_merge_pipeline)


def test_run_single_fuzz_adapter_delegates(monkeypatch):
    # _maybe_merge_drivers must call run_merge_pipeline (no duplicated orchestration)
    import run_single_fuzz
    import tools.merge_drivers.pipeline as pipe
    called = {}
    def fake(candidates, **kw):
        called["candidates"] = list(candidates)
        called["kw"] = kw
        return "/tmp/merged"
    monkeypatch.setattr(pipe, "run_merge_pipeline", fake)

    class _BR:  # minimal best_result
        compiles = True
        cov_pcs = 0
    class _TR:
        trial = 1
        best_result = _BR()
    class _Bench:
        project = "demo"
        file_type = ".c"
    class _WD:
        base = "/tmp/wd"
        fuzz_targets = "/tmp/wd/ft"
    # 2 compiling, non-crashing trials with on-disk sources
    import os
    os.makedirs("/tmp/wd/ft", exist_ok=True)
    for i in (1, 2):
        open(f"/tmp/wd/ft/{i:02d}.fuzz_target", "w").write("int x;")
    trs = []
    for i in (1, 2):
        tr = _TR(); tr.trial = i; trs.append(tr)
    monkeypatch.setattr(run_single_fuzz, "_should_quarantine_from_merge",
                        lambda br, tr: False, raising=False)
    out = run_single_fuzz._maybe_merge_drivers(_Bench(), _WD(), trs)
    assert out == "/tmp/merged"
    assert len(called["candidates"]) == 2
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_run_merge_pipeline.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.merge_drivers.pipeline'`.

- [ ] **Step 3: Create `pipeline.py` and move the orchestration + helpers**

1. Create `tools/merge_drivers/pipeline.py`. MOVE these functions VERBATIM from `run_single_fuzz.py` into it (cut from run_single_fuzz.py:512-887): `_is_immediate_crash_fp`, `_should_quarantine_from_merge`, `_trial_confirms_real_bug`, `_preflight_rejection_set`, `_preflight_filter_candidates`, `_compile_validate_candidates`, `_edges_weights_for`, `_stock_target_lang`, `_iquote_dirs_for_target`, `_is_degenerate_binary_set`, `_resolve_candidate_binary`. Fix their imports (they use `logger`, `os`, `Path`, the `tools.merge_drivers.*` leaves) by importing those at the top of `pipeline.py`. Replace any `benchmark`/`work_dirs` attribute access inside them with the explicit params (`project`, `stock_lang`, `iquote_dirs`, `preflight_dir`).
2. Add `run_merge_pipeline(...)` with the body of `_maybe_merge_drivers` (run_single_fuzz.py:924-1082), parameterized: replace `getattr(benchmark, 'project', '')` → `project`; `_stock_target_lang(benchmark)` → `stock_lang`; `_iquote_dirs_for_target(benchmark)` → `iquote_dirs`; `Path(work_dirs.base) / 'merged'` → `out_dir`; the quarantine loop reads `trial_verdicts` instead of `_should_quarantine_from_merge(br, tr)` — when `trial_verdicts is None`, skip quarantine. `_preflight_filter_candidates`/`_compile_validate_candidates` take `preflight_dir`/`project`/`stock_lang`/`iquote_dirs` explicitly.
3. Keep `select.dominance_filter` UNused for now (wired in Task 3) so this task is behavior-preserving.

- [ ] **Step 4: Rewrite `_maybe_merge_drivers` as an adapter**

Replace `run_single_fuzz._maybe_merge_drivers` (the whole function) with:

```python
def _maybe_merge_drivers(benchmark, work_dirs, trial_results, model_name=None):
  """Adapter onto tools.merge_drivers.pipeline.run_merge_pipeline (the SSOT)."""
  from pathlib import Path
  from tools.merge_drivers import pipeline as _pipe
  candidates, verdicts = [], {}
  for tr in trial_results:
    if not tr or not getattr(tr, 'best_result', None):
      continue
    br = tr.best_result
    if not getattr(br, 'compiles', False):
      continue
    src = Path(work_dirs.fuzz_targets) / f'{tr.trial:02d}.fuzz_target'
    if not src.exists():
      continue
    candidates.append(src)
    verdicts[src] = _pipe._should_quarantine_from_merge(br, tr)
  return _pipe.run_merge_pipeline(
      candidates,
      project=getattr(benchmark, 'project', '') or '',
      stock_lang=_pipe._stock_target_lang(benchmark),
      iquote_dirs=_pipe._iquote_dirs_for_target(benchmark),
      out_dir=Path(work_dirs.base) / 'merged',
      trial_verdicts=verdicts,
      preflight_dir=Path(work_dirs.base) / 'preflight_bins',
      cov_reports_dir=Path(getattr(work_dirs, 'code_coverage_report', '') or
                           (Path(work_dirs.base) / 'code-coverage-reports')),
      model_name=model_name,
      cdf=os.environ.get('LOGICFUZZ_CDF_DISPATCH', '0').strip().lower()
          in ('1', 'true', 'yes', 'on'))
```

In `run_merge_pipeline`, the quarantine loop becomes: `if trial_verdicts is not None and trial_verdicts.get(src): quarantined += 1; continue` (the adapter pre-computed the verdict bool per source).

- [ ] **Step 5: Run the tests to verify they pass + no import breakage**

Run: `python3 -c "import run_single_fuzz, tools.merge_drivers.pipeline" && python3 -m pytest tests/test_run_merge_pipeline.py tests/ -k "merge or orphan or preflight or quarantine or dominance" -q`
Expected: PASS (the existing merge/orphan/preflight/quarantine suites + the 2 new tests).

- [ ] **Step 6: Commit**

```bash
git add tools/merge_drivers/pipeline.py run_single_fuzz.py tests/test_run_merge_pipeline.py
git commit -m "refactor(merge): extract run_merge_pipeline; _maybe_merge_drivers is now an adapter"
```

---

### Task 3: Wire the dominance-filter into `run_merge_pipeline`

**Files:**
- Modify: `tools/merge_drivers/pipeline.py` (add the dominance stage after compile-validate)
- Test: `tests/test_pipeline_dominance_stage.py` (create)

**Interfaces:**
- Consumes: `select.dominance_filter`, `select.DriverCoverage.from_oss_fuzz_report`, `_edges_weights_for` (for edges_15s).
- Produces: dominance-filtered `successful_sources` before synthesis.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline_dominance_stage.py
from pathlib import Path
from tools.merge_drivers import pipeline as pipe


def test_dominance_stage_drops_subset_when_reports_present(tmp_path, monkeypatch):
    # 3 sources; build cov reports so B's set ⊆ A's set → B dropped.
    srcs = []
    for n in ("a", "b", "c"):
        p = tmp_path / f"{n}.fuzz_target"; p.write_text("int x;"); srcs.append(p)
    reports = tmp_path / "reports"
    def _funcs(names):
        return {"data": [{"functions": [{"name": x, "count": 1} for x in names]}]}
    import json
    for n, fs in (("a", ["f1", "f2", "f3"]), ("b", ["f1"]), ("c", ["f9"])):
        d = reports / f"{n}.fuzz_target" / "linux"; d.mkdir(parents=True)
        (d / "summary.json").write_text(json.dumps(_funcs(fs)))
    kept = pipe._apply_dominance(srcs, cov_reports_dir=reports)
    names = sorted(p.stem for p in kept)
    assert names == ["a", "c"]            # b ⊆ a → dropped


def test_dominance_stage_noop_without_reports(tmp_path):
    srcs = [tmp_path / f"{n}.fuzz_target" for n in ("a", "b")]
    for p in srcs:
        p.write_text("int x;")
    kept = pipe._apply_dominance(srcs, cov_reports_dir=tmp_path / "nope")
    assert sorted(p.stem for p in kept) == ["a", "b"]   # keep-all fallback
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_pipeline_dominance_stage.py -q`
Expected: FAIL — `AttributeError: module 'tools.merge_drivers.pipeline' has no attribute '_apply_dominance'`.

- [ ] **Step 3: Implement `_apply_dominance` and call it after compile-validate**

Add to `pipeline.py`:

```python
def _apply_dominance(sources, *, cov_reports_dir, edges=None):
    """Drop sources whose measured reached-function set is fully dominated by
    another kept source. No-op (keep all) when <2 sources have real coverage
    data — the correctness fallback. ``edges`` is an optional
    {Path: edges_15s} map for the exact-duplicate tie-break."""
    from tools.merge_drivers.select import DriverCoverage, dominance_filter
    edges = edges or {}
    covs = [
        DriverCoverage.from_oss_fuzz_report(
            s,
            (cov_reports_dir / s.name) if cov_reports_dir else None,
            edges_15s=int(edges.get(s, 0)),
        )
        for s in sources
    ]
    if sum(1 for c in covs if c.has_real_data) < 2:
        return list(sources)  # correctness fallback: never select blind
    res = dominance_filter(covs)
    return [c.driver_path for c in res.kept]
```

In `run_merge_pipeline`, immediately AFTER the compile-validation block (the `successful_sources = _compile_validate_candidates(...)` + its `< 2` guard) and BEFORE the `from tools.merge_drivers.merge import` synthesis block, insert:

```python
  _before = len(successful_sources)
  successful_sources = _apply_dominance(
      successful_sources, cov_reports_dir=cov_reports_dir,
      edges=(_edges_weights_for(successful_sources, work_dirs=None,
                                preflight_dir=preflight_dir) or {}))
  if len(successful_sources) < _before:
    logger.info(f'merge_drivers: dominance-filter dropped '
                f'{_before - len(successful_sources)} fully-redundant driver(s)',
                trial=0)
```

(If `_edges_weights_for`'s signature does not already accept `preflight_dir`, pass `{}` for `edges` instead — edges are only a tie-break, never required.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_pipeline_dominance_stage.py tests/test_dominance_filter.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/merge_drivers/pipeline.py tests/test_pipeline_dominance_stage.py
git commit -m "feat(merge): integrate dominance-filter after compile-validate (no flag)"
```

---

### Task 4: CLI adapters onto `run_merge_pipeline`

**Files:**
- Modify: `tools/merge_drivers/__main__.py` (`_cmd_merge`, `_cmd_pipeline` → adapters; delete `_trial_failed_to_build`)
- Test: `tests/test_merge_cli_adapter.py` (create)

**Interfaces:**
- Consumes: `pipeline.run_merge_pipeline`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_merge_cli_adapter.py
import tools.merge_drivers.__main__ as cli


def test_cmd_merge_calls_run_merge_pipeline(monkeypatch, tmp_path):
    import tools.merge_drivers.pipeline as pipe
    seen = {}
    monkeypatch.setattr(pipe, "run_merge_pipeline",
                        lambda candidates, **kw: seen.update(kw) or "/out")
    s1 = tmp_path / "01.c"; s1.write_text("int x;")
    s2 = tmp_path / "02.c"; s2.write_text("int y;")
    rc = cli._cmd_merge(type("A", (), {
        "inputs": [str(s1), str(s2)], "output": str(tmp_path / "m"),
        "project": "demo", "mode": "uniform", "position": "tail",
        "libs": None, "includes": None,
    })())
    assert "project" in seen and seen["project"] == "demo"


def test_trial_failed_to_build_removed():
    assert not hasattr(cli, "_trial_failed_to_build")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_merge_cli_adapter.py -q`
Expected: FAIL (`_trial_failed_to_build` still present and/or `_cmd_merge` does not delegate).

- [ ] **Step 3: Rewrite the CLI subcommands as adapters**

In `tools/merge_drivers/__main__.py`: DELETE `_trial_failed_to_build` (lines ~92-99) and the static-`HOLE[` heuristic. Rewrite `_cmd_merge` and `_cmd_pipeline` to gather their input paths and call `pipeline.run_merge_pipeline(...)` with `project=args.project` (add a `--project` arg; when absent, the compile gate fail-opens — keep all), `trial_verdicts=None` (CLI has no per-trial triage → quarantine skipped), `cov_reports_dir`/`corpus_root` from args (so the dominance-filter + corpus union run when data is supplied). Map `--mode/--position` to the same enums the pipeline uses.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_merge_cli_adapter.py tests/ -k "merge" -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/merge_drivers/__main__.py tests/test_merge_cli_adapter.py
git commit -m "refactor(merge): CLI subcommands delegate to run_merge_pipeline; drop static HOLE heuristic"
```

---

### Task 5: Multi-project static regression validation

**Files:**
- Test: `tests/test_merge_distinct_api_invariant.py` (create — pure, no docker)
- Modify: `CLAUDE.md` (Key Files: name `tools/merge_drivers/pipeline.run_merge_pipeline` as the merge SSOT); `docs/generation.md` §6 (one-line cross-ref)

**Interfaces:** none new.

- [ ] **Step 1: Write the invariant test (the dominance guarantee, property-style)**

```python
# tests/test_merge_distinct_api_invariant.py
import random
from pathlib import Path
from tools.merge_drivers.select import DriverCoverage, dominance_filter


def test_union_preserved_over_random_pools():
    rng = random.Random(0)   # fixed seed: deterministic, no PYTHONHASHSEED dep
    for _ in range(200):
        n = rng.randint(1, 12)
        drivers = [
            DriverCoverage(
                driver_path=Path(f"/x/{i}.fuzz_target"),
                reached_funcs=frozenset(rng.sample(range(8), rng.randint(0, 8))),
                edges_15s=rng.randint(0, 5),
            )
            for i in range(n)
        ]
        res = dominance_filter(drivers)
        union_in = set().union(*(d.reached_funcs for d in drivers)) if drivers else set()
        union_kept = set().union(*(d.reached_funcs for d in res.kept)) if res.kept else set()
        assert union_kept == union_in            # never lose a reached function
        assert len(res.kept) <= len(drivers)     # only ever drops
```

- [ ] **Step 2: Run it**

Run: `python3 -m pytest tests/test_merge_distinct_api_invariant.py -q`
Expected: PASS.

- [ ] **Step 3: Full suite — confirm no regression across the touched modules**

Run: `python3 -m pytest tests/ -k "merge or orphan or preflight or quarantine or dominance or pipeline" -q`
Expected: PASS (all).

- [ ] **Step 4: Live static A/B (manual, documented — not a unit test)**

For each of cjson, c-ares, lcms, libpng: run `LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/<proj>.yaml --eval -l deepseek-v4-pro --closed-loop-iters 1`, then read `results/output-<proj>-project/merged/` — record merged driver count + distinct-API union, and confirm `merged/compile_validation.json` shows shipped == compiled (A≡B). Expected: merged distinct-API union unchanged vs a keep-all run on the same candidates (dominance drops only fully-redundant drivers); lcms holds ≥69 merged-distinct APIs.

- [ ] **Step 5: Update docs + commit**

```bash
git add CLAUDE.md docs/generation.md tests/test_merge_distinct_api_invariant.py
git commit -m "test+docs(merge): distinct-API invariant + name run_merge_pipeline as merge SSOT"
```

---

## Notes / deliberate simplifications (YAGNI)

- **No subsystem cluster floor.** The dominance guarantee already preserves every reached function (a dropped driver's functions are all in its dominator), so a "≥1 driver per cluster" floor adds nothing to breadth; omitted unless a measured regression shows otherwise.
- **De-duplication of construction-time levers** (API_FLOOR ×2, portfolio, marginal loops) is OUT of scope — a separate, per-item-verified follow-up (the review's counts were overstated; see spec).
- **Greedy/Z3-exact max-cover** stays available (`select.select_top_k`) for a future hard-cap path; not wired now.
