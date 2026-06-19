# Idiom-Aware Recall + Repair (A-first) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn degenerate idiom-gated skeletons (file-opener APIs whose path arg renders NULL and mode arg renders raw fuzz bytes) into live drivers, by emitting a `FILE_FROM_FUZZ` value-intent that the existing Prototyper renders as the `tmpfile→open` idiom.

**Architecture:** Extend the existing deterministic value-intent layer (`hole_semantics`). A resource-opener (an `ApiRole.CREATOR` taking a `char*` path) gets a `FILE_FROM_FUZZ` directive on its path arg + a file-mode value-domain on its companion `char*` arg. These flow through the *already-wired* path `value_intents_for_sequence` → `annotate_skeletons` (Step 10b) → Prototyper CALLSPEC → LLM, which writes the idiom. No new module, no `validity_contract` reconstruction, no new LLM call-site.

**Tech Stack:** Python 3.10, pytest. Reuses `hole_semantics`, `APISemanticModel` (`ArgRole`/`ApiRole`), the Prototyper, `compile_validate`, the dead-driver merge filter.

## Global Constraints

- **Spec deviation (documented):** R0+R1 from the spec are implemented together inside `value_intents_for_sequence` (the value-intent channel *is* the recall router). The separate `skeleton_recall.py` + Step 10c + `validity_contract` I2a/I2b routing are **not built** — they were heavier glue for the same behavior. `validity_contract` corroboration remains a deferred option if false-positives appear.
- **Load-bearing, untouched:** the dead-driver merge filter, symbolic construction, the automaton.
- **Fail-open:** any error in the new intent path must leave the skeleton unmodified.
- **Gated A/B:** `LOGICFUZZ_DISABLE_RECALL=1` disables the file-opener intents (default ON).
- **Generic, not zlib-specific:** detection keys on `ApiRole.CREATOR` + `char*` arg, never on `gz`/zlib names. Measured on zlib + libpng + c-ares.
- **Temp path must be unique per process** (not a literal shared `./dummy_file`) — the directive says so.
- Tests: `python3 -m pytest tests/ -q`. Commit per task, file-scoped `git add` (never `-A`).

---

### Task 1: File-opener detection + `FILE_FROM_FUZZ` intent (pure helpers)

**Files:**
- Modify: `liberator_adapter/analysis/hole_semantics.py` (add helpers near `_arg_intent`, ~line 133)
- Test: `tests/test_idiom_recall.py` (create)

**Interfaces:**
- Produces: `file_opener_intents(sem) -> Dict[int, str]` — maps arg-index → directive string for a resource-opener `sem` (empty dict when `sem` is not a CREATOR or has no `char*` path arg). `sem` is an `ApiSemantics` (`.role: ApiRole`, `.args: List[ArgSemantics]`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_idiom_recall.py
from liberator_adapter.analysis.api_semantic_model import (
    ApiSemantics, ArgSemantics, ApiRole, ArgRole)
from liberator_adapter.analysis.hole_semantics import file_opener_intents


def _api(role, args):
    return ApiSemantics(name="x", role=role, args=args)

def _arg(i, role, t):
    return ArgSemantics(index=i, role=role, type_str=t)


def test_creator_charptr_path_gets_file_from_fuzz():
    # gzopen(const char* path, const char* mode) — CREATOR returning a handle
    sem = _api(ApiRole.CREATOR, [
        _arg(0, ArgRole.INPUT_BUFFER, "const char *"),   # path
        _arg(1, ArgRole.CONFIG, "const char *"),         # mode
    ])
    intents = file_opener_intents(sem)
    assert "FILE_FROM_FUZZ" in intents[0]                # path arg
    assert "tmp" in intents[0].lower() and "NULL" in intents[0]
    assert "FUZZ_DERIVE" in intents[1] and '"rb"' in intents[1]  # mode value-domain


def test_non_creator_is_empty():
    sem = _api(ApiRole.CONSUMER, [_arg(0, ArgRole.INPUT_BUFFER, "const char *")])
    assert file_opener_intents(sem) == {}


def test_creator_without_charptr_is_empty():
    # deflateInit_ style — no char* path arg
    sem = _api(ApiRole.CREATOR, [_arg(0, ArgRole.HANDLE_IN, "z_stream *")])
    assert file_opener_intents(sem) == {}


def test_length_and_output_charptr_skipped():
    sem = _api(ApiRole.CREATOR, [
        _arg(0, ArgRole.OUTPUT, "char *"),     # out buffer, not a path
        _arg(1, ArgRole.LENGTH, "char *"),     # (degenerate type) length
    ])
    assert file_opener_intents(sem) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_idiom_recall.py -k file -q`
Expected: FAIL — `ImportError: cannot import name 'file_opener_intents'`.

- [ ] **Step 3: Implement the helpers**

```python
# liberator_adapter/analysis/hole_semantics.py  (module scope, near _arg_intent)
from liberator_adapter.analysis.api_semantic_model import ApiRole, ArgRole

_FILE_FROM_FUZZ = (
    "FILE_FROM_FUZZ: this is a filesystem PATH, not raw input. Write the fuzzer "
    "bytes to a UNIQUE temp file (e.g. ./lf_tmp_<pid>_<n>) and pass THAT path "
    "here. Do NOT pass NULL and do NOT pass raw fuzz bytes."
)
_FILE_MODE_DOMAIN = (
    'FUZZ_DERIVE: file-mode string — pick from the legal set '
    '{"rb","wb","ab","r","w"}; do NOT use raw fuzz bytes.'
)


def _is_charptr(type_str: str) -> bool:
    t = (type_str or "")
    return t.count("*") == 1 and "char" in t.lower()


def file_opener_intents(sem) -> dict:
    """Directives for a resource-opener's path + mode args.

    A CREATOR (produces a fresh handle/resource) that takes a single-pointer
    char* is treated as a file opener: the FIRST eligible char* is the PATH
    (FILE_FROM_FUZZ — write fuzz bytes to a temp file, pass the path), a SECOND
    eligible char* is the mode (value-domain). Eligible = not LENGTH/OUTPUT.
    Empty for non-CREATORs or CREATORs with no char* path arg. Name-free +
    library-agnostic (keys on role+type only)."""
    role = getattr(sem.role, "value", sem.role)
    if role != ApiRole.CREATOR.value:
        return {}
    charptrs = [a for a in sem.args
                if a.role not in (ArgRole.LENGTH, ArgRole.OUTPUT)
                and _is_charptr(a.type_str)]
    if not charptrs:
        return {}
    out = {charptrs[0].index: _FILE_FROM_FUZZ}
    if len(charptrs) > 1:
        out[charptrs[1].index] = _FILE_MODE_DOMAIN
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_idiom_recall.py -k file -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/hole_semantics.py tests/test_idiom_recall.py
git commit -m "feat(recall): FILE_FROM_FUZZ value-intent for resource-opener APIs (R0)"
```

---

### Task 2: Wire the intents into `value_intents_for_sequence` (gated)

**Files:**
- Modify: `liberator_adapter/analysis/hole_semantics.py` (`value_intents_for_sequence`, ~line 341; per-arg record loop)
- Test: `tests/test_idiom_recall.py` (append)

**Interfaces:**
- Consumes: `file_opener_intents(sem)` (Task 1).
- Produces: each `args[]` record's `intent` carries the `FILE_FROM_FUZZ`/mode directive when applicable; gated off by `LOGICFUZZ_DISABLE_RECALL=1`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_idiom_recall.py  (append)
import os
from liberator_adapter.analysis.hole_semantics import value_intents_for_sequence
from liberator_adapter.analysis.api_semantic_model import APISemanticModel

def _opener_model():
    m = APISemanticModel()
    m.apis["openf"] = _api(ApiRole.CREATOR, [
        _arg(0, ArgRole.INPUT_BUFFER, "const char *"),
        _arg(1, ArgRole.CONFIG, "const char *"),
    ])
    m.apis["openf"].name = "openf"
    return m

def test_file_intent_appears_in_records(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DISABLE_RECALL", raising=False)
    recs = value_intents_for_sequence(_opener_model(), ["openf"])
    arg0 = [a for r in recs for a in r["args"] if a["index"] == 0][0]
    assert "FILE_FROM_FUZZ" in arg0["intent"]

def test_gate_disables_file_intent(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DISABLE_RECALL", "1")
    recs = value_intents_for_sequence(_opener_model(), ["openf"])
    arg0s = [a for r in recs for a in r["args"] if a["index"] == 0]
    assert all("FILE_FROM_FUZZ" not in a["intent"] for a in arg0s)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_idiom_recall.py -k "intent_appears or gate" -v`
Expected: FAIL — `arg0["intent"]` has no `FILE_FROM_FUZZ` (not yet wired).

- [ ] **Step 3: Implement the wiring**

In `value_intents_for_sequence`, before the `for arg in sem.args:` loop, compute the opener intents once (gated); merge into each arg's intent (file directive overrides/augments the per-arg intent):

```python
        import os as _os_r
        _file_intents = ({} if _os_r.environ.get("LOGICFUZZ_DISABLE_RECALL")
                         else file_opener_intents(sem))
```
Then inside the arg loop, after `intent = _arg_intent(arg, name, vocab)`:
```python
            if arg.index in _file_intents:
                intent = _file_intents[arg.index]   # recall: idiom directive wins
```
Keep the existing `if intent is None and not set_by: continue` — a file intent is non-None so the arg record is now emitted.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_idiom_recall.py -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/hole_semantics.py tests/test_idiom_recall.py
git commit -m "feat(recall): emit file-opener idiom intents in value_intents (gated R1)"
```

---

### Task 3: Ablation counter — `recall_ablation.json`

**Files:**
- Modify: `src/context/data_context.py` (Step 10b block, ~line 2211-2236, after `annotate_skeletons`)
- Test: `tests/test_idiom_recall.py` (append)

**Interfaces:**
- Produces: `count_file_idiom_skeletons(skeletons) -> int` (in `hole_semantics.py`) — number of skeletons carrying ≥1 `FILE_FROM_FUZZ` intent; written to `results/<project>/recall_ablation.json` as `{"file_idiom_skeletons": N, "total_skeletons": M, "disabled": bool}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_idiom_recall.py  (append)
from liberator_adapter.analysis.hole_semantics import count_file_idiom_skeletons

def test_count_file_idiom_skeletons():
    skels = [
        {"value_intents": [{"args": [{"index": 0, "intent": "FILE_FROM_FUZZ: ..."}]}]},
        {"value_intents": [{"args": [{"index": 0, "intent": "FUZZ_DERIVE: enum"}]}]},
        {"value_intents": []},
    ]
    assert count_file_idiom_skeletons(skels) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_idiom_recall.py -k count -q`
Expected: FAIL — `ImportError: cannot import name 'count_file_idiom_skeletons'`.

- [ ] **Step 3: Implement the counter + wire the JSON dump**

```python
# liberator_adapter/analysis/hole_semantics.py
def count_file_idiom_skeletons(skeletons) -> int:
    """Skeletons carrying ≥1 FILE_FROM_FUZZ intent (the recalled idiom-gated set)."""
    n = 0
    for sk in skeletons:
        vis = sk.get("value_intents") or []
        if any("FILE_FROM_FUZZ" in (a.get("intent") or "")
               for rec in vis for a in (rec.get("args") or [])):
            n += 1
    return n
```
In `data_context.py` after the `annotate_skeletons(...)` call (~line 2233), add (fail-open):
```python
                try:
                    import json as _json_r, os as _os_r
                    from liberator_adapter.analysis.hole_semantics import (
                        count_file_idiom_skeletons)
                    _abl = {
                        "file_idiom_skeletons": count_file_idiom_skeletons(skeleton_drivers),
                        "total_skeletons": len(skeleton_drivers),
                        "disabled": bool(_os_r.environ.get("LOGICFUZZ_DISABLE_RECALL")),
                    }
                    with open(f"results/{project_name}/recall_ablation.json", "w") as _f:
                        _json_r.dump(_abl, _f, indent=2)
                except Exception as _e:
                    log.debug("   10b recall ablation dump skipped: %s", _e)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_idiom_recall.py -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add liberator_adapter/analysis/hole_semantics.py src/context/data_context.py tests/test_idiom_recall.py
git commit -m "feat(recall): recall_ablation.json counter for file-idiom skeletons"
```

---

### Task 4: Integration proof — zlib gz* drivers become live (opt-in)

**Files:**
- Test: `tests/test_idiom_recall_integration.py` (create, opt-in/slow)

**Interfaces:**
- Consumes: the full pipeline + the new intents.

- [ ] **Step 1: Add the opt-in integration test**

```python
# tests/test_idiom_recall_integration.py
import os, json, glob, subprocess, pytest

@pytest.mark.skipif(os.environ.get("RUN_RECALL_INTEGRATION") != "1",
                    reason="docker+LLM; set RUN_RECALL_INTEGRATION=1")
def test_zlib_gz_drivers_live_with_recall():
    # recall ON: expect ≥1 gz* skeleton flagged + at least one gz* driver generated
    subprocess.run("LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/zlib.yaml "
                   "-l deepseek-v4-flash --num-drivers 22", shell=True, timeout=5400, check=False)
    abl = json.load(open("results/zlib/recall_ablation.json"))
    assert abl["file_idiom_skeletons"] >= 1, abl
    gz = [f for f in glob.glob("results/output-zlib-project/fuzz_targets/*.fuzz_target")
          if "gzopen" in open(f).read()]
    assert gz, "no gz* driver generated with recall on"
    # at least one gz* driver writes fuzz bytes to a temp file (the idiom landed)
    assert any(("tmp" in open(f).read().lower() or "fopen" in open(f).read())
               for f in gz), "gz* drivers still degenerate (no tmpfile idiom)"
```

- [ ] **Step 2: Run it once manually**

Run: `RUN_RECALL_INTEGRATION=1 python3 -m pytest tests/test_idiom_recall_integration.py -q`
Expected: PASS — `file_idiom_skeletons ≥ 1` and ≥1 gz* driver carries the tmpfile idiom.

- [ ] **Step 3: Commit**

```bash
git add tests/test_idiom_recall_integration.py
git commit -m "test(recall): opt-in zlib gz* idiom integration proof"
```

---

## Self-Review

- **Spec coverage:** R0 (FILE_FROM_FUZZ + mode domain) → Task 1; R1 routing (intent emission, gated) → Task 2; R2 (Prototyper renders) → exercised by Task 4 (the Prototyper already consumes `value_intents` — no code change needed, so no separate task); ablation harness (§8) → Task 3; multi-lib measurement → run Task 4's command on libpng/c-ares (operational, not a code task). The spec's `skeleton_recall.py`/Step 10c/`validity_contract` routing is intentionally **not** built (documented in Global Constraints — same behavior, less code).
- **Placeholder scan:** none — every code step is complete. The only judgement step is "run on libpng/c-ares too," which is an operational measurement, not a code placeholder.
- **Type consistency:** `file_opener_intents(sem)->dict`, `count_file_idiom_skeletons(skeletons)->int`, the `value_intents` record shape (`{args:[{index,role,type,intent}]}`), and `LOGICFUZZ_DISABLE_RECALL` are consistent across Tasks 1-4.
