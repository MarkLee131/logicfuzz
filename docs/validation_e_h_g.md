# Validation checklist — Phases E, H, G

This document records the deferred validation work for the three optimization
phases shipped in commits `76e3d632` (E + H + EDSM groundwork) and the
follow-up commit (G + closed-loop CLI).

The phases were implemented in dependency order:

```
E (post-parse extension) → H (Z3 hard pruning)  → G (closed-loop)
                          (depends on E's longer chains)
                                                 (depends on H's stronger guard)
```

Validation should be run in the same order — E's signal is a prerequisite
for the gains H/G provide.

---

## Phase E — Post-parse sequence extension

### What changed

- `liberator_adapter/analysis/usedef.py:extend_post_def(graph, typestate, sequence, depth, branching)`
  enumerates valid downstream consumer chains for a sequence.
- `liberator_adapter/analysis/project_automaton.py:AutomatonArtifact.post_parse_extensions(seq, depth, branching, acceptance_threshold)`
  wraps the above and exposes acceptance-threshold filtering.
- `liberator_adapter/constraints/coverage_ranker.py:rank_and_select` adds a
  third pool augmentation (post-DEF extensions) alongside the existing
  sample-paths and creator-graft augmentations.
- `select_top_k_sequences` exposes `automaton_post_extend_depth`,
  `automaton_post_extend_branching`, `automaton_post_extend_max_inputs`,
  and `automaton_post_extend_acceptance_threshold` knobs.
- New `automaton.post_extend_enabled` and `automaton.post_extend_added`
  fields land in the L4 selection summary for telemetry.

### Unit test plan

```bash
# Smoke (already passes — kept for regression):
python3 -c "
from liberator_adapter.analysis.usedef import (
    APIEffect, UseDefGraph, Typestate, extend_post_def,
)
effects = [
    APIEffect(name='ucl_parser_new', use=frozenset(),
              def_=frozenset({'ucl_parser*'})),
    APIEffect(name='ucl_parser_add_chunk',
              use=frozenset({'ucl_parser*'}), def_=frozenset()),
    APIEffect(name='ucl_parser_get_object',
              use=frozenset({'ucl_parser*'}),
              def_=frozenset({'ucl_object_t*'})),
    APIEffect(name='ucl_object_emit',
              use=frozenset({'ucl_object_t*'}), def_=frozenset()),
]
g = UseDefGraph(effects)
ext = extend_post_def(g, Typestate(g),
                     ['ucl_parser_new', 'ucl_parser_add_chunk'],
                     depth=3, branching=4)
assert any('ucl_parser_get_object' in e for e in ext)
assert any('ucl_object_emit' in e for e in ext)
"
```

### Integration test plan

1. Run libucl benchmark with extension enabled (default):
   ```bash
   python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o
   ```
   Expected: in `coverage_ranking.summary.automaton`, see
   `post_extend_enabled=True` and `post_extend_added > 0`.

2. Inspect Top-K — should contain at least one sequence longer than the
   pre-extension dominant pattern `[ucl_parser_new, ucl_parser_add_chunk]`,
   reaching `ucl_parser_get_object` and downstream
   (`ucl_object_emit` / `ucl_object_unref` / `ucl_parser_free`).

3. A/B against pre-E baseline (commit before `76e3d632`):
   - Metric: line coverage diff vs OSS-Fuzz baseline (currently +9.7% on
     libucl per CLAUDE.md Case 1).
   - **Acceptance bar**: ≥ +5pp on libucl. The architecturally
     reachable gap is 49.3%; +5pp is the conservative first-iteration target.

4. Cross-project sanity — re2 and sqlite3 should not regress (sequences
   that don't have downstream consumers naturally produce zero extensions).

### Risks to watch

- **Extension explosion**: `branching=4`, `depth=2`, and
  `post_extend_max_inputs=12` cap fan-out at 96 extra candidates. If the
  L4 input pool grows by >2× without coverage gain, drop `branching` to 2.
- **Typestate false negatives**: `extend_post_def` rejects on any
  non-`UNCLOSED_RESOURCE` violation. If a project's lifecycle pairs are
  incomplete, legitimate chains may be filtered. Audit
  `lifecycle_pairs` count in the automaton metadata.

---

## Phase H — Z3 hard pruning from automaton

### What changed

- `liberator_adapter/constraints/z3_guided_synthesis.py:AutomatonAcceptanceGuard`
  — strength-gated hard-pruning. Strength requires
  `observed_apis ≥ 10 ∧ n_merged_states ≥ 4`; weak guards admit everything.
  Auto-relax: 5 consecutive UNSAT → drop threshold by 0.15.
- `IncrementalZ3Solver` accepts an optional `automaton_guard`; `push/pop`
  now snapshots and rolls back `api_sequence` so the guard sees the same
  frame as Z3.
- `IncrementalZ3Solver.check_candidate` consults the guard *before*
  invoking Z3 — eliminates Z3 calls on automaton-rejected candidates.
- `Z3GuidedSynthesisController` and `create_guided_controller` accept
  `automaton_artifact` + `automaton_threshold`; `get_automaton_stats()`
  exposes telemetry.
- `CBFactory.__init__` accepts `automaton_artifact` + `automaton_threshold`.
- `_generate_cbfactory_drivers` in `data_context.py` pipes the artifact
  through; pre-synthesis log line announces `strong/weak` state,
  post-synthesis log line summarizes prunings.

### Unit test plan

```bash
# Already passes — kept for regression:
python3 -c "
from liberator_adapter.constraints.z3_guided_synthesis import (
    AutomatonAcceptanceGuard, IncrementalZ3Solver, create_guided_controller,
)
class FakeArt:
    n_merged_states = 10
    def observed_apis(self): return set('abcdefghijk')
    def acceptance_score(self, seq): return 0.9 if seq[0]=='a' else 0.2

g = AutomatonAcceptanceGuard(artifact=FakeArt(), threshold=0.5)
assert g.is_strong()
assert g.admits(['a','b']) is True
assert g.admits(['x','y']) is False

# Push/pop sequence rollback
solver = IncrementalZ3Solver(automaton_guard=g)
solver.add_api_called('a', 0)
solver.push()
solver.add_api_called('b', 1)
solver.pop()
assert solver.api_sequence == ['a']
"
```

### Integration test plan

1. Benchmark with strong-automaton project (libucl, sqlite3 once
   automaton learning works):
   ```bash
   python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o \
       --num-synthesis-drivers 10
   ```
   Expected logs:
   ```
   [Z3 Guided] Enabled for decision guidance (... automaton_guard=strong)
   📊 Automaton guard final: pruned=N passed=M relaxes=R threshold=T
   ```
   Acceptance bar: `pruned > 0` (the guard actually engages),
   `relaxes ≤ 2` (over-eager threshold isn't starving synthesis).

2. Weak-automaton project (a brand-new repo with no tests/examples):
   - Should log `automaton_guard=weak` — no behavioural change vs pre-H.
   - `pruned == 0` always.

3. **Top-K average acceptance** before vs after H:
   - Before: mean acceptance over `synthesized_drivers` ≈ baseline.
   - After: should be ≥ 0.5 higher when guard is strong. Re-derive via
     `automaton.acceptance_score(d['api_sequence'])` per driver.

4. **Z3 timing**: per-synthesis Z3 budget should drop because the guard
   short-circuits. Sample `time` flame-graph for one libucl run.

### Risks to watch

- **Auto-relax cascading to 0.0**: indicates the threshold was
  catastrophically wrong for this project. Revisit
  `min_observed_apis`/`min_merged_states` thresholds — the strength gate
  should have caught a project with no learnable typestate first.
- **Push/pop sequence rollback bug**: any sequence-track-vs-Z3-frame
  divergence corrupts the guard's running view. Add an assertion
  `len(solver.api_sequence) <= solver.checkpoint_level + initial_seq_len`
  if you see odd `acceptance_score` patterns.

---

## Phase G — Closed-loop CBFactory feedback

### What changed

- `liberator_adapter/analysis/edsm.py:_UnionFind.extend` adds fresh ids
  without resetting parent/rank.
- `liberator_adapter/analysis/edsm.py:incremental_merge(prev_result, pta, new_node_ids, ...)`
  preserves prior unions and only proposes pairs touching new ids.
- `AutomatonArtifact.update_with_traces(api_sequences, source_label, persist, oracle_fn, min_score_to_merge)`
  ingests runtime evidence as lightweight `StaticTrace`s, runs
  incremental EDSM, and re-persists `traces.json` / `pta.json` /
  `merged.json` / `metadata.json`.
- `src/closed_loop.py:run_closed_loop(...)` orchestrator — N feedback
  iterations with optional preflight gate, early-stop on automaton
  saturation, per-iter trajectory dump.
- CLI flags in `run_logicfuzz.py`: `--closed-loop`, `--closed-loop-iters
  N`, `--closed-loop-early-stop K`.
- `src/runner.py` threads CLI flags into
  `FuzzingContext.prepare(closed_loop_iters=, closed_loop_early_stop=)`.
- `data_context.py` Step 11b runs the loop after initial synthesis when
  `closed_loop_iters > 0`.

### Unit test plan

```bash
# Already passes — kept for regression:
python3 -c "
from liberator_adapter.analysis.project_automaton import AutomatonArtifact
from liberator_adapter.analysis.usedef import APIEffect, UseDefGraph
from liberator_adapter.analysis.pta import PrefixTreeAcceptor
from liberator_adapter.analysis.edsm import EDSMResult, _UnionFind
from src.closed_loop import run_closed_loop
from pathlib import Path
import tempfile

effects = [
    APIEffect(name='a', use=frozenset(), def_=frozenset({'x'})),
    APIEffect(name='b', use=frozenset({'x'}), def_=frozenset()),
    APIEffect(name='c', use=frozenset({'x'}), def_=frozenset()),
]
graph = UseDefGraph(effects)
pta = PrefixTreeAcceptor(graph)
uf = _UnionFind(pta.nodes.keys())
edsm = EDSMResult(pta=pta, uf=uf, n_input_states=1, n_output_states=1,
                  n_proposals_evaluated=0, n_merges_applied=0,
                  n_oracle_yes=0, n_oracle_no=0, n_oracle_uncertain=0)
with tempfile.TemporaryDirectory() as td:
    art = AutomatonArtifact(
        project='test', n_files_parsed=0, n_traces=0,
        n_pta_states=1, n_merged_states=1,
        n_oracle_calls=0, handle_binding_hit_rate=0.0,
        output_dir=Path(td), pta=pta, edsm=edsm, graph=graph,
    )
    res = run_closed_loop(
        project='test', automaton_artifact=art,
        initial_drivers=[{'api_sequence': ['a','b']}, {'api_sequence': ['a','c']}],
        resynthesize_fn=lambda a, k: [{'api_sequence': ['a','b','c']}],
        n_iters=4, target_drivers_per_iter=1,
        persist_dir=Path(td) / 'cl',
    )
    assert res.early_stopped  # saturates after 2-3 iters
    assert (Path(td) / 'cl' / 'closed_loop_trajectory.json').exists()
"
```

### Integration test plan

1. End-to-end on libucl with 3 iterations:
   ```bash
   python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o \
       --closed-loop --closed-loop-iters 3
   ```
   Expected per-iter log:
   ```
   [closed-loop iter N] evidence=E nodes+D Δmerged=±M drivers=K passed=P
   ```
   Acceptance bar:
   - Iter 1: `Δmerged < 0` (initial compression as evidence accumulates).
   - Iter 2-3: monotone non-increasing |Δmerged| (saturating).
   - Total wall-time ≤ 1.5× single-pass.

2. **Coverage trajectory** (requires preflight + extended fuzz wired):
   ```bash
   # After closed-loop, run extended fuzz for each iter's drivers
   for i in 0 1 2 3; do
       python scripts/run_extended_fuzzing.py -p libucl \
           -f results/output-libucl-project/iter${i}/fuzz_targets/01.fuzz_target \
           -d 1800
   done
   ```
   Acceptance bar: line coverage at iter 3 ≥ iter 0 + 3pp on libucl.
   Single-axis monotonicity is too strict; allow one regression iter.

3. **Saturation test** (high `--closed-loop-iters`):
   ```bash
   python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o \
       --closed-loop --closed-loop-iters 10
   ```
   Should early-stop with `automaton_saturated_2_consecutive_iters`
   well before iter 10. If it runs all 10, the saturation criterion is
   too lax — try `--closed-loop-early-stop 1`.

4. **Trajectory file inspection**:
   ```bash
   cat results/libucl/automaton/closed_loop_trajectory.json | jq .
   ```
   Verify: `n_evidence_traces` grows monotonically; `delta_merged_states`
   trends toward 0; `automaton_strong` flips to `true` after enough evidence.

### Risks to watch

- **Feedback echo / overfitting**: if the same drivers' sequences are
  re-fed every iter, the automaton over-learns the synthesizer's blind
  spots. Mitigation: deduplicate evidence on (sequence) tuples before
  feeding (currently relies on incremental EDSM's bucket dedup).
- **Per-iter cost blow-up**: bounded by `target_drivers_per_iter`
  × CBFactory time. If iter 2 takes >2× iter 1, bisect the synthesis
  loop.
- **Preflight not yet auto-wired**: `run_closed_loop` accepts an
  optional `preflight_runner` but `data_context.py` doesn't pass one.
  All synthesized drivers feed evidence currently. Wiring TODO:
  call `tools/merge_drivers/preflight.py:preflight()` in `_resynth`'s
  closure (needs a built fuzzer binary path per driver — first wire
  the libfuzz backend to surface those).

---

## What is *not* validated by these phases

- **Coverage feedback from execution** (true closed-loop, not synthesis-only).
  G's evidence is currently the synthesizer's own emissions; expanding to
  libFuzzer corpus traces requires decoding the merged-driver selector
  bytes — see `tools/merge_drivers/__main__.py:DispatchMode.CDF`.
- **TLV-aware seed generation** — independent track, see CLAUDE.md TODO.
- **L1/L2/L3 → UseDefGraph migration** — Phase E uses the substrate but
  L1/L2/L3 still re-implement matchers.

---

## Order of operations

```bash
# 1. E baseline
python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o \
    --num-synthesis-drivers 10
# Inspect coverage_ranking summary; expect post_extend_added > 0

# 2. H on top
# (no flag — H activates automatically when artifact is strong)
# Inspect logs for "automaton_guard=strong" + "Automaton guard final"

# 3. G on top
python3 run_logicfuzz.py -y comparison/libucl.yaml -l gpt-4o \
    --closed-loop --closed-loop-iters 3 --num-synthesis-drivers 10
# Inspect closed_loop_trajectory.json
```

A/B baseline: revert to commit `64af9310` (just before phase E).
Run the same yaml; record line coverage diff. Compare to post-G run.
**Headline number**: line coverage delta on libucl, `+5pp` minimum.
