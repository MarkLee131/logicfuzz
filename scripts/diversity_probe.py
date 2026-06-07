"""Offline A/B for LOGICFUZZ_DIVERSITY_SELECT: does true max-marginal greedy
cover more of the API surface (fewer/more-diverse drivers) than the legacy
acceptance-order walk? Runs the real construct pool through the ranker at a
top_k sweep, flag off vs on. $0, no docker/LLM. Usage: python3 scripts/diversity_probe.py [proj]
"""
import json, os, sys

os.environ.setdefault('LOGICFUZZ_DENSE_CONSTRUCT', '1')  # match production density
proj = sys.argv[1] if len(sys.argv) > 1 else 'lcms'
base = f'results/{proj}/static_analysis'
apis = [a for a in json.load(open(f'{base}/project_apis.json')).get('apis', [])
        if isinstance(a, dict)]
allnames = {a['function_name'] for a in apis}

from liberator_adapter.analysis.api_semantic_model import reconcile, APIRole
from liberator_adapter.analysis.sequence_constructor import construct_sequences
from liberator_adapter.constraints.coverage_ranker import CoverageRanker

m = reconcile(apis, project=proj)
paths = []
tp = f'results/{proj}/automaton/traces.json'
if os.path.exists(tp):
    tr = json.load(open(tp)); tr = tr if isinstance(tr, list) else tr.get('traces', [])
    for t in tr:
        nm = [c.get('api_name') for c in (t.get('api_calls') or []) if c.get('api_name')]
        if len(nm) >= 2: paths.append(nm)
prod = {}
for s in m.apis.values():
    for tt in s.produces: prod.setdefault(tt, s.name)
pairs = [(prod[t], s.name) for s in m.apis.values()
         if s.role is APIRole.DESTROYER for t in s.destroys if t in prod]
res = construct_sequences(m, project_apis=apis, lifecycle_pairs=pairs,
                          gap_apis=set(allnames), accepting_paths=paths,
                          construct_mode='merged')
seqs = [list(s) for s in res.sequences]
pool_union = len(set(a for s in seqs for a in s))
print(f'{proj}: pool={len(seqs)} seqs, candidate union={pool_union}/{len(allnames)} APIs\n')
print(f'  {"top_k":>6} | {"legacy APIs (drv)":>20} | {"diversity APIs (drv)":>22} | gain')
ranker = CoverageRanker()
for k in [10, 30, 56, 100, 150, 250]:
    os.environ['LOGICFUZZ_DIVERSITY_SELECT'] = '0'
    r0 = ranker.rank_and_select(seqs, top_k=k)
    os.environ['LOGICFUZZ_DIVERSITY_SELECT'] = '1'
    r1 = ranker.rank_and_select(seqs, top_k=k)
    a0, a1 = len(r0.total_api_coverage), len(r1.total_api_coverage)
    print(f'  {k:>6} | {a0:>10} ({len(r0.selected_sequences):>3} drv) | '
          f'{a1:>12} ({len(r1.selected_sequences):>3} drv) | {a1 - a0:+d}')
