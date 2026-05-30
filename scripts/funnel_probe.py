"""Where in the funnel is API-surface recall lost? c-ares case.

Stages: project APIs → L4 output (filtered_sequences cache) → construct alone
(no budget) → construct+budget(40). Prints unique-API coverage at each stage so
we attribute the recall loss to the right layer instead of guessing.
"""
import json, os, sys

proj = sys.argv[1] if len(sys.argv) > 1 else 'c-ares'
base = f'results/{proj}/static_analysis'
apis = [a for a in json.load(open(f'{base}/project_apis.json')).get('apis', []) if isinstance(a, dict)]
allnames = {a['function_name'] for a in apis}

# Stage A: L4 output = cached filtered_sequences
filt = json.load(open(f'{base}/filtered_sequences.json'))
l4 = set()
for s in filt['sequences']:
    l4.update(s['apis'])

# Stage B: construct alone (full project_apis, no budget)
from liberator_adapter.analysis.api_semantic_model import reconcile, APIRole
from liberator_adapter.analysis.sequence_constructor import construct_sequences
m = reconcile(apis, project=proj)
gap = set(allnames)
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
pairs = [(prod[t], s.name) for s in m.apis.values() if s.role is APIRole.DESTROYER for t in s.destroys if t in prod]
res = construct_sequences(m, project_apis=apis, lifecycle_pairs=pairs, gap_apis=gap,
                          accepting_paths=paths, construct_mode='merged')
construct_all = set(a for s in res.sequences for a in s)

print(f'{proj}: project_APIs={len(allnames)}')
print(f'  L4 output (filtered_sequences cache): {len(l4)} APIs ({100*len(l4)/len(allnames):.0f}%)')
print(f'  construct ALONE (no budget):          {len(construct_all)} APIs ({100*len(construct_all)/len(allnames):.0f}%)  [{len(res.sequences)} seqs]')
print(f'  → recall lost at L4 (vs construct-possible): {len(construct_all - l4)} APIs construct could reach but L4-cache shows missing')
