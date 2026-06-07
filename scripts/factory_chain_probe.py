"""Offline A/B for LOGICFUZZ_FACTORY_CHAIN: how many opaque-consuming APIs get a
FULL constructable producer chain (instead of a NULL hole) once return-by-value
opaque handles (typedef void* cmsHTRANSFORM) are producer-linked by naming and the
existing recursive _build_prefix chains them transitively to fuzzer leaves.

Metric (the coverage proxy): a "deep opaque arg" is a required NON-pointer handle
type with NO real producer (its creator's `produces` was erased by IR desugaring)
— without recovery it stays a NULL arg and the deep API covers ~0. We count, flag
OFF vs ON, how many such args / APIs get a non-NULL producer chain. $0, no
docker/LLM. Usage: python3 scripts/factory_chain_probe.py [proj]
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

proj = sys.argv[1] if len(sys.argv) > 1 else 'lcms'
base = f'results/{proj}/static_analysis'
apis = [a for a in json.load(open(f'{base}/project_apis.json')).get('apis', [])
        if isinstance(a, dict)]

from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import _build_index, _build_prefix

m = reconcile(apis, project=proj)


def measure(flag: bool) -> dict:
    if flag:
        os.environ['LOGICFUZZ_FACTORY_CHAIN'] = '1'
    else:
        os.environ.pop('LOGICFUZZ_FACTORY_CHAIN', None)
    idx = _build_index(m)
    real_producers = {t for t, ps in idx.producers.items() if ps}
    # deep opaque arg = required, non-pointer, no real producer (a NULL hole).
    opaque_args, satisfied_args, consumers, rescued = 0, 0, set(), set()
    prefix_lens = []
    for name, sem in m.apis.items():
        deep = {t for t in sem.requires if '*' not in t and t not in real_producers}
        if not deep:
            continue
        consumers.add(name)
        opaque_args += len(deep)
        pre, opened = _build_prefix(sem, idx, 6)
        prefix_lens.append(len(pre))
        sat = deep & opened
        satisfied_args += len(sat)
        if sat:
            rescued.add(name)
    avg_pre = round(sum(prefix_lens) / len(prefix_lens), 2) if prefix_lens else 0
    return dict(recovered=sorted(idx.recovered_producers),
                consumers=len(consumers), opaque_args=opaque_args,
                satisfied_args=satisfied_args, rescued=len(rescued),
                avg_prefix=avg_pre)


off = measure(False)
on = measure(True)

print(f'{proj}: {len(m.apis)} APIs; opaque-consuming APIs (>=1 deep opaque arg) = '
      f'{off["consumers"]}\n')
print(f'  {"metric":<34} | {"OFF":>8} | {"ON":>8} | gain')
print('  ' + '-' * 64)
rows = [
    ('recovered opaque handle types', len(off['recovered']), len(on['recovered'])),
    ('deep opaque args SATISFIED', off['satisfied_args'], on['satisfied_args']),
    ('  (of total deep opaque args)', off['opaque_args'], on['opaque_args']),
    ('APIs w/ >=1 opaque arg chained', off['rescued'], on['rescued']),
    ('avg producer-prefix length', off['avg_prefix'], on['avg_prefix']),
]
for label, a, b in rows:
    gain = f'{b - a:+g}' if not label.startswith('  ') else ''
    print(f'  {label:<34} | {a:>8} | {b:>8} | {gain}')
print(f'\n  recovered types (ON): {on["recovered"]}')

# Showcase the deepest chain we can build for a known opaque-deep API.
from liberator_adapter.analysis.sequence_constructor import _closing_destroyers
os.environ['LOGICFUZZ_FACTORY_CHAIN'] = '1'
idx = _build_index(m)
for showcase in ('cmsDoTransform', 'cmsTransform2DeviceLink'):
    if showcase in m.apis:
        pre, opened = _build_prefix(m.apis[showcase], idx, 6)
        seq = pre + [showcase] + _closing_destroyers(opened, idx)
        print(f'  showcase {showcase}: {seq}')
