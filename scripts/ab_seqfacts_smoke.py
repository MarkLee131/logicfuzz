"""A/B smoke: Comprehender-B with vs without per-sequence symbolic facts.
Offline (no docker): reconstruct inputs from cached results/<proj>/, run the
real LLM twice on the SAME sequences, diff verdicts. Cache bypassed so the LLM
actually runs both times."""
import json, sys
from liberator_adapter.analysis.usedef import extract_api_effects, UseDefGraph
from src.knowledge.comprehender import Comprehender

PROJ = sys.argv[1] if len(sys.argv) > 1 else "c-ares"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 12
R = f"results/{PROJ}"

def load_apis(p):
    txt = open(p).read().strip()
    try:
        d = json.loads(txt); return d.get('apis', d) if isinstance(d, dict) else d
    except json.JSONDecodeError:
        return [json.loads(l) for l in txt.splitlines() if l.strip()]

project_apis = load_apis(f"{R}/apis_llvm.json")
graph = UseDefGraph(extract_api_effects(project_apis))
usages = json.load(open(f"{R}/comprehension/api_usage.json"))
purpose = open(f"{R}/comprehension/purpose.txt").read().strip()
cached = json.load(open(f"{R}/comprehension/sequences.json"))

# Prefer sequences that actually have symbolic facts (where behavior can change),
# but keep a couple of clean ones as controls.
from src.knowledge.comprehender import _build_sequence_facts
items = list(cached.values())
# Only sequences whose facts are NON-EMPTY: those are the ONLY ones where A and B
# prompts differ, so the only place my feature can have an effect. (No-facts
# sequences get identical prompts -> any flip there is pure LLM noise.)
chosen = [v for v in items if _build_sequence_facts(v["sequence"], graph).strip()][:N]
seqs = [v["sequence"] for v in chosen]
old = {tuple(v["sequence"]): v["semantic_status"] for v in chosen}
allowed = sorted({a for s in seqs for a in s})

def run(graph_arg, tag):
    from src.llm.models import get_chat_model
    comp = Comprehender(PROJ, model_name="gpt-4o-mini")
    comp._chat_model = get_chat_model("gpt-4o-mini", temperature=0)  # deterministic
    comp.cache.load_sequence_semantics = lambda: {}          # no cache hits
    comp.cache.save_sequence_semantics = lambda *a, **k: None  # no pollution
    res = comp.comprehend_sequences(
        sequences=seqs, api_usages=usages, purpose=purpose,
        allowed_apis=allowed, automaton_acceptance_fn=None, use_def_graph=graph_arg)
    return {tuple(r.sequence): r for r in res}

print(f"== A/B on {PROJ}: {len(seqs)} FACTS-BEARING sequences (temp=0) ==")
A1 = run(None, "A1")          # no facts
A2 = run(None, "A2")          # no facts (identical to A1 -> measures noise floor)
B  = run(graph, "B")          # facts

from collections import Counter
def dist(d): return dict(Counter(r.semantic_status for r in d.values()))
def flips(x, y):
    return [(s, x[tuple(s)].semantic_status, y[tuple(s)].semantic_status)
            for s in seqs if x[tuple(s)].semantic_status != y[tuple(s)].semantic_status]
print("A1 (no facts):", dist(A1))
print("A2 (no facts):", dist(A2))
print("B  (facts)   :", dist(B))
print()
nf = flips(A1, A2)
print(f"NOISE FLOOR  A1 vs A2 (identical prompts): {len(nf)}/{len(seqs)} flips")
for s, a, b in nf:
    print(f"   noise {a}->{b}: {' -> '.join(s)}")
sg = flips(A1, B)
print(f"\nSIGNAL+noise A1 vs B (facts on): {len(sg)}/{len(seqs)} flips")
for s, a, b in sg:
    print(f"   {a}->{b}: {' -> '.join(s)}")
    print(f"      B diag: {B[tuple(s)].diagnosis[:110]}")
# direction: INVALID->{SUBOPTIMAL,VALID} = rescue (good); {VALID,SUBOPTIMAL}->INVALID = reject
rescue = sum(1 for _, a, b in sg if a == "INVALID" and b != "INVALID")
reject = sum(1 for _, a, b in sg if a != "INVALID" and b == "INVALID")
print(f"\nrescued (INVALID->usable): {rescue}   newly-rejected (usable->INVALID): {reject}")
