import sys, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from liberator_adapter.analysis.order_sets import OrderSet, normalize_traces, minimize_traces
def test_small_dropped(): assert OrderSet.from_sequence(["a","b"])==[]
def test_within_bounds_single():
    r=OrderSet.from_sequence(["a","b","c","d"]); assert len(r)==1 and r[0].order_list==["a","b","c","d"]
def test_large_splits_preserve_apis():
    seq=[f"api_{i}" for i in range(30)]; r=OrderSet.from_sequence(seq)
    assert len(r)>=2 and {a for o in r for a in o.unique_apis}==set(seq)
def test_minimize_covers_all():
    traces=[["a","b","c"],["c","d","e"],["a","d"],["b","e"],["a","b","c","d","e"]]
    m=minimize_traces(traces); assert {a for s in m for a in s}=={"a","b","c","d","e"} and len(m)==1
def test_end_to_end():
    raw=[[f"api_{i}" for i in range(20)],[f"api_{i}" for i in range(10,30)]]
    m=minimize_traces(normalize_traces(raw)); assert {a for s in m for a in s}=={f"api_{i}" for i in range(30)}
