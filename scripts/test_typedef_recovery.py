"""Generalization probe for the typedef-handle recovery (方向1).

Given a project that has been extract-only'd (results/<p>/apis_clang.json +
exported_functions.txt + headers on disk), run the deterministic
recovery -> reconcile -> construct path and report whether the handle dependency
graph was recovered and whether deep creator->consumer->destroyer chains now
construct. No LLM, no docker.

Usage: python scripts/test_typedef_recovery.py <project>
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from liberator_adapter.analysis.handle_typedef_recovery import recover_handle_types
from liberator_adapter.analysis import reconcile
from liberator_adapter.analysis.sequence_constructor import construct_sequences


def load_project_apis(proj):
    apis = []
    for line in open(f"results/{proj}/apis_clang.json"):
        line = line.strip()
        if not line:
            continue
        a = json.loads(line)
        apis.append({
            "function_name": a["function_name"],
            "return_type": (a.get("return_info") or {}).get("type_clang", ""),
            "arguments": [{
                "name": p.get("name", ""),
                "type": p.get("type_clang", ""),
                "flag": "ref" if "*" in (p.get("type_clang", "") or "") else "val",
            } for p in (a.get("arguments_info") or [])],
        })
    return apis


def find_headers(proj):
    ph = f"results/{proj}/public_headers.txt"
    names = []
    if os.path.exists(ph):
        names = [l.strip() for l in open(ph) if l.strip()]
    hdrs = []
    for n in names:
        base = os.path.basename(n)
        hits = glob.glob(f"results/{proj}/**/{base}", recursive=True)
        if hits:
            hdrs.append(hits[0])
    return hdrs


def main():
    proj = sys.argv[1]
    apis = load_project_apis(proj)
    exported = f"results/{proj}/exported_functions.txt"
    headers = find_headers(proj)
    print(f"== {proj}: {len(apis)} APIs, exported={os.path.exists(exported)}, "
          f"{len(headers)} headers ==")

    # BEFORE
    m0 = reconcile(apis)
    prod0 = sum(1 for s in m0.apis.values() if s.produces)
    req0 = sum(1 for s in m0.apis.values() if s.requires)

    # recover, AFTER
    n_up = recover_handle_types(apis, exported_functions=exported,
                                header_paths=headers)
    m1 = reconcile(apis)
    prod1 = sum(1 for s in m1.apis.values() if s.produces)
    req1 = sum(1 for s in m1.apis.values() if s.requires)

    print(f"  upgraded slots: {n_up}")
    print(f"  APIs with produces:  {prod0} -> {prod1}")
    print(f"  APIs with requires:  {req0} -> {req1}")

    # construct (lifecycle pairs unknown here -> destroyers may be CONSUMERs;
    # we only check that creator->consumer chains of length>=2 now form)
    res = construct_sequences(m1, project_apis=apis)
    seqs = res.sequences
    deep = [s for s in seqs if len(s) >= 2]
    print(f"  constructed sequences: {len(seqs)} (>=2 calls: {len(deep)})")
    for s in deep[:6]:
        print("     ", s)


if __name__ == "__main__":
    main()
