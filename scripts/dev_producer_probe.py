"""DEV probe (no docker): producer index + SVF write-signal from cached data.

Runs extract_api_effects on cached raw apis to show, per project, which handle
types have a producer — the signal the construct's _build_prefix relies on.
Used to validate the caller-alloc-init producer fix (z_stream) without rerunning
the docker-coupled extraction. TEMPORARY dev tool.

Usage: python3 scripts/dev_producer_probe.py
"""
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from liberator_adapter.analysis.usedef import (  # noqa: E402
    extract_api_effects, annotate_svf_writes, _Channel,
)

PROJECTS = ["zlib", "c-ares", "libpng", "cjson"]


def load_apis(proj):
    path = f"results/{proj}/apis_llvm.json"
    if not os.path.exists(path):
        path = f"results/{proj}/apis_clang.json"
    txt = open(path).read().strip()
    try:
        d = json.loads(txt)
        return d.get("apis", d) if isinstance(d, dict) else d
    except json.JSONDecodeError:
        return [json.loads(l) for l in txt.splitlines() if l.strip()]


def write_signal_map(proj):
    """{(fname, arg_idx): True} when SVF shows a WRITE access on that param."""
    path = f"results/{proj}/conditions.json"
    if not os.path.exists(path):
        return {}
    out = {}
    for e in json.load(open(path)):
        if not isinstance(e, dict):
            continue
        fn = e.get("function_name")
        for k, v in e.items():
            if not k.startswith("param_") or not isinstance(v, dict):
                continue
            try:
                idx = int(k.split("_")[1])
            except ValueError:
                continue
            wrote = any(a.get("access") in ("write", "delete")
                        for a in v.get("access_type_set", []))
            if wrote:
                out[(fn, idx)] = True
    return out


def producer_index(apis, conditions):
    """handle type -> list of producing api names (after SVF-write annotation)."""
    annotate_svf_writes(apis, conditions)
    idx, init_prods = {}, []
    for e in extract_api_effects(apis):
        for p in e.productions:
            if p.channel is _Channel.INIT:
                init_prods.append((e.name, p.handle))
        for h in e.def_:
            idx.setdefault(h, []).append(e.name)
    return idx, init_prods


def load_conditions(proj):
    path = f"results/{proj}/conditions.json"
    if not os.path.exists(path):
        return []
    return json.load(open(path))


def main():
    for proj in PROJECTS:
        try:
            apis = load_apis(proj)
        except FileNotFoundError:
            print(f"{proj}: no apis file"); continue
        pidx, init_prods = producer_index(apis, load_conditions(proj))
        ws = write_signal_map(proj)
        print(f"=== {proj}: {len(apis)} apis | {len(pidx)} produced handle types "
              f"| {len(init_prods)} INIT-channel productions ===")
        print(f"   INIT productions: {sorted(init_prods)}")
        # spotlight: z_stream for zlib
        for spot in ("z_stream*", "%struct.z_stream_s*", "z_stream_s*"):
            if spot in pidx:
                print(f"   PRODUCED {spot}: {pidx[spot]}")
        if proj == "zlib":
            zs = [k for k in pidx if "z_stream" in k.lower()]
            print(f"   z_stream-ish produced keys: {zs or 'NONE (blocked)'}")
            # show the write signal on the init APIs
            for n in ("deflateInit_", "inflateInit_", "inflateInit2_"):
                print(f"   {n}: arg0 write-signal={ws.get((n, 0), False)}")
        # producer-set fingerprint for no-regression A/B
        fp = sorted((h, len(v)) for h, v in pidx.items())
        print(f"   producer-set fingerprint (handle,count): {fp[:8]}{'...' if len(fp) > 8 else ''}")


if __name__ == "__main__":
    main()
