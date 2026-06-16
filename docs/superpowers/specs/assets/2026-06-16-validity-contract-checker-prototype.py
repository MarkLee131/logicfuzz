#!/usr/bin/env python3
"""Validity-contract invariant checker (quantification for the valid-by-construction
design). Operates on the APISemanticModel (per-arg nullable + type_str) + the rendered
driver sequences. Counts violations of:
  #1 lifecycle order   : a handle arg used BEFORE its producer (close-before-open)
  #2a orphan handle    : nullable=False HANDLE arg bound to a NULL var with no producer
  #2b missing value    : nullable=False non-handle (string/config ptr) arg = NULL
  #3 type-confusion    : handle arg bound to a producer whose return type != arg type
This is read-only; it tells us which invariant dominates + reject-vs-repair scope.
"""
import json, re, sys, glob, os
from collections import Counter, defaultdict

model = json.load(open("/tmp/inv_check/model.json"))
APIS = model.get("apis", model)

def args_of(api):
    v = APIS.get(api)
    if not isinstance(v, dict): return None
    return v.get("args") or []

def ret_kind(api):
    """Crude return 'kind' for type-confusion: which handle family an API produces."""
    a = api.lower()
    if "transform" in a: return "transform"
    if "profile" in a or "srgb" in a or "lab" in a or "xyz" in a or "devicelink" in a: return "profile"
    if "tonecurve" in a or "gamma" in a: return "tonecurve"
    if "pipeline" in a: return "pipeline"
    if "stage" in a: return "stage"
    if "context" in a: return "context"
    if "it8" in a: return "it8"
    if "tag" in a or "readtag" in a: return "tag"
    return "other"

def arg_kind(type_str):
    t = (type_str or "").lower()
    if "transform" in t: return "transform"
    if "hprofile" in t or "profile" in t: return "profile"
    if "tonecurve" in t: return "tonecurve"
    if "pipeline" in t: return "pipeline"
    if "stage" in t: return "stage"
    if "context" in t: return "context"
    if "it8" in t: return "it8"
    return None  # not a known handle type (scalar/string/buffer)

HANDLE_TYPE_RE = re.compile(r"cmsH[A-Z]|cms\w+\s*\*|cmsContext|cmsHANDLE|cmsHPROFILE|cmsHTRANSFORM")
def is_handle_type(type_str):
    return arg_kind(type_str) is not None or bool(HANDLE_TYPE_RE.search(type_str or ""))
def is_string_type(type_str):
    return "char" in (type_str or "").lower()

DECL_RE = re.compile(r"^\s*[\w\s\*]+?\b(\w+)\s*=\s*(.+?);\s*$")
CALL_RE = re.compile(r"(?:(\w+)\s*=\s*)?(\bcms[A-Za-z0-9_]+)\s*\(([^;]*)\)\s*;")

def body(src):
    m = re.search(r"LLVMFuzzerTestOneInput[^{]*\{(.*)\n\}", src, re.S)
    return m.group(1) if m else src

def first_ident(expr):
    e = re.sub(r"^\([^)]*\)\s*", "", expr.strip())  # strip cast
    e = e.lstrip("&").strip()
    m = re.match(r"([A-Za-z_]\w*)", e)
    return m.group(1) if m else None

viol = Counter()
drivers_with = Counter()
per_driver = {}

for f in sorted(glob.glob("/tmp/inv_check/*.fuzz_target")):
    src = open(f, errors="ignore").read()
    b = body(src)
    lines = b.split("\n")
    # pass 1: producer-statement index for each ret var + decl null vars
    produced_at = {}          # var -> stmt index where assigned a producer ret
    producer_of = {}          # var -> producing api
    null_decl = set()         # vars declared = NULL
    stmts = []                # (idx, raw)
    for i, ln in enumerate(lines):
        m = re.match(r"\s*[\w\s\*]+?\b(\w+)\s*=\s*NULL\s*;", ln)
        if m: null_decl.add(m.group(1))
        stmts.append((i, ln))
    # pass 2: walk calls in order, record producers as we go, check consumers
    dv = Counter()
    seen_producer_idx = {}
    # first map ret_X = api(...) producer assignments to their order
    order = []
    for i, ln in enumerate(lines):
        cm = CALL_RE.search(ln)
        if cm:
            lhs, api, argstr = cm.group(1), cm.group(2), cm.group(3)
            order.append((i, lhs, api, argstr))
            if lhs and lhs.startswith("ret_"):
                producer_of[lhs] = api
                produced_at[lhs] = i
    # now check each call's args
    for (i, lhs, api, argstr) in order:
        margs = args_of(api)
        if margs is None: continue
        # split top-level args
        parts, depth, cur = [], 0, ""
        for ch in argstr:
            if ch == "," and depth == 0: parts.append(cur); cur = ""
            else:
                if ch in "([{": depth += 1
                elif ch in ")]}": depth -= 1
                cur += ch
        if cur.strip(): parts.append(cur)
        for idx, raw in enumerate(parts):
            ma = next((a for a in margs if a.get("index") == idx), None)
            if ma is None: continue
            if ma.get("nullable", True): continue  # nullable arg, NULL is legal
            ts = ma.get("type_str", "")
            var = first_ident(raw)
            handle = is_handle_type(ts)
            string = is_string_type(ts)
            # resolve binding state
            prod_idx = produced_at.get(var)
            is_null_lit = raw.strip() == "NULL" or (var in null_decl and prod_idx is None)
            if handle:
                if prod_idx is None:
                    if var in null_decl or raw.strip() == "NULL":
                        viol["#2a orphan-handle (nonNULL handle = NULL, no producer)"] += 1; dv["#2a"] += 1
                elif prod_idx > i:
                    viol["#1 use-before-produce (close-before-open)"] += 1; dv["#1"] += 1
                else:
                    # produced before — check type match
                    pk = ret_kind(producer_of.get(var, ""))
                    ak = arg_kind(ts)
                    if ak and pk != "other" and pk != ak:
                        viol["#3 type-confusion (handle bound to wrong-type producer)"] += 1; dv["#3"] += 1
            elif string:
                if is_null_lit:
                    viol["#2b missing-value (nonNULL string/ptr arg = NULL)"] += 1; dv["#2b"] += 1
    if dv:
        for k in dv: drivers_with[k] += 1
    per_driver[os.path.basename(f)] = dict(dv)

print(f"drivers analyzed: {len(per_driver)}")
print("\n=== VIOLATION COUNTS (across all drivers) ===")
for k, c in viol.most_common():
    print(f"  {c:4d}  {k}")
print("\n=== DRIVERS AFFECTED (>=1 of that violation) ===")
for k, c in drivers_with.most_common():
    print(f"  {c:3d}/{len(per_driver)} drivers  have {k}")
clean = sum(1 for d in per_driver.values() if not d)
print(f"\n  CLEAN drivers (0 violations): {clean}/{len(per_driver)}")
print(f"  INVALID drivers (>=1 violation): {len(per_driver)-clean}/{len(per_driver)}")
