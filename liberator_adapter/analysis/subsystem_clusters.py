"""Subsystem clustering for coverage-complete portfolio construction.

Partition the API surface into SUBSYSTEM clusters so the portfolio can guarantee
>=1 lifecycle-valid driver per subsystem (coverage-COMPLETE) instead of a global
top-k that lets parser-entry chains crowd out object-construction subsystems
(the measured lcms root cause: 93 creators -> 17 anchored -> 8 drivers, whole
subsystems Pipeline/MLU/NamedColor/ToneCurve never selected).

A cluster = a SUBSYSTEM HANDLE TYPE. Each API is assigned to the cluster of its
PRIMARY subsystem handle (its produced handle if it is a creator, else the
handle it consumes), where "subsystem handle" = a handle type touched by <=
``plumbing_frac`` of APIs. We deliberately do NOT take transitive connected
components: pipeline / stage / tone-curve share handle types (a pipeline holds
stages, a stage holds tone-curves), so a connected-component merge collapses
them into one 130-API blob; per-primary-handle assignment keeps them as the
distinct fuzzing subsystems they are. A multi-handle API is disambiguated by a
NAME-TOKEN match (``cmsStageAllocToneCurves`` -> the ``Stage`` handle, earliest
token in the name wins). Ubiquitous PLUMBING handles (the context handle; the
central profile / generic handle typedefs touched by a large fraction of the
surface) are EXCLUDED so they don't swallow every subsystem. APIs touching only
plumbing handles (or no handle) fall back to a NAME-PREFIX cluster, which groups
handle-less families (e.g. the cms*DeltaE / color-math ops, the profile builders).

Pure-deterministic, 0 LLM. Operates on an ``APISemanticModel`` (objects with
``.requires``/``.produces``) OR a loaded JSON dict-model (``{name: {requires,
produces, role}}``) — both are accepted.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List


_VERB = (r'(?:Create|Get|Set|Build|Alloc|Open|Write|Read|Free|Delete|Dup|Is|'
         r'Eval|Save|Load|Compute|Append|Insert|New|Init|Close|Reverse|Join|'
         r'Smooth|Estimate|Add|Detect|Adapt|Channels|Desaturate)?')


def _name_token(name: str, lib_prefix: str) -> str:
    """Coarse subsystem token for the handle-less fallback: strip the lib prefix,
    drop a leading verb, take the leading noun word (so cmsBuildGamma -> Gamma,
    cmsCreateGrayProfile -> Gray... wait, noun after verb)."""
    core = name
    if lib_prefix and core.lower().startswith(lib_prefix.lower()):
        core = core[len(lib_prefix):]
    core = core.lstrip("_")
    m = re.match(_VERB + r'([A-Z][a-z0-9]+)', core)
    if m and m.group(1):
        return m.group(1)
    # no verb+noun match: leading CamelCase word, else first 6 chars
    m2 = re.match(r'([A-Za-z][a-z0-9]+)', core)
    return (m2.group(1) if m2 else core[:6]) or name


def _accessor(apis: Dict[str, Any]):
    """Return a (requires, produces) accessor that works for object- and
    dict-shaped models."""
    sample = next(iter(apis.values()), None)
    if sample is not None and hasattr(sample, "requires"):
        def get(name, attr):
            return [h for h in (getattr(apis[name], attr, None) or []) if h]
    else:
        def get(name, attr):
            return [h for h in ((apis.get(name) or {}).get(attr) or []) if h]
    return get


def _handle_token(h: str) -> str:
    """Comparable core token of a handle type: ``cmspipeline*`` -> ``pipeline``,
    ``cmsnamedcolorlist*`` -> ``namedcolorlist``, ``_cmscontext_*`` -> ``context``."""
    core = re.sub(r'[^a-z0-9]', '', h.lower())
    core = re.sub(r'^(?:cms|lcms)', '', core)
    return core


def subsystem_clusters(model: Any, plumbing_frac: float = 0.10) -> Dict[str, str]:
    """Map each API name -> its subsystem cluster id.

    Handle clusters get id = the handle type (e.g. ``cmspipeline*``); name-prefix
    fallback clusters get id ``"N:<token>"``. Every API name is assigned exactly
    one cluster (the partition is total).
    """
    apis = getattr(model, "apis", {}) or {}
    names: List[str] = [n for n in apis.keys() if n]
    n = len(names)
    if n == 0:
        return {}
    get = _accessor(apis)

    # 1. plumbing handles = touched (required OR produced) by > plumbing_frac of
    #    APIs (shared substrate: context handle, central profile/handle typedefs).
    touch_count: Counter = Counter()
    for nm in names:
        for h in set(get(nm, "requires")) | set(get(nm, "produces")):
            touch_count[h] += 1
    thresh = max(2, int(plumbing_frac * n))
    plumbing = {h for h, c in touch_count.items() if c > thresh}

    try:
        from liberator_adapter.analysis.sequence_constructor import _detect_lib_prefix
        lib_prefix = _detect_lib_prefix(names)
    except Exception:
        lib_prefix = ""

    def _primary_handle(nm: str):
        prod = [h for h in get(nm, "produces") if h not in plumbing]
        req = [h for h in get(nm, "requires") if h not in plumbing]
        cands = prod + req
        if not cands:
            return None
        low = nm.lower()
        # (a) name-token match: the handle whose core token appears in the API
        #     name; the EARLIEST occurrence wins (cmsPipelineInsertStage -> the
        #     Pipeline handle, not Stage). Ties broken by more-specific (rarer).
        best, best_key = None, None
        for h in cands:
            pos = low.find(_handle_token(h))
            if pos >= 0:
                key = (pos, touch_count[h], h)
                if best_key is None or key < best_key:
                    best, best_key = h, key
        if best is not None:
            return best
        # (b) no name match: a creator is defined by its PRODUCED handle; else the
        #     consumer joins its most-specific (rarest) required handle.
        pool = prod if prod else req
        return min(pool, key=lambda h: (touch_count[h], h))

    clusters: Dict[str, str] = {}
    for nm in names:
        h = _primary_handle(nm)
        clusters[nm] = h if h is not None else "N:" + _name_token(nm, lib_prefix)
    return clusters


def cluster_summary(clusters: Dict[str, str]) -> Dict[str, List[str]]:
    """Invert name->cluster into cluster->sorted member names (for logging/tests)."""
    out: Dict[str, List[str]] = defaultdict(list)
    for name, cid in clusters.items():
        out[cid].append(name)
    return {cid: sorted(ms) for cid, ms in out.items()}
