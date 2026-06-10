#!/usr/bin/env python3
"""T7 step 2 — distill each corpus driver into a library-AGNOSTIC construction
template, so retrieval matches on *transferable construction shape* (reference
value) instead of domain vocabulary (what raw-source embedding measured).

Why: the leave-one-out probe showed source-embedding ranks by DOMAIN, but
reference value = "can the target's driver be built by adapting this shape?" —
the lifecycle skeleton + input-consumption idiom + call order, with API names
genericized. We distill that shape once (gpt-4o-mini), then embed the TEMPLATE
text so cosine lives in construction space.

  python3 scripts/distill_construction_templates.py --shard 1/5 --workers 4   # distill
  python3 scripts/distill_construction_templates.py --merge --shards 5         # concat
  python3 scripts/distill_construction_templates.py --embed                    # embed templates

Outputs under results/xproj_index/:
  templates_{i}of{N}.jsonl  →  templates.jsonl  →  templates_embeddings.npy + templates_meta.jsonl
Idempotent per shard. One-time cost ≈ $1.5 (4757 × mini distill) + ~$0.2 embed.
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.build_xproj_embeddings import (  # noqa: E402
    list_files, clean, batches, embed_batch, MODEL as EMB_MODEL, DIM,
)
from liberator_adapter.analysis.cross_project_retrieval import (  # noqa: E402
    extract_api_calls,
)

CHAT_MODEL = "gpt-4o-mini"
OUTDIR = ROOT / "results" / "xproj_index"

ENTRY_TYPES = ["direct_buffer", "fuzzed_data_provider", "file_path", "string", "other"]
RESOURCE = ["stateless", "single_handle", "context_plus_items", "nested_handles", "other"]
ROLES = ["create", "configure", "feed_input", "consume", "iterate", "query",
         "check_error", "destroy"]

# entry_type is a STRUCTURAL FACT — detect it deterministically (the LLM guessed
# "fuzzed_data_provider" for everything in the smoke test). The LLM is used ONLY
# to genericize the ACTUAL extracted calls into roles + a specific idiom.
def detect_entry(src: str) -> str:
    if any(k in src for k in ("FuzzedDataProvider", "ConsumeBytes", "ConsumeInteg",
                              "ConsumeRandom", "ConsumeRemaining")):
        return "fuzzed_data_provider"
    if any(k in src for k in ("fmemopen", "tmpfile", "mkstemp", "TmpFile",
                              "/tmp/", "tmpnam")):
        return "file_path"
    return "direct_buffer"


PROMPT = (
    "You distill a libFuzzer harness into its TRANSFERABLE construction pattern —"
    " the library-AGNOSTIC shape a harness for a DIFFERENT library could reuse.\n"
    "Detected input mode: {entry}.\n"
    "The harness's API calls, IN ORDER (already extracted):\n{apis}\n"
    "Source (for context):\n```\n{src}\n```\n"
    "Describe ONLY what THIS harness actually does — DO NOT invent lifecycle steps"
    " that are not present (a trivial parse-and-free harness must NOT come out as a"
    " full create/configure/.../destroy lifecycle). Output STRICT JSON:\n"
    '{"input_wiring": "<=15 words: how the {entry} bytes reach the first real API",\n'
    ' "resource_shape": one of ' + str(RESOURCE) + ',\n'
    ' "role_sequence": for ONLY the actual calls above, their roles IN ORDER, each'
    ' from ' + str(ROLES) + ' (omit a role if no call plays it; repeat if several),\n'
    ' "construction_idiom": "<=20 words, NO library names — the reusable shape'
    ' SPECIFIC to this harness, not a generic lifecycle"}'
)

_FALLBACK = {"entry_type": "other", "input_wiring": "", "resource_shape": "other",
             "role_sequence": [], "construction_idiom": ""}


def distill_one(client, src: str, retries: int = 4) -> dict:
    entry = detect_entry(src)
    apis = extract_api_calls(src)
    api_str = ", ".join(apis[:40]) if apis else "(none extracted)"
    msg = PROMPT.replace("{entry}", entry).replace("{apis}", api_str).replace("{src}", src)
    delay = 2.0
    for attempt in range(retries):
        try:
            r = client.chat.completions.create(
                model=CHAT_MODEL, temperature=0,
                response_format={"type": "json_object"},
                messages=[{"role": "user", "content": msg}])
            t = json.loads(r.choices[0].message.content)
            return {
                "entry_type": entry,                                    # deterministic
                "input_wiring": str(t.get("input_wiring", ""))[:160],
                "resource_shape": t.get("resource_shape") if t.get("resource_shape") in RESOURCE else "other",
                "role_sequence": [x for x in (t.get("role_sequence") or []) if x in ROLES][:16],
                "construction_idiom": str(t.get("construction_idiom", ""))[:200],
            }
        except Exception:  # noqa: BLE001
            if attempt == retries - 1:
                return {**_FALLBACK, "entry_type": entry}
            time.sleep(delay); delay *= 2
    return {**_FALLBACK, "entry_type": entry}


def render(t: dict) -> str:
    """Template → compact text for embedding (construction space)."""
    roles = ">".join(t.get("role_sequence") or []) or "-"
    return (f"entry:{t.get('entry_type','other')} | resource:{t.get('resource_shape','other')} | "
            f"roles:{roles} | wiring:{t.get('input_wiring','')} | "
            f"idiom:{t.get('construction_idiom','')}")


def run_shard(i: int, n: int, workers: int) -> None:
    from openai import OpenAI
    OUTDIR.mkdir(parents=True, exist_ok=True)
    out = OUTDIR / f"templates_{i}of{n}.jsonl"
    if out.exists():
        print(f"[shard {i}/{n}] exists → skip", flush=True)
        return
    allf = list_files()
    mine = [f for k, f in enumerate(allf) if k % n == (i - 1)]
    print(f"[shard {i}/{n}] {len(mine)} drivers", flush=True)
    client = OpenAI()

    def work(f: Path):
        try:
            src, _ = clean(f.read_text(errors="replace"))  # comment-strip + token-cap
        except OSError:
            return None
        return {"project": f.parent.name, "name": f.stem,
                "path": str(f.relative_to(ROOT)),
                "template": distill_one(client, src)}

    rows, done, fb = [None] * len(mine), 0, 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, f): k for k, f in enumerate(mine)}
        for fut in as_completed(futs):
            k = futs[fut]; rows[k] = fut.result()
            done += 1
            if rows[k] and rows[k]["template"] == _FALLBACK:
                fb += 1
            if done % 100 == 0:
                print(f"[shard {i}/{n}] {done}/{len(mine)} (fallbacks {fb})", flush=True)
    rows = [r for r in rows if r]
    out.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    print(f"[shard {i}/{n}] DONE → {out.name} ({len(rows)} rows, {fb} fallback)", flush=True)


def merge(n: int) -> None:
    rows = []
    for i in range(1, n + 1):
        p = OUTDIR / f"templates_{i}of{n}.jsonl"
        if not p.exists():
            print(f"merge: MISSING shard {i}/{n} → abort", flush=True); return
        rows.extend(json.loads(l) for l in p.read_text().splitlines() if l.strip())
    (OUTDIR / "templates.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    print(f"merge DONE → templates.jsonl ({len(rows)} rows)", flush=True)


def embed() -> None:
    from openai import OpenAI
    rows = [json.loads(l) for l in (OUTDIR / "templates.jsonl").read_text().splitlines() if l.strip()]
    items = [(k, render(r["template"]), 0) for k, r in enumerate(rows)]   # ntok unused (short)
    client = OpenAI()
    vecs = np.zeros((len(rows), DIM), dtype=np.float32)
    got = 0
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(embed_batch, client, b) for b in batches(items)]
        for f in as_completed(futs):
            for idx, emb in f.result():
                vecs[idx] = np.asarray(emb, dtype=np.float32); got += 1
    np.save(OUTDIR / "templates_embeddings.npy", vecs)
    (OUTDIR / "templates_meta.jsonl").write_text(
        "\n".join(json.dumps({k: r[k] for k in ("project", "name", "path", "template")})
                  for r in rows), encoding="utf-8")
    print(f"embed DONE → templates_embeddings.npy {vecs.shape} ({got}/{len(rows)} via {EMB_MODEL})", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard"); ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--merge", action="store_true"); ap.add_argument("--shards", type=int, default=0)
    ap.add_argument("--embed", action="store_true")
    a = ap.parse_args()
    if a.merge:
        merge(a.shards)
    elif a.embed:
        embed()
    elif a.shard:
        i, n = (int(x) for x in a.shard.split("/")); run_shard(i, n, a.workers)
    else:
        ap.error("need --shard i/N | --merge --shards N | --embed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
