#!/usr/bin/env python3
"""Build the T7 cross-project driver embedding index (OpenAI text-embedding-3-large).

Corpus: ``extracted_fuzz_drivers/<project>/*.{c,cc,cpp,cxx,c++}`` (GCS bucket
``oss-fuzz-llm-public/human_written_targets``, 484 projects / ~4.7k harnesses).

Comments (incl. the license boilerplate every driver shares) are stripped BEFORE
embedding — reusing the exact ``_COMMENT_RE`` the structure-sig path uses — so the
license header does not inflate pairwise cosine similarity or waste tokens
(memory: project-t7-embedding-strip-comments). This is the (previously unwired)
embedding-fallback re-rank index for ``cross_project_retrieval``.

Sharded for parallel subagent execution::

    python3 scripts/build_xproj_embeddings.py --shard 1/5 --workers 4
    ...
    python3 scripts/build_xproj_embeddings.py --merge --shards 5   # after all shards

Each shard writes ``results/xproj_index/shard_{i}of{N}_{vec.npy,meta.jsonl}``;
``--merge`` concatenates them into ``embeddings.npy`` + ``meta.jsonl`` +
``manifest.json``. Idempotent: a shard whose outputs exist is skipped.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import tiktoken

ROOT = Path(__file__).resolve().parent.parent
_ENC = tiktoken.get_encoding("cl100k_base")   # text-embedding-3-* encoding
sys.path.insert(0, str(ROOT))


def load_project_env(path: Path = ROOT / "logicfuzz.env") -> None:
    """Load API keys from logicfuzz.env, OVERRIDING the inherited environment.

    `~/.bashrc` may carry a DIFFERENT OPENAI_API_KEY; logicfuzz.env is this
    project's single source of truth for API usage, so it must win. Key values
    are never logged. No-op if the file is absent."""
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v:
                os.environ[k] = v
    except OSError:
        pass


load_project_env()   # run at import so any consumer (distill imports this) is covered
from liberator_adapter.analysis.cross_project_retrieval import (  # noqa: E402
    _COMMENT_RE, extract_api_calls,
)

MODEL = "text-embedding-3-large"
DIM = 3072
EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++")
MAX_TOKENS = 8_000          # under the model's 8191/input hard cap (code is
                            # token-dense — char proxies overshoot, hence tiktoken)
BATCH_ITEMS = 96            # items per request
BATCH_TOKENS = 200_000      # per-request token budget
CORPUS = ROOT / "extracted_fuzz_drivers"
OUTDIR = ROOT / "results" / "xproj_index"


def clean(source: str) -> tuple[str, int]:
    """Strip comments (license + inline), collapse whitespace, token-truncate.

    Returns (text, n_tokens). Truncation is by ACTUAL tokens (tiktoken), not a
    char proxy — C/C++ is token-dense, so a 30k-char cap overshot 8192 tokens and
    a single oversized input 400'd the whole 96-item batch (the gap bug)."""
    txt = _COMMENT_RE.sub(" ", source or "")
    txt = " ".join(txt.split())
    toks = _ENC.encode(txt)
    if len(toks) > MAX_TOKENS:
        toks = toks[:MAX_TOKENS]
        txt = _ENC.decode(toks)
    return txt, len(toks)


def list_files() -> list[Path]:
    out: list[Path] = []
    if not CORPUS.is_dir():
        return out
    for proj in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        for f in sorted(proj.iterdir()):
            if f.is_file() and f.suffix.lower() in EXTS:
                out.append(f)
    return out


def batches(items: list[tuple]):
    """Token/size-bounded batches of (idx, text, ntok) tuples."""
    cur, ntok = [], 0
    for it in items:
        t = it[2]
        if cur and (len(cur) >= BATCH_ITEMS or ntok + t > BATCH_TOKENS):
            yield cur
            cur, ntok = [], 0
        cur.append(it)
        ntok += t
    if cur:
        yield cur


def embed_batch(client, batch: list[tuple], retries: int = 5) -> list[tuple]:
    inputs = [it[1] for it in batch]
    delay = 2.0
    for attempt in range(retries):
        try:
            resp = client.embeddings.create(model=MODEL, input=inputs)
            return [(batch[j][0], d.embedding) for j, d in enumerate(resp.data)]
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            # Oversized input → bisect so one bad item drops only itself, not the
            # whole batch. (Shouldn't fire post token-truncation; safety net.)
            if "maximum input length" in msg or "'input[" in msg:
                if len(batch) == 1:
                    print(f"  drop oversized item idx={batch[0][0]}", flush=True)
                    return []
                mid = len(batch) // 2
                return (embed_batch(client, batch[:mid], retries)
                        + embed_batch(client, batch[mid:], retries))
            if attempt == retries - 1:
                print(f"  batch FAILED after {retries}: {exc!r}", flush=True)
                return []
            time.sleep(delay)
            delay *= 2
    return []


def run_shard(i: int, n: int, workers: int) -> None:
    from openai import OpenAI
    OUTDIR.mkdir(parents=True, exist_ok=True)
    vec_path = OUTDIR / f"shard_{i}of{n}_vec.npy"
    meta_path = OUTDIR / f"shard_{i}of{n}_meta.jsonl"
    if vec_path.exists() and meta_path.exists():
        print(f"[shard {i}/{n}] already done → skip", flush=True)
        return

    allf = list_files()
    mine = [f for k, f in enumerate(allf) if k % n == (i - 1)]
    print(f"[shard {i}/{n}] {len(mine)} files (of {len(allf)})", flush=True)

    items, meta = [], []
    for f in mine:
        try:
            src = f.read_text(errors="replace")
        except OSError:
            continue
        txt, ntok = clean(src)
        if not txt:
            continue
        items.append((len(meta), txt, ntok))
        meta.append({"project": f.parent.name, "name": f.stem,
                     "path": str(f.relative_to(ROOT)),
                     "n_api_calls": len(extract_api_calls(src))})

    client = OpenAI()
    vecs = np.zeros((len(meta), DIM), dtype=np.float32)
    got = 0
    bl = list(batches(items))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(embed_batch, client, b): bi for bi, b in enumerate(bl)}
        for done in as_completed(futs):
            for idx, emb in done.result():
                vecs[idx] = np.asarray(emb, dtype=np.float32)
                got += 1
            print(f"[shard {i}/{n}] {got}/{len(meta)} embedded", flush=True)

    np.save(vec_path, vecs)
    meta_path.write_text("\n".join(json.dumps(m) for m in meta), encoding="utf-8")
    print(f"[shard {i}/{n}] DONE → {vec_path.name} ({got}/{len(meta)})", flush=True)


def merge(n: int) -> None:
    vecs, meta = [], []
    for i in range(1, n + 1):
        vp = OUTDIR / f"shard_{i}of{n}_vec.npy"
        mp = OUTDIR / f"shard_{i}of{n}_meta.jsonl"
        if not (vp.exists() and mp.exists()):
            print(f"merge: MISSING shard {i}/{n} → abort", flush=True)
            return
        vecs.append(np.load(vp))
        meta.extend(json.loads(l) for l in mp.read_text().splitlines() if l.strip())
    mat = np.concatenate(vecs, axis=0)
    np.save(OUTDIR / "embeddings.npy", mat)
    (OUTDIR / "meta.jsonl").write_text(
        "\n".join(json.dumps(m) for m in meta), encoding="utf-8")
    (OUTDIR / "manifest.json").write_text(json.dumps({
        "model": MODEL, "dim": DIM, "count": int(mat.shape[0]),
        "shards": n, "corpus": "extracted_fuzz_drivers",
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, indent=2), encoding="utf-8")
    print(f"merge DONE → embeddings.npy {mat.shape}, {len(meta)} meta rows", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", help="i/N, 1-indexed (e.g. 1/5)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--merge", action="store_true")
    ap.add_argument("--shards", type=int, default=0, help="N for --merge")
    a = ap.parse_args()
    if a.merge:
        merge(a.shards)
        return 0
    if not a.shard:
        ap.error("need --shard i/N or --merge --shards N")
    i, n = (int(x) for x in a.shard.split("/"))
    run_shard(i, n, a.workers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
