#!/usr/bin/env python3
"""Deduplicate the T7 corpus index AFTER embedding (no re-embed needed).

Two cleanups, both data-grounded by the leave-one-out probe:
  1. NOISE blacklist — libFuzzer engine self-tests / generic runner stubs that
     aren't library drivers (FuzzerUnittest, MultipleConstraints…, standalone_
     fuzz_target_runner, libfuzzer_emulator).
  2. NEAR-DUPLICATE collapse — the SAME harness vendored across projects
     (libpng_read_fuzzer ×9, ares-fuzz ×3, cryptofuzz entry ×9, …). Detected by
     SOURCE-embedding cosine > τ (≈identical text). We KEEP one representative per
     cluster. Uses SOURCE embeddings on purpose — TEMPLATE-embedding would also
     fuse "same construction, different library" pairs, which are the VALUABLE
     cross-domain analogs we must NOT drop.

Output: results/xproj_index/dedup_keep.json = {"keep_paths": [...], "stats": {...}}.
Retrieval loads this and restricts both indexes to keep_paths (rows align by path).
$0 — reuses results/xproj_index/embeddings.npy. python3 scripts/dedup_xproj_index.py [tau]
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import numpy as np

IDX = Path(__file__).resolve().parent.parent / "results" / "xproj_index"
TAU = float(sys.argv[1]) if len(sys.argv) > 1 else 0.97
NOISE = {"FuzzerUnittest", "MultipleConstraintsOnSmallInputTest",
         "standalone_fuzz_target_runner", "libfuzzer_emulator"}


def main():
    meta = [json.loads(l) for l in (IDX / "meta.jsonl").read_text().splitlines() if l.strip()]
    V = np.load(IDX / "embeddings.npy").astype(np.float32)
    V /= (np.linalg.norm(V, axis=1, keepdims=True) + 1e-9)
    n = len(meta)
    assert V.shape[0] == n

    noise_idx = {i for i, m in enumerate(meta) if m["name"] in NOISE}
    # Greedy near-dup clustering: walk in order, keep i as a representative,
    # absorb every later j with cos>τ into i's cluster (dropped).
    dropped_dup = set()
    kept_reps = []
    for i in range(n):
        if i in noise_idx or i in dropped_dup:
            continue
        kept_reps.append(i)
        sims = V[i + 1:] @ V[i]          # only compare to later rows (upper tri)
        for off in np.nonzero(sims > TAU)[0]:
            j = i + 1 + int(off)
            if j not in noise_idx:
                dropped_dup.add(j)

    keep = [i for i in range(n) if i not in noise_idx and i not in dropped_dup]
    keep_paths = [meta[i]["path"] for i in keep]

    # cluster-size histogram for the report (how vendored is the corpus?)
    from collections import Counter
    by_name = Counter(meta[j]["name"] for j in dropped_dup)
    stats = {
        "total": n,
        "noise_dropped": len(noise_idx),
        "near_dup_dropped": len(dropped_dup),
        "kept_unique": len(keep),
        "tau": TAU,
        "top_vendored_basenames": by_name.most_common(8),
    }
    (IDX / "dedup_keep.json").write_text(
        json.dumps({"keep_paths": keep_paths, "stats": stats}, indent=1),
        encoding="utf-8")
    print(json.dumps(stats, indent=1, ensure_ascii=False))
    print(f"\n-> kept {len(keep)}/{n} unique drivers "
          f"({(n-len(keep))/n*100:.1f}% removed) → results/xproj_index/dedup_keep.json")


if __name__ == "__main__":
    main()
