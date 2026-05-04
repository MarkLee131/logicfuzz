"""O4 — corpus union for merged harness.

Each surviving sub-driver typically ships its own corpus
(``results/output-{project}-project/corpora/<id>.fuzz_target/``) that
LogicFuzz already produced during the per-driver coverage build. When
we fuse drivers, naive union is wrong: each seed must be tagged with a
selector that *routes back to the sub-driver it came from*, otherwise
the fused binary just feeds it to a random sub-harness.

We do not deduplicate or minset — that's libFuzzer's
``-merge=1`` job. We just write the tagged seeds into a flat
``corpus_merged/`` directory.

Implementation maps to the dispatch geometry:

  * ``DispatchMode.UNIFORM``: selector = ``i % 256`` (or ``int.from_bytes(_, k)``
    yielding ``i mod N`` after the runtime modulo). Concretely: write
    selector bytes ``= i.to_bytes(selector_bytes, 'little')`` so
    ``memcpy(&driverIndex, sel, k); driverIndex % N == i``.
  * ``DispatchMode.CDF``: selector = midpoint of bucket ``i``'s
    threshold range, big-endian written as 2 bytes (matches the
    ``memcpy(&selector, ., 2)`` lookup above on little-endian; we use
    little-endian write to match host byte order — preflight test
    confirms x86-64 default).

Selector position (HEAD vs TAIL) determines whether selector bytes
are prepended or appended to the original seed.

Dictionary union: each driver's existing dict (if any) is concatenated
with a per-driver comment header. There's no way to namespace tokens
to a sub-harness in OSS-Fuzz dict format, so all tokens become global —
this introduces token noise across sub-harnesses. We accept this as a
known cost.
"""
from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from tools.merge_drivers.merge import (
    DispatchMode,
    SelectorPosition,
    SynthesizedDriver,
    _compute_cdf_thresholds,
)

logger = logging.getLogger(__name__)


@dataclass
class CorpusUnionStats:
    """Telemetry from a corpus union pass."""

    n_drivers_with_corpus: int
    n_seeds_tagged: int
    n_dicts_merged: int
    output_corpus_dir: Path
    output_dict_path: Optional[Path]


def _selector_bytes_for_uniform(driver_index: int, n: int, sb: int) -> bytes:
    """Return ``sb`` bytes such that ``int.from_bytes(...) % n == driver_index``.

    libFuzzer / our dispatcher reads with ``memcpy(&u32, ptr, sb)``,
    which on x86-64 / little-endian is equivalent to ``int.from_bytes(
    ptr, 'little')`` truncated to ``sb`` bytes. So we just write the
    target driver index in little-endian; the runtime ``% N`` reduces
    cleanly.
    """
    if not (0 <= driver_index < n):
        raise ValueError(f"driver_index {driver_index} out of range for N={n}")
    return driver_index.to_bytes(sb, "little")


def _selector_bytes_for_cdf(
    driver_index: int,
    thresholds: Sequence[int],
) -> bytes:
    """Return 2 bytes selecting bucket ``driver_index`` under CDF.

    Picks the midpoint of bucket ``i``'s range — half way between
    ``threshold[i-1]`` (exclusive lower bound) and ``threshold[i]``
    (exclusive upper bound). Midpoint is the most stable choice under
    libFuzzer's bit-flip / arithmetic mutators (a 1-bit flip is least
    likely to cross either neighbouring threshold).
    """
    lo = thresholds[driver_index - 1] if driver_index > 0 else 0
    hi = thresholds[driver_index]
    midpoint = (lo + hi) // 2
    midpoint = max(0, min(midpoint, 65535))
    return midpoint.to_bytes(2, "little")


def _tag_seed(
    seed_bytes: bytes,
    selector_bytes: bytes,
    position: SelectorPosition,
) -> bytes:
    if position == SelectorPosition.HEAD:
        return selector_bytes + seed_bytes
    return seed_bytes + selector_bytes


def _stable_seed_name(prefix: str, seed_path: Path, index: int) -> str:
    """Filename for a tagged seed in the merged corpus.

    Includes the originating sub-driver id (``prefix``) for triage and
    a content-derived suffix. Avoiding pure hash collisions across
    drivers is why we prefix.
    """
    return f"{prefix}_{index:06d}_{seed_path.name}"


def _resolve_corpus_dir(
    driver_path: Path,
    project_root: Optional[Path],
) -> Optional[Path]:
    """Look up the LogicFuzz corpus dir for a sub-driver source.

    ``results/output-<proj>-project/corpora/<basename>/`` is the
    LogicFuzz layout; the sub-driver source typically lives at
    ``results/output-<proj>-project/fuzz_targets/<basename>``.
    """
    if project_root is None:
        # Walk up: fuzz_targets/<id>.fuzz_target → ../corpora/<id>.fuzz_target
        candidate = (
            driver_path.parent.parent
            / "corpora"
            / driver_path.name
        )
        return candidate if candidate.exists() else None
    candidate = project_root / "corpora" / driver_path.name
    return candidate if candidate.exists() else None


def union_corpus(
    synth: SynthesizedDriver,
    output_dir: Path,
    project_root: Optional[Path] = None,
    dict_paths: Optional[List[Optional[Path]]] = None,
) -> CorpusUnionStats:
    """Build a tagged seed corpus for the synthesized harness.

    Args:
        synth: the synthesized driver. ``synth.drivers`` order defines
            the routing index for each sub-driver.
        output_dir: where to write ``corpus_merged/`` (the seeds) and
            ``merged.dict`` (the dictionary union, if any tokens exist).
        project_root: LogicFuzz project root (e.g.
            ``results/output-libucl-project``). When ``None``, we
            auto-locate the corpus via the sub-driver's path layout.
        dict_paths: optional same-length-as-``synth.drivers`` list of
            dict file paths; ``None`` entries skipped. Pass ``None`` to
            skip dict union entirely.

    Returns:
        ``CorpusUnionStats``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = output_dir / "corpus_merged"
    if corpus_dir.exists():
        shutil.rmtree(corpus_dir)
    corpus_dir.mkdir()

    n = synth.driver_count
    if synth.mode == DispatchMode.CDF:
        assert synth.weights is not None
        thresholds = _compute_cdf_thresholds(synth.weights)
    else:
        thresholds = []  # unused for UNIFORM

    n_with_corpus = 0
    n_seeds = 0
    for i, drv in enumerate(synth.drivers):
        src_corpus = _resolve_corpus_dir(drv.driver_path, project_root)
        if src_corpus is None or not src_corpus.is_dir():
            logger.info("no corpus for sub-driver %s — skipping", drv.driver_id)
            continue

        # Build the right selector bytes for this sub-driver
        if synth.mode == DispatchMode.UNIFORM:
            sel = _selector_bytes_for_uniform(i, n, synth.selector_bytes)
        else:
            sel = _selector_bytes_for_cdf(i, thresholds)

        seeds = [p for p in src_corpus.iterdir() if p.is_file()]
        if not seeds:
            logger.info("empty corpus for sub-driver %s", drv.driver_id)
            continue

        n_with_corpus += 1
        for j, seed_path in enumerate(seeds):
            try:
                seed_bytes = seed_path.read_bytes()
            except OSError as e:
                logger.warning("skip unreadable seed %s: %s", seed_path, e)
                continue
            tagged = _tag_seed(seed_bytes, sel, synth.position)
            out_name = _stable_seed_name(drv.driver_id, seed_path, j)
            (corpus_dir / out_name).write_bytes(tagged)
            n_seeds += 1
        logger.info(
            "sub-driver %s: %d seeds tagged with selector %s",
            drv.driver_id,
            len(seeds),
            sel.hex(),
        )

    # Dict union (optional)
    out_dict: Optional[Path] = None
    n_dicts = 0
    if dict_paths is not None:
        out_dict = output_dir / "merged.dict"
        with open(out_dict, "w") as out:
            out.write(
                "# Merged dictionary for synthesized harness — "
                "tokens NOT namespaced; cross-sub-harness noise is "
                "an accepted cost.\n"
            )
            for i, dpath in enumerate(dict_paths):
                if dpath is None or not dpath.exists():
                    continue
                try:
                    text = dpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                drv_id = synth.drivers[i].driver_id
                out.write(f"\n# ----- from sub-driver {drv_id} ({dpath}) -----\n")
                out.write(text)
                if not text.endswith("\n"):
                    out.write("\n")
                n_dicts += 1
        if n_dicts == 0:
            out_dict.unlink()
            out_dict = None

    return CorpusUnionStats(
        n_drivers_with_corpus=n_with_corpus,
        n_seeds_tagged=n_seeds,
        n_dicts_merged=n_dicts,
        output_corpus_dir=corpus_dir,
        output_dict_path=out_dict,
    )
