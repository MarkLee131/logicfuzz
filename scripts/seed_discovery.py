"""Discover a project's real fuzzing seeds for continuous/extended fuzzing.

Why: our generated drivers now correctly feed the fuzz buffer to parser entry
points (``cmsOpenProfileFromMem``, ``cmsIT8LoadFromMem``, …). But a format
parser rejects *random* bytes at its header/magic check and early-returns, so a
seedless run barely moves coverage. Real projects ship valid sample inputs
(ICC profiles, IT8 datasets, OSS-Fuzz ``*_seed_corpus.zip``) that immediately
drive the parser into deep code. This module finds those and hands them to the
extended/continuous fuzzing corpus.

The short-run pipeline eval may stay seedless; continuous fuzzing should not.

Deterministic, best-effort, never raises: returns whatever real seeds it can
locate (possibly empty), and the caller falls back to synthetic seeds.
"""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

# Directory names that are *dedicated fuzzing corpora* — every file inside is a
# real seed, taken wholesale. (NOT generic ``testdata`` dirs, which hold
# arbitrary non-input files like test-framework headers — those go through the
# extension filter below instead.)
# Dirs where EVERY file is a fuzz seed (corpus / extension-less binary inputs).
# Includes project fuzz-input conventions: c-ares ships its DNS-packet and
# name corpora in test/fuzzinput and test/fuzznames (clusterfuzz-* / hash names,
# no extension) — missed by both the old dir list and the sample-extension
# filter, so 119 real c-ares seeds were silently dropped.
_SEED_DIR_NAMES = ("corpus", "seeds", "seed_corpus",
                   "fuzzinput", "fuzznames", "fuzz_corpus", "fuzz_inputs",
                   "fuzz_seeds", "afl_seeds")
# Sample-bearing dirs scanned only for known input-format files (ext-filtered).
_SAMPLE_DIR_NAMES = ("testbed", "tests", "test", "samples", "examples",
                     "fuzzers", "fuzz", "data", "testdata", "test_data")
# Extensions that are almost always valid library inputs worth seeding with.
_SAMPLE_EXTS = (
    ".icc", ".icm",            # ICC color profiles (lcms)
    ".it8", ".cgats", ".ti1", ".ti3",  # IT8/CGATS datasets (lcms)
    ".json",                   # cjson and friends
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp",  # image parsers
    ".pdf", ".xml", ".html", ".svg", ".ttf", ".otf", ".woff",
    ".wav", ".mp3", ".flac", ".ogg", ".zip", ".gz", ".tar", ".pcap",
    ".der", ".pem", ".crt", ".asn1", ".dns",
)
_MAX_SEED_BYTES = 1_000_000          # skip absurdly large samples
_DEFAULT_MAX_SEEDS = 400


def _default_roots(project: str) -> List[Path]:
    base = Path(f"results/{project}")
    return [
        base / "src_ossfuzz" / project,
        base / "src_ossfuzz",
        base,
    ]


def _iter_seed_dir_files(root: Path) -> List[Path]:
    """Every file inside any conventional seed directory under ``root``."""
    out: List[Path] = []
    for d in root.rglob("*"):
        if d.is_dir() and d.name.lower() in _SEED_DIR_NAMES:
            for f in d.iterdir():
                if f.is_file() and f.stat().st_size <= _MAX_SEED_BYTES:
                    out.append(f)
    return out


def _iter_sample_files(root: Path) -> List[Path]:
    """Known input-format sample files under sample-bearing dirs."""
    out: List[Path] = []
    for d in root.rglob("*"):
        if d.is_dir() and d.name.lower() in _SAMPLE_DIR_NAMES:
            for f in d.rglob("*"):
                if (f.is_file() and f.suffix.lower() in _SAMPLE_EXTS
                        and f.stat().st_size <= _MAX_SEED_BYTES):
                    out.append(f)
    return out


def _extract_seed_corpus_zips(root: Path, dest: Path) -> List[Path]:
    """Extract OSS-Fuzz ``*_seed_corpus.zip`` archives — the canonical seeds."""
    out: List[Path] = []
    for z in root.rglob("*_seed_corpus.zip"):
        if not z.is_file():
            continue
        try:
            with zipfile.ZipFile(z) as zf:
                sub = dest / z.stem
                sub.mkdir(parents=True, exist_ok=True)
                for name in zf.namelist():
                    info = zf.getinfo(name)
                    if info.is_dir() or info.file_size > _MAX_SEED_BYTES:
                        continue
                    target = sub / Path(name).name
                    with zf.open(info) as srcf, open(target, "wb") as dstf:
                        dstf.write(srcf.read())
                    out.append(target)
        except Exception as exc:
            logger.debug("seed_corpus zip %s skipped: %s", z, exc)
    return out


def discover_project_seeds(
    project: str,
    *,
    extra_roots: Optional[Sequence[Path]] = None,
    extract_dir: Optional[Path] = None,
    max_seeds: int = _DEFAULT_MAX_SEEDS,
) -> List[Path]:
    """Locate real seed files for ``project``.

    Searches (in priority order): OSS-Fuzz ``*_seed_corpus.zip`` archives,
    conventional ``corpus``/``seeds`` directories, and known input-format
    sample files (``*.icc``/``*.it8``/images/…) under ``testbed``/``tests``/…

    Returns a de-duplicated, size-capped list of seed file paths. Never raises.
    """
    roots = list(extra_roots or []) + _default_roots(project)
    roots = [r for r in roots if r.exists()]
    extract_dir = extract_dir or Path(f"results/{project}/discovered_seeds")

    found: List[Path] = []
    seen_names: set = set()

    def _add(paths: Sequence[Path]) -> None:
        for p in paths:
            # de-dupe by (name, size) so identical samples copied in several
            # places aren't seeded repeatedly.
            try:
                key = (p.name, p.stat().st_size)
            except OSError:
                continue
            if key in seen_names:
                continue
            seen_names.add(key)
            found.append(p)

    for root in roots:
        try:
            _add(_extract_seed_corpus_zips(root, extract_dir))   # highest value
            _add(_iter_seed_dir_files(root))
            _add(_iter_sample_files(root))
        except Exception as exc:
            logger.debug("seed discovery under %s failed: %s", root, exc)
        if len(found) >= max_seeds:
            break

    found = found[:max_seeds]
    if found:
        logger.info("Seed discovery for %s: %d real seed file(s) found",
                    project, len(found))
    else:
        logger.info("Seed discovery for %s: no project seeds found "
                    "(caller will fall back to synthetic)", project)
    return found
