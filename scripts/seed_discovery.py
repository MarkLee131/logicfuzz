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
import re
import shutil
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

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


# ---------------------------------------------------------------------------
# Format-matching seed routing into a per-driver corpus dir
# ---------------------------------------------------------------------------
#
# ``discover_project_seeds`` finds ALL of a project's real inputs. But a
# generated driver consumes ONE format at its fuzz-byte entry (lcms profile
# drivers parse ICC via ``cmsOpenProfileFromMem``; an IT8 driver parses CGATS
# via ``cmsIT8LoadFromMem``). Seeding a driver with the WRONG-format inputs is
# wasted corpus (and, post-merge, routes a real ``.icc`` to a sub-driver that
# can't parse it). So we route each driver to the seeds whose format it
# actually consumes — inferred from (1) the parser-entry APIs the driver calls
# and (2) the seed's own format (extension, else file magic).
#
# This is the generation-phase analogue of what ``run_extended_fuzzing.py``
# already does for the 24h continuous run. It reuses ``discover_project_seeds``;
# it does NOT fork a parallel seed system.

# Format families: a stable label → the seed file extensions that belong to it.
_FORMAT_EXTS: Dict[str, Tuple[str, ...]] = {
    "icc": (".icc", ".icm"),
    "it8": (".it8", ".cgats", ".ti1", ".ti3"),
    "json": (".json",),
    "image": (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp"),
    "xml": (".xml", ".html", ".svg"),
    "font": (".ttf", ".otf", ".woff"),
    "pdf": (".pdf",),
    "audio": (".wav", ".mp3", ".flac", ".ogg"),
    "archive": (".zip", ".gz", ".tar"),
    "pcap": (".pcap",),
    "crypto": (".der", ".pem", ".crt", ".asn1"),
    "dns": (".dns",),
}

# Parser-entry API name substrings → the format family they consume. Matched
# case-insensitively against the driver source. Keep this driven by the SAME
# formats ``_FORMAT_EXTS`` knows; an unknown API yields no constraint (we then
# fall back to ALL discovered seeds — a real input still beats random bytes).
_API_FORMAT_HINTS: Tuple[Tuple[str, str], ...] = (
    ("openprofilefrommem", "icc"),   # lcms  cmsOpenProfileFromMem
    ("openprofilefromfile", "icc"),
    ("it8loadfrommem", "it8"),       # lcms  cmsIT8LoadFromMem
    ("it8loadfromfile", "it8"),
    ("cms_it8", "it8"),
    ("json", "json"),                # cjson cJSON_Parse*, json_* …
    ("png_", "image"), ("readpng", "image"), ("read_png", "image"),
    ("jpeg", "image"), ("jpg", "image"), ("gif", "image"),
    ("xml", "xml"), ("html", "xml"), ("svg", "xml"),
    ("ttf", "font"), ("freetype", "font"), ("ft_", "font"),
    ("pdf", "pdf"),
    ("pcap", "pcap"), ("dns", "dns"), ("ares_", "dns"),
)

# ICC profiles carry the magic 'acsp' at byte offset 36 — recover the format of
# an extension-less corpus seed (OSS-Fuzz hash-named files) by content.
_MAGIC_PROBES: Tuple[Tuple[str, int, bytes], ...] = (
    ("icc", 36, b"acsp"),
    ("image", 0, b"\x89PNG"),
    ("image", 0, b"\xff\xd8\xff"),       # JPEG
    ("image", 0, b"GIF8"),
    ("pdf", 0, b"%PDF"),
    ("archive", 0, b"PK\x03\x04"),       # zip
    ("archive", 0, b"\x1f\x8b"),         # gzip
    ("font", 0, b"\x00\x01\x00\x00"),    # TTF
    ("font", 0, b"OTTO"),                # OTF
)


def classify_seed_format(path: Path) -> Optional[str]:
    """Return the format family of ``path`` (by extension, else magic), or None.

    Deterministic, best-effort. Extension wins (fast, unambiguous for the
    project's own ``*.icc``/``*.it8`` samples); magic is the fallback for
    extension-less corpus seeds. JSON/IT8 are text and have no reliable magic,
    so an extension-less file of those formats returns None (→ unconstrained).
    """
    suffix = path.suffix.lower()
    if suffix:
        for fam, exts in _FORMAT_EXTS.items():
            if suffix in exts:
                return fam
    try:
        head = path.read_bytes()[:64]
    except OSError:
        return None
    for fam, off, sig in _MAGIC_PROBES:
        if head[off:off + len(sig)] == sig:
            return fam
    return None


def infer_driver_formats(driver_source: str) -> Set[str]:
    """Infer the input-format families a driver consumes from its API calls.

    Returns the set of format labels whose parser-entry API the driver calls.
    Empty set = no recognised parser entry (→ caller should not constrain).
    """
    text = driver_source.lower()
    fams: Set[str] = set()
    for needle, fam in _API_FORMAT_HINTS:
        if needle in text:
            fams.add(fam)
    return fams


def select_seeds_for_driver(
    driver_source: str,
    seeds: Sequence[Path],
) -> List[Path]:
    """Pick the discovered seeds whose format matches what the driver consumes.

    Routing rule:
      * If the driver names a recognised parser-entry API (→ a non-empty format
        set) AND at least one discovered seed matches one of those formats,
        return ONLY the matching seeds (don't pollute an ICC driver with JSON).
      * Otherwise return ALL seeds — either the driver's format is unknown, or
        no on-disk seed matches it; a real project input still beats random
        bytes, and this never makes things worse than the seedless status quo.
    """
    wanted = infer_driver_formats(driver_source)
    if not wanted:
        return list(seeds)
    matched = [s for s in seeds if classify_seed_format(s) in wanted]
    return matched if matched else list(seeds)


def seed_corpus_for_driver(
    project: str,
    corpus_dir: Path,
    driver_source_path: Optional[Path] = None,
    *,
    seeds: Optional[Sequence[Path]] = None,
    max_seeds: int = 64,
) -> int:
    """Copy format-matching real seeds into a driver's (per-trial) corpus dir.

    The generation-phase fuzz/coverage run reads ``corpus_dir`` (empty by
    default — ``WorkDirs.corpus`` just ``mkdir``s it), so a parser-entry driver
    fed only random bytes early-returns at its header/magic check and barely
    moves coverage. This routes the project's REAL inputs (valid ICC profiles,
    IT8 datasets, …) — filtered to the format the driver actually parses — into
    that dir so the driver reaches deep parse code.

    Idempotent and additive: never clears the dir, never overwrites an existing
    file (libFuzzer-discovered inputs are preserved), capped at ``max_seeds``.
    Best-effort: any error is swallowed and 0 is returned. Returns the number
    of seeds copied.

    Args:
        project: project name (for ``discover_project_seeds``).
        corpus_dir: the per-driver corpus directory to seed.
        driver_source_path: path to the ``.fuzz_target`` source; used to route
            by which parser-entry API consumes the buffer. None → no routing
            (all discovered seeds copied).
        seeds: pre-discovered seeds (test/perf hook). None → discover them.
        max_seeds: per-driver copy cap.

    Returns:
        Count of seed files copied into ``corpus_dir``.
    """
    try:
        corpus_dir = Path(corpus_dir)
        corpus_dir.mkdir(parents=True, exist_ok=True)
        all_seeds = list(seeds) if seeds is not None \
            else discover_project_seeds(project)
        if not all_seeds:
            return 0

        driver_source = ""
        if driver_source_path is not None:
            try:
                driver_source = Path(driver_source_path).read_text(
                    errors="replace")
            except OSError:
                driver_source = ""
        chosen = (select_seeds_for_driver(driver_source, all_seeds)
                  if driver_source else list(all_seeds))
        chosen = chosen[:max_seeds]

        n = 0
        for src in chosen:
            # Stable, collision-free name; preserve the original so triage can
            # tell a routed real seed from a libFuzzer-discovered one.
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)
            dst = corpus_dir / f"projseed_{safe}"
            if dst.exists():
                continue
            try:
                shutil.copy(src, dst)
                n += 1
            except OSError:
                continue
        if n:
            logger.info(
                "Seeded %s corpus dir %s with %d format-matching real seed(s)",
                project, corpus_dir, n)
        return n
    except Exception as exc:  # noqa: BLE001 — seeding must never break a run
        logger.debug("seed_corpus_for_driver(%s) skipped: %s", project, exc)
        return 0
