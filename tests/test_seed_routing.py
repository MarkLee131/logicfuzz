"""Regression tests for format-matching seed routing into per-driver corpora.

Background — see docs/generation.md §6 "Input/seed layer" and CLAUDE.md:

  The factory chain made lcms's ``cmsDoTransform`` constructable+compilable, but
  a 30s probe covered 0/799 of ``cmsxform.c`` because random fuzzer bytes never
  form a valid ICC profile to traverse the opaque chain (``cmsOpenProfileFromMem``
  → NULL → guard → ``cmsDoTransform`` never runs). The generation-phase corpus
  dir (``WorkDirs.corpus``) starts EMPTY — real ``.icc`` seeds never reached it;
  only ``scripts/run_extended_fuzzing.py`` (the 24h path) seeded with real
  inputs.

These tests pin the new ``scripts.seed_discovery`` routing logic that copies the
project's REAL inputs — filtered to the format the driver actually parses — into
a per-driver corpus dir. The filesystem is mocked via ``tmp_path``; no project
checkout or Docker is required.
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure repo root is importable (run from any cwd).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scripts.seed_discovery import (  # noqa: E402
    classify_seed_format,
    infer_driver_formats,
    select_seeds_for_driver,
    seed_corpus_for_driver,
)


# --- driver fixtures ---------------------------------------------------------

_ICC_DRIVER = """
#include "lcms2.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsHPROFILE p = cmsOpenProfileFromMem(data, size);
    if (!p) return 0;
    cmsCloseProfile(p);
    return 0;
}
"""

_TRANSFORM_DRIVER = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsHPROFILE in = cmsOpenProfileFromMem(data, size);
    if (!in) return 0;
    cmsHTRANSFORM t = cmsCreateTransform(in, TYPE_RGB_8, NULL, TYPE_RGB_8, 0, 0);
    cmsDoTransform(t, data, data, 1);
    return 0;
}
"""

_JSON_DRIVER = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cJSON *j = cJSON_ParseWithLength((const char*)data, size);
    cJSON_Delete(j);
    return 0;
}
"""

_OPAQUE_DRIVER = """
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    do_something_with(data, size);  // no recognised parser entry
    return 0;
}
"""


def _icc_bytes(n: int = 200) -> bytes:
    """A blob with the ICC magic ('acsp' at offset 36) for magic-probe tests."""
    buf = bytearray(b"\x00" * max(n, 40))
    buf[36:40] = b"acsp"
    return bytes(buf)


# --- classify_seed_format ----------------------------------------------------

def test_classify_by_extension(tmp_path):
    assert classify_seed_format(tmp_path / "p.icc") == "icc"
    assert classify_seed_format(tmp_path / "p.ICM") == "icc"
    assert classify_seed_format(tmp_path / "d.it8") == "it8"
    assert classify_seed_format(tmp_path / "x.json") == "json"
    assert classify_seed_format(tmp_path / "i.png") == "image"


def test_classify_by_magic_when_extensionless(tmp_path):
    """OSS-Fuzz corpus seeds are hash-named (no extension) → use magic."""
    f = tmp_path / "deadbeefcafe"          # extensionless
    f.write_bytes(_icc_bytes())
    assert classify_seed_format(f) == "icc"

    png = tmp_path / "abc123"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    assert classify_seed_format(png) == "image"


def test_classify_unknown_returns_none(tmp_path):
    f = tmp_path / "random.bin"
    f.write_bytes(b"not a known format" * 4)
    assert classify_seed_format(f) is None


# --- infer_driver_formats ----------------------------------------------------

def test_infer_icc_from_profile_api():
    assert "icc" in infer_driver_formats(_ICC_DRIVER)


def test_infer_icc_from_transform_chain():
    # The transform driver still consumes ICC at its fuzz-byte entry.
    assert "icc" in infer_driver_formats(_TRANSFORM_DRIVER)


def test_infer_json_from_cjson_api():
    fams = infer_driver_formats(_JSON_DRIVER)
    assert "json" in fams
    assert "icc" not in fams


def test_infer_empty_for_unrecognised_entry():
    assert infer_driver_formats(_OPAQUE_DRIVER) == set()


# --- select_seeds_for_driver -------------------------------------------------

def _mk_seeds(tmp_path):
    icc = tmp_path / "test1.icc"
    icc.write_bytes(_icc_bytes())
    js = tmp_path / "sample.json"
    js.write_bytes(b'{"k":1}')
    png = tmp_path / "img.png"
    png.write_bytes(b"\x89PNG" + b"\x00" * 8)
    return icc, js, png


def test_select_routes_icc_driver_to_icc_seed_only(tmp_path):
    icc, js, png = _mk_seeds(tmp_path)
    chosen = select_seeds_for_driver(_ICC_DRIVER, [icc, js, png])
    assert chosen == [icc], "ICC driver must not be polluted with json/png seeds"


def test_select_routes_json_driver_to_json_seed_only(tmp_path):
    icc, js, png = _mk_seeds(tmp_path)
    chosen = select_seeds_for_driver(_JSON_DRIVER, [icc, js, png])
    assert chosen == [js]


def test_select_unknown_driver_gets_all_seeds(tmp_path):
    """No recognised parser entry → don't constrain; a real input beats random."""
    icc, js, png = _mk_seeds(tmp_path)
    chosen = select_seeds_for_driver(_OPAQUE_DRIVER, [icc, js, png])
    assert set(chosen) == {icc, js, png}


def test_select_falls_back_to_all_when_no_format_match(tmp_path):
    """ICC driver but project ships only json/png → fall back to all (not empty).

    Never make it WORSE than the seedless status quo: an unrelated real input
    is still better than no seed at all.
    """
    _icc, js, png = _mk_seeds(tmp_path)
    chosen = select_seeds_for_driver(_ICC_DRIVER, [js, png])
    assert set(chosen) == {js, png}


# --- seed_corpus_for_driver (end-to-end into a corpus dir) -------------------

def test_seed_corpus_copies_matching_seed_into_dir(tmp_path):
    icc = tmp_path / "real.icc"
    icc.write_bytes(_icc_bytes())
    js = tmp_path / "x.json"
    js.write_bytes(b"{}")
    corpus = tmp_path / "corpora" / "01.fuzz_target"

    drv = tmp_path / "01.fuzz_target"
    drv.write_text(_ICC_DRIVER)

    n = seed_corpus_for_driver("lcms", corpus, drv, seeds=[icc, js])
    assert n == 1
    names = sorted(p.name for p in corpus.iterdir())
    assert names == ["projseed_real.icc"], \
        "only the ICC seed should land in the ICC driver's corpus"


def test_seed_corpus_is_idempotent_and_additive(tmp_path):
    """Second call copies nothing new; pre-existing (libFuzzer) files untouched."""
    icc = tmp_path / "real.icc"
    icc.write_bytes(_icc_bytes())
    corpus = tmp_path / "corpora" / "01.fuzz_target"
    corpus.mkdir(parents=True)
    # Simulate a libFuzzer-discovered input already present.
    (corpus / "deadbeef").write_bytes(b"\x01\x02")

    drv = tmp_path / "01.fuzz_target"
    drv.write_text(_ICC_DRIVER)

    first = seed_corpus_for_driver("lcms", corpus, drv, seeds=[icc])
    second = seed_corpus_for_driver("lcms", corpus, drv, seeds=[icc])
    assert first == 1
    assert second == 0, "re-seeding must not duplicate"
    # The libFuzzer-discovered input is preserved.
    assert (corpus / "deadbeef").read_bytes() == b"\x01\x02"
    assert (corpus / "projseed_real.icc").exists()


def test_seed_corpus_no_seeds_returns_zero(tmp_path):
    corpus = tmp_path / "corpora" / "01.fuzz_target"
    drv = tmp_path / "01.fuzz_target"
    drv.write_text(_ICC_DRIVER)
    assert seed_corpus_for_driver("lcms", corpus, drv, seeds=[]) == 0


def test_seed_corpus_respects_max_cap(tmp_path):
    seeds = []
    for i in range(10):
        s = tmp_path / f"p{i}.icc"
        s.write_bytes(_icc_bytes())
        seeds.append(s)
    corpus = tmp_path / "corpora" / "01.fuzz_target"
    drv = tmp_path / "01.fuzz_target"
    drv.write_text(_ICC_DRIVER)
    n = seed_corpus_for_driver("lcms", corpus, drv, seeds=seeds, max_seeds=3)
    assert n == 3
    assert len(list(corpus.iterdir())) == 3


def test_seed_corpus_no_driver_source_copies_all(tmp_path):
    """driver_source_path=None → no routing, all seeds copied."""
    icc = tmp_path / "a.icc"
    icc.write_bytes(_icc_bytes())
    js = tmp_path / "b.json"
    js.write_bytes(b"{}")
    corpus = tmp_path / "corpora" / "01.fuzz_target"
    n = seed_corpus_for_driver("lcms", corpus, None, seeds=[icc, js])
    assert n == 2


# --- builder_runner seeding --------------------------------------------------

def test_builder_runner_routes_real_seed(tmp_path, monkeypatch):
    """_seed_corpus_dir (always on) routes a real format-matching seed into the
    driver's corpus dir."""
    import experiment.builder_runner as br

    icc = tmp_path / "real.icc"
    icc.write_bytes(_icc_bytes())
    fuzz_targets = tmp_path / "fuzz_targets"
    fuzz_targets.mkdir()
    (fuzz_targets / "01.fuzz_target").write_text(_ICC_DRIVER)
    corpus = tmp_path / "corpora" / "01.fuzz_target"
    corpus.mkdir(parents=True)

    runner = object.__new__(br.BuilderRunner)
    runner.benchmark = type("B", (), {"project": "lcms"})()
    runner.work_dirs = type("W", (), {"fuzz_targets": str(fuzz_targets)})()

    # Route discovery through our fixture seeds (no project checkout needed).
    import scripts.seed_discovery as sd
    monkeypatch.setattr(sd, "discover_project_seeds", lambda _p, **_k: [icc])

    runner._seed_corpus_dir(str(corpus), "01.fuzz_target")
    names = [p.name for p in corpus.iterdir()]
    assert names == ["projseed_real.icc"], \
        "gate on → the ICC driver's corpus gets the real .icc seed"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
