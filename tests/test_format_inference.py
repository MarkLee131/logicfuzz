"""T10 — generalized format-entry inference + synthetic seed (LOGICFUZZ_FORMAT_INFER).

A parser-entry API early-returns on random bytes at its magic gate. When no real
seed ships, T10 synthesizes a minimal front-gate-passing seed from a FormatSpec
inferred deterministically (sampled seed prefix > known-magic registry >
header #define magic constants). Covers the pure inference module + the
seed_discovery synthesis fallback.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.analysis.format_inference import (  # noqa: E402
    FormatSpec, magic_defines_from_text, spec_from_seed_sample, infer_spec,
    synthesize_minimal_seed, format_recipe_text, _REGISTRY,
)
from scripts.seed_discovery import seed_corpus_for_driver  # noqa: E402


# ---- FormatSpec invariants -------------------------------------------------

def test_min_length_spans_magic_at_offset():
    s = FormatSpec("icc", b"acsp", offset=36, min_length=0)
    assert s.min_length == 40   # bumped to offset+len(magic)


# ---- header #define magic scan (the generalization) ------------------------

def test_magic_define_string_literal():
    specs = magic_defines_from_text('#define FOO_MAGIC "GIF8"')
    assert len(specs) == 1
    assert specs[0].magic == b"GIF8"
    assert specs[0].source == "header_define"


def test_magic_define_hex_literal():
    specs = magic_defines_from_text("#define BAR_SIGNATURE 0x89504E47")
    assert specs[0].magic == b"\x89\x50\x4e\x47"


def test_magic_define_ignores_non_magic_names():
    assert magic_defines_from_text("#define MAX_SIZE 1024") == []
    assert magic_defines_from_text("#define COLOR_COUNT 7") == []


# ---- seed-sample inference -------------------------------------------------

def test_spec_from_seed_sample_takes_prefix():
    s = spec_from_seed_sample(b"\x89PNG\r\n\x1a\nIHDR....", label="image")
    assert s is not None
    assert s.magic == b"\x89PNG\r\n\x1a\n"   # first 8 bytes
    assert s.source == "seed_sample"


def test_spec_from_empty_seed_is_none():
    assert spec_from_seed_sample(b"") is None


# ---- precedence: seed_sample > registry > header ---------------------------

def test_infer_prefers_seed_sample_over_registry():
    s = infer_spec("icc", seed_sample=b"CUSTOMHDR")
    assert s.source == "seed_sample"


def test_infer_registry_for_known_family():
    s = infer_spec("icc")
    assert s is not None and s.magic == b"acsp" and s.offset == 36


def test_infer_header_when_unknown_family():
    s = infer_spec("weirdfmt", header_texts=['#define WF_MAGIC "WfMt"'])
    assert s is not None and s.magic == b"WfMt"


def test_infer_none_when_nothing_matches():
    assert infer_spec("weirdfmt") is None


# ---- synthesis -------------------------------------------------------------

def test_synthesize_places_magic_at_offset():
    seed = synthesize_minimal_seed(_REGISTRY["icc"])
    assert len(seed) == 132
    assert seed[36:40] == b"acsp"
    assert seed[:36] == b"\x00" * 36          # zero-padded prefix


def test_recipe_text_mentions_magic_and_offset():
    txt = format_recipe_text(_REGISTRY["icc"])
    assert "acsp" in txt and "offset 36" in txt


# ---- seed_discovery synthesis fallback (gated) -----------------------------

def _icc_driver(tmp_path):
    p = tmp_path / "00.fuzz_target"
    p.write_text("int LLVMFuzzerTestOneInput(){ cmsOpenProfileFromMem(d,n); }")
    return p


def test_synth_fallback_writes_seed_when_gated(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_FORMAT_INFER", "1")
    corpus = tmp_path / "corpus"
    n = seed_corpus_for_driver("proj", corpus, _icc_driver(tmp_path), seeds=[])
    assert n >= 1   # diverse corpus: minimal seed + varied-body variants
    synth = corpus / "synthseed_icc_00"
    assert synth.exists()
    assert synth.read_bytes()[36:40] == b"acsp"   # front gate cleared


def test_synth_fallback_off_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_FORMAT_INFER", raising=False)
    corpus = tmp_path / "corpus"
    n = seed_corpus_for_driver("proj", corpus, _icc_driver(tmp_path), seeds=[])
    assert n == 0
    assert not (corpus / "synthseed_icc").exists()


def test_synth_skipped_when_real_seed_present(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_FORMAT_INFER", "1")
    real = tmp_path / "real.icc"
    real.write_bytes(b"\x00" * 36 + b"acsp" + b"\x00" * 92)
    corpus = tmp_path / "corpus"
    n = seed_corpus_for_driver("proj", corpus, _icc_driver(tmp_path),
                               seeds=[real])
    # real seed routed → synth fallback must NOT fire
    assert not (corpus / "synthseed_icc").exists()
    assert n >= 1


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
