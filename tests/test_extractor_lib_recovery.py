"""Unit tests for the pure helpers behind the extractor lib-recovery branches
(Plan 3-lib). The in-container build branches are validated by a real
--extract-only run, not here."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from liberator_adapter.extractors.llvm_extractor import (
    _select_fallback_archive, STUB_ENGINE_PATH,
)


def test_picks_largest_archive():
    cands = [("/src/p.main/build/libjpeg.a", 5000),
             ("/src/p.main/build/libturbojpeg.a", 4000),
             ("/src/p.main/third_party/libtiny.a", 50)]
    assert _select_fallback_archive(cands) == "/src/p.main/build/libjpeg.a"


def test_excludes_stub_engine():
    cands = [(STUB_ENGINE_PATH, 999999), ("/src/p/build/libjpeg.a", 4000)]
    assert _select_fallback_archive(cands) == "/src/p/build/libjpeg.a"


def test_excludes_zero_size_and_empty():
    assert _select_fallback_archive([("/src/x.a", 0)]) is None
    assert _select_fallback_archive([]) is None


def test_deterministic_tiebreak_by_path():
    cands = [("/src/b.a", 100), ("/src/a.a", 100)]
    assert _select_fallback_archive(cands) == "/src/a.a"
