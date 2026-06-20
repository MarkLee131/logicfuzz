"""Gate include-discovery must find public headers regardless of layout, so it
doesn't drop drivers the real merged build would compile (false-negative → lost breadth)."""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.merge_drivers import compile_validate as cv


def test_include_search_dirs_covers_lib_includes_layout():
    dirs = cv._include_search_dirs()
    # the nghttp2 layout the gate used to miss
    assert "/src/$PROJ/lib/includes" in dirs
    # originals preserved (no regression)
    for d in ("/src/$PROJ/include", "/src/$PROJ", "/src"):
        assert d in dirs


def test_build_validate_script_interpolates_and_hardens():
    script = cv._build_validate_script("nghttp2", iquote_dirs=["/src/nghttp2/tests"])
    # project interpolated, no leftover placeholders
    assert 'PROJ="nghttp2"' in script
    for placeholder in ("__PROJECT__", "__INCDIRS__", "__IQUOTE__"):
        assert placeholder not in script
    # hardened static dir in the -I search loop
    assert "/src/$PROJ/lib/includes" in script
    # auto-discovery of nested include/includes roots
    assert "-name include" in script and "-name includes" in script
    # iquote flag threaded through
    assert '-iquote "/src/nghttp2/tests"' in script


def test_script_generates_config_headers_before_discovery():
    # gate runs a lightweight configure-only step (cmake configure_file headers
    # like nghttp2ver.h) BEFORE include discovery so the generated dir is -I'd.
    script = cv._build_validate_script("nghttp2", [])
    # lightweight cmake configure-only header generation
    assert "CMakeLists.txt" in script
    assert "cmake /src/$PROJ" in script
    # autotools fallback
    assert "configure" in script
    # header generation must precede nested-include auto-discovery
    assert script.index("cmake /src/$PROJ") < script.index("-name includes")


def test_build_validate_script_no_iquote_when_empty():
    script = cv._build_validate_script("cjson", iquote_dirs=None)
    assert 'PROJ="cjson"' in script
    # no actual -iquote FLAG emitted (literal appears only in a comment); IQUOTE empty
    assert '-iquote "' not in script
    assert 'IQUOTE=""' in script
