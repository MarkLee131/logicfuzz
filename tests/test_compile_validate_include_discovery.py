"""Gate include-discovery hardening: the compile-validation gate must find a
project's public headers regardless of layout, so it doesn't DROP drivers that
the real merged build would compile (a false-negative → lost breadth).

Root cause (nghttp2, 2026-06-20): nghttp2 keeps <nghttp2/nghttp2.h> under
/src/nghttp2/lib/includes, but the gate's -I search list was only
``/src/$PROJ/include /src/$PROJ /src/$PROJ/src /src/include /src`` — missing
lib/includes — so EVERY nghttp2 driver failed 'nghttp2/nghttp2.h not found',
independent of the language fix. Broaden the static base list AND auto-discover
any nested include/includes dir.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.merge_drivers import compile_validate as cv


def test_include_search_dirs_covers_lib_includes_layout():
    dirs = cv._include_search_dirs()
    # the nghttp2 layout the gate used to miss
    assert "/src/$PROJ/lib/includes" in dirs
    # originals preserved (no regression for projects that relied on them)
    for d in ("/src/$PROJ/include", "/src/$PROJ", "/src"):
        assert d in dirs


def test_build_validate_script_interpolates_and_hardens():
    script = cv._build_validate_script("nghttp2", iquote_dirs=["/src/nghttp2/tests"])
    # project interpolated, no leftover placeholders
    assert 'PROJ="nghttp2"' in script
    for placeholder in ("__PROJECT__", "__INCDIRS__", "__IQUOTE__"):
        assert placeholder not in script
    # the hardened static dir is in the -I search loop
    assert "/src/$PROJ/lib/includes" in script
    # dynamic auto-discovery of nested include/includes roots (layout-agnostic)
    assert "-name include" in script and "-name includes" in script
    # iquote flag threaded through
    assert '-iquote "/src/nghttp2/tests"' in script


def test_build_validate_script_no_iquote_when_empty():
    script = cv._build_validate_script("cjson", iquote_dirs=None)
    assert 'PROJ="cjson"' in script
    # no actual -iquote FLAG emitted (the literal '-iquote' appears in a comment);
    # the IQUOTE var is empty.
    assert '-iquote "' not in script
    assert 'IQUOTE=""' in script
