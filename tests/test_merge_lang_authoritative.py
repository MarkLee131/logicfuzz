"""Merge must compile generated drivers in the STOCK FUZZ TARGET's language, not
content-sniff it per driver.

Root cause (verified 2026-06-20 on libpng): the generated drivers are saved as
extensionless ``NN.fuzz_target``. The per-trial build writes each to
``benchmark.target_path`` (``libpng_read_fuzzer.cc`` → compiled as C++ by
OSS-Fuzz's ``$CXX``) and they PASS. But the merge gate + merge build re-derive the
language by CONTENT-SNIFFING the extensionless file (``IndividualDriver.suffix`` /
``_merge_target_lang``), guess C, and fail — dropping 34/110 libpng drivers on
"must use 'struct' tag" / "expected identifier" / "expected expression". That is an
A≢B bug: the per-trial build compiled them as C++, the merge as C.

``benchmark.file_type`` (from the ``target_path`` extension) is the authoritative
compile language and is ALREADY what the per-trial build uses. Threading it into
the merge as a ``lang`` override — instead of sniffing — recovers all 34
deterministically with zero risk (the per-trial C++ build is the existence proof
they all compile as C++). NOTE: the yaml ``language`` field is the *library*
language (``c`` for libpng) — the WRONG signal; the target extension is right.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.merge_drivers.merge import IndividualDriver, SynthesizedDriver
from tools.merge_drivers import compile_validate as cv

# A libpng-style driver that SNIFFS AS C (guarded extern "C", no std::/class/cast)
# but is only valid as C++ (bare ``BufState`` struct-tag usage). This is the exact
# class the merge silently dropped.
_LIBPNG_STRUCT_TAG_DRIVER = """\
#include <stdint.h>
#include <png.h>
#ifdef __cplusplus
extern "C" {
#endif
struct BufState { const uint8_t* data; size_t bytes_left; };
static void user_read_data(png_structp p, png_bytep out, png_size_t len) {
  BufState* st = (BufState*)png_get_io_ptr(p);   // bare struct tag → C++-only
  (void)st; (void)out; (void)len;
}
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }
#ifdef __cplusplus
}
#endif
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_lang_override_forces_suffix(tmp_path):
    src = _write(tmp_path, "08.fuzz_target", _LIBPNG_STRUCT_TAG_DRIVER)
    # Without the override, the sniffer guesses C (the bug).
    assert IndividualDriver(src, 0).suffix == "c"
    # With the stock target's language threaded in, it compiles as C++ (correct).
    assert IndividualDriver(src, 0, lang_override="cpp").suffix == "cpp"


def test_lang_override_normalizes_extension_forms(tmp_path):
    src = _write(tmp_path, "08.fuzz_target", _LIBPNG_STRUCT_TAG_DRIVER)
    assert IndividualDriver(src, 0, lang_override="c++").suffix == "cpp"
    assert IndividualDriver(src, 0, lang_override="cc").suffix == "cpp"
    assert IndividualDriver(src, 0, lang_override="c").suffix == "c"


def test_sniff_preserved_when_no_override(tmp_path):
    # The content-sniff remains the fallback for the standalone merge CLI that has
    # no benchmark (a C++ marker → cpp; pure C → c).
    cpp = _write(tmp_path, "01.fuzz_target",
                 "int LLVMFuzzerTestOneInput(){ std::vector<int> v; return 0; }")
    assert IndividualDriver(cpp, 0).suffix == "cpp"
    c = _write(tmp_path, "02.fuzz_target",
               "int LLVMFuzzerTestOneInput(){ return 0; }")
    assert IndividualDriver(c, 0).suffix == "c"


def test_from_paths_propagates_lang_to_all_drivers(tmp_path):
    a = _write(tmp_path, "08.fuzz_target", _LIBPNG_STRUCT_TAG_DRIVER)
    b = _write(tmp_path, "11.fuzz_target", _LIBPNG_STRUCT_TAG_DRIVER)
    harness = SynthesizedDriver.from_paths([a, b], lang="cpp")
    assert all(d.suffix == "cpp" for d in harness.drivers)
    assert harness.is_cpp is True


# ---- compile-validation gate must use the same authoritative language ----------

def test_compile_validate_resolve_lang_honors_override(tmp_path):
    src = _write(tmp_path, "08.fuzz_target", _LIBPNG_STRUCT_TAG_DRIVER)
    # override wins over the content sniff (which would say 'c' here)
    assert cv._resolve_lang(src, "cpp") == "cpp"
    assert cv._resolve_lang(src, "c++") == "cpp"
    assert cv._resolve_lang(src, "c") == "c"


def test_compile_validate_resolve_lang_falls_back_to_sniff(tmp_path):
    # No override ⇒ delegate to the existing per-driver sniff (standalone CLI).
    cpp = _write(tmp_path, "01.cpp", "int LLVMFuzzerTestOneInput(){return 0;}")
    assert cv._resolve_lang(cpp, None) == cv._merge_target_lang(cpp)
    assert cv._resolve_lang(cpp, None) == "cpp"   # .cpp extension → cpp
