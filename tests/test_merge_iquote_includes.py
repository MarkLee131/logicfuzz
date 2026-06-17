"""Header resolution for relocated synthesized drivers via -iquote (root fix).

Root cause (2026-06-18 systematic-debugging, reproduced): a quote-include
``#include "../cJSON.h"`` resolves relative to the DIRECTORY OF THE INCLUDING
FILE. OFG's per-driver build places our driver at target_path
(``/src/cjson/fuzzing/cjson_read_fuzzer.c``) — the stock fuzzer's location — so
``../cJSON.h`` resolves and COMPILES. The merge build relocates drivers to
``$SRC/synthesized/`` and compile-validate to ``/candidates/``, where the same
``../`` points nowhere → error. The include itself is correct; relocation broke it.

Fix: give the relocated compile the stock fuzzer's directory as an include
search base via ``-iquote <dirname(target_path)>``, so the original oss-fuzz
relative include resolves exactly as in the per-driver build — no symlink farm,
no source rewriting.
"""

import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools.merge_drivers.merge import SynthesizedDriver  # noqa: E402


def _snippet(tmp_path, iquote_dirs):
    d = tmp_path / "synthesized"
    d.mkdir()
    (d / "00.c").write_text(
        '#include "../cJSON.h"\n'
        "int LLVMFuzzerTestOneInput_00(const unsigned char*x,unsigned long n)"
        "{return 0;}\n"
    )
    drv = SynthesizedDriver.from_paths([Path(d / "00.c")])
    return drv.emit_oss_fuzz_build_snippet(
        target_name="merged_fuzzer", iquote_dirs=iquote_dirs)


def test_iquote_dirs_injected_into_compiles(tmp_path):
    snip = _snippet(tmp_path, ["/src/cjson/fuzzing", "/src/cjson"])
    assert '-iquote "/src/cjson/fuzzing"' in snip, snip
    assert '-iquote "/src/cjson"' in snip, snip


def test_symlink_farm_removed(tmp_path):
    snip = _snippet(tmp_path, ["/src/cjson/fuzzing"])
    # The old band-aid symlinked every header to $SRC; it must be gone.
    assert "ln -sf" not in snip, snip
    assert 'find "$SRC"' not in snip, snip


def test_no_iquote_when_dirs_absent(tmp_path):
    # Backward-compatible: no dirs → no -iquote tokens (byte-stable for callers
    # that don't pass them).
    snip = _snippet(tmp_path, None)
    assert "-iquote" not in snip, snip
