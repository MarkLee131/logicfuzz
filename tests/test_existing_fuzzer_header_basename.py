"""Regression: existing-fuzzer header extraction must normalise quote-form
project includes to their BASENAME (drop ``../`` / dir components).

Root cause (2026-06-18 systematic-debugging): the stock cjson fuzzer lives in
``$SRC/cjson/fuzzing/`` and does ``#include "../cJSON.h"``. The extraction
docstring promised to "Strip leading ./ or directory components for the
quote-form references", but the code stored ``../cJSON.h`` verbatim. That
location-relative path was then surfaced to the LLM and copied into generated
drivers, which live in a DIFFERENT directory (``$SRC/synthesized/``) where
``../`` resolves to the wrong place — forcing a downstream symlink farm in the
merge/compile-validate bash to make it resolve. Fixing the extraction to honour
its own contract (basename) removes the location dependence at the source.
"""

import logging
import textwrap

from src.context.data_context import _extract_existing_fuzzer_headers


def _write_driver(root, name, body):
    p = root / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_quote_form_project_headers_are_basenames(tmp_path, monkeypatch):
    proj = tmp_path / "cjson"
    proj.mkdir()
    _write_driver(
        proj,
        "cjson_read_fuzzer.c",
        """
        #include <stdint.h>
        #include <stddef.h>
        #include "../cJSON.h"
        #include "sub/dir/extra.h"
        #include "plain.h"
        int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }
        """,
    )
    monkeypatch.setenv("LOGICFUZZ_DRIVERS_ROOT", str(tmp_path))

    headers = _extract_existing_fuzzer_headers("cjson", logging.getLogger("t"))

    # Angle-form (system) includes unchanged.
    assert "<stdint.h>" in headers["standard_headers"]
    assert "<stddef.h>" in headers["standard_headers"]

    # Quote-form project includes are reduced to BASENAME — no path component,
    # so they resolve independent of the driver's directory.
    proj_h = headers["project_headers"]
    assert "cJSON.h" in proj_h, proj_h
    assert "extra.h" in proj_h, proj_h
    assert "plain.h" in proj_h, proj_h
    # The location-relative forms must NOT survive.
    assert not any("/" in h for h in proj_h), proj_h
    assert "../cJSON.h" not in proj_h, proj_h
