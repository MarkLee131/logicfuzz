"""Regression: ``_ensure_project_headers`` must treat a project header as
already-present when the driver includes it under ANY path form (``../X.h``,
``dir/X.h``), comparing by basename — otherwise it adds a duplicate include.

This pairs with the extraction-layer basename fix
(``_extract_existing_fuzzer_headers``): now that ``project_headers`` are
basenames (``cJSON.h``), a driver that already carries ``#include "../cJSON.h"``
must NOT get a second ``#include <cJSON.h>`` appended.
"""

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402

_ensure = LangGraphPrototyper._ensure_project_headers


def _run(code, project_headers):
    fake_self = types.SimpleNamespace(trial="t")
    return _ensure(
        fake_self,
        code,
        {"project_headers": project_headers, "standard_headers": []},
        "c",
    )


def test_no_duplicate_when_relative_form_present():
    code = (
        "#include <stdint.h>\n"
        '#include "../cJSON.h"\n'
        "int LLVMFuzzerTestOneInput(const uint8_t *d, unsigned long n){return 0;}\n"
    )
    out = _run(code, ["cJSON.h"])
    assert out.count("cJSON.h") == 1, out


def test_still_adds_when_genuinely_missing():
    code = (
        "#include <stdint.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, unsigned long n){return 0;}\n"
    )
    out = _run(code, ["cJSON.h"])
    assert "cJSON.h" in out, out
