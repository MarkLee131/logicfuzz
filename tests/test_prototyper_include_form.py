"""Header fix (B): _ensure_project_headers must add missing project headers with
the DOUBLE-QUOTE form `#include "h"`, not the forced angle-bracket `#include <h>`.
The library header is in-tree (not installed), so quote (local-dir + search-path
fallback) is the safer default for new/unknown projects; angle-bracket only resolves
if the header dir is on -I (the per-trial build didn't add it → HEADER_NOT_FOUND,
cjson 11/27 dead). Pairs with the trial-build -I fix."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
# Documented workflow↔agents circular import: the retry populates partial state.
try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa: E402

CODE = "int LLVMFuzzerTestOneInput(const uint8_t* d, size_t s){ (void)d;(void)s; return 0; }\n"


def _ensure(headers, code=CODE, lang='c'):
    p = LangGraphPrototyper.__new__(LangGraphPrototyper)  # bare instance
    p.trial = 0  # only self.* the fn touches (a log call)
    return p._ensure_project_headers(code, {'project_headers': headers}, lang)


def test_missing_header_added_as_quote_not_angle():
    out = _ensure(['cJSON.h'])
    assert '#include "cJSON.h"' in out
    assert '#include <cJSON.h>' not in out


def test_already_included_not_duplicated():
    out = _ensure(['cJSON.h'], code='#include "cJSON.h"\n' + CODE)
    assert out.count('cJSON.h') == 1
