"""Tests for the INCONCLUSIVE_LINK triage class.

Background — see the methodology critique in conversation history.

The previous behavior bucketed every undefined symbol that wasn't in the
static-extracted known_apis as FAKE_DEFINITION (recoverable=False), and
the supervisor interpreted that as "give up, this is a hallucination."
That was a *triage* defect masked by a *supervisor* band-aid: macro
expansions, weak symbols, and `#define`-renamed real functions are
genuinely linkable but invisible to the static extractor, so they kept
killing trials prematurely.

The fix splits the undefined-symbol bucket on evidence:

  - LINK_ERROR        symbol is in known_apis or is a system symbol
  - INCONCLUSIVE_LINK symbol is NOT in known_apis but has a close prefix
                       match to one (≥ 4 shared chars). Recoverable;
                       fixer gets one informed shot with a similar-API
                       hint embedded in `details`.
  - FAKE_DEFINITION   symbol has no plausible match. Genuine
                       hallucination, not recoverable.

These tests pin that behavior down so future tweaks to the triage stay
honest about which bucket each kind of error lands in.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.utils.compilation_error_triage import (  # noqa: E402
    triage_build_errors,
    ErrorCategory,
    CompilationErrorTriage,
)


KNOWN_CJSON = [
    {'function_name': 'cJSON_Parse'},
    {'function_name': 'cJSON_Print'},
    {'function_name': 'cJSON_Delete'},
    {'function_name': 'cJSON_GetArraySize'},
    {'function_name': 'cJSON_AddItemToArray'},
]


def _err(symbol: str) -> str:
    return f"/src/fuzz.c:42: undefined reference to `{symbol}'"


def test_known_symbol_classifies_as_link_error():
    r = triage_build_errors([_err('cJSON_Parse')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.LINK_ERROR
    assert r.recoverable is True


def test_macro_style_unknown_classifies_as_inconclusive():
    """cJSON_FreeMemory: not in known_apis, but cJSON_* prefix matches.
    Could be a macro alias for cJSON_free or similar; must be recoverable."""
    r = triage_build_errors([_err('cJSON_FreeMemory')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.INCONCLUSIVE_LINK
    assert r.recoverable is True
    # The hint must mention a real candidate so the fixer prompt has
    # something concrete to show the LLM.
    err = r.errors[0]
    assert err.extracted_symbol == 'cJSON_FreeMemory'
    assert 'cJSON_' in err.details, \
        "INCONCLUSIVE_LINK details should reference the resembling API"


def test_garbage_name_classifies_as_fake_definition():
    """A symbol with no plausible prefix overlap is a real hallucination."""
    r = triage_build_errors([_err('do_some_random_thing')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.FAKE_DEFINITION
    assert r.recoverable is False


def test_short_prefix_below_threshold_is_fake():
    """3-char shared prefix is below the 4-char gate → still FAKE."""
    # "cJs" matches first 3 chars of "cJSON_*"; below the cutoff.
    r = triage_build_errors([_err('cJsanity_check')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.FAKE_DEFINITION


def test_system_symbol_falls_through_to_link_error():
    """Compiler-runtime / libc symbols must never be flagged as fake."""
    r = triage_build_errors([_err('__asan_init')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.LINK_ERROR


def test_llvm_fuzzer_test_one_input_is_language_mismatch():
    """Pre-existing special case: undefined LLVMFuzzerTestOneInput means
    the C target was compiled by clang++ without extern "C". Must not
    be reclassified to FAKE/INCONCLUSIVE."""
    r = triage_build_errors([_err('LLVMFuzzerTestOneInput')], KNOWN_CJSON)
    assert r.primary_category == ErrorCategory.LANGUAGE_MISMATCH


def test_no_known_apis_falls_through_to_link_error():
    """When the project APIs aren't supplied, we can't classify
    fake-vs-real. The triage should NOT escalate to FAKE_DEFINITION
    on its own — that would re-introduce the same false-positive
    failure mode."""
    r = triage_build_errors([_err('cJSON_FreeMemory')], None)
    assert r.primary_category == ErrorCategory.LINK_ERROR
    assert r.recoverable is True


def test_find_similar_api_returns_best_prefix_match():
    """Lower-level helper: check the prefix-matching primitive picks
    the longest match and returns None below the threshold."""
    triage = CompilationErrorTriage()
    known = {'cJSON_Parse', 'cJSON_Print', 'json_parse_simple'}
    # 'cJSON_Print' shares 11 chars with itself; we expect cJSON_Print
    assert triage._find_similar_api('cJSON_Print', known) == 'cJSON_Print'
    # 'cJSON_FreeMemory' shares 6 chars (cJSON_) with both cJSON_*
    # candidates; either match is acceptable.
    sim = triage._find_similar_api('cJSON_FreeMemory', known)
    assert sim in {'cJSON_Parse', 'cJSON_Print'}
    # Below the threshold: 'cJs' shares 3 chars with cJSON_*; → None
    assert triage._find_similar_api('cJsanity', known) is None
    # Empty input handling
    assert triage._find_similar_api('', known) is None
    assert triage._find_similar_api('cJSON_Parse', set()) is None


if __name__ == '__main__':
    import pytest  # type: ignore[import-not-found]
    sys.exit(pytest.main([__file__, '-v']))
